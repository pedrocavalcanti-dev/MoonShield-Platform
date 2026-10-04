#!/usr/bin/env bash

_package_list() {
  sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$MANIFEST_DIR/debian-packages.txt"
}

_sanitize_apt_output() {
  sed -E \
    -e 's#(https?://)[^/@[:space:]]+@#\1***@#g' \
    -e 's#([?&](password|passwd|secret|token|access_token|api_key|apikey)=)[^&[:space:]]+#\1***#Ig' \
    -e 's#((password|passwd|secret|token|access_token|api_key|apikey)[=:])[[:space:]]*[^[:space:]]+#\1***#Ig' \
    -e 's#(authorization:[[:space:]]*(basic|bearer))[[:space:]]+[^[:space:]]+#\1 ***#Ig'
}

_run_offline_apt() {
  local stage="$1"; shift
  local stdout_file stderr_file relevant line
  stdout_file="$(mktemp /tmp/moonshield-apt-stdout.XXXXXX)"
  stderr_file="$(mktemp /tmp/moonshield-apt-stderr.XXXXXX)"
  TEMP_FILES+=("$stdout_file" "$stderr_file")
  if LANG=C.UTF-8 LC_ALL=C.UTF-8 "$@" >"$stdout_file" 2>"$stderr_file"; then
    ok "$stage concluida."
    return 0
  fi

  relevant="$(grep -Ehi \
    'dpkg: error processing package|errors were encountered while processing|depends:|predepends:|unmet dependencies|not installable|not going to be installed|unable to locate package|has no installation candidate' \
    "$stdout_file" "$stderr_file" | tail -n 24 | _sanitize_apt_output || true)"
  if [[ -n "$relevant" ]]; then
    while IFS= read -r line; do
      [[ -n "$line" ]] && log ERROR "APT pacote/dependencia: $line"
    done <<<"$relevant"
  else
    log ERROR "$stage falhou sem identificar pacote/dependencia na saida do APT."
  fi
  if [[ -s "$stderr_file" ]]; then
    while IFS= read -r line; do
      [[ -n "$line" ]] && log ERROR "APT stderr: $line"
    done < <(tail -n 80 "$stderr_file" | _sanitize_apt_output)
  fi
  if [[ -s "$stdout_file" ]]; then
    while IFS= read -r line; do
      [[ -n "$line" ]] && log ERROR "APT output: $line"
    done < <(tail -n 40 "$stdout_file" | _sanitize_apt_output)
  fi
  return 1
}

_run_with_package_service_starts_suppressed() {
  local policy=/usr/sbin/policy-rc.d temporary status
  if [[ -e "$policy" || -L "$policy" ]]; then
    warn "policy-rc.d ja existe; a politica existente sera preservada durante a instalacao de pacotes."
    "$@"
    return
  fi

  temporary="$(mktemp /usr/sbin/.moonshield-policy-rc.d.XXXXXX)"
  TEMP_FILES+=("$temporary")
  printf '%s\n' '#!/bin/sh' 'exit 101' >"$temporary"
  chown root:root "$temporary"
  chmod 0755 "$temporary"
  mv -- "$temporary" "$policy"
  TEMP_FILES+=("$policy")
  info "Inicios automaticos de servicos foram suprimidos somente durante a etapa de pacotes."

  if "$@"; then
    status=0
  else
    status=$?
  fi

  rm -f -- "$policy"
  if (( status != 0 )); then
    return "$status"
  fi
  ok "Politica temporaria policy-rc.d removida; os servicos serao iniciados apenas pelas etapas MoonShield seguintes."
}

_install_packages() {
  local package apt_root source_list deb arch
  local -a packages deb_files apt_args
  mapfile -t packages < <(_package_list)
  ((${#packages[@]} > 0)) || die "Manifest Debian vazio."
  if [[ "$INSTALL_MODE" == offline ]]; then
    [[ -d "$OFFLINE_BUNDLE/debs" && -f "$OFFLINE_BUNDLE/SHA256SUMS" \
       && -f "$OFFLINE_BUNDLE/Packages" && -f "$OFFLINE_BUNDLE/Packages.gz" ]] \
      || die "Bundle offline de pacotes/repositório APT ausente ou incompleto."
    (cd "$OFFLINE_BUNDLE" && sha256sum --check SHA256SUMS >/dev/null) || die "Checksum do bundle offline falhou."
    grep -qx 'PackageIndex=local-apt' "$OFFLINE_BUNDLE/BUILD-INFO" \
      || die "Bundle offline sem indice APT local validado."
    grep -qx 'DependencyValidation=empty-dpkg-status' "$OFFLINE_BUNDLE/BUILD-INFO" \
      || die "Bundle offline sem prova de fechamento de dependencias."
    shopt -s nullglob
    deb_files=("$OFFLINE_BUNDLE"/debs/*.deb)
    ((${#deb_files[@]} > 0)) || die "Bundle offline não contém .deb."
    for deb in "${deb_files[@]}"; do
      dpkg-deb --info "$deb" >/dev/null || die "Pacote .deb invalido: $(basename -- "$deb")."
      arch="$(dpkg-deb -f "$deb" Architecture)"
      [[ "$arch" == amd64 || "$arch" == all ]] \
        || die "Pacote .deb de arquitetura incompatível: $(basename -- "$deb") ($arch)."
    done

    apt_root="$(mktemp -d /tmp/moonshield-apt-offline.XXXXXX)"
    TEMP_DIRS+=("$apt_root")
    mkdir -p "$apt_root/lists/partial" "$apt_root/archives/partial" "$apt_root/sourceparts"
    source_list="$apt_root/sources.list"
    printf 'deb [trusted=yes] file:%s ./\n' "$OFFLINE_BUNDLE" >"$source_list"
    apt_args=(
      -o "Dir::State::lists=$apt_root/lists"
      -o "Dir::Cache::archives=$apt_root/archives"
      -o "Dir::Etc::sourcelist=$source_list"
      -o "Dir::Etc::sourceparts=$apt_root/sourceparts"
      -o "APT::Sandbox::User=root"
      -o "Acquire::Languages=none"
      -o "APT::Get::List-Cleanup=false"
    )
    info "Validando indice e instalando exclusivamente pelo repositorio APT local do bundle."
    _run_offline_apt "Indice APT offline" apt-get "${apt_args[@]}" update \
      || die "Indice APT offline falhou; nenhuma fonte de rede foi consultada."
    _run_offline_apt "APT offline" apt-get "${apt_args[@]}" \
      --no-install-recommends --yes install "${packages[@]}" \
      || die "APT offline falhou; consulte pacote, dependencia e stderr sanitizado acima."
  else
    info "Atualizando índices assinados do Debian; nenhuma configuração de repositório será criada."
    run_with_tls_retry "apt-get update" apt-get update || die "apt-get update falhou; classe de falha disponível no log."
    info "Instalando pacotes mínimos declarados no manifest sem recomendações."
    run_with_tls_retry "APT install" apt-get install --no-install-recommends --yes "${packages[@]}" || die "Instalação de pacotes falhou; nenhum pacote será removido."
  fi
  for package in python3 python3-venv postgresql nginx network-manager nftables suricata; do
    dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q 'install ok installed' || die "Pacote crítico ausente após instalação: $package."
  done
  for binary in nmcli nft suricata suricata-update mtr ping traceroute dig ip ss curl openssl; do
    require_command "$binary"
  done
  local suricata_version nginx_version networkmanager_version nft_version
  suricata_version="$(suricata -V 2>&1 || true)"
  nginx_version="$(nginx -v 2>&1 || true)"
  networkmanager_version="$(nmcli --version 2>&1 || true)"
  nft_version="$(nft --version 2>&1 || true)"
  [[ "$suricata_version" == *"7.0.10"* ]] || die "Suricata incompatível; baseline exigido 7.0.10."
  [[ "$nginx_version" == *"1.26.3"* ]] || die "Nginx incompatível; baseline exigido 1.26.3."
  [[ "$networkmanager_version" == *"1.52.1"* ]] || die "NetworkManager incompatível; baseline exigido 1.52.1."
  [[ "$nft_version" == *"1.1.3"* ]] || die "nftables incompatível; baseline exigido 1.1.3."
  ok "Pacotes críticos instalados/verificados."
}

install_packages() {
  _run_with_package_service_starts_suppressed _install_packages
}
