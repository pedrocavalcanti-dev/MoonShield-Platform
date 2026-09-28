#!/usr/bin/env bash

_package_list() {
  sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$MANIFEST_DIR/debian-packages.txt"
}

install_packages() {
  local package
  local -a packages deb_files
  mapfile -t packages < <(_package_list)
  ((${#packages[@]} > 0)) || die "Manifest Debian vazio."
  if [[ "$INSTALL_MODE" == offline ]]; then
    [[ -d "$OFFLINE_BUNDLE/debs" && -f "$OFFLINE_BUNDLE/SHA256SUMS" ]] || die "Bundle offline de pacotes ausente/incompleto."
    (cd "$OFFLINE_BUNDLE" && sha256sum --check --status SHA256SUMS) || die "Checksum do bundle offline falhou."
    shopt -s nullglob
    deb_files=("$OFFLINE_BUNDLE"/debs/*.deb)
    ((${#deb_files[@]} > 0)) || die "Bundle offline não contém .deb."
    info "Instalando somente .deb verificados do bundle; sem fallback de rede."
    run_checked "APT offline" apt-get --no-download --no-install-recommends --yes install "${deb_files[@]}" || die "APT offline falhou; bundle não cobre a resolução de dependências."
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
