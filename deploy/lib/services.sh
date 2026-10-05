#!/usr/bin/env bash

# shellcheck source=adguard-archive.sh
. "$DEPLOY_DIR/lib/adguard-archive.sh"

_SERVICES_MANAGED_BACKUP_PATH=""
_SERVICES_MANAGED_FILE_EXISTED=0

_services_install_managed_file() {
  local source="$1" destination="$2" mode="$3" parent temp
  parent="$(dirname -- "$destination")"
  install -d -o root -g root -m 0755 "$parent"
  _SERVICES_MANAGED_BACKUP_PATH=""
  _SERVICES_MANAGED_FILE_EXISTED=0
  if [[ -e "$destination" ]]; then
    _SERVICES_MANAGED_FILE_EXISTED=1
  fi
  if [[ "$_SERVICES_MANAGED_FILE_EXISTED" == 1 ]] && ! cmp -s -- "$source" "$destination"; then
    _SERVICES_MANAGED_BACKUP_PATH="${destination}.backup.$(date -u +%Y%m%dT%H%M%SZ).$$"
    cp -a -- "$destination" "$_SERVICES_MANAGED_BACKUP_PATH"
    warn "Configuração anterior preservada em backup antes da atualização do arquivo gerenciado."
  fi
  temp="$(mktemp "$parent/.moonshield.XXXXXX")"
  TEMP_FILES+=("$temp")
  install -o root -g root -m "$mode" -- "$source" "$temp"
  mv -f -- "$temp" "$destination"
}

install_adguard_binary() {
  local artifact expected_url cache_dir
  local expected actual extraction install_source adguard_version
  if [[ -x /opt/AdGuardHome/AdGuardHome ]]; then
    adguard_version="$(/opt/AdGuardHome/AdGuardHome --version 2>&1 || true)"
    [[ "$adguard_version" == *"v0.107.79"* ]] || die "AdGuard existente não corresponde à versão v0.107.79; estado preservado e instalação interrompida."
    info "AdGuard v0.107.79 existente verificado e preservado; dados/configuração não serão substituídos."
    return 0
  fi
  [[ ! -e /opt/AdGuardHome ]] || die "Diretório /opt/AdGuardHome existe sem binário executável; preservado para inspeção, sem cópia sobre estado parcial."
  expected_url="$(manifest_value "$MANIFEST_DIR/external-artifacts.env" ADGUARD_URL)"
  expected="$(manifest_value "$MANIFEST_DIR/external-artifacts.env" ADGUARD_SHA256)"
  [[ "$expected" =~ ^[A-Fa-f0-9]{64}$ ]] || die "Checksum confiável do AdGuard não definido; instalação recusada."
  if [[ "$INSTALL_MODE" == offline ]]; then
    artifact="$OFFLINE_BUNDLE/artifacts/AdGuardHome_linux_amd64.tar.gz"
    [[ -f "$artifact" ]] || die "Artifact AdGuard v0.107.79 ausente do bundle offline."
  else
    [[ "$expected_url" == https://* ]] || die "URL HTTPS versionada do AdGuard ausente; instalação recusada."
    cache_dir=/var/cache/moonshield/artifacts
    install -d -o root -g root -m 0755 "$cache_dir"
    artifact="$cache_dir/AdGuardHome_linux_amd64.tar.gz"
    if [[ ! -f "$artifact" ]] || [[ "$(sha256sum "$artifact" | awk '{print $1}')" != "${expected,,}" ]]; then
      download_verified "$expected_url" "$expected" "$artifact"
    fi
  fi
  actual="$(sha256sum "$artifact" | awk '{print $1}')"
  [[ "${actual,,}" == "${expected,,}" ]] || die "Checksum do AdGuard diverge do manifest; instalação recusada."
  validate_adguard_archive "$artifact" || die "Arquivo AdGuard não atende ao contrato seguro de extração."
  extraction="$(mktemp -d /opt/.moonshield-adguard.extract.XXXXXX)"
  TEMP_DIRS+=("$extraction")
  tar --no-same-owner --no-same-permissions -xzf "$artifact" -C "$extraction" || die "Extração segura do artifact AdGuard falhou."
  [[ -x "$extraction/AdGuardHome/AdGuardHome" ]] || die "Binário esperado ausente no artifact AdGuard."
  chown -R root:root "$extraction/AdGuardHome"
  find "$extraction/AdGuardHome" -type d -exec chmod 0755 {} +
  find "$extraction/AdGuardHome" -type f -exec chmod 0644 {} +
  chmod 0755 "$extraction/AdGuardHome/AdGuardHome"
  adguard_version="$("$extraction/AdGuardHome/AdGuardHome" --version 2>&1 || true)"
  [[ "$adguard_version" == *"v0.107.79"* ]] || die "Binário AdGuard instalado não reporta v0.107.79; verificação falhou."
  install_source="$extraction/AdGuardHome"
  mv -- "$install_source" /opt/AdGuardHome || die "Publicação atômica do AdGuard falhou."
  ok "Binário AdGuard v0.107.79 instalado; serviço/configuração serão provisionados pelo bootstrap existente."
}

install_nginx_site() {
  local source="$DEPLOY_DIR/nginx/moonshield.conf" destination=/etc/nginx/conf.d/moonshield.conf
  local tls_source tls_temp cert=/etc/moonshield/tls/fullchain.pem key=/etc/moonshield/tls/privkey.pem
  local default_site=/etc/nginx/sites-enabled/default default_target default_backup=""
  local default_backup_dir=/var/lib/moonshield/recovery/nginx
  [[ -f "$source" ]] || die "Template Nginx versionado ausente."
  tls_source="$(mktemp /tmp/moonshield-nginx.XXXXXX)"
  TEMP_FILES+=("$tls_source")
  cp -- "$source" "$tls_source"
  if [[ -e "$cert" || -e "$key" ]]; then
    [[ -s "$cert" && -s "$key" ]] || die "Certificado/chave TLS incompletos; arquivos existentes foram preservados."
    openssl x509 -in "$cert" -noout >/dev/null 2>&1 || die "Certificado TLS local inválido; configuração não alterada."
    openssl pkey -in "$key" -noout >/dev/null 2>&1 || die "Chave TLS local inválida; configuração não alterada."
    cat >>"$tls_source" <<'NGINX_TLS'

server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;
    server_tokens off;
    client_max_body_size 20m;
    ssl_certificate /etc/moonshield/tls/fullchain.pem;
    ssl_certificate_key /etc/moonshield/tls/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    location /static/ { alias /var/lib/moonshield/static/; access_log off; expires 7d; }
    location /media/ { alias /var/lib/moonshield/media/; expires 1h; }
    location / {
        proxy_pass http://moonshield_web;
        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 10s;
        proxy_send_timeout 120s;
        proxy_read_timeout 120s;
    }
}
NGINX_TLS
    info "TLS da appliance configurado com certificado local fornecido explicitamente."
  else
    warn "Certificado TLS da appliance ausente; Nginx ficará apenas em HTTP até o provisionamento TLS."
  fi
  if [[ -L "$default_site" ]]; then
    default_target="$(readlink -f -- "$default_site")"
    if [[ "$default_target" == /etc/nginx/sites-available/default ]] \
      && grep -Fq 'listen 80 default_server;' "$default_target" \
      && grep -Fq 'root /var/www/html;' "$default_target" \
      && grep -Fq 'try_files $uri $uri/ =404;' "$default_target"; then
      install -d -o root -g root -m 0700 "$default_backup_dir"
      default_backup="$default_backup_dir/default.$(date -u +%Y%m%dT%H%M%SZ).$$.bak"
      cp -a -- "$default_site" "$default_backup"
      if [[ -L "$default_backup" ]]; then
        chown -h root:root "$default_backup"
      elif [[ -f "$default_backup" ]]; then
        chown root:root "$default_backup"
        chmod 0600 "$default_backup"
      else
        die "Backup do vhost default Nginx tem tipo inesperado; configuracao preservada."
      fi
      rm -- "$default_site"
      info "Vhost default do pacote Nginx substituído pelo default_server MoonShield; symlink original preservado em backup."
    else
      die "Vhost /etc/nginx/sites-enabled/default não é o padrão do pacote; nenhuma configuração foi substituída."
    fi
  elif [[ -e "$default_site" ]]; then
    die "Vhost default Nginx é arquivo regular; nenhuma configuração foi substituída."
  fi
  tls_temp="$tls_source"
  _services_install_managed_file "$tls_temp" "$destination" 0644
  if ! nginx -t; then
    if [[ -n "$_SERVICES_MANAGED_BACKUP_PATH" ]]; then
      cp -a -- "$_SERVICES_MANAGED_BACKUP_PATH" "$destination"
      warn "Configuração Nginx anterior restaurada após falha de validação."
    elif [[ "$_SERVICES_MANAGED_FILE_EXISTED" == 0 ]]; then
      rm -f -- "$destination"
    fi
    if [[ -n "$default_backup" ]]; then cp -a -- "$default_backup" "$default_site"; fi
    die "Nginx recusou a configuração; arquivo anterior preservado/restaurado."
  fi
  systemctl enable nginx.service >/dev/null
  systemctl reload nginx.service 2>/dev/null || systemctl start nginx.service
  systemctl is-active --quiet nginx.service || die "Nginx não iniciou após validar a configuração."
  ok "Nginx validado com proxy loopback e encaminhamento de headers."
}

install_systemd_services() {
  local source="$DEPLOY_DIR/systemd/moonshield-web.service" destination=/etc/systemd/system/moonshield-web.service
  local adguard_source="$DEPLOY_DIR/systemd/AdGuardHome.service"
  [[ -f "$source" ]] || die "Unit systemd moonshield-web.service ausente."
  [[ -f "$adguard_source" ]] || die "Unit systemd AdGuardHome.service ausente."
  _services_install_managed_file "$source" "$destination" 0644
  _services_install_managed_file "$adguard_source" /etc/systemd/system/AdGuardHome.service 0644
  systemctl daemon-reload
  systemctl enable moonshield-web.service >/dev/null
  systemctl enable AdGuardHome.service >/dev/null
  ok "Units web e AdGuard instaladas; AdGuard inicia ao receber topologia DNS válida."
}

provision_suricata_ruleset() {
  local config="$1" rules_dir=/var/lib/suricata/rules
  local moonshield_source=/opt/moonshield/source/MoonShield-Agent/suricata/regras_ms.rules
  local -a bundled_rules
  local moonshield_dir temp_rules temp_ms
  [[ -f "$moonshield_source" && -s "$moonshield_source" ]] \
    || die "Ruleset MoonShield versionado ausente ou vazio."
  [[ -f "$config" && ! -L "$config" ]] || die "suricata.yaml ausente ou é symlink; estado preservado."
  shopt -s nullglob
  bundled_rules=(/etc/suricata/rules/*.rules)
  shopt -u nullglob
  ((${#bundled_rules[@]} > 0)) \
    || die "Pacote Suricata não forneceu ruleset local em /etc/suricata/rules."
  install -d -o root -g root -m 0755 "$rules_dir"
  moonshield_dir="$rules_dir/moonshield"
  install -d -o root -g root -m 0755 "$moonshield_dir"
  temp_rules="$(mktemp "$rules_dir/.suricata.rules.XXXXXX")"
  TEMP_FILES+=("$temp_rules")
  "$DEPLOY_DIR/scripts/moonshield-suricata-rules-filter" "$config" "$temp_rules" "${bundled_rules[@]}" || die "Não foi possível filtrar o ruleset Debian conforme suricata.yaml."
  [[ -s "$temp_rules" ]] || die "Ruleset local do pacote Suricata ficou vazio."
  if [[ ! -s "$rules_dir/suricata.rules" ]] || ! cmp -s -- "$temp_rules" "$rules_dir/suricata.rules"; then
    install -o root -g root -m 0644 "$temp_rules" "$rules_dir/suricata.rules"
    info "Ruleset Debian publicado após filtrar protocolos desabilitados no suricata.yaml."
  else
    info "Ruleset Suricata existente já corresponde aos protocolos habilitados."
  fi
  if [[ ! -s "$moonshield_dir/ms.rules" ]]; then
    temp_ms="$(mktemp "$moonshield_dir/.ms.rules.XXXXXX")"
    TEMP_FILES+=("$temp_ms")
    install -o root -g root -m 0644 "$moonshield_source" "$temp_ms"
    mv -f -- "$temp_ms" "$moonshield_dir/ms.rules"
  else
    info "Regras MoonShield existentes preservadas durante repair."
  fi
  python3 - "$config" <<'PY' || die "Não foi possível incluir moonshield/ms.rules no suricata.yaml."
from pathlib import Path
import os
import stat
import tempfile
import sys

path = Path(sys.argv[1])
entry = "moonshield/ms.rules"
lines = path.read_text(encoding="utf-8", errors="strict").splitlines()
if not any(line.strip().lstrip("-").strip() == entry for line in lines):
    start = next(
        (index for index, line in enumerate(lines) if line.strip() == "rule-files:" and not line.startswith((" ", "\t"))),
        None,
    )
    if start is None:
        raise SystemExit("seção rule-files ausente")
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if line.strip() and not line.startswith((" ", "\t", "#")):
            end = index
            break
    lines.insert(end, f"  - {entry}")
    mode = stat.S_IMODE(path.stat().st_mode)
    fd, temporary = tempfile.mkstemp(prefix=".suricata.yaml.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as output:
            output.write("\n".join(lines) + "\n")
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
PY
  [[ -s "$rules_dir/suricata.rules" && -s "$moonshield_dir/ms.rules" ]] \
    || die "Ruleset Suricata não foi publicado corretamente."
  grep -Fqx '  - moonshield/ms.rules' "$config" \
    || die "suricata.yaml não referencia as regras MoonShield."
  info "Ruleset Suricata offline publicado com regras Debian e MoonShield; ET Open será atualizado somente após o onboarding."
}

_services_interface_exists() {
  local interface="$1"
  [[ "$interface" =~ ^[A-Za-z0-9_.:-]{1,64}$ && "$interface" != lo && -d "/sys/class/net/$interface" ]]
}

_services_bootstrap_capture_interface() {
  local route interface candidate
  while IFS= read -r route; do
    [[ "$route" =~ (^|[[:space:]])dev[[:space:]]+([^[:space:]]+) ]] || continue
    interface="${BASH_REMATCH[2]}"
    if _services_interface_exists "$interface"; then
      printf '%s\n' "$interface"
      return 0
    fi
  done < <(ip -o route show default 2>/dev/null || true)

  while IFS= read -r candidate; do
    if _services_interface_exists "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done < <(ip -o link show up 2>/dev/null | awk -F': ' '{split($2, name, "@"); if (name[1] != "lo") print name[1]}' | LC_ALL=C sort -u)
  return 1
}

_services_has_valid_runtime_capture() {
  local config="$1" interface
  local -a interfaces
  grep -Fqx '  # == MOONSHIELD RUNTIME ==' "$config" || return 1
  mapfile -t interfaces < <(python3 - "$config" <<'PY'
from pathlib import Path
import re
import sys

lines = Path(sys.argv[1]).read_text(encoding="utf-8", errors="strict").splitlines()
start = next((index for index, line in enumerate(lines) if line == "af-packet:"), None)
if start is None:
    raise SystemExit(0)
for line in lines[start + 1:]:
    if line.strip() and not line.startswith((" ", "\t", "#")):
        break
    match = re.match(r"^[ \t]+-[ \t]+interface:[ \t]*([^\s#]+)", line)
    if match:
        print(match.group(1))
PY
)
  ((${#interfaces[@]} > 0)) || return 1
  for interface in "${interfaces[@]}"; do
    _services_interface_exists "$interface" || return 1
  done
}

_services_prepare_suricata_bootstrap_capture() {
  local config="$1" interface
  if _services_has_valid_runtime_capture "$config"; then
    info "Captura Suricata ja segue a topologia MoonShield aplicada; bootstrap nao ira alterar interfaces."
    return 0
  fi
  interface="$(_services_bootstrap_capture_interface)" \
    || die "Nenhuma interface nao-loopback ativa foi encontrada para a captura provisoria do Suricata."
  python3 - "$config" "$interface" <<'PY' || die "Nao foi possivel preparar a captura provisoria do Suricata."
from pathlib import Path
import os
import re
import stat
import sys
import tempfile

path = Path(sys.argv[1])
interface = sys.argv[2]
if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", interface):
    raise SystemExit("interface invalida")
lines = path.read_text(encoding="utf-8", errors="strict").splitlines()
start = next((index for index, line in enumerate(lines) if line == "af-packet:"), None)
if start is None:
    raise SystemExit("secao af-packet ausente")
end = len(lines)
for index in range(start + 1, len(lines)):
    line = lines[index]
    if line.strip() and not line.startswith((" ", "\t", "#")):
        end = index
        break
block = [
    "af-packet:",
    "  # == MOONSHIELD BOOTSTRAP ==",
    f"  - interface: {interface}",
    "    threads: auto",
    "    cluster-id: 99",
    "    cluster-type: cluster_flow",
    "    defrag: yes",
]
content = "\n".join(lines[:start] + block + lines[end:]) + "\n"
metadata = path.stat()
fd, temporary = tempfile.mkstemp(prefix=".suricata.yaml.", dir=path.parent)
try:
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as output:
        output.write(content)
        output.flush()
        os.fsync(output.fileno())
    os.chmod(temporary, stat.S_IMODE(metadata.st_mode))
    os.chown(temporary, metadata.st_uid, metadata.st_gid)
    os.replace(temporary, path)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PY
  info "Captura Suricata provisoria configurada dinamicamente em $interface; o onboarding substituira somente apos aplicar a topologia oficial."
}

_services_start_suricata_checked() {
  local attempt line
  systemctl start suricata.service || warn "systemctl start suricata retornou falha; verificando liveness e journal."
  for attempt in 1 2 3; do
    if systemctl is-active --quiet suricata.service; then
      ok "Suricata ativo apos validacao da configuracao."
      return 0
    fi
    [[ "$attempt" == 3 ]] || sleep 1
  done
  while IFS= read -r line; do
    [[ -n "$line" ]] && log ERROR "Suricata journal: $line"
  done < <(journalctl -u suricata.service -n 30 --no-pager 2>/dev/null || true)
  die "Suricata nao ficou ativo apos tres verificacoes; consulte o journal acima."
}

provision_moonshield_local_services() {
  local django_dir=/opt/moonshield/source/MoonShield python_bin=/opt/moonshield/venv/bin/python
  [[ -x /opt/AdGuardHome/AdGuardHome ]] || die "Binário AdGuard não instalado."
  if systemctl is-active --quiet NetworkManager.service; then
    systemctl enable NetworkManager.service >/dev/null || die "Não foi possível habilitar NetworkManager."
    info "NetworkManager já estava ativo; estado de interfaces/perfis foi preservado."
  else
    warn "NetworkManager inativo; não será iniciado/habilitado automaticamente para evitar perda de conectividade."
  fi
  local suricata_config=/etc/suricata/suricata.yaml suricata_output line
  command -v suricata >/dev/null 2>&1 || die "Binário Suricata ausente antes da validação."
  [[ -s "$suricata_config" ]] || die "Configuração Suricata ausente ou vazia: $suricata_config."
  _services_prepare_suricata_bootstrap_capture "$suricata_config"
  provision_suricata_ruleset "$suricata_config"
  info "Validando Suricata antes de habilitar/iniciar: suricata -T -c $suricata_config"
  if suricata_output="$(suricata -T -c "$suricata_config" 2>&1)"; then
    while IFS= read -r line; do
      [[ -n "$line" ]] && info "Suricata -T: $line"
    done <<<"$suricata_output"
  else
    local suricata_status=$?
    while IFS= read -r line; do
      [[ -n "$line" ]] && log ERROR "Suricata -T ($suricata_config): $line"
    done <<<"$suricata_output"
    die "suricata -T falhou (exit=$suricata_status, config=$suricata_config); serviço não será habilitado nem iniciado."
  fi
  systemctl enable suricata.service >/dev/null || die "Não foi possível habilitar Suricata."
  _services_start_suricata_checked
  for unit in moonshield-agent.service moonshield-suricata-worker.service moonshield-firewall-worker.service moonshield-suricata-monitor.service; do
    if [[ -e "/etc/systemd/system/$unit" ]]; then
      cp -a -- "/etc/systemd/system/$unit" "/etc/systemd/system/$unit.backup.$(date -u +%Y%m%dT%H%M%SZ).$$"
    fi
  done
  (cd "$django_dir" && "$python_bin" gerenciar.py instalar_moonshield) || die "Bootstrap existente do Agent/AdGuard falhou."
  systemctl start moonshield-web.service || die "MoonShield web não iniciou."
  systemctl is-active --quiet moonshield-web.service || die "MoonShield web não ficou ativo."
  ok "Agent, AdGuard, Suricata e web iniciados sem substituir configuração padrão de nftables ou rede."
}

prepare_networkmanager_preonboarding() {
  local helper="$DEPLOY_DIR/scripts/moonshield-nm-preonboarding"
  [[ -x "$helper" ]] || chmod 0755 "$helper"
  "$helper" || die "Falha ao aplicar configuração pre-onboarding do NetworkManager."
  ok "NetworkManager pre-onboarding concluído."
}
