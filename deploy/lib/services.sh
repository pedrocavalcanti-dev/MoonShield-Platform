#!/usr/bin/env bash

MANAGED_BACKUP_PATH=""
MANAGED_FILE_EXISTED=0

_backup_managed_file() {
  local source="$1" destination="$2" mode="$3" parent temp
  parent="$(dirname -- "$destination")"
  install -d -o root -g root -m 0755 "$parent"
  MANAGED_BACKUP_PATH=""
  MANAGED_FILE_EXISTED=0
  if [[ -e "$destination" ]]; then
    MANAGED_FILE_EXISTED=1
  fi
  if [[ "$MANAGED_FILE_EXISTED" == 1 ]] && ! cmp -s -- "$source" "$destination"; then
    MANAGED_BACKUP_PATH="${destination}.backup.$(date -u +%Y%m%dT%H%M%SZ).$$"
    cp -a -- "$destination" "$MANAGED_BACKUP_PATH"
    warn "Configuração anterior preservada em backup antes da atualização do arquivo gerenciado."
  fi
  temp="$(mktemp "$parent/.moonshield.XXXXXX")"
  TEMP_FILES+=("$temp")
  install -o root -g root -m "$mode" -- "$source" "$temp"
  mv -f -- "$temp" "$destination"
}

install_adguard_binary() {
  local artifact expected_url cache_dir
  local expected actual extraction archive_names adguard_version
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
  archive_names="$(tar -tzf "$artifact")" || die "Arquivo AdGuard inválido ou ilegível."
  printf '%s\n' "$archive_names" | awk 'index($0, "../") || $0 ~ /^\// || $0 !~ /^AdGuardHome\// { bad=1 } END { exit bad }' || die "Arquivo AdGuard contém caminhos inesperados."
  extraction="$(mktemp -d /opt/moonshield/adguard.extract.XXXXXX)"
  TEMP_DIRS+=("$extraction")
  tar --no-same-owner -xzf "$artifact" -C "$extraction"
  [[ -x "$extraction/AdGuardHome/AdGuardHome" ]] || die "Binário esperado ausente no artifact AdGuard."
  install -d -o root -g root -m 0755 /opt/AdGuardHome
  cp -a -- "$extraction/AdGuardHome/." /opt/AdGuardHome/
  chown -R root:root /opt/AdGuardHome
  chmod 0755 /opt/AdGuardHome/AdGuardHome
  adguard_version="$(/opt/AdGuardHome/AdGuardHome --version 2>&1 || true)"
  [[ "$adguard_version" == *"v0.107.79"* ]] || die "Binário AdGuard instalado não reporta v0.107.79; verificação falhou."
  ok "Binário AdGuard v0.107.79 instalado; serviço/configuração serão provisionados pelo bootstrap existente."
}

install_nginx_site() {
  local source="$DEPLOY_DIR/nginx/moonshield.conf" destination=/etc/nginx/conf.d/moonshield.conf
  local tls_source tls_temp cert=/etc/moonshield/tls/fullchain.pem key=/etc/moonshield/tls/privkey.pem
  local default_site=/etc/nginx/sites-enabled/default default_target default_backup=""
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
      default_backup="${default_site}.backup.$(date -u +%Y%m%dT%H%M%SZ).$$"
      cp -a -- "$default_site" "$default_backup"
      rm -- "$default_site"
      info "Vhost default do pacote Nginx substituído pelo default_server MoonShield; symlink original preservado em backup."
    else
      die "Vhost /etc/nginx/sites-enabled/default não é o padrão do pacote; nenhuma configuração foi substituída."
    fi
  elif [[ -e "$default_site" ]]; then
    die "Vhost default Nginx é arquivo regular; nenhuma configuração foi substituída."
  fi
  tls_temp="$tls_source"
  _backup_managed_file "$tls_temp" "$destination" 0644
  if ! nginx -t; then
    if [[ -n "$MANAGED_BACKUP_PATH" ]]; then
      cp -a -- "$MANAGED_BACKUP_PATH" "$destination"
      warn "Configuração Nginx anterior restaurada após falha de validação."
    elif [[ "$MANAGED_FILE_EXISTED" == 0 ]]; then
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
  _backup_managed_file "$source" "$destination" 0644
  _backup_managed_file "$adguard_source" /etc/systemd/system/AdGuardHome.service 0644
  systemctl daemon-reload
  systemctl enable moonshield-web.service >/dev/null
  systemctl enable AdGuardHome.service >/dev/null
  ok "Units web e AdGuard instaladas; AdGuard inicia ao receber topologia DNS válida."
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
  systemctl enable suricata.service >/dev/null || die "Não foi possível habilitar Suricata."
  systemctl start suricata.service || die "Suricata não iniciou com a configuração instalada."
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
