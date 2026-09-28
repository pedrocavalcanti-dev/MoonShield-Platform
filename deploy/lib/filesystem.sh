#!/usr/bin/env bash

ensure_os_identity() {
  if ! getent group moonshield >/dev/null; then
    groupadd --system moonshield
    ok "Grupo de sistema moonshield criado."
  else
    info "Grupo moonshield existente preservado."
  fi
  if ! getent passwd moonshield >/dev/null; then
    useradd --system --gid moonshield --home-dir /opt/moonshield --no-create-home --shell /usr/sbin/nologin moonshield
    ok "Usuário de sistema moonshield sem login criado."
  else
    info "Usuário moonshield existente preservado."
    usermod --append --groups moonshield moonshield
  fi
}

_ensure_dir() {
  local path="$1" owner="$2" group="$3" mode="$4"
  mkdir -p -- "$path"
  chown "$owner:$group" "$path"
  chmod "$mode" "$path"
}

ensure_filesystem() {
  _ensure_dir /opt/moonshield root root 0755
  _ensure_dir /etc/moonshield root moonshield 0750
  _ensure_dir /etc/moonshield/secrets root moonshield 0750
  _ensure_dir /etc/moonshield/rede root moonshield 0750
  _ensure_dir /etc/moonshield/firewall root moonshield 0750
  _ensure_dir /etc/moonshield/tls root root 0700
  _ensure_dir /var/lib/moonshield root moonshield 0751
  _ensure_dir /var/lib/moonshield/firewall root moonshield 0770
  _ensure_dir /var/lib/moonshield/rede root moonshield 0770
  _ensure_dir /var/lib/moonshield/dns root moonshield 0770
  _ensure_dir /var/lib/moonshield/suricata moonshield moonshield 0750
  _ensure_dir /var/lib/moonshield/static moonshield www-data 0750
  _ensure_dir /var/lib/moonshield/media moonshield www-data 0750
  _ensure_dir /var/log/moonshield root moonshield 0750
  _ensure_dir /var/log/moonshield/app moonshield moonshield 0750
  _ensure_dir /run/moonshield root moonshield 0750
  if [[ -d /opt/moonshield/source ]]; then
    chown root:root /opt/moonshield/source
    chmod 0755 /opt/moonshield/source
  fi
  ok "Diretórios MoonShield verificados sem recursão sobre estado existente."
}

install_source_release() {
  local source_target=/opt/moonshield/source temp_target
  [[ -f "$REPO_ROOT/MoonShield/gerenciar.py" && -d "$REPO_ROOT/MoonShield-Agent" ]] || die "Release precisa conter MoonShield/gerenciar.py e MoonShield-Agent/."
  if [[ -e "$source_target" ]]; then
    info "Source existente preservado em /opt/moonshield/source; instalação não sobrescreve release ativo."
    return 0
  fi
  temp_target="$(mktemp -d /opt/moonshield/source.new.XXXXXX)"
  TEMP_DIRS+=("$temp_target")
  tar -C "$REPO_ROOT" \
    --exclude=.git --exclude='*/.git' --exclude=.env --exclude='.env.*' \
    --exclude='*/.env' --exclude='*/.env.*' --exclude='*/__pycache__' \
    --exclude='*.pyc' --exclude='*.pyo' --exclude='*.sqlite3' --exclude='*.log' \
    --exclude='*/logs' --exclude='*/var' --exclude='*/media' --exclude='*/staticfiles' \
    --exclude='.venv' --exclude='*/.venv' --exclude='venv' --exclude='*/venv' \
    --exclude='build' --exclude='deploy/offline-bundle' \
    -cf - MoonShield MoonShield-Agent deploy requirements-prod.txt | tar -C "$temp_target" -xf -
  chown -R root:root "$temp_target"
  find "$temp_target" -type d -exec chmod 0755 {} +
  find "$temp_target" -type f -exec chmod go-w {} +
  mv -- "$temp_target" "$source_target"
  ok "Release copiado para /opt/moonshield/source sem .git, .env, logs, mídia ou DB local."
}

externalize_application_runtime() {
  local django_dir=/opt/moonshield/source/MoonShield
  local runtime_dir=/var/lib/moonshield/django
  [[ -d "$django_dir" ]] || die "Source Django ausente ao externalizar runtime."
  install -d -o moonshield -g moonshield -m 0750 "$runtime_dir/var/cursors"
  if [[ ! -e "$django_dir/var" && ! -L "$django_dir/var" ]]; then
    ln -s "$runtime_dir/var" "$django_dir/var"
  else
    info "Diretório var já existente no source preservado sem migração automática."
  fi
  if [[ ! -e "$django_dir/logs" && ! -L "$django_dir/logs" ]]; then
    ln -s /var/log/moonshield "$django_dir/logs"
  else
    info "Diretório logs já existente no source preservado sem migração automática."
  fi
}

write_appliance_config() {
  local config=/etc/moonshield/appliance.conf db_env=/etc/moonshield/database.env secret=/etc/moonshield/secrets/django_secret_key
  local hostname_value ip_values allowed https_settings="" cert=/etc/moonshield/tls/fullchain.pem key=/etc/moonshield/tls/privkey.pem
  if [[ -e "$cert" || -e "$key" ]]; then
    [[ -s "$cert" && -s "$key" ]] || die "Certificado/chave TLS incompletos; arquivos preservados."
    openssl x509 -in "$cert" -noout >/dev/null 2>&1 || die "Certificado TLS local inválido."
    openssl pkey -in "$key" -noout >/dev/null 2>&1 || die "Chave privada TLS local inválida."
    local cert_public key_public key_mode
    cert_public="$(openssl x509 -in "$cert" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
    key_public="$(openssl pkey -in "$key" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
    [[ -n "$cert_public" && "$cert_public" == "$key_public" ]] || die "Certificado TLS e chave privada não formam um par."
    key_mode="$(stat -c '%a:%U:%G' "$key" 2>/dev/null || true)"
    [[ "$key_mode" == 600:root:root ]] || die "Chave TLS deve ser root:root 0600; arquivo preservado."
    chown root:root "$cert"
    chmod 0644 "$cert"
    https_settings=$'\nSECURE_SSL_REDIRECT=True\nSESSION_COOKIE_SECURE=True\nCSRF_COOKIE_SECURE=True'
  fi
  if [[ -e "$config" ]]; then
    info "appliance.conf existente preservado."
  else
    hostname_value="$(hostname -f 2>/dev/null || hostname)"
    [[ "$hostname_value" =~ ^[A-Za-z0-9.-]+$ ]] || hostname_value=moonshield.local
    ip_values="$(ip -o -4 addr show scope global 2>/dev/null | awk '{sub(/\/.*/, "", $4); print $4}' | paste -sd, -)"
    allowed="localhost,127.0.0.1,::1,moonshield,moonshield.local,$hostname_value"
    [[ -z "$ip_values" ]] || allowed="$allowed,$ip_values"
    umask 027
    printf 'DEBUG=False\nDJANGO_ADMIN_ENABLED=False\nSECRET_KEY_FILE=%s\nALLOWED_HOSTS=%s%s\n' "$secret" "$allowed" "$https_settings" >"$config"
    chown root:moonshield "$config"
    chmod 0640 "$config"
  fi
  local config_mode
  config_mode="$(stat -c '%a:%U:%G' "$config" 2>/dev/null || true)"
  [[ "$config_mode" == 640:root:moonshield ]] || die "appliance.conf existente deve ser root:moonshield 0640; conteúdo preservado."
  grep -Fxq 'DEBUG=False' "$config" || die "appliance.conf deve declarar DEBUG=False; conteúdo preservado."
  grep -Fxq 'DJANGO_ADMIN_ENABLED=False' "$config" || die "appliance.conf deve manter Django Admin desabilitado; conteúdo preservado."
  grep -Fxq "SECRET_KEY_FILE=$secret" "$config" || die "appliance.conf deve apontar para o segredo persistente esperado; conteúdo preservado."
  if [[ -n "$https_settings" ]]; then
    grep -Fxq 'SECURE_SSL_REDIRECT=True' "$config" && grep -Fxq 'SESSION_COOKIE_SECURE=True' "$config" \
      && grep -Fxq 'CSRF_COOKIE_SECURE=True' "$config" \
      || die "TLS local existe, mas appliance.conf não habilita redirect/cookies seguros; conteúdo preservado para ajuste explícito."
  elif grep -Fxq 'SECURE_SSL_REDIRECT=True' "$config"; then
    die "appliance.conf exige HTTPS, mas certificado/chave da appliance não estão disponíveis; conteúdo preservado."
  fi
  if [[ ! -f "$secret" ]]; then
    openssl rand -base64 64 | tr -d '\n' >"$secret"
    chown root:moonshield "$secret"
    chmod 0640 "$secret"
    ok "SECRET_KEY aleatória gerada uma única vez e guardada fora do source."
  else
    info "SECRET_KEY existente preservada."
  fi
  [[ -s "$secret" ]] || die "SECRET_KEY vazia/inválida; não será substituída automaticamente."
  local secret_mode
  secret_mode="$(stat -c '%a:%U:%G' "$secret" 2>/dev/null || true)"
  [[ "$secret_mode" == 640:root:moonshield ]] || die "SECRET_KEY existente deve ser root:moonshield 0640; arquivo preservado."
  if [[ -f "$db_env" ]]; then
    info "database.env existente preservado; nenhuma senha PostgreSQL será trocada."
    chown root:moonshield "$db_env"
    chmod 0640 "$db_env"
  fi
}
