_console_backup_managed_file() {
  local path="$1" recovery=/var/lib/moonshield/recovery
  [[ -e "$path" || -L "$path" ]] || return 0
  install -d -o root -g root -m 0700 "$recovery"
  local stamp destination
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  destination="$recovery/$(basename "$path").$stamp.$$.bak"
  cp -a -- "$path" "$destination"
  if [[ -L "$destination" ]]; then
    chown -h root:root "$destination"
  elif [[ -f "$destination" ]]; then
    chown root:root "$destination"
    chmod 0600 "$destination"
  else
    die "Tipo de arquivo inesperado ao criar backup: $destination"
  fi
  info "Cópia de recuperação criada em $destination"
}

_console_install_managed_file() {
  local source="$1" destination="$2" mode="$3" owner="$4" group="$5"
  [[ -f "$source" ]] || die "Arquivo da release ausente: $source"
  if [[ ! -L "$destination" && -f "$destination" ]] && cmp -s -- "$source" "$destination"; then
    chown "$owner:$group" "$destination"
    chmod "$mode" "$destination"
    return 0
  fi
  _console_backup_managed_file "$destination"
  [[ ! -L "$destination" ]] || rm -f -- "$destination"
  install -o "$owner" -g "$group" -m "$mode" "$source" "$destination"
}

_remove_alpha_debug_access() {
  local alpha_policy=/etc/ssh/sshd_config.d/00-moonshield-alpha-debug.conf unit
  for unit in moonshield-alpha-debug-ssh-bootstrap.service moonshield-alpha-debug-ssh-firewall.service; do
    if systemctl list-unit-files --no-legend "$unit" 2>/dev/null | grep -q "^$unit"; then
      systemctl disable --now "$unit" >/dev/null 2>&1 \
        || die "Não foi possível desabilitar $unit após o provisionamento."
    fi
  done
  if command -v nft >/dev/null 2>&1 && nft list table inet moonshield_alpha_debug >/dev/null 2>&1; then
    nft delete table inet moonshield_alpha_debug \
      || die "Não foi possível remover a regra temporária do Alpha Debug SSH."
  fi
  _console_backup_managed_file "$alpha_policy"
  rm -f -- "$alpha_policy" /etc/moonshield/alpha-debug \
    /var/lib/moonshield/.alpha-debug-ssh-ready \
    /var/lib/moonshield/.alpha-debug-ssh-failed \
    /etc/apt/moonshield-alpha-debug.list
}

_install_final_access_policy() {
  local tty unit_file ssh_dir ssh_policy unit_static
  if [[ -f /etc/moonshield/final-iso && -f /etc/moonshield/alpha-debug ]]; then
    _remove_alpha_debug_access
  fi
  for tty in 2 3 4 5 6; do
    unit_file="/etc/systemd/system/getty@tty${tty}.service"
    if [[ -L "$unit_file" && "$(readlink "$unit_file")" == /dev/null ]]; then
      continue
    fi
    _console_backup_managed_file "$unit_file"
    [[ ! -e "$unit_file" && ! -L "$unit_file" ]] || rm -f -- "$unit_file"
    systemctl mask --now "getty@tty${tty}.service" >/dev/null
  done

  unit_static="/etc/systemd/system/getty-static.service"
  if [[ ! -L "$unit_static" || "$(readlink "$unit_static")" != /dev/null ]]; then
    _console_backup_managed_file "$unit_static"
    [[ ! -e "$unit_static" && ! -L "$unit_static" ]] || rm -f -- "$unit_static"
    systemctl mask --now getty-static.service >/dev/null
  fi

  if [[ -f /etc/moonshield/alpha-debug ]]; then
    ssh_dir=/etc/ssh/sshd_config.d
    ssh_policy="$ssh_dir/00-moonshield-alpha-debug.conf"
    bootstrap_unit=/etc/systemd/system/moonshield-alpha-debug-ssh-bootstrap.service
    bootstrap_script=/usr/local/lib/moonshield-iso/moonshield-alpha-debug-ssh-bootstrap.sh
    firewall_unit=/etc/systemd/system/moonshield-alpha-debug-ssh-firewall.service
    if [[ -f /var/lib/moonshield/.alpha-debug-ssh-failed ]]; then
      warn "Alpha Debug SSH falhou; consulte /var/log/moonshield/alpha-debug-ssh.log."
      return 0
    fi
    if [[ ! -f /var/lib/moonshield/.alpha-debug-ssh-ready ]]; then
      warn "Alpha Debug SSH ainda esta preparando; politica final de SSH sera preservada."
      return 0
    fi
    [[ -d "$ssh_dir" && -s /root/.ssh/authorized_keys && -f "$ssh_policy" \
      && -f "$bootstrap_unit" && -x "$bootstrap_script" && -f "$firewall_unit" ]] \
      || die "Alpha Debug SSH marcado, mas chave/configuracao/restricao de rede esta ausente."
    grep -Fxq 'PermitRootLogin prohibit-password' "$ssh_policy" \
      && grep -Fxq 'PasswordAuthentication no' "$ssh_policy" \
      && grep -Fxq 'KbdInteractiveAuthentication no' "$ssh_policy" \
      && grep -Fxq 'PubkeyAuthentication yes' "$ssh_policy" \
      && grep -Fxq 'AuthenticationMethods publickey' "$ssh_policy" \
      || die "Politica de autenticacao Alpha Debug SSH invalida."
    sshd -t || die "PolÃ­tica Alpha Debug SSH invÃ¡lida."
    systemctl daemon-reload
    systemctl enable moonshield-alpha-debug-ssh-bootstrap.service moonshield-alpha-debug-ssh-firewall.service >/dev/null \
      || die "NÃ£o foi possÃ­vel manter a restricao de interface do SSH Alpha Debug."
    systemctl enable ssh.service >/dev/null \
      || die "NÃ£o foi possÃ­vel manter ssh.service habilitado no Alpha Debug."
    ok "Alpha Debug SSH ativo somente por chave pÃºblica; TCP/22 restrito a enp0s3."
    return 0
  fi

  ssh_dir=/etc/ssh/sshd_config.d
  ssh_policy="$ssh_dir/00-moonshield-appliance.conf"
  if [[ -d /etc/ssh ]]; then
    [[ ! -L "$ssh_dir" ]] || die "Diretório SSH é symlink; política preservada sem alteração."
    install -d -o root -g root -m 0755 "$ssh_dir"
    local temp_policy
    temp_policy="$(mktemp)"
    TEMP_FILES+=("$temp_policy")
    cat >"$temp_policy" <<'EOF'
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
EOF
    if [[ -L "$ssh_policy" ]] || [[ ! -f "$ssh_policy" ]] || ! cmp -s -- "$temp_policy" "$ssh_policy"; then
      _console_backup_managed_file "$ssh_policy"
      [[ ! -L "$ssh_policy" ]] || rm -f -- "$ssh_policy"
      install -o root -g root -m 0644 "$temp_policy" "$ssh_policy"
    fi
    rm -f -- "$temp_policy"
    if command -v sshd >/dev/null 2>&1; then
      sshd -t || die "Política SSH inválida; serviço SSH não será desabilitado."
    fi
    for unit in ssh.service ssh.socket; do
      if systemctl list-unit-files --no-legend "$unit" 2>/dev/null | grep -q "^$unit"; then
        systemctl disable --now "$unit" >/dev/null 2>&1 || die "Não foi possível desabilitar $unit no modo final ISO."
      fi
    done
  else
    warn "openssh-server ausente; nenhuma política SSH foi instalada."
  fi
  systemctl daemon-reload
  ok "Hardening final aplicado: getty TTY2-6 mascarados e SSH desabilitado."
}

finalize_final_access_policy() {
  (( FINAL_ISO_MODE )) || return 0
  [[ -e /etc/moonshield/final-iso ]] || install -o root -g root -m 0644 /dev/null /etc/moonshield/final-iso
  _install_final_access_policy
  systemctl daemon-reload
  systemctl enable moonshield-console.service >/dev/null \
    || die "Não foi possível habilitar a console MoonShield após o hardening final."
  systemctl is-enabled --quiet moonshield-console.service \
    || die "A console MoonShield não ficou habilitada após o hardening final."
}

validate_maintenance_public_key() {
  local public_key="$DEPLOY_DIR/console/maintenance_public.pem" key_details key_bits
  [[ -f "$public_key" ]] || die "Chave pública ausente; forneça deploy/console/maintenance_public.pem antes de --final-iso."
  command -v openssl >/dev/null 2>&1 || die "OpenSSL é necessário para validar a chave pública de manutenção."
  key_details="$(openssl pkey -pubin -in "$public_key" -text -noout 2>/dev/null)" || die "Chave pública de manutenção inválida."
  key_bits="$(printf '%s\n' "$key_details" | sed -nE 's/.*Public-Key: \(([0-9]+) bit\).*/\1/p' | head -n1)"
  [[ "$key_bits" =~ ^[0-9]+$ ]] && (( key_bits >= 3072 )) || die "Chave pública de manutenção deve ser RSA 3072 bits ou superior."
}

install_console() {
  local unit_source="$DEPLOY_DIR/systemd/moonshield-console.service"
  local unit_target=/etc/systemd/system/moonshield-console.service
  local console_source="$DEPLOY_DIR/console/moonshield_console.py"
  local check_source="$DEPLOY_DIR/scripts/moonshield-install-check"
  local diag_source="$DEPLOY_DIR/scripts/moonshield-diag"
  local public_key="$DEPLOY_DIR/console/maintenance_public.pem"
  install -d -o root -g root -m 0755 /opt/moonshield/console /usr/local/sbin
  _console_install_managed_file "$console_source" /opt/moonshield/console/moonshield_console.py 0644 root root
  _console_install_managed_file "$check_source" /usr/local/sbin/moonshield-install-check 0755 root root
  _console_install_managed_file "$diag_source" /usr/local/sbin/moonshield-diag 0755 root root
  install -d -o root -g root -m 0755 /etc/moonshield/support
  _console_install_managed_file "$unit_source" "$unit_target" 0644 root root
  if [[ -f "$public_key" ]]; then
    validate_maintenance_public_key
    _console_install_managed_file "$public_key" /etc/moonshield/support/maintenance_public.pem 0644 root root
  elif (( FINAL_ISO_MODE )); then
    validate_maintenance_public_key
  else
    warn "MAINTENANCE_PUBLIC_KEY=REQUIRED_BEFORE_ISO; Maintenance Mode ficará NOT PROVISIONED."
  fi
  if (( FINAL_ISO_MODE )); then
    [[ -e /etc/moonshield/final-iso ]] || install -o root -g root -m 0644 /dev/null /etc/moonshield/final-iso
  fi
  systemctl daemon-reload
  systemctl enable moonshield-console.service >/dev/null \
    || die "Não foi possível habilitar a console MoonShield."
  systemctl is-enabled --quiet moonshield-console.service \
    || die "A console MoonShield não ficou habilitada."
  ok "Console instalada e habilitada para TTY1; será iniciada no próximo boot."
}
