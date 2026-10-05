_console_backup_managed_file() {
  local path="$1" recovery=/var/lib/moonshield/recovery stamp destination
  [[ -e "$path" || -L "$path" ]] || return 0
  install -d -o root -g root -m 0700 "$recovery"
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  destination="$recovery/$(basename "$path").$stamp.$$.bak"
  cp -a -- "$path" "$destination"
  if [[ -L "$destination" ]]; then chown -h root:root "$destination"; else chown root:root "$destination"; chmod 0600 "$destination"; fi
  info "Copia de recuperacao criada em $destination"
}

_console_install_managed_file() {
  local source="$1" destination="$2" mode="$3" owner="$4" group="$5"
  [[ -f "$source" ]] || die "Arquivo da release ausente: $source"
  if [[ ! -L "$destination" && -f "$destination" ]] && cmp -s -- "$source" "$destination"; then
    chown "$owner:$group" "$destination"; chmod "$mode" "$destination"; return 0
  fi
  _console_backup_managed_file "$destination"
  [[ ! -L "$destination" ]] || rm -f -- "$destination"
  install -o "$owner" -g "$group" -m "$mode" "$source" "$destination"
}

_install_final_access_policy() {
  local tty unit_file unit_static
  for tty in 2 3 4 5 6; do
    unit_file="/etc/systemd/system/getty@tty${tty}.service"
    if [[ -L "$unit_file" && "$(readlink "$unit_file")" == /dev/null ]]; then continue; fi
    _console_backup_managed_file "$unit_file"
    [[ ! -e "$unit_file" && ! -L "$unit_file" ]] || rm -f -- "$unit_file"
    systemctl mask --now "getty@tty${tty}.service" >/dev/null
  done
  unit_static=/etc/systemd/system/getty-static.service
  if [[ ! -L "$unit_static" || "$(readlink "$unit_static")" != /dev/null ]]; then
    _console_backup_managed_file "$unit_static"
    [[ ! -e "$unit_static" && ! -L "$unit_static" ]] || rm -f -- "$unit_static"
    systemctl mask --now getty-static.service >/dev/null
  fi
  systemctl daemon-reload
  ok "Hardening final aplicado: getty TTY2-6 mascarados."
}

finalize_final_access_policy() {
  (( FINAL_ISO_MODE )) || return 0
  [[ -e /etc/moonshield/final-iso ]] || install -o root -g root -m 0644 /dev/null /etc/moonshield/final-iso
  _install_final_access_policy
  systemctl daemon-reload
  systemctl enable moonshield-console.service >/dev/null || die "Nao foi possivel habilitar a console MoonShield apos o hardening final."
  systemctl is-enabled --quiet moonshield-console.service || die "A console MoonShield nao ficou habilitada apos o hardening final."
}

validate_maintenance_public_key() {
  local public_key="$DEPLOY_DIR/console/maintenance_public.pem" key_details key_bits
  [[ -f "$public_key" ]] || die "Chave publica ausente; forneca deploy/console/maintenance_public.pem antes de --final-iso."
  command -v openssl >/dev/null 2>&1 || die "OpenSSL e necessario para validar a chave publica de manutencao."
  key_details="$(openssl pkey -pubin -in "$public_key" -text -noout 2>/dev/null)" || die "Chave publica de manutencao invalida."
  key_bits="$(printf '%s\n' "$key_details" | sed -nE 's/.*Public-Key: \(([0-9]+) bit\).*/\1/p' | head -n1)"
  [[ "$key_bits" =~ ^[0-9]+$ ]] && (( key_bits >= 3072 )) || die "Chave publica de manutencao deve ser RSA 3072 bits ou superior."
}

install_console() {
  local unit_source="$DEPLOY_DIR/systemd/moonshield-console.service" unit_target=/etc/systemd/system/moonshield-console.service
  local console_source="$DEPLOY_DIR/console/moonshield_console.py" check_source="$DEPLOY_DIR/scripts/moonshield-install-check"
  local diag_source="$DEPLOY_DIR/scripts/moonshield-diag" public_key="$DEPLOY_DIR/console/maintenance_public.pem"
  install -d -o root -g root -m 0755 /opt/moonshield/console /usr/local/sbin /etc/moonshield/support
  _console_install_managed_file "$console_source" /opt/moonshield/console/moonshield_console.py 0644 root root
  _console_install_managed_file "$check_source" /usr/local/sbin/moonshield-install-check 0755 root root
  _console_install_managed_file "$diag_source" /usr/local/sbin/moonshield-diag 0755 root root
  _console_install_managed_file "$unit_source" "$unit_target" 0644 root root
  if [[ -f "$public_key" ]]; then
    validate_maintenance_public_key
    _console_install_managed_file "$public_key" /etc/moonshield/support/maintenance_public.pem 0644 root root
  elif (( FINAL_ISO_MODE )); then
    validate_maintenance_public_key
  else
    warn "MAINTENANCE_PUBLIC_KEY=REQUIRED_BEFORE_ISO; Maintenance Mode ficara NOT PROVISIONED."
  fi
  if (( FINAL_ISO_MODE )); then [[ -e /etc/moonshield/final-iso ]] || install -o root -g root -m 0644 /dev/null /etc/moonshield/final-iso; fi
  systemctl daemon-reload
  systemctl enable moonshield-console.service >/dev/null || die "Nao foi possivel habilitar a console MoonShield."
  systemctl is-enabled --quiet moonshield-console.service || die "A console MoonShield nao ficou habilitada."
  ok "Console instalada e habilitada para TTY1; sera iniciada no proximo boot."
}
