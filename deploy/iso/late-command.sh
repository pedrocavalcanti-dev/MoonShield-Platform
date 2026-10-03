#!/bin/sh
set -eu

# Mantem defaults do Debian Installer, mas permite teste seguro em staging.
MEDIA="${MOONSHIELD_MEDIA:-/cdrom/moonshield}"
RELEASE="$MEDIA/release"
BUNDLE="$MEDIA/offline-bundle"
FIRSTBOOT="$MEDIA/firstboot"
TARGET="${MOONSHIELD_TARGET:-/target}"
STAGE="$TARGET/var/lib/moonshield-iso-bootstrap"
RUNTIME="$TARGET/usr/local/lib/moonshield-iso"
SYSTEMD="$TARGET/etc/systemd/system"
WANTS="$SYSTEMD/multi-user.target.wants"
LOG_DIR="$TARGET/var/log/moonshield"
LOG="$LOG_DIR/late-command.log"
PRODUCT_DIR="$TARGET/var/lib/moonshield"
SUPPORT_DIR="$TARGET/etc/moonshield/support"
BOOTSTRAP_READY=0
ALPHA_DEBUG_MARKER="$TARGET/etc/moonshield/alpha-debug"

console_log() {
    printf '[MOONSHIELD ISO] %s\n' "$*"
    if command -v logger >/dev/null 2>&1; then
        logger -t moonshield-late-command -- "$*" >/dev/null 2>&1 || true
    fi
}

install_alpha_debug_ssh() {
    local apt_root="$TARGET/var/lib/moonshield-alpha-apt" source_list="$TARGET/etc/apt/moonshield-alpha-debug.list"
    local key_source="$SUPPORT_DIR/maintenance_public.pem" authorized_tmp="$TARGET/root/.ssh/authorized_keys.moonshield-tmp" key_bits

    [ -f "$RELEASE/deploy/ALPHA-DEBUG-SSH" ] || fail 'Marcador Alpha Debug SSH ausente na release.'
    grep -qx 'ALPHA_DEBUG_SSH=enabled' "$RELEASE/deploy/ALPHA-DEBUG-SSH" || fail 'Marcador Alpha Debug SSH invalido.'
    console_log 'WARNING: ALPHA DEBUG SSH ENABLED (chave publica, temporario para Alpha 2 DEV).'

    mkdir -p "$apt_root/lists/partial" "$apt_root/archives/partial" "$apt_root/sourceparts"
    printf 'deb [trusted=yes] file:/var/lib/moonshield-iso-bootstrap/offline-bundle ./\n' >"$source_list"
    chmod 0600 "$source_list"
    chroot "$TARGET" /usr/bin/apt-get \
        -o Dir::State::lists=/var/lib/moonshield-alpha-apt/lists \
        -o Dir::Cache::archives=/var/lib/moonshield-alpha-apt/archives \
        -o Dir::Etc::sourcelist=/etc/apt/moonshield-alpha-debug.list \
        -o Dir::Etc::sourceparts=/var/lib/moonshield-alpha-apt/sourceparts \
        -o APT::Sandbox::User=root -o Acquire::Languages=none \
        -o APT::Get::List-Cleanup=false update || fail 'Indice APT local nao preparou openssh-server.'
    chroot "$TARGET" /usr/bin/apt-get \
        -o Dir::State::lists=/var/lib/moonshield-alpha-apt/lists \
        -o Dir::Cache::archives=/var/lib/moonshield-alpha-apt/archives \
        -o Dir::Etc::sourcelist=/etc/apt/moonshield-alpha-debug.list \
        -o Dir::Etc::sourceparts=/var/lib/moonshield-alpha-apt/sourceparts \
        -o APT::Sandbox::User=root --no-download --no-install-recommends --yes \
        install openssh-server || fail 'Instalacao offline de openssh-server falhou.'

    [ -s "$key_source" ] || fail 'Chave publica de manutencao ausente no sistema alvo.'
    install -d -o root -g root -m 0700 "$TARGET/root/.ssh"
    chroot "$TARGET" /usr/bin/ssh-keygen -i -m PKCS8 -f /etc/moonshield/support/maintenance_public.pem >"$authorized_tmp" \
        || fail 'Conversao da chave publica para OpenSSH falhou.'
    [ -s "$authorized_tmp" ] && grep -q '^ssh-rsa ' "$authorized_tmp" \
        || fail 'Chave autorizada convertida nao e uma chave RSA OpenSSH valida.'
    key_bits="$(chroot "$TARGET" /usr/bin/ssh-keygen -lf /root/.ssh/authorized_keys.moonshield-tmp 2>/dev/null | awk 'NR == 1 {print $1}')"
    case "$key_bits" in ''|*[!0-9]*) fail 'Nao foi possivel validar o tamanho da chave SSH convertida.' ;; esac
    [ "$key_bits" -ge 3072 ] || fail 'Chave SSH de manutencao deve ter no minimo 3072 bits.'
    install -o root -g root -m 0600 "$authorized_tmp" "$TARGET/root/.ssh/authorized_keys"
    rm -f "$authorized_tmp"
    cat >"$TARGET/etc/ssh/sshd_config.d/00-moonshield-alpha-debug.conf" <<'EOF'
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
EOF
    chmod 0644 "$TARGET/etc/ssh/sshd_config.d/00-moonshield-alpha-debug.conf"
    chroot "$TARGET" /usr/sbin/sshd -t || fail 'Configuracao de SSH Alpha Debug rejeitada por sshd -t.'
    chroot "$TARGET" /bin/systemctl enable ssh.service || fail 'Nao foi possivel habilitar ssh.service no alvo.'
    install -o root -g root -m 0644 "$RELEASE/deploy/ALPHA-DEBUG-SSH" "$ALPHA_DEBUG_MARKER" || fail 'Falha ao instalar marcador Alpha Debug.'
    rm -f "$source_list"
    rm -rf "$apt_root"
    console_log 'Alpha Debug SSH preparado antes do firstboot; autenticacao somente por chave.'
}


preserve_installer_logs() {
    dest="$TARGET/var/log/moonshield/installer"
    mkdir -p "$dest" 2>/dev/null || return 0
    chmod 0700 "$dest" 2>/dev/null || true
    for src in /var/log/syslog /var/log/partman /var/log/hardware-summary /var/log/cdebconf; do
        if [ -f "$src" ] && [ ! -L "$src" ]; then
            name=$(basename "$src")
            cp "$src" "$dest/$name" 2>/dev/null || true
            chmod 0600 "$dest/$name" 2>/dev/null || true
        fi
    done
}

write_failure_state() {
    reason="$1"
    mkdir -p "$STAGE/state" "$PRODUCT_DIR" "$LOG_DIR" 2>/dev/null || true
    chmod 0700 "$STAGE" "$STAGE/state" 2>/dev/null || true
    cat >"$STAGE/state/status.json" <<'JSON' 2>/dev/null || true
{
  "phase": "failed",
  "message": "Falha ao preparar o provisionamento inicial.",
  "steps": {
    "base": "ok",
    "payload": "error",
    "platform": "pending",
    "health": "pending",
    "console": "pending"
  },
  "detail": "Consulte /var/log/moonshield/late-command.log"
}
JSON
    printf 'status=failed\nreason=%s\n' "$reason" >"$PRODUCT_DIR/.installation-failed" 2>/dev/null || true
    chmod 0600 "$PRODUCT_DIR/.installation-failed" 2>/dev/null || true
}

enable_boot_gate() {
    mkdir -p "$SYSTEMD" "$WANTS" 2>/dev/null || return 1

    # Nunca exponha prompt de login Debian. A gate usa tty1 e os demais VTs
    # permanecem indisponiveis ao operador.
    tty=1
    while [ "$tty" -le 6 ]; do
        unit="$SYSTEMD/getty@tty${tty}.service"
        rm -f "$unit" 2>/dev/null || true
        ln -s /dev/null "$unit" || return 1
        tty=$((tty + 1))
    done

    rm -f "$WANTS/moonshield-iso-console-gate.service" "$WANTS/moonshield-iso-firstboot.service" 2>/dev/null || true
    ln -s ../moonshield-iso-console-gate.service "$WANTS/moonshield-iso-console-gate.service" || return 1
    ln -s ../moonshield-iso-firstboot.service "$WANTS/moonshield-iso-firstboot.service" || return 1
    return 0
}

apply_installed_branding() {
    grub_defaults_src="$RELEASE/deploy/iso/templates/grub-installed.cfg"
    grub_theme_src="$RELEASE/deploy/iso/templates/moonshield-installed-theme.txt"
    grub_defaults_dir="$TARGET/etc/default/grub.d"
    grub_theme_dir="$TARGET/boot/grub/themes/moonshield"

    console_log 'Aplicando identidade MoonShield ao sistema instalado.'
    mkdir -p "$grub_defaults_dir" "$grub_theme_dir" "$TARGET/etc/moonshield" || return 1

    if [ -f "$grub_defaults_src" ]; then
        cp "$grub_defaults_src" "$grub_defaults_dir/99-moonshield.cfg" || return 1
        chmod 0644 "$grub_defaults_dir/99-moonshield.cfg" || return 1
    fi
    if [ -f "$grub_theme_src" ]; then
        cp "$grub_theme_src" "$grub_theme_dir/theme.txt" || return 1
        chmod 0644 "$grub_theme_dir/theme.txt" || return 1
    fi

    cat >"$TARGET/etc/issue" <<'EOF'
MOONSHIELD Appliance de Seguranca de Rede
Console local protegido
EOF
    cp "$TARGET/etc/issue" "$TARGET/etc/issue.net" 2>/dev/null || true
    cat >"$TARGET/etc/motd" <<'EOF'
MOONSHIELD Appliance
Acesso local gerenciado pela console MoonShield.
EOF
    cat >"$TARGET/etc/machine-info" <<'EOF'
PRETTY_HOSTNAME=MOONSHIELD
ICON_NAME=computer-server
CHASSIS=server
DEPLOYMENT=appliance
EOF
    cat >"$TARGET/etc/moonshield/release" <<'EOF'
MOONSHIELD_VERSION=0.1.0-alpha.2
BASE_OS=Debian 13
EDITION=Alpha 2
EOF
    if [ -f "$MEDIA/BUILD-INFO" ]; then
        cp "$MEDIA/BUILD-INFO" "$TARGET/etc/moonshield/build-info" || return 1
        chmod 0644 "$TARGET/etc/moonshield/build-info" || return 1
    fi
    chmod 0644 "$TARGET/etc/issue" "$TARGET/etc/issue.net" "$TARGET/etc/motd" "$TARGET/etc/machine-info" "$TARGET/etc/moonshield/release" 2>/dev/null || true

    # Gera o GRUB definitivo com GRUB_DISTRIBUTOR=MOONSHIELD. Branding nao deve
    # invalidar uma instalacao funcional; se update-grub falhar, aplicamos um
    # fallback textual ao grub.cfg ja gerado pelo Debian Installer.
    if command -v in-target >/dev/null 2>&1; then
        if ! in-target update-grub; then
            console_log 'AVISO: update-grub falhou; aplicando fallback de rotulos.'
        fi
    elif [ -x "$TARGET/usr/sbin/update-grub" ]; then
        if ! chroot "$TARGET" /usr/sbin/update-grub; then
            console_log 'AVISO: update-grub via chroot falhou; aplicando fallback de rotulos.'
        fi
    fi

    if [ -f "$TARGET/boot/grub/grub.cfg" ]; then
        sed -i \
            -e 's/Debian GNU\/Linux/MOONSHIELD/g' \
            -e 's/MOONSHIELD GNU\/Linux/MOONSHIELD/g' \
            -e 's/Advanced options for MOONSHIELD/Opcoes avancadas do MOONSHIELD/g' \
            "$TARGET/boot/grub/grub.cfg" 2>/dev/null || true
        console_log 'Entradas GRUB instaladas:'
        grep -E '^[[:space:]]*menuentry ' "$TARGET/boot/grub/grub.cfg" 2>/dev/null | head -n 4 || true
    fi
    return 0
}

fail() {
    reason="$*"
    console_log "ERRO: $reason"
    write_failure_state "$reason"
    if [ "$BOOTSTRAP_READY" -eq 1 ]; then
        enable_boot_gate >/dev/null 2>&1 || true
    fi
    preserve_installer_logs
    exit 1
}

[ -d "$TARGET" ] || fail 'Diretorio /target do Debian Installer ausente.'
mkdir -p "$LOG_DIR"
chmod 0750 "$LOG_DIR"
: >"$LOG"
chmod 0600 "$LOG"
exec >>"$LOG" 2>&1

console_log 'Iniciando late-command Alpha 2.'

# Valide primeiro o minimo necessario para garantir uma tela MoonShield no
# proximo boot, inclusive se o restante do staging falhar.
[ -f "$RELEASE/deploy/console/maintenance_public.pem" ] || fail 'Chave publica de manutencao ausente na release.'
[ -f "$FIRSTBOOT/moonshield-firstboot.py" ] || fail 'Firstboot MoonShield ausente da midia.'
[ -f "$FIRSTBOOT/moonshield-console-gate.py" ] || fail 'Console gate MoonShield ausente da midia.'
[ -f "$FIRSTBOOT/moonshield-iso-firstboot.service" ] || fail 'Unit firstboot ausente da midia.'
[ -f "$FIRSTBOOT/moonshield-iso-console-gate.service" ] || fail 'Unit console gate ausente da midia.'

[ ! -e "$STAGE" ] && [ ! -L "$STAGE" ] || fail "Staging ja existe no sistema alvo: $STAGE"
mkdir -p "$STAGE/release" "$STAGE/offline-bundle" "$STAGE/state" \
    "$RUNTIME" "$SYSTEMD" "$WANTS" "$PRODUCT_DIR" "$SUPPORT_DIR"
chmod 0700 "$STAGE" "$STAGE/state"

console_log 'Preparando console gate e firstboot no sistema alvo.'
cp "$FIRSTBOOT/moonshield-firstboot.py" "$RUNTIME/moonshield-firstboot.py" || fail 'Falha ao copiar moonshield-firstboot.py.'
cp "$FIRSTBOOT/moonshield-console-gate.py" "$RUNTIME/moonshield-console-gate.py" || fail 'Falha ao copiar moonshield-console-gate.py.'
cp "$FIRSTBOOT/moonshield-iso-firstboot.service" "$SYSTEMD/moonshield-iso-firstboot.service" || fail 'Falha ao copiar unit firstboot.'
cp "$FIRSTBOOT/moonshield-iso-console-gate.service" "$SYSTEMD/moonshield-iso-console-gate.service" || fail 'Falha ao copiar unit console gate.'
cp "$RELEASE/deploy/console/maintenance_public.pem" "$SUPPORT_DIR/maintenance_public.pem" || fail 'Falha ao instalar chave publica de manutencao.'
chmod 0755 "$RUNTIME/moonshield-firstboot.py" "$RUNTIME/moonshield-console-gate.py"
chmod 0644 "$SYSTEMD/moonshield-iso-firstboot.service" "$SYSTEMD/moonshield-iso-console-gate.service" "$SUPPORT_DIR/maintenance_public.pem"
BOOTSTRAP_READY=1
enable_boot_gate || fail 'Falha ao habilitar gate/firstboot ou mascarar consoles Debian.'

# Branding e feito antes do staging pesado. Falha visual nao deve impedir boot
# seguro, portanto apenas registramos aviso se o update do GRUB nao funcionar.
apply_installed_branding || console_log 'AVISO: identidade visual do sistema instalado ficou parcial.'

# Daqui em diante qualquer erro continua protegido pela gate.
[ -f "$RELEASE/deploy/install.sh" ] || fail 'Release tree ausente na midia.'
[ -f "$BUNDLE/SHA256SUMS" ] || fail 'Offline bundle ausente ou sem SHA256SUMS.'
[ -f "$BUNDLE/BUILD-INFO" ] || fail 'Offline bundle ausente ou sem BUILD-INFO.'
[ -f "$RELEASE/deploy/scripts/moonshield-diag" ] || fail 'Comando moonshield-diag ausente na release.'
mkdir -p "$TARGET/usr/local/sbin"
install -o root -g root -m 0755 "$RELEASE/deploy/scripts/moonshield-diag" "$TARGET/usr/local/sbin/moonshield-diag" \
    || fail 'Falha ao instalar moonshield-diag para uso no Modo Seguro.'

cat >"$STAGE/state/status.json" <<'JSON'
{
  "phase": "waiting",
  "message": "Aguardando inicio do provisionamento...",
  "steps": {
    "base": "ok",
    "payload": "pending",
    "platform": "pending",
    "health": "pending",
    "console": "pending"
  },
  "detail": ""
}
JSON
chmod 0600 "$STAGE/state/status.json"

console_log 'Copiando release MoonShield para o sistema alvo.'
cp -a "$RELEASE/." "$STAGE/release/" || fail 'Falha ao copiar a release MoonShield.'
[ -f "$STAGE/release/deploy/install.sh" ] || fail 'Release copiada ficou incompleta.'

console_log 'Copiando bundle offline para o sistema alvo.'
cp -a "$BUNDLE/." "$STAGE/offline-bundle/" || fail 'Falha ao copiar o bundle offline.'
[ -f "$STAGE/offline-bundle/SHA256SUMS" ] || fail 'Bundle copiado ficou incompleto.'

install_alpha_debug_ssh

if [ -f "$MEDIA/BUILD-INFO" ]; then
    cp "$MEDIA/BUILD-INFO" "$STAGE/BUILD-INFO" || fail 'Falha ao copiar BUILD-INFO.'
    chmod 0600 "$STAGE/BUILD-INFO"
fi

console_log 'Bootstrap preparado; integridade completa sera validada no primeiro boot.'
sync 2>/dev/null || true
preserve_installer_logs
console_log 'Late-command concluido com sucesso.'
exit 0
