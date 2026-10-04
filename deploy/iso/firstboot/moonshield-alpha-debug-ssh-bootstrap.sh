#!/bin/sh
set -u

MARKER=/etc/moonshield/alpha-debug
PRODUCT_DIR=/var/lib/moonshield
BUNDLE=/var/lib/moonshield-iso-bootstrap/offline-bundle
APT_ROOT=/var/lib/moonshield-alpha-debug-apt
SOURCE_LIST=/etc/apt/moonshield-alpha-debug.list
SOURCE_PARTS="$APT_ROOT/sourceparts"
LOG_DIR=/var/log/moonshield
LOG_FILE="$LOG_DIR/alpha-debug-ssh.log"
READY_MARKER="$PRODUCT_DIR/.alpha-debug-ssh-ready"
FAILED_MARKER="$PRODUCT_DIR/.alpha-debug-ssh-failed"
FIREWALL_SERVICE=moonshield-alpha-debug-ssh-firewall.service

log() {
    printf '[MOONSHIELD ALPHA DEBUG SSH] %s\n' "$*"
}

fail() {
    message="$*"
    rm -f "$READY_MARKER"
    printf 'status=failed\nreason=%s\n' "$message" >"$FAILED_MARKER"
    chmod 0600 "$FAILED_MARKER"
    log "ERRO: $message"
    exit 0
}

require_installed() {
    package="$1"
    dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -qx 'install ok installed' \
        || fail "Pacote critico ausente apos APT: $package"
}

apply_firewall() {
    [ -f "$MARKER" ] || exit 0
    command -v nft >/dev/null 2>&1 || exit 1
    nft delete table inet moonshield_alpha_debug 2>/dev/null || true
    nft -f - <<'RULESET'
table inet moonshield_alpha_debug {
    chain input {
        type filter hook input priority -200; policy accept;
        iifname "enp0s3" tcp dport 22 accept comment "MoonShield Alpha Debug SSH: enp0s3 only"
        tcp dport 22 drop comment "MoonShield Alpha Debug SSH: deny non-enp0s3"
    }
}
RULESET
}

bootstrap() {
    [ -f "$MARKER" ] || exit 0
    mkdir -p "$PRODUCT_DIR" "$LOG_DIR" "$APT_ROOT/lists/partial" "$APT_ROOT/archives/partial" "$SOURCE_PARTS" \
        || fail 'Nao foi possivel preparar diretorios do bootstrap SSH.'
    chmod 0700 "$APT_ROOT" "$SOURCE_PARTS" || fail 'Permissoes do APT Alpha Debug invalidas.'
    chmod 0750 "$LOG_DIR" || fail 'Permissoes do diretorio de logs invalidas.'
    : >"$LOG_FILE" || fail 'Nao foi possivel criar o log Alpha Debug SSH.'
    chmod 0600 "$LOG_FILE" || fail 'Permissoes do log Alpha Debug SSH invalidas.'
    exec >>"$LOG_FILE" 2>&1

    [ -f "$BUNDLE/Packages" ] && [ -f "$BUNDLE/Packages.gz" ] || fail 'Bundle offline APT ausente ou incompleto.'
    [ -s /etc/moonshield/support/maintenance_public.pem ] || fail 'Chave publica de manutencao ausente.'
    printf 'deb [trusted=yes] file:%s ./\n' "$BUNDLE" >"$SOURCE_LIST" || fail 'Nao foi possivel criar source APT local.'
    chmod 0600 "$SOURCE_LIST" || fail 'Permissoes do source APT local invalidas.'

    log 'Preparando indice APT local.'
    apt-get \
        -o "Dir::State::lists=$APT_ROOT/lists" \
        -o "Dir::Cache::archives=$APT_ROOT/archives" \
        -o "Dir::Etc::sourcelist=$SOURCE_LIST" \
        -o "Dir::Etc::sourceparts=$SOURCE_PARTS" \
        -o APT::Sandbox::User=root -o Acquire::Languages=none \
        -o APT::Get::List-Cleanup=false update || fail 'Indice APT local falhou.'
    log 'Instalando openssh-server e nftables do bundle local.'
    apt-get \
        -o "Dir::State::lists=$APT_ROOT/lists" \
        -o "Dir::Cache::archives=$APT_ROOT/archives" \
        -o "Dir::Etc::sourcelist=$SOURCE_LIST" \
        -o "Dir::Etc::sourceparts=$SOURCE_PARTS" \
        -o APT::Sandbox::User=root --no-install-recommends --yes \
        install openssh-server nftables || fail 'Instalacao offline de openssh-server/nftables falhou.'
    require_installed openssh-server
    require_installed nftables
    for binary in /usr/sbin/sshd /usr/bin/ssh-keygen /usr/sbin/nft; do
        [ -x "$binary" ] || fail "Binario critico ausente apos APT: $binary"
    done

    install -d -o root -g root -m 0700 /root/.ssh /run/sshd \
        || fail 'Nao foi possivel preparar diretorios SSH.'
    ssh-keygen -i -m PKCS8 -f /etc/moonshield/support/maintenance_public.pem > /root/.ssh/authorized_keys.moonshield-tmp \
        || fail 'Conversao da chave publica para OpenSSH falhou.'
    [ -s /root/.ssh/authorized_keys.moonshield-tmp ] \
        && grep -q '^ssh-rsa ' /root/.ssh/authorized_keys.moonshield-tmp \
        || fail 'Chave autorizada convertida nao e uma chave RSA OpenSSH valida.'
    key_bits="$(ssh-keygen -lf /root/.ssh/authorized_keys.moonshield-tmp 2>/dev/null | awk 'NR == 1 {print $1}')"
    case "$key_bits" in ''|*[!0-9]*) fail 'Nao foi possivel validar o tamanho da chave SSH convertida.' ;; esac
    [ "$key_bits" -ge 3072 ] || fail 'Chave SSH de manutencao deve ter no minimo 3072 bits.'
    install -o root -g root -m 0600 /root/.ssh/authorized_keys.moonshield-tmp /root/.ssh/authorized_keys
    rm -f /root/.ssh/authorized_keys.moonshield-tmp

    install -d -o root -g root -m 0755 /etc/ssh/sshd_config.d \
        || fail 'Nao foi possivel preparar a configuracao SSH.'
    if ! cat >/etc/ssh/sshd_config.d/00-moonshield-alpha-debug.conf <<'EOF'
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
EOF
    then
        fail 'Nao foi possivel gravar a configuracao SSH Alpha Debug.'
    fi
    chmod 0644 /etc/ssh/sshd_config.d/00-moonshield-alpha-debug.conf \
        || fail 'Permissoes da configuracao SSH Alpha Debug invalidas.'
    ssh-keygen -A || fail 'Geracao de host keys SSH falhou.'
    find /etc/ssh -maxdepth 1 -type f -name 'ssh_host_*_key' -size +0c -print -quit | grep -q . \
        || fail 'Nenhuma host key SSH foi encontrada.'
    sshd -t || fail 'sshd -t rejeitou a configuracao Alpha Debug.'

    systemctl daemon-reload || fail 'systemd daemon-reload falhou.'
    systemctl enable --now nftables.service || fail 'Nao foi possivel habilitar/iniciar nftables.service.'
    systemctl enable --now "$FIREWALL_SERVICE" || fail 'Nao foi possivel habilitar/iniciar a restricao de interface SSH.'
    systemctl enable --now ssh.service || fail 'Nao foi possivel habilitar/iniciar ssh.service.'
    systemctl is-active --quiet "$FIREWALL_SERVICE" || fail 'Restricao de interface SSH nao ficou ativa.'
    systemctl is-active --quiet ssh.service || fail 'ssh.service nao ficou ativo.'

    rm -f "$FAILED_MARKER" || fail 'Nao foi possivel limpar marcador de falha SSH anterior.'
    printf 'status=ready\n' >"$READY_MARKER" || fail 'Nao foi possivel gravar marcador SSH pronto.'
    chmod 0600 "$READY_MARKER" || fail 'Permissoes do marcador SSH pronto invalidas.'
    rm -f "$SOURCE_LIST" || log 'AVISO: source APT temporario sera preservado para diagnostico.'
    log 'Alpha Debug SSH pronto: chave publica somente, TCP/22 restrito a enp0s3.'
}

case "${1:-bootstrap}" in
    bootstrap) bootstrap ;;
    firewall) apply_firewall ;;
    *) printf '%s\n' "uso: $0 [bootstrap|firewall]" >&2; exit 2 ;;
esac
