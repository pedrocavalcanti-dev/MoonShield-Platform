#!/bin/sh
set -eu

# Mantém defaults do Debian Installer, mas permite teste seguro em staging.
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

console_log() {
    printf '[MOONSHIELD ISO] %s\n' "$*"
    if command -v logger >/dev/null 2>&1; then
        logger -t moonshield-late-command -- "$*" >/dev/null 2>&1 || true
    fi
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

    # Nunca exponha um prompt de login Debian na appliance. A gate usa tty1
    # diretamente e os demais VTs permanecem indisponíveis ao operador.
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

fail() {
    reason="$*"
    console_log "ERRO: $reason"
    write_failure_state "$reason"
    if [ "$BOOTSTRAP_READY" -eq 1 ]; then
        enable_boot_gate >/dev/null 2>&1 || true
    fi
    exit 1
}

[ -d "$TARGET" ] || fail 'Diretório /target do Debian Installer ausente.'
mkdir -p "$LOG_DIR"
chmod 0750 "$LOG_DIR"
: >"$LOG"
chmod 0600 "$LOG"
exec >>"$LOG" 2>&1

console_log 'Iniciando late-command Alpha 2.'

# Primeiro valide somente o mínimo necessário para garantir uma tela MoonShield
# no próximo boot, inclusive se o restante do staging falhar.
[ -f "$RELEASE/deploy/console/maintenance_public.pem" ] || fail 'Chave pública de manutenção ausente na release.'
[ -f "$FIRSTBOOT/moonshield-firstboot.py" ] || fail 'Firstboot MoonShield ausente da mídia.'
[ -f "$FIRSTBOOT/moonshield-console-gate.py" ] || fail 'Console gate MoonShield ausente da mídia.'
[ -f "$FIRSTBOOT/moonshield-iso-firstboot.service" ] || fail 'Unit firstboot ausente da mídia.'
[ -f "$FIRSTBOOT/moonshield-iso-console-gate.service" ] || fail 'Unit console gate ausente da mídia.'

[ ! -e "$STAGE" ] && [ ! -L "$STAGE" ] || fail "Staging já existe no sistema alvo: $STAGE"
mkdir -p "$STAGE/release" "$STAGE/offline-bundle" "$STAGE/state" \
    "$RUNTIME" "$SYSTEMD" "$WANTS" "$PRODUCT_DIR" "$SUPPORT_DIR"
chmod 0700 "$STAGE" "$STAGE/state"

# Instala primeiro a infraestrutura de recuperação. Assim, mesmo se uma cópia
# posterior falhar e o operador mandar o d-i continuar, o próximo boot não cai
# em login Debian: a gate MoonShield mostra a falha e mantém F12 protegido.
console_log 'Preparando console gate e firstboot no sistema alvo.'
cp "$FIRSTBOOT/moonshield-firstboot.py" "$RUNTIME/moonshield-firstboot.py" || fail 'Falha ao copiar moonshield-firstboot.py.'
cp "$FIRSTBOOT/moonshield-console-gate.py" "$RUNTIME/moonshield-console-gate.py" || fail 'Falha ao copiar moonshield-console-gate.py.'
cp "$FIRSTBOOT/moonshield-iso-firstboot.service" "$SYSTEMD/moonshield-iso-firstboot.service" || fail 'Falha ao copiar unit firstboot.'
cp "$FIRSTBOOT/moonshield-iso-console-gate.service" "$SYSTEMD/moonshield-iso-console-gate.service" || fail 'Falha ao copiar unit console gate.'
cp "$RELEASE/deploy/console/maintenance_public.pem" "$SUPPORT_DIR/maintenance_public.pem" || fail 'Falha ao instalar chave pública de manutenção.'
chmod 0755 "$RUNTIME/moonshield-firstboot.py" "$RUNTIME/moonshield-console-gate.py"
chmod 0644 "$SYSTEMD/moonshield-iso-firstboot.service" "$SYSTEMD/moonshield-iso-console-gate.service" "$SUPPORT_DIR/maintenance_public.pem"
BOOTSTRAP_READY=1
enable_boot_gate || fail 'Falha ao habilitar gate/firstboot ou mascarar consoles Debian.'

# Daqui em diante qualquer erro continua protegido pela gate preparada acima.
# A integridade completa do bundle é validada no primeiro boot pelo Debian
# instalado, com coreutils completo.
[ -f "$RELEASE/deploy/install.sh" ] || fail 'Release tree ausente na mídia.'
[ -f "$BUNDLE/SHA256SUMS" ] || fail 'Offline bundle ausente ou sem SHA256SUMS.'

cat >"$STAGE/state/status.json" <<'JSON'
{
  "phase": "waiting",
  "message": "Aguardando início do provisionamento...",
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

if [ -f "$MEDIA/BUILD-INFO" ]; then
    cp "$MEDIA/BUILD-INFO" "$STAGE/BUILD-INFO" || fail 'Falha ao copiar BUILD-INFO.'
    chmod 0600 "$STAGE/BUILD-INFO"
fi

# O firstboot valida SHA256SUMS com /usr/bin/sha256sum do Debian instalado antes
# de executar deploy/install.sh. Evita depender das opções reduzidas do sha256sum
# presente no ambiente udeb/BusyBox do Debian Installer.
console_log 'Bootstrap preparado; integridade completa será validada no primeiro boot.'

# Ajuda a descarregar os dados copiados antes do reboot. Falha de sync não deve
# invalidar um staging já verificado.
sync 2>/dev/null || true
console_log 'Late-command concluído com sucesso.'
exit 0
