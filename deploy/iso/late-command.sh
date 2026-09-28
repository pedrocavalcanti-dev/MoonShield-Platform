#!/bin/sh
set -eu

MEDIA=/cdrom/moonshield
RELEASE="$MEDIA/release"
BUNDLE="$MEDIA/offline-bundle"
FIRSTBOOT="$MEDIA/firstboot"
TARGET=/target
STAGE="$TARGET/var/lib/moonshield-iso-bootstrap"
RUNTIME="$TARGET/usr/local/lib/moonshield-iso"
SYSTEMD="$TARGET/etc/systemd/system"
WANTS="$SYSTEMD/multi-user.target.wants"
LOG_DIR="$TARGET/var/log/moonshield"
LOG="$LOG_DIR/late-command.log"

fail() {
    printf '[MOONSHIELD ISO] ERRO: %s\n' "$*" >&2
    exit 1
}

[ -d "$TARGET" ] || fail 'Diretório /target do Debian Installer ausente.'
mkdir -p "$LOG_DIR"
chmod 0750 "$LOG_DIR"
: >"$LOG"
chmod 0600 "$LOG"
exec >>"$LOG" 2>&1

printf '[MOONSHIELD ISO] Iniciando late-command.\n'
[ -f "$RELEASE/deploy/install.sh" ] || fail 'Release tree ausente na mídia.'
[ -f "$RELEASE/deploy/console/maintenance_public.pem" ] || fail 'Chave pública de manutenção ausente na release.'
[ -f "$BUNDLE/SHA256SUMS" ] || fail 'Offline bundle ausente ou sem SHA256SUMS.'
[ -f "$FIRSTBOOT/moonshield-firstboot.py" ] || fail 'Firstboot MoonShield ausente da mídia.'
[ -f "$FIRSTBOOT/moonshield-console-gate.py" ] || fail 'Console gate MoonShield ausente da mídia.'
[ -f "$FIRSTBOOT/moonshield-iso-firstboot.service" ] || fail 'Unit firstboot ausente da mídia.'
[ -f "$FIRSTBOOT/moonshield-iso-console-gate.service" ] || fail 'Unit console gate ausente da mídia.'

if command -v sha256sum >/dev/null 2>&1; then
    (cd "$BUNDLE" && sha256sum --check --status SHA256SUMS) || fail 'Checksum do offline bundle falhou ainda na mídia.'
else
    fail 'sha256sum não está disponível no Debian Installer.'
fi

[ ! -e "$STAGE" ] && [ ! -L "$STAGE" ] || fail "Staging já existe no sistema alvo: $STAGE"
mkdir -p "$STAGE/release" "$STAGE/offline-bundle" "$STAGE/state" "$RUNTIME" "$WANTS"
chmod 0700 "$STAGE" "$STAGE/state"

printf '[MOONSHIELD ISO] Copiando release e bundle offline para o sistema alvo.\n'
cp -a "$RELEASE/." "$STAGE/release/"
cp -a "$BUNDLE/." "$STAGE/offline-bundle/"

cp "$FIRSTBOOT/moonshield-firstboot.py" "$RUNTIME/moonshield-firstboot.py"
cp "$FIRSTBOOT/moonshield-console-gate.py" "$RUNTIME/moonshield-console-gate.py"
cp "$FIRSTBOOT/moonshield-iso-firstboot.service" "$SYSTEMD/moonshield-iso-firstboot.service"
cp "$FIRSTBOOT/moonshield-iso-console-gate.service" "$SYSTEMD/moonshield-iso-console-gate.service"
chmod 0755 "$RUNTIME/moonshield-firstboot.py" "$RUNTIME/moonshield-console-gate.py"
chmod 0644 "$SYSTEMD/moonshield-iso-firstboot.service" "$SYSTEMD/moonshield-iso-console-gate.service"

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

# TTY1 nunca deve cair em login Debian normal. A gate assume esse terminal no primeiro boot.
TTY1_MASK="$SYSTEMD/getty@tty1.service"
if [ -e "$TTY1_MASK" ] || [ -L "$TTY1_MASK" ]; then
    rm -f "$TTY1_MASK"
fi
ln -s /dev/null "$TTY1_MASK"

ln -s ../moonshield-iso-console-gate.service "$WANTS/moonshield-iso-console-gate.service"
ln -s ../moonshield-iso-firstboot.service "$WANTS/moonshield-iso-firstboot.service"

printf '[MOONSHIELD ISO] Bootstrap preparado. No próximo boot a appliance será provisionada offline.\n'
