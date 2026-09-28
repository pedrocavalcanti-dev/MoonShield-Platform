#!/bin/sh
set -eu

MEDIA=/cdrom/moonshield
STAGE=/target/var/lib/moonshield-iso-bootstrap
RELEASE="$MEDIA/release"
BUNDLE="$MEDIA/offline-bundle"

fail() {
  printf '[MOONSHIELD ISO] ERRO: %s\n' "$*" >&2
  exit 1
}

if [ "${1:-}" = --firstboot ]; then
  BOOT_STAGE=/var/lib/moonshield-iso-bootstrap
  [ "$(id -u)" -eq 0 ] || fail 'bootstrap exige root.'
  [ -f "$BOOT_STAGE/release/deploy/install.sh" ] || fail 'release stage ausente.'
  /bin/bash "$BOOT_STAGE/release/deploy/install.sh" \
    --offline "$BOOT_STAGE/offline-bundle" --final-iso
  systemctl disable moonshield-iso-firstboot.service
  rm -f -- /etc/systemd/system/moonshield-iso-firstboot.service
  systemctl daemon-reload
  systemctl start moonshield-console.service
  [ "$BOOT_STAGE" = /var/lib/moonshield-iso-bootstrap ] || fail 'caminho de staging inesperado.'
  [ ! -L "$BOOT_STAGE" ] || fail 'staging virou symlink; preservado para diagnóstico.'
  rm -rf -- "$BOOT_STAGE"
  exit 0
fi

[ -d /target ] || fail 'alvo Debian Installer ausente.'
[ -f "$RELEASE/deploy/install.sh" ] || fail 'release tree ausente na mídia.'
[ -f "$RELEASE/deploy/console/maintenance_public.pem" ] || fail 'MAINTENANCE_PUBLIC_KEY=REQUIRED_BEFORE_ISO'
[ -f "$BUNDLE/SHA256SUMS" ] || fail 'offline bundle ausente ou sem SHA256SUMS.'
[ ! -e "$STAGE" ] && [ ! -L "$STAGE" ] || fail "staging já existe: $STAGE"

mkdir -p -- "$STAGE/release" "$STAGE/offline-bundle"
cp -a -- "$RELEASE/." "$STAGE/release/"
cp -a -- "$BUNDLE/." "$STAGE/offline-bundle/"
cp -- "$0" /target/var/lib/moonshield-iso-bootstrap/firstboot.sh
chmod 0755 /target/var/lib/moonshield-iso-bootstrap/firstboot.sh
WANTS=/target/etc/systemd/system/multi-user.target.wants
UNIT_LINK="$WANTS/moonshield-iso-firstboot.service"
[ ! -e "$UNIT_LINK" ] && [ ! -L "$UNIT_LINK" ] || fail 'unit de bootstrap já existe no sistema-alvo.'
mkdir -p -- "$WANTS"
cat >/target/etc/systemd/system/moonshield-iso-firstboot.service <<'UNIT'
[Unit]
Description=Install MoonShield from the Alpha ISO payload
After=local-fs.target
Before=multi-user.target

[Service]
Type=oneshot
ExecStart=/var/lib/moonshield-iso-bootstrap/firstboot.sh --firstboot
TimeoutStartSec=infinity

[Install]
WantedBy=multi-user.target
UNIT
ln -s ../moonshield-iso-firstboot.service "$UNIT_LINK"

printf '[MOONSHIELD ISO] Installer agendado para o primeiro boot do sistema-alvo.\n'
