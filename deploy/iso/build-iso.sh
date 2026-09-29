#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)"
MANIFEST="$SCRIPT_DIR/manifests/debian-base.env"
ISO_VERSION="0.1.0-alpha.2"
ISO_NAME="MoonShield-${ISO_VERSION}-amd64.iso"
VOLUME_ID="MOONSHIELD_ALPHA2"
OUTPUT_DIR="${4:-$REPO_ROOT/build/iso}"

WORK=""
TEMP_ISO=""

die() { printf '[ERRO] %s\n' "$*" >&2; exit 1; }
info() { printf '[INFO] %s\n' "$*"; }
ok() { printf '[OK] %s\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || die "Comando obrigatório ausente no builder: $1"; }
cleanup() {
  [[ -z "$WORK" ]] || rm -rf -- "$WORK"
  [[ -z "$TEMP_ISO" ]] || rm -f -- "$TEMP_ISO"
}
trap cleanup EXIT

manifest_value() {
  local key="$1" value
  value="$(sed -nE "s/^${key}=([^#[:space:]]+)$/\\1/p" "$MANIFEST")"
  [[ -n "$value" ]] || die "Manifest Debian sem $key."
  printf '%s' "$value"
}

usage() {
  cat <<'USAGE'
Uso: sudo bash deploy/iso/build-iso.sh DEBIAN_ISO RELEASE_TREE OFFLINE_BUNDLE [OUTPUT_DIR]

Gera:
  MoonShield-0.1.0-alpha.2-amd64.iso
  MoonShield-0.1.0-alpha.2-amd64.iso.sha256

O build remasteriza a ISO Debian em staging, embute o preseed no initrd,
injeta o instalador/firstboot MoonShield e valida a mídia final antes de publicar.
USAGE
}

(($# >= 1)) && [[ "${1:-}" == -h || "${1:-}" == --help ]] && { usage; exit 0; }
(($# >= 3 && $# <= 4)) || { usage >&2; exit 2; }

for tool in xorriso sha256sum openssl python3 dpkg realpath cpio gzip; do need "$tool"; done
[[ -r /etc/os-release ]] || die 'Builder deve ser Debian 13 amd64.'
# shellcheck disable=SC1091
. /etc/os-release
[[ "${ID:-}" == debian && "${VERSION_ID:-}" == 13* ]] || die 'Builder deve ser Debian 13.'
[[ "$(dpkg --print-architecture)" == amd64 ]] || die 'Builder deve ser amd64.'

BASE_ISO="$(realpath -e -- "$1")" || die "ISO Debian não encontrada: $1"
RELEASE="$(realpath -e -- "$2")" || die "Release tree não encontrada: $2"
BUNDLE="$(realpath -e -- "$3")" || die "Offline bundle não encontrado: $3"
OUTPUT_DIR="$(realpath -m -- "$OUTPUT_DIR")"

EXPECTED_FILENAME="$(manifest_value DEBIAN_ISO_FILENAME)"
[[ "$(basename -- "$BASE_ISO")" == "$EXPECTED_FILENAME" ]] || die "ISO base deve ser $EXPECTED_FILENAME."

validate_release() {
  [[ -f "$RELEASE/MoonShield/gerenciar.py" && -d "$RELEASE/MoonShield-Agent" \
     && -f "$RELEASE/deploy/install.sh" && -f "$RELEASE/requirements-prod.txt" ]] \
    || die 'Release tree incompleta; gere-a com deploy/scripts/build-release-tree.sh.'
  [[ ! -d "$RELEASE/deploy/support" ]] || die 'Release tree contém deploy/support proibido.'
  [[ -f "$RELEASE/deploy/console/maintenance_public.pem" ]] \
    || die 'MAINTENANCE_PUBLIC_KEY=REQUIRED_BEFORE_ISO'

  if find "$RELEASE" \( -name .git -o -name .env -o -name '.env.*' -o -name logs \
    -o -name '*.sqlite3' -o -name '*.log' -o -name __pycache__ -o -name tests \) \
    -print -quit | grep -q .; then
    die 'Release tree contém estado/artefato de desenvolvimento proibido.'
  fi
  if grep -RIlE -- '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----' "$RELEASE" | grep -q .; then
    die 'Release tree contém material de chave privada.'
  fi
  if find "$RELEASE" -type f \( -iname '*private*.pem' -o -iname '*.p8' -o -iname '*.p12' -o -iname '*.pfx' \) -print -quit | grep -q .; then
    die 'Release tree contém arquivo com nome/formato de chave privada.'
  fi

  local key_details key_bits
  key_details="$(openssl pkey -pubin -in "$RELEASE/deploy/console/maintenance_public.pem" -text -noout 2>/dev/null)" \
    || die 'Chave pública de manutenção inválida.'
  key_bits="$(printf '%s\n' "$key_details" | sed -nE 's/.*Public-Key: \(([0-9]+) bit\).*/\1/p' | head -n1)"
  [[ "$key_bits" =~ ^[0-9]+$ ]] && (( key_bits >= 3072 )) \
    || die 'Chave pública de manutenção deve ser RSA 3072 bits ou superior.'
  ok 'Release tree validada e sem chave privada detectada.'
}

validate_base_iso() {
  local expected_sha
  expected_sha="$(manifest_value DEBIAN_ISO_SHA256)"
  [[ "$expected_sha" != REQUIRED_BEFORE_BUILD ]] \
    || die 'DEBIAN_ISO_SHA256=REQUIRED_BEFORE_BUILD; fixe o hash autenticado no manifest.'
  [[ "$expected_sha" =~ ^[[:xdigit:]]{64}$ ]] || die 'DEBIAN_ISO_SHA256 inválido no manifest.'
  printf '%s  %s\n' "$expected_sha" "$BASE_ISO" | sha256sum --check --status \
    || die 'Checksum da ISO Debian diverge do manifest.'

  xorriso -indev "$BASE_ISO" -find / -name isolinux.bin -exec report_lba -- 2>/dev/null \
    | grep -q 'isolinux.bin' || die 'ISO base sem boot BIOS isolinux.bin.'
  xorriso -osirrox on -indev "$BASE_ISO" \
    -extract /boot/grub/grub.cfg "$WORK/base-grub.cfg" \
    -extract /boot/grub/efi.img "$WORK/base-efi.img" \
    -extract /install.amd/initrd.gz "$WORK/base-initrd.gz" \
    >/dev/null 2>&1 || die 'ISO base sem estrutura UEFI/initrd esperada.'
  [[ -s "$WORK/base-efi.img" && -s "$WORK/base-initrd.gz" ]] || die 'Arquivos de boot base vazios.'
  ok 'ISO Debian base autenticada e estrutura BIOS/UEFI validada.'
}

validate_bundle() {
  [[ -f "$BUNDLE/BUILD-INFO" && -f "$BUNDLE/SHA256SUMS" \
     && -d "$BUNDLE/debs" && -d "$BUNDLE/wheelhouse" \
     && -f "$BUNDLE/artifacts/AdGuardHome_linux_amd64.tar.gz" ]] \
    || die 'Offline bundle incompleto.'
  grep -qx 'Debian=13' "$BUNDLE/BUILD-INFO" || die 'Offline bundle não foi preparado em Debian 13.'
  grep -qx 'Architecture=amd64' "$BUNDLE/BUILD-INFO" || die 'Offline bundle não é amd64.'
  (cd -- "$BUNDLE" && sha256sum --check --status SHA256SUMS) || die 'Checksum do offline bundle falhou.'
  ok 'Offline bundle validado.'
}

detect_compression() {
  python3 - "$1" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
head = p.read_bytes()[:8]
if head.startswith(b"\x1f\x8b"):
    print("gzip")
elif head.startswith(b"\xfd7zXZ\x00"):
    print("xz")
elif head.startswith(b"\x28\xb5\x2f\xfd"):
    print("zstd")
elif head.startswith(b"070701") or head.startswith(b"070702"):
    print("cpio")
else:
    print("unknown")
PY
}

unpack_initrd() {
  local source="$1" destination="$2" raw="$3" compression
  compression="$(detect_compression "$source")"
  rm -rf -- "$destination"
  mkdir -p -- "$destination"
  case "$compression" in
    gzip) gzip -dc -- "$source" >"$raw" ;;
    xz) need xz; xz -dc -- "$source" >"$raw" ;;
    zstd) need zstd; zstd -q -dc -- "$source" >"$raw" ;;
    cpio) cp -- "$source" "$raw" ;;
    *) die "Formato de initrd não suportado: $compression" ;;
  esac
  (cd -- "$destination" && cpio --quiet -idmu --no-absolute-filenames <"$raw") \
    || die 'Falha ao extrair initrd Debian.'
  printf '%s' "$compression"
}

compress_initrd_raw() {
  local raw="$1" compression="$2" destination="$3"
  case "$compression" in
    gzip) gzip -9 -n -c -- "$raw" >"$destination" ;;
    xz) need xz; xz -C crc32 -9 -c -- "$raw" >"$destination" ;;
    zstd) need zstd; zstd -q -19 -c -- "$raw" >"$destination" ;;
    cpio) cp -- "$raw" "$destination" ;;
    *) die "Formato de initrd não suportado para rebuild: $compression" ;;
  esac
  [[ -s "$destination" ]] || die 'Initrd reconstruído ficou vazio.'
}

embed_preseed() {
  local raw="$WORK/initrd.raw" rebuilt="$WORK/moonshield-initrd.gz" compression overlay
  compression="$(detect_compression "$WORK/base-initrd.gz")"
  case "$compression" in
    gzip) gzip -dc -- "$WORK/base-initrd.gz" >"$raw" ;;
    xz) need xz; xz -dc -- "$WORK/base-initrd.gz" >"$raw" ;;
    zstd) need zstd; zstd -q -dc -- "$WORK/base-initrd.gz" >"$raw" ;;
    cpio) cp -- "$WORK/base-initrd.gz" "$raw" ;;
    *) die "Formato de initrd não suportado: $compression" ;;
  esac

  # Preserva o cpio original e apenas acrescenta os arquivos MoonShield antes do TRAILER.
  # Isso reduz o risco de alterar permissões, hardlinks ou arquivos internos do d-i.
  overlay="$WORK/initrd-overlay"
  mkdir -p -- "$overlay/moonshield"
  install -m 0644 "$SCRIPT_DIR/preseed.cfg" "$overlay/preseed.cfg"
  install -m 0755 "$SCRIPT_DIR/installer/select-disk.sh" "$overlay/moonshield/select-disk.sh"
  (cd -- "$overlay" && find . -mindepth 1 -print0 | LC_ALL=C sort -z \
    | cpio --null --quiet -o -H newc -A -F "$raw") \
    || die 'Falha ao acrescentar preseed/seletor ao initrd Debian.'

  compress_initrd_raw "$raw" "$compression" "$rebuilt"

  rm -rf -- "$WORK/initrd-verify"
  verify_compression="$(unpack_initrd "$rebuilt" "$WORK/initrd-verify" "$WORK/verify.raw")"
  [[ "$verify_compression" == "$compression" ]] || die 'Compressão do initrd mudou inesperadamente.'
  [[ -f "$WORK/initrd-verify/preseed.cfg" ]] || die 'preseed.cfg não está no initrd reconstruído.'
  [[ -f "$WORK/initrd-verify/moonshield/select-disk.sh" ]] || die 'Seletor de disco não está no initrd reconstruído.'
  grep -Fq 'partman/early_command' "$WORK/initrd-verify/preseed.cfg" || die 'Preseed embutido não contém hook de disco.'
  ok 'Preseed e seletor de disco embutidos no initrd de staging.'
}

prepare_metadata() {
  local commit='unknown'
  if command -v git >/dev/null 2>&1 && git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    commit="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || printf unknown)"
  fi
  cat >"$WORK/BUILD-INFO" <<META
MoonShieldVersion=$ISO_VERSION
DebianBase=$(manifest_value DEBIAN_ISO_VERSION)
Architecture=amd64
GitCommit=$commit
BuildTimeUTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
META
}

build_iso() {
  cp -- "$SCRIPT_DIR/templates/isolinux-menu.cfg" "$WORK/moonshield-menu.cfg"
  cp -- "$SCRIPT_DIR/templates/grub.cfg" "$WORK/moonshield-grub.cfg"
  prepare_metadata

  info 'Remasterizando mídia e preservando metadados de boot da ISO Debian.'
  xorriso -indev "$BASE_ISO" -outdev "$TEMP_ISO" \
    -map "$WORK/moonshield-initrd.gz" /install.amd/initrd.gz \
    -map "$SCRIPT_DIR/preseed.cfg" /preseed.cfg \
    -map "$SCRIPT_DIR/preseed.cfg" /moonshield/preseed.cfg \
    -map "$SCRIPT_DIR/installer/select-disk.sh" /moonshield/select-disk.sh \
    -map "$SCRIPT_DIR/late-command.sh" /moonshield/late-command.sh \
    -map "$SCRIPT_DIR/firstboot" /moonshield/firstboot \
    -map "$RELEASE" /moonshield/release \
    -map "$BUNDLE" /moonshield/offline-bundle \
    -map "$WORK/BUILD-INFO" /moonshield/BUILD-INFO \
    -map "$WORK/moonshield-menu.cfg" /isolinux/menu.cfg \
    -map "$WORK/moonshield-grub.cfg" /boot/grub/grub.cfg \
    -map "$SCRIPT_DIR/templates/moonshield-theme.txt" /boot/grub/moonshield-theme.txt \
    -volid "$VOLUME_ID" \
    -boot_image any replay -commit -end
  [[ -s "$TEMP_ISO" ]] || die 'xorriso não gerou ISO de saída.'
}

validate_final_iso() {
  local verify="$WORK/final-verify" final_initrd="$WORK/final-initrd.gz" compression
  mkdir -p -- "$verify"
  xorriso -indev "$TEMP_ISO" -find / -name isolinux.bin -exec report_lba -- 2>/dev/null \
    | grep -q 'isolinux.bin' || die 'ISO final perdeu boot BIOS.'
  xorriso -osirrox on -indev "$TEMP_ISO" \
    -extract /boot/grub/efi.img "$verify/efi.img" \
    -extract /boot/grub/grub.cfg "$verify/grub.cfg" \
    -extract /isolinux/menu.cfg "$verify/menu.cfg" \
    -extract /install.amd/initrd.gz "$final_initrd" \
    -extract /preseed.cfg "$verify/cdrom-preseed.cfg" \
    -extract /moonshield/preseed.cfg "$verify/preseed.cfg" \
    -extract /moonshield/select-disk.sh "$verify/select-disk.sh" \
    -extract /moonshield/late-command.sh "$verify/late-command.sh" \
    -extract /moonshield/firstboot/moonshield-firstboot.py "$verify/firstboot.py" \
    -extract /moonshield/firstboot/moonshield-console-gate.py "$verify/console-gate.py" \
    -extract /moonshield/release/deploy/install.sh "$verify/install.sh" \
    -extract /moonshield/release/deploy/console/maintenance_public.pem "$verify/maintenance_public.pem" \
    -extract /moonshield/offline-bundle/SHA256SUMS "$verify/bundle-sha256" \
    -extract /moonshield/BUILD-INFO "$verify/BUILD-INFO" \
    >/dev/null 2>&1 || die 'ISO final está sem payload obrigatório.'

  [[ -s "$verify/efi.img" ]] || die 'ISO final perdeu imagem UEFI.'
  grep -Fq 'Instalar MoonShield' "$verify/grub.cfg" || die 'Menu UEFI final não contém Instalar MoonShield.'
  grep -Fq 'Opções avançadas' "$verify/grub.cfg" || die 'Menu UEFI final não contém Opções avançadas.'
  grep -Fq 'Instalar MoonShield' "$verify/menu.cfg" || die 'Menu BIOS final não contém Instalar MoonShield.'
  grep -Fq 'Opções avançadas' "$verify/menu.cfg" || die 'Menu BIOS final não contém Opções avançadas.'
  cmp -s "$verify/cdrom-preseed.cfg" "$verify/preseed.cfg" || die 'Cópias do preseed na ISO divergem.'
  grep -Fq 'partman/early_command' "$verify/preseed.cfg" || die 'Preseed final sem seletor de disco.'
  grep -Fq 'preseed/file=/cdrom/preseed.cfg' "$verify/grub.cfg" || die 'Menu UEFI não aponta para /cdrom/preseed.cfg.'
  grep -Fq 'preseed/file=/cdrom/preseed.cfg' "$verify/menu.cfg" || die 'Menu BIOS não aponta para /cdrom/preseed.cfg.'
  grep -Fq 'FIRSTBOOT="$MEDIA/firstboot"' "$verify/late-command.sh" || die 'Late-command final não referencia firstboot.'
  grep -Fq '0.1.0-alpha.2' "$verify/BUILD-INFO" || die 'BUILD-INFO final com versão incorreta.'

  rm -rf -- "$WORK/final-initrd-root"
  compression="$(unpack_initrd "$final_initrd" "$WORK/final-initrd-root" "$WORK/final-initrd.raw")"
  [[ "$compression" != unknown ]] || die 'Initrd final inválido.'
  [[ -f "$WORK/final-initrd-root/preseed.cfg" ]] || die 'ISO final não contém preseed.cfg no initrd.'
  [[ -f "$WORK/final-initrd-root/moonshield/select-disk.sh" ]] || die 'ISO final não contém seletor de disco no initrd.'

  xorriso -indev "$TEMP_ISO" -pvd_info 2>&1 \
    | grep -Fq "$VOLUME_ID" \
    || die "Volume ID final não é $VOLUME_ID."

  ok 'Boot BIOS validado na estrutura final.'
  ok 'Boot UEFI validado na estrutura final.'
  ok 'Preseed embutido validado no initrd final.'
  ok 'Payload release/offline/firstboot validado na ISO final.'
  ok "Volume ID validado: $VOLUME_ID"
}

validate_sources() {
  for path in \
    "$SCRIPT_DIR/preseed.cfg" \
    "$SCRIPT_DIR/late-command.sh" \
    "$SCRIPT_DIR/installer/select-disk.sh" \
    "$SCRIPT_DIR/firstboot/moonshield-firstboot.py" \
    "$SCRIPT_DIR/firstboot/moonshield-console-gate.py" \
    "$SCRIPT_DIR/firstboot/moonshield-iso-firstboot.service" \
    "$SCRIPT_DIR/firstboot/moonshield-iso-console-gate.service" \
    "$SCRIPT_DIR/templates/grub.cfg" \
    "$SCRIPT_DIR/templates/isolinux-menu.cfg" \
    "$SCRIPT_DIR/templates/moonshield-theme.txt"; do
    [[ -f "$path" ]] || die "Arquivo ISO obrigatório ausente: $path"
  done
  if grep -RIlE -- '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----' "$SCRIPT_DIR" | grep -q .; then
    die 'deploy/iso contém chave privada.'
  fi
}

validate_sources
validate_release
validate_bundle

mkdir -p -- "$OUTPUT_DIR"
OUTPUT_DIR="$(cd -- "$OUTPUT_DIR" && pwd -P)"
[[ ! -e "$OUTPUT_DIR/$ISO_NAME" && ! -e "$OUTPUT_DIR/$ISO_NAME.sha256" ]] \
  || die "Saída já existe e foi preservada: $OUTPUT_DIR/$ISO_NAME"
TEMP_ISO="$OUTPUT_DIR/.${ISO_NAME}.tmp.$$"
[[ ! -e "$TEMP_ISO" && ! -L "$TEMP_ISO" ]] || die 'Arquivo temporário ISO já existe; preservado.'
WORK="$(mktemp -d "${TMPDIR:-/tmp}/moonshield-iso.XXXXXX")"

validate_base_iso
embed_preseed
build_iso
validate_final_iso

ln -- "$TEMP_ISO" "$OUTPUT_DIR/$ISO_NAME" \
  || die "Saída surgiu durante a geração e foi preservada: $OUTPUT_DIR/$ISO_NAME"
rm -- "$TEMP_ISO"
TEMP_ISO=""
(cd -- "$OUTPUT_DIR" && sha256sum "$ISO_NAME" >"$ISO_NAME.sha256")
(cd -- "$OUTPUT_DIR" && sha256sum --check --status "$ISO_NAME.sha256") || die 'Checksum da ISO publicada falhou.'

ok "ISO criada: $OUTPUT_DIR/$ISO_NAME"
ok "Checksum: $OUTPUT_DIR/$ISO_NAME.sha256"
printf '\nPróximo passo: instalar em VM descartável com disco vazio e validar o fluxo completo.\n'
