#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)"
MANIFEST="$SCRIPT_DIR/manifests/debian-base.env"
ISO_VERSION=0.1.0-alpha.1
ISO_NAME="MoonShield-${ISO_VERSION}-amd64.iso"
OUTPUT_DIR="${4:-$REPO_ROOT/build/iso}"

die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "Comando obrigatório ausente: $1"; }
manifest_value() {
  local key="$1" value
  value="$(sed -nE "s/^${key}=([^#[:space:]]+)$/\\1/p" "$MANIFEST")"
  [[ -n "$value" ]] || die "Manifest Debian sem $key."
  printf '%s' "$value"
}

usage() {
  cat <<'USAGE'
Uso: sudo bash deploy/iso/build-iso.sh DEBIAN_ISO RELEASE_TREE OFFLINE_BUNDLE [OUTPUT_DIR]

Gera MoonShield-0.1.0-alpha.1-amd64.iso e seu .sha256 sem instalar ou alterar
serviços, rede ou estado da máquina builder.
USAGE
}

if [[ "${1:-}" == -h || "${1:-}" == --help ]]; then usage; exit 0; fi
(($# >= 3 && $# <= 4)) || { usage >&2; exit 2; }

BASE_ISO="$(realpath -e -- "$1")" || die "ISO Debian não encontrada: $1"
RELEASE="$(realpath -e -- "$2")" || die "Release tree não encontrada: $2"
BUNDLE="$(realpath -e -- "$3")" || die "Offline bundle não encontrado: $3"
OUTPUT_DIR="$(realpath -m -- "$OUTPUT_DIR")"

for tool in xorriso sha256sum openssl python3 dpkg realpath; do need "$tool"; done
[[ -r /etc/os-release ]] || die 'Builder deve ser Debian 13 amd64.'
# shellcheck disable=SC1091
. /etc/os-release
[[ "${ID:-}" == debian && "${VERSION_ID:-}" == 13* ]] || die 'Builder deve ser Debian 13.'
[[ "$(dpkg --print-architecture)" == amd64 ]] || die 'Builder deve ser amd64.'

EXPECTED_FILENAME="$(manifest_value DEBIAN_ISO_FILENAME)"
[[ "$(basename -- "$BASE_ISO")" == "$EXPECTED_FILENAME" ]] || die "ISO base deve ser $EXPECTED_FILENAME."

[[ -f "$RELEASE/MoonShield/gerenciar.py" && -d "$RELEASE/MoonShield-Agent" \
   && -f "$RELEASE/deploy/install.sh" && -f "$RELEASE/requirements-prod.txt" ]] \
  || die 'Release tree incompleta; gere-a com deploy/scripts/build-release-tree.sh.'
[[ ! -d "$RELEASE/deploy/support" ]] || die 'Release tree contém deploy/support proibido.'
if find "$RELEASE" \( -name .git -o -name .env -o -name '.env.*' -o -name logs \
  -o -name '*.sqlite3' -o -name '*.log' -o -name __pycache__ -o -name tests \) \
  -print -quit | grep -q .; then
  die 'Release tree contém estado/artefato de desenvolvimento proibido.'
fi
if grep -RIlE -- '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----' "$RELEASE" | grep -q .; then
  die 'Release tree contém material de chave privada; ISO não será produzida.'
fi
PUBLIC_KEY="$RELEASE/deploy/console/maintenance_public.pem"
[[ -f "$PUBLIC_KEY" ]] || die 'MAINTENANCE_PUBLIC_KEY=REQUIRED_BEFORE_ISO'
KEY_DETAILS="$(openssl pkey -pubin -in "$PUBLIC_KEY" -text -noout 2>/dev/null)" \
  || die 'Chave pública de manutenção inválida.'
KEY_BITS="$(printf '%s\n' "$KEY_DETAILS" | sed -nE 's/.*Public-Key: \(([0-9]+) bit\).*/\1/p' | head -n1)"
[[ "$KEY_BITS" =~ ^[0-9]+$ ]] && (( KEY_BITS >= 3072 )) \
  || die 'Chave pública de manutenção deve ser RSA 3072 bits ou superior.'

ISO_SHA256="$(manifest_value DEBIAN_ISO_SHA256)"
[[ "$ISO_SHA256" != REQUIRED_BEFORE_BUILD ]] || die 'DEBIAN_ISO_SHA256=REQUIRED_BEFORE_BUILD; valide a assinatura Debian de SHA256SUMS e fixe o hash no manifest.'
[[ "$ISO_SHA256" =~ ^[[:xdigit:]]{64}$ ]] || die 'DEBIAN_ISO_SHA256 inválido no manifest.'
printf '%s  %s\n' "$ISO_SHA256" "$BASE_ISO" | sha256sum --check --status \
  || die 'Checksum da ISO Debian diverge do manifest.'

[[ -f "$BUNDLE/BUILD-INFO" && -f "$BUNDLE/SHA256SUMS" \
   && -d "$BUNDLE/debs" && -d "$BUNDLE/wheelhouse" \
   && -f "$BUNDLE/artifacts/AdGuardHome_linux_amd64.tar.gz" ]] \
  || die 'Offline bundle incompleto; prepare-o com deploy/scripts/prepare-offline-bundle.sh.'
grep -qx 'Debian=13' "$BUNDLE/BUILD-INFO" || die 'Offline bundle não foi preparado em Debian 13.'
grep -qx 'Architecture=amd64' "$BUNDLE/BUILD-INFO" || die 'Offline bundle não é amd64.'
(cd -- "$BUNDLE" && sha256sum --check --status SHA256SUMS) || die 'Checksum do offline bundle falhou.'

mkdir -p -- "$OUTPUT_DIR"
OUTPUT_DIR="$(cd -- "$OUTPUT_DIR" && pwd -P)"
[[ ! -e "$OUTPUT_DIR/$ISO_NAME" && ! -e "$OUTPUT_DIR/$ISO_NAME.sha256" ]] \
  || die "Saída já existe e foi preservada: $OUTPUT_DIR/$ISO_NAME"
TEMP_ISO="$OUTPUT_DIR/.${ISO_NAME}.tmp.$$"
[[ ! -e "$TEMP_ISO" && ! -L "$TEMP_ISO" ]] || die 'Arquivo temporário ISO já existe; preservado.'
WORK="$(mktemp -d "${TMPDIR:-/tmp}/moonshield-iso.XXXXXX")"
trap 'rm -rf -- "$WORK"; rm -f -- "$TEMP_ISO"' EXIT

printf '[INFO] Conferindo estrutura da ISO base com xorriso.\n'
xorriso -indev "$BASE_ISO" -find / -name isolinux.bin -exec report_lba -- 2>/dev/null \
  | grep -q 'isolinux.bin' || die 'ISO sem boot BIOS isolinux.bin; estrutura Debian inesperada.'
xorriso -osirrox on -indev "$BASE_ISO" \
  -extract /isolinux/txt.cfg "$WORK/txt.cfg" \
  -extract /boot/grub/grub.cfg "$WORK/grub.cfg" \
  -extract /boot/grub/efi.img "$WORK/efi.img" \
  >/dev/null 2>&1 || die 'ISO sem os arquivos BIOS/UEFI esperados (isolinux/txt.cfg, grub.cfg, efi.img).'

python3 - "$WORK/txt.cfg" "$WORK/grub.cfg" "$SCRIPT_DIR/preseed.cfg" <<'PY'
from pathlib import Path
import re
import sys

txt_path, grub_path, preseed_path = map(Path, sys.argv[1:])
args = "preseed/file=/cdrom/moonshield/preseed.cfg"

txt = txt_path.read_text(encoding="utf-8")
lines = txt.splitlines()
in_install = False
patched_txt = 0
for index, line in enumerate(lines):
    label = re.match(r"\s*label\s+(\S+)", line, re.IGNORECASE)
    if label:
        in_install = label.group(1).lower() == "install"
    if in_install and re.match(r"\s*append\s+", line, re.IGNORECASE):
        if "preseed/file=" not in line:
            if "---" in line:
                line = line.replace("---", f"{args} ---", 1)
            else:
                line = f"{line} {args}"
            lines[index] = line
        patched_txt += 1
if not patched_txt:
    raise SystemExit("txt.cfg não contém entrada isolinux 'install' compatível.")
txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

grub = grub_path.read_text(encoding="utf-8")
lines = grub.splitlines()
patched_grub = 0
for index, line in enumerate(lines):
    if re.match(r"\s*linux(?:efi)?\s+/install\.amd/vmlinuz(?:\s|$)", line):
        if "preseed/file=" not in line:
            if "---" in line:
                line = line.replace("---", f"{args} ---", 1)
            else:
                line = f"{line} {args}"
            lines[index] = line
        patched_grub += 1
if not patched_grub:
    raise SystemExit("grub.cfg não contém kernel installer amd64 compatível.")
grub_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

cp -- "$SCRIPT_DIR/templates/isolinux-menu.cfg" "$WORK/moonshield-menu.cfg"
cp -- "$SCRIPT_DIR/templates/grub.cfg" "$WORK/moonshield-grub.cfg"

printf '[INFO] Remasterizando mídia e preservando os parâmetros de boot da ISO original.\n'
xorriso -indev "$BASE_ISO" -outdev "$TEMP_ISO" \
  -map "$SCRIPT_DIR/preseed.cfg" /moonshield/preseed.cfg \
  -map "$SCRIPT_DIR/late-command.sh" /moonshield/late-command.sh \
  -map "$RELEASE" /moonshield/release \
  -map "$BUNDLE" /moonshield/offline-bundle \
  -map "$WORK/moonshield-menu.cfg" /isolinux/menu.cfg \
  -map "$WORK/moonshield-grub.cfg" /boot/grub/grub.cfg \
  -map "$SCRIPT_DIR/templates/moonshield-theme.txt" /boot/grub/moonshield-theme.txt \
  -volid MOONSHIELD_ALPHA1 \
  -boot_image any replay -commit -end

[[ -s "$TEMP_ISO" ]] || die 'xorriso não gerou uma ISO de saída.'
ln -- "$TEMP_ISO" "$OUTPUT_DIR/$ISO_NAME" \
  || die "Saída surgiu durante a geração e foi preservada: $OUTPUT_DIR/$ISO_NAME"
rm -- "$TEMP_ISO"
(cd -- "$OUTPUT_DIR" && sha256sum "$ISO_NAME" >"$ISO_NAME.sha256")
printf '[OK] ISO criada: %s/%s\n' "$OUTPUT_DIR" "$ISO_NAME"
printf '[OK] Checksum: %s/%s.sha256\n' "$OUTPUT_DIR" "$ISO_NAME"
