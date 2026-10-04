#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
DEPLOY_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
REPO_ROOT="$(cd -- "$DEPLOY_DIR/.." && pwd -P)"
# shellcheck source=../lib/common.sh
. "$DEPLOY_DIR/lib/common.sh"
# shellcheck source=../lib/certificates.sh
. "$DEPLOY_DIR/lib/certificates.sh"

OUTPUT="${1:-$DEPLOY_DIR/offline-bundle}"
OUTPUT="$(mkdir -p -- "$(dirname -- "$OUTPUT")" && cd -- "$(dirname -- "$OUTPUT")" && pwd -P)/$(basename -- "$OUTPUT")"
[[ ! -e "$OUTPUT" ]] || die "Bundle de destino já existe; nenhum conteúdo foi sobrescrito."
[[ "$(id -u)" == 0 ]] || die "Gere o bundle em Debian 13 amd64 com internet usando root."
[[ -r /etc/os-release ]] || die "Sistema sem /etc/os-release."
# shellcheck disable=SC1091
. /etc/os-release
[[ "${ID:-}" == debian && "${VERSION_ID:-}" == 13* ]] || die "Builder deve ser Debian 13."
[[ "$(dpkg --print-architecture)" == amd64 ]] || die "Builder deve ser amd64."

ADGUARD_URL="$(manifest_value "$MANIFEST_DIR/external-artifacts.env" ADGUARD_URL)"
ADGUARD_SHA256="$(manifest_value "$MANIFEST_DIR/external-artifacts.env" ADGUARD_SHA256)"
[[ "$ADGUARD_URL" != REQUIRED_BEFORE_ISO && "$ADGUARD_SHA256" != REQUIRED_BEFORE_ISO ]] || die "Preencha URL versionada e SHA-256 oficial do AdGuard antes de preparar o bundle."
[[ -r "$REPO_ROOT/requirements-prod.txt" ]] || die "requirements-prod.txt ausente."
require_command apt-get
require_command pip3
require_command python3
require_command curl
require_command sha256sum
require_command dpkg-deb
require_command dpkg-scanpackages
require_command gzip

init_logging
INSTALL_MODE=online
ensure_certificate_trust

WORK="$(mktemp -d /tmp/moonshield-offline-build.XXXXXX)"
TEMP_DIRS+=("$WORK")
mkdir -p "$WORK/apt/partial" "$OUTPUT/debs" "$OUTPUT/wheelhouse" "$OUTPUT/artifacts" "$OUTPUT/certificates"
: >"$WORK/empty-status"

mapfile -t PACKAGES < <(sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$MANIFEST_DIR/debian-packages.txt")
apt_args=(
  -o "Dir::Cache::archives=$WORK/apt/"
  -o "Dir::State::status=$WORK/empty-status"
  -o "APT::Install-Recommends=false"
  -o "APT::Install-Suggests=false"
)
info "Atualizando índices APT do builder (nenhuma instalação de pacotes no builder)."
run_with_tls_retry "apt-get update" apt-get update
info "Resolvendo fechamento COMPLETO de dependências em estado dpkg vazio."
# O status isolado evita o bug em que dependências já instaladas no builder não
# eram copiadas para o bundle e faltavam na VM limpa. O bundle cresce, mas passa
# a ser autocontido para Debian 13 amd64.
run_with_tls_retry "download-only do closure Debian" apt-get "${apt_args[@]}" --download-only --no-install-recommends --yes install "${PACKAGES[@]}"
shopt -s nullglob
deb_files=("$WORK/apt"/*.deb)
((${#deb_files[@]} > 0)) || die "APT não baixou nenhum pacote .deb."
cp -- "${deb_files[@]}" "$OUTPUT/debs/"
for deb in "$OUTPUT"/debs/*.deb; do
  dpkg-deb --info "$deb" >/dev/null || die "Pacote .deb invalido no bundle: $(basename -- "$deb")."
  deb_arch="$(dpkg-deb -f "$deb" Architecture)"
  [[ "$deb_arch" == amd64 || "$deb_arch" == all ]] \
    || die "Pacote com arquitetura incompatível no bundle: $(basename -- "$deb") ($deb_arch)."
  printf '%s\t%s\t%s\n' "$(dpkg-deb -f "$deb" Package)" "$(dpkg-deb -f "$deb" Version)" "$deb_arch"
done | sort >"$OUTPUT/DEBIAN-PACKAGES.tsv"

info "Gerando repositorio APT local e validando o fechamento sem usar o estado do builder."
(cd "$OUTPUT" && dpkg-scanpackages --multiversion debs /dev/null >Packages)
gzip -9 -n -c "$OUTPUT/Packages" >"$OUTPUT/Packages.gz"

mkdir -p "$WORK/verify-lists/partial" "$WORK/verify-archives/partial" "$WORK/verify-sourceparts"
: >"$WORK/verify-status"
printf 'deb [trusted=yes] file:%s ./\n' "$OUTPUT" >"$WORK/offline.sources.list"
verify_apt_args=(
  -o "Dir::State::status=$WORK/verify-status"
  -o "Dir::State::lists=$WORK/verify-lists"
  -o "Dir::Cache::archives=$WORK/verify-archives"
  -o "Dir::Etc::sourcelist=$WORK/offline.sources.list"
  -o "Dir::Etc::sourceparts=$WORK/verify-sourceparts"
  -o "APT::Sandbox::User=root"
  -o "Acquire::Languages=none"
  -o "APT::Get::List-Cleanup=false"
)
run_checked "indice APT local" apt-get "${verify_apt_args[@]}" update \
  || die "Repositorio APT local do bundle invalido."
run_checked "fechamento APT offline" apt-get "${verify_apt_args[@]}" \
  --simulate --no-download --no-install-recommends --yes install "${PACKAGES[@]}" \
  || die "Bundle Debian incompleto; a simulacao em estado dpkg vazio encontrou dependencias ausentes."

info "Baixando wheels versionadas para Python/Linux amd64."
run_with_tls_retry "pip download de dependências" pip3 download --disable-pip-version-check \
  --only-binary=:all: --requirement "$REPO_ROOT/requirements-prod.txt" --dest "$OUTPUT/wheelhouse"
python3 - "$OUTPUT/wheelhouse" <<'PY' || die "Wheelhouse offline sem distribuição Pillow válida."
from pathlib import Path
import sys
from zipfile import BadZipFile, ZipFile

wheelhouse = Path(sys.argv[1])
for wheel in sorted(wheelhouse.glob("*.whl")):
    try:
        with ZipFile(wheel) as archive:
            metadata = next(
                (name for name in archive.namelist() if name.endswith(".dist-info/METADATA")),
                None,
            )
            if metadata is None:
                continue
            name = next(
                (
                    line.partition(":")[2].strip()
                    for line in archive.read(metadata).decode("utf-8", errors="replace").splitlines()
                    if line.lower().startswith("name:")
                ),
                "",
            )
            if name.casefold() == "pillow":
                raise SystemExit(0)
    except BadZipFile:
        continue
raise SystemExit("Pillow não encontrado nos metadados dos wheels.")
PY
run_checked "validação do fechamento pip offline" pip3 install --dry-run --ignore-installed --disable-pip-version-check \
  --no-index --only-binary=:all: --find-links "$OUTPUT/wheelhouse" \
  --requirement "$REPO_ROOT/requirements-prod.txt" \
  || die "Wheelhouse Python incompatível ou incompleto para o requirements-prod.txt."
download_verified "$ADGUARD_URL" "$ADGUARD_SHA256" "$OUTPUT/artifacts/AdGuardHome_linux_amd64.tar.gz"

for ca in "$DEPLOY_DIR/certificates/optional/corporate-ca.crt" "$DEPLOY_DIR/certificates/optional/senac-ca.crt"; do
  [[ ! -f "$ca" ]] || install -m 0644 "$ca" "$OUTPUT/certificates/corporate-ca.crt"
done
printf 'Debian=%s\nArchitecture=amd64\nBundleFormat=2\nDependencyClosure=full\nPackageIndex=local-apt\nDependencyValidation=empty-dpkg-status\nBuilder=%s\n' \
  "${VERSION_ID}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$OUTPUT/BUILD-INFO"
(cd "$OUTPUT" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum >SHA256SUMS)
chmod -R go-w "$OUTPUT"
ok "Bundle offline preparado e validado em estado dpkg vazio: $OUTPUT."
warn "A validacao APT offline nao substitui o teste final de boot em VM Debian 13 limpa."
