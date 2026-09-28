#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=lib/certificates.sh
. "$SCRIPT_DIR/lib/certificates.sh"
# shellcheck source=lib/preflight.sh
. "$SCRIPT_DIR/lib/preflight.sh"
# shellcheck source=lib/packages.sh
. "$SCRIPT_DIR/lib/packages.sh"
# shellcheck source=lib/filesystem.sh
. "$SCRIPT_DIR/lib/filesystem.sh"
# shellcheck source=lib/python.sh
. "$SCRIPT_DIR/lib/python.sh"
# shellcheck source=lib/postgres.sh
. "$SCRIPT_DIR/lib/postgres.sh"
# shellcheck source=lib/django.sh
. "$SCRIPT_DIR/lib/django.sh"
# shellcheck source=lib/services.sh
. "$SCRIPT_DIR/lib/services.sh"

usage() {
  cat <<'USAGE'
MoonShield Appliance installer (Debian 13 amd64)

Usage: sudo bash ./deploy/install.sh [--online | --offline [DIR]] [--ca-cert FILE] [--repair] [--check]

  --online             usa APT/PyPI validados e artifact HTTPS versionado (padrão)
  --offline [DIR]      usa deploy/offline-bundle ou o diretório informado
  --offline-bundle DIR alias explícito de --offline DIR
  --ca-cert FILE       CA corporativa PEM fornecida explicitamente pelo operador
  --repair             reconcilia dependências/serviços sem resetar estado persistente
  --check              executa apenas preflight e healthcheck read-only
  -h, --help           mostra esta ajuda
USAGE
}

while (($#)); do
  case "$1" in
    --online) INSTALL_MODE=online; shift ;;
    --offline)
      INSTALL_MODE=offline
      if (($# >= 2)) && [[ "$2" != --* ]]; then
        OFFLINE_BUNDLE="$(cd -- "$2" 2>/dev/null && pwd -P)" || die "Diretório do bundle offline não encontrado."
        shift 2
      else
        shift
      fi
      ;;
    --offline-bundle)
      (($# >= 2)) || die "--offline-bundle exige um diretório."
      INSTALL_MODE=offline
      OFFLINE_BUNDLE="$(cd -- "$2" 2>/dev/null && pwd -P)" || die "Diretório do bundle offline não encontrado."
      shift 2
      ;;
    --ca-cert)
      (($# >= 2)) || die "--ca-cert exige o caminho do arquivo."
      CA_CERT_PATH="$2"
      shift 2
      ;;
    --repair) REPAIR_MODE=1; shift ;;
    --check) CHECK_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Argumento desconhecido: $1" ;;
  esac
done

[[ "$(id -u)" == 0 ]] || die "Execute como root."
export DEBIAN_FRONTEND=noninteractive
init_logging
preflight

if (( CHECK_ONLY )); then
  [[ -x /opt/moonshield/venv/bin/python && -x /opt/moonshield/source/deploy/scripts/moonshield-install-check ]] || die "Healthcheck instalado ausente; --check não instala arquivos."
  exec /opt/moonshield/source/deploy/scripts/moonshield-install-check
fi

if [[ "$INSTALL_MODE" == offline ]]; then
  [[ -f "$OFFLINE_BUNDLE/SHA256SUMS" ]] || die "Bundle offline sem SHA256SUMS."
  (cd "$OFFLINE_BUNDLE" && sha256sum --check --status SHA256SUMS) || die "Checksum do bundle offline falhou."
  grep -qx 'Debian=13' "$OFFLINE_BUNDLE/BUILD-INFO" || die "Bundle offline não foi produzido em Debian 13."
  grep -qx 'Architecture=amd64' "$OFFLINE_BUNDLE/BUILD-INFO" || die "Bundle offline não é amd64."
  [[ -f "$OFFLINE_BUNDLE/artifacts/AdGuardHome_linux_amd64.tar.gz" ]] || die "Bundle offline sem AdGuard v0.107.79."
else
  ensure_certificate_trust
fi

info "Iniciando instalação MoonShield (modo=$INSTALL_MODE, repair=$REPAIR_MODE)."
install_packages
if [[ "$INSTALL_MODE" == offline ]]; then ensure_certificate_trust; fi
ensure_os_identity
ensure_filesystem
write_appliance_config
install_source_release
externalize_application_runtime
install_python_runtime
install_postgresql
install_django_application
install_adguard_binary
install_systemd_services
install_nginx_site
provision_moonshield_local_services

check_script=/opt/moonshield/source/deploy/scripts/moonshield-install-check
[[ -x "$check_script" ]] || die "Healthcheck não foi incluído na release."
"$check_script" || die "Healthcheck final sinalizou falhas; log e estado existentes foram preservados para diagnóstico."
ok "MoonShield Appliance instalada. Crie a primeira conta exclusivamente pela interface de onboarding/login."
