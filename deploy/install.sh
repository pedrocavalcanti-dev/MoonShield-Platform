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
# shellcheck source=lib/console.sh
. "$SCRIPT_DIR/lib/console.sh"

FINAL_ISO_MODE=0
INSTALL_STAGE_FILE=/var/lib/moonshield/install-stage

run_stage() {
  local label="$1"; shift
  mkdir -p /var/lib/moonshield
  printf "%s\n" "$label" >"$INSTALL_STAGE_FILE"
  chmod 0600 "$INSTALL_STAGE_FILE"
  info "ETAPA: $label"
  "$@"
}


usage() {
  cat <<'USAGE'
MoonShield Appliance installer (Debian 13 amd64)

Usage: sudo bash ./deploy/install.sh [--online | --offline [DIR]] [--ca-cert FILE] [--repair] [--check]

  --online             usa APT/PyPI validados e artifact HTTPS versionado (padrão)
  --offline [DIR]      usa deploy/offline-bundle ou o diretório informado
  --offline-bundle DIR alias explícito de --offline DIR
  --ca-cert FILE       CA corporativa PEM fornecida explicitamente pelo operador
  --repair             reconcilia dependências/serviços sem resetar estado persistente
  --final-iso          aplica políticas de console/TTY/SSH da imagem final e exige chave pública
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
    --final-iso) FINAL_ISO_MODE=1; shift ;;
    --check) CHECK_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Argumento desconhecido: $1" ;;
  esac
done

[[ "$(id -u)" == 0 ]] || die "Execute como root."
export DEBIAN_FRONTEND=noninteractive
init_logging
preflight

if (( FINAL_ISO_MODE )); then
  validate_maintenance_public_key
fi

if (( CHECK_ONLY )); then
  [[ -x /opt/moonshield/venv/bin/python && -x /usr/local/sbin/moonshield-install-check ]] || die "Healthcheck instalado ausente; --check não instala arquivos."
  exec /usr/local/sbin/moonshield-install-check
fi

if [[ "$INSTALL_MODE" == offline ]]; then
  [[ -f "$OFFLINE_BUNDLE/SHA256SUMS" ]] || die "Bundle offline sem SHA256SUMS."
  (cd "$OFFLINE_BUNDLE" && sha256sum --check SHA256SUMS >/dev/null) || die "Checksum do bundle offline falhou."
  grep -qx 'Debian=13' "$OFFLINE_BUNDLE/BUILD-INFO" || die "Bundle offline não foi produzido em Debian 13."
  grep -qx 'Architecture=amd64' "$OFFLINE_BUNDLE/BUILD-INFO" || die "Bundle offline não é amd64."
  grep -qx 'BundleFormat=2' "$OFFLINE_BUNDLE/BUILD-INFO" || die "Bundle offline antigo/incompleto; regenere com prepare-offline-bundle.sh desta release."
  grep -qx 'DependencyClosure=full' "$OFFLINE_BUNDLE/BUILD-INFO" || die "Bundle offline sem fechamento completo de dependências Debian."
  [[ -f "$OFFLINE_BUNDLE/artifacts/AdGuardHome_linux_amd64.tar.gz" ]] || die "Bundle offline sem AdGuard v0.107.79."
else
  ensure_certificate_trust
fi

info "Iniciando instalação MoonShield (modo=$INSTALL_MODE, repair=$REPAIR_MODE)."
run_stage "01-pacotes" install_packages
  run_stage "01b-networkmanager-pre-onboarding" prepare_networkmanager_preonboarding
if [[ "$INSTALL_MODE" == offline ]]; then run_stage "02-trust-local" ensure_certificate_trust; fi
run_stage "03-identidade-sistema" ensure_os_identity
run_stage "04-filesystem" ensure_filesystem
run_stage "05-config-appliance" write_appliance_config
run_stage "06-release" install_source_release
run_stage "07-runtime-externo" externalize_application_runtime
run_stage "08-python" install_python_runtime
run_stage "09-postgresql" install_postgresql
run_stage "10-django" install_django_application
run_stage "11-adguard" install_adguard_binary
run_stage "12-systemd" install_systemd_services
run_stage "13-nginx" install_nginx_site
run_stage "14-servicos-locais" provision_moonshield_local_services
run_stage "15-console" install_console

check_script=/usr/local/sbin/moonshield-install-check
[[ -x "$check_script" ]] || die "Healthcheck não foi incluído na release."
if (( FINAL_ISO_MODE )); then
  run_stage "16-pre-final-healthcheck" "$check_script" --pre-final-access \
    || die "Healthcheck pré-final sinalizou falhas; Alpha Debug SSH e estado existentes foram preservados para diagnóstico."
  run_stage "17-final-access" finalize_final_access_policy
  run_stage "18-final-healthcheck" "$check_script" \
    || die "Healthcheck final sinalizou falhas; log e estado existentes foram preservados para diagnóstico."
else
  run_stage "16-healthcheck" "$check_script" \
    || die "Healthcheck final sinalizou falhas; log e estado existentes foram preservados para diagnóstico."
fi
printf '%s\n' "complete" >"$INSTALL_STAGE_FILE"
chmod 0600 "$INSTALL_STAGE_FILE"
ok "MoonShield Appliance instalada. Crie a primeira conta exclusivamente pela interface de onboarding/login."
