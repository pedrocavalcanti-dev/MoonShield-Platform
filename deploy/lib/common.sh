#!/usr/bin/env bash
# Shared safety, logging, download and failure-classification helpers.

set -Eeuo pipefail
umask 077

DEPLOY_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
REPO_ROOT="$(cd -- "$DEPLOY_DIR/.." && pwd -P)"
MANIFEST_DIR="$DEPLOY_DIR/manifests"
OFFLINE_BUNDLE="${MOONSHIELD_OFFLINE_BUNDLE:-$DEPLOY_DIR/offline-bundle}"
LOG_FILE="${MOONSHIELD_INSTALL_LOG:-/var/log/moonshield/install.log}"
CA_CERT_PATH=""
INSTALL_MODE="online"
REPAIR_MODE=0
CHECK_ONLY=0
TEMP_FILES=()
TEMP_DIRS=()

_timestamp() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

log() {
  local level="$1" message="$2" line
  line="[$(_timestamp)] [$level] $message"
  printf '%s\n' "$line"
  if [[ -n "${LOG_FILE:-}" && -d "$(dirname -- "$LOG_FILE")" ]]; then
    printf '%s\n' "$line" >>"$LOG_FILE"
  fi
}

info() { log INFO "$1"; }
ok() { log OK "$1"; }
warn() { log WARN "$1"; }
die() { log ERROR "$1"; exit 1; }

_cleanup() {
  local item
  for item in "${TEMP_FILES[@]:-}"; do
    [[ -n "$item" ]] && rm -f -- "$item"
  done
  for item in "${TEMP_DIRS[@]:-}"; do
    [[ -n "$item" ]] && rm -rf -- "$item"
  done
}

_on_error() {
  local code="$1" line="$2"
  trap - ERR
  log ERROR "Etapa interrompida (exit=$code, linha=$line); consulte o diagnóstico sem dados sensíveis."
  exit "$code"
}

init_logging() {
  local log_dir
  log_dir="$(dirname -- "$LOG_FILE")"
  mkdir -p -- "$log_dir"
  chmod 0750 "$log_dir"
  touch -- "$LOG_FILE"
  chmod 0600 "$LOG_FILE"
  trap '_on_error "$?" "$LINENO"' ERR
  trap _cleanup EXIT
}

manifest_value() {
  local file="$1" key="$2"
  [[ -r "$file" ]] || return 1
  awk -F= -v wanted="$key" '
    /^[[:space:]]*#/ || NF < 2 { next }
    $1 == wanted { sub(/^[^=]*=/, ""); gsub(/\r$/, ""); print; found=1; exit }
    END { if (!found) exit 1 }
  ' "$file"
}

classify_failure() {
  local output_file="$1" http_code="${2:-}" text
  if [[ "$http_code" =~ ^[0-9]{3}$ ]]; then
    case "$http_code" in
      403) printf 'http_403'; return ;;
      407) printf 'proxy_auth_required'; return ;;
      5??) printf 'http_5xx'; return ;;
    esac
  fi
  text="$(tr '[:upper:]' '[:lower:]' <"$output_file" 2>/dev/null || true)"
  case "$text" in
    *"certificate verify failed"*|*"certificate verification failed"*|*"unable to get local issuer certificate"*|*"self-signed certificate in certificate chain"*|*"tls: failed to verify"*) printf 'tls_certificate' ;;
    *"407 proxy authentication required"*|*"proxy authentication required"*|*"407"*"proxy"*|*"proxy"*"407"*) printf 'proxy_auth_required' ;;
    *"repository is not signed"*|*"signature verification"*|*"the following signatures couldn't be verified"*|*"no_pubkey"*) printf 'apt_signature' ;;
    *"temporary failure resolving"*|*"could not resolve"*|*"name or service not known"*|*"name resolution"*) printf 'dns_failure' ;;
    *"network is unreachable"*|*"no route to host"*) printf 'network_unreachable' ;;
    *"timed out"*|*"timeout"*) printf 'timeout' ;;
    *"no space left on device"*|*"disk full"*) printf 'disk_full' ;;
    *"permission denied"*) printf 'permission_denied' ;;
    *"unable to locate package"*|*"has no installation candidate"*|*"package .* not found"*) printf 'package_unavailable' ;;
    *"resolutionimpossible"*|*"resolution impossible"*|*"no matching distribution found"*|*"dependency conflict"*|*"conflicting dependencies"*) printf 'pip_resolution' ;;
    *"failed to start"*|*"job for .* failed"*|*"start operation timed out"*) printf 'service_startup' ;;
    *"403 forbidden"*) printf 'http_403' ;;
    *"500 internal server error"*|*"502 bad gateway"*|*"503 service unavailable"*|*"504 gateway timeout"*) printf 'http_5xx' ;;
    *) printf 'unknown' ;;
  esac
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "Comando obrigatório ausente: $1."
}

diagnose_network_failure() {
  local resolved=0 route=0 proxy_set=0 variable
  if command -v ip >/dev/null 2>&1 && ip route show default 2>/dev/null | grep -q .; then route=1; fi
  if command -v getent >/dev/null 2>&1 && getent ahosts deb.debian.org >/dev/null 2>&1; then resolved=1; fi
  for variable in HTTP_PROXY HTTPS_PROXY NO_PROXY http_proxy https_proxy no_proxy; do
    [[ -z "${!variable:-}" ]] || proxy_set=1
  done
  [[ "$route" == 1 ]] && info "Diagnóstico de rede: rota default presente." || warn "Diagnóstico de rede: nenhuma rota default detectada."
  [[ "$resolved" == 1 ]] && info "Diagnóstico DNS: deb.debian.org resolve." || warn "Diagnóstico DNS: falha de resolução para deb.debian.org."
  [[ "$proxy_set" == 1 ]] && info "Variável proxy configurada (valor ocultado)." || info "Nenhuma variável proxy detectada."
}

run_checked() {
  local stage="$1"; shift
  local output_file category
  output_file="$(mktemp /tmp/moonshield-stage.XXXXXX)"
  TEMP_FILES+=("$output_file")
  if "$@" >/dev/null 2>"$output_file"; then
    ok "$stage concluída."
    return 0
  fi
  category="$(classify_failure "$output_file")"
  log ERROR "$stage falhou (classe: $category); saída do comando omitida para evitar vazar credenciais."
  return 1
}

run_with_tls_retry() {
  local stage="$1"; shift
  local output_file http_code category attempt
  for attempt in 1 2; do
    output_file="$(mktemp /tmp/moonshield-network.XXXXXX)"
    TEMP_FILES+=("$output_file")
    http_code=""
    if "$@" >"$output_file" 2>&1; then
      ok "$stage concluída."
      return 0
    fi
    category="$(classify_failure "$output_file" "$http_code")"
    if [[ "$category" == tls_certificate && "$attempt" == 1 ]]; then
      warn "Falha TLS em $stage; possível inspeção TLS/proxy corporativo detectado."
      if declare -F bootstrap_corporate_ca >/dev/null && bootstrap_corporate_ca; then
        info "Repetindo $stage uma única vez após validar CA fornecida explicitamente."
        continue
      fi
    fi
    diagnose_network_failure
    log ERROR "$stage falhou (classe: $category); consulte conectividade, proxy e trust store."
    return 1
  done
  return 1
}

download_verified() {
  local url="$1" expected_sha256="$2" destination="$3"
  local tmp output_file code actual category attempt
  [[ "$url" == https://* && "$url" != *'@'* ]] || die "Artifact URL inválida; exige HTTPS e não aceita credenciais embutidas."
  [[ "$expected_sha256" =~ ^[A-Fa-f0-9]{64}$ ]] || die "Checksum ausente/inválido para artifact; use SHA256_REQUIRED até obter valor confiável."
  mkdir -p -- "$(dirname -- "$destination")"
  for attempt in 1 2; do
    tmp="$(mktemp "$(dirname -- "$destination")/.download.XXXXXX")"
    output_file="$(mktemp /tmp/moonshield-download.XXXXXX)"
    TEMP_FILES+=("$tmp" "$output_file")
    code="$(curl --silent --show-error --location --fail --proto '=https' --tlsv1.2 \
      --connect-timeout 15 --max-time 300 --retry 2 --output "$tmp" \
      --write-out '%{http_code}' "$url" 2>"$output_file" || true)"
    if [[ "$code" =~ ^2[0-9][0-9]$ && -s "$tmp" ]]; then
      actual="$(sha256sum "$tmp" | awk '{print $1}')"
      [[ "${actual,,}" == "${expected_sha256,,}" ]] || die "Checksum SHA-256 divergente para artifact; arquivo temporário descartado."
      chmod 0644 "$tmp"
      mv -f -- "$tmp" "$destination"
      ok "Download verificado e instalado em destino temporário."
      return 0
    fi
    category="$(classify_failure "$output_file" "$code")"
    if [[ "$category" == tls_certificate && "$attempt" == 1 ]] && bootstrap_corporate_ca; then
      warn "Falha TLS; repetindo download após instalar CA de origem explicitamente confiável."
      continue
    fi
    diagnose_network_failure
    die "Download HTTPS falhou (classe: $category, HTTP ${code:-desconhecido}); nenhum bypass TLS foi usado."
  done
}
