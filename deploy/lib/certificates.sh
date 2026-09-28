#!/usr/bin/env bash

_select_explicit_ca() {
  if [[ -n "${CA_CERT_PATH:-}" ]]; then
    [[ -f "$CA_CERT_PATH" && -r "$CA_CERT_PATH" ]] || die "Arquivo --ca-cert não existe ou não pode ser lido."
    printf '%s' "$CA_CERT_PATH"
    return 0
  fi
  local candidate
  for candidate in \
    "$DEPLOY_DIR/certificates/optional/corporate-ca.crt" \
    "$DEPLOY_DIR/certificates/optional/senac-ca.crt" \
    "$OFFLINE_BUNDLE/certificates/senac-ca.crt" \
    "$OFFLINE_BUNDLE/certificates/corporate-ca.crt"; do
    if [[ -f "$candidate" && -r "$candidate" ]]; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  return 1
}

bootstrap_corporate_ca() {
  local source fingerprint expected dest backup
  [[ -f /etc/ssl/certs/ca-certificates.crt ]] || die "Trust store padrão não existe: /etc/ssl/certs/ca-certificates.crt."
  source="$(_select_explicit_ca)" || {
    warn "CA institucional não foi fornecida; não confiarei no certificado apresentado pela conexão."
    return 1
  }
  require_command openssl
  require_command update-ca-certificates
  openssl x509 -in "$source" -noout >/dev/null 2>&1 || die "CA fornecida não é um certificado X.509 PEM válido."
  fingerprint="$(openssl x509 -in "$source" -noout -fingerprint -sha256 | sed 's/^[^=]*=//; s/://g' | tr '[:upper:]' '[:lower:]')"
  expected="$(manifest_value "$MANIFEST_DIR/external-artifacts.env" CORPORATE_CA_SHA256 2>/dev/null || true)"
  if [[ -n "$expected" && "$expected" != REQUIRED_BEFORE_ISO && "${expected,,}" != "$fingerprint" ]]; then
    die "Fingerprint SHA-256 da CA diverge do manifest; certificado não instalado."
  fi
  dest=/usr/local/share/ca-certificates/moonshield-corporate-ca.crt
  if [[ -e "$dest" ]] && ! cmp -s -- "$source" "$dest"; then
    backup="${dest}.backup.$(date -u +%Y%m%dT%H%M%SZ).$$"
    cp -a -- "$dest" "$backup"
    warn "CA anterior preservada em backup timestamped antes da atualização."
  fi
  install -o root -g root -m 0644 -- "$source" "$dest"
  update-ca-certificates >/dev/null
  [[ -s /etc/ssl/certs/ca-certificates.crt ]] || die "Trust store não foi atualizado."
  export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
  export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
  export PIP_CERT=/etc/ssl/certs/ca-certificates.crt
  ok "Trust corporativo instalado a partir de arquivo X.509 fornecido explicitamente (SHA-256: $fingerprint)."
}

_https_probe() {
  local url="$1" code output_file category
  output_file="$(mktemp /tmp/moonshield-tls-probe.XXXXXX)"
  TEMP_FILES+=("$output_file")
  code="$(curl --silent --show-error --head --location --proto '=https' --tlsv1.2 \
    --connect-timeout 8 --max-time 15 --output /dev/null --write-out '%{http_code}' \
    "$url" 2>"$output_file" || true)"
  if [[ "$code" =~ ^2[0-9][0-9]$ ]]; then
    return 0
  fi
  category="$(classify_failure "$output_file" "$code")"
  [[ "$category" == tls_certificate ]] && return 2
  return 1
}

ensure_certificate_trust() {
  [[ -f /etc/ssl/certs/ca-certificates.crt ]] || die "Trust store padrão Debian ausente."
  if [[ "$INSTALL_MODE" == offline ]]; then
    if _select_explicit_ca >/dev/null; then
      bootstrap_corporate_ca
    else
      info "Modo offline: probes HTTPS ignorados; trust store padrão preservado."
    fi
    return 0
  fi
  local probe_status
  if _https_probe https://pypi.org/simple/; then
    ok "Probe HTTPS com trust store padrão passou."
    return 0
  else
    probe_status=$?
  fi
  if [[ "$probe_status" == 2 ]]; then
    warn "Falha de validação TLS; possível inspeção TLS/proxy corporativo detectado."
    bootstrap_corporate_ca || die "TLS falhou e nenhuma CA institucional explícita foi fornecida. Use --ca-cert ou inclua corporate-ca.crt na mídia."
    _https_probe https://pypi.org/simple/ || die "Probe HTTPS continua falhando após trust configurado; confira diagnóstico/proxy."
  else
    diagnose_network_failure
    die "Probe HTTPS falhou por conectividade/proxy/HTTP, não por CA TLS; trust store não foi alterado."
  fi
  ok "HTTPS validado após instalar CA explicitamente confiável."
}
