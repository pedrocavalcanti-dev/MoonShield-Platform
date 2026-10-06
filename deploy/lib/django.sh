#!/usr/bin/env bash

install_django_application() {
  local python_bin=/opt/moonshield/venv/bin/python django_dir=/opt/moonshield/source/MoonShield
  [[ -f /etc/moonshield/appliance.conf && -s /etc/moonshield/database.env ]] || die "Configuração de appliance/database externa ausente."
  [[ -s /etc/moonshield/secrets/django_secret_key ]] || die "SECRET_KEY não provisionada."
  [[ -f "$django_dir/gerenciar.py" ]] || die "gerenciar.py ausente no source release."
  [[ -x "$python_bin" ]] || die "Python do virtualenv Django ausente: $python_bin."
  info "Django runtime: python=$python_bin; cwd=$django_dir; DJANGO_SETTINGS_MODULE=config.settings."
  _run_django_step check "$python_bin" gerenciar.py check || die "Django check falhou; detalhes sanitizados registrados acima."
  _run_django_step migrate "$python_bin" gerenciar.py migrate --noinput || die "Django migrate falhou; detalhes sanitizados registrados acima."
  _run_django_step collectstatic "$python_bin" gerenciar.py collectstatic --noinput || die "Django collectstatic falhou; detalhes sanitizados registrados acima."
  [[ -d /var/lib/moonshield/static ]] || die "STATIC_ROOT esperado não foi criado."
  chown -R moonshield:www-data /var/lib/moonshield/static /var/lib/moonshield/media
  find /var/lib/moonshield/static /var/lib/moonshield/media -type d -exec chmod 0750 {} +
  find /var/lib/moonshield/static /var/lib/moonshield/media -type f -exec chmod 0640 {} +
  for static_file in \
    /var/lib/moonshield/static/css/autenticacao/login.css \
    /var/lib/moonshield/static/js/autenticacao/login.js; do
    [[ -s "$static_file" ]] || die "Staticfile obrigatório ausente/vazio: $static_file."
    runuser -u www-data -- test -r "$static_file" || die "www-data não consegue ler staticfile obrigatório: $static_file."
  done
  [[ ! -L /var/log/moonshield && ! -L /var/log/moonshield/app ]] || die "Diretório de logs Django é symlink; destino preservado sem alteração."
  install -d -o moonshield -g moonshield -m 0750 /var/log/moonshield/app
  chown -R moonshield:moonshield /var/log/moonshield/app
  find /var/log/moonshield/app -type d -exec chmod 0750 {} +
  find /var/log/moonshield/app -type f -exec chmod 0640 {} +
  _run_django_step final-check runuser -u moonshield -- "$python_bin" gerenciar.py check || die "Django check final falhou como usuário do serviço; detalhes sanitizados registrados acima."
  ok "Migrations/collectstatic concluídos; nenhuma conta inicial ou Django superuser foi criada."
}

_sanitize_django_output() {
  python3 - "$1" <<'PY'
from pathlib import Path
import re
import sys

text = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
patterns = (
    (r"(?i)(postgres(?:ql)?://[^:/@\s]+:)[^@/\s]+(@)", r"\1***\2"),
    (r"(?i)(\b(?:secret(?:_key)?|database_password|password|passwd|token|api[_-]?key|authorization|cookie|database_url)\b\s*[=:]\s*)[^\s,;]+", r"\1***"),
)
for pattern, replacement in patterns:
    text = re.sub(pattern, replacement, text)
text = re.sub(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]+", r"\1***", text)
text = re.sub(r"(?im)^.*\b(?:authorization|proxy-authorization|set-cookie|cookie|maintenance[_ -]?response)\b.*$", "[sensitive header/response redacted]", text)
text = re.sub(r"(?im)(^\s*(?:authorization|proxy-authorization)\s*[:=]\s*).*$", r"\1***", text)
text = re.sub(r"(?im)(^\s*(?:set-cookie|cookie)\s*[:=]\s*).*$", r"\1***", text)
for line in text.splitlines():
    print(line[:2000])
PY
}

_run_django_step() {
  local step="$1"; shift
  local output_file status line
  output_file="$(mktemp /tmp/moonshield-django.XXXXXX)"
  TEMP_FILES+=("$output_file")
  info "Django comando: (cd /opt/moonshield/source/MoonShield && $*)"
  if (cd /opt/moonshield/source/MoonShield && "$@") >"$output_file" 2>&1; then
    status=0
  else
    status=$?
  fi
  while IFS= read -r line; do
    [[ -n "$line" ]] && log "$([[ "$status" == 0 ]] && printf INFO || printf ERROR)" "Django $step: $line"
  done < <(_sanitize_django_output "$output_file")
  log "$([[ "$status" == 0 ]] && printf OK || printf ERROR)" "Django $step terminou (exit=$status)."
  rm -f -- "$output_file"
  [[ "$status" == 0 ]]
}
