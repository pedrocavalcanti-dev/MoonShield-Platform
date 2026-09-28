#!/usr/bin/env bash

install_django_application() {
  local python_bin=/opt/moonshield/venv/bin/python django_dir=/opt/moonshield/source/MoonShield
  [[ -f /etc/moonshield/appliance.conf && -s /etc/moonshield/database.env ]] || die "Configuração de appliance/database externa ausente."
  [[ -s /etc/moonshield/secrets/django_secret_key ]] || die "SECRET_KEY não provisionada."
  [[ -f "$django_dir/gerenciar.py" ]] || die "gerenciar.py ausente no source release."
  (cd "$django_dir" && "$python_bin" gerenciar.py check) || die "Django check falhou; migrations não serão iniciadas."
  (cd "$django_dir" && "$python_bin" gerenciar.py migrate --noinput) || die "Django migrate falhou."
  (cd "$django_dir" && "$python_bin" gerenciar.py collectstatic --noinput) || die "Django collectstatic falhou."
  [[ -d /var/lib/moonshield/static ]] || die "STATIC_ROOT esperado não foi criado."
  chown -R moonshield:www-data /var/lib/moonshield/static /var/lib/moonshield/media
  chmod 0750 /var/lib/moonshield/static /var/lib/moonshield/media
  [[ ! -L /var/log/moonshield && ! -L /var/log/moonshield/app ]] || die "Diretório de logs Django é symlink; destino preservado sem alteração."
  install -d -o moonshield -g moonshield -m 0750 /var/log/moonshield/app
  chown -R moonshield:moonshield /var/log/moonshield/app
  find /var/log/moonshield/app -type d -exec chmod 0750 {} +
  find /var/log/moonshield/app -type f -exec chmod 0640 {} +
  (cd "$django_dir" && runuser -u moonshield -- "$python_bin" gerenciar.py check) || die "Django check final falhou como usuário do serviço."
  ok "Migrations/collectstatic concluídos; nenhuma conta inicial ou Django superuser foi criada."
}
