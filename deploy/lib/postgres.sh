#!/usr/bin/env bash

_pg_scalar() {
  runuser -u postgres -- psql --no-psqlrc --tuples-only --no-align --dbname postgres --command "$1" 2>/dev/null | tr -d '[:space:]'
}

_read_database_password() {
  python3 - /etc/moonshield/database.env <<'PY'
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit
import sys

values = {}
for raw in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    line = raw.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    key, value = line.split("=", 1)
    values[key.strip()] = value.strip().strip("\"'")
parsed = urlsplit(values.get("DATABASE_URL", ""))
if parsed.scheme not in {"postgres", "postgresql"} or parsed.hostname not in {"127.0.0.1", "localhost"}:
    raise SystemExit(2)
if parsed.username != "moonshield" or parsed.path != "/moonshield":
    raise SystemExit(2)
password = unquote(parsed.password or "")
if not re.fullmatch(r"[A-Za-z0-9._~-]+", password):
    raise SystemExit(2)
print(password, end="")
PY
}

install_postgresql() {
  local pg_version listen role_exists database_exists password db_env=/etc/moonshield/database.env
  systemctl enable postgresql.service >/dev/null
  systemctl start postgresql.service >/dev/null
  systemctl is-active --quiet postgresql.service || die "PostgreSQL não iniciou."
  pg_version="$(psql --version | sed -n 's/.* \([0-9][0-9]*\)\..*/\1/p')"
  [[ "$pg_version" == 17 ]] || die "PostgreSQL incompatível: esperado major 17, obtido ${pg_version:-desconhecido}."
  listen="$(_pg_scalar 'SHOW listen_addresses;')"
  [[ -n "$listen" ]] || die "Não foi possível ler listen_addresses."
  local address
  IFS=',' read -r -a listen_addresses <<<"$listen"
  for address in "${listen_addresses[@]}"; do
    address="$(printf '%s' "$address" | xargs)"
    case "$address" in
      localhost|127.0.0.1|::1) ;;
      *) die "PostgreSQL está configurado para escutar além de loopback; configuração preservada e instalação interrompida." ;;
    esac
  done
  role_exists="$(_pg_scalar "SELECT count(*) FROM pg_roles WHERE rolname='moonshield';")"
  database_exists="$(_pg_scalar "SELECT count(*) FROM pg_database WHERE datname='moonshield';")"

  if [[ -f "$db_env" ]]; then
    password="$(_read_database_password)" || die "database.env não segue o formato local PostgreSQL esperado; preservado e não interpretado como shell."
    [[ -n "$password" ]] || die "database.env não contém password utilizável; não será rotacionado."
    if [[ "$role_exists" == 0 ]]; then
      printf "CREATE ROLE moonshield LOGIN PASSWORD '%s';\n" "$password" | runuser -u postgres -- psql --no-psqlrc --set=ON_ERROR_STOP=1 --dbname postgres >/dev/null
      role_exists=1
      ok "Role PostgreSQL recriada a partir da credencial persistida (sem imprimir segredo)."
    fi
    if [[ "$database_exists" == 0 ]]; then
      printf 'CREATE DATABASE moonshield OWNER moonshield;\n' | runuser -u postgres -- psql --no-psqlrc --set=ON_ERROR_STOP=1 --dbname postgres >/dev/null
      ok "Database moonshield criada; nenhum banco existente foi apagado."
    fi
    chown root:moonshield "$db_env"
    chmod 0640 "$db_env"
  else
    if [[ "$role_exists" != 0 || "$database_exists" != 0 ]]; then
      die "Role/database já existe mas /etc/moonshield/database.env está ausente; recusando redefinir senha ou assumir propriedade."
    fi
    password="$(openssl rand -hex 32)"
    printf "CREATE ROLE moonshield LOGIN PASSWORD '%s';\nCREATE DATABASE moonshield OWNER moonshield;\n" "$password" | runuser -u postgres -- psql --no-psqlrc --set=ON_ERROR_STOP=1 --dbname postgres >/dev/null
    printf 'DATABASE_URL=postgresql://moonshield:%s@127.0.0.1:5432/moonshield\n' "$password" >"$db_env"
    chown root:moonshield "$db_env"
    chmod 0640 "$db_env"
    ok "Role/database criados e URL local persistida em database.env com 0640."
  fi

  password="$(_read_database_password)" || die "DATABASE_URL não aponta para PostgreSQL local esperado."
  PGPASSWORD="$password" psql --no-psqlrc --host=127.0.0.1 --port=5432 --username=moonshield --dbname=moonshield --tuples-only --no-align --command='SELECT 1' >/dev/null 2>&1 || die "Autenticação/conectividade PostgreSQL local falhou; segredo existente não foi alterado."
  ok "PostgreSQL 17 autenticado exclusivamente em loopback."
}
