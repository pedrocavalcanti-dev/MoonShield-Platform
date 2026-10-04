#!/usr/bin/env bash

_secure_venv_for_moonshield() {
  local venv="$1"
  [[ -d "$venv" && ! -L "$venv" ]] || die "Virtualenv inválido ou ausente: $venv."
  [[ -d "$venv/bin" && ! -L "$venv/bin" ]] || die "Diretório bin do virtualenv inválido."
  chown -R root:moonshield "$venv"
  find "$venv" -type d -exec chmod 0750 {} +
  find "$venv" -type f -exec chmod 0640 {} +
  find "$venv/bin" -type f -exec chmod 0750 {} +
  [[ ! -n "$(find "$venv" ! -type l -perm -0020 -print -quit)" ]] \
    || die "Virtualenv ficou gravável pelo grupo moonshield; instalação recusada."
  runuser -u moonshield -- "$venv/bin/python" --version >/dev/null \
    || die "Usuário moonshield não consegue executar o Python do virtualenv."
}

install_python_runtime() {
  local venv=/opt/moonshield/venv python_bin
  python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 13) and sys.version_info < (3, 14) else 1)' || die "Python runtime incompatível; appliance requer Python 3.13.x."
  if [[ ! -x "$venv/bin/python" ]]; then
    python3 -m venv "$venv"
    chown -R root:root "$venv"
    chmod -R go-w "$venv"
    ok "Virtualenv criado em /opt/moonshield/venv."
  else
    info "Virtualenv existente preservado; dependências serão reconciliadas com pins versionados."
  fi
  python_bin="$venv/bin/python"
  if [[ "$INSTALL_MODE" == offline ]]; then
    [[ -d "$OFFLINE_BUNDLE/wheelhouse" && -f "$OFFLINE_BUNDLE/SHA256SUMS" ]] || die "Wheelhouse offline ausente."
    (cd "$OFFLINE_BUNDLE" && sha256sum --check SHA256SUMS >/dev/null) || die "Checksum do bundle offline falhou."
    run_checked "pip offline" "$python_bin" -m pip install --disable-pip-version-check --no-index --find-links "$OFFLINE_BUNDLE/wheelhouse" --requirement /opt/moonshield/source/requirements-prod.txt || die "Instalação Python offline falhou; nenhuma tentativa de rede foi feita."
  else
    run_with_tls_retry "pip install" "$python_bin" -m pip install --disable-pip-version-check --requirement /opt/moonshield/source/requirements-prod.txt || die "Instalação das dependências Python falhou."
  fi
  local expected_gunicorn actual_gunicorn
  expected_gunicorn="$(manifest_value "$MANIFEST_DIR/versions.env" GUNICORN_VERSION)"
  actual_gunicorn="$("$venv/bin/gunicorn" --version 2>&1 || true)"
  [[ "$actual_gunicorn" == *"${expected_gunicorn}"* ]] || die "Gunicorn incompatível; baseline esperado ${expected_gunicorn}."
  run_checked "pip check" "$python_bin" -m pip check || die "Dependências Python inconsistentes."
  _secure_venv_for_moonshield "$venv"
  ok "Ambiente Python validado."
}
