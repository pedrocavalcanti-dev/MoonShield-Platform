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

_run_offline_pip() {
  local python_bin="$1" requirements="$2" wheelhouse="$3" output_file category wheel_count requirements_sha line
  output_file="$(mktemp /tmp/moonshield-pip-offline.XXXXXX)"
  TEMP_FILES+=("$output_file")
  wheel_count="$(find "$wheelhouse" -maxdepth 1 -type f -name '*.whl' | wc -l)"
  requirements_sha="$(sha256sum "$requirements" | awk '{print $1}')"
  info "Pip offline: python=$($python_bin --version 2>&1); pip=$($python_bin -m pip --version 2>&1 | cut -d' ' -f1-2); wheels=$wheel_count; wheelhouse=$wheelhouse; requirements_sha=$requirements_sha."
  if "$python_bin" -m pip install --disable-pip-version-check --no-index --only-binary=:all: \
    --find-links "$wheelhouse" --requirement "$requirements" >"$output_file" 2>&1; then
    ok "pip offline concluida."
    return 0
  fi
  category="$(classify_failure "$output_file")"
  while IFS= read -r line; do
    case "$line" in
      *"No matching distribution found"*|*"Could not find a version"*|*"ResolutionImpossible"*|*"Requires-Python"*|*"conflict"*)
        log ERROR "pip offline diagnostico: ${line:0:500}"
        ;;
    esac
  done < <(sed -E 's#(https?://)[^[:space:]@/]+:[^[:space:]@/]+@#\1***:***@#g; s#(password|passwd|secret|token)=([^[:space:]]+)#\1=***#Ig' "$output_file")
  log ERROR "pip offline falhou (classe: $category); wheelhouse=$wheelhouse; requirements_sha=$requirements_sha."
  return 1
}

install_python_runtime() {
  local venv=/opt/moonshield/venv python_bin requirements expected_requirements_sha actual_requirements_sha
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
    requirements=/opt/moonshield/source/requirements-prod.txt
    [[ -r "$requirements" && -d "$OFFLINE_BUNDLE/wheelhouse" && -f "$OFFLINE_BUNDLE/SHA256SUMS" ]] || die "Requirements ou wheelhouse offline ausente."
    (cd "$OFFLINE_BUNDLE" && sha256sum --check SHA256SUMS >/dev/null) || die "Checksum do bundle offline falhou."
    expected_requirements_sha="$(manifest_value "$OFFLINE_BUNDLE/BUILD-INFO" RequirementsProdSHA256 || true)"
    actual_requirements_sha="$(sha256sum "$requirements" | awk '{print $1}')"
    [[ "$expected_requirements_sha" =~ ^[[:xdigit:]]{64}$ && "$expected_requirements_sha" == "$actual_requirements_sha" ]] \
      || die "Requirements da release diverge do bundle offline; instalação Python recusada."
    _run_offline_pip "$python_bin" "$requirements" "$OFFLINE_BUNDLE/wheelhouse" || die "Instalação Python offline falhou; nenhuma tentativa de rede foi feita."
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
