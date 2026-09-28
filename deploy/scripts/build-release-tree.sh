#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)"
OUTPUT="${1:-$REPO_ROOT/build/moonshield-root}"

python3 - "$REPO_ROOT" "$OUTPUT" <<'PY'
from pathlib import Path
import shutil
import sys

source = Path(sys.argv[1]).resolve()
target = Path(sys.argv[2]).resolve()
if target == source or source in target.parents or target in source.parents:
    raise SystemExit("[ERROR] output deve ficar fora da árvore fonte.")
if target.exists():
    raise SystemExit("[ERROR] output já existe; preservado. Escolha outro diretório vazio.")

excluded_dirs = {
    ".git", ".venv", "venv", "env", "node_modules", "__pycache__",
    ".pytest_cache", "staticfiles", "media", "logs", "offline-bundle",
    "build", ".vscode", ".idea", "tests", "test", "__tests__",
}
excluded_names = {
    ".env", "config.json", "AdGuardHome_linux_amd64.tar.gz",
    "db.sqlite3", "test_db.sqlite3", "FETCH_HEAD",
}

def ignore(directory: str, names: list[str]) -> set[str]:
    ignored = set()
    current = Path(directory).resolve()
    for name in names:
        path = Path(directory) / name
        if name in excluded_names or name in excluded_dirs:
            ignored.add(name)
        elif name == "var" and current == source / "MoonShield":
            ignored.add(name)
        elif name.endswith((".pyc", ".pyo", ".sqlite3", ".log", ".tmp")):
            ignored.add(name)
        elif name == "tests.py" or (name.startswith("test_") and name.endswith(".py")):
            ignored.add(name)
        elif name.startswith(".env."):
            ignored.add(name)
        elif path.is_dir() and name.startswith(".git"):
            ignored.add(name)
    return ignored

target.mkdir(parents=True)
for name in ("MoonShield", "MoonShield-Agent", "deploy"):
    source_path = source / name
    if not source_path.is_dir():
        raise SystemExit(f"[ERROR] diretório obrigatório ausente: {name}")
    shutil.copytree(source_path, target / name, ignore=ignore, symlinks=False)
for name in ("requirements-prod.txt",):
    src = source / name
    if not src.is_file():
        raise SystemExit(f"[ERROR] arquivo obrigatório ausente: {name}")
    shutil.copy2(src, target / name)

for path in target.rglob("*.sh"):
    path.chmod(path.stat().st_mode | 0o111)
for path in target.rglob("moonshield-install-check"):
    path.chmod(path.stat().st_mode | 0o111)
print(f"[OK] Release tree criado em {target}; source não foi alterado.")
PY
