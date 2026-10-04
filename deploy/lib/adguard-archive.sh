#!/usr/bin/env bash

# Valida o contrato do artefato oficial antes de qualquer extração. O mesmo
# contrato é aplicado no builder e no installer para não aceitar um bundle que
# a appliance depois recusaria.
validate_adguard_archive() {
  local archive="$1"
  [[ -f "$archive" ]] || return 1
  python3 - "$archive" <<'PY'
from pathlib import Path
import sys
import tarfile

archive_path = Path(sys.argv[1])
root = "AdGuardHome"
binary = f"{root}/AdGuardHome"
seen = set()
has_root = False
binary_member = None

try:
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
except (OSError, tarfile.TarError) as exc:
    raise SystemExit(f"arquivo tar inválido: {exc}")

if not members:
    raise SystemExit("arquivo tar vazio")

for member in members:
    raw_name = member.name
    name = raw_name
    while name.startswith("./"):
        name = name[2:]
    parts = name.split("/")
    if (
        not name
        or raw_name.startswith("/")
        or "\\" in raw_name
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise SystemExit(f"caminho inválido no tar: {raw_name!r}")
    if name != root and not name.startswith(f"{root}/"):
        raise SystemExit(f"caminho fora da árvore permitida: {raw_name!r}")
    if name in seen:
        raise SystemExit(f"entrada duplicada no tar: {name!r}")
    seen.add(name)
    if member.issym() or member.islnk() or member.isdev() or member.isfifo():
        raise SystemExit(f"tipo de entrada não permitido no tar: {name!r}")
    if not (member.isdir() or member.isreg()):
        raise SystemExit(f"tipo de entrada inesperado no tar: {name!r}")
    if name == root:
        if not member.isdir():
            raise SystemExit("raiz AdGuardHome não é diretório")
        has_root = True
    elif name == binary:
        binary_member = member

if not has_root:
    raise SystemExit("diretório raiz AdGuardHome ausente")
if binary_member is None or not binary_member.isreg() or not (binary_member.mode & 0o111):
    raise SystemExit("binário executável AdGuardHome ausente")
PY
}
