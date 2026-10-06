#!/usr/bin/env bash
set -Eeuo pipefail

python_bin="${PYTHON_BIN:-python3}"
workdir="$(mktemp -d)"
trap 'rm -rf -- "$workdir"' EXIT

"$python_bin" - "$workdir" <<'PY'
from pathlib import Path
import sys
from zipfile import ZipFile


def write_wheel(wheelhouse: Path, name: str, version: str) -> None:
    wheelhouse.mkdir(parents=True, exist_ok=True)
    filename = wheelhouse / f"{name}-{version}-py3-none-any.whl"
    with ZipFile(filename, "w") as archive:
        archive.writestr(
            f"{name}-{version}.dist-info/METADATA",
            f"Name: {name}\nVersion: {version}\n",
        )


def contains_required_pillow(wheelhouse: Path) -> bool:
    for wheel in wheelhouse.glob("*.whl"):
        with ZipFile(wheel) as archive:
            metadata = next(
                (name for name in archive.namelist() if name.endswith(".dist-info/METADATA")),
                "",
            )
            if not metadata:
                continue
            values = {}
            for line in archive.read(metadata).decode("utf-8", errors="replace").splitlines():
                key, separator, value = line.partition(":")
                if not separator:
                    continue
                values[key.strip().casefold()] = value.strip()
            if (
                values.get("name", "").casefold() == "pillow"
                and values.get("version") == "12.1.1"
            ):
                return True
    return False


root = Path(sys.argv[1])
cases = (
    ("lowercase-name", "pillow", "12.1.1", True),
    ("wrong-version", "pillow", "12.1.0", False),
    ("normal-name", "Pillow", "12.1.1", True),
)
for directory, name, version, expected in cases:
    wheelhouse = root / directory
    write_wheel(wheelhouse, name, version)
    actual = contains_required_pillow(wheelhouse)
    if actual != expected:
        raise SystemExit(
            f"Pillow gate mismatch for Name={name!r}, Version={version!r}: "
            f"expected {expected}, got {actual}."
        )
PY

printf '%s\n' 'Pillow wheelhouse gate regression tests passed.'
