"""
MoonShield Agent — Suricata / Status
====================================

Leitura operacional do Suricata.

Não decide topologia. Quando uma configuração é enviada pelo Control Plane,
ela é apenas comparada com o estado observado do host.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from suricata.configuracao import (
    EVE_PADRAO,
    RULES_MS_PADRAO,
    YAML_PADRAO,
    normalizar_config,
)

VERSAO_STATUS = "1.0"
TIMEOUT = 20


def obter_status(dados: dict[str, Any] | None = None) -> dict[str, Any]:
    dados = dados or {}
    config_raw = dados.get("config") if isinstance(dados, dict) else None

    desejado = None
    erro_config = ""
    if config_raw:
        try:
            desejado = normalizar_config(config_raw)
        except Exception as exc:
            erro_config = str(exc)

    yaml_path = Path(
        desejado.yaml_path if desejado else str(dados.get("suricata_yaml") or YAML_PADRAO)
    )
    eve_path = Path(
        desejado.eve_path if desejado else str(dados.get("eve_path") or EVE_PADRAO)
    )

    versao = _versao_suricata()
    servico = _servico()
    observado = _ler_observado_yaml(yaml_path)
    eve = _status_eve(eve_path)

    drift: dict[str, Any] = {}
    if desejado:
        drift = {
            "home_net": sorted(observado.get("home_net", [])) != sorted(desejado.home_net),
            "interfaces_monitoradas": (
                observado.get("interfaces_monitoradas", [])
                != list(desejado.interfaces_monitoradas)
            ),
            "eve_path": bool(
                observado.get("eve_path")
                and observado.get("eve_path") != desejado.eve_path
            ),
            "rules_ms": not observado.get("rules_ms_carregada", False),
        }

    tem_drift = any(drift.values()) if drift else False

    return {
        "ok": bool(versao.get("instalado")),
        "versao_status": VERSAO_STATUS,
        "modo": "ids_passivo",
        "suricata": versao,
        "servico": servico,
        "yaml": {
            "path": str(yaml_path),
            "existe": yaml_path.exists(),
        },
        "observado": observado,
        "desejado": desejado.para_dict() if desejado else None,
        "erro_config_desejada": erro_config,
        "drift": {
            "tem_drift": tem_drift,
            "campos": drift,
        },
        "eve": eve,
        "rules_ms": {
            "path": str(RULES_MS_PADRAO),
            "existe": RULES_MS_PADRAO.exists(),
            "bytes": RULES_MS_PADRAO.stat().st_size if RULES_MS_PADRAO.exists() else 0,
        },
        "atualizado_em": datetime.now(timezone.utc).isoformat(),
    }


def _versao_suricata() -> dict[str, Any]:
    binario = shutil.which("suricata")
    if not binario:
        return {"instalado": False, "binario": "", "versao": ""}

    r = subprocess.run(
        [binario, "--version"],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    texto = (r.stdout or r.stderr or "").strip()
    return {
        "instalado": r.returncode == 0,
        "binario": binario,
        "versao": texto.splitlines()[0] if texto else "",
    }


def _servico() -> dict[str, Any]:
    systemctl = shutil.which("systemctl")
    if not systemctl:
        return {"disponivel": False, "active": False, "estado": "systemd_ausente"}

    r = subprocess.run(
        [systemctl, "is-active", "suricata"],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    estado = (r.stdout or "").strip() or "unknown"
    return {
        "disponivel": True,
        "active": r.returncode == 0 and estado == "active",
        "estado": estado,
    }


def _ler_observado_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "home_net": [],
            "interfaces_monitoradas": [],
            "eve_path": "",
            "rules_ms_carregada": False,
        }

    texto = path.read_text(encoding="utf-8", errors="ignore")
    home: list[str] = []

    m = re.search(r'(?m)^\s*HOME_NET:\s*["\']?(\[[^\n"\']+\])', texto)
    if m:
        raw = m.group(1).strip()[1:-1]
        home = [x.strip() for x in raw.split(",") if x.strip()]

    interfaces: list[str] = []
    m_af = re.search(r"(?ms)^af-packet:\n(?:(?:[ \t].*)?\n)*", texto)
    if m_af:
        for iface in re.findall(r"(?m)^\s*-\s+interface:\s*([^\s#]+)", m_af.group(0)):
            if iface not in {"default", "none"} and iface not in interfaces:
                interfaces.append(iface)

    eve_path = ""
    m_eve = re.search(
        r"(?ms)^\s*-\s+eve-log:\s*\n(.*?)(?=^\s*-\s+\S|\Z)",
        texto,
    )
    if m_eve:
        m_file = re.search(r"(?m)^\s*filename:\s*([^\s#]+)", m_eve.group(1))
        if m_file:
            eve_path = m_file.group(1).strip()

    return {
        "home_net": home,
        "interfaces_monitoradas": interfaces,
        "eve_path": eve_path,
        "rules_ms_carregada": "moonshield/ms.rules" in texto,
    }


def _status_eve(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "existe": False,
            "path": str(path),
            "bytes": 0,
            "ultimo_evento": None,
        }

    ultimo = None
    try:
        with path.open("rb") as fp:
            fp.seek(0, 2)
            tamanho = fp.tell()
            bloco = min(tamanho, 131072)
            fp.seek(max(0, tamanho - bloco))
            linhas = fp.read().decode("utf-8", errors="ignore").splitlines()
        for linha in reversed(linhas):
            if not linha.strip():
                continue
            try:
                item = json.loads(linha)
                ultimo = {
                    "timestamp": item.get("timestamp"),
                    "event_type": item.get("event_type"),
                }
                break
            except Exception:
                continue
    except Exception:
        tamanho = path.stat().st_size

    return {
        "existe": True,
        "path": str(path),
        "bytes": path.stat().st_size,
        "mtime": path.stat().st_mtime,
        "ultimo_evento": ultimo,
    }


def status(dados: dict[str, Any] | None = None) -> dict[str, Any]:
    return obter_status(dados)
