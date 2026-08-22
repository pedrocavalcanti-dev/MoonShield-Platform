"""
MoonShield Agent — Rede / Inventário
====================================

Consulta o estado real da rede através do backend ativo.

Não define papéis WAN/LAN/MGMT.
Não altera interfaces.
Não aplica configuração.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from rede.backends.base import BackendRedeErro
from .configuracao import VERSAO_MODULO_REDE, detectar_backend, obter_backend, obter_info_ambiente


def _agora_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# =============================================================================
# INVENTÁRIO
# =============================================================================

def obter_inventario(*, incluir_loopback: bool = False) -> dict[str, Any]:
    backend = obter_backend()
    interfaces = backend.listar_interfaces(incluir_loopback=incluir_loopback)

    return {
        "backend": backend.nome,
        "versao_backend": backend.versao,
        "interfaces": interfaces,
        "total": len(interfaces),
        "atualizado_em": _agora_iso(),
    }


def listar_interfaces(*, incluir_loopback: bool = False) -> list[dict[str, Any]]:
    return obter_inventario(incluir_loopback=incluir_loopback)["interfaces"]


def obter_interface(nome: str) -> dict[str, Any]:
    if not nome or not str(nome).strip():
        raise ValueError("Nome da interface não informado.")

    backend = obter_backend()
    return backend.obter_interface(str(nome).strip())


# =============================================================================
# STATUS
# =============================================================================

def obter_status_rede() -> dict[str, Any]:
    backend_nome = detectar_backend()

    if not backend_nome:
        return {
            "ok": False,
            "modulo": "rede",
            "versao": VERSAO_MODULO_REDE,
            "backend": None,
            "disponivel": False,
            "interfaces": 0,
            "erro": {
                "codigo": "backend_nao_detectado",
                "mensagem": "Nenhum backend de rede suportado foi detectado.",
            },
            "ambiente": obter_info_ambiente(),
            "atualizado_em": _agora_iso(),
        }

    try:
        backend = obter_backend()
        status_backend = backend.status()
        interfaces = backend.listar_interfaces(incluir_loopback=False)

        total = len(interfaces)
        links_up = sum(1 for item in interfaces if item.get("estado_link") == "up")
        com_ipv4 = sum(1 for item in interfaces if item.get("ipv4_atual"))

        return {
            "ok": True,
            "modulo": "rede",
            "versao": VERSAO_MODULO_REDE,
            "backend": backend.nome,
            "versao_backend": backend.versao,
            "disponivel": True,
            "status_backend": status_backend,
            "interfaces": total,
            "interfaces_up": links_up,
            "interfaces_com_ipv4": com_ipv4,
            "atualizado_em": _agora_iso(),
        }

    except BackendRedeErro as exc:
        return {
            "ok": False,
            "modulo": "rede",
            "versao": VERSAO_MODULO_REDE,
            "backend": backend_nome,
            "disponivel": False,
            "interfaces": 0,
            "erro": {
                "codigo": getattr(exc, "codigo", "backend_rede_erro"),
                "mensagem": str(exc),
                "detalhes": getattr(exc, "detalhes", {}),
            },
            "atualizado_em": _agora_iso(),
        }


# =============================================================================
# RESUMO
# =============================================================================

def obter_resumo_interfaces() -> dict[str, Any]:
    interfaces = listar_interfaces()

    resumo = {
        "total": len(interfaces),
        "up": 0,
        "down": 0,
        "com_ipv4": 0,
        "com_rota_default": 0,
    }

    for interface in interfaces:
        if interface.get("estado_link") == "up":
            resumo["up"] += 1
        else:
            resumo["down"] += 1

        if interface.get("ipv4_atual"):
            resumo["com_ipv4"] += 1

        if interface.get("rota_default"):
            resumo["com_rota_default"] += 1

    return resumo


__all__ = [
    "obter_inventario",
    "listar_interfaces",
    "obter_interface",
    "obter_status_rede",
    "obter_resumo_interfaces",
]