"""
MoonShield Agent — Rede / Roteamento
====================================

Consulta e auxilia na aplicação de roteamento IPv4.

Este módulo não decide qual interface é WAN.
Essa decisão vem do estado desejado enviado pelo Django.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .configuracao import obter_backend


IPV4_FORWARD_PATH = Path("/proc/sys/net/ipv4/ip_forward")


# =============================================================================
# IPv4 FORWARD
# =============================================================================

def obter_ipv4_forward() -> bool:
    try:
        return IPV4_FORWARD_PATH.read_text(encoding="utf-8").strip() == "1"
    except (OSError, ValueError):
        return False


def definir_ipv4_forward(ativo: bool) -> dict[str, Any]:
    valor = "1" if bool(ativo) else "0"

    try:
        IPV4_FORWARD_PATH.write_text(valor, encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(
            f"Não foi possível alterar net.ipv4.ip_forward: {exc}"
        ) from exc

    atual = obter_ipv4_forward()

    if atual != bool(ativo):
        raise RuntimeError(
            "O valor de net.ipv4.ip_forward não permaneceu no estado solicitado."
        )

    return {
        "ok": True,
        "ipv4_forward": atual,
    }


# =============================================================================
# ROTAS
# =============================================================================

def listar_rotas() -> list[dict[str, Any]]:
    backend = obter_backend()
    return backend.obter_rotas()


def listar_rotas_default() -> list[dict[str, Any]]:
    return [
        rota
        for rota in listar_rotas()
        if rota.get("default")
    ]


def obter_rota_default() -> dict[str, Any] | None:
    rotas = listar_rotas_default()

    if not rotas:
        return None

    def chave(rota: dict[str, Any]) -> tuple[int, str]:
        metrica = rota.get("metrica")
        try:
            metrica = int(metrica)
        except (TypeError, ValueError):
            metrica = 2**31 - 1

        return metrica, str(rota.get("interface") or "")

    return sorted(rotas, key=chave)[0]


# =============================================================================
# STATUS
# =============================================================================

def obter_status_roteamento() -> dict[str, Any]:
    backend = obter_backend()

    rotas = backend.obter_rotas()
    defaults = [
        rota
        for rota in rotas
        if rota.get("default")
    ]

    rota_principal = obter_rota_default()

    return {
        "backend": backend.nome,
        "ipv4_forward": obter_ipv4_forward(),
        "rotas": rotas,
        "total_rotas": len(rotas),
        "rotas_default": defaults,
        "total_rotas_default": len(defaults),
        "rota_default": rota_principal,
    }


# =============================================================================
# CONFIGURAÇÃO PERSISTENTE DE ROTAS
# =============================================================================

def configurar_rotas(
    rotas: list[dict[str, Any]],
    *,
    interfaces_alvo: list[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(rotas, list):
        raise ValueError("'rotas' precisa ser uma lista.")

    backend = obter_backend()

    return backend.configurar_rotas(
        rotas,
        interfaces_alvo=interfaces_alvo,
    )


__all__ = [
    "IPV4_FORWARD_PATH",
    "obter_ipv4_forward",
    "definir_ipv4_forward",
    "listar_rotas",
    "listar_rotas_default",
    "obter_rota_default",
    "obter_status_roteamento",
    "configurar_rotas",
]