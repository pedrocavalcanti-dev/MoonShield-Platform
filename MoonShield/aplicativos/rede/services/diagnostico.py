"""
MoonShield Network
==================

Serviço Django para diagnóstico da camada de Rede.

Os testes reais são executados pelo MoonShield-Agent.

Exemplos futuros:

    NetworkManager
    interfaces
    carrier
    gateway
    rota default
    ip_forward
    NAT
    internet
"""

from __future__ import annotations

from typing import Any

from rede.services.agent_client import (
    requisitar_agent,
)


# =============================================================================
# EXECUÇÃO
# =============================================================================


def executar_diagnostico() -> dict:
    """
    Solicita diagnóstico completo ao Agent.
    """

    dados = requisitar_agent(
        "network.diagnostics"
    )

    testes = dados.get(
        "checks",
        dados.get(
            "testes",
            [],
        ),
    )

    if not isinstance(
        testes,
        list,
    ):
        testes = []

    normalizados = [
        normalizar_teste(
            teste
        )
        for teste in testes
        if isinstance(
            teste,
            dict,
        )
    ]

    resumo = calcular_resumo(
        normalizados
    )

    return {
        "ok": resumo["falhas"] == 0,
        "backend": dados.get(
            "backend",
            "unknown",
        ),
        "resumo": resumo,
        "testes": normalizados,
    }


# =============================================================================
# NORMALIZAÇÃO
# =============================================================================


def normalizar_teste(
    teste: dict,
) -> dict:
    """
    Formato normalizado:

    {
        "codigo": "gateway",
        "nome": "Gateway",
        "status": "ok",
        "mensagem": "...",
        "detalhes": {}
    }
    """

    status = str(
        teste.get(
            "status",
            "unknown",
        )
    ).strip().lower()

    if status not in {
        "ok",
        "warning",
        "error",
        "unknown",
    }:
        status = "unknown"

    return {
        "codigo": str(
            teste.get(
                "codigo",
                teste.get(
                    "code",
                    "",
                ),
            )
        ).strip(),

        "nome": str(
            teste.get(
                "nome",
                teste.get(
                    "name",
                    "",
                ),
            )
        ).strip(),

        "status": status,

        "mensagem": str(
            teste.get(
                "mensagem",
                teste.get(
                    "message",
                    "",
                ),
            )
        ).strip(),

        "detalhes": (
            teste.get("detalhes")
            or teste.get("details")
            or {}
        ),
    }


# =============================================================================
# RESUMO
# =============================================================================


def calcular_resumo(
    testes: list[dict],
) -> dict:
    """
    Calcula totais para cards/API.
    """

    resultado = {
        "total": len(
            testes
        ),
        "sucessos": 0,
        "avisos": 0,
        "falhas": 0,
        "desconhecidos": 0,
    }

    for teste in testes:
        status = teste.get(
            "status"
        )

        if status == "ok":
            resultado[
                "sucessos"
            ] += 1

        elif status == "warning":
            resultado[
                "avisos"
            ] += 1

        elif status == "error":
            resultado[
                "falhas"
            ] += 1

        else:
            resultado[
                "desconhecidos"
            ] += 1

    return resultado


def diagnostico_saudavel(
    diagnostico: dict[str, Any],
) -> bool:
    """
    Retorna True quando não existe falha crítica.
    """

    resumo = diagnostico.get(
        "resumo",
        {},
    )

    return (
        resumo.get(
            "falhas",
            0,
        )
        == 0
    )