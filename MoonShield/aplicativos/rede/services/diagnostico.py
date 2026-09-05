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

from rede.dominio.erros import AgentRespostaInvalidaErro, RedeErro
from rede.dominio.tipos import NivelEventoRede
from rede.services.alteracoes import registrar_evento
from rede.services.agent_client import (
    requisitar_agent,
)
from rede.services.topologia import obter_topologia


# =============================================================================
# EXECUÇÃO
# =============================================================================


def executar_diagnostico(*, usuario=None) -> dict:
    """
    Solicita diagnóstico completo ao Agent.
    """

    try:
        dados = requisitar_agent("network.diagnostics")
    except RedeErro as exc:
        _registrar_falha_diagnostico(exc, usuario=usuario)
        raise

    if not isinstance(dados, dict):
        erro = AgentRespostaInvalidaErro(
            "A resposta de diagnostico do Agent deve ser um objeto JSON."
        )
        _registrar_falha_diagnostico(erro, usuario=usuario)
        raise erro

    testes = dados.get(
        "checks",
        dados.get(
            "testes",
            [],
        ),
    )

    if not isinstance(testes, list) or not testes:
        erro = AgentRespostaInvalidaErro(
            "A resposta de diagnostico do Agent nao possui checks validos."
        )
        _registrar_falha_diagnostico(erro, usuario=usuario)
        raise erro

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

    if not normalizados:
        erro = AgentRespostaInvalidaErro(
            "A resposta de diagnostico do Agent nao possui checks estruturados."
        )
        _registrar_falha_diagnostico(erro, usuario=usuario)
        raise erro

    topologia = obter_topologia()
    saudavel = resumo["falhas"] == 0 and resumo["desconhecidos"] == 0
    diagnostico = {
        "ok": saudavel,
        "saudavel": saudavel,
        "resultado": _resultado(resumo),
        "backend": dados.get(
            "backend",
            "unknown",
        ),
        "executado_em": dados.get("executado_em"),
        "resumo": resumo,
        "testes": normalizados,
        "topologia": _resumir_topologia(topologia),
    }

    _registrar_resultado_diagnostico(diagnostico, usuario=usuario)
    return diagnostico


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


def _resultado(resumo: dict) -> str:
    if resumo["falhas"]:
        return "error"

    if resumo["avisos"] or resumo["desconhecidos"]:
        return "warning"

    return "ok"


def _resumir_topologia(topologia: dict) -> dict:
    """Retorna somente o contexto oficial necessario ao diagnostico."""
    return {
        "valida": bool(topologia.get("valida")),
        "wan": _nome_interface(topologia.get("wan", {}).get("principal")),
        "lan": _nome_interface(topologia.get("lan", {}).get("principal")),
        "mgmt": _nome_interface(topologia.get("mgmt", {}).get("principal")),
        "home_net": list(topologia.get("home_net") or []),
        "problemas": _codigos_topologia(topologia.get("problemas")),
        "avisos": _codigos_topologia(topologia.get("avisos")),
    }


def _nome_interface(interface: Any) -> str | None:
    if not isinstance(interface, dict):
        return None

    nome = str(interface.get("nome") or "").strip()
    return nome or None


def _codigos_topologia(itens: Any) -> list[str]:
    if not isinstance(itens, list):
        return []

    return [
        str(item.get("codigo")).strip()
        for item in itens
        if isinstance(item, dict) and str(item.get("codigo") or "").strip()
    ]


def _registrar_resultado_diagnostico(
    diagnostico: dict,
    *,
    usuario=None,
) -> None:
    resultado = diagnostico["resultado"]
    nivel = {
        "ok": NivelEventoRede.SUCCESS.value,
        "warning": NivelEventoRede.WARNING.value,
        "error": NivelEventoRede.ERROR.value,
    }[resultado]

    registrar_evento(
        nivel=nivel,
        codigo="network_diagnostic_completed",
        titulo="Diagnostico de rede executado",
        mensagem=_mensagem_resultado(diagnostico),
        dados={
            "tipo": "geral",
            "acao": "network.diagnostics",
            "resultado": resultado,
            "resumo": diagnostico["resumo"],
            "backend": diagnostico["backend"],
            "executado_em": diagnostico["executado_em"],
            "topologia_valida": diagnostico["topologia"]["valida"],
        },
        usuario=usuario,
    )


def _registrar_falha_diagnostico(
    exc: RedeErro,
    *,
    usuario=None,
) -> None:
    registrar_evento(
        nivel=NivelEventoRede.ERROR.value,
        codigo="network_diagnostic_failed",
        titulo="Diagnostico de rede indisponivel",
        mensagem=exc.mensagem,
        dados={
            "tipo": "geral",
            "acao": "network.diagnostics",
            "erro_codigo": exc.codigo,
        },
        usuario=usuario,
    )


def _mensagem_resultado(diagnostico: dict) -> str:
    resumo = diagnostico["resumo"]
    return (
        f"{resumo['total']} check(s): {resumo['sucessos']} sucesso(s), "
        f"{resumo['avisos']} aviso(s), {resumo['falhas']} falha(s)."
    )


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
        and resumo.get("desconhecidos", 0) == 0
        and resumo.get("total", 0) > 0
    )
