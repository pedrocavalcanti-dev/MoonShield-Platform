"""
MoonShield Network API
======================

Status geral do módulo de Rede.

Este endpoint é somente leitura.

Não modifica:
- interfaces;
- rotas;
- NAT;
- NetworkManager;
- nftables.
"""

from __future__ import annotations

from django.http import JsonResponse
from django.views.decorators.http import require_GET

from rede.models import (
    AlteracaoRede,
    RegraNat,
    RotaEstatica,
)

from rede.dominio.erros import (
    RedeErro,
)
from rede.dominio.tipos import EstadoSincronizacao, PapelInterface
from rede.services.agent_client import AgentClient
from rede.services.reconciliacao import obter_estado_reconciliado, reconciliar_interfaces
from rede.services.topologia import obter_topologia


# =============================================================================
# HELPERS
# =============================================================================


def _erro(
    *,
    codigo: str,
    mensagem: str,
    status: int = 400,
    detalhes=None,
) -> JsonResponse:
    payload = {
        "ok": False,
        "erro": {
            "codigo": codigo,
            "mensagem": mensagem,
        },
    }

    if detalhes is not None:
        payload["erro"]["detalhes"] = detalhes

    return JsonResponse(
        payload,
        status=status,
    )


def _erro_rede(
    exc: RedeErro,
    *,
    status: int = 400,
) -> JsonResponse:
    return _erro(
        codigo=exc.codigo,
        mensagem=exc.mensagem,
        detalhes=exc.detalhes,
        status=status,
    )


def _nao_autenticado() -> JsonResponse:
    return _erro(
        codigo="nao_autenticado",
        mensagem="Autenticação necessária.",
        status=401,
    )


def _resultado_persistido(exc: RedeErro) -> tuple[dict, bool, dict]:
    """Retorna o último observado e deixa explícita a falha de atualização."""
    resultado = obter_estado_reconciliado()
    interfaces = resultado.get("interfaces", [])
    resultado["backend"] = next(
        (
            interface.get("real", {}).get("backend")
            for interface in interfaces
            if interface.get("real", {}).get("backend")
        ),
        None,
    )
    return resultado, False, {"codigo": exc.codigo, "mensagem": exc.mensagem}


def _resumo_interfaces(resultado: dict, topologia: dict) -> dict:
    interfaces = resultado.get("interfaces", [])
    estados = {estado.value: 0 for estado in EstadoSincronizacao}

    for interface in interfaces:
        estado = interface.get("estado_sincronizacao")
        if estado in estados:
            estados[estado] += 1

    gerenciadas = [
        interface for interface in interfaces
        if str(
            interface.get("desejado", {}).get("papel")
            or PapelInterface.NAO_ATRIBUIDA.value
        ) != PapelInterface.NAO_ATRIBUIDA.value
    ]

    return {
        "total": len(interfaces),
        "configuradas": len(gerenciadas),
        "pendentes": sum(
            estados[estado.value]
            for estado in (
                EstadoSincronizacao.PENDING_APPLY,
                EstadoSincronizacao.APPLYING,
                EstadoSincronizacao.WAITING_CONFIRMATION,
            )
        ),
        "nao_atribuidas": estados[EstadoSincronizacao.UNMANAGED.value],
        "sincronizadas": estados[EstadoSincronizacao.SYNCED.value],
        "estados_sincronizacao": estados,
        "wan_principal": topologia["wan"]["principal"],
        "lan_principal": topologia["lan"]["principal"],
        "mgmt_principal": topologia["mgmt"]["principal"],
    }


# =============================================================================
# STATUS
# =============================================================================


@require_GET
def api_status_rede(request):
    """
    GET /rede/api/status/

    Retorna:

    - estado do Agent;
    - backend de rede;
    - quantidade de interfaces;
    - interfaces configuradas;
    - alterações pendentes;
    - NAT;
    - rotas.
    """

    if not request.user.is_authenticated:
        return _nao_autenticado()

    agent_online = False
    agent_status = {}
    agent_erro = None

    try:
        agent_status = AgentClient().status()
        agent_online = True
    except RedeErro as exc:
        agent_erro = {
            "codigo": exc.codigo,
            "mensagem": exc.mensagem,
        }
    except Exception as exc:
        agent_erro = {
            "codigo": "agent_status_error",
            "mensagem": str(exc),
        }

    try:
        resultado, reconciliado, aviso = reconciliar_interfaces(), True, None
    except RedeErro as exc:
        try:
            resultado, reconciliado, aviso = _resultado_persistido(exc)
        except RedeErro:
            return _erro_rede(exc, status=503)
        except Exception:
            return _erro_rede(exc, status=503)
    except Exception as exc:
        return _erro(
            codigo="network_status_error",
            mensagem="Não foi possível atualizar o status da Rede.",
            detalhes={"erro": str(exc)},
            status=500,
        )

    topologia = obter_topologia()
    resumo_interfaces = _resumo_interfaces(resultado, topologia)
    backend = resultado.get("backend")

    rotas_ativas = (
        RotaEstatica.objects
        .filter(
            ativa=True
        )
        .count()
    )

    nat_ativo = (
        RegraNat.objects
        .filter(
            ativa=True
        )
        .count()
    )

    alteracoes_pendentes = (
        AlteracaoRede.objects
        .filter(
            status__in=AlteracaoRede.statuses_em_andamento()
        )
        .count()
    )

    # =========================================================================
    # RESPOSTA
    # =========================================================================

    return JsonResponse(
        {
            "ok": True,

            "dados": {
                "modulo": "rede",

                "reconciliado": reconciliado,

                "aviso": aviso,

                "backend": backend,

                "agent": {
                    "online": agent_online,
                    "status": agent_status,
                    "erro": agent_erro,
                },

                "interfaces": resumo_interfaces,

                "topologia": topologia,

                "roteamento": {
                    "rotas_ativas": rotas_ativas,
                },

                "nat": {
                    "regras_ativas": nat_ativo,
                },

                "alteracoes": {
                    "pendentes": (
                        alteracoes_pendentes
                    ),
                },
            },
        }
    )
