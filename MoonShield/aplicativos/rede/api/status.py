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
    InterfaceRede,
    RegraNat,
    RotaEstatica,
)

from rede.services.agent_client import (
    AgentClient,
)

from rede.dominio.erros import (
    RedeErro,
)


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

    # =========================================================================
    # AGENT
    # =========================================================================

    agent_online = False
    agent_status = {}
    agent_erro = None

    try:
        client = AgentClient()

        agent_status = client.status()

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

    # =========================================================================
    # BANCO
    # =========================================================================

    total_interfaces = (
        InterfaceRede.objects.count()
    )

    configuradas = (
        InterfaceRede.objects
        .exclude(
            papel=(
                InterfaceRede
                .Papel
                .NAO_ATRIBUIDA
            )
        )
        .count()
    )

    interfaces_pendentes = (
        InterfaceRede.objects
        .filter(
            pendente=True
        )
        .count()
    )

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
            status__in=[
                AlteracaoRede.Status.CRIADA,
                AlteracaoRede.Status.VALIDANDO,
                AlteracaoRede.Status.APLICANDO,
                (
                    AlteracaoRede
                    .Status
                    .AGUARDANDO_CONFIRMACAO
                ),
                AlteracaoRede.Status.ROLLBACK,
            ]
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

                "agent": {
                    "online": agent_online,
                    "status": agent_status,
                    "erro": agent_erro,
                },

                "interfaces": {
                    "total": total_interfaces,
                    "configuradas": configuradas,
                    "pendentes": (
                        interfaces_pendentes
                    ),
                },

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