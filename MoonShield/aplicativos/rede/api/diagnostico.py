"""
MoonShield Network API
======================

Diagnóstico do módulo de Rede.

O Django não executa comandos Linux diretamente.

Fluxo:

    API
      ↓
    services/diagnostico.py
      ↓
    MoonShield-Agent
      ↓
    testes reais

Exemplos de verificações futuras:

- NetworkManager;
- interfaces;
- carrier;
- IPv4;
- gateway;
- rota padrão;
- ip_forward;
- NAT;
- conectividade externa.
"""

from __future__ import annotations

from django.http import JsonResponse
from django.views.decorators.http import (
    require_GET,
)

from rede.dominio.erros import (
    AgentIndisponivelErro,
    AgentTimeoutErro,
    RedeErro,
)

from rede.services.diagnostico import (
    executar_diagnostico,
)


# =============================================================================
# HELPERS
# =============================================================================


def _resposta(
    dados=None,
    *,
    status: int = 200,
) -> JsonResponse:
    return JsonResponse(
        {
            "ok": True,
            "dados": (
                dados
                if dados is not None
                else {}
            ),
        },
        status=status,
    )


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
        payload["erro"][
            "detalhes"
        ] = detalhes

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


# =============================================================================
# DIAGNÓSTICO
# =============================================================================


@require_GET
def api_diagnostico(request):
    """
    GET /rede/api/diagnostico/

    Executa diagnóstico real através do Agent.

    Endpoint somente leitura.
    """

    if not request.user.is_authenticated:
        return _erro(
            codigo="nao_autenticado",
            mensagem="Autenticação necessária.",
            status=401,
        )

    try:
        diagnostico = (
            executar_diagnostico()
        )

        return _resposta(
            diagnostico
        )

    except AgentIndisponivelErro as exc:
        return _erro_rede(
            exc,
            status=503,
        )

    except AgentTimeoutErro as exc:
        return _erro_rede(
            exc,
            status=504,
        )

    except RedeErro as exc:
        return _erro_rede(
            exc
        )

    except Exception as exc:
        return _erro(
            codigo="diagnostico_rede_error",
            mensagem=(
                "Não foi possível executar "
                "o diagnóstico de rede."
            ),
            detalhes={
                "erro": str(exc),
            },
            status=500,
        )