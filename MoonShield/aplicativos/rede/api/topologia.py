"""Endpoint de leitura da topologia oficial de Rede."""

from __future__ import annotations

from django.http import JsonResponse
from django.views.decorators.http import require_GET

from rede.dominio.erros import RedeErro
from rede.services.reconciliacao import reconciliar_interfaces
from rede.services.topologia import obter_topologia


def _erro(*, codigo: str, mensagem: str, status: int = 400, detalhes=None) -> JsonResponse:
    payload = {"ok": False, "erro": {"codigo": codigo, "mensagem": mensagem}}
    if detalhes is not None:
        payload["erro"]["detalhes"] = detalhes
    return JsonResponse(payload, status=status)


@require_GET
def api_topologia(request) -> JsonResponse:
    """Retorna topologia fresca quando possível e persistida quando o Agent falha."""
    if not request.user.is_authenticated:
        return _erro(codigo="nao_autenticado", mensagem="Autenticação necessária.", status=401)

    try:
        reconciliar_interfaces()
        reconciliado = True
        aviso = None
    except RedeErro as exc:
        reconciliado = False
        aviso = {"codigo": exc.codigo, "mensagem": exc.mensagem}
    except Exception as exc:
        return _erro(
            codigo="topologia_reconciliacao_error",
            mensagem="Não foi possível atualizar o inventário de Rede.",
            detalhes={"erro": str(exc)},
            status=500,
        )

    try:
        return JsonResponse({
            "ok": True,
            "dados": {
                "topologia": obter_topologia(),
                "reconciliado": reconciliado,
                "aviso": aviso,
            },
        })
    except Exception as exc:
        return _erro(
            codigo="topologia_error",
            mensagem="Não foi possível montar a topologia de Rede.",
            detalhes={"erro": str(exc)},
            status=500,
        )
