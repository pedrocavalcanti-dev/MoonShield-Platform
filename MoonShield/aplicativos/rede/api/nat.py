"""
MoonShield Network API
======================

API de NAT.

Responsabilidades:
- listar/criar/editar/remover estado desejado NAT;
- consultar estado real via Agent;
- aplicar NAT pelo Safe Apply.

Nenhuma operação nftables é executada pelo Django.
"""

from __future__ import annotations

import json

from django.http import JsonResponse
from django.views.decorators.http import require_GET, require_POST, require_http_methods

from rede.dominio.erros import (
    AgentIndisponivelErro,
    AgentTimeoutErro,
    AlteracaoEstadoInvalidoErro,
    AlteracaoExpiradaErro,
    AlteracaoNaoEncontradaErro,
    RedeErro,
)
from rede.models import AlteracaoRede
from rede.services.alteracoes import (
    aplicar_alteracao,
    criar_alteracao_nat,
    obter_alteracao,
    obter_alteracao_ativa,
    reconciliar_alteracoes_expiradas,
    serializar_alteracao,
)
from rede.services.nat import (
    excluir_regra_nat,
    listar_regras_nat,
    obter_estado_nat_real,
    obter_regra_nat,
    salvar_regra_nat,
    serializar_regra_nat,
)


def _resposta(dados=None, *, status: int = 200) -> JsonResponse:
    return JsonResponse({"ok": True, "dados": dados if dados is not None else {}}, status=status)


def _erro(*, codigo: str, mensagem: str, status: int = 400, detalhes=None) -> JsonResponse:
    payload = {"ok": False, "erro": {"codigo": codigo, "mensagem": mensagem}}
    if detalhes is not None:
        payload["erro"]["detalhes"] = detalhes
    return JsonResponse(payload, status=status)


def _detalhes_com_alteracao(exc: RedeErro) -> dict:
    detalhes = dict(exc.detalhes or {})
    alteracao_id = detalhes.get("alteracao_id")
    if alteracao_id:
        try:
            detalhes["alteracao"] = serializar_alteracao(obter_alteracao(alteracao_id))
        except Exception:
            pass
    return detalhes


def _erro_rede(exc: RedeErro, *, status: int | None = None) -> JsonResponse:
    if status is None:
        status = 400
        if isinstance(exc, AlteracaoNaoEncontradaErro):
            status = 404
        elif isinstance(exc, AgentIndisponivelErro):
            status = 503
        elif isinstance(exc, AgentTimeoutErro):
            status = 504
        elif isinstance(exc, (AlteracaoEstadoInvalidoErro, AlteracaoExpiradaErro)):
            status = 409

    detalhes = _detalhes_com_alteracao(exc)
    codigo = exc.codigo
    if (
        status == 409
        and isinstance(exc, AlteracaoEstadoInvalidoErro)
        and detalhes.get("alteracao_id")
        and detalhes.get("status") in set(AlteracaoRede.statuses_em_andamento())
    ):
        codigo = "alteracao_rede_em_andamento"

    return _erro(codigo=codigo, mensagem=exc.mensagem, detalhes=detalhes, status=status)


def _autenticado(request):
    if request.user.is_authenticated:
        return None
    return _erro(codigo="nao_autenticado", mensagem="Autenticação necessária.", status=401)


def _ler_json(request) -> dict:
    if not request.body:
        return {}
    try:
        dados = json.loads(request.body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("JSON inválido.") from exc
    if not isinstance(dados, dict):
        raise ValueError("O corpo da requisição deve ser um objeto JSON.")
    return dados


def _bloquear_mutacao_durante_safe_apply():
    try:
        reconciliar_alteracoes_expiradas()
    except Exception:
        pass

    ativa = obter_alteracao_ativa()
    if ativa is None:
        return None

    return _erro(
        codigo="alteracao_rede_em_andamento",
        mensagem="Existe uma alteração de Rede aguardando conclusão.",
        status=409,
        detalhes={
            "alteracao_id": str(ativa.id),
            "status": ativa.status,
            "status_label": ativa.get_status_display(),
            "titulo": ativa.titulo,
            "alteracao": serializar_alteracao(ativa),
        },
    )


@require_http_methods(["GET", "POST"])
def api_nat(request):
    """
    GET  /rede/api/nat/
    POST /rede/api/nat/

    POST salva apenas estado desejado.
    """
    auth = _autenticado(request)
    if auth:
        return auth

    if request.method == "GET":
        try:
            regras = listar_regras_nat()
            return _resposta({"total": len(regras), "regras": regras})
        except RedeErro as exc:
            return _erro_rede(exc)
        except Exception as exc:
            return _erro(
                codigo="nat_list_error",
                mensagem="Não foi possível listar as regras NAT.",
                detalhes={"erro": str(exc)},
                status=500,
            )

    bloqueio = _bloquear_mutacao_durante_safe_apply()
    if bloqueio:
        return bloqueio

    try:
        regra = salvar_regra_nat(_ler_json(request))
        return _resposta({
            "regra": serializar_regra_nat(regra),
            "mensagem": "Regra NAT salva como estado desejado. Ainda não aplicada no Linux.",
        }, status=201)
    except ValueError as exc:
        return _erro(codigo="json_invalido", mensagem=str(exc))
    except RedeErro as exc:
        return _erro_rede(exc)
    except Exception as exc:
        return _erro(
            codigo="nat_create_error",
            mensagem="Não foi possível criar a regra NAT.",
            detalhes={"erro": str(exc)},
            status=500,
        )


@require_http_methods(["GET", "POST", "DELETE"])
def api_nat_detalhe(request, regra_id: int):
    """
    GET    /rede/api/nat/<id>/
    POST   /rede/api/nat/<id>/
    DELETE /rede/api/nat/<id>/
    """
    auth = _autenticado(request)
    if auth:
        return auth

    if request.method == "GET":
        try:
            return _resposta(serializar_regra_nat(obter_regra_nat(regra_id)))
        except RedeErro as exc:
            return _erro_rede(exc, status=404)
        except Exception as exc:
            return _erro(
                codigo="nat_detail_error",
                mensagem="Não foi possível carregar a regra NAT.",
                detalhes={"erro": str(exc)},
                status=500,
            )

    bloqueio = _bloquear_mutacao_durante_safe_apply()
    if bloqueio:
        return bloqueio

    if request.method == "POST":
        try:
            regra = salvar_regra_nat(_ler_json(request), regra_id=regra_id)
            return _resposta({
                "regra": serializar_regra_nat(regra),
                "mensagem": "Regra NAT atualizada. Alteração ainda não aplicada.",
            })
        except ValueError as exc:
            return _erro(codigo="json_invalido", mensagem=str(exc))
        except RedeErro as exc:
            return _erro_rede(exc)
        except Exception as exc:
            return _erro(
                codigo="nat_update_error",
                mensagem="Não foi possível atualizar a regra NAT.",
                detalhes={"erro": str(exc)},
                status=500,
            )

    try:
        excluir_regra_nat(regra_id)
        return _resposta({
            "removida": True,
            "id": regra_id,
            "mensagem": "Regra removida do estado desejado. Aplique NAT para sincronizar o Linux.",
        })
    except RedeErro as exc:
        return _erro_rede(exc, status=404)
    except Exception as exc:
        return _erro(
            codigo="nat_delete_error",
            mensagem="Não foi possível remover a regra NAT.",
            detalhes={"erro": str(exc)},
            status=500,
        )


@require_GET
def api_nat_real(request):
    """GET /rede/api/nat/real/ — consulta nftables via Agent sem alteração."""
    auth = _autenticado(request)
    if auth:
        return auth

    try:
        return _resposta(obter_estado_nat_real())
    except AgentIndisponivelErro as exc:
        return _erro_rede(exc, status=503)
    except RedeErro as exc:
        return _erro_rede(exc)
    except Exception as exc:
        return _erro(
            codigo="nat_real_status_error",
            mensagem="Não foi possível consultar o estado NAT real.",
            detalhes={"erro": str(exc)},
            status=500,
        )


@require_POST
def api_nat_aplicar(request):
    """
    POST /rede/api/nat/aplicar/

    O service garante exclusividade global do Safe Apply.
    """
    auth = _autenticado(request)
    if auth:
        return auth

    try:
        alteracao = criar_alteracao_nat(
            usuario=request.user,
            requer_confirmacao=True,
        )
        alteracao = aplicar_alteracao(alteracao.id)

        return _resposta({
            "alteracao": serializar_alteracao(alteracao),
            "mensagem": "Configuração NAT enviada para aplicação segura.",
        }, status=202)
    except AgentIndisponivelErro as exc:
        return _erro_rede(exc, status=503)
    except RedeErro as exc:
        return _erro_rede(exc)
    except Exception as exc:
        return _erro(
            codigo="nat_apply_error",
            mensagem="Não foi possível aplicar a configuração NAT.",
            detalhes={"erro": str(exc)},
            status=500,
        )