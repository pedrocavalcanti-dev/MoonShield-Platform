"""
MoonShield Network API
======================

Endpoints das interfaces de rede.

Fluxos:
    LISTAR     PostgreSQL → API
    DETECTAR   Agent → Linux → inventário → PostgreSQL
    CONFIGURAR API → estado desejado → PostgreSQL
    APLICAR    API → AlteracaoRede → Safe Apply → Agent
"""

from __future__ import annotations

import json

from django.http import JsonResponse
from django.views.decorators.http import require_GET, require_POST

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
    criar_alteracao_interface,
    obter_alteracao,
    obter_alteracao_ativa,
    reconciliar_alteracoes_expiradas,
    serializar_alteracao,
)
from rede.services.interfaces import (
    listar_interfaces,
    obter_interface_por_id,
    salvar_configuracao_interface,
    serializar_interface,
    sincronizar_inventario,
)
from rede.services.inventario import obter_inventario


def _resposta(dados=None, *, status: int = 200) -> JsonResponse:
    return JsonResponse({"ok": True, "dados": dados if dados is not None else {}}, status=status)


def _erro(*, codigo: str, mensagem: str, status: int = 400, detalhes=None) -> JsonResponse:
    payload = {"ok": False, "erro": {"codigo": codigo, "mensagem": mensagem}}
    if detalhes is not None:
        payload["erro"]["detalhes"] = detalhes
    return JsonResponse(payload, status=status)


def _detalhes_com_alteracao(exc: RedeErro):
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

    codigo = exc.codigo
    detalhes = _detalhes_com_alteracao(exc)

    if (
        status == 409
        and isinstance(exc, AlteracaoEstadoInvalidoErro)
        and detalhes.get("alteracao_id")
        and detalhes.get("status") in set(AlteracaoRede.statuses_em_andamento())
    ):
        codigo = "alteracao_rede_em_andamento"

    return _erro(
        codigo=codigo,
        mensagem=exc.mensagem,
        detalhes=detalhes,
        status=status,
    )


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


def _alteracao_ativa_serializada():
    ativa = obter_alteracao_ativa()
    return serializar_alteracao(ativa) if ativa else None


def _bloquear_configuracao_durante_safe_apply():
    """
    Impede mudança do estado desejado enquanto uma operação de rede está ativa.

    Primeiro tenta limpar timeouts já concluídos no Agent. Se não for possível
    reconciliar, preserva o lock em vez de assumir que a rede está livre.
    """
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


@require_GET
def api_interfaces(request):
    """GET /rede/api/interfaces/"""
    auth = _autenticado(request)
    if auth:
        return auth

    try:
        interfaces = listar_interfaces()
        return _resposta({
            "total": len(interfaces),
            "interfaces": interfaces,
            "alteracao_ativa": _alteracao_ativa_serializada(),
        })
    except RedeErro as exc:
        return _erro_rede(exc)
    except Exception as exc:
        return _erro(
            codigo="interfaces_list_error",
            mensagem="Não foi possível listar as interfaces.",
            detalhes={"erro": str(exc)},
            status=500,
        )


@require_POST
def api_interfaces_detectar(request):
    """
    POST /rede/api/interfaces/detectar/

    Atualiza somente inventário/estado real. Não altera o estado desejado nem
    aplica configuração no Linux, por isso continua permitido durante Safe Apply.
    """
    auth = _autenticado(request)
    if auth:
        return auth

    try:
        inventario = obter_inventario()
        sincronizar_inventario(inventario)
        interfaces = listar_interfaces()

        return _resposta({
            "backend": inventario.get("backend"),
            "total": len(interfaces),
            "interfaces": interfaces,
            "alteracao_ativa": _alteracao_ativa_serializada(),
        })
    except AgentIndisponivelErro as exc:
        return _erro_rede(exc, status=503)
    except RedeErro as exc:
        return _erro_rede(exc)
    except Exception as exc:
        return _erro(
            codigo="interface_detection_error",
            mensagem="Falha ao detectar interfaces.",
            detalhes={"erro": str(exc)},
            status=500,
        )


@require_GET
def api_interface_detalhe(request, interface_id: int):
    """GET /rede/api/interfaces/<id>/"""
    auth = _autenticado(request)
    if auth:
        return auth

    try:
        interface = obter_interface_por_id(interface_id)
        return _resposta({
            "interface": serializar_interface(interface),
            "alteracao_ativa": _alteracao_ativa_serializada(),
        })
    except RedeErro as exc:
        return _erro_rede(exc, status=404)
    except Exception as exc:
        return _erro(
            codigo="interface_detail_error",
            mensagem="Não foi possível carregar a interface.",
            detalhes={"erro": str(exc)},
            status=500,
        )


@require_POST
def api_interface_configurar(request, interface_id: int):
    """
    POST /rede/api/interfaces/<id>/configurar/

    Salva o estado desejado, mas não altera Linux. Durante um Safe Apply ativo,
    bloqueamos a edição para não misturar um desired state novo com uma operação
    que está sendo confirmada/revertida.
    """
    auth = _autenticado(request)
    if auth:
        return auth

    bloqueio = _bloquear_configuracao_durante_safe_apply()
    if bloqueio:
        return bloqueio

    try:
        dados = _ler_json(request)
        interface_atual = obter_interface_por_id(interface_id)
        interface = salvar_configuracao_interface(interface_atual.nome, dados)

        return _resposta({
            "interface": serializar_interface(interface),
            "alteracao_ativa": None,
            "mensagem": "Configuração desejada salva. Ainda não aplicada no Linux.",
        })
    except ValueError as exc:
        return _erro(codigo="json_invalido", mensagem=str(exc), status=400)
    except RedeErro as exc:
        return _erro_rede(exc)
    except Exception as exc:
        return _erro(
            codigo="interface_config_error",
            mensagem="Não foi possível salvar a configuração da interface.",
            detalhes={"erro": str(exc)},
            status=500,
        )


@require_POST
def api_interface_aplicar(request, interface_id: int):
    """
    POST /rede/api/interfaces/<id>/aplicar/

    A criação da alteração usa o lock global do service. Se houver outra operação
    ativa, esta API devolve 409 sem criar uma nova linha de histórico.
    """
    auth = _autenticado(request)
    if auth:
        return auth

    try:
        obter_interface_por_id(interface_id)

        alteracao = criar_alteracao_interface(
            interface_id,
            usuario=request.user,
            requer_confirmacao=True,
        )
        alteracao = aplicar_alteracao(alteracao.id)

        return _resposta({
            "alteracao": serializar_alteracao(alteracao),
            "alteracao_ativa": serializar_alteracao(alteracao) if alteracao.em_andamento else None,
            "mensagem": "Configuração enviada para aplicação segura.",
        }, status=202)
    except AgentIndisponivelErro as exc:
        return _erro_rede(exc, status=503)
    except RedeErro as exc:
        return _erro_rede(exc)
    except Exception as exc:
        return _erro(
            codigo="interface_apply_error",
            mensagem="Falha ao aplicar interface.",
            detalhes={"erro": str(exc)},
            status=500,
        )