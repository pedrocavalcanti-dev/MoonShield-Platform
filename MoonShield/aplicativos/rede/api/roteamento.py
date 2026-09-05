"""
MoonShield Network API
======================

API de roteamento.

Responsabilidades HTTP:

- consultar configuração global;
- salvar ip_forward;
- configurar comportamento de rollback;
- listar rotas;
- criar rota;
- editar rota;
- excluir rota;
- aplicar configuração via safe apply.

Nenhuma view executa comandos Linux diretamente.
"""

from __future__ import annotations

import json

from django.http import JsonResponse
from django.views.decorators.http import (
    require_GET,
    require_http_methods,
    require_POST,
)

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
    criar_alteracao_roteamento,
    obter_alteracao,
    obter_alteracao_ativa,
    reconciliar_alteracoes_expiradas,
    serializar_alteracao,
)

from rede.services.roteamento import (
    excluir_rota,
    listar_rotas,
    obter_configuracao,
    obter_estado_roteamento_real,
    obter_rota,
    salvar_configuracao,
    salvar_rota,
    serializar_configuracao,
    serializar_rota,
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
        payload[
            "erro"
        ][
            "detalhes"
        ] = detalhes

    return JsonResponse(
        payload,
        status=status,
    )


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

    return _erro(
        codigo=codigo,
        mensagem=exc.mensagem,
        detalhes=detalhes,
        status=status,
    )


def _autenticado(request):
    if request.user.is_authenticated:
        return None

    return _erro(
        codigo="nao_autenticado",
        mensagem="Autenticação necessária.",
        status=401,
    )


def _ler_json(
    request,
) -> dict:
    if not request.body:
        return {}

    try:
        dados = json.loads(
            request.body.decode(
                "utf-8"
            )
        )

    except (
        json.JSONDecodeError,
        UnicodeDecodeError,
    ) as exc:
        raise ValueError(
            "JSON inválido."
        ) from exc

    if not isinstance(
        dados,
        dict,
    ):
        raise ValueError(
            (
                "O corpo da requisição "
                "deve ser um objeto JSON."
            )
        )

    return dados


def _bloquear_mutacao_durante_safe_apply():
    """Não mistura novo estado desejado com uma alteração ainda reversível."""
    try:
        reconciliar_alteracoes_expiradas()
    except Exception:
        # Se o Agent não puder confirmar o timeout, preservamos o lock local.
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


# =============================================================================
# CONFIGURAÇÃO GERAL
# =============================================================================


@require_GET
def api_roteamento(request):
    """
    GET /rede/api/roteamento/

    Retorna estado desejado.

    Não chama Agent.
    """

    auth = _autenticado(
        request
    )

    if auth:
        return auth

    try:
        config = (
            obter_configuracao()
        )

        return _resposta(
            {
                "configuracao": (
                    serializar_configuracao(
                        config
                    )
                ),

                "rotas": (
                    listar_rotas()
                ),
                "alteracao_ativa": (
                    serializar_alteracao(obter_alteracao_ativa())
                    if obter_alteracao_ativa()
                    else None
                ),
            }
        )

    except RedeErro as exc:
        return _erro_rede(
            exc
        )

    except Exception as exc:
        return _erro(
            codigo=(
                "routing_status_error"
            ),

            mensagem=(
                "Não foi possível carregar "
                "a configuração de roteamento."
            ),

            detalhes={
                "erro": str(
                    exc
                )
            },

            status=500,
        )


# =============================================================================
# ESTADO REAL
# =============================================================================


@require_GET
def api_roteamento_real(request):
    """
    GET /rede/api/roteamento/real/

    Consulta o Agent.

    Não modifica nada.
    """

    auth = _autenticado(
        request
    )

    if auth:
        return auth

    try:
        estado = (
            obter_estado_roteamento_real()
        )

        return _resposta(
            estado
        )

    except AgentIndisponivelErro as exc:
        return _erro_rede(
            exc,
            status=503,
        )

    except RedeErro as exc:
        return _erro_rede(
            exc
        )

    except Exception as exc:
        return _erro(
            codigo=(
                "routing_real_status_error"
            ),

            mensagem=(
                "Não foi possível consultar "
                "o roteamento real."
            ),

            detalhes={
                "erro": str(
                    exc
                )
            },

            status=500,
        )


# =============================================================================
# SALVAR CONFIGURAÇÃO
# =============================================================================


@require_POST
def api_roteamento_configurar(request):
    """
    POST /rede/api/roteamento/configurar/

    Exemplo:

    {
        "ipv4_forward": true,
        "rollback_automatico": true,
        "tempo_confirmacao": 60
    }

    Apenas PostgreSQL.
    """

    auth = _autenticado(
        request
    )

    if auth:
        return auth

    bloqueio = _bloquear_mutacao_durante_safe_apply()
    if bloqueio:
        return bloqueio

    try:
        dados = _ler_json(
            request
        )

        config = salvar_configuracao(
            dados
        )

        return _resposta(
            {
                "configuracao": (
                    serializar_configuracao(
                        config
                    )
                ),

                "mensagem": (
                    "Configuração de roteamento "
                    "salva como estado desejado."
                ),
            }
        )

    except ValueError as exc:
        return _erro(
            codigo="json_invalido",
            mensagem=str(
                exc
            ),
        )

    except RedeErro as exc:
        return _erro_rede(
            exc
        )

    except Exception as exc:
        return _erro(
            codigo=(
                "routing_config_error"
            ),

            mensagem=(
                "Não foi possível salvar "
                "o roteamento."
            ),

            detalhes={
                "erro": str(
                    exc
                )
            },

            status=500,
        )


# =============================================================================
# LISTAR / CRIAR ROTAS
# =============================================================================


@require_http_methods(["GET", "POST"])
def api_rotas(request):
    """
    GET  /rede/api/roteamento/rotas/
    POST /rede/api/roteamento/rotas/
    """

    auth = _autenticado(
        request
    )

    if auth:
        return auth

    # =========================================================================
    # GET
    # =========================================================================

    if request.method == "GET":
        try:
            rotas = listar_rotas()

            return _resposta(
                {
                    "total": len(
                        rotas
                    ),

                    "rotas": rotas,
                }
            )

        except RedeErro as exc:
            return _erro_rede(
                exc
            )

        except Exception as exc:
            return _erro(
                codigo=(
                    "routes_list_error"
                ),

                mensagem=(
                    "Não foi possível listar "
                    "as rotas."
                ),

                detalhes={
                    "erro": str(
                        exc
                    )
                },

                status=500,
            )

    bloqueio = _bloquear_mutacao_durante_safe_apply()
    if bloqueio:
        return bloqueio

    try:
        rota = salvar_rota(_ler_json(request))
        return _resposta({
            "rota": serializar_rota(rota),
            "mensagem": "Rota salva como estado desejado.",
        }, status=201)
    except ValueError as exc:
        return _erro(codigo="json_invalido", mensagem=str(exc))
    except RedeErro as exc:
        return _erro_rede(exc)
    except Exception as exc:
        return _erro(
            codigo="route_create_error",
            mensagem="Não foi possível criar a rota.",
            detalhes={"erro": str(exc)},
            status=500,
        )


# =============================================================================
# DETALHE / ATUALIZAÇÃO / EXCLUSÃO
# =============================================================================


@require_http_methods(["GET", "POST", "DELETE"])
def api_rota_detalhe(
    request,
    rota_id: int,
):
    """
    GET    /rede/api/roteamento/rotas/<id>/
    POST   /rede/api/roteamento/rotas/<id>/
    DELETE /rede/api/roteamento/rotas/<id>/
    """

    auth = _autenticado(
        request
    )

    if auth:
        return auth

    # =========================================================================
    # GET
    # =========================================================================

    if request.method == "GET":
        try:
            rota = obter_rota(
                rota_id
            )

            return _resposta(
                serializar_rota(
                    rota
                )
            )

        except RedeErro as exc:
            return _erro_rede(
                exc,
                status=404,
            )

    bloqueio = _bloquear_mutacao_durante_safe_apply()
    if bloqueio:
        return bloqueio

    if request.method == "POST":
        try:
            dados = _ler_json(
                request
            )

            rota = salvar_rota(
                dados,
                rota_id=rota_id,
            )

            return _resposta(
                {
                    "rota": (
                        serializar_rota(
                            rota
                        )
                    ),

                    "mensagem": (
                        "Rota atualizada."
                    ),
                }
            )

        except ValueError as exc:
            return _erro(
                codigo="json_invalido",
                mensagem=str(
                    exc
                ),
            )

        except RedeErro as exc:
            return _erro_rede(
                exc
            )

        except Exception as exc:
            return _erro(
                codigo="route_update_error",
                mensagem="Não foi possível atualizar a rota.",
                detalhes={"erro": str(exc)},
                status=500,
            )

    # =========================================================================
    # DELETE
    # =========================================================================

    if request.method == "DELETE":
        try:
            excluir_rota(
                rota_id
            )

            return _resposta(
                {
                    "removida": True,
                    "id": rota_id,
                }
            )

        except RedeErro as exc:
            return _erro_rede(
                exc,
                status=404,
            )

        except Exception as exc:
            return _erro(
                codigo="route_delete_error",
                mensagem="Não foi possível remover a rota.",
                detalhes={"erro": str(exc)},
                status=500,
            )


# =============================================================================
# APLICAR
# =============================================================================


@require_POST
def api_roteamento_aplicar(request):
    """
    POST /rede/api/roteamento/aplicar/

    Aplica todo o estado desejado de roteamento
    usando safe apply.
    """

    auth = _autenticado(
        request
    )

    if auth:
        return auth

    try:
        alteracao = (
            criar_alteracao_roteamento(
                usuario=request.user,
                requer_confirmacao=True,
            )
        )

        alteracao = (
            aplicar_alteracao(
                alteracao.id
            )
        )

        return _resposta(
            {
                "alteracao": (
                    serializar_alteracao(
                        alteracao
                    )
                ),

                "mensagem": (
                    "Roteamento enviado para "
                    "aplicação segura."
                ),
                "alteracao_ativa": serializar_alteracao(alteracao) if alteracao.em_andamento else None,
            },
            status=202,
        )

    except AgentIndisponivelErro as exc:
        return _erro_rede(
            exc,
            status=503,
        )

    except RedeErro as exc:
        return _erro_rede(
            exc
        )

    except Exception as exc:
        return _erro(
            codigo=(
                "routing_apply_error"
            ),

            mensagem=(
                "Não foi possível aplicar "
                "o roteamento."
            ),

            detalhes={
                "erro": str(
                    exc
                )
            },

            status=500,
        )
