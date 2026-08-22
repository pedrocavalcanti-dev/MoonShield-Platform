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
    require_POST,
)

from rede.dominio.erros import (
    AgentIndisponivelErro,
    RedeErro,
)

from rede.services.alteracoes import (
    aplicar_alteracao,
    criar_alteracao_roteamento,
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

    # =========================================================================
    # POST
    # =========================================================================

    if request.method == "POST":
        try:
            dados = _ler_json(
                request
            )

            rota = salvar_rota(
                dados
            )

            return _resposta(
                {
                    "rota": (
                        serializar_rota(
                            rota
                        )
                    ),

                    "mensagem": (
                        "Rota salva como "
                        "estado desejado."
                    ),
                },
                status=201,
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
                    "route_create_error"
                ),

                mensagem=(
                    "Não foi possível "
                    "criar a rota."
                ),

                detalhes={
                    "erro": str(
                        exc
                    )
                },

                status=500,
            )

    return _erro(
        codigo="metodo_nao_permitido",
        mensagem="Método não permitido.",
        status=405,
    )


# =============================================================================
# DETALHE / ATUALIZAÇÃO / EXCLUSÃO
# =============================================================================


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

    # =========================================================================
    # POST
    # =========================================================================

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

    return _erro(
        codigo="metodo_nao_permitido",
        mensagem="Método não permitido.",
        status=405,
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