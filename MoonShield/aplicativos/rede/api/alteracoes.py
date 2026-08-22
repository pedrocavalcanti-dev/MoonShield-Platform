"""
MoonShield Network API
======================

API do sistema de alterações seguras da Rede.

Endpoints responsáveis por:

- histórico;
- detalhe;
- confirmação;
- rollback;
- cancelamento;
- consulta de estado no Agent;
- reconciliação;
- aplicação completa da Rede.

IMPORTANTE:

O timer real de rollback pertence ao MoonShield-Agent.

O Django registra e apresenta o estado,
mas não é a autoridade responsável pela recuperação
de conectividade.
"""

from __future__ import annotations

from uuid import UUID

from django.http import JsonResponse
from django.views.decorators.http import (
    require_GET,
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

from rede.models import (
    AlteracaoRede,
)

from rede.services.alteracoes import (
    aplicar_alteracao,
    cancelar_alteracao,
    confirmar_alteracao,
    consultar_status_agent,
    criar_alteracao_geral,
    executar_rollback,
    listar_alteracoes,
    obter_alteracao,
    reconciliar_alteracoes_expiradas,
    serializar_alteracao,
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
    status: int | None = None,
) -> JsonResponse:
    """
    Mapeia erros conhecidos para HTTP.
    """

    if status is None:
        status = 400

        if isinstance(
            exc,
            AlteracaoNaoEncontradaErro,
        ):
            status = 404

        elif isinstance(
            exc,
            AgentIndisponivelErro,
        ):
            status = 503

        elif isinstance(
            exc,
            AgentTimeoutErro,
        ):
            status = 504

        elif isinstance(
            exc,
            (
                AlteracaoEstadoInvalidoErro,
                AlteracaoExpiradaErro,
            ),
        ):
            status = 409

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


# =============================================================================
# LISTAR
# =============================================================================


@require_GET
def api_alteracoes(request):
    """
    GET /rede/api/alteracoes/

    Filtros opcionais:

        ?status=waiting_confirmation
        ?tipo=interface
        ?limite=50
    """

    auth = _autenticado(
        request
    )

    if auth:
        return auth

    try:
        status_filtro = (
            request.GET.get(
                "status"
            )
        )

        tipo_filtro = (
            request.GET.get(
                "tipo"
            )
        )

        limite = (
            request.GET.get(
                "limite",
                100,
            )
        )

        # =====================================================================
        # VALIDA STATUS
        # =====================================================================

        if status_filtro:
            status_validos = {
                item[0]
                for item
                in AlteracaoRede.Status.choices
            }

            if (
                status_filtro
                not in status_validos
            ):
                return _erro(
                    codigo=(
                        "status_alteracao_invalido"
                    ),
                    mensagem=(
                        "Status de alteração "
                        "inválido."
                    ),
                    detalhes={
                        "recebido": (
                            status_filtro
                        ),
                        "validos": sorted(
                            status_validos
                        ),
                    },
                )

        # =====================================================================
        # VALIDA TIPO
        # =====================================================================

        if tipo_filtro:
            tipos_validos = {
                item[0]
                for item
                in AlteracaoRede.Tipo.choices
            }

            if (
                tipo_filtro
                not in tipos_validos
            ):
                return _erro(
                    codigo=(
                        "tipo_alteracao_invalido"
                    ),
                    mensagem=(
                        "Tipo de alteração "
                        "inválido."
                    ),
                    detalhes={
                        "recebido": tipo_filtro,
                        "validos": sorted(
                            tipos_validos
                        ),
                    },
                )

        alteracoes = (
            listar_alteracoes(
                status=status_filtro,
                tipo=tipo_filtro,
                limite=limite,
            )
        )

        return _resposta(
            {
                "total": len(
                    alteracoes
                ),

                "alteracoes": (
                    alteracoes
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
                "network_changes_list_error"
            ),
            mensagem=(
                "Não foi possível listar "
                "as alterações de rede."
            ),
            detalhes={
                "erro": str(exc),
            },
            status=500,
        )


# =============================================================================
# DETALHE
# =============================================================================


@require_GET
def api_alteracao_detalhe(
    request,
    alteracao_id: UUID,
):
    """
    GET /rede/api/alteracoes/<uuid>/
    """

    auth = _autenticado(
        request
    )

    if auth:
        return auth

    try:
        alteracao = obter_alteracao(
            alteracao_id
        )

        return _resposta(
            serializar_alteracao(
                alteracao
            )
        )

    except RedeErro as exc:
        return _erro_rede(
            exc
        )

    except Exception as exc:
        return _erro(
            codigo=(
                "network_change_detail_error"
            ),
            mensagem=(
                "Não foi possível carregar "
                "a alteração de rede."
            ),
            detalhes={
                "erro": str(exc),
            },
            status=500,
        )


# =============================================================================
# CONFIRMAR
# =============================================================================


@require_POST
def api_alteracao_confirmar(
    request,
    alteracao_id: UUID,
):
    """
    POST
    /rede/api/alteracoes/<uuid>/confirmar/

    Confirma que o administrador manteve acesso.

    O Agent cancela o rollback automático.
    """

    auth = _autenticado(
        request
    )

    if auth:
        return auth

    try:
        alteracao = confirmar_alteracao(
            alteracao_id,
            usuario=request.user,
        )

        return _resposta(
            {
                "alteracao": (
                    serializar_alteracao(
                        alteracao
                    )
                ),

                "mensagem": (
                    "Alteração confirmada. "
                    "Rollback automático cancelado."
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
                "network_change_confirm_error"
            ),
            mensagem=(
                "Não foi possível confirmar "
                "a alteração."
            ),
            detalhes={
                "erro": str(exc),
            },
            status=500,
        )


# =============================================================================
# ROLLBACK
# =============================================================================


@require_POST
def api_alteracao_rollback(
    request,
    alteracao_id: UUID,
):
    """
    POST
    /rede/api/alteracoes/<uuid>/rollback/

    Solicita rollback manual ao Agent.
    """

    auth = _autenticado(
        request
    )

    if auth:
        return auth

    try:
        motivo = (
            request.POST.get(
                "motivo"
            )
            or "Rollback solicitado pelo administrador."
        )

        alteracao = executar_rollback(
            alteracao_id,
            usuario=request.user,
            motivo=str(
                motivo
            ).strip(),
        )

        return _resposta(
            {
                "alteracao": (
                    serializar_alteracao(
                        alteracao
                    )
                ),

                "mensagem": (
                    "Rollback executado."
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
                "network_change_rollback_error"
            ),
            mensagem=(
                "Não foi possível executar "
                "o rollback."
            ),
            detalhes={
                "erro": str(exc),
            },
            status=500,
        )


# =============================================================================
# CANCELAR
# =============================================================================


@require_POST
def api_alteracao_cancelar(
    request,
    alteracao_id: UUID,
):
    """
    POST
    /rede/api/alteracoes/<uuid>/cancelar/

    Somente alterações ainda em estado CRIADA
    podem ser canceladas.
    """

    auth = _autenticado(
        request
    )

    if auth:
        return auth

    try:
        alteracao = cancelar_alteracao(
            alteracao_id,
            usuario=request.user,
        )

        return _resposta(
            {
                "alteracao": (
                    serializar_alteracao(
                        alteracao
                    )
                ),

                "mensagem": (
                    "Alteração cancelada."
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
                "network_change_cancel_error"
            ),
            mensagem=(
                "Não foi possível cancelar "
                "a alteração."
            ),
            detalhes={
                "erro": str(exc),
            },
            status=500,
        )


# =============================================================================
# STATUS NO AGENT
# =============================================================================


@require_GET
def api_alteracao_status_agent(
    request,
    alteracao_id: UUID,
):
    """
    GET
    /rede/api/alteracoes/<uuid>/status-agent/

    Consulta a autoridade real da operação.
    """

    auth = _autenticado(
        request
    )

    if auth:
        return auth

    try:
        resultado = consultar_status_agent(
            alteracao_id
        )

        return _resposta(
            {
                "alteracao_id": str(
                    alteracao_id
                ),

                "agent": resultado,
            }
        )

    except RedeErro as exc:
        return _erro_rede(
            exc
        )

    except Exception as exc:
        return _erro(
            codigo=(
                "network_change_agent_status_error"
            ),
            mensagem=(
                "Não foi possível consultar "
                "o estado da alteração no Agent."
            ),
            detalhes={
                "erro": str(exc),
            },
            status=500,
        )


# =============================================================================
# RECONCILIAÇÃO
# =============================================================================


@require_POST
def api_alteracoes_reconciliar(
    request,
):
    """
    POST /rede/api/alteracoes/reconciliar/

    Verifica alterações expiradas no PostgreSQL
    e pergunta ao Agent o estado real.

    Não executa rollback cegamente.
    """

    auth = _autenticado(
        request
    )

    if auth:
        return auth

    try:
        total = (
            reconciliar_alteracoes_expiradas()
        )

        return _resposta(
            {
                "processadas": total,

                "mensagem": (
                    "Reconciliação concluída."
                ),
            }
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
                "network_reconciliation_error"
            ),
            mensagem=(
                "Não foi possível reconciliar "
                "as alterações."
            ),
            detalhes={
                "erro": str(exc),
            },
            status=500,
        )


# =============================================================================
# APLICAR CONFIGURAÇÃO COMPLETA
# =============================================================================


@require_POST
def api_aplicar_tudo(
    request,
):
    """
    POST /rede/api/alteracoes/aplicar-tudo/

    Envia para o Agent:

    - interfaces;
    - roteamento;
    - NAT.

    Tudo dentro de uma única alteração segura.
    """

    auth = _autenticado(
        request
    )

    if auth:
        return auth

    try:
        alteracao = (
            criar_alteracao_geral(
                usuario=request.user,
                requer_confirmacao=True,
            )
        )

        alteracao = aplicar_alteracao(
            alteracao.id
        )

        return _resposta(
            {
                "alteracao": (
                    serializar_alteracao(
                        alteracao
                    )
                ),

                "mensagem": (
                    "Configuração completa da rede "
                    "enviada para aplicação segura."
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
                "network_apply_all_error"
            ),
            mensagem=(
                "Não foi possível aplicar "
                "a configuração completa da rede."
            ),
            detalhes={
                "erro": str(exc),
            },
            status=500,
        )