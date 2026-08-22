"""
MoonShield Network API
======================

Endpoints das interfaces de rede.

Fluxos:

LISTAR
    PostgreSQL → API

DETECTAR
    Agent → Linux → inventário → PostgreSQL

CONFIGURAR
    API → estado desejado → PostgreSQL

APLICAR
    API
      ↓
    AlteracaoRede
      ↓
    safe apply
      ↓
    Agent
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
    criar_alteracao_interface,
    serializar_alteracao,
)

from rede.services.interfaces import (
    listar_interfaces,
    obter_interface_por_id,
    salvar_configuracao_interface,
    serializar_interface,
    sincronizar_inventario,
)

from rede.services.inventario import (
    obter_inventario,
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
    """
    Converte body JSON em dict.
    """

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
# LISTAR
# =============================================================================


@require_GET
def api_interfaces(request):
    """
    GET /rede/api/interfaces/

    Lista interfaces já conhecidas pelo MoonShield.

    Não chama o Agent automaticamente.
    """

    auth = _autenticado(
        request
    )

    if auth:
        return auth

    try:
        interfaces = (
            listar_interfaces()
        )

        return _resposta(
            {
                "total": len(
                    interfaces
                ),

                "interfaces": (
                    interfaces
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
                "interfaces_list_error"
            ),

            mensagem=(
                "Não foi possível listar "
                "as interfaces."
            ),

            detalhes={
                "erro": str(
                    exc
                )
            },

            status=500,
        )


# =============================================================================
# DETECTAR / SINCRONIZAR INVENTÁRIO
# =============================================================================


@require_POST
def api_interfaces_detectar(request):
    """
    POST /rede/api/interfaces/detectar/

    Consulta o Agent e atualiza somente o ESTADO REAL.

    Não altera configuração desejada.
    """

    auth = _autenticado(
        request
    )

    if auth:
        return auth

    try:
        inventario = (
            obter_inventario()
        )

        sincronizar_inventario(
            inventario
        )

        interfaces = (
            listar_interfaces()
        )

        return _resposta(
            {
                "backend": (
                    inventario.get(
                        "backend"
                    )
                ),

                "total": len(
                    interfaces
                ),

                "interfaces": interfaces,
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
                "interface_detection_error"
            ),

            mensagem=(
                "Falha ao detectar interfaces."
            ),

            detalhes={
                "erro": str(
                    exc
                )
            },

            status=500,
        )


# =============================================================================
# DETALHE
# =============================================================================


@require_GET
def api_interface_detalhe(
    request,
    interface_id: int,
):
    """
    GET /rede/api/interfaces/<id>/
    """

    auth = _autenticado(
        request
    )

    if auth:
        return auth

    try:
        interface = (
            obter_interface_por_id(
                interface_id
            )
        )

        return _resposta(
            serializar_interface(
                interface
            )
        )

    except RedeErro as exc:
        return _erro_rede(
            exc,
            status=404,
        )

    except Exception as exc:
        return _erro(
            codigo=(
                "interface_detail_error"
            ),

            mensagem=(
                "Não foi possível carregar "
                "a interface."
            ),

            detalhes={
                "erro": str(
                    exc
                )
            },

            status=500,
        )


# =============================================================================
# CONFIGURAR ESTADO DESEJADO
# =============================================================================


@require_POST
def api_interface_configurar(
    request,
    interface_id: int,
):
    """
    POST /rede/api/interfaces/<id>/configurar/

    Salva configuração desejada.

    NÃO altera o Linux.
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

        interface_atual = (
            obter_interface_por_id(
                interface_id
            )
        )

        interface = (
            salvar_configuracao_interface(
                interface_atual.nome,
                dados,
            )
        )

        return _resposta(
            {
                "interface": (
                    serializar_interface(
                        interface
                    )
                ),

                "mensagem": (
                    "Configuração desejada salva. "
                    "Ainda não aplicada no Linux."
                ),
            }
        )

    except ValueError as exc:
        return _erro(
            codigo="json_invalido",
            mensagem=str(
                exc
            ),
            status=400,
        )

    except RedeErro as exc:
        return _erro_rede(
            exc
        )

    except Exception as exc:
        return _erro(
            codigo=(
                "interface_config_error"
            ),

            mensagem=(
                "Não foi possível salvar "
                "a configuração da interface."
            ),

            detalhes={
                "erro": str(
                    exc
                )
            },

            status=500,
        )


# =============================================================================
# APLICAR
# =============================================================================


@require_POST
def api_interface_aplicar(
    request,
    interface_id: int,
):
    """
    POST /rede/api/interfaces/<id>/aplicar/

    Cria AlteracaoRede e dispara safe apply.
    """

    auth = _autenticado(
        request
    )

    if auth:
        return auth

    try:
        # Confirma existência antes de criar alteração.
        obter_interface_por_id(
            interface_id
        )

        alteracao = (
            criar_alteracao_interface(
                interface_id,
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
                    "Configuração enviada para "
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
                "interface_apply_error"
            ),

            mensagem=(
                "Falha ao aplicar interface."
            ),

            detalhes={
                "erro": str(
                    exc
                )
            },

            status=500,
        )