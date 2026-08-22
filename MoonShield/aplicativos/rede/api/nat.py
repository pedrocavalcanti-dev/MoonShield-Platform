"""
MoonShield Network API
======================

API de NAT.

Responsabilidades HTTP:

- listar configuração NAT desejada;
- criar regra NAT;
- editar regra NAT;
- remover regra NAT;
- consultar estado NAT real;
- aplicar NAT através do fluxo seguro.

Nenhuma operação nftables é executada pelo Django.

Fluxo:

    API
      ↓
    services/nat.py
      ↓
    services/alteracoes.py
      ↓
    MoonShield-Agent
      ↓
    nftables
"""

from __future__ import annotations

import json

from django.http import JsonResponse
from django.views.decorators.http import (
    require_GET,
    require_POST,
    require_http_methods,
)

from rede.dominio.erros import (
    AgentIndisponivelErro,
    RedeErro,
)

from rede.services.alteracoes import (
    aplicar_alteracao,
    criar_alteracao_nat,
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


def _autenticado(request):
    if request.user.is_authenticated:
        return None

    return _erro(
        codigo="nao_autenticado",
        mensagem="Autenticação necessária.",
        status=401,
    )


def _ler_json(request) -> dict:
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
# LISTAR / CRIAR
# =============================================================================


@require_http_methods(
    [
        "GET",
        "POST",
    ]
)
def api_nat(request):
    """
    GET
        /rede/api/nat/

    POST
        /rede/api/nat/

    POST exemplo:

    {
        "nome": "LAN para Internet",
        "interface_origem": "enp0s8",
        "interface_saida": "enp0s3",
        "origem_cidr": "10.10.0.0/24",
        "ativa": true,
        "prioridade": 100
    }

    POST apenas salva estado desejado.
    Não altera nftables.
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
            regras = (
                listar_regras_nat()
            )

            return _resposta(
                {
                    "total": len(
                        regras
                    ),
                    "regras": regras,
                }
            )

        except RedeErro as exc:
            return _erro_rede(
                exc
            )

        except Exception as exc:
            return _erro(
                codigo="nat_list_error",
                mensagem=(
                    "Não foi possível listar "
                    "as regras NAT."
                ),
                detalhes={
                    "erro": str(exc),
                },
                status=500,
            )

    # =========================================================================
    # POST
    # =========================================================================

    try:
        dados = _ler_json(
            request
        )

        regra = salvar_regra_nat(
            dados
        )

        return _resposta(
            {
                "regra": (
                    serializar_regra_nat(
                        regra
                    )
                ),

                "mensagem": (
                    "Regra NAT salva como "
                    "estado desejado. "
                    "Ainda não aplicada no Linux."
                ),
            },
            status=201,
        )

    except ValueError as exc:
        return _erro(
            codigo="json_invalido",
            mensagem=str(exc),
        )

    except RedeErro as exc:
        return _erro_rede(
            exc
        )

    except Exception as exc:
        return _erro(
            codigo="nat_create_error",
            mensagem=(
                "Não foi possível criar "
                "a regra NAT."
            ),
            detalhes={
                "erro": str(exc),
            },
            status=500,
        )


# =============================================================================
# DETALHE / ATUALIZAÇÃO / EXCLUSÃO
# =============================================================================


@require_http_methods(
    [
        "GET",
        "POST",
        "DELETE",
    ]
)
def api_nat_detalhe(
    request,
    regra_id: int,
):
    """
    GET
        /rede/api/nat/<id>/

    POST
        /rede/api/nat/<id>/

    DELETE
        /rede/api/nat/<id>/
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
            regra = obter_regra_nat(
                regra_id
            )

            return _resposta(
                serializar_regra_nat(
                    regra
                )
            )

        except RedeErro as exc:
            return _erro_rede(
                exc,
                status=404,
            )

        except Exception as exc:
            return _erro(
                codigo="nat_detail_error",
                mensagem=(
                    "Não foi possível carregar "
                    "a regra NAT."
                ),
                detalhes={
                    "erro": str(exc),
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

            regra = salvar_regra_nat(
                dados,
                regra_id=regra_id,
            )

            return _resposta(
                {
                    "regra": (
                        serializar_regra_nat(
                            regra
                        )
                    ),

                    "mensagem": (
                        "Regra NAT atualizada. "
                        "Alteração ainda não aplicada."
                    ),
                }
            )

        except ValueError as exc:
            return _erro(
                codigo="json_invalido",
                mensagem=str(exc),
            )

        except RedeErro as exc:
            return _erro_rede(
                exc
            )

        except Exception as exc:
            return _erro(
                codigo="nat_update_error",
                mensagem=(
                    "Não foi possível atualizar "
                    "a regra NAT."
                ),
                detalhes={
                    "erro": str(exc),
                },
                status=500,
            )

    # =========================================================================
    # DELETE
    # =========================================================================

    try:
        excluir_regra_nat(
            regra_id
        )

        return _resposta(
            {
                "removida": True,
                "id": regra_id,

                "mensagem": (
                    "Regra removida do estado desejado. "
                    "Aplique a configuração NAT para "
                    "sincronizar o Linux."
                ),
            }
        )

    except RedeErro as exc:
        return _erro_rede(
            exc,
            status=404,
        )

    except Exception as exc:
        return _erro(
            codigo="nat_delete_error",
            mensagem=(
                "Não foi possível remover "
                "a regra NAT."
            ),
            detalhes={
                "erro": str(exc),
            },
            status=500,
        )


# =============================================================================
# ESTADO REAL
# =============================================================================


@require_GET
def api_nat_real(request):
    """
    GET /rede/api/nat/real/

    Consulta nftables através do Agent.

    Não altera nada.
    """

    auth = _autenticado(
        request
    )

    if auth:
        return auth

    try:
        estado = (
            obter_estado_nat_real()
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
            codigo="nat_real_status_error",
            mensagem=(
                "Não foi possível consultar "
                "o estado NAT real."
            ),
            detalhes={
                "erro": str(exc),
            },
            status=500,
        )


# =============================================================================
# APLICAR
# =============================================================================


@require_POST
def api_nat_aplicar(request):
    """
    POST /rede/api/nat/aplicar/

    Cria AlteracaoRede e executa safe apply.

    O Agent será responsável por:

    - snapshot;
    - nftables;
    - timer de rollback;
    - confirmação.
    """

    auth = _autenticado(
        request
    )

    if auth:
        return auth

    try:
        alteracao = (
            criar_alteracao_nat(
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
                    "Configuração NAT enviada "
                    "para aplicação segura."
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
            codigo="nat_apply_error",
            mensagem=(
                "Não foi possível aplicar "
                "a configuração NAT."
            ),
            detalhes={
                "erro": str(exc),
            },
            status=500,
        )