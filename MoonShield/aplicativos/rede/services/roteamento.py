"""
MoonShield Network
==================

Serviço de roteamento do Control Plane.

Responsabilidades:

- configuração global de IPv4 Forward;
- rollback automático;
- timeout de confirmação;
- rotas estáticas;
- payload desejado para o Agent;
- leitura do estado real.

Não executa:

    ip route
    sysctl
    nmcli

diretamente.
"""

from __future__ import annotations

from typing import Any

from django.db import transaction

from rede.dominio.erros import (
    ConfiguracaoRedeInvalidaErro,
    InterfaceNaoEncontradaErro,
    RoteamentoErro,
)

from rede.dominio.constantes import PAPEIS_GERENCIADOS
from rede.dominio.tipos import ModoIPv4, PapelInterface
from rede.dominio.validacoes import (
    validar_gateway,
    validar_rota_estatica,
    validar_tempo_confirmacao,
)

from rede.models import (
    ConfiguracaoRoteamento,
    InterfaceRede,
    RotaEstatica,
)

from rede.services.agent_client import (
    requisitar_agent,
)


# =============================================================================
# HELPERS
# =============================================================================


def _bool(
    valor: Any,
) -> bool:
    if isinstance(
        valor,
        bool,
    ):
        return valor

    if isinstance(
        valor,
        int,
    ):
        return valor != 0

    return str(
        valor or ""
    ).strip().lower() in {
        "1",
        "true",
        "yes",
        "sim",
        "on",
    }


def _obter_interface(
    nome: str,
) -> InterfaceRede:
    try:
        return InterfaceRede.objects.get(
            nome=nome
        )

    except InterfaceRede.DoesNotExist as exc:
        raise InterfaceNaoEncontradaErro(
            (
                f"Interface '{nome}' não está "
                "cadastrada no MoonShield."
            )
        ) from exc


def _obter_interface_por_id(interface_id: Any) -> InterfaceRede:
    try:
        return InterfaceRede.objects.get(pk=int(interface_id))
    except (InterfaceRede.DoesNotExist, TypeError, ValueError) as exc:
        raise InterfaceNaoEncontradaErro(
            f"Interface #{interface_id} não está cadastrada no MoonShield."
        ) from exc


def _normalizar_dados_rota(dados: dict[str, Any]) -> dict[str, Any]:
    """Aceita a referência por id usada pelo painel e o nome do contrato legado."""
    normalizado = dict(dados)

    if "interface_id" not in normalizado:
        return normalizado

    interface_id = normalizado.get("interface_id")
    if interface_id in (None, ""):
        normalizado["interface"] = ""
        return normalizado

    normalizado["interface"] = _obter_interface_por_id(interface_id).nome
    return normalizado


def _validar_interface_rota(interface: InterfaceRede) -> None:
    if interface.papel not in PAPEIS_GERENCIADOS:
        raise ConfiguracaoRedeInvalidaErro(
            "Rota estática exige uma interface gerenciada pela topologia oficial.",
            detalhes={"interface": interface.nome, "papel": interface.papel},
        )


def _endereco_prefixo_para_gateway(interface: InterfaceRede) -> tuple[str | None, int | None]:
    """Usa o desejado estático ou o último observado em uma interface DHCP."""
    if interface.ipv4_modo == ModoIPv4.STATIC.value:
        return interface.ipv4_endereco, interface.ipv4_prefixo

    return interface.ipv4_atual, interface.prefixo_atual


# =============================================================================
# CONFIGURAÇÃO GLOBAL
# =============================================================================


def obter_configuracao() -> ConfiguracaoRoteamento:
    """
    Retorna configuração singleton.
    """

    return ConfiguracaoRoteamento.atual()


def serializar_configuracao(
    config: ConfiguracaoRoteamento,
) -> dict:
    return {
        "id": config.pk,

        "ipv4_forward": (
            config.ipv4_forward
        ),

        "gerenciamento_automatico_rota_default": (
            config.gerenciamento_automatico_rota_default
        ),

        "rollback_automatico": (
            config.rollback_automatico
        ),

        "tempo_confirmacao": (
            config.tempo_confirmacao
        ),

        "ativo": config.ativo,

        "criado_em": (
            config.criado_em.isoformat()
        ),

        "atualizado_em": (
            config.atualizado_em.isoformat()
        ),
    }


@transaction.atomic
def salvar_configuracao(
    dados: dict[str, Any],
) -> ConfiguracaoRoteamento:
    """
    Salva apenas estado desejado.

    NÃO aplica sysctl nem rotas.
    """

    config = (
        ConfiguracaoRoteamento.objects
        .select_for_update()
        .filter(
            pk=1
        )
        .first()
    )

    if config is None:
        config = ConfiguracaoRoteamento(
            pk=1
        )

    if "ipv4_forward" in dados:
        config.ipv4_forward = _bool(
            dados[
                "ipv4_forward"
            ]
        )

    if (
        "gerenciamento_automatico_rota_default"
        in dados
    ):
        config.gerenciamento_automatico_rota_default = _bool(
            dados[
                "gerenciamento_automatico_rota_default"
            ]
        )

    if "rollback_automatico" in dados:
        config.rollback_automatico = _bool(
            dados[
                "rollback_automatico"
            ]
        )

    if "tempo_confirmacao" in dados:
        config.tempo_confirmacao = (
            validar_tempo_confirmacao(
                dados[
                    "tempo_confirmacao"
                ]
            )
        )

    if "ativo" in dados:
        config.ativo = _bool(
            dados[
                "ativo"
            ]
        )

    config.full_clean()
    config.save()

    return config


# =============================================================================
# ROTAS
# =============================================================================


def serializar_rota(
    rota: RotaEstatica,
) -> dict:
    return {
        "id": rota.pk,
        "nome": rota.nome,
        "destino": rota.destino,
        "gateway": rota.gateway,

        "interface": (
            {
                "id": rota.interface_id,
                "nome": rota.interface.nome,
                "papel": rota.interface.papel,
            }
            if rota.interface
            else None
        ),

        "metrica": rota.metrica,
        "ativa": rota.ativa,

        "sincronizada": (
            rota.sincronizada
        ),

        "pendente": rota.pendente,

        "ultimo_erro": (
            rota.ultimo_erro
        ),

        "criado_em": (
            rota.criado_em.isoformat()
        ),

        "atualizado_em": (
            rota.atualizado_em.isoformat()
        ),
    }


def listar_rotas(
    *,
    somente_ativas: bool = False,
) -> list[dict]:
    queryset = (
        RotaEstatica.objects
        .select_related(
            "interface"
        )
        .all()
    )

    if somente_ativas:
        queryset = queryset.filter(
            ativa=True
        )

    return [
        serializar_rota(
            rota
        )
        for rota in queryset
    ]


def obter_rota(
    rota_id: int,
) -> RotaEstatica:
    try:
        return (
            RotaEstatica.objects
            .select_related(
                "interface"
            )
            .get(
                pk=rota_id
            )
        )

    except RotaEstatica.DoesNotExist as exc:
        raise RoteamentoErro(
            f"Rota #{rota_id} não encontrada."
        ) from exc


# =============================================================================
# SALVAR ROTA
# =============================================================================


@transaction.atomic
def salvar_rota(
    dados: dict[str, Any],
    *,
    rota_id: int | None = None,
) -> RotaEstatica:
    """
    Cria/atualiza rota desejada.
    """

    dados = _normalizar_dados_rota(dados)
    normalizado = validar_rota_estatica(dados)

    # A rota default pertence à configuração da WAN.
    if (
        normalizado["destino"]
        == "0.0.0.0/0"
    ):
        raise ConfiguracaoRedeInvalidaErro(
            (
                "A rota padrão não deve ser criada como "
                "RotaEstatica. Configure-a na WAN principal."
            )
        )

    interface = _obter_interface(normalizado["interface"]) if normalizado["interface"] else None
    if interface is None:
        raise ConfiguracaoRedeInvalidaErro(
            "Rota estática exige uma interface de saída gerenciada.",
        )

    _validar_interface_rota(interface)

    # -------------------------------------------------------------------------
    # GATEWAY DEVE SER ALCANÇÁVEL PELA INTERFACE
    # -------------------------------------------------------------------------

    gateway = normalizado[
        "gateway"
    ]

    endereco, prefixo = _endereco_prefixo_para_gateway(interface)
    if gateway and endereco and prefixo is not None:
        validar_gateway(
            gateway,
            endereco=endereco,
            prefixo=prefixo,
            obrigatorio=True,
        )

    if rota_id is None:
        rota = RotaEstatica()
    else:
        rota = obter_rota(
            rota_id
        )

    rota.nome = str(dados.get("nome", "") or "").strip()

    rota.destino = normalizado[
        "destino"
    ]

    rota.gateway = gateway

    rota.interface = interface

    rota.metrica = normalizado[
        "metrica"
    ]

    rota.ativa = normalizado[
        "ativa"
    ]

    rota.sincronizada = False
    rota.pendente = True
    rota.ultimo_erro = ""

    rota.full_clean()
    rota.save()

    return rota


# =============================================================================
# REMOVER ROTA
# =============================================================================


@transaction.atomic
def excluir_rota(
    rota_id: int,
) -> None:
    """
    Remove configuração desejada.

    A retirada real do Linux será feita através
    do fluxo seguro de alteração.
    """

    rota = obter_rota(
        rota_id
    )

    rota.delete()


# =============================================================================
# PAYLOAD
# =============================================================================


def montar_payload_roteamento() -> dict:
    """
    Estado completo desejado para o Agent.
    """

    config = obter_configuracao()

    rotas = RotaEstatica.objects.select_related("interface").filter(ativa=True).order_by("metrica", "destino")
    payload_rotas = []

    for rota in rotas:
        if rota.interface is None:
            raise ConfiguracaoRedeInvalidaErro(
                f"Rota estática #{rota.pk} não possui interface de saída.",
            )

        _validar_interface_rota(rota.interface)
        payload_rotas.append({
            "id": rota.pk,
            "destino": rota.destino,
            "gateway": rota.gateway,
            "interface_nome": rota.interface.nome,
            "metrica": rota.metrica,
            "ativa": True,
        })

    interfaces_alvo = list(
        InterfaceRede.objects.exclude(papel=PapelInterface.NAO_ATRIBUIDA.value)
        .order_by("nome")
        .values_list("nome", flat=True)
    )

    return {
        "ipv4_forward": (
            config.ipv4_forward
        ),

        "rotas": payload_rotas,
        "interfaces_alvo": interfaces_alvo,
    }


# =============================================================================
# ESTADO REAL
# =============================================================================


def obter_estado_roteamento_real() -> dict:
    """
    Consulta:

    - ip_forward;
    - rota default;
    - tabela IPv4;
    - métricas;

    através do Agent.
    """

    return requisitar_agent(
        "network.routing.status"
    )


# =============================================================================
# STATUS DE ROTAS
# =============================================================================


def marcar_rota_sincronizada(
    rota: RotaEstatica,
) -> None:
    rota.sincronizada = True
    rota.pendente = False
    rota.ultimo_erro = ""

    rota.save(
        update_fields=[
            "sincronizada",
            "pendente",
            "ultimo_erro",
            "atualizado_em",
        ]
    )


def marcar_rota_erro(
    rota: RotaEstatica,
    erro: str,
) -> None:
    rota.sincronizada = False
    rota.pendente = True
    rota.ultimo_erro = str(
        erro or ""
    )

    rota.save(
        update_fields=[
            "sincronizada",
            "pendente",
            "ultimo_erro",
            "atualizado_em",
        ]
    )
