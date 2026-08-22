"""
MoonShield Network
==================

Serviço de NAT do Control Plane Django.

Responsabilidades:

- armazenar configuração desejada no PostgreSQL;
- validar regras NAT;
- resolver interfaces;
- montar payload para o MoonShield-Agent;
- consultar estado NAT real;
- controlar status de sincronização.

IMPORTANTE:

Este serviço NÃO aplica nftables diretamente.

A aplicação real será coordenada por:

    services/alteracoes.py
        ↓
    MoonShield-Agent
        ↓
    nftables

O módulo Rede administra somente NAT.

Políticas ALLOW / DENY / FORWARD pertencem ao módulo Firewall.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from django.db import transaction
from django.utils import timezone

from rede.dominio.erros import (
    ConfiguracaoRedeInvalidaErro,
    InterfaceNaoEncontradaErro,
    NatErro,
)

from rede.dominio.tipos import (
    ModoIPv4,
    PapelInterface,
    TipoNat,
)

from rede.dominio.validacoes import (
    validar_nat_masquerade,
)

from rede.models import (
    InterfaceRede,
    RegraNat,
)

from rede.services.agent_client import (
    requisitar_agent,
)


# =============================================================================
# SERIALIZAÇÃO
# =============================================================================


def serializar_regra_nat(
    regra: RegraNat,
) -> dict:
    """
    Converte RegraNat em dict seguro para API/service.
    """

    return {
        "id": regra.pk,
        "nome": regra.nome,
        "tipo": regra.tipo,

        "interface_origem": {
            "id": regra.interface_origem_id,
            "nome": regra.interface_origem.nome,
            "papel": regra.interface_origem.papel,
        },

        "interface_saida": {
            "id": regra.interface_saida_id,
            "nome": regra.interface_saida.nome,
            "papel": regra.interface_saida.papel,
        },

        "origem_cidr": regra.origem_cidr,

        "ativa": regra.ativa,
        "prioridade": regra.prioridade,

        "sincronizada": regra.sincronizada,
        "pendente": regra.pendente,
        "ultimo_erro": regra.ultimo_erro,

        "aplicada_em": (
            regra.aplicada_em.isoformat()
            if regra.aplicada_em
            else None
        ),

        "criado_em": regra.criado_em.isoformat(),
        "atualizado_em": regra.atualizado_em.isoformat(),
    }


# =============================================================================
# CONSULTAS
# =============================================================================


def listar_regras_nat(
    *,
    somente_ativas: bool = False,
) -> list[dict]:
    queryset = (
        RegraNat.objects
        .select_related(
            "interface_origem",
            "interface_saida",
        )
        .all()
    )

    if somente_ativas:
        queryset = queryset.filter(
            ativa=True
        )

    return [
        serializar_regra_nat(regra)
        for regra in queryset
    ]


def obter_regra_nat(
    regra_id: int,
) -> RegraNat:
    try:
        return (
            RegraNat.objects
            .select_related(
                "interface_origem",
                "interface_saida",
            )
            .get(
                pk=regra_id
            )
        )

    except RegraNat.DoesNotExist as exc:
        raise NatErro(
            f"Regra NAT #{regra_id} não encontrada."
        ) from exc


# =============================================================================
# INTERFACES
# =============================================================================


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
                f"Interface '{nome}' não está cadastrada "
                "no MoonShield."
            )
        ) from exc


# =============================================================================
# REGRAS DE NEGÓCIO
# =============================================================================


def _validar_papeis_nat(
    origem: InterfaceRede,
    saida: InterfaceRede,
) -> None:
    """
    Regras V1:

    saída:
        obrigatoriamente WAN

    origem:
        LAN, DMZ ou CUSTOM

    MGMT não recebe NAT automaticamente.
    """

    if (
        saida.papel
        != PapelInterface.WAN.value
    ):
        raise ConfiguracaoRedeInvalidaErro(
            (
                "A interface de saída do NAT deve "
                "possuir papel WAN."
            ),
            detalhes={
                "interface": saida.nome,
                "papel": saida.papel,
            },
        )

    papeis_origem = {
        PapelInterface.LAN.value,
        PapelInterface.DMZ.value,
        PapelInterface.CUSTOM.value,
    }

    if origem.papel not in papeis_origem:
        raise ConfiguracaoRedeInvalidaErro(
            (
                "A interface de origem do NAT deve ser "
                "LAN, DMZ ou CUSTOM."
            ),
            detalhes={
                "interface": origem.nome,
                "papel": origem.papel,
            },
        )


def _descobrir_cidr_origem(
    interface: InterfaceRede,
) -> str:
    """
    Quando origem_cidr não foi informada, tenta calcular
    através da configuração estática desejada.
    """

    if (
        interface.ipv4_modo
        != ModoIPv4.STATIC.value
    ):
        return ""

    if (
        not interface.ipv4_endereco
        or interface.ipv4_prefixo is None
    ):
        return ""

    rede = ipaddress.IPv4Network(
        (
            f"{interface.ipv4_endereco}/"
            f"{interface.ipv4_prefixo}"
        ),
        strict=False,
    )

    return str(rede)


# =============================================================================
# SALVAR
# =============================================================================


@transaction.atomic
def salvar_regra_nat(
    dados: dict[str, Any],
    *,
    regra_id: int | None = None,
) -> RegraNat:
    """
    Cria ou atualiza uma configuração NAT desejada.

    NÃO aplica no Linux.
    """

    normalizado = validar_nat_masquerade(
        dados
    )

    origem = _obter_interface(
        normalizado[
            "interface_origem"
        ]
    )

    saida = _obter_interface(
        normalizado[
            "interface_saida"
        ]
    )

    _validar_papeis_nat(
        origem,
        saida,
    )

    origem_cidr = (
        normalizado[
            "origem_cidr"
        ]
        or _descobrir_cidr_origem(
            origem
        )
    )

    prioridade = dados.get(
        "prioridade",
        100,
    )

    try:
        prioridade = int(
            prioridade
        )
    except (
        TypeError,
        ValueError,
    ) as exc:
        raise ConfiguracaoRedeInvalidaErro(
            "Prioridade NAT inválida."
        ) from exc

    if prioridade < 0:
        raise ConfiguracaoRedeInvalidaErro(
            (
                "Prioridade NAT não pode "
                "ser negativa."
            )
        )

    nome = str(
        dados.get(
            "nome",
            "NAT LAN → WAN",
        )
        or "NAT LAN → WAN"
    ).strip()

    if regra_id is None:
        existente = (
            RegraNat.objects
            .filter(
                interface_origem=origem,
                interface_saida=saida,
                tipo=TipoNat.MASQUERADE.value,
            )
            .first()
        )

        if existente:
            regra = existente
        else:
            regra = RegraNat(
                interface_origem=origem,
                interface_saida=saida,
            )

    else:
        regra = obter_regra_nat(
            regra_id
        )

    regra.nome = nome

    regra.tipo = (
        TipoNat.MASQUERADE.value
    )

    regra.interface_origem = origem
    regra.interface_saida = saida

    regra.origem_cidr = (
        origem_cidr
    )

    regra.ativa = normalizado[
        "ativa"
    ]

    regra.prioridade = prioridade

    # Alteração no estado desejado.
    regra.sincronizada = False
    regra.pendente = True
    regra.ultimo_erro = ""

    regra.save()

    return regra


# =============================================================================
# EXCLUSÃO
# =============================================================================


@transaction.atomic
def excluir_regra_nat(
    regra_id: int,
) -> None:
    """
    Remove a configuração desejada.

    ATENÇÃO:
    Quem removerá a regra real do Linux será alteracoes.py.
    """

    regra = obter_regra_nat(
        regra_id
    )

    regra.delete()


# =============================================================================
# PAYLOAD PARA AGENT
# =============================================================================


def montar_payload_nat(
    *,
    somente_ativas: bool = True,
) -> dict:
    """
    Gera contrato esperado pelo Agent.

    Exemplo:

    {
        "regras": [
            {
                "id": 1,
                "tipo": "masquerade",
                "interface_origem": "enp0s8",
                "interface_saida": "enp0s3",
                "origem_cidr": "10.10.0.0/24",
                "ativa": true
            }
        ]
    }
    """

    queryset = (
        RegraNat.objects
        .select_related(
            "interface_origem",
            "interface_saida",
        )
        .order_by(
            "prioridade",
            "id",
        )
    )

    if somente_ativas:
        queryset = queryset.filter(
            ativa=True
        )

    regras = []

    for regra in queryset:
        regras.append(
            {
                "id": regra.pk,
                "tipo": regra.tipo,

                "interface_origem": (
                    regra.interface_origem.nome
                ),

                "interface_saida": (
                    regra.interface_saida.nome
                ),

                "origem_cidr": (
                    regra.origem_cidr
                ),

                "prioridade": (
                    regra.prioridade
                ),

                "ativa": regra.ativa,
            }
        )

    return {
        "regras": regras,
    }


# =============================================================================
# ESTADO REAL
# =============================================================================


def obter_estado_nat_real() -> dict:
    """
    Consulta nftables através do Agent.

    Não altera nada.
    """

    return requisitar_agent(
        "network.nat.status"
    )


# =============================================================================
# SINCRONIZAÇÃO
# =============================================================================


def marcar_regra_sincronizada(
    regra: RegraNat,
) -> None:
    regra.sincronizada = True
    regra.pendente = False
    regra.ultimo_erro = ""
    regra.aplicada_em = timezone.now()

    regra.save(
        update_fields=[
            "sincronizada",
            "pendente",
            "ultimo_erro",
            "aplicada_em",
            "atualizado_em",
        ]
    )


def marcar_regra_erro(
    regra: RegraNat,
    erro: str,
) -> None:
    regra.sincronizada = False
    regra.pendente = True
    regra.ultimo_erro = str(
        erro or ""
    )

    regra.save(
        update_fields=[
            "sincronizada",
            "pendente",
            "ultimo_erro",
            "atualizado_em",
        ]
    )