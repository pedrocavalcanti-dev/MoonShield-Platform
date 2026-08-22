"""
MoonShield Network
==================

Tipos e enums centrais do domínio de Rede.

Este módulo NÃO deve:

- acessar banco de dados;
- importar models Django;
- executar comandos Linux;
- conversar com o MoonShield-Agent;
- conhecer HTTP ou views.

Ele apenas define os conceitos utilizados pelo módulo de Rede.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any


# =============================================================================
# INTERFACES
# =============================================================================


class PapelInterface(StrEnum):
    """
    Papel lógico de uma interface dentro do MoonShield.

    O nome físico da interface é sempre descoberto pelo sistema:

        enp0s3
        enp0s8
        ens18
        eno1
        eth0
        bond0
        br0
        etc.

    O MoonShield nunca deve assumir nomes fixos.
    """

    NAO_ATRIBUIDA = "unassigned"
    WAN = "wan"
    LAN = "lan"
    MGMT = "mgmt"
    DMZ = "dmz"
    CUSTOM = "custom"


class ModoIPv4(StrEnum):
    """
    Forma como o IPv4 da interface será configurado.
    """

    DHCP = "dhcp"
    STATIC = "static"
    DISABLED = "disabled"


class EstadoLink(StrEnum):
    """
    Estado simplificado do link de rede.
    """

    DESCONHECIDO = "unknown"
    UP = "up"
    DOWN = "down"


# =============================================================================
# BACKENDS DE REDE
# =============================================================================


class BackendRede(StrEnum):
    """
    Backend responsável por persistir/aplicar rede no Linux.

    V1 oficial:
        NetworkManager

    Os demais ficam previstos para compatibilidade futura.
    """

    DESCONHECIDO = "unknown"
    NETWORK_MANAGER = "networkmanager"
    SYSTEMD_NETWORKD = "networkd"
    IFUPDOWN = "ifupdown"
    RUNTIME = "runtime"


# =============================================================================
# NAT
# =============================================================================


class TipoNat(StrEnum):
    """
    Tipos NAT suportados.

    V1:
        MASQUERADE

    DNAT/SNAT/Port Forward podem ser adicionados posteriormente,
    caso façam sentido dentro da arquitetura do MoonShield.
    """

    MASQUERADE = "masquerade"


# =============================================================================
# ALTERAÇÕES
# =============================================================================


class TipoAlteracaoRede(StrEnum):
    INTERFACE = "interface"
    ROTEAMENTO = "routing"
    NAT = "nat"
    ROTA = "route"
    GERAL = "general"


class StatusAlteracaoRede(StrEnum):
    CRIADA = "created"
    VALIDANDO = "validating"
    APLICANDO = "applying"
    AGUARDANDO_CONFIRMACAO = "waiting_confirmation"
    CONFIRMADA = "confirmed"
    ROLLBACK = "rollback"
    REVERTIDA = "reverted"
    FALHOU = "failed"
    CANCELADA = "cancelled"


# =============================================================================
# EVENTOS
# =============================================================================


class NivelEventoRede(StrEnum):
    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"


# =============================================================================
# HELPERS
# =============================================================================


def valores_enum(enum_cls: type[StrEnum]) -> set[str]:
    """
    Retorna os valores válidos de um enum.

    Exemplo:

        valores_enum(PapelInterface)

    Resultado:

        {
            "unassigned",
            "wan",
            "lan",
            ...
        }
    """

    return {
        item.value
        for item in enum_cls
    }


def valor_enum(
    valor: Any,
    enum_cls: type[StrEnum],
) -> str:
    """
    Normaliza um valor para string de enum.

    Aceita:

        PapelInterface.WAN
        "wan"

    Retorna:

        "wan"

    Não faz validação.
    """

    if isinstance(valor, enum_cls):
        return valor.value

    if valor is None:
        return ""

    return str(valor).strip().lower()


def enum_ou_none(
    valor: Any,
    enum_cls: type[StrEnum],
):
    """
    Converte valor em enum quando possível.

    Retorna None se inválido.
    """

    if isinstance(valor, enum_cls):
        return valor

    try:
        return enum_cls(
            str(valor).strip().lower()
        )
    except (ValueError, TypeError):
        return None