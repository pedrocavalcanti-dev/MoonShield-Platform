"""
MoonShield Network
==================

Serviço de inventário real das interfaces.

Fonte:

    Linux
      ↓
    MoonShield-Agent
      ↓
    network.inventory
      ↓
    Django

Este serviço NÃO altera interfaces e NÃO grava configuração desejada.
"""

from __future__ import annotations

from typing import Any

from rede.dominio.tipos import (
    BackendRede,
    EstadoLink,
)

from rede.services.agent_client import (
    requisitar_agent,
)


# =============================================================================
# API PÚBLICA
# =============================================================================


def obter_inventario() -> dict:
    """
    Consulta o inventário real através do Agent.

    Retorno normalizado:

    {
        "backend": "networkmanager",
        "interfaces": [...]
    }
    """

    dados = requisitar_agent(
        "network.inventory"
    )

    backend = _normalizar_backend(
        dados.get(
            "backend"
        )
    )

    interfaces_brutas = dados.get(
        "interfaces",
        [],
    )

    if not isinstance(
        interfaces_brutas,
        list,
    ):
        interfaces_brutas = []

    interfaces = []

    for item in interfaces_brutas:
        normalizada = (
            normalizar_interface(
                item,
                backend=backend,
            )
        )

        if normalizada:
            interfaces.append(
                normalizada
            )

    interfaces.sort(
        key=lambda item: item["name"]
    )

    return {
        "backend": backend,
        "total": len(
            interfaces
        ),
        "interfaces": interfaces,
    }


def listar_interfaces() -> list[dict]:
    """
    Retorna apenas a lista de interfaces.
    """

    return obter_inventario()[
        "interfaces"
    ]


def buscar_interface(
    nome: str,
) -> dict | None:
    """
    Procura uma interface física/lógica pelo nome.
    """

    nome = str(
        nome or ""
    ).strip()

    if not nome:
        return None

    for interface in listar_interfaces():
        if interface["name"] == nome:
            return interface

    return None


# =============================================================================
# NORMALIZAÇÃO
# =============================================================================


def normalizar_interface(
    item: Any,
    *,
    backend: str = BackendRede.DESCONHECIDO.value,
) -> dict | None:
    """
    Normaliza interface recebida do Agent.
    """

    if not isinstance(
        item,
        dict,
    ):
        return None

    nome = str(
        item.get("name")
        or item.get("nome")
        or item.get("interface")
        or ""
    ).strip()

    if not nome:
        return None

    ipv4, prefixo = _extrair_ipv4(
        item.get("ipv4")
    )

    # Compatibilidade caso o Agent devolva
    # os valores diretamente.
    if not ipv4:
        ipv4 = (
            item.get("ipv4_address")
            or item.get("address")
            or None
        )

    if prefixo is None:
        prefixo = (
            item.get("ipv4_prefix")
            or item.get("prefix")
        )

    prefixo = _inteiro_ou_none(
        prefixo
    )

    conexao = item.get(
        "connection",
        {},
    )

    if not isinstance(
        conexao,
        dict,
    ):
        conexao = {}

    estado = _normalizar_estado(
        item.get(
            "state"
        )
    )

    return {
        "name": nome,

        "mac": str(
            item.get("mac")
            or item.get("mac_address")
            or ""
        ).strip(),

        "state": estado,

        "carrier": _bool_ou_none(
            item.get(
                "carrier"
            )
        ),

        "ipv4": (
            str(ipv4).strip()
            if ipv4
            else None
        ),

        "prefix": prefixo,

        "gateway": (
            str(
                item.get("gateway")
            ).strip()
            if item.get("gateway")
            else None
        ),

        "metric": _inteiro_ou_none(
            item.get(
                "metric"
            )
        ),

        "mtu": _inteiro_ou_none(
            item.get(
                "mtu"
            )
        ),

        "backend": _normalizar_backend(
            item.get(
                "backend",
                backend,
            )
        ),

        "connection_name": str(
            conexao.get("name")
            or item.get("connection_name")
            or ""
        ).strip(),

        "connection_uuid": str(
            conexao.get("uuid")
            or item.get("connection_uuid")
            or ""
        ).strip(),
    }


# =============================================================================
# HELPERS
# =============================================================================


def _extrair_ipv4(
    valor: Any,
) -> tuple[str | None, int | None]:
    """
    Aceita:

        {
            "address": "192.168.0.100",
            "prefix": 24
        }

    ou:

        [
            {
                "address": "...",
                "prefix": 24
            }
        ]

    ou:

        "192.168.0.100"
    """

    if not valor:
        return None, None

    if isinstance(
        valor,
        list,
    ):
        if not valor:
            return None, None

        valor = valor[0]

    if isinstance(
        valor,
        dict,
    ):
        endereco = (
            valor.get("address")
            or valor.get("endereco")
            or valor.get("ip")
        )

        prefixo = (
            valor.get("prefix")
            or valor.get("prefixo")
        )

        return (
            str(endereco).strip()
            if endereco
            else None,
            _inteiro_ou_none(
                prefixo
            ),
        )

    if isinstance(
        valor,
        str,
    ):
        valor = valor.strip()

        if "/" in valor:
            ip, prefixo = valor.split(
                "/",
                1,
            )

            return (
                ip.strip(),
                _inteiro_ou_none(
                    prefixo
                ),
            )

        return valor, None

    return None, None


def _normalizar_backend(
    valor: Any,
) -> str:
    texto = str(
        valor or ""
    ).strip().lower()

    validos = {
        backend.value
        for backend in BackendRede
    }

    if texto in validos:
        return texto

    return BackendRede.DESCONHECIDO.value


def _normalizar_estado(
    valor: Any,
) -> str:
    texto = str(
        valor or ""
    ).strip().lower()

    if texto in {
        "up",
        "connected",
        "activated",
    }:
        return EstadoLink.UP.value

    if texto in {
        "down",
        "disconnected",
        "unavailable",
        "disabled",
    }:
        return EstadoLink.DOWN.value

    return EstadoLink.DESCONHECIDO.value


def _inteiro_ou_none(
    valor: Any,
) -> int | None:
    if valor in (
        None,
        "",
    ):
        return None

    try:
        return int(
            valor
        )
    except (
        TypeError,
        ValueError,
    ):
        return None


def _bool_ou_none(
    valor: Any,
) -> bool | None:
    if valor is None:
        return None

    if isinstance(
        valor,
        bool,
    ):
        return valor

    if isinstance(
        valor,
        int,
    ):
        return bool(
            valor
        )

    texto = str(
        valor
    ).strip().lower()

    if texto in {
        "1",
        "true",
        "yes",
        "sim",
        "on",
        "up",
    }:
        return True

    if texto in {
        "0",
        "false",
        "no",
        "nao",
        "não",
        "off",
        "down",
    }:
        return False

    return None