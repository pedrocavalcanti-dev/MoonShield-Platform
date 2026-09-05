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

import ipaddress
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

    backend = _normalizar_backend(dados.get("backend"))
    interfaces_brutas = dados.get("interfaces", [])
    if not isinstance(interfaces_brutas, list):
        interfaces_brutas = []

    interfaces = [
        interface
        for item in interfaces_brutas
        if (interface := normalizar_interface(item, backend=backend))
    ]
    interfaces.sort(key=lambda item: item["nome"])

    return {
        "backend": backend,
        "total": len(interfaces),
        "interfaces": interfaces,
    }


def listar_interfaces() -> list[dict]:
    """
    Retorna apenas a lista de interfaces.
    """

    return obter_inventario()["interfaces"]


def buscar_interface(
    nome: str,
) -> dict | None:
    """
    Procura uma interface física/lógica pelo nome.
    """

    nome = str(nome or "").strip()

    if not nome:
        return None

    for interface in listar_interfaces():
        if interface["nome"] == nome:
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

    if not isinstance(item, dict):
        return None

    nome = _texto_ou_none(item.get("nome") or item.get("name") or item.get("interface"))

    if not nome:
        return None

    enderecos_ipv4 = _normalizar_enderecos_ipv4(
        item.get("ipv4") or item.get("enderecos_ipv4") or item.get("addresses")
    )
    ipv4_atual = _normalizar_ipv4(
        item.get("ipv4_atual") or item.get("ipv4_address") or item.get("address")
    )
    prefixo_atual = _inteiro_ou_none(
        item.get("prefixo_atual", item.get("ipv4_prefix", item.get("prefix")))
    )

    if not ipv4_atual and enderecos_ipv4:
        ipv4_atual, prefixo_endereco = _extrair_ipv4(enderecos_ipv4[0])
        prefixo_atual = prefixo_atual if prefixo_atual is not None else prefixo_endereco

    conexao = item.get("connection")
    conexao = conexao if isinstance(conexao, dict) else {}
    nome_conexao = _texto_ou_none(
        item.get("conexao") or conexao.get("name") or item.get("connection_name")
    )
    uuid_conexao = _texto_ou_none(
        conexao.get("uuid") or item.get("connection_uuid") or item.get("conexao_uuid")
    )
    estado = _normalizar_estado(item.get("estado_link") or item.get("state"))
    gateway_atual = _texto_ou_none(item.get("gateway_atual") or item.get("gateway"))
    metrica_atual = _inteiro_ou_none(item.get("metrica_atual", item.get("metric")))
    mtu_atual = _inteiro_ou_none(item.get("mtu_atual", item.get("mtu")))
    mac_address = _texto_ou_none(item.get("mac_address") or item.get("mac"))

    return {
        "nome": nome,
        "name": nome,
        "mac_address": mac_address,
        "mac": mac_address,
        "estado_link": estado,
        "state": estado,
        "carrier": _bool_ou_none(item.get("carrier")),
        "ipv4": enderecos_ipv4,
        "enderecos_ipv4": enderecos_ipv4,
        "ipv4_atual": ipv4_atual,
        "prefixo_atual": prefixo_atual,
        "prefix": prefixo_atual,
        "gateway_atual": gateway_atual,
        "gateway": gateway_atual,
        "metrica_atual": metrica_atual,
        "metric": metrica_atual,
        "mtu_atual": mtu_atual,
        "mtu": mtu_atual,
        "backend": _normalizar_backend(item.get("backend", backend)),
        "conexao": nome_conexao,
        "connection_name": nome_conexao,
        "connection_uuid": uuid_conexao,
    }


# =============================================================================
# HELPERS
# =============================================================================


def _extrair_ipv4(valor: Any) -> tuple[str | None, int | None]:
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

    if isinstance(valor, dict):
        endereco = valor.get("endereco") or valor.get("address") or valor.get("ip")
        prefixo = valor.get("prefixo", valor.get("prefix"))
        return _normalizar_ipv4(endereco), _inteiro_ou_none(prefixo)

    texto = _texto_ou_none(valor)
    if not texto:
        return None, None
    if "/" not in texto:
        return _normalizar_ipv4(texto), None

    endereco, prefixo = texto.rsplit("/", 1)
    return _normalizar_ipv4(endereco), _inteiro_ou_none(prefixo)


def _normalizar_enderecos_ipv4(valor: Any) -> list[str]:
    if valor is None:
        return []
    if not isinstance(valor, list):
        valor = [valor]

    resultado = []
    for item in valor:
        endereco, prefixo = _extrair_ipv4(item)
        if not endereco:
            continue
        cidr = f"{endereco}/{prefixo}" if prefixo is not None else endereco
        try:
            cidr = str(ipaddress.IPv4Interface(cidr)) if prefixo is not None else str(ipaddress.IPv4Address(cidr))
        except ValueError:
            continue
        if cidr not in resultado:
            resultado.append(cidr)
    return resultado


def _normalizar_ipv4(valor: Any) -> str | None:
    texto = _texto_ou_none(valor)
    if not texto:
        return None
    try:
        return str(ipaddress.IPv4Address(texto.split("/", 1)[0]))
    except ValueError:
        return None


def _texto_ou_none(valor: Any) -> str | None:
    texto = str(valor or "").strip()
    return texto or None


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
