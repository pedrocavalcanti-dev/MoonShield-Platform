"""
MoonShield Platform — Firewall / Status Service
===============================================

Camada de serviço do Django responsável por transformar o status técnico do
MoonShield-Agent em um estado estável para:

- views do Firewall;
- onboarding/instalação;
- página Configurações;
- healthcheck;
- dashboard;
- APIs internas.

Fonte de verdade do estado Linux:
    MoonShield-Agent via Unix Socket.

Este módulo NÃO:
- executa nft;
- acessa Sensor;
- usa HTTP;
- usa token;
- procura IP de sensor;
- altera regras.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from . import agent_client


logger = logging.getLogger(__name__)


VERSAO_STATUS_SERVICE = "1.0"


# =============================================================================
# STATUS CONSOLIDADO
# =============================================================================

def obter_estado_firewall(
    *,
    incluir_detalhes: bool = True,
) -> dict[str, Any]:
    """
    Retorna um estado padronizado para o restante do Django.

    Nunca lança exceção por Agent offline.
    """
    consulta = agent_client.status_seguro()

    if not consulta.get(
        "agent_disponivel"
    ):
        erro = consulta.get(
            "erro"
        ) or {}

        return _estado_indisponivel(
            codigo=str(
                erro.get("codigo")
                or "agent_indisponivel"
            ),
            mensagem=str(
                erro.get("mensagem")
                or "MoonShield-Agent indisponível."
            ),
        )

    raw = consulta.get(
        "firewall"
    )

    if not isinstance(
        raw,
        dict,
    ):
        raw = {}

    ping = consulta.get(
        "ping"
    )

    if not isinstance(
        ping,
        dict,
    ):
        ping = {}

    nft = raw.get(
        "nftables"
    )

    if not isinstance(
        nft,
        dict,
    ):
        nft = {}

    tabela = raw.get(
        "tabela"
    )

    if not isinstance(
        tabela,
        dict,
    ):
        tabela = {}

    chains = raw.get(
        "chains"
    )

    if not isinstance(
        chains,
        dict,
    ):
        chains = {}

    topologia = raw.get(
        "topologia"
    )

    if not isinstance(
        topologia,
        dict,
    ):
        topologia = {}

    ipc = raw.get(
        "ipc"
    )

    if not isinstance(
        ipc,
        dict,
    ):
        ipc = {}

    nft_instalado = _bool(
        nft.get(
            "instalado",
            False,
        )
    )

    tabela_instalada = _bool(
        tabela.get(
            "existe",
            False,
        )
    )

    chains_ok = _bool(
        chains.get(
            "ok",
            False,
        )
    )

    configurado = _bool(
        raw.get(
            "configurado",
            False,
        )
    )

    instalado = _bool(
        raw.get(
            "instalado",
            False,
        )
    )

    operacional_raw = _bool(
        raw.get(
            "operacional",
            False,
        )
    )

    agent_ok = True

    operacional = bool(
        agent_ok
        and nft_instalado
        and tabela_instalada
        and chains_ok
        and configurado
        and operacional_raw
    )

    status, status_label = _resolver_status(
        agent_ok=agent_ok,
        nft_instalado=nft_instalado,
        tabela_instalada=tabela_instalada,
        configurado=configurado,
        chains_ok=chains_ok,
        operacional=operacional,
        raw_status=str(
            raw.get("status")
            or ""
        ),
        raw_label=str(
            raw.get("status_label")
            or ""
        ),
    )

    resultado: dict[str, Any] = {
        "ok": True,

        # Contrato principal para o Django/Configurações.
        "fonte": "local",
        "modo": "real",

        "agent_ativo": True,
        "agent_disponivel": True,

        "nftables_instalado": nft_instalado,
        "nftables_versao": str(
            nft.get("versao")
            or ""
        ),

        "instalado": instalado,
        "configurado": configurado,
        "ativo": tabela_instalada,

        "tabela_instalada": tabela_instalada,
        "chains_ok": chains_ok,

        "operacional": operacional,
        "saudavel": operacional,

        "status": status,
        "status_label": status_label,

        "interface_wan": str(
            topologia.get("wan")
            or ""
        ),
        "interface_lan": str(
            topologia.get("lan")
            or ""
        ),
        "interface_mgmt": str(
            topologia.get("mgmt")
            or ""
        ),
        "home_net": str(
            topologia.get("home_net")
            or ""
        ),

        "ip_local": str(
            topologia.get("ip_local")
            or ""
        ),
        "gateway": str(
            topologia.get("gateway")
            or ""
        ),
        "rede_mgmt": str(
            topologia.get("rede_mgmt")
            or ""
        ),

        "ipc": {
            "ok": True,
            "socket": str(
                ipc.get("caminho")
                or agent_client.obter_socket_path()
            ),
            "socket_existe": _bool(
                ipc.get(
                    "existe",
                    True,
                )
            ),
        },

        "agent": {
            "pong": _bool(
                ping.get(
                    "pong",
                    True,
                )
            ),
            "servico": str(
                ping.get("servico")
                or "moonshield-agent"
            ),
            "pid": ping.get(
                "pid"
            ),
            "uptime_segundos": ping.get(
                "uptime_segundos",
                0,
            ),
            "ipc_versao": ping.get(
                "ipc"
            ),
        },

        "erro": None,

        "atualizado_em": _agora_iso(),
        "versao_service": VERSAO_STATUS_SERVICE,
    }

    if incluir_detalhes:
        resultado[
            "detalhes"
        ] = {
            "raw": raw,
            "ping": ping,
            "tabela": tabela,
            "chains": chains,
            "topologia": topologia,
        }

    return resultado


# =============================================================================
# ATALHOS
# =============================================================================

def obter_status_resumido() -> dict[str, Any]:
    estado = obter_estado_firewall(
        incluir_detalhes=False
    )

    return {
        "ok": estado.get(
            "ok",
            False,
        ),
        "fonte": estado.get(
            "fonte",
            "local",
        ),
        "agent_ativo": estado.get(
            "agent_ativo",
            False,
        ),
        "instalado": estado.get(
            "instalado",
            False,
        ),
        "configurado": estado.get(
            "configurado",
            False,
        ),
        "ativo": estado.get(
            "ativo",
            False,
        ),
        "saudavel": estado.get(
            "saudavel",
            False,
        ),
        "operacional": estado.get(
            "operacional",
            False,
        ),
        "status": estado.get(
            "status",
            "indisponivel",
        ),
        "status_label": estado.get(
            "status_label",
            "Indisponível",
        ),
        "nftables_versao": estado.get(
            "nftables_versao",
            "",
        ),
        "erro": estado.get(
            "erro"
        ),
    }


def obter_interfaces() -> dict[str, Any]:
    """
    Consulta interfaces diretamente no Agent.

    Nunca executa comandos no host Django.
    """
    try:
        dados = agent_client.interfaces()

        return {
            "ok": True,
            **dados,
            "erro": None,
        }

    except agent_client.ErroAgent as exc:
        return {
            "ok": False,
            "interfaces": [],
            "mapeamento": {
                "WAN": "",
                "LAN": "",
                "MGMT": "",
            },
            "erro": {
                "codigo": "agent_indisponivel",
                "mensagem": str(exc),
            },
        }


def obter_diagnostico() -> dict[str, Any]:
    try:
        dados = agent_client.diagnostico()

        return {
            "ok": True,
            **dados,
            "erro": None,
        }

    except agent_client.ErroAgent as exc:
        return {
            "ok": False,
            "pronto": False,
            "total_checks": 0,
            "total_ok": 0,
            "total_falhas": 1,
            "total_criticos": 1,
            "itens": [],
            "erro": {
                "codigo": "agent_indisponivel",
                "mensagem": str(exc),
            },
        }


def firewall_operacional() -> bool:
    return bool(
        obter_estado_firewall(
            incluir_detalhes=False
        ).get(
            "operacional",
            False,
        )
    )


def agent_operacional() -> bool:
    try:
        return bool(
            agent_client.ping().get(
                "pong"
            )
        )
    except agent_client.ErroAgent:
        return False


# =============================================================================
# ESTADOS DE FALHA
# =============================================================================

def _estado_indisponivel(
    *,
    codigo: str,
    mensagem: str,
) -> dict[str, Any]:
    return {
        "ok": False,

        "fonte": "local",
        "modo": "real",

        "agent_ativo": False,
        "agent_disponivel": False,

        "nftables_instalado": False,
        "nftables_versao": "",

        "instalado": False,
        "configurado": False,
        "ativo": False,

        "tabela_instalada": False,
        "chains_ok": False,

        "operacional": False,
        "saudavel": False,

        "status": "agent_indisponivel",
        "status_label": "Agent indisponível",

        "interface_wan": "",
        "interface_lan": "",
        "interface_mgmt": "",
        "home_net": "",

        "ip_local": "",
        "gateway": "",
        "rede_mgmt": "",

        "ipc": {
            "ok": False,
            "socket": agent_client.obter_socket_path(),
            "socket_existe": agent_client.socket_existe(),
        },

        "agent": {
            "pong": False,
            "servico": "moonshield-agent",
            "pid": None,
            "uptime_segundos": 0,
            "ipc_versao": None,
        },

        "erro": {
            "codigo": codigo,
            "mensagem": mensagem,
        },

        "atualizado_em": _agora_iso(),
        "versao_service": VERSAO_STATUS_SERVICE,
    }


# =============================================================================
# NORMALIZAÇÃO
# =============================================================================

def _resolver_status(
    *,
    agent_ok: bool,
    nft_instalado: bool,
    tabela_instalada: bool,
    configurado: bool,
    chains_ok: bool,
    operacional: bool,
    raw_status: str,
    raw_label: str,
) -> tuple[str, str]:
    if not agent_ok:
        return (
            "agent_indisponivel",
            "Agent indisponível",
        )

    if not nft_instalado:
        return (
            "nftables_nao_instalado",
            "nftables não instalado",
        )

    if not tabela_instalada:
        return (
            "nao_instalado",
            "Firewall não instalado",
        )

    if not configurado:
        return (
            "configuracao_pendente",
            "Configuração pendente",
        )

    if not chains_ok:
        return (
            "requer_reparo",
            "Requer reparo",
        )

    if operacional:
        return (
            "operacional",
            "Operacional",
        )

    if raw_status:
        return (
            raw_status,
            raw_label
            or raw_status.replace(
                "_",
                " ",
            ).capitalize(),
        )

    return (
        "atencao",
        "Atenção",
    )


def _bool(
    valor: Any,
) -> bool:
    if isinstance(
        valor,
        bool,
    ):
        return valor

    if valor is None:
        return False

    return str(
        valor
    ).strip().lower() in {
        "1",
        "true",
        "sim",
        "yes",
        "on",
        "ativo",
        "operacional",
        "ok",
    }


def _agora_iso() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()