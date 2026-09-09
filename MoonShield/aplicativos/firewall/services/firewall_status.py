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

import ipaddress
import logging
from datetime import datetime, timezone
from typing import Any

from rede.services.topologia import obter_topologia

from . import agent_client


logger = logging.getLogger(__name__)


VERSAO_STATUS_SERVICE = "1.1"


# =============================================================================
# TOPOLOGIA OFICIAL — NETWORK CONTROL
# =============================================================================

def obter_contexto_firewall_rede() -> dict[str, Any]:
    """
    Monta o contexto de topologia consumido pelo Firewall a partir do módulo
    `rede`, que é a fonte oficial de WAN/LAN/MGMT e redes internas.

    O Firewall não descobre papéis pela rota default e não consulta Linux para
    decidir topologia. O Agent continuará validando se as interfaces recebidas
    realmente existem no host.
    """
    try:
        topologia = obter_topologia()
    except Exception as exc:
        logger.exception(
            "Falha ao obter topologia oficial da Rede para o Firewall."
        )
        return _contexto_rede_indisponivel(
            codigo="topologia_rede_indisponivel",
            mensagem=str(exc),
        )

    if not isinstance(topologia, dict):
        return _contexto_rede_indisponivel(
            codigo="topologia_rede_invalida",
            mensagem="O módulo Rede retornou topologia em formato inválido.",
        )

    wan = _selecionar_interface_topologia(
        topologia.get("wan"),
    )
    lan = _selecionar_interface_topologia(
        topologia.get("lan"),
    )
    mgmt = _selecionar_interface_topologia(
        topologia.get("mgmt"),
    )

    redes_internas = _extrair_redes_internas(
        topologia,
    )
    home_net = _extrair_home_net(
        topologia,
        lan=lan,
        redes_internas=redes_internas,
    )

    interface_wan = _nome_interface(wan)
    interface_lan = _nome_interface(lan)
    interface_mgmt = _nome_interface(mgmt)

    interfaces_gerenciamento = _extrair_interfaces_gerenciamento(
        topologia,
        lan=lan,
        mgmt=mgmt,
    )

    iface_map = {
        chave: valor
        for chave, valor in {
            "WAN": interface_wan,
            "LAN": interface_lan,
            "MGMT": interface_mgmt,
        }.items()
        if valor
    }

    config_agent = {
        "interface_wan": interface_wan,
        "interface_lan": interface_lan,
        "interface_mgmt": interface_mgmt,
        "home_net": home_net,
        # A lista de interfaces administrativas é decisão do Control Plane.
        # O Agent apenas valida/observa as interfaces recebidas.
        "interfaces_gerenciamento": interfaces_gerenciamento,
    }

    faltando: list[str] = []

    if not interface_wan:
        faltando.append("WAN")

    if not interface_lan:
        faltando.append("LAN")

    return {
        "ok": not faltando,
        "fonte": "rede",
        "interface_wan": interface_wan,
        "interface_lan": interface_lan,
        "interface_mgmt": interface_mgmt,
        "home_net": home_net,
        "redes_internas": redes_internas,
        "interfaces_gerenciamento": interfaces_gerenciamento,
        "iface_map": iface_map,
        "config_agent": config_agent,
        "faltando": faltando,
        "erro": (
            None
            if not faltando
            else {
                "codigo": "topologia_rede_incompleta",
                "mensagem": (
                    "A topologia oficial da Rede ainda não possui: "
                    + ", ".join(faltando)
                    + "."
                ),
            }
        ),
        "raw": topologia,
    }


def _contexto_rede_indisponivel(
    *,
    codigo: str,
    mensagem: str,
) -> dict[str, Any]:
    return {
        "ok": False,
        "fonte": "rede",
        "interface_wan": "",
        "interface_lan": "",
        "interface_mgmt": "",
        "home_net": "",
        "redes_internas": [],
        "interfaces_gerenciamento": [],
        "iface_map": {},
        "config_agent": {
            "interface_wan": "",
            "interface_lan": "",
            "interface_mgmt": "",
            "home_net": "",
            "interfaces_gerenciamento": [],
        },
        "faltando": [
            "WAN",
            "LAN",
        ],
        "erro": {
            "codigo": codigo,
            "mensagem": mensagem,
        },
        "raw": {},
    }


def _selecionar_interface_topologia(
    grupo: Any,
) -> dict[str, Any]:
    """
    Seleciona a interface principal de um grupo de topologia.

    Compatível com o contrato atual de `rede.services.topologia`, onde grupos
    como WAN/LAN expõem `interfaces`, sem assumir quantidade fixa de NICs.
    """
    if isinstance(grupo, dict):
        principal = grupo.get("principal")

        if isinstance(principal, dict) and _nome_interface(principal):
            return principal

        interfaces = grupo.get("interfaces")
    elif isinstance(grupo, list):
        interfaces = grupo
    else:
        interfaces = []

    if not isinstance(interfaces, list):
        return {}

    validas = [
        item
        for item in interfaces
        if isinstance(item, dict) and _nome_interface(item)
    ]

    for item in validas:
        desejado = item.get("desejado")
        desejado = desejado if isinstance(desejado, dict) else {}

        if _bool(
            item.get("principal")
            or desejado.get("principal")
        ):
            return item

    for item in validas:
        desejado = item.get("desejado")
        desejado = desejado if isinstance(desejado, dict) else {}

        if _bool(
            desejado.get("habilitada", True)
        ):
            return item

    return validas[0] if validas else {}


def _nome_interface(
    interface: Any,
) -> str:
    if isinstance(interface, str):
        return interface.strip()

    if not isinstance(interface, dict):
        return ""

    return str(
        interface.get("nome")
        or interface.get("interface")
        or ""
    ).strip()


def _iterar_interfaces_topologia(
    topologia: dict[str, Any],
):
    """Itera interfaces conhecidas sem assumir quantidade fixa de NICs."""
    vistos: set[str] = set()

    for chave in (
        "wan",
        "lan",
        "mgmt",
        "dmz",
        "custom",
    ):
        grupo = topologia.get(chave)

        if isinstance(grupo, dict):
            interfaces = grupo.get("interfaces", [])
        elif isinstance(grupo, list):
            interfaces = grupo
        else:
            interfaces = []

        if not isinstance(interfaces, list):
            continue

        for interface in interfaces:
            if not isinstance(interface, dict):
                continue

            nome = _nome_interface(interface)

            if not nome or nome in vistos:
                continue

            vistos.add(nome)
            yield interface


def _extrair_interfaces_gerenciamento(
    topologia: dict[str, Any],
    *,
    lan: dict[str, Any],
    mgmt: dict[str, Any],
) -> list[str]:
    """
    Resolve onde o appliance pode ser administrado usando SOMENTE decisões do
    Network Control.

    Ordem:
    1. interfaces com `acesso_gerenciamento=True`;
    2. MGMT dedicada, quando existente;
    3. LAN principal como fallback de produto para topologias de 2 NICs.

    O fallback pertence ao Django/Control Plane; o Agent não o deduz do Linux.
    """
    nomes: list[str] = []

    for interface in _iterar_interfaces_topologia(topologia):
        desejado = interface.get("desejado")
        desejado = desejado if isinstance(desejado, dict) else {}

        if not _bool(
            desejado.get("acesso_gerenciamento")
            or interface.get("acesso_gerenciamento")
        ):
            continue

        nome = _nome_interface(interface)

        if nome and nome not in nomes:
            nomes.append(nome)

    if nomes:
        return nomes

    nome_mgmt = _nome_interface(mgmt)

    if nome_mgmt:
        return [nome_mgmt]

    nome_lan = _nome_interface(lan)

    return [nome_lan] if nome_lan else []


def _extrair_redes_internas(
    topologia: dict[str, Any],
) -> list[str]:
    """
    Lista CIDRs internos derivados da própria topologia da Rede.

    Preferimos a configuração desejada; o último estado observado da Rede é
    usado apenas quando a interface não possui endereço estático desejado.
    """
    redes: list[str] = []

    fornecidas = topologia.get("redes_internas")

    if isinstance(fornecidas, (list, tuple, set)):
        for item in fornecidas:
            cidr = ""

            if isinstance(item, str):
                cidr = item
            elif isinstance(item, dict):
                cidr = str(
                    item.get("cidr")
                    or item.get("rede")
                    or ""
                )

            normalizada = _normalizar_cidr(cidr)
            if normalizada and normalizada not in redes:
                redes.append(normalizada)

    for chave in (
        "lan",
        "dmz",
        "custom",
    ):
        grupo = topologia.get(chave)

        if isinstance(grupo, dict):
            interfaces = grupo.get("interfaces", [])
        elif isinstance(grupo, list):
            interfaces = grupo
        else:
            interfaces = []

        if not isinstance(interfaces, list):
            continue

        for interface in interfaces:
            if not isinstance(interface, dict):
                continue

            cidr = _cidr_interface_topologia(
                interface
            )

            if cidr and cidr not in redes:
                redes.append(cidr)

    return redes


def _extrair_home_net(
    topologia: dict[str, Any],
    *,
    lan: dict[str, Any],
    redes_internas: list[str],
) -> str:
    """
    Mantém o contrato V1 do Agent, que recebe um único HOME_NET.

    Se a Rede já fornecer HOME_NET explicitamente, usamos esse valor. Caso
    contrário, usamos a rede da LAN principal. A lista completa de redes
    internas continua disponível separadamente para módulos futuros.
    """
    for chave in (
        "home_net",
        "HOME_NET",
    ):
        normalizada = _normalizar_cidr(
            topologia.get(chave)
        )
        if normalizada:
            return normalizada

    cidr_lan = _cidr_interface_topologia(
        lan
    )

    if cidr_lan:
        return cidr_lan

    return (
        redes_internas[0]
        if redes_internas
        else ""
    )


def _cidr_interface_topologia(
    interface: dict[str, Any],
) -> str:
    if not isinstance(interface, dict):
        return ""

    desejado = interface.get("desejado")
    desejado = desejado if isinstance(desejado, dict) else {}

    endereco = str(
        desejado.get("ipv4_endereco")
        or ""
    ).strip()
    prefixo = desejado.get(
        "ipv4_prefixo"
    )

    if endereco and prefixo is not None:
        return _normalizar_cidr(
            f"{endereco}/{prefixo}"
        )

    real = interface.get("real")
    real = real if isinstance(real, dict) else {}

    enderecos = real.get(
        "enderecos_ipv4"
    )

    if isinstance(enderecos, list):
        for cidr in enderecos:
            normalizada = _normalizar_cidr(
                cidr
            )
            if normalizada:
                return normalizada

    endereco_real = str(
        real.get("ipv4")
        or ""
    ).strip()
    prefixo_real = real.get(
        "prefixo"
    )

    if endereco_real and prefixo_real is not None:
        return _normalizar_cidr(
            f"{endereco_real}/{prefixo_real}"
        )

    return ""


def _normalizar_cidr(
    valor: Any,
) -> str:
    texto = str(
        valor
        or ""
    ).strip()

    if not texto:
        return ""

    try:
        rede = ipaddress.ip_network(
            texto,
            strict=False,
        )
    except ValueError:
        return ""

    if rede.version != 4:
        return ""

    return str(rede)


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
    topologia_rede = obter_contexto_firewall_rede()

    consulta = agent_client.status_seguro(
        config=topologia_rede.get(
            "config_agent",
            {},
        ),
    )

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
            topologia_rede=topologia_rede,
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

    topologia_agent = raw.get(
        "topologia"
    )

    if not isinstance(
        topologia_agent,
        dict,
    ):
        topologia_agent = {}

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

    configurado_agent = _bool(
        raw.get(
            "configurado",
            False,
        )
    )

    configurado = bool(
        topologia_rede.get("ok")
        and configurado_agent
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

        # WAN/LAN/MGMT/HOME_NET vêm exclusivamente do Network Control.
        "topologia_fonte": "rede",
        "topologia_rede_ok": bool(
            topologia_rede.get("ok")
        ),
        "topologia_erro": topologia_rede.get(
            "erro"
        ),
        "interface_wan": str(
            topologia_rede.get("interface_wan")
            or ""
        ),
        "interface_lan": str(
            topologia_rede.get("interface_lan")
            or ""
        ),
        "interface_mgmt": str(
            topologia_rede.get("interface_mgmt")
            or ""
        ),
        "home_net": str(
            topologia_rede.get("home_net")
            or ""
        ),
        "redes_internas": list(
            topologia_rede.get("redes_internas")
            or []
        ),

        # Dados abaixo são observados pelo Agent e não definem papéis.
        "ip_local": str(
            topologia_agent.get("ip_local")
            or ""
        ),
        "gateway": str(
            topologia_agent.get("gateway")
            or ""
        ),
        "rede_mgmt": str(
            topologia_agent.get("rede_mgmt")
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
            "topologia_rede": topologia_rede,
            "topologia_agent_observada": topologia_agent,
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
    Consulta interfaces no Agent, mas o mapeamento WAN/LAN/MGMT é sempre
    fornecido pelo módulo `rede`.
    """
    topologia_rede = obter_contexto_firewall_rede()

    try:
        dados = agent_client.interfaces(
            config=topologia_rede.get(
                "config_agent",
                {},
            ),
        )

        if not isinstance(dados, dict):
            dados = {}

        dados = dict(dados)
        dados["mapeamento"] = dict(
            topologia_rede.get("iface_map")
            or {}
        )
        dados["home_net"] = str(
            topologia_rede.get("home_net")
            or ""
        )
        dados["redes_internas"] = list(
            topologia_rede.get("redes_internas")
            or []
        )
        dados["topologia_fonte"] = "rede"
        dados["topologia_rede_ok"] = bool(
            topologia_rede.get("ok")
        )

        return {
            "ok": True,
            **dados,
            "erro": topologia_rede.get("erro"),
        }

    except agent_client.ErroAgent as exc:
        return {
            "ok": False,
            "interfaces": [],
            "mapeamento": dict(
                topologia_rede.get("iface_map")
                or {}
            ),
            "home_net": str(
                topologia_rede.get("home_net")
                or ""
            ),
            "redes_internas": list(
                topologia_rede.get("redes_internas")
                or []
            ),
            "topologia_fonte": "rede",
            "topologia_rede_ok": bool(
                topologia_rede.get("ok")
            ),
            "erro": {
                "codigo": "agent_indisponivel",
                "mensagem": str(exc),
            },
        }


def obter_diagnostico() -> dict[str, Any]:
    topologia_rede = obter_contexto_firewall_rede()

    try:
        dados = agent_client.diagnostico(
            config=topologia_rede.get(
                "config_agent",
                {},
            ),
        )

        return {
            "ok": True,
            **dados,
            "topologia_fonte": "rede",
            "topologia_rede_ok": bool(
                topologia_rede.get("ok")
            ),
            "topologia_rede": topologia_rede,
            "erro": topologia_rede.get("erro"),
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
    topologia_rede: dict[str, Any] | None = None,
) -> dict[str, Any]:
    topologia_rede = (
        topologia_rede
        if isinstance(topologia_rede, dict)
        else _contexto_rede_indisponivel(
            codigo="topologia_rede_indisponivel",
            mensagem="Topologia da Rede indisponível.",
        )
    )
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

        "topologia_fonte": "rede",
        "topologia_rede_ok": bool(
            topologia_rede.get("ok")
        ),
        "topologia_erro": topologia_rede.get(
            "erro"
        ),
        "interface_wan": str(
            topologia_rede.get("interface_wan")
            or ""
        ),
        "interface_lan": str(
            topologia_rede.get("interface_lan")
            or ""
        ),
        "interface_mgmt": str(
            topologia_rede.get("interface_mgmt")
            or ""
        ),
        "home_net": str(
            topologia_rede.get("home_net")
            or ""
        ),
        "redes_internas": list(
            topologia_rede.get("redes_internas")
            or []
        ),

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