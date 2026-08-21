"""
MoonShield Platform — Firewall / Install Service
================================================

Orquestra a instalação/configuração do Firewall pelo Django.

IMPORTANTE:
- Django NÃO executa apt, nft, systemctl ou comandos privilegiados.
- Toda execução Linux é delegada ao MoonShield-Agent por IPC local.
- Este service prepara payloads, valida dados básicos, chama o Agent e
  devolve um contrato estável para views/tarefas.

Fluxo:

    View/Tarefa Django
        ↓
    firewall_install.py
        ↓
    agent_client.py
        ↓
    /run/moonshield/agent.sock
        ↓
    MoonShield-Agent
        ↓
    instalador.py
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

from . import agent_client
from .firewall_status import obter_estado_firewall, obter_interfaces


logger = logging.getLogger(__name__)

VERSAO_INSTALL_SERVICE = "1.0"


# =============================================================================
# CONFIGURAÇÃO
# =============================================================================

def montar_configuracao(
    *,
    interface_wan: str,
    interface_lan: str,
    interface_mgmt: str = "",
    home_net: str = "",
) -> dict[str, Any]:
    """
    Valida e normaliza configuração antes de enviar ao Agent.
    """
    wan = str(interface_wan or "").strip()
    lan = str(interface_lan or "").strip()
    mgmt = str(interface_mgmt or "").strip()
    home = str(home_net or "").strip()

    erros: list[str] = []

    if not wan:
        erros.append("Interface WAN é obrigatória.")

    if not lan:
        erros.append("Interface LAN é obrigatória.")

    definidas = [x for x in (wan, lan, mgmt) if x]

    if len(definidas) != len(set(definidas)):
        erros.append(
            "WAN, LAN e MGMT não podem usar a mesma interface."
        )

    if home:
        try:
            rede = ipaddress.ip_network(
                home,
                strict=False,
            )
            home = str(rede)
        except ValueError:
            erros.append(
                f"HOME_NET inválido: {home!r}."
            )

    if erros:
        return {
            "ok": False,
            "erros": erros,
            "config": {},
        }

    return {
        "ok": True,
        "erros": [],
        "config": {
            "interface_wan": wan,
            "interface_lan": lan,
            "interface_mgmt": mgmt,
            "home_net": home,
        },
    }


# =============================================================================
# PRÉ-CHECK
# =============================================================================

def precheck_instalacao() -> dict[str, Any]:
    """
    Consulta Agent + interfaces sem realizar mudanças.
    """
    estado = obter_estado_firewall(
        incluir_detalhes=False
    )

    interfaces = obter_interfaces()

    erros: list[str] = []
    avisos: list[str] = []

    if not estado.get("agent_disponivel"):
        erros.append(
            "MoonShield-Agent não está disponível."
        )

    lista_interfaces = interfaces.get(
        "interfaces",
        []
    )

    if not lista_interfaces:
        avisos.append(
            "Nenhuma interface de rede foi retornada pelo Agent."
        )

    return {
        "ok": not erros,
        "pronto": not erros,
        "estado": estado,
        "interfaces": lista_interfaces,
        "mapeamento": interfaces.get(
            "mapeamento",
            {},
        ),
        "erros": erros,
        "avisos": avisos,
        "versao_service": VERSAO_INSTALL_SERVICE,
    }


# =============================================================================
# INSTALAÇÃO
# =============================================================================

def instalar_firewall(
    *,
    interface_wan: str,
    interface_lan: str,
    interface_mgmt: str = "",
    home_net: str = "",
    instalar_pacote: bool = True,
) -> dict[str, Any]:
    validacao = montar_configuracao(
        interface_wan=interface_wan,
        interface_lan=interface_lan,
        interface_mgmt=interface_mgmt,
        home_net=home_net,
    )

    if not validacao["ok"]:
        return {
            "ok": False,
            "status": "erro",
            "codigo": "configuracao_invalida",
            "erro": "Configuração do Firewall inválida.",
            "detalhes": validacao,
        }

    try:
        resultado = agent_client.instalar(
            config=validacao["config"],
            instalar_pacote=instalar_pacote,
        )

        estado = obter_estado_firewall(
            incluir_detalhes=True
        )

        return {
            "ok": True,
            "status": "sucesso",
            "mensagem": resultado.get(
                "mensagem",
                "Firewall instalado.",
            ),
            "resultado_agent": resultado,
            "estado": estado,
        }

    except agent_client.OperacaoAgentFalhou as exc:
        logger.warning(
            "Instalação do Firewall recusada pelo Agent: %s",
            exc,
        )

        return {
            "ok": False,
            "status": "erro",
            "codigo": exc.codigo,
            "erro": str(exc),
            "detalhes": exc.detalhes,
            "resposta_agent": exc.resposta,
        }

    except agent_client.ErroAgent as exc:
        logger.error(
            "Falha de comunicação com Agent durante instalação: %s",
            exc,
        )

        return {
            "ok": False,
            "status": "erro",
            "codigo": "agent_indisponivel",
            "erro": str(exc),
        }


# =============================================================================
# REPARO
# =============================================================================

def reparar_firewall(
    *,
    interface_wan: str | None = None,
    interface_lan: str | None = None,
    interface_mgmt: str | None = None,
    home_net: str | None = None,
) -> dict[str, Any]:
    config: dict[str, Any] | None = None

    if (
        interface_wan is not None
        or interface_lan is not None
        or interface_mgmt is not None
        or home_net is not None
    ):
        atual = obter_estado_firewall(
            incluir_detalhes=False
        )

        validacao = montar_configuracao(
            interface_wan=(
                interface_wan
                if interface_wan is not None
                else atual.get("interface_wan", "")
            ),
            interface_lan=(
                interface_lan
                if interface_lan is not None
                else atual.get("interface_lan", "")
            ),
            interface_mgmt=(
                interface_mgmt
                if interface_mgmt is not None
                else atual.get("interface_mgmt", "")
            ),
            home_net=(
                home_net
                if home_net is not None
                else atual.get("home_net", "")
            ),
        )

        if not validacao["ok"]:
            return {
                "ok": False,
                "codigo": "configuracao_invalida",
                "erro": "Configuração inválida.",
                "detalhes": validacao,
            }

        config = validacao["config"]

    try:
        resultado = agent_client.reparar(
            config=config
        )

        return {
            "ok": True,
            "mensagem": resultado.get(
                "mensagem",
                "Firewall reparado.",
            ),
            "resultado_agent": resultado,
            "estado": obter_estado_firewall(
                incluir_detalhes=True
            ),
        }

    except agent_client.OperacaoAgentFalhou as exc:
        return {
            "ok": False,
            "codigo": exc.codigo,
            "erro": str(exc),
            "detalhes": exc.detalhes,
        }

    except agent_client.ErroAgent as exc:
        return {
            "ok": False,
            "codigo": "agent_indisponivel",
            "erro": str(exc),
        }


# =============================================================================
# DESINSTALAÇÃO
# =============================================================================

def desinstalar_firewall(
    *,
    confirmar: bool,
    remover_config: bool = False,
) -> dict[str, Any]:
    if not confirmar:
        return {
            "ok": False,
            "codigo": "confirmacao_necessaria",
            "erro": "Confirmação obrigatória.",
        }

    try:
        resultado = agent_client.desinstalar(
            confirmar=True,
            remover_config=remover_config,
        )

        return {
            "ok": True,
            "mensagem": resultado.get(
                "mensagem",
                "Firewall removido.",
            ),
            "resultado_agent": resultado,
            "estado": obter_estado_firewall(
                incluir_detalhes=True
            ),
        }

    except agent_client.OperacaoAgentFalhou as exc:
        return {
            "ok": False,
            "codigo": exc.codigo,
            "erro": str(exc),
            "detalhes": exc.detalhes,
        }

    except agent_client.ErroAgent as exc:
        return {
            "ok": False,
            "codigo": "agent_indisponivel",
            "erro": str(exc),
        }