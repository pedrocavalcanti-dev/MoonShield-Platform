"""
Adapter para comunicação entre Django e Agent para o módulo Suricata.
"""

from __future__ import annotations

from rede.services.agent_client import requisitar_agent
from rede.services.topologia import obter_topologia


class ErroSuricataAgent(Exception):
    """Exceção base para erros no adapter do Suricata."""
    pass


class TopologiaSuricataInvalida(ErroSuricataAgent):
    """Exceção levantada quando a topologia não é válida para configurar o Suricata."""
    
    def __init__(self, problemas: list[dict]):
        self.problemas = problemas
        super().__init__(f"Topologia inválida: {problemas}")


def montar_payload_topologia() -> dict:
    """Monta o payload de topologia a partir do módulo rede."""
    topologia = obter_topologia()

    if not topologia.get("valida"):
        raise TopologiaSuricataInvalida(topologia.get("problemas", []))

    wan_principal = topologia.get("wan", {}).get("principal")
    lan_principal = topologia.get("lan", {}).get("principal")
    mgmt_principal = topologia.get("mgmt", {}).get("principal")

    nome_wan = wan_principal.get("nome") if wan_principal else ""
    nome_lan = lan_principal.get("nome") if lan_principal else ""
    nome_mgmt = mgmt_principal.get("nome") if mgmt_principal else ""

    lan_interfaces = topologia.get("lan", {}).get("interfaces", [])
    dmz_interfaces = topologia.get("dmz", [])
    custom_interfaces = topologia.get("custom", [])

    monitoradas = []
    for lista in [lan_interfaces, dmz_interfaces, custom_interfaces]:
        for interface in lista:
            habilitada = interface.get("desejado", {}).get("habilitada", True)
            if habilitada:
                nome = interface.get("nome")
                if nome and nome not in monitoradas:
                    monitoradas.append(nome)

    home_net = topologia.get("home_net", [])

    return {
        "interface_wan": nome_wan,
        "interface_lan": nome_lan,
        "interface_mgmt": nome_mgmt,
        "interfaces_monitoradas": monitoradas,
        "home_net": home_net,
        "suricata_yaml": "/etc/suricata/suricata.yaml",
        "eve_path": "/var/log/suricata/eve.json",
        "rules_ms_path": "/var/lib/suricata/rules/moonshield/ms.rules",
    }


def obter_status() -> dict:
    """Obtém o status geral do Suricata via Agent."""
    payload = montar_payload_topologia()
    return requisitar_agent("suricata.status", payload, timeout=15)


def obter_diagnostico() -> dict:
    """Obtém diagnósticos avançados do Suricata via Agent."""
    payload = montar_payload_topologia()
    return requisitar_agent("suricata.diagnostics", payload, timeout=180)


def validar_configuracao() -> dict:
    """Valida a configuração desejada do Suricata sem aplicá-la."""
    payload = montar_payload_topologia()
    return requisitar_agent("suricata.config.validate", payload, timeout=180)


def aplicar_configuracao() -> dict:
    """Aplica a configuração ao Suricata via Agent e recarrega o serviço."""
    payload = montar_payload_topologia()
    return requisitar_agent("suricata.config.apply", payload, timeout=180)


def obter_status_servico() -> dict:
    """Obtém o status do serviço systemd do Suricata."""
    return requisitar_agent("suricata.service.status", {}, timeout=15)


def iniciar_servico() -> dict:
    """Inicia o serviço do Suricata."""
    return requisitar_agent("suricata.service.start", {}, timeout=120)


def parar_servico() -> dict:
    """Para o serviço do Suricata."""
    return requisitar_agent("suricata.service.stop", {}, timeout=120)


def reiniciar_servico() -> dict:
    """Reinicia o serviço do Suricata."""
    return requisitar_agent("suricata.service.restart", {}, timeout=120)

