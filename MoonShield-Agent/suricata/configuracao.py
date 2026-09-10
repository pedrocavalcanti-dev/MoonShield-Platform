"""
MoonShield Agent — Suricata / Configuração
==========================================

Camada de configuração operacional do Suricata.

Regras de arquitetura:
- NÃO descobre WAN/LAN/MGMT por conta própria;
- recebe topologia do Control Plane (Django/Rede);
- mantém Suricata em IDS passivo (AF_PACKET);
- não executa comandos privilegiados neste módulo;
- não altera configuração do host neste módulo.

O instalador legado continua responsável pela instalação inicial.
Este módulo é usado pelo runtime após o appliance já estar instalado.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

VERSAO_CONFIGURACAO = "1.0"

YAML_PADRAO = Path("/etc/suricata/suricata.yaml")
EVE_PADRAO = Path("/var/log/suricata/eve.json")
RULES_MS_PADRAO = Path("/var/lib/suricata/rules/moonshield/ms.rules")

BASE_STATE = Path("/var/lib/moonshield/suricata")
BACKUP_DIR = BASE_STATE / "backups"

IFACES_PROIBIDAS = {"", "lo"}


@dataclass(slots=True, frozen=True)
class ConfiguracaoSuricata:
    interface_wan: str
    interface_lan: str
    interface_mgmt: str
    interfaces_monitoradas: tuple[str, ...]
    home_net: tuple[str, ...]
    yaml_path: str
    eve_path: str
    rules_ms_path: str

    def para_dict(self) -> dict[str, Any]:
        return {
            "interface_wan": self.interface_wan,
            "interface_lan": self.interface_lan,
            "interface_mgmt": self.interface_mgmt,
            "interfaces_monitoradas": list(self.interfaces_monitoradas),
            "home_net": list(self.home_net),
            "yaml_path": self.yaml_path,
            "eve_path": self.eve_path,
            "rules_ms_path": self.rules_ms_path,
            "modo": "ids_passivo",
        }


def normalizar_config(dados: dict[str, Any] | None) -> ConfiguracaoSuricata:
    """
    Normaliza SOMENTE valores enviados pelo Control Plane.

    Não há detecção de rota padrão, interface com mais tráfego ou qualquer
    inferência de papel de rede no Agent.
    """
    dados = dados or {}
    if not isinstance(dados, dict):
        raise TypeError("config deve ser um objeto.")

    wan = _iface(dados.get("interface_wan"))
    lan = _iface(dados.get("interface_lan"))
    mgmt = _iface(dados.get("interface_mgmt"))

    raw_ifaces = dados.get("interfaces_monitoradas")
    if raw_ifaces is None:
        # Compatibilidade explícita: só usa interface_captura se o Control Plane
        # realmente a enviou. Não deriva LAN/WAN automaticamente.
        captura = _iface(dados.get("interface_captura"))
        raw_ifaces = [captura] if captura else []

    if isinstance(raw_ifaces, str):
        raw_ifaces = [raw_ifaces]
    if not isinstance(raw_ifaces, (list, tuple)):
        raise ValueError("interfaces_monitoradas deve ser uma lista.")

    monitoradas: list[str] = []
    for valor in raw_ifaces:
        nome = _iface(valor)
        if not nome:
            continue
        if nome in IFACES_PROIBIDAS:
            raise ValueError(f"Interface de captura inválida: {nome!r}.")
        if nome not in monitoradas:
            monitoradas.append(nome)

    raw_home = dados.get("home_net") or []
    if isinstance(raw_home, str):
        raw_home = [raw_home]
    if not isinstance(raw_home, (list, tuple)):
        raise ValueError("home_net deve ser string CIDR ou lista de CIDRs.")

    redes: list[str] = []
    for valor in raw_home:
        texto = str(valor or "").strip()
        if not texto:
            continue
        rede = ipaddress.ip_network(texto, strict=False)
        canonica = str(rede)
        if canonica not in redes:
            redes.append(canonica)

    if not monitoradas:
        raise ValueError(
            "Nenhuma interface de captura foi informada pelo Control Plane."
        )
    if not redes:
        raise ValueError("HOME_NET não foi informado pelo Control Plane.")

    yaml_path = str(dados.get("suricata_yaml") or YAML_PADRAO)
    eve_path = str(dados.get("eve_path") or EVE_PADRAO)
    rules_path = str(dados.get("rules_ms_path") or RULES_MS_PADRAO)

    return ConfiguracaoSuricata(
        interface_wan=wan,
        interface_lan=lan,
        interface_mgmt=mgmt,
        interfaces_monitoradas=tuple(monitoradas),
        home_net=tuple(redes),
        yaml_path=yaml_path,
        eve_path=eve_path,
        rules_ms_path=rules_path,
    )


def validar_config_host(cfg: ConfiguracaoSuricata) -> dict[str, Any]:
    erros: list[str] = []
    avisos: list[str] = []

    for iface in cfg.interfaces_monitoradas:
        if not Path("/sys/class/net").joinpath(iface).exists():
            erros.append(f"Interface monitorada não existe no host: {iface}")

    if cfg.interface_mgmt and cfg.interface_mgmt in cfg.interfaces_monitoradas:
        avisos.append(
            "A interface MGMT foi incluída explicitamente na captura pelo Control Plane."
        )

    if cfg.interface_wan and cfg.interface_wan == cfg.interface_lan:
        erros.append("WAN e LAN não podem apontar para a mesma interface.")

    return {
        "ok": not erros,
        "erros": erros,
        "avisos": avisos,
        "config": cfg.para_dict(),
    }


def renderizar_yaml(base_yaml: str, cfg: ConfiguracaoSuricata) -> str:
    """
    Aplica somente os trechos operacionais que o MoonShield deve possuir:
    HOME_NET, rule-files MoonShield, eve.json e AF_PACKET.

    Mantém o restante do suricata.yaml da distribuição.
    """
    conteudo = str(base_yaml)
    conteudo = _patch_home_net(conteudo, cfg.home_net)
    conteudo = _patch_rule_files(conteudo)
    conteudo = _patch_eve_filename(conteudo, cfg.eve_path)
    conteudo = _patch_af_packet(conteudo, cfg.interfaces_monitoradas)
    return conteudo


def _patch_home_net(conteudo: str, home_net: tuple[str, ...]) -> str:
    valor = "[" + ",".join(home_net) + "]"
    nova = f'    HOME_NET: "{valor}"'

    linhas = conteudo.splitlines()
    substituiu = False
    saida: list[str] = []

    for linha in linhas:
        if linha.strip().startswith("HOME_NET:") and not linha.lstrip().startswith("#"):
            if not substituiu:
                saida.append(nova)
                substituiu = True
            continue
        saida.append(linha)

    if not substituiu:
        for idx, linha in enumerate(saida):
            if linha.strip() == "address-groups:":
                saida.insert(idx + 1, nova)
                substituiu = True
                break

    if not substituiu:
        raise ValueError("Seção vars/address-groups do suricata.yaml não encontrada.")

    return "\n".join(saida) + "\n"


def _patch_rule_files(conteudo: str) -> str:
    marcador = "moonshield/ms.rules"
    if marcador in conteudo:
        return conteudo

    linhas = conteudo.splitlines()
    for idx, linha in enumerate(linhas):
        if linha.strip() == "rule-files:":
            linhas.insert(idx + 1, "  - moonshield/ms.rules")
            return "\n".join(linhas) + "\n"

    raise ValueError("Seção rule-files do suricata.yaml não encontrada.")


def _patch_eve_filename(conteudo: str, eve_path: str) -> str:
    """
    O arquivo padrão do Debian já possui eve-log. Só fixa o filename da
    primeira seção eve-log encontrada; não cria um segundo output duplicado.
    """
    linhas = conteudo.splitlines()
    inicio = None
    indent_eve = None

    for idx, linha in enumerate(linhas):
        if re.match(r"^\s*-\s+eve-log:\s*$", linha):
            inicio = idx
            indent_eve = len(linha) - len(linha.lstrip())
            break

    if inicio is None:
        raise ValueError("Seção outputs/eve-log do suricata.yaml não encontrada.")

    for idx in range(inicio + 1, len(linhas)):
        linha = linhas[idx]
        if linha.strip() and (len(linha) - len(linha.lstrip())) <= indent_eve:
            break
        if linha.strip().startswith("filename:"):
            prefixo = linha[: len(linha) - len(linha.lstrip())]
            linhas[idx] = f"{prefixo}filename: {eve_path}"
            return "\n".join(linhas) + "\n"

    raise ValueError("Campo filename da seção eve-log não encontrado.")


def _patch_af_packet(conteudo: str, interfaces: tuple[str, ...]) -> str:
    bloco = ["af-packet:", "  # == MOONSHIELD RUNTIME =="]
    for i, iface in enumerate(interfaces):
        bloco.extend([
            f"  - interface: {iface}",
            "    threads: auto",
            f"    cluster-id: {99 + i}",
            "    cluster-type: cluster_flow",
            "    defrag: yes",
        ])
    novo_bloco = "\n".join(bloco) + "\n"

    padrao = re.compile(r"(?ms)^af-packet:\n(?:(?:[ \t].*)?\n)*")
    if not padrao.search(conteudo):
        raise ValueError("Seção af-packet do suricata.yaml não encontrada.")

    return padrao.sub(novo_bloco, conteudo, count=1)


def _iface(valor: Any) -> str:
    nome = str(valor or "").strip()
    if not nome:
        return ""
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", nome):
        raise ValueError(f"Nome de interface inválido: {nome!r}")
    return nome
