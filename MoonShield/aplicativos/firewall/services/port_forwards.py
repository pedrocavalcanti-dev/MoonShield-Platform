"""Estado desejado e sincronizacao segura de Port Forwards do Firewall."""

from __future__ import annotations

import ipaddress
from typing import Any

from firewall.models import NatEntry
from firewall.services import agent_client
from firewall.services.firewall_status import obter_contexto_firewall_rede


def _porta(valor: Any, campo: str) -> int:
    try:
        porta = int(str(valor).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{campo} deve estar entre 1 e 65535.") from exc
    if not 1 <= porta <= 65535:
        raise ValueError(f"{campo} deve estar entre 1 e 65535.")
    return porta


def _redes_internas() -> tuple[dict[str, Any], list[ipaddress.IPv4Network]]:
    contexto = obter_contexto_firewall_rede()
    if not contexto.get("ok"):
        raise ValueError("Topologia oficial da Rede indisponivel para Port Forward.")
    redes = []
    for cidr in contexto.get("redes_internas", []):
        try:
            rede = ipaddress.ip_network(str(cidr), strict=False)
        except ValueError:
            continue
        if rede.version == 4:
            redes.append(rede)
    if not redes:
        raise ValueError("Nenhuma rede interna valida foi definida pela Rede.")
    return contexto, redes


def payload_port_forward(entry: NatEntry, *, contexto: dict[str, Any] | None = None) -> dict[str, Any]:
    contexto, redes = _redes_internas() if contexto is None else (contexto, [
        ipaddress.ip_network(cidr, strict=False)
        for cidr in contexto.get("redes_internas", [])
    ])
    try:
        destino = ipaddress.ip_address(entry.lan_ip)
    except ValueError as exc:
        raise ValueError("IP interno invalido.") from exc
    if destino.version != 4 or destino.is_loopback or destino.is_multicast or destino.is_unspecified:
        raise ValueError("IP interno nao permitido.")
    if not any(destino in rede for rede in redes if rede.version == 4):
        raise ValueError("IP interno deve pertencer a uma rede interna oficial.")

    iface_logica = str(entry.iface or "").upper()
    if iface_logica != "WAN":
        raise ValueError("Port Forward V1 aceita somente a interface logica WAN.")
    interface = str((contexto.get("iface_map") or {}).get("WAN") or "")
    if not interface:
        raise ValueError("WAN oficial nao definida.")

    proto = str(entry.proto or "").lower()
    if proto not in {"tcp", "udp", "any"}:
        raise ValueError("Protocolo de Port Forward invalido.")

    return {
        "id": entry.pk or f"novo-{entry.name}",
        "interface": interface,
        "proto": proto,
        "wan_port": _porta(entry.wan_port, "Porta externa"),
        "lan_ip": str(destino),
        "lan_port": _porta(entry.lan_port, "Porta interna"),
        "enabled": bool(entry.enabled),
    }


def validar_port_forward(entry: NatEntry, *, excluir_id: int | None = None) -> None:
    contexto, _ = _redes_internas()
    candidato = payload_port_forward(entry, contexto=contexto)
    protocolos = {"tcp", "udp"} if candidato["proto"] == "any" else {candidato["proto"]}
    if not candidato["enabled"]:
        return
    existentes = NatEntry.objects.filter(enabled=True)
    if excluir_id is not None:
        existentes = existentes.exclude(pk=excluir_id)
    for existente in existentes:
        outro = payload_port_forward(existente, contexto=contexto)
        outros_protocolos = {"tcp", "udp"} if outro["proto"] == "any" else {outro["proto"]}
        if (
            outro["enabled"]
            and outro["interface"] == candidato["interface"]
            and outro["wan_port"] == candidato["wan_port"]
            and protocolos & outros_protocolos
        ):
            raise ValueError("Ja existe Port Forward para esta porta externa e protocolo.")


def sincronizar_port_forwards(*, excluir_id: int | None = None) -> dict[str, Any]:
    contexto, _ = _redes_internas()
    entries = NatEntry.objects.all()
    if excluir_id is not None:
        entries = entries.exclude(pk=excluir_id)
    payloads = [payload_port_forward(entry, contexto=contexto) for entry in entries]
    return agent_client.sincronizar_port_forwards(payloads)
