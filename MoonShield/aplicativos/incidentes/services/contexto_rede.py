"""Contexto de rede SOC derivado exclusivamente da topologia oficial."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from rede.services.topologia import obter_topologia


_PAPEIS_INTERNOS = ("lan", "mgmt", "dmz", "custom")


def classificar_ip_rede(ip: str | None) -> dict:
    """Classifica um IP com a SSOT de Rede e fallback seguro do ``ipaddress``."""
    return _classificar_ip(ip, _redes_topologia())


def classificar_fluxo(src_ip: str | None, dst_ip: str | None) -> dict:
    """Classifica os dois lados sem substituir a direção bruta do Suricata."""
    redes_topologia = _redes_topologia()
    origem = _classificar_ip(src_ip, redes_topologia)
    destino = _classificar_ip(dst_ip, redes_topologia)
    src_interno = origem["scope"] == "internal"
    dst_interno = destino["scope"] == "internal"

    if src_interno and dst_interno:
        flow_scope = "internal"
    elif src_interno:
        flow_scope = "outbound"
    elif dst_interno:
        flow_scope = "inbound"
    else:
        flow_scope = "external"

    return {
        "src": origem,
        "dst": destino,
        "flow_scope": flow_scope,
        "direction": flow_scope,
        "src_is_local": src_interno,
        "dst_is_local": dst_interno,
    }


def _classificar_ip(ip: str | None, redes_topologia: Iterable[tuple]) -> dict:
    resultado = {
        "ip": ip or "",
        "scope": "external",
        "role": None,
        "network": None,
        "is_private": False,
        "is_local": False,
        "geoip_allowed": False,
    }

    try:
        endereco = ipaddress.ip_address(ip or "")
    except ValueError:
        resultado["scope"] = "unknown"
        return resultado

    resultado["is_private"] = endereco.is_private

    for papel, rede, endereco_interface in redes_topologia:
        if endereco == endereco_interface:
            return {
                **resultado,
                "scope": "internal",
                "role": papel.upper(),
                "network": str(rede),
                "is_local": True,
                "geoip_allowed": False,
            }
        if endereco in rede and papel in _PAPEIS_INTERNOS:
            return {
                **resultado,
                "scope": "internal",
                "role": papel.upper(),
                "network": str(rede),
                "geoip_allowed": False,
            }

    if endereco.is_loopback:
        return {
            **resultado,
            "scope": "internal",
            "role": "LOCAL",
            "is_local": True,
            "geoip_allowed": False,
        }

    if _nao_publico(endereco):
        return {**resultado, "scope": "internal", "geoip_allowed": False}

    return {**resultado, "geoip_allowed": True}


def _redes_topologia() -> Iterable[tuple]:
    """Retorna redes configuradas sem consultar Linux diretamente."""
    try:
        topologia = obter_topologia()
    except Exception:
        return ()

    redes = []
    for papel in (*_PAPEIS_INTERNOS, "wan"):
        grupo = topologia.get(papel, {})
        interfaces = grupo.get("interfaces", []) if isinstance(grupo, dict) else grupo
        for interface in interfaces or []:
            for rede, endereco in _redes_interface(interface):
                redes.append((papel, rede, endereco))
    return redes


def _redes_interface(interface: dict) -> Iterable[tuple]:
    desejado = interface.get("desejado", {})
    real = interface.get("real", {})
    candidatos = []

    endereco_desejado = desejado.get("ipv4_endereco")
    prefixo_desejado = desejado.get("ipv4_prefixo")
    if endereco_desejado and prefixo_desejado is not None:
        candidatos.append(f"{endereco_desejado}/{prefixo_desejado}")

    enderecos_reais = real.get("enderecos_ipv4") or []
    if not enderecos_reais and real.get("ipv4") and real.get("prefixo") is not None:
        enderecos_reais = [f"{real['ipv4']}/{real['prefixo']}"]
    candidatos.extend(enderecos_reais)

    for candidato in candidatos:
        try:
            interface_ip = ipaddress.ip_interface(candidato)
        except ValueError:
            continue
        yield interface_ip.network, interface_ip.ip


def _nao_publico(endereco: ipaddress._BaseAddress) -> bool:
    return any((
        endereco.is_private,
        endereco.is_loopback,
        endereco.is_link_local,
        endereco.is_multicast,
        endereco.is_unspecified,
        endereco.is_reserved,
    ))
