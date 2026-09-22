"""Discovery local e limitado, executado somente pelo MoonShield Agent."""
from __future__ import annotations

import ipaddress
import logging
import json
import shutil
import xml.etree.ElementTree as ET
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from pathlib import Path
from typing import Any

MAX_TARGETS = 8
MAX_HOSTS_HARD = 1024
PING_WORKERS = 16
PORT_WORKERS = 8
PORTS = (22, 80, 443, 445, 554, 631, 9100, 3389)
_MAC_RE = re.compile(r"^[0-9A-F]{2}(?::[0-9A-F]{2}){5}$")
logger = logging.getLogger(__name__)


class DiscoveryError(ValueError):
    codigo = "devices_scan_invalido"


def _mac(value: Any) -> str | None:
    value = str(value or "").strip().upper().replace("-", ":")
    return value if _MAC_RE.fullmatch(value) and value != "00:00:00:00:00:00" and not (int(value[:2], 16) & 1) else None


def _run(*args: str, timeout: float = 2.0) -> str:
    try:
        completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout if completed.returncode == 0 else ""


def _agent_interfaces() -> dict[str, list[ipaddress.IPv4Interface]]:
    """Normaliza o formato real do inventário do backend de rede do Agent."""
    from rede.nucleo.inventario import obter_inventario

    inventory = obter_inventario()
    result: dict[str, list[ipaddress.IPv4Interface]] = {}
    for item in inventory.get("interfaces") or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("nome") or item.get("name") or "").strip()
        addresses = item.get("ipv4") or item.get("enderecos_ipv4") or []
        if not isinstance(addresses, list):
            addresses = [addresses]

        parsed = []
        for address in addresses:
            if isinstance(address, dict):
                host = address.get("endereco") or address.get("address") or address.get("local")
                prefix = address.get("prefixo") if "prefixo" in address else address.get("prefixlen")
                address = f"{host}/{prefix}" if host and prefix is not None else ""
            try:
                parsed.append(ipaddress.IPv4Interface(str(address)))
            except (ipaddress.AddressValueError, ValueError):
                continue
        if name and parsed:
            result[name] = parsed
    return result


def _targets(payload: dict[str, Any], *, probe: bool = False) -> list[dict]:
    values = payload.get("targets")
    if not isinstance(values, list) or not values or len(values) > MAX_TARGETS:
        raise DiscoveryError("Uma lista limitada de targets é obrigatória.")
    try:
        limit = min(MAX_HOSTS_HARD, max(1, int(payload.get("max_hosts", 254))))
    except (TypeError, ValueError) as exc:
        raise DiscoveryError("Limite de hosts inválido.") from exc
    interfaces = _agent_interfaces()
    validated = []
    seen = set()
    for value in values:
        if not isinstance(value, dict):
            raise DiscoveryError("Target inválido.")
        network_id = str(value.get("network_id") or "").strip()
        interface = str(value.get("interface") or "").strip()
        role = str(value.get("role") or "").strip().lower()
        try:
            network = ipaddress.IPv4Network(str(value.get("cidr") or ""), strict=True)
        except (ipaddress.AddressValueError, ValueError) as exc:
            raise DiscoveryError("CIDR IPv4 inválido.") from exc
        if network_id != f"{role}:{interface}" or not interface or interface.startswith("-") or role not in {"lan", "wan", "mgmt", "dmz", "custom"}:
            raise DiscoveryError("Target sem identidade, interface ou papel válido.")
        if network.is_loopback or network.is_link_local or network.prefixlen == 0 or not network.is_private:
            raise DiscoveryError("A rede solicitada não é elegível ao discovery.")
        if not probe and network.num_addresses - 2 > limit:
            raise DiscoveryError("A rede solicitada excede o limite de hosts.")
        if not any(address.network == network for address in interfaces.get(interface, [])):
            raise DiscoveryError("CIDR não pertence a uma interface real conhecida pelo Agent.")
        if network_id in seen:
            raise DiscoveryError("Target duplicado.")
        seen.add(network_id)
        validated.append({"network_id": network_id, "interface": interface, "role": role, "network": network})
    return validated


def _neighbors(interface: str, network: ipaddress.IPv4Network, *, recent_only=False, strict=False) -> dict[str, str]:
    neighbors = {}
    for line in (_checked_run("ip", "neigh", "show", "dev", interface) if strict else _run("ip", "neigh", "show", "dev", interface)).splitlines():
        parts = line.split()
        if recent_only and "REACHABLE" not in parts:
            continue
        if "FAILED" in parts or "INCOMPLETE" in parts:
            continue
        if len(parts) < 4 or "lladdr" not in parts:
            continue
        try:
            ip = str(ipaddress.IPv4Address(parts[0]))
        except ipaddress.AddressValueError:
            continue
        if ipaddress.IPv4Address(ip) not in network:
            continue
        mac = _mac(parts[parts.index("lladdr") + 1] if parts.index("lladdr") + 1 < len(parts) else "")
        if mac:
            neighbors[ip] = mac
    return neighbors


def _ping(ip: str, interface: str) -> bool:
    return bool(_run("ping", "-I", interface, "-c", "1", "-W", "1", ip, timeout=2.0))


def _ports(ip: str) -> list[int]:
    def open_port(port: int) -> int | None:
        try:
            with socket.create_connection((ip, port), timeout=0.25):
                return port
        except OSError:
            return None
    with ThreadPoolExecutor(max_workers=PORT_WORKERS) as executor:
        return sorted(port for port in executor.map(open_port, PORTS) if port)


@lru_cache(maxsize=1)
def _oui() -> dict[str, str]:
    entries = {}
    for candidate in ("/usr/share/ieee-data/oui.txt", "/usr/share/misc/oui.txt", "/usr/share/nmap/nmap-mac-prefixes"):
        path = Path(candidate)
        if not path.is_file():
            continue
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                match = re.match(r"^([0-9A-Fa-f]{2}[-:]?[0-9A-Fa-f]{2}[-:]?[0-9A-Fa-f]{2}).*?(?:\(base 16\)|\(hex\))\s*(.+)$", line)
                if not match and path.name == "nmap-mac-prefixes":
                    match = re.match(r"^([0-9A-Fa-f]{6})\s+(.+)$", line)
                if match:
                    entries[re.sub(r"[^0-9A-F]", "", match.group(1).upper())] = match.group(2).strip()[:120]
        except OSError:
            continue
    return entries


def _scan_target(target: dict) -> dict:
    network = target["network"]
    interface = target["interface"]
    own_ips = {str(address.ip) for address in _agent_interfaces().get(interface, [])}
    neighbors = _neighbors(interface, network)
    hosts = [str(host) for host in network.hosts() if str(host) not in own_ips]
    alive = set(_neighbors(interface, network, recent_only=True))
    with ThreadPoolExecutor(max_workers=min(PING_WORKERS, max(1, len(hosts)))) as executor:
        futures = {executor.submit(_ping, host, interface): host for host in hosts}
        for future in as_completed(futures):
            if future.result():
                alive.add(futures[future])
    neighbors.update(_neighbors(interface, network))
    alive.update(_neighbors(interface, network, recent_only=True))
    alive.difference_update(own_ips)
    devices = []
    oui = _oui()
    for ip in sorted(alive, key=lambda value: int(ipaddress.IPv4Address(value))):
        mac = neighbors.get(ip)
        devices.append({
            "ip": ip,
            "mac": mac,
            "hostname": _hostname(ip),
            "vendor": oui.get(mac.replace(":", "")[:6], "Desconhecido") if mac else "Desconhecido",
            "open_ports": _ports(ip),
        })
    return {"network_id": target["network_id"], "ok": True, "devices": devices}


def executar_device_scan(dados: dict[str, Any]) -> dict[str, Any]:
    mode = dados.get("mode", "quick")
    if mode not in {"quick", "advanced"}:
        raise DiscoveryError("Modo de scan inválido.")
    if mode == "advanced" and not shutil.which("nmap"):
        raise DiscoveryError("Identificação avançada indisponível: Nmap não instalado.")
    targets = _targets(dados)
    advanced_remaining = 8
    logger.info("[devices.scan] recebido | targets=%d", len(targets))
    results = []
    for target in targets:
        try:
            result = _scan_target(target)
            if mode == "advanced":
                enriched = 0
                for device in result["devices"][:advanced_remaining]:
                    try:
                        extra = _advanced(device["ip"], target["interface"])
                        extra["open_ports"] = sorted(set(device["open_ports"]) | set(extra.get("open_ports", [])))
                        if device.get("hostname"):
                            extra.pop("hostname", None)
                        device.update(extra)
                    except (DiscoveryError, ET.ParseError):
                        result.setdefault("warnings", []).append("Identificação avançada incompleta; descoberta preservada.")
                    advanced_remaining -= 1
                    enriched += 1
                if len(result["devices"]) > enriched:
                    result.setdefault("warnings", []).append("Identificação avançada limitada a 8 hosts por solicitação.")
            results.append(result)
        except Exception as exc:
            results.append({"network_id": target["network_id"], "ok": False, "error": str(exc)[:500]})
    logger.info("[devices.scan] concluido | targets=%d sucesso=%d", len(results), sum(1 for result in results if result.get("ok")))
    return {"targets": results}



def _checked_run(*args: str, timeout: float = 2.0) -> str:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DiscoveryError("Ferramenta local indisponível ou timeout.") from exc
    if result.returncode != 0:
        raise DiscoveryError("Falha na consulta local de rede.")
    return result.stdout


def _hostname(ip: str) -> str | None:
    # Resolver local, limitado por processo; nenhuma API externa de identificação.
    result = _run("getent", "hosts", ip, timeout=0.6).split()
    if len(result) >= 2 and result[0] == ip:
        return result[1].strip().rstrip(".")[:120] or None
    return None


def _link_ready(interface: str) -> None:
    records = json.loads(_checked_run("ip", "-j", "link", "show", "dev", interface))
    if not records or "UP" not in records[0].get("flags", []) or records[0].get("operstate") not in {"UP", "UNKNOWN"}:
        raise DiscoveryError("Interface indisponível; disponibilidade não foi verificada.")


def _probe_ping(ip: str, interface: str) -> bool:
    try:
        result = subprocess.run(
            ["ping", "-I", interface, "-c", "1", "-W", "1", ip],
            capture_output=True, text=True, timeout=2, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DiscoveryError("ICMP indisponível; ciclo não conclusivo.") from exc
    if result.returncode not in (0, 1):
        raise DiscoveryError("Erro local ao executar ICMP.")
    return result.returncode == 0


def executar_device_probe(dados: dict[str, Any]) -> dict[str, Any]:
    if set(dados) - {"targets", "max_hosts"}:
        raise DiscoveryError("Probe aceita somente redes oficiais e hosts conhecidos.")
    targets = _targets(dados, probe=True)
    requested = {value["network_id"]: value for value in dados["targets"]}
    total = 0
    for target in targets:
        hosts = requested[target["network_id"]].get("hosts")
        if not isinstance(hosts, list):
            raise DiscoveryError("Lista de hosts conhecidos obrigatória.")
        seen = set()
        for host in hosts:
            if not isinstance(host, dict) or not str(host.get("device_id", "")).isdigit():
                raise DiscoveryError("Host sem identidade persistente.")
            try:
                address = ipaddress.IPv4Address(host.get("ip", ""))
            except (ValueError, TypeError) as exc:
                raise DiscoveryError("IP conhecido inválido.") from exc
            if address not in target["network"] or (target["network"].prefixlen < 31 and address in {target["network"].network_address, target["network"].broadcast_address}):
                raise DiscoveryError("Host fora da rede oficial.")
            if str(address) in seen:
                raise DiscoveryError("Host duplicado.")
            seen.add(str(address))
        total += len(hosts)
        target["hosts"] = hosts
    if total > 64:
        raise DiscoveryError("Probe limitado a 64 hosts por chamada.")
    results = []
    for target in targets:
        try:
            interface, network = target["interface"], target["network"]
            _link_ready(interface)
            _neighbors(interface, network, strict=True)
            with ThreadPoolExecutor(max_workers=8) as executor:
                positive = list(executor.map(lambda host: _probe_ping(host["ip"], interface), target["hosts"]))
            neighbors = _neighbors(interface, network, strict=True)
            recent = _neighbors(interface, network, recent_only=True, strict=True)
            _link_ready(interface)
            devices = []
            for host, ping_ok in zip(target["hosts"], positive):
                mac = neighbors.get(host["ip"])
                devices.append({
                    "device_id": str(host["device_id"]), "ip": host["ip"],
                    "online": ping_ok or host["ip"] in recent, "mac": mac,
                    "vendor": _oui().get(mac.replace(":", "")[:6]) if mac else None,
                })
            results.append({"network_id": target["network_id"], "ok": True, "devices": devices})
        except Exception as exc:
            results.append({"network_id": target["network_id"], "ok": False, "error": str(exc)[:500]})
    return {"targets": results}


def device_capabilities(dados: dict[str, Any]) -> dict[str, Any]:
    return {"advanced": bool(shutil.which("nmap")), "advanced_max_hosts": 8}


def _parse_nmap(xml: str, ip: str) -> dict:
    root = ET.fromstring(xml)
    for host in root.findall("host"):
        if not any(address.get("addr") == ip and address.get("addrtype") == "ipv4" for address in host.findall("address")):
            continue
        result = {}
        hostname = host.find("hostnames/hostname")
        if hostname is not None and hostname.get("name"):
            result["hostname"] = hostname.get("name")[:120]
        services, ports = [], []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if port.get("protocol") != "tcp" or state is None or state.get("state") != "open":
                continue
            number = int(port.get("portid", "0"))
            if not 0 < number < 65536:
                continue
            ports.append(number)
            service = port.find("service")
            if service is not None:
                services.append({"port": number, **{key: str(service.get(key, ""))[:120] for key in ("name", "product", "version", "ostype")}})
        result["open_ports"] = sorted(set(ports))
        result["services"] = services
        matches = host.findall("os/osmatch")
        if matches:
            best = max(matches, key=lambda match: int(match.get("accuracy", "0")))
            if int(best.get("accuracy", "0")) >= 85:
                result["os_fingerprint"] = best.get("name", "")[:160]
                result["os_confidence"] = min(95, int(best.get("accuracy", "0")))
        return result
    return {}


def _advanced(ip: str, interface: str) -> dict:
    executable = shutil.which("nmap")
    if not executable:
        raise DiscoveryError("Nmap não instalado.")
    xml = _checked_run(
        executable, "-n", "-Pn", "-e", interface, "-sS", "-sV", "--version-light",
        "-O", "--osscan-limit", "--top-ports", "20", "--max-retries", "0",
        "--host-timeout", "5s", "-T3", "-oX", "-", ip, timeout=6,
    )
    return _parse_nmap(xml, ip)
