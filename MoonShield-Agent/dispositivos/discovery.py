"""Discovery local e limitado, executado somente pelo MoonShield Agent."""
from __future__ import annotations

import ipaddress
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


class DiscoveryError(ValueError):
    codigo = "devices_scan_invalido"


def _mac(value: Any) -> str | None:
    value = str(value or "").strip().upper().replace("-", ":")
    return value if _MAC_RE.fullmatch(value) else None


def _run(*args: str, timeout: float = 2.0) -> str:
    try:
        completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout if completed.returncode == 0 else ""


def _agent_interfaces() -> dict[str, list[ipaddress.IPv4Interface]]:
    from rede.nucleo.inventario import obter_inventario
    inventory = obter_inventario()
    result: dict[str, list[ipaddress.IPv4Interface]] = {}
    for item in inventory.get("interfaces") or []:
        name = str(item.get("nome") or item.get("name") or "").strip()
        addresses = item.get("ipv4") or item.get("enderecos_ipv4") or []
        if not isinstance(addresses, list):
            addresses = [addresses]
        parsed = []
        for address in addresses:
            try:
                parsed.append(ipaddress.IPv4Interface(str(address)))
            except (ipaddress.AddressValueError, ValueError):
                continue
        if name and parsed:
            result[name] = parsed
    return result


def _targets(payload: dict[str, Any]) -> list[dict]:
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
        if not network_id or not interface or role not in {"lan", "wan", "mgmt", "dmz", "custom"}:
            raise DiscoveryError("Target sem identidade, interface ou papel válido.")
        if network.is_loopback or network.is_link_local or network.prefixlen == 0 or not network.is_private:
            raise DiscoveryError("A rede solicitada não é elegível ao discovery.")
        if network.num_addresses - 2 > limit:
            raise DiscoveryError("A rede solicitada excede o limite de hosts.")
        if not any(address.network == network for address in interfaces.get(interface, [])):
            raise DiscoveryError("CIDR não pertence a uma interface real conhecida pelo Agent.")
        if network_id in seen:
            raise DiscoveryError("Target duplicado.")
        seen.add(network_id)
        validated.append({"network_id": network_id, "interface": interface, "role": role, "network": network})
    return validated


def _neighbors(interface: str, network: ipaddress.IPv4Network) -> dict[str, str]:
    neighbors = {}
    for line in _run("ip", "neigh", "show", "dev", interface).splitlines():
        parts = line.split()
        if len(parts) < 5 or "lladdr" not in parts:
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
    for candidate in ("/usr/share/ieee-data/oui.txt", "/usr/share/misc/oui.txt", "/usr/share/ieee-data/oui36.txt"):
        path = Path(candidate)
        if not path.is_file():
            continue
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                match = re.match(r"^([0-9A-Fa-f]{2}[-:]?[0-9A-Fa-f]{2}[-:]?[0-9A-Fa-f]{2}).*?(?:\(base 16\)|\(hex\))\s*(.+)$", line)
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
    alive = set(neighbors)
    with ThreadPoolExecutor(max_workers=min(PING_WORKERS, max(1, len(hosts)))) as executor:
        futures = {executor.submit(_ping, host, interface): host for host in hosts}
        for future in as_completed(futures):
            if future.result():
                alive.add(futures[future])
    neighbors.update(_neighbors(interface, network))
    devices = []
    oui = _oui()
    for ip in sorted(alive, key=lambda value: int(ipaddress.IPv4Address(value))):
        mac = neighbors.get(ip)
        devices.append({
            "ip": ip,
            "mac": mac,
            "hostname": None,
            "vendor": oui.get(mac.replace(":", "")[:6], "Desconhecido") if mac else "Desconhecido",
            "open_ports": _ports(ip),
        })
    return {"network_id": target["network_id"], "ok": True, "devices": devices}


def executar_device_scan(dados: dict[str, Any]) -> dict[str, Any]:
    targets = _targets(dados)
    results = []
    for target in targets:
        try:
            results.append(_scan_target(target))
        except Exception as exc:
            results.append({"network_id": target["network_id"], "ok": False, "error": str(exc)[:500]})
    return {"targets": results}
