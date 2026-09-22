"""Serviços do inventário Dispositivos V2.

O módulo só consulta o estado persistido de Rede e delega discovery ao Agent.
Nenhum comando de sistema é executado pelo Django.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from datetime import timedelta
from collections.abc import Iterable
from typing import Any

from django.db import IntegrityError, transaction
from django.utils import timezone

from rede.services.agent_client import requisitar_agent
from rede.services.topologia import obter_topologia

from .models import Dispositivo, RedeDiscovery, ScanRun

logger = logging.getLogger(__name__)

_SCAN_LOCK_KEY = "devices-discovery"
_MAC_RE = re.compile(r"^[0-9A-F]{2}(?::[0-9A-F]{2}){5}$")


class DiscoveryValidationError(ValueError):
    pass


def _normalizar_mac(value: Any) -> str | None:
    mac = str(value or "").strip().upper().replace("-", ":")
    return mac if _MAC_RE.fullmatch(mac) else None


def _normalizar_ip(value: Any) -> str | None:
    try:
        return str(ipaddress.IPv4Address(str(value or "").strip()))
    except ipaddress.AddressValueError:
        return None


def _cidr_da_interface(interface: dict) -> str | None:
    real = interface.get("real") or {}
    candidates = real.get("enderecos_ipv4") or []
    if not candidates:
        candidates = [(real.get("ipv4"), real.get("prefixo"))]
    for value in candidates:
        if isinstance(value, tuple):
            address, prefix = value
            value = f"{address}/{prefix}" if address and prefix is not None else ""
        try:
            parsed = ipaddress.IPv4Interface(str(value))
        except (ipaddress.AddressValueError, ValueError):
            continue
        network = parsed.network
        if network.is_loopback or network.is_link_local or network.prefixlen == 0:
            continue
        return str(network)
    return None


def _max_hosts() -> int:
    try:
        from configuracoes.models import ConfigSistema
        value = ConfigSistema.objects.filter(pk=1).values_list("max_hosts", flat=True).first()
        return min(1024, max(1, int(value or 254)))
    except (ImportError, TypeError, ValueError):
        return 254


def redes_elegiveis() -> list[dict]:
    """Lista somente redes diretamente associadas à topologia oficial."""
    topologia = obter_topologia()
    groups = {
        "wan": (topologia.get("wan") or {}).get("interfaces") or [],
        "lan": (topologia.get("lan") or {}).get("interfaces") or [],
        "mgmt": (topologia.get("mgmt") or {}).get("interfaces") or [],
        "dmz": topologia.get("dmz") or [],
        "custom": topologia.get("custom") or [],
    }
    max_hosts = _max_hosts()
    result = []
    for role, interfaces in groups.items():
        for interface in interfaces:
            if not (interface.get("desejado") or {}).get("habilitada", True):
                continue
            cidr = _cidr_da_interface(interface)
            if not cidr:
                continue
            network = ipaddress.IPv4Network(cidr)
            allowed = network.num_addresses - 2 <= max_hosts
            network_id = f"{role}:{interface['nome']}"
            preference, created = RedeDiscovery.objects.get_or_create(
                network_id=network_id,
                defaults={
                    "role": role,
                    "interface_name": interface["nome"],
                    "cidr": cidr,
                    "selected": role == "lan",
                },
            )
            changed = []
            for field, value in (("role", role), ("interface_name", interface["nome"]), ("cidr", cidr)):
                if getattr(preference, field) != value:
                    setattr(preference, field, value)
                    changed.append(field)
            if changed:
                preference.save(update_fields=[*changed, "updated_at"])
            result.append({
                "id": network_id,
                "role": role,
                "interface": interface["nome"],
                "cidr": cidr,
                "selected": preference.selected,
                "allowed": allowed,
                "device_count": Dispositivo.objects.filter(network_id=network_id).count(),
                "last_scan": preference.last_scan.isoformat() if preference.last_scan else None,
                "gateway": (interface.get("real") or {}).get("gateway") or (interface.get("desejado") or {}).get("gateway"),
            })
    return result


def selecionar_redes(network_ids: Any) -> list[dict]:
    available = {network["id"]: network for network in redes_elegiveis()}
    if network_ids is None:
        selected = [network for network in available.values() if network["selected"]]
    else:
        if not isinstance(network_ids, list) or not all(isinstance(item, str) for item in network_ids):
            raise DiscoveryValidationError("'networks' deve ser uma lista de identificadores de rede.")
        if len(set(network_ids)) != len(network_ids):
            raise DiscoveryValidationError("A mesma rede foi informada mais de uma vez.")
        unknown = set(network_ids) - set(available)
        if unknown:
            raise DiscoveryValidationError("Uma ou mais redes não pertencem à topologia oficial.")
        with transaction.atomic():
            RedeDiscovery.objects.filter(network_id__in=available).update(selected=False)
            RedeDiscovery.objects.filter(network_id__in=network_ids).update(selected=True)
        selected = [available[item] for item in network_ids]

    if not selected:
        raise DiscoveryValidationError("Nenhuma rede foi selecionada para discovery.")
    denied = [network["id"] for network in selected if not network["allowed"]]
    if denied:
        raise DiscoveryValidationError("Uma rede selecionada excede o limite configurado de hosts.")
    return selected


def _classificar(device: dict, target: dict) -> tuple[str, str, str, int]:
    ports = {int(port) for port in device.get("open_ports", []) if str(port).isdigit()}
    hostname = str(device.get("hostname") or "").lower()
    vendor = str(device.get("vendor") or "").lower()
    ip = device.get("ip")
    if ip and ip == target.get("gateway"):
        return "Gateway", "Desconhecido", "bi-router-fill", 95
    if {9100, 631}.intersection(ports) and (9100 in ports or "print" in hostname or "printer" in vendor):
        return "Impressora", "Desconhecido", "bi-printer-fill", 85
    if 554 in ports and ("cam" in hostname or "hik" in vendor or "dahua" in vendor or 80 in ports):
        return "Câmera/NVR", "Desconhecido", "bi-camera-video-fill", 85
    if ("srv" in hostname or "server" in hostname or "dc" in hostname) and ({22, 445, 3389}.intersection(ports)):
        os_guess = "Windows provável" if {445, 3389}.intersection(ports) else "Linux provável"
        return "Servidor", os_guess, "bi-server", 80
    if {445, 3389}.intersection(ports) and ("pc" in hostname or "desktop" in hostname or "lenovo" in vendor):
        return "Computador", "Windows provável", "bi-pc-display-horizontal", 65
    if "android" in hostname or "iphone" in hostname or "mobile" in hostname:
        return "Dispositivo móvel", "Android provável" if "android" in hostname else "Desconhecido", "bi-phone", 65
    if 22 in ports and ("switch" in hostname or "ap-" in hostname or "ubiquiti" in vendor or "cisco" in vendor):
        return "Infraestrutura", "Linux provável", "bi-diagram-3", 65
    if any(word in hostname for word in ("iot", "esp", "shelly", "tuya")):
        return "IoT", "Desconhecido", "bi-cpu", 65
    return "Desconhecido", "Desconhecido", "bi-hdd-network-fill", 0


def _risk_score(ports: Iterable[int]) -> int:
    ports = {int(port) for port in ports}
    score = 10
    if {445, 3389}.intersection(ports):
        score += 40
    if 22 in ports:
        score += 20
    return min(100, score)


def _temporary_key(target: dict, ip: str) -> str:
    return f"temporary:{target['id']}:{ip}"


def _get_or_promote_device(target: dict, discovered: dict) -> Dispositivo:
    ip = discovered["ip"]
    mac = discovered.get("mac")
    temporary_key = _temporary_key(target, ip)
    with transaction.atomic():
        by_mac = Dispositivo.objects.select_for_update().filter(identity_key=f"mac:{mac}").first() if mac else None
        temporary = Dispositivo.objects.select_for_update().filter(identity_key=temporary_key).first()
        if by_mac and temporary and by_mac.pk != temporary.pk:
            if not by_mac.custom_name and temporary.custom_name:
                by_mac.custom_name = temporary.custom_name
                by_mac.save(update_fields=["custom_name"])
            temporary.delete()
        device = by_mac or temporary
        if device is None:
            device = Dispositivo.objects.create(
                identity_key=f"mac:{mac}" if mac else temporary_key,
                identity_temporary=not bool(mac),
                current_ip=ip,
            )
        elif mac and device.identity_key != f"mac:{mac}":
            device.identity_key = f"mac:{mac}"
            device.identity_temporary = False

        # Um IP que passou a ser anunciado por outro MAC não conserva o nome
        # ou a identidade do equipamento antigo.
        if mac:
            Dispositivo.objects.select_for_update().filter(current_ip=ip).exclude(pk=device.pk).update(
                current_ip=None, status=Dispositivo.Status.OFFLINE,
            )
        return device


def _persist_device(target: dict, raw: dict, now) -> Dispositivo | None:
    ip = _normalizar_ip(raw.get("ip"))
    if not ip or ipaddress.IPv4Address(ip) not in ipaddress.IPv4Network(target["cidr"]):
        return None
    mac = _normalizar_mac(raw.get("mac"))
    ports = sorted({int(port) for port in raw.get("open_ports", []) if str(port).isdigit() and 0 < int(port) < 65536})
    hostname = str(raw.get("hostname") or "").strip()[:120] or None
    vendor = str(raw.get("vendor") or "").strip()[:120] or None
    device = _get_or_promote_device(target, {"ip": ip, "mac": mac})
    device_type, os_guess, icon, confidence = _classificar({"ip": ip, "hostname": hostname, "vendor": vendor, "open_ports": ports}, target)
    device.current_ip = ip
    device.mac = mac or device.mac
    device.detected_hostname = hostname or device.detected_hostname
    device.vendor = vendor or device.vendor or "Desconhecido"
    device.device_type = device_type
    device.os_guess = os_guess
    device.icon = icon
    device.classification_confidence = confidence
    device.observed_ports = ports
    device.interface_name = target["interface"]
    device.network_role = target["role"]
    device.network_cidr = target["cidr"]
    device.network_id = target["id"]
    device.status = Dispositivo.Status.ONLINE
    device.risk_score = _risk_score(ports)
    device.last_seen = now
    device.last_scan = now
    device.save()
    return device


def executar_scan(network_ids: Any = None) -> dict:
    targets = selecionar_redes(network_ids)
    requested = [{key: target[key] for key in ("id", "role", "interface", "cidr")} for target in targets]
    try:
        scan = ScanRun.objects.create(lock_key=_SCAN_LOCK_KEY, requested_networks=requested)
    except IntegrityError as exc:
        raise DiscoveryValidationError("Já existe um discovery em andamento.") from exc

    now = timezone.now()
    errors: dict[str, str] = {}
    found = 0
    successful_ids: set[str] = set()
    try:
        agent_targets = [{"network_id": target["id"], "interface": target["interface"], "cidr": target["cidr"], "role": target["role"]} for target in targets]
        result = requisitar_agent("devices.scan", {"targets": agent_targets, "max_hosts": _max_hosts()}, timeout=120)
        responses = result.get("targets") if isinstance(result.get("targets"), list) else []
        by_id = {target["id"]: target for target in targets}
        for response in responses:
            if not isinstance(response, dict) or response.get("network_id") not in by_id:
                continue
            target = by_id[response["network_id"]]
            if not response.get("ok"):
                errors[target["id"]] = str(response.get("error") or "Falha no Agent.")[:500]
                continue
            successful_ids.add(target["id"])
            seen_ids = set()
            for raw in response.get("devices") or []:
                if not isinstance(raw, dict):
                    continue
                device = _persist_device(target, raw, now)
                if device:
                    seen_ids.add(device.pk)
                    found += 1
            Dispositivo.objects.filter(network_id=target["id"]).exclude(pk__in=seen_ids).update(
                status=Dispositivo.Status.OFFLINE, last_scan=now,
            )
            RedeDiscovery.objects.filter(network_id=target["id"]).update(last_scan=now)
        missing = set(by_id) - successful_ids - set(errors)
        errors.update({network_id: "O Agent não retornou resultado para esta rede." for network_id in missing})
        scan.status = ScanRun.Status.COMPLETED if not errors else (ScanRun.Status.PARTIAL if successful_ids else ScanRun.Status.FAILED)
        scan.found = found
        scan.errors_by_network = errors
        scan.summary = {"successful_networks": sorted(successful_ids), "found": found}
        return {"ok": not errors, "scan_id": scan.pk, "found": found, "status": scan.status, "errors": errors}
    except Exception as exc:
        logger.exception("Falha ao executar discovery de dispositivos")
        scan.status = ScanRun.Status.FAILED
        scan.errors_by_network = {"agent": str(exc)[:500]}
        scan.summary = {"found": 0}
        raise
    finally:
        scan.finished_at = timezone.now()
        scan.lock_key = None
        scan.save(update_fields=["status", "found", "errors_by_network", "summary", "finished_at", "lock_key"])


def marcar_inventario_stale() -> int:
    """Evita afirmar online/offline quando a última observação já expirou."""
    try:
        from configuracoes.models import ConfigSistema
        interval = ConfigSistema.objects.filter(pk=1).values_list("scan_interval", flat=True).first()
        seconds = max(300, min(86400, int(interval or 60) * 2))
    except (ImportError, TypeError, ValueError):
        seconds = 300
    cutoff = timezone.now() - timedelta(seconds=seconds)
    return Dispositivo.objects.filter(
        status__in=[Dispositivo.Status.ONLINE, Dispositivo.Status.OFFLINE],
        last_scan__lt=cutoff,
    ).update(status=Dispositivo.Status.STALE)
def serializar_dispositivo(device: Dispositivo) -> dict:
    return {
        "device_id": str(device.pk), "ip": device.current_ip, "current_ip": device.current_ip,
        "mac": device.mac, "hostname": device.display_name(), "detected_hostname": device.detected_hostname,
        "display_name": device.display_name(), "vendor": device.vendor, "os_guess": device.os_guess,
        "device_type": device.device_type, "type": device.device_type, "os": device.os_guess, "status": device.status, "risk_score": device.risk_score,
        "interface": device.interface_name, "network_role": device.network_role, "network_cidr": device.network_cidr,
        "network_id": device.network_id, "open_ports": device.observed_ports or [],
        "last_seen": device.last_seen.isoformat() if device.last_seen else None,
        "last_scan": device.last_scan.isoformat() if device.last_scan else None,
        "first_seen": device.first_seen.isoformat() if device.first_seen else None,
    }


def validar_custom_name(value: Any) -> str:
    if not isinstance(value, str):
        raise DiscoveryValidationError("O nome deve ser texto.")
    name = value.strip()
    if not name or len(name) > 120:
        raise DiscoveryValidationError("O nome deve ter entre 1 e 120 caracteres.")
    if any(ord(char) < 32 for char in name) or "<" in name or ">" in name:
        raise DiscoveryValidationError("O nome contém caracteres inválidos.")
    return name
