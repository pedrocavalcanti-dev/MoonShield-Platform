"""Monitor de disponibilidade: configurações e orquestração via IPC."""
from contextlib import contextmanager
from datetime import timedelta
from functools import wraps
import ipaddress

from django.db import connection, transaction
from django.utils import timezone

from .models import Dispositivo, MonitorDispositivos, RedeDiscovery


@contextmanager
def inventory_lock():
    # Lock de sessão PostgreSQL: liberado inclusive quando o processo termina.
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_try_advisory_lock(%s)", [73402109])
        acquired = cursor.fetchone()[0]
    try:
        yield acquired
    finally:
        if acquired:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_unlock(%s)", [73402109])


def inventory_operation(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        from .services import DiscoveryValidationError
        with inventory_lock() as acquired:
            if not acquired:
                raise DiscoveryValidationError("Já existe um discovery ou monitor em andamento.")
            return function(*args, **kwargs)
    return wrapped


def monitor_config():
    config, _ = MonitorDispositivos.objects.get_or_create(pk=1)
    return {
        "enabled": config.enabled, "interval_minutes": config.interval_minutes,
        "networks": list(RedeDiscovery.objects.filter(monitored=True).values_list("network_id", flat=True)),
        "last_attempt": config.last_attempt.isoformat() if config.last_attempt else None,
    }


def save_monitor_config(body):
    from .services import DiscoveryValidationError, redes_elegiveis
    if set(body) != {"enabled", "interval_minutes", "networks"}:
        raise DiscoveryValidationError("Informe somente ativação, intervalo e IDs de redes oficiais.")
    ids = body["networks"]
    interval = body["interval_minutes"]
    if type(body["enabled"]) is not bool or type(interval) is not int or interval not in {2, 3, 5, 10}:
        raise DiscoveryValidationError("Ativação ou intervalo inválido; use 2, 3, 5 ou 10 minutos.")
    if not isinstance(ids, list) or not all(isinstance(item, str) for item in ids) or len(ids) > 8 or len(ids) != len(set(ids)):
        raise DiscoveryValidationError("Selecione até oito redes oficiais, sem duplicatas.")
    available = {network["id"]: network for network in redes_elegiveis()}
    if any(item not in available or not available[item]["monitor_allowed"] for item in ids):
        raise DiscoveryValidationError("Uma rede não pertence à topologia oficial elegível.")
    if body["enabled"] and not ids:
        raise DiscoveryValidationError("Selecione ao menos uma rede para ativar o monitor.")
    with transaction.atomic():
        config, _ = MonitorDispositivos.objects.get_or_create(pk=1)
        config.enabled = body["enabled"]
        config.interval_minutes = interval
        config.last_attempt = None
        config.save(update_fields=["enabled", "interval_minutes", "last_attempt"])
        old = set(RedeDiscovery.objects.filter(monitored=True).values_list("network_id", flat=True))
        RedeDiscovery.objects.update(monitored=False)
        RedeDiscovery.objects.filter(network_id__in=ids).update(monitored=True)
        changed = old.symmetric_difference(ids)
        Dispositivo.objects.filter(network_id__in=changed).update(availability_failures=0)
    return monitor_config()


def _apply_probe(device, raw, now, interval):
    from .services import _normalizar_mac
    # Nunca promove um novo ocupante do IP para a identidade antiga.
    mac = _normalizar_mac(raw.get("mac"))
    if mac and device.mac and mac != device.mac:
        device.status = Dispositivo.Status.STALE
        device.availability_failures = 0
        device.availability_checked_at = None
        device.save(update_fields=["status", "availability_failures", "availability_checked_at"])
        return
    if raw["online"]:
        if mac and not device.mac:
            if Dispositivo.objects.exclude(pk=device.pk).filter(identity_key=f"mac:{mac}").exists():
                device.status = Dispositivo.Status.STALE
                device.save(update_fields=["status"])
                return
            device.mac = mac
            device.identity_key = f"mac:{mac}"
            device.identity_temporary = False
        if mac and raw.get("vendor"):
            device.vendor = str(raw["vendor"])[:120]
        device.availability_failures = 0
        device.status = Dispositivo.Status.ONLINE
        device.last_seen = now
    else:
        if not device.availability_checked_at or now - device.availability_checked_at > timedelta(minutes=interval * 3 + 1):
            device.availability_failures = 0
        device.availability_failures = min(3, device.availability_failures + 1)
        if device.availability_failures >= 3:
            device.status = Dispositivo.Status.OFFLINE
    device.availability_checked_at = now
    device.save()


def monitor_once():
    from rede.services.agent_client import requisitar_agent
    from .services import marcar_inventario_stale, redes_elegiveis
    with inventory_lock() as acquired:
        if not acquired:
            return {"skipped": "busy"}
        config, _ = MonitorDispositivos.objects.get_or_create(pk=1)
        now = timezone.now()
        marcar_inventario_stale()
        if not config.enabled:
            return {"skipped": "disabled"}
        if config.last_attempt and now - config.last_attempt < timedelta(minutes=config.interval_minutes):
            return {"skipped": "interval"}
        config.last_attempt = now
        config.save(update_fields=["last_attempt"])
        targets = [network for network in redes_elegiveis() if network["monitored"] and network["monitor_allowed"]]
        checked, errors = 0, {}
        for target in targets:
            records = list(Dispositivo.objects.filter(
                network_id=target["id"], network_cidr=target["cidr"],
                interface_name=target["interface"], current_ip__isnull=False,
            ).order_by("pk"))
            hosts = [{"device_id": str(item.pk), "ip": item.current_ip} for item in records
                     if ipaddress.IPv4Address(item.current_ip) in ipaddress.IPv4Network(target["cidr"])]
            # Ambiguidade de IP mantém registros acessíveis, sem inventar identidade.
            counts = {}
            for host in hosts:
                counts[host["ip"]] = counts.get(host["ip"], 0) + 1
            hosts = [host for host in hosts if counts[host["ip"]] == 1]
            results = {}
            try:
                # Valida também redes vazias, sem discovery.
                chunks = [hosts[index:index + 64] for index in range(0, len(hosts), 64)] or [[]]
                for chunk in chunks:
                    payload = {"network_id": target["id"], "interface": target["interface"],
                               "role": target["role"], "cidr": target["cidr"], "hosts": chunk}
                    response = requisitar_agent("devices.probe", {"targets": [payload]}, timeout=30)
                    replies = response.get("targets", [])
                    if len(replies) != 1 or replies[0].get("network_id") != target["id"] or replies[0].get("ok") is not True:
                        raise ValueError("Agent não verificou a rede com sucesso.")
                    expected = {host["device_id"]: host["ip"] for host in chunk}
                    returned = {}
                    for raw in replies[0].get("devices", []):
                        identity = str(raw.get("device_id", ""))
                        if identity not in expected or identity in returned or raw.get("ip") != expected[identity] or type(raw.get("online")) is not bool:
                            raise ValueError("Resultado de probe incompatível com os hosts conhecidos.")
                        returned[identity] = raw
                    if set(returned) != set(expected):
                        raise ValueError("Probe incompleto; ciclo descartado.")
                    results.update(returned)
                # Descarta respostas se seleção/topologia mudou durante o IPC.
                current = {network["id"]: network for network in redes_elegiveis()}.get(target["id"])
                config.refresh_from_db()
                if not config.enabled or not current or not current["monitored"] or current["cidr"] != target["cidr"]:
                    continue
                completed = timezone.now()
                with transaction.atomic():
                    for device in Dispositivo.objects.select_for_update().filter(pk__in=results):
                        raw = results[str(device.pk)]
                        if device.network_id == target["id"] and device.current_ip == raw["ip"]:
                            _apply_probe(device, raw, completed, config.interval_minutes)
                            checked += 1
                    RedeDiscovery.objects.filter(network_id=target["id"]).update(last_probe=completed, last_probe_error="")
            except Exception as exc:
                errors[target["id"]] = str(exc)[:500]
                RedeDiscovery.objects.filter(network_id=target["id"]).update(last_probe_error=errors[target["id"]])
        marcar_inventario_stale()
        return {"checked": checked, "errors": errors}
