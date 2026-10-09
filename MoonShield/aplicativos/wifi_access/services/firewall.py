from __future__ import annotations

import ipaddress
import logging
from collections.abc import Iterable

from django.db import connection

from wifi_access.models import WifiAuthorization, WifiTrustedDevice


logger = logging.getLogger(__name__)

# Chave fixa do advisory lock PostgreSQL que serializa mudanÃ§as Wi-Fi.
_WIFI_LOCK_KEY = 0x57494649  # "WIFI"


class WifiFirewallError(RuntimeError):
    def __init__(self, result: dict):
        self.result = dict(result or {})
        self.code = str(self.result.get("codigo") or "firewall_indisponivel")
        super().__init__(str(self.result.get("erro") or "NÃ£o foi possÃ­vel aplicar a autorizaÃ§Ã£o no firewall."))


def _ipv4(value: object) -> str | None:
    try:
        return str(ipaddress.IPv4Address(str(value or "").strip()))
    except ipaddress.AddressValueError:
        return None


def lock_wifi_changes() -> None:
    """Serializa alteraÃ§Ãµes Wi-Fi + firewall dentro da transaÃ§Ã£o atual.

    Evita que dois logins simultÃ¢neos enviem allowlists concorrentes ao Agent
    (o Ãºltimo sobrescreveria o primeiro). Em SQLite (dev) a prÃ³pria escrita
    serializa a transaÃ§Ã£o.
    """
    if connection.vendor == "postgresql":
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_xact_lock(%s)", [_WIFI_LOCK_KEY])


def desired_wifi_ips() -> set[str]:
    """IPs Wi-Fi desejados, derivados do banco (uma entrada por MAC)."""
    by_mac: dict[str, str] = {}
    for mac, ip in WifiAuthorization.objects.filter(active=True).values_list("mac_address", "ip_address"):
        if current := _ipv4(ip):
            by_mac[mac] = current
    trusted = WifiTrustedDevice.objects.filter(active=True).exclude(ip_address__isnull=True)
    for mac, ip in trusted.values_list("mac_address", "ip_address"):
        if current := _ipv4(ip):
            by_mac[mac] = current  # Permanente tem precedÃªncia sobre login.
    return set(by_mac.values())


def get_wifi_firewall_payload(topologia_rede: dict) -> dict:
    from django.conf import settings
    enforcement = getattr(settings, "WIFI_ENFORCEMENT_ENABLED", False)
    range_start = getattr(settings, "WIFI_CLIENT_RANGE_START", "").strip()
    range_end = getattr(settings, "WIFI_CLIENT_RANGE_END", "").strip()
    egress_interfaces = getattr(settings, "WIFI_EGRESS_INTERFACES", "")

    if enforcement:
        try:
            start_ip = ipaddress.IPv4Address(range_start)
            end_ip = ipaddress.IPv4Address(range_end)
            if start_ip > end_ip:
                raise ValueError("start > end")
            # Same network check can be skipped or done via string split for now
        except Exception:
            enforcement = False
            logger.warning("enforcement solicitado, mas faixa DHCP invÃ¡lida")

    if not egress_interfaces:
        # Fallback to topology WAN
        wan = topologia_rede.get("interface_wan")
        if wan:
            egress_interfaces = wan

    payload = {
        "enabled": enforcement,
        "range_start": range_start if enforcement else "",
        "range_end": range_end if enforcement else "",
        "egress_interfaces": [i.strip() for i in egress_interfaces.split(",") if i.strip()] if egress_interfaces else [],
        "authorized_ips": sorted(list(desired_wifi_ips())),
    }
    return payload


def sync_authorizations() -> dict:
    """Reaplica o Firewall pelo fluxo oficial, jÃ¡ com o estado Wi-Fi do banco.

    Usa ``aplicar_regras_pendentes`` (Agent + Safe Apply/confirmaÃ§Ã£o existente).
    A allowlist nativa Ã© montada por ``listar_allowlist_para_agent``, que
    agrega os IPs Wi-Fi via ``merge_allowlist`` sem tocar nas entradas do
    usuÃ¡rio. Nunca lanÃ§a exceÃ§Ã£o: falhas retornam ``ok=False`` controlado.
    """
    try:
        from firewall.services.firewall_rules import aplicar_regras_pendentes

        result = aplicar_regras_pendentes()
    except Exception as exc:  # Ex.: Windows sem socket Unix, erro inesperado no IPC.
        logger.warning("SincronizaÃ§Ã£o Wi-Fi com o Firewall falhou: %s", exc)
        return {"ok": False, "codigo": "firewall_indisponivel", "erro": "Firewall/Agent indisponÃ­vel neste ambiente."}
    if not isinstance(result, dict):
        return {"ok": False, "codigo": "firewall_resposta_invalida", "erro": "Resposta invÃ¡lida do Firewall."}
    return result


def apply_or_raise() -> dict:
    """Sincroniza e lanÃ§a ``WifiFirewallError`` para provocar rollback do banco."""
    result = sync_authorizations()
    if not result.get("ok"):
        raise WifiFirewallError(result)
    return result
