from __future__ import annotations

import logging
from typing import Any

from django.db import transaction
from django.utils import timezone

from dispositivos.models import Dispositivo
from wifi_access.models import WifiAuthorization, WifiTrustedDevice
from wifi_access.services.devices import _UNRELIABLE_STATUS, _INVALID_NEIGH_STATES, _safe_mac, agent_neighbors
from wifi_access.services.firewall import lock_wifi_changes, apply_or_raise, desired_wifi_ips

logger = logging.getLogger(__name__)

def build_mac_to_ip_map() -> dict[str, str]:
    """Constrói mapeamento seguro de MAC para IP atual (fonte: Inventário + Neighbour)."""
    mac_to_ip: dict[str, str] = {}

    # 1. ARP/Neighbour tem precedência por ser o tempo real da rede local
    try:
        neighbors = agent_neighbors()
        for item in neighbors:
            states = item.get("state") or []
            states = {str(state).upper() for state in (states if isinstance(states, list) else [states])}
            if states & _INVALID_NEIGH_STATES:
                continue
            mac = _safe_mac(item.get("lladdr"))
            ip = item.get("dst")
            if mac and ip:
                mac_to_ip[mac] = ip
    except Exception as exc:
        logger.warning("Falha ao obter neighbors durante reconciliação: %s", exc)

    # 2. Inventário preenche lacunas com dados confiáveis
    inventory = Dispositivo.objects.exclude(current_ip__isnull=True).exclude(current_ip="").exclude(mac__isnull=True).exclude(mac="")
    for raw_mac, ip, status in inventory.values_list("mac", "current_ip", "status"):
        if status in _UNRELIABLE_STATUS:
            continue
        mac = _safe_mac(raw_mac)
        if mac and mac not in mac_to_ip:
            mac_to_ip[mac] = ip

    return mac_to_ip


def reconcile_wifi_access(*, dry_run: bool = False) -> dict[str, Any]:
    """Reconcilia ativamente MAC->IP, expirações e aplica o estado no Firewall.

    - Expira sessões que passaram do tempo.
    - Atualiza IP de Trusted Devices e Autorizações com base no MAC real.
    - Revoga autorizações ativas que ficaram órfãs de IP ou cujo IP foi repassado.
    - Idempotente e serializado.
    """
    now = timezone.now()
    mac_to_ip = build_mac_to_ip_map()

    actions_taken = []

    if dry_run:
        return _dry_run_logic(now, mac_to_ip)

    try:
        with transaction.atomic():
            lock_wifi_changes()

            # 1. Expiração explícita
            expired = WifiAuthorization.objects.select_for_update().filter(active=True, expires_at__lte=now)
            for auth in expired:
                actions_taken.append(f"Expirando autorização de {auth.username} (MAC {auth.mac_address})")
                auth.active = False
                auth.revoked_at = now
                auth.revoked_reason = "expirado"
                auth.save(update_fields=["active", "revoked_at", "revoked_reason", "updated_at"])

            # 2. Reconciliação MAC -> IP para Trusted Devices
            trusted = WifiTrustedDevice.objects.select_for_update().filter(active=True)
            for device in trusted:
                real_ip = mac_to_ip.get(device.mac_address)
                if real_ip and device.ip_address != real_ip:
                    actions_taken.append(f"Trusted {device.nome} (MAC {device.mac_address}): IP alterado de {device.ip_address} para {real_ip}")
                    device.ip_address = real_ip
                    device.save(update_fields=["ip_address", "updated_at"])

            # 3. Reconciliação MAC -> IP para Authorizations
            auths = WifiAuthorization.objects.select_for_update().filter(active=True)
            active_ips = set()
            for auth in auths:
                real_ip = mac_to_ip.get(auth.mac_address)
                if real_ip and auth.ip_address != real_ip:
                    actions_taken.append(f"Login {auth.username} (MAC {auth.mac_address}): IP alterado de {auth.ip_address} para {real_ip}")
                    auth.ip_address = real_ip
                    auth.save(update_fields=["ip_address", "updated_at"])

                # Se não temos ideia do IP real agora, mantemos o que está salvo para não derrubar
                # a conexão temporária do usuário, a menos que esse IP esteja em uso por outro MAC.
                current_ip = auth.ip_address
                if current_ip:
                    active_ips.add(current_ip)

            # 4. Tratamento de Reuso de IP (Inconsistência)
            # Se dois MACs diferentes têm o mesmo IP ativo, o que tiver a autorização mais antiga deve ser revogado.
            # O `authorize` original já limpa IPs anteriores ao logar. Mas a reconciliação pega
            # mudanças assíncronas do DHCP (via `agent_neighbors` ou inventário).
            ip_to_active_mac = {}
            # Ordena do mais recente para o mais antigo, para manter o login mais recente e derrubar os velhos.
            ordered_auths = WifiAuthorization.objects.select_for_update().filter(active=True).order_by("-authorized_at")
            for auth in ordered_auths:
                if auth.ip_address:
                    if auth.ip_address in ip_to_active_mac and ip_to_active_mac[auth.ip_address] != auth.mac_address:
                        actions_taken.append(f"Revogando {auth.username} (MAC {auth.mac_address}) devido a reuso do IP {auth.ip_address}")
                        auth.active = False
                        auth.revoked_at = now
                        auth.revoked_reason = "ip_reatribuido"
                        auth.save(update_fields=["active", "revoked_at", "revoked_reason", "updated_at"])
                    else:
                        ip_to_active_mac[auth.ip_address] = auth.mac_address

            # 5. Sincronização Final com o Agent
            result = apply_or_raise()

    except Exception as exc:
        logger.error("Falha na reconciliação Wi-Fi: %s", exc)
        return {
            "ok": False,
            "error": str(exc),
            "actions_taken": actions_taken
        }

    return {
        "ok": True,
        "actions_taken": actions_taken,
        "sync_result": result,
    }


def _dry_run_logic(now, mac_to_ip: dict[str, str]) -> dict[str, Any]:
    """Retorna exatamente o que seria feito, sem tocar no banco ou firewall."""
    actions = []

    expired = WifiAuthorization.objects.filter(active=True, expires_at__lte=now)
    for auth in expired:
        actions.append(f"[EXPIRE] Autorização de {auth.username} (MAC {auth.mac_address}) seria expirada.")

    trusted = WifiTrustedDevice.objects.filter(active=True)
    for device in trusted:
        real_ip = mac_to_ip.get(device.mac_address)
        if real_ip and device.ip_address != real_ip:
            actions.append(f"[UPDATE] Trusted {device.nome} mudaria IP de {device.ip_address} para {real_ip}.")

    auths = WifiAuthorization.objects.filter(active=True)
    ip_to_mac = {}
    for auth in auths.order_by("-authorized_at"):
        real_ip = mac_to_ip.get(auth.mac_address)
        ip = real_ip or auth.ip_address
        if real_ip and auth.ip_address != real_ip:
            actions.append(f"[UPDATE] Login {auth.username} mudaria IP de {auth.ip_address} para {real_ip}.")

        if ip:
            if ip in ip_to_mac and ip_to_mac[ip] != auth.mac_address:
                actions.append(f"[REVOKE] Login {auth.username} seria revogado por reuso do IP {ip} pelo MAC {ip_to_mac[ip]}.")
            else:
                ip_to_mac[ip] = auth.mac_address

    from django.conf import settings
    enforcement = getattr(settings, "WIFI_ENFORCEMENT_ENABLED", False)
    cidrs = getattr(settings, "WIFI_CLIENT_CIDRS", "")
    ifaces = getattr(settings, "WIFI_INGRESS_INTERFACES", "")

    return {
        "ok": True,
        "dry_run": True,
        "actions_taken": actions,
        "state": {
            "enforcement_enabled": enforcement,
            "cidrs": cidrs,
            "interfaces": ifaces,
            "desired_ips": list(desired_wifi_ips()),
        }
    }
