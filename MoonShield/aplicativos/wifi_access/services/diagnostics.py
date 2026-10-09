from __future__ import annotations

import logging
from typing import Any

from django.conf import settings
from django.utils import timezone

from wifi_access.models import WifiAuthorization, WifiTrustedDevice

logger = logging.getLogger(__name__)

def get_diagnostics() -> dict[str, Any]:
    """Retorna o estado de saÃºde e diagnÃ³stico do controle de acesso Wi-Fi."""
    agent_online = False
    try:
        from rede.services.agent_client import agent_disponivel
        agent_online = agent_disponivel()
    except Exception as exc:
        logger.info("Erro ao verificar disponibilidade do Agent para o Wi-Fi: %s", exc)

    now = timezone.now()

    # Contadores de Authorizations
    all_auths = WifiAuthorization.objects.all()
    active_logins = all_auths.filter(active=True).count()
    expired_logins = all_auths.filter(active=False, revoked_reason="expirado").count()

    # Contadores de Trusted
    all_trusted = WifiTrustedDevice.objects.all()
    active_trusted = all_trusted.filter(active=True).count()

    # InconsistÃªncias conhecidas no banco (apenas um chute inicial, a reconciliaÃ§Ã£o corrige)
    # Por exemplo: MACs diferentes com mesmo IP ativo
    active_ips = list(WifiAuthorization.objects.filter(active=True).exclude(ip_address__isnull=True).values_list("ip_address", flat=True))
    reused_ips = len(active_ips) - len(set(active_ips))

    # ConfiguraÃ§Ãµes do enforcement
    enforcement_enabled = getattr(settings, "WIFI_ENFORCEMENT_ENABLED", False)
    cidrs = getattr(settings, "WIFI_CLIENT_CIDRS", None) or "IndisponÃ­vel"
    ifaces = getattr(settings, "WIFI_INGRESS_INTERFACES", None) or "IndisponÃ­vel"

    from wifi_access.services.firewall import desired_wifi_ips
    desired_count = len(desired_wifi_ips())

    # Ãšltima sync seria o horÃ¡rio que a tarefa de reconciliaÃ§Ã£o rodou com sucesso.
    # Como nÃ£o temos um log global persistente disso alÃ©m dos registros de autorizaÃ§Ã£o,
    # podemos olhar o Ãºltimo "updated_at" global de um dispositivo alterado ou
    # o status do firewall.
    from firewall.services.firewall_rules import obter_sync_status
    sync_status = obter_sync_status()

    return {
        "agent_online": agent_online,
        "enforcement_enabled": enforcement_enabled,
        "enforcement_cidrs": cidrs,
        "enforcement_interfaces": ifaces,
        "trusted_devices": active_trusted,
        "active_logins": active_logins,
        "expired_logins": expired_logins,
        "ip_inconsistencies": reused_ips,
        "desired_ips_count": desired_count,
        "firewall_in_sync": sync_status.get("em_sync"),
    }
