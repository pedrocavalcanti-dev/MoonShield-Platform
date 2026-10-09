from __future__ import annotations

import ipaddress

from django.db import transaction
from django.utils import timezone

from wifi_access.models import WifiAuthorization, WifiTrustedDevice

from .devices import MacResolutionError, resolve_mac
from .firewall import WifiFirewallError, apply_or_raise, lock_wifi_changes


class WifiAuthorizationError(ValueError):
    def __init__(self, code: str, message: str, *, status: int = 400):
        super().__init__(message)
        self.code = code
        self.status = status


def _ip(value: object) -> str:
    if not isinstance(value, str):
        raise WifiAuthorizationError("ip_invalido", "Informe um endereÃ§o IPv4 vÃ¡lido.")
    try:
        return str(ipaddress.IPv4Address(value.strip()))
    except ipaddress.AddressValueError as exc:
        raise WifiAuthorizationError("ip_invalido", "Informe um endereÃ§o IPv4 vÃ¡lido.") from exc


def _username(value: object) -> str:
    username = value.strip() if isinstance(value, str) else ""
    if not username or len(username) > 150 or any(ord(char) < 32 or ord(char) == 127 for char in username):
        raise WifiAuthorizationError("username_invalido", "Informe um usuÃ¡rio vÃ¡lido.")
    return username


def _firewall_error(exc: WifiFirewallError) -> WifiAuthorizationError:
    return WifiAuthorizationError(exc.code, str(exc), status=503)


def is_trusted_mac(mac_address: str) -> bool:
    return WifiTrustedDevice.objects.filter(mac_address=mac_address, active=True).exists()


def authorize(username: object, ip_address: object) -> dict:
    """Autoriza um cliente jÃ¡ autenticado pelo AUTH01.

    O banco Ã© alterado dentro de uma transaÃ§Ã£o; o Firewall Ã© aplicado com esse
    estado e, se falhar, a transaÃ§Ã£o Ã© desfeita (nada fica ativo sem firewall).
    """
    username = _username(username)
    ip_address = _ip(ip_address)
    try:
        mac_address = resolve_mac(ip_address)
    except MacResolutionError as exc:
        raise WifiAuthorizationError(exc.code, str(exc), status=400 if exc.code == "ip_invalido" else 404) from exc

    now = timezone.now()
    try:
        with transaction.atomic():
            lock_wifi_changes()
            trusted = WifiTrustedDevice.objects.select_for_update().filter(mac_address=mac_address, active=True).first()
            # IP reatribuÃ­do pelo DHCP: autorizaÃ§Ãµes de outros MACs neste IP deixam de valer.
            WifiAuthorization.objects.filter(active=True, ip_address=ip_address).exclude(mac_address=mac_address).update(
                active=False, revoked_at=now, revoked_reason="ip_reatribuido", updated_at=now,
            )
            if trusted:
                if trusted.ip_address != ip_address:
                    trusted.ip_address = ip_address
                    trusted.save(update_fields=["ip_address", "updated_at"])
                apply_or_raise()
                return {"username": username, "ip_address": ip_address, "mac_address": mac_address, "trusted": True, "authorized": True}

            authorization = WifiAuthorization.objects.select_for_update().filter(mac_address=mac_address, active=True).first()
            if authorization is None:
                authorization = WifiAuthorization(username=username, mac_address=mac_address, authorized_at=now, active=True)
            elif authorization.username != username:
                # Outro usuÃ¡rio no mesmo dispositivo: encerra a sessÃ£o anterior para auditoria.
                authorization.active = False
                authorization.revoked_at = now
                authorization.revoked_reason = "substituida_por_novo_login"
                authorization.save(update_fields=["active", "revoked_at", "revoked_reason", "updated_at"])
                authorization = WifiAuthorization(username=username, mac_address=mac_address, authorized_at=now, active=True)
            authorization.ip_address = ip_address
            authorization.last_seen_at = now
            authorization.save()
            apply_or_raise()
    except WifiFirewallError as exc:
        raise _firewall_error(exc) from exc

    return {
        "authorization": authorization,
        "username": username,
        "ip_address": ip_address,
        "mac_address": mac_address,
        "trusted": False,
        "authorized": True,
    }


def revoke(*, ip_address: object = None, authorization_id: object = None, reason: object = "") -> WifiAuthorization:
    if (ip_address is None) == (authorization_id is None):
        raise WifiAuthorizationError("revogacao_invalida", "Informe somente ip_address ou authorization_id.")
    if authorization_id is not None and (type(authorization_id) is not int or authorization_id <= 0):
        raise WifiAuthorizationError("revogacao_invalida", "authorization_id deve ser inteiro positivo.")
    lookup = {"pk": authorization_id} if authorization_id is not None else {"ip_address": _ip(ip_address)}

    try:
        with transaction.atomic():
            lock_wifi_changes()
            authorization = WifiAuthorization.objects.select_for_update().filter(active=True, **lookup).first()
            if authorization is None:
                raise WifiAuthorizationError("autorizacao_nao_encontrada", "AutorizaÃ§Ã£o ativa nÃ£o encontrada.", status=404)
            authorization.active = False
            authorization.revoked_at = timezone.now()
            authorization.revoked_reason = str(reason or "")[:255]
            authorization.save(update_fields=["active", "revoked_at", "revoked_reason", "updated_at"])
            apply_or_raise()
    except WifiFirewallError as exc:
        raise _firewall_error(exc) from exc
    return authorization
