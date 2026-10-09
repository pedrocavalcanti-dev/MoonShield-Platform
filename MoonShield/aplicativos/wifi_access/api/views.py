from __future__ import annotations

import hmac
import ipaddress
import json

from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from wifi_access.models import WifiAuthorization, WifiTrustedDevice
from wifi_access.services.authorization import WifiAuthorizationError, authorize as authorize_device, revoke as revoke_device
from wifi_access.services.devices import MacResolutionError, resolve_mac


_PASSWORD_FIELDS = {"password", "senha", "password_hash"}
_MAC_FIELDS = {"mac", "mac_address"}


def _error(code: str, message: str, status: int) -> JsonResponse:
    return JsonResponse({"ok": False, "codigo": code, "erro": message}, status=status)


def _source_ip(request) -> str | None:
    """Obtém IP do cliente; só aceita header do proxy local confiável (Nginx)."""
    remote = str(request.META.get("REMOTE_ADDR") or "").strip()
    candidate = request.META.get("HTTP_X_REAL_IP") if remote in {"127.0.0.1", "::1"} else remote
    try:
        return str(ipaddress.ip_address(str(candidate or "").strip()))
    except ValueError:
        return None


def _authenticate(request) -> JsonResponse | None:
    token = str(getattr(settings, "WIFI_API_TOKEN", "") or "").encode("utf-8")
    authorization = str(request.META.get("HTTP_AUTHORIZATION") or "")
    prefix, _, provided = authorization.partition(" ")
    provided = provided.strip().encode("utf-8", "surrogateescape")
    if not token or prefix.lower() != "bearer" or not provided or not hmac.compare_digest(token, provided):
        return _error("token_invalido", "Token de API inválido.", 401)
    allowed = set(getattr(settings, "WIFI_API_ALLOWED_IPS", ()) or ())
    source = _source_ip(request)
    if not allowed or source not in allowed:
        return _error("origem_nao_permitida", "Origem da API não permitida.", 403)
    return None


def _reject_duplicates(pairs):
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("Chave JSON duplicada.")
    return dict(pairs)


def _json_body(request, *, allowed_fields: set[str]) -> tuple[dict | None, JsonResponse | None]:
    if not str(request.content_type or "").lower().startswith("application/json"):
        return None, _error("content_type_invalido", "Envie application/json.", 415)
    try:
        body = json.loads(request.body.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, ValueError):
        return None, _error("json_invalido", "Corpo JSON inválido.", 400)
    if not isinstance(body, dict):
        return None, _error("json_invalido", "O corpo deve ser um objeto JSON.", 400)
    fields = {str(key).strip().lower() for key in body}
    if fields & _PASSWORD_FIELDS:
        return None, _error("campo_proibido", "Credenciais não são aceitas nesta API; a autenticação é feita no AUTH01.", 400)
    if fields & _MAC_FIELDS:
        return None, _error("mac_nao_permitido", "O MAC não deve ser enviado; o MoonShield o resolve pela própria rede.", 400)
    if set(body) - allowed_fields:
        return None, _error("campo_invalido", "A requisição possui campos não permitidos.", 400)
    return body, None


@csrf_exempt
def authorize(request):
    if request.method != "POST":
        return _error("metodo_nao_permitido", "Use POST.", 405)
    if error := _authenticate(request):
        return error
    body, error = _json_body(request, allowed_fields={"username", "ip_address"})
    if error:
        return error
    try:
        result = authorize_device(body.get("username"), body.get("ip_address"))
    except WifiAuthorizationError as exc:
        return _error(exc.code, str(exc), exc.status)
    return JsonResponse({"ok": True, **{key: value for key, value in result.items() if key != "authorization"}})


@csrf_exempt
def revoke(request):
    if request.method != "POST":
        return _error("metodo_nao_permitido", "Use POST.", 405)
    if error := _authenticate(request):
        return error
    body, error = _json_body(request, allowed_fields={"ip_address", "authorization_id", "revoked_reason"})
    if error:
        return error
    try:
        authorization = revoke_device(
            ip_address=body.get("ip_address"),
            authorization_id=body.get("authorization_id"),
            reason=body.get("revoked_reason", ""),
        )
    except WifiAuthorizationError as exc:
        return _error(exc.code, str(exc), exc.status)
    return JsonResponse({"ok": True, "authorization_id": authorization.pk, "revoked": True})


def status(request):
    if request.method != "GET":
        return _error("metodo_nao_permitido", "Use GET.", 405)
    if error := _authenticate(request):
        return error
    ip_address = request.GET.get("ip_address")
    try:
        mac_address = resolve_mac(ip_address)
    except MacResolutionError as exc:
        return _error(exc.code, str(exc), 400 if exc.code == "ip_invalido" else 404)
    trusted = WifiTrustedDevice.objects.filter(mac_address=mac_address, active=True).exists()
    authorization = WifiAuthorization.objects.filter(mac_address=mac_address).order_by("-authorized_at", "-pk").first()
    if not trusted and authorization is None:
        return _error("autorizacao_nao_encontrada", "Nenhuma autorização encontrada para este dispositivo.", 404)
    login_active = bool(authorization and authorization.active and authorization.ip_address == str(ipaddress.ip_address(ip_address)))
    return JsonResponse({
        "ok": True,
        "username": authorization.username if authorization else None,
        "ip_address": str(ipaddress.ip_address(ip_address)),
        "mac_address": mac_address,
        "active": bool(trusted or login_active),
        "trusted": trusted,
        "authorized_at": authorization.authorized_at.isoformat() if authorization else None,
        "expires_at": authorization.expires_at.isoformat() if authorization and authorization.expires_at else None,
        "last_seen_at": authorization.last_seen_at.isoformat() if authorization and authorization.last_seen_at else None,
    })
