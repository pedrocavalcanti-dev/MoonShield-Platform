from __future__ import annotations

import json

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, render
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_GET, require_POST

from .models import WifiAuthorization, WifiTrustedDevice, normalize_mac
from .services.authorization import WifiAuthorizationError, revoke
from .services.firewall import sync_authorizations


def _json_body(request) -> dict:
    try:
        body = json.loads(request.body.decode("utf-8") or "{}")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Corpo JSON inválido.") from exc
    if not isinstance(body, dict):
        raise ValueError("O corpo deve ser um objeto JSON.")
    return body


def _trusted_payload(device: WifiTrustedDevice) -> dict:
    return {
        "id": device.pk,
        "name": device.nome,
        "mac_address": device.mac_address,
        "ip_address": device.ip_address,
        "description": device.descricao,
        "active": device.active,
        "created_at": device.created_at.isoformat(),
        "updated_at": device.updated_at.isoformat(),
    }


def _authorization_payload(authorization: WifiAuthorization) -> dict:
    return {
        "id": authorization.pk,
        "username": authorization.username,
        "ip_address": authorization.ip_address,
        "mac_address": authorization.mac_address,
        "active": authorization.active,
        "authorized_at": authorization.authorized_at.isoformat(),
        "expires_at": authorization.expires_at.isoformat() if authorization.expires_at else None,
        "last_seen_at": authorization.last_seen_at.isoformat() if authorization.last_seen_at else None,
        "revoked_at": authorization.revoked_at.isoformat() if authorization.revoked_at else None,
        "revoked_reason": authorization.revoked_reason,
    }


@ensure_csrf_cookie
@login_required(login_url="autenticacao:login")
def panel(request):
    return render(request, "wifi/painel.html")


@require_GET
@login_required(login_url="autenticacao:login")
def panel_state(request):
    trusted = WifiTrustedDevice.objects.order_by("nome", "pk")
    authorizations = WifiAuthorization.objects.order_by("-authorized_at", "-pk")
    return JsonResponse({
        "ok": True,
        "trusted_devices": [_trusted_payload(item) for item in trusted],
        "authorizations": [_authorization_payload(item) for item in authorizations],
        "counts": {
            "trusted": trusted.filter(active=True).count(),
            "authorized": authorizations.filter(active=True).count(),
        },
    })


@require_POST
@login_required(login_url="autenticacao:login")
def trusted_devices(request):
    try:
        body = _json_body(request)
        if set(body) - {"name", "mac_address", "ip_address", "description"}:
            raise ValueError("Campos não permitidos.")
        device = WifiTrustedDevice(
            nome=str(body.get("name") or "").strip(),
            mac_address=normalize_mac(body.get("mac_address")),
            ip_address=body.get("ip_address") or None,
            descricao=str(body.get("description") or "").strip(),
        )
        device.full_clean()
        device.save()
        if device.ip_address:
            result = sync_authorizations()
            if not result.get("ok"):
                device.delete()
                return JsonResponse({"ok": False, "codigo": result.get("codigo"), "error": result.get("erro")}, status=503)
    except Exception as exc:
        return JsonResponse({"ok": False, "error": str(exc)}, status=400)
    return JsonResponse({"ok": True, "device": _trusted_payload(device)}, status=201)


@require_POST
@login_required(login_url="autenticacao:login")
def trusted_device_detail(request, device_id: int):
    device = get_object_or_404(WifiTrustedDevice, pk=device_id)
    try:
        body = _json_body(request)
        if set(body) - {"name", "mac_address", "ip_address", "description", "active"}:
            raise ValueError("Campos não permitidos.")
        for field, key in (("nome", "name"), ("descricao", "description"), ("ip_address", "ip_address")):
            if key in body:
                setattr(device, field, (str(body[key]).strip() if body[key] is not None else None))
        if "mac_address" in body:
            device.mac_address = normalize_mac(body["mac_address"])
        if "active" in body:
            if type(body["active"]) is not bool:
                raise ValueError("active deve ser booleano.")
            device.active = body["active"]
        device.full_clean()
        original = WifiTrustedDevice.objects.get(pk=device.pk)
        device.save()
        result = sync_authorizations()
        if not result.get("ok"):
            original.save()
            return JsonResponse({"ok": False, "codigo": result.get("codigo"), "error": result.get("erro")}, status=503)
    except Exception as exc:
        return JsonResponse({"ok": False, "error": str(exc)}, status=400)
    return JsonResponse({"ok": True, "device": _trusted_payload(device)})


@require_POST
@login_required(login_url="autenticacao:login")
def deactivate_trusted_device(request, device_id: int):
    device = get_object_or_404(WifiTrustedDevice, pk=device_id)
    if not device.active:
        return JsonResponse({"ok": True, "device": _trusted_payload(device)})
    device.active = False
    device.save(update_fields=["active", "updated_at"])
    result = sync_authorizations()
    if not result.get("ok"):
        device.active = True
        device.save(update_fields=["active", "updated_at"])
        return JsonResponse({"ok": False, "codigo": result.get("codigo"), "error": result.get("erro")}, status=503)
    return JsonResponse({"ok": True, "device": _trusted_payload(device)})


@require_POST
@login_required(login_url="autenticacao:login")
def revoke_authorization(request, authorization_id: int):
    try:
        body = _json_body(request)
        if set(body) - {"revoked_reason"}:
            raise ValueError("Campos não permitidos.")
        authorization = revoke(authorization_id=authorization_id, reason=body.get("revoked_reason", ""))
    except WifiAuthorizationError as exc:
        return JsonResponse({"ok": False, "codigo": exc.code, "error": str(exc)}, status=exc.status)
    except Exception as exc:
        return JsonResponse({"ok": False, "error": str(exc)}, status=400)
    return JsonResponse({"ok": True, "authorization": _authorization_payload(authorization)})


@require_POST
@login_required(login_url="autenticacao:login")
def bulk_trusted_devices(request):
    from django.core.exceptions import ValidationError
    from django.db import transaction
    try:
        body = _json_body(request)
        devices_data = body.get("devices")
        if not isinstance(devices_data, list):
            raise ValueError("O corpo deve conter uma lista 'devices'.")
        if len(devices_data) > 100:
            raise ValueError("O limite máximo é de 100 dispositivos por lote.")

        valid_devices = []
        macs_in_batch = set()

        for item in devices_data:
            if not isinstance(item, dict):
                raise ValueError("Cada dispositivo deve ser um objeto JSON.")
            if set(item) - {"name", "mac_address", "ip_address", "description"}:
                raise ValueError("Campos não permitidos encontrados em um ou mais dispositivos.")

        with transaction.atomic():
            for item in devices_data:
                try:
                    mac = normalize_mac(item.get("mac_address"))
                except ValidationError as e:
                    raise ValueError(f"MAC inválido: {item.get('mac_address')} - {e.messages[0]}")

                if mac in macs_in_batch:
                    raise ValueError(f"MAC duplicado no lote: {mac}")
                macs_in_batch.add(mac)

                if WifiTrustedDevice.objects.filter(mac_address=mac).exists():
                    raise ValueError(f"MAC já cadastrado no banco: {mac}")

                device = WifiTrustedDevice(
                    nome=str(item.get("name") or "").strip(),
                    mac_address=mac,
                    ip_address=item.get("ip_address") or None,
                    descricao=str(item.get("description") or "").strip(),
                )
                device.full_clean()
                device.save()
                valid_devices.append(device)

            if valid_devices:
                result = sync_authorizations()
                if not result.get("ok"):
                    raise RuntimeError(json.dumps({"ok": False, "codigo": result.get("codigo"), "error": result.get("erro")}))

    except RuntimeError as exc:
        try:
            err_data = json.loads(str(exc))
            return JsonResponse(err_data, status=503)
        except json.JSONDecodeError:
            return JsonResponse({"ok": False, "error": str(exc)}, status=503)
    except Exception as exc:
        return JsonResponse({"ok": False, "error": str(exc)}, status=400)

    return JsonResponse({
        "ok": True,
        "added": len(valid_devices),
        "devices": [_trusted_payload(d) for d in valid_devices]
    }, status=201)


@require_POST
@login_required(login_url="autenticacao:login")
def bulk_trusted_action(request):
    from django.db import transaction
    from django.utils import timezone
    try:
        body = _json_body(request)
        device_ids = body.get("device_ids")
        action = body.get("action")
        if not isinstance(device_ids, list) or action not in {"activate", "deactivate"}:
            raise ValueError("Parâmetros inválidos.")

        with transaction.atomic():
            devices = WifiTrustedDevice.objects.filter(pk__in=device_ids)
            devices.update(active=(action == "activate"), updated_at=timezone.now())

            result = sync_authorizations()
            if not result.get("ok"):
                raise RuntimeError(json.dumps({"ok": False, "codigo": result.get("codigo"), "error": result.get("erro")}))

    except RuntimeError as exc:
        try:
            err_data = json.loads(str(exc))
            return JsonResponse(err_data, status=503)
        except json.JSONDecodeError:
            return JsonResponse({"ok": False, "error": str(exc)}, status=503)
    except Exception as exc:
        return JsonResponse({"ok": False, "error": str(exc)}, status=400)

    return JsonResponse({"ok": True})


@require_GET
@login_required(login_url="autenticacao:login")
def diagnostics_data(request):
    from wifi_access.services.diagnostics import get_diagnostics
    return JsonResponse({"ok": True, "diagnostics": get_diagnostics()})


@require_POST
@ensure_csrf_cookie
@login_required(login_url="autenticacao:login")
def sync_now(request):
    from wifi_access.services.reconciliation import reconcile_wifi_access

    if not request.user.is_staff:
        return JsonResponse({"ok": False, "error": "Acesso negado."}, status=403)

    result = reconcile_wifi_access()
    return JsonResponse(result, status=200 if result.get("ok") else 503)
