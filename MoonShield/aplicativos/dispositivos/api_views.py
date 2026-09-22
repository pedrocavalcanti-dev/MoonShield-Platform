"""APIs autenticadas do inventário persistente de Dispositivos."""
from __future__ import annotations

import json
import logging

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_GET, require_POST

from .models import Dispositivo
from .monitoring import monitor_config, save_monitor_config
from rede.services.agent_client import requisitar_agent
from .services import (
    DiscoveryValidationError,
    executar_scan,
    marcar_inventario_stale,
    redes_elegiveis,
    serializar_dispositivo,
    validar_custom_name,
)

logger = logging.getLogger(__name__)


def _json_body(request):
    try:
        body = json.loads(request.body.decode("utf-8") or "{}")
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise DiscoveryValidationError("Corpo JSON inválido.")
    if not isinstance(body, dict):
        raise DiscoveryValidationError("O corpo deve ser um objeto JSON.")
    return body


@require_GET
@login_required(login_url="autenticacao:login")
def get_inventory(request):
    marcar_inventario_stale()
    devices = Dispositivo.objects.order_by("-last_seen", "current_ip", "pk")
    return JsonResponse({
        "ok": True,
        "source": "postgresql",
        "devices": [serializar_dispositivo(device) for device in devices],
    })


@require_GET
@login_required(login_url="autenticacao:login")
def networks(request):
    capabilities = {"advanced": False, "reason": "Nmap não verificado."}
    try:
        capabilities = requisitar_agent("devices.capabilities", {}, timeout=3)
        if not capabilities.get("advanced"):
            capabilities.setdefault("reason", "Nmap não instalado.")
    except Exception:
        pass
    return JsonResponse({"ok": True, "networks": redes_elegiveis(), "monitor": monitor_config(), "capabilities": capabilities})


@require_POST
@login_required(login_url="autenticacao:login")
def network_scan(request):
    network_ids: list[str] = []
    try:
        body = _json_body(request)
        if set(body) - {"networks", "mode"}:
            raise DiscoveryValidationError("CIDR livre não é aceito; informe somente IDs de redes oficiais.")
        if isinstance(body.get("networks"), list):
            network_ids = [item for item in body["networks"] if isinstance(item, str)][:8]
        result = executar_scan(body.get("networks"), mode=body.get("mode", "quick"))
    except DiscoveryValidationError as exc:
        status = 409 if "em andamento" in str(exc).lower() else 400
        return JsonResponse({"ok": False, "error": str(exc)}, status=status)
    except Exception as exc:
        logger.exception(
            "devices.scan falhou | networks=%s tipo=%s",
            network_ids,
            type(exc).__name__,
        )
        return JsonResponse({"ok": False, "error": "Não foi possível concluir o discovery pelo MoonShield Agent."}, status=502)
    result["devices"] = [serializar_dispositivo(device) for device in Dispositivo.objects.order_by("-last_seen", "current_ip", "pk")]
    return JsonResponse(result, status=200 if result["ok"] else 207)


@require_POST
@login_required(login_url="autenticacao:login")
def rename_device(request):
    try:
        body = _json_body(request)
        device_id = int(body.get("device_id"))
        name = validar_custom_name(body.get("new_name"))
        device = Dispositivo.objects.get(pk=device_id)
    except (TypeError, ValueError, Dispositivo.DoesNotExist, DiscoveryValidationError) as exc:
        return JsonResponse({"ok": False, "error": str(exc) or "Dispositivo ou nome inválido."}, status=400)
    device.custom_name = name
    device.save(update_fields=["custom_name"])
    return JsonResponse({"ok": True, "device": serializar_dispositivo(device)})


@require_POST
@login_required(login_url="autenticacao:login")
def save_monitor(request):
    try:
        result = save_monitor_config(_json_body(request))
    except DiscoveryValidationError as exc:
        return JsonResponse({"ok": False, "error": str(exc)}, status=400)
    return JsonResponse({"ok": True, "monitor": result})
