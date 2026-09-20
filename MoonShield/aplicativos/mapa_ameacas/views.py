"""Endpoints do Mapa de Ameacas; todos usam eventos reais e contexto SOC."""

from __future__ import annotations

import ipaddress
import json
from datetime import timedelta

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.http import require_GET, require_POST

from configuracoes.models import ConfigSistema
from incidentes.services.contexto_rede import classificar_ip_rede

from .services import FeedNormalizer


_PERIODOS = {"1h": 1, "6h": 6, "24h": 24, "7d": 168, "30d": 720}
_FONTES = {"ids", "firewall", "dns"}
_SEVERIDADES = {"critical", "high", "medium", "low"}
_DIRECOES = {"internal", "inbound", "outbound", "external", "unknown"}


def _lista_filtro(request, name, allowed, default):
    raw = request.GET.get(name, "all")
    values = {value.strip().lower() for value in raw.split(",") if value.strip()}
    if not values or "all" in values:
        return default
    return sorted(values.intersection(allowed)) or default


def _parametros_feed(request):
    periodo = request.GET.get("period", "24h")
    horas = _PERIODOS.get(periodo, _PERIODOS["24h"])
    raw_limit = request.GET.get("limit", "200")
    try:
        limit = max(1, min(200, int(raw_limit)))
    except (TypeError, ValueError):
        limit = 200
    normalizer = FeedNormalizer(
        start_time=timezone.now() - timedelta(hours=horas),
        severities=_lista_filtro(request, "sev", _SEVERIDADES, list(_SEVERIDADES)),
        sources=_lista_filtro(request, "source", _FONTES, list(_FONTES)),
        category=request.GET.get("category"),
        country=request.GET.get("country"),
        query=(request.GET.get("query") or "")[:160],
        protocol=request.GET.get("protocol"),
        direction=request.GET.get("direction"),
        zone=request.GET.get("zone") or request.GET.get("role"),
    )
    return normalizer, horas, limit


def _node_payload():
    cfg = ConfigSistema.get_solo()
    return {
        "name": cfg.node_name,
        "cidr": cfg.cidr,
        "iface": cfg.iface_principal,
        "latitude": cfg.node_latitude,
        "longitude": cfg.node_longitude,
        "city": cfg.node_city,
        "country_code": cfg.node_country_code,
    }


def _overview_payload(normalizer, horas, limit):
    # Uma coleta unica mantem os contadores e facetas coerentes com o mesmo recorte.
    eventos_contexto = normalizer.get_all_events(max_limit=500)
    eventos_geo = [evento for evento in eventos_contexto if evento["has_geo"]][:limit]
    total = sum(evento["count"] for evento in eventos_contexto)
    criticos = sum(
        evento["count"] for evento in eventos_contexto if evento["severity"] == "critical"
    )
    geo_count = sum(evento["count"] for evento in eventos_contexto if evento["has_geo"])
    facets = normalizer.get_facets(eventos_contexto)
    top_country = (
        max(facets["countries"].items(), key=lambda item: item[1])[0]
        if facets["countries"]
        else None
    )
    return {
        "ok": True,
        "fonte": "local",
        "total": total,
        "kpis": {
            "events": total,
            "active": total,
            "critical": criticos,
            "geo_on_map": geo_count,
            "rate": round(total / max(1, horas * 60), 2),
            "top_country": top_country,
            "matched_total": total,
        },
        # Contrato do mapa: este feed nunca contem evento sem coordenada GeoIP valida.
        "events": eventos_geo,
        "facets": facets,
        "filter_facets": facets,
        "cursor": None,
        "config": {"trail_duration": 15000, "max_events": limit, "rot_speed": 0.05},
        "node": _node_payload(),
        "last_update": timezone.now().isoformat(),
        "source_health": normalizer.source_health,
    }


@login_required(login_url="autenticacao:login")
def mapa_view(request):
    return render(request, "mapa_ameacas/mapa.html", {
        "mapbox_token": getattr(settings, "MAPBOX_ACCESS_TOKEN", ""),
    })


@require_GET
@login_required(login_url="autenticacao:login")
def api_map_overview(request):
    normalizer, horas, limit = _parametros_feed(request)
    return JsonResponse(_overview_payload(normalizer, horas, limit))


@require_GET
@login_required(login_url="autenticacao:login")
def api_map_feed(request):
    """Feed explicito para paineis; geo_only=1 e o padrao seguro para o mapa."""
    normalizer, _, limit = _parametros_feed(request)
    geo_only = request.GET.get("geo_only", "1") != "0"
    eventos = normalizer.get_all_events(max_limit=500, geo_only=geo_only)[:limit]
    return JsonResponse({
        "ok": True,
        "events": eventos,
        "total": sum(evento["count"] for evento in eventos),
        "geo_only": geo_only,
        "source_health": normalizer.source_health,
        "last_update": timezone.now().isoformat(),
    })


@require_GET
@login_required(login_url="autenticacao:login")
def api_map_facets(request):
    normalizer, _, _ = _parametros_feed(request)
    eventos = normalizer.get_all_events(max_limit=500)
    return JsonResponse({
        "ok": True,
        "facets": normalizer.get_facets(eventos),
        "source_health": normalizer.source_health,
    })


@require_GET
@login_required(login_url="autenticacao:login")
def api_map_search(request):
    query = (request.GET.get("q") or request.GET.get("query") or "").strip()[:160]
    if not query:
        return JsonResponse({"ok": True, "query": "", "results": [], "total": 0})
    normalizer, _, limit = _parametros_feed(request)
    normalizer.query = query
    eventos = normalizer.get_all_events(max_limit=500)[:limit]
    results = [{"type": "event", **evento} for evento in eventos]
    try:
        ipaddress.ip_address(query)
    except ValueError:
        pass
    else:
        contexto = classificar_ip_rede(query)
        if not any(evento.get("src_ip") == query or evento.get("dst_ip") == query for evento in eventos):
            results.insert(0, {
                "type": "ip",
                "value": query,
                "has_geo": False,
                "scope": contexto["scope"],
                "role": contexto.get("role"),
                "geoip_allowed": contexto["geoip_allowed"],
            })
    return JsonResponse({
        "ok": True,
        "query": query,
        "results": results,
        "total": len(results),
        "source_health": normalizer.source_health,
    })


@require_POST
@login_required(login_url="autenticacao:login")
def api_set_location(request):
    try:
        data = json.loads(request.body.decode("utf-8"))
    except Exception:
        return JsonResponse({"ok": False, "erro": "JSON invalido"}, status=400)

    lat = data.get("latitude")
    lon = data.get("longitude")
    source = data.get("source", "unknown")

    if source not in ["manual", "browser", "config", "geoip", "unknown"]:
        return JsonResponse({"ok": False, "erro": "Source invalido"}, status=400)

    cfg = ConfigSistema.get_solo()
    cfg.node_latitude = lat
    cfg.node_longitude = lon
    cfg.node_location_source = source
    cfg.save()
    return JsonResponse({"ok": True})
