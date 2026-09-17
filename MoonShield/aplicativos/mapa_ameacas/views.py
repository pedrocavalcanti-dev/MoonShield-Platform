import json
from django.utils import timezone
from datetime import timedelta
from django.http import JsonResponse
from django.conf import settings
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST, require_GET
from configuracoes.models import ConfigSistema
from .services import FeedNormalizer

@login_required(login_url="autenticacao:login")
def mapa_view(request):
    return render(request, "mapa_ameacas/mapa.html", {
        "mapbox_token": getattr(settings, "MAPBOX_ACCESS_TOKEN", ""),
    })

@require_GET
@login_required(login_url="autenticacao:login")
def api_map_overview(request):
    periodo = request.GET.get("period", "24h")
    horas = {"1h": 1, "24h": 24, "7d": 168, "30d": 720}.get(periodo, 24)
    sev_filter = request.GET.get("sev", "all")
    source_filter = request.GET.get("source", "all")

    desde = timezone.now() - timedelta(hours=horas)

    severities = [sev_filter] if sev_filter != 'all' else ['critical', 'high', 'medium', 'low', 'info']
    sources = [source_filter] if source_filter != 'all' else ['ids', 'firewall', 'dns']
    category = request.GET.get('category')
    country = request.GET.get('country')
    query = request.GET.get('query')

    normalizer = FeedNormalizer(start_time=desde, severities=severities, sources=sources, category=category, country=country, query=query)

    raw_limit = request.GET.get('limit', '200')
    try:
        max_events = int(raw_limit)
        max_events = max(1, min(200, max_events))
    except (ValueError, TypeError):
        max_events = 200

    eventos = normalizer.get_all_events(max_limit=max_events)

    total = sum(e['count'] for e in eventos)
    criticos = sum(e['count'] for e in eventos if e['severity'] == "critical")

    facets = {
        "categories": {},
        "countries": {},
        "sources": {}
    }
    for e in eventos:
        cat = e.get('category') or 'other'
        src = e.get('source') or 'unknown'
        facets['categories'][cat] = facets['categories'].get(cat, 0) + e['count']
        facets['sources'][src] = facets['sources'].get(src, 0) + e['count']

        if e.get('external_geo', {}).get('geolocatable'):
            c = e['external_geo'].get('country_code')
            if c:
                facets['countries'][c] = facets['countries'].get(c, 0) + e['count']

    top_country = max(facets['countries'].items(), key=lambda x: x[1])[0] if facets['countries'] else "--"

    cfg = ConfigSistema.get_solo()

    # KPIs baseados na janela solicitada
    rate = total / max(1, (horas * 60))

    return JsonResponse({
        "ok": True,
        "mode": "real",
        "fonte": "local",
        "total": len(eventos),
        "kpis": {
            "active": len(eventos),
            "critical": criticos,
            "rate": round(rate, 2),
            "top_country": top_country,
            "matched_total": total,
        },
        "events": eventos,
        "facets": facets,
        "cursor": None,
        "config": {"trail_duration": 15000, "max_events": max_events, "rot_speed": 0.05},
        "node": {
            "name": cfg.node_name,
            "cidr": cfg.cidr,
            "iface": cfg.iface_principal,
            "latitude": cfg.node_latitude,
            "longitude": cfg.node_longitude,
            "city": cfg.node_city,
            "country_code": cfg.node_country_code
        },
        "last_update": timezone.now().isoformat(),
        "source_health": normalizer.source_health
    })

@require_POST
@login_required(login_url="autenticacao:login")
def api_set_location(request):
    try:
        data = json.loads(request.body.decode("utf-8"))
    except Exception:
        return JsonResponse({"ok": False, "erro": "JSON inválido"}, status=400)

    lat = data.get("latitude")
    lon = data.get("longitude")
    source = data.get("source", "unknown")

    if source not in ['manual', 'browser', 'config', 'geoip', 'unknown']:
        return JsonResponse({"ok": False, "erro": "Source inválido"}, status=400)

    cfg = ConfigSistema.get_solo()
    cfg.node_latitude = lat
    cfg.node_longitude = lon
    cfg.node_location_source = source
    cfg.save()
    return JsonResponse({"ok": True})
