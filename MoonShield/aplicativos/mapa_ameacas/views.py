from datetime import datetime, timedelta

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_GET

from configuracoes.models import ConfigSistema
from incidentes.models import Incidente


@login_required(login_url="autenticacao:login")
def mapa_view(request):
    return render(request, "mapa_ameacas/mapa.html", {
        "mapbox_token": settings.MAPBOX_ACCESS_TOKEN,
    })


def _severidade_mapa(valor: str) -> str:
    return {
        "critico": "critical",
        "alto": "high",
        "medio": "medium",
    }.get(valor, "low")


@require_GET
@login_required(login_url="autenticacao:login")
def api_map_overview(request):
    periodo = request.GET.get("period", "24h")
    horas = {"1h": 1, "24h": 24, "7d": 168, "30d": 720}.get(periodo, 24)
    severidade = request.GET.get("sev", "all")
    desde = datetime.now().astimezone() - timedelta(hours=horas)
    incidentes = Incidente.objects.filter(last_seen__gte=desde).order_by("-last_seen")
    if severidade != "all":
        incidentes = incidentes.filter(severidade_jg=severidade)

    eventos = []
    for incidente in incidentes[:200]:
        if incidente.latitude is None or incidente.longitude is None:
            continue
        eventos.append({
            "id": str(incidente.pk),
            "timestamp": incidente.last_seen.strftime("%H:%M:%S"),
            "ts": incidente.last_seen.isoformat(),
            "source": "IDS",
            "severity": _severidade_mapa(incidente.severidade_jg),
            "type": incidente.categoria_jg or "evento",
            "src_ip": incidente.src_ip,
            "src_country": incidente.pais_codigo or "",
            "src_city": incidente.cidade or "",
            "src_lat": incidente.latitude,
            "src_lon": incidente.longitude,
            "dest_ip": incidente.dest_ip or "",
            "signature": incidente.titulo_jg or incidente.signature,
            "port": incidente.dest_porta,
            "proto": incidente.protocolo,
            "asn": incidente.asn or incidente.asn_org or "",
        })

    total = len(eventos)
    criticos = sum(evento["severity"] == "critical" for evento in eventos)
    top_country = next((evento["src_country"] for evento in eventos if evento["src_country"]), "--")
    cfg = ConfigSistema.get_solo()
    return JsonResponse({
        "ok": True,
        "mode": "real",
        "fonte": "local",
        "total": total,
        "kpis": {
            "active": total,
            "critical": criticos,
            "rate": 0,
            "top_country": top_country,
            "session_total": total,
        },
        "events": eventos,
        "config": {"trail_duration": 15000, "max_events": 200, "rot_speed": 0.05},
        "node": {"name": cfg.node_name, "cidr": cfg.cidr, "iface": cfg.iface_principal},
        "last_update": datetime.now().astimezone().isoformat(),
    })
