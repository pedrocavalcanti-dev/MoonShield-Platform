import time
from datetime import datetime, timedelta

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_GET
from autenticacao.models import UserProfile


def _overview_real(cfg):
    """Agrega somente contratos operacionais locais da appliance."""
    from configuracoes.views import _servicos, _topologia
    from dns.views import _get_adguard_client
    from incidentes.models import Incidente

    servicos = _servicos(cfg, _topologia())
    adguard = servicos["adguard"]
    suricata = servicos["suricata"]
    firewall = servicos["firewall"]
    dns = {"metrics": {}, "charts": {}}
    try:
        client = _get_adguard_client(cfg)
        if client:
            dns = client.fetch_all()
    except Exception:
        pass

    metrics = dns.get("metrics") or {}
    dns_charts = dns.get("charts") or {}
    agora = datetime.now()
    desde = agora - timedelta(hours=24)
    incidentes = Incidente.objects.filter(last_seen__gte=desde).order_by("-last_seen")
    ameaças = incidentes.count()
    severidades = {
        "crit": incidentes.filter(severidade_jg="critico").count(),
        "high": incidentes.filter(severidade_jg="alto").count(),
        "med": incidentes.filter(severidade_jg="medio").count(),
    }
    hours = list(dns_charts.get("hours") or _hour_labels())
    zeros = [0] * len(hours)
    feed = [
        {
            "ts": item.last_seen.isoformat(), "type": "IDS", "sev": {
                "critico": "crit", "alto": "high", "medio": "warn",
            }.get(item.severidade_jg, "info"),
            "src": getattr(item, "src_ip", None) or "—",
            "msg": getattr(item, "titulo_jg", None) or getattr(item, "signature", None) or "Incidente",
        }
        for item in incidentes[:20]
    ]
    sensores = (adguard, suricata, firewall)
    return {
        "ok": True,
        "mode": "real",
        "fonte": "local",
        "kpis": {
            "ameacas_hoje": ameaças,
            "dns_queries": int(metrics.get("queries", 0) or 0),
            "dns_bloqueios": int(metrics.get("bloqueios", 0) or 0),
            "sensores_online": sum(bool(item.get("saudavel")) for item in sensores),
            "sensores_total": 3,
            "bloqueio_pct": float(metrics.get("pctBloq", 0) or 0),
        },
        "charts": {
            "hours": hours,
            "attacks": {key: [value if index == len(hours) - 1 else 0 for index in range(len(hours))] for key, value in severidades.items()},
            "dns": {"queries": list(dns_charts.get("queries") or zeros), "blocked": list(dns_charts.get("bloqueios") or zeros)},
        },
        "feed": feed,
        "map": {"active": 0, "events": []},
        "intel": {"origens": [], "ataques": []},
        "infra": {
            "dispositivos": {"online": 0, "offline": 0, "novo_hoje": 0, "pct": 0},
            "firewall": {"drops": 0, "top_porta": "—", "blocks": 0, "pct": 0},
            "dns_infra": {"bloqueio_pct": float(metrics.get("pctBloq", 0) or 0), "clientes": int(metrics.get("clientes", 0) or 0), "ameacas": ameaças, "bloqueios": int(metrics.get("bloqueios", 0) or 0), "permitidos": max(0, int(metrics.get("queries", 0) or 0) - int(metrics.get("bloqueios", 0) or 0))},
        },
        "saude": {"dns": adguard, "ids": suricata, "firewall": firewall},
        "node": {"name": getattr(cfg, "node_name", "—") if cfg else "—", "cidr": "—", "iface": "—"},
        "last_update": agora.isoformat(),
    }

try:
    from configuracoes.models import ConfigSistema
except ImportError:
    ConfigSistema = None

# Guarda o momento em que o processo subiu (para calcular uptime)
_BOOT_TIME = time.time()


# ─────────────────────────────────────────────────────────────────────────────
# HELPER — obtém config sem explodir se tabela não existir
# ─────────────────────────────────────────────────────────────────────────────

def _get_cfg():
    if ConfigSistema is None:
        return None
    try:
        if hasattr(ConfigSistema, "get_solo"):
            return ConfigSistema.get_solo()
        return ConfigSistema.objects.first()
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# PÁGINA PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

@login_required(login_url="autenticacao:login")
def index(request):
    profile, _ = UserProfile.objects.get_or_create(user=request.user)

    # True apenas na primeira carga após login — pop() consome e nunca repete
    mostrar_boasvindas = request.session.pop("mostrar_boasvindas", False)

    return render(request, "painel/dashboard.html", {
        "profile":            profile,
        "mostrar_boasvindas": mostrar_boasvindas,
    })


# ─────────────────────────────────────────────────────────────────────────────
# GET /painel/api/overview/   (e alias /api/overview/)
# ─────────────────────────────────────────────────────────────────────────────

@require_GET
@login_required(login_url="autenticacao:login")
def api_overview(request):
    return JsonResponse(_overview_real(_get_cfg()))
# ─────────────────────────────────────────────────────────────────────────────
# GET /api/sensores/   ← topbar.js
# ─────────────────────────────────────────────────────────────────────────────

@require_GET
@login_required(login_url="autenticacao:login")
def api_sensores(request):
    dados = _overview_real(_get_cfg())["saude"]
    return JsonResponse({
        "ids": "ok" if dados["ids"].get("saudavel") else "offline",
        "dns": "ok" if dados["dns"].get("saudavel") else "offline",
        "firewall": "ok" if dados["firewall"].get("saudavel") else "offline",
    })


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/badges/   ← sidebar.js
# ─────────────────────────────────────────────────────────────────────────────

@login_required(login_url="autenticacao:login")
@require_GET
def api_badges(request):
    return JsonResponse({
        "incidentes": 0,
        "alertas":    0,
        "mensagens":  0
    })


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/uptime/   ← footer.js
# ─────────────────────────────────────────────────────────────────────────────

@require_GET
@login_required(login_url="autenticacao:login")
def api_uptime(request):
    uptime_seconds = int(time.time() - _BOOT_TIME)
    return JsonResponse({"uptime_seconds": uptime_seconds, "ok": True})


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/alertas/         ← notificacoes.js (lista completa)
# GET /api/alertas/count/   ← notificacoes.js (só a contagem)
# ─────────────────────────────────────────────────────────────────────────────

@require_GET
@login_required(login_url="autenticacao:login")
def api_alertas(request):
    from incidentes.models import Incidente

    alertas = [
        {
            "id": incidente.pk,
            "titulo": getattr(incidente, "titulo_jg", None) or getattr(incidente, "signature", None) or "Incidente",
            "descricao": getattr(incidente, "src_ip", None) or "Evento detectado pelo Suricata",
            "severidade": getattr(incidente, "severidade_jg", "medio"),
            "tipo": "ids",
            "timestamp": incidente.last_seen.isoformat(),
            "url": "/incidentes/",
        }
        for incidente in Incidente.objects.order_by("-last_seen")[:20]
    ]
    return JsonResponse(alertas, safe=False)


@require_GET
@login_required(login_url="autenticacao:login")
def api_alertas_count(request):
    from incidentes.models import Incidente

    return JsonResponse({"count": Incidente.objects.count(), "ok": True})


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _hour_labels():
    now = datetime.now()
    return [f"{(now.hour - 23 + i) % 24:02d}h" for i in range(24)]


def _rarr(n, a, b):
    return [random.randint(a, b) for _ in range(n)]


def _demo_overview(cfg, period, sev):
    mult = {"1h": 0.15, "24h": 1, "7d": 4.5, "30d": 18}.get(period, 1)

    hours = _hour_labels()
    crit  = _rarr(24, 0,   int(4  * mult))
    high  = _rarr(24, 1,   int(7  * mult))
    med   = _rarr(24, 2,   int(12 * mult))
    dns   = _rarr(24, 400, int(2400 * max(mult, 1)))
    bloq  = _rarr(24, 20,  int(320  * max(mult, 1)))

    total_ameacas = sum(crit) + sum(high) + sum(med)
    total_dns     = sum(dns)
    total_bloq    = sum(bloq)
    bloqueio_pct  = round((total_bloq / total_dns * 100) if total_dns else 0, 1)

    dev_online  = random.randint(10, 15)
    dev_offline = random.randint(1, 3)
    dev_total   = dev_online + dev_offline
    dev_pct     = round(dev_online / dev_total * 100, 1)

    fw_drops  = random.randint(900, 1800)
    fw_blocks = random.randint(5, 14)

    feed_templates = [
        {"sev": "crit", "type": "IDS",  "src": "45.88.12.3",    "msg": "ET SCAN SSH Brute Force (SID 2001219)"},
        {"sev": "high", "type": "IDS",  "src": "91.108.4.1",    "msg": "ET SCAN Nmap OS Detection"},
        {"sev": "crit", "type": "FW",   "src": "45.88.12.3",    "msg": "Porta 22 — TCP DROP INPUT"},
        {"sev": "warn", "type": "DNS",  "src": "10.0.0.21",     "msg": "malware-tracker.ru (Blocklist)"},
        {"sev": "warn", "type": "DNS",  "src": "10.0.0.5",      "msg": "tracking-domain.xyz (OISD)"},
        {"sev": "info", "type": "DEV",  "src": "10.0.0.101",    "msg": "Novo dispositivo detectado"},
        {"sev": "high", "type": "IDS",  "src": "104.21.8.99",   "msg": "ET DROP Known Compromised IP"},
        {"sev": "info", "type": "DNS",  "src": "10.0.0.5",      "msg": "google.com · 8 queries/min"},
        {"sev": "warn", "type": "FW",   "src": "185.220.10.2",  "msg": "Porta 3389 — RDP block"},
        {"sev": "crit", "type": "IDS",  "src": "185.220.101.5", "msg": "ET SCAN Nmap SYN Scan"},
        {"sev": "high", "type": "FW",   "src": "104.21.8.99",   "msg": "Multi-porta · UDP flood"},
        {"sev": "info", "type": "DEV",  "src": "10.0.0.77",     "msg": "Samsung TV · heartbeat OK"},
    ]
    feed = [
        {**random.choice(feed_templates), "ts": datetime.now().isoformat()}
        for _ in range(14)
    ]

    origens = [
        {"rank": 1, "flag": "🇨🇳", "pais": "China",    "count": random.randint(5, 9),  "pct": 80, "color": "#ef4444"},
        {"rank": 2, "flag": "🇷🇺", "pais": "Rússia",   "count": random.randint(3, 6),  "pct": 55, "color": "#f97316"},
        {"rank": 3, "flag": "🇺🇸", "pais": "EUA",      "count": random.randint(2, 4),  "pct": 40, "color": "#eab308"},
        {"rank": 4, "flag": "🇳🇱", "pais": "Holanda",  "count": random.randint(1, 3),  "pct": 26, "color": "#6b7280"},
        {"rank": 5, "flag": "🇩🇪", "pais": "Alemanha", "count": random.randint(1, 2),  "pct": 14, "color": "#4b5563"},
    ]

    ataques = [
        {"icon": "shield", "nome": "ET SCAN SSH Brute",   "sub": "Porta 22 · TCP",    "sev": "crit", "count": 7},
        {"icon": "search", "nome": "ET SCAN Nmap SYN",    "sub": "TCP · Multi-porta", "sev": "high", "count": 4},
        {"icon": "globe",  "nome": "DNS Malware Tracker", "sub": "malware-track.ru",  "sev": "high", "count": 3},
        {"icon": "pulse",  "nome": "Port Scan Detectado", "sub": "UDP · Multi-porta", "sev": "med",  "count": 2},
    ]

    return {
        "ok":   True,
        "mode": "demo",
        "providers": {"dns": True, "ids": True, "fw": True},
        "kpis": {
            "ameacas_hoje":    total_ameacas,
            "dns_queries":     total_dns,
            "dns_bloqueios":   total_bloq,
            "sensores_online": 2,
            "sensores_total":  3,
            "bloqueio_pct":    bloqueio_pct,
        },
        "charts": {
            "hours":   hours,
            "attacks": {"crit": crit, "high": high, "med": med},
            "dns":     {"queries": dns, "blocked": bloq},
        },
        "feed":  feed,
        "map":   {"active": random.randint(8, 14), "events": []},
        "intel": {"origens": origens, "ataques": ataques},
        "infra": {
            "dispositivos": {
                "online":    dev_online,
                "offline":   dev_offline,
                "novo_hoje": random.randint(0, 2),
                "pct":       dev_pct,
            },
            "firewall": {
                "drops":     fw_drops,
                "top_porta": 22,
                "blocks":    fw_blocks,
                "pct":       62,
            },
            "dns_infra": {
                "bloqueio_pct": bloqueio_pct,
                "clientes":     random.randint(6, 12),
                "ameacas":      random.randint(1, 5),
                "bloqueios":    total_bloq,
                "permitidos":   total_dns - total_bloq,
            },
        },
        "node": {
            "name":  getattr(cfg, "node_name",       "JG-DEMO")        if cfg else "JG-DEMO",
            "cidr":  getattr(cfg, "cidr",             "192.168.0.0/24") if cfg else "192.168.0.0/24",
            "iface": getattr(cfg, "iface_principal",  "Ethernet")       if cfg else "Ethernet",
        },
        "last_update": datetime.now().isoformat(),
    }
