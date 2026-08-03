import random
import time
from datetime import datetime

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_GET
from autenticacao.models import UserProfile

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
    period = request.GET.get("period", "24h")
    sev    = request.GET.get("sev",    "all")

    cfg  = _get_cfg()
    modo = getattr(cfg, "modo", "demo") if cfg else "demo"

    if modo == "demo":
        return JsonResponse(_demo_overview(cfg, period, sev))

    # ── PROD ──────────────────────────────────────────────────────────────────
    return JsonResponse({
        "ok":   True,
        "mode": "prod",
        "providers": {
            "dns": bool(cfg and getattr(cfg, "dns_enabled", False) and getattr(cfg, "adguard_mode", "mock") != "mock"),
            "ids": bool(cfg and getattr(cfg, "ids_enabled", False) and getattr(cfg, "suricata_mode", "mock") != "mock"),
            "fw":  bool(cfg and getattr(cfg, "fw_enabled",  False) and getattr(cfg, "fw_mode", "mock") != "mock"),
        },
        "kpis": {
            "ameacas_hoje":    0,
            "dns_queries":     0,
            "dns_bloqueios":   0,
            "sensores_online": 0,
            "sensores_total":  3,
            "bloqueio_pct":    0,
        },
        "charts": {
            "hours":   _hour_labels(),
            "attacks": {"crit": [0]*24, "high": [0]*24, "med": [0]*24},
            "dns":     {"queries": [0]*24, "blocked": [0]*24},
        },
        "feed":   [],
        "map":    {"active": 0, "events": []},
        "intel":  {"origens": [], "ataques": []},
        "infra": {
            "dispositivos": {"online": 0, "offline": 0, "novo_hoje": 0, "pct": 0},
            "firewall":     {"drops": 0, "top_porta": 0, "blocks": 0, "pct": 0},
            "dns_infra":    {"bloqueio_pct": 0, "clientes": 0, "ameacas": 0,
                             "bloqueios": 0, "permitidos": 0},
        },
        "node": {
            "name":  getattr(cfg, "node_name",      "—") if cfg else "—",
            "cidr":  getattr(cfg, "cidr",            "—") if cfg else "—",
            "iface": getattr(cfg, "iface_principal", "—") if cfg else "—",
        },
        "last_update": datetime.now().isoformat(),
        "msg": "PROD ativo — aguardando integração dos coletores reais.",
    })


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/sensores/   ← topbar.js
# ─────────────────────────────────────────────────────────────────────────────

@require_GET
@login_required(login_url="autenticacao:login")
def api_sensores(request):
    cfg  = _get_cfg()
    modo = getattr(cfg, "modo", "demo") if cfg else "demo"

    if modo == "demo":
        return JsonResponse({"ids": "ok", "dns": "ok", "firewall": "warn"})

    return JsonResponse({
        "ids":      "ok" if (cfg and getattr(cfg, "ids_enabled", False)) else "off",
        "dns":      "ok" if (cfg and getattr(cfg, "dns_enabled", False)) else "off",
        "firewall": "ok" if (cfg and getattr(cfg, "fw_enabled",  False)) else "off",
    })


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/badges/   ← sidebar.js
# ─────────────────────────────────────────────────────────────────────────────

@require_GET
@login_required(login_url="autenticacao:login")
def api_badges(request):
    cfg  = _get_cfg()
    modo = getattr(cfg, "modo", "demo") if cfg else "demo"

    if modo == "demo":
        return JsonResponse({
            "incidentes": random.randint(0, 5),
            "mapa":       random.randint(0, 12),
            "firewall":   random.randint(0, 3),
        })

    return JsonResponse({"incidentes": 0, "mapa": 0, "firewall": 0})


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
    cfg  = _get_cfg()
    modo = getattr(cfg, "modo", "demo") if cfg else "demo"

    if modo == "demo":
        now = datetime.now()

        def ts(minutes_ago):
            from datetime import timedelta
            return (now - timedelta(minutes=minutes_ago)).isoformat()

        alertas = [
            {
                "id": 1,
                "titulo": "Port Scan Detectado",
                "descricao": "192.168.1.45 → 22/80/443 (Suricata SID:2000001)",
                "severidade": "critico",
                "tipo": "scan",
                "timestamp": ts(3),
                "url": "/incidentes/",
            },
            {
                "id": 2,
                "titulo": "DNS Blocklist Hit",
                "descricao": "malware-tracker.ru bloqueado via AdGuard",
                "severidade": "alto",
                "tipo": "dns",
                "timestamp": ts(10),
                "url": "/dns/",
            },
            {
                "id": 3,
                "titulo": "Tentativa SSH Brute Force",
                "descricao": "47.89.12.3 — 23 tentativas em 60s",
                "severidade": "critico",
                "tipo": "ids",
                "timestamp": ts(15),
                "url": "/incidentes/",
            },
        ]
        return JsonResponse(alertas, safe=False)

    return JsonResponse([], safe=False)


@require_GET
@login_required(login_url="autenticacao:login")
def api_alertas_count(request):
    cfg  = _get_cfg()
    modo = getattr(cfg, "modo", "demo") if cfg else "demo"

    if modo == "demo":
        return JsonResponse({"count": random.randint(1, 5), "ok": True})

    return JsonResponse({"count": 0, "ok": True})


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