import random
from datetime import datetime

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_GET

try:
    from configuracoes.models import ConfigSistema
except ImportError:
    ConfigSistema = None

# ─────────────────────────────────────────────────────────────────────────────
# PÁGINA PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────
@login_required(login_url='autenticacao:login')
def mapa_view(request):
    return render(request, 'mapa_ameacas/mapa.html', {
        'mapbox_token': settings.MAPBOX_ACCESS_TOKEN
    })

# ─────────────────────────────────────────────────────────────────────────────
# API: GET /mapa/api/overview/
# ─────────────────────────────────────────────────────────────────────────────
@require_GET
@login_required(login_url='autenticacao:login')
def api_map_overview(request):
    period = request.GET.get("period", "24h")
    sev    = request.GET.get("sev", "all")

    cfg  = ConfigSistema.get_solo() if ConfigSistema else None
    modo = cfg.modo if cfg else "demo"

    if modo == "demo":
        return JsonResponse(_demo_map_overview(cfg, period, sev))

    # ── PROD ─────────────────────────────────────────────────────────────────
    return JsonResponse({
        "ok": True,
        "mode": "prod",
        "providers": {
            "ids": bool(cfg and cfg.ids_enabled),
            "fw":  bool(cfg and cfg.fw_enabled),
            "dns": bool(cfg and cfg.dns_enabled)
        },
        "kpis": {"active": 0, "critical": 0, "rate": 0, "top_country": "--", "session_total": 0},
        "events": [],
        "config": {"trail_duration": 15000, "max_events": 200, "rot_speed": 0.05},
        "node": {
            "name": cfg.node_name if cfg else "—",
            "cidr": cfg.cidr if cfg else "—",
            "iface": cfg.iface_principal if cfg else "—"
        },
        "msg": "PROD ativo — aguardando integração dos coletores reais.",
        "last_update": datetime.now().isoformat()
    })

# ─────────────────────────────────────────────────────────────────────────────
# MOCK DATA (MIGRADO DO FRONT-END)
# ─────────────────────────────────────────────────────────────────────────────
ATTACKERS = [
    {'country': 'CN', 'flag': '🇨🇳', 'city': 'Shanxi', 'lat': 37.87, 'lon': 112.55, 'isp': 'China Telecom'},
    {'country': 'CN', 'flag': '🇨🇳', 'city': 'Guangzhou', 'lat': 23.13, 'lon': 113.26, 'isp': 'China Unicom'},
    {'country': 'RU', 'flag': '🇷🇺', 'city': 'Moscou', 'lat': 55.75, 'lon': 37.62, 'isp': 'MTS Russia'},
    {'country': 'US', 'flag': '🇺🇸', 'city': 'Ashburn', 'lat': 39.04, 'lon': -77.49, 'isp': 'Vultr Holdings'},
    {'country': 'NL', 'flag': '🇳🇱', 'city': 'Amsterdam', 'lat': 52.37, 'lon': 4.90, 'isp': 'KPN Netherlands'},
    {'country': 'DE', 'flag': '🇩🇪', 'city': 'Frankfurt', 'lat': 50.11, 'lon': 8.68, 'isp': 'Deutsche Telekom'},
    {'country': 'BR', 'flag': '🇧🇷', 'city': 'São Paulo', 'lat': -23.55, 'lon': -46.63, 'isp': 'Telemar Norte Leste'},
]

SIGNATURES = {
    'bruteforce': ['ET SCAN SSH Brute Force (SID 2001219)', 'ET SCAN Telnet Brute Force', 'ET SCAN RDP Login Attempt'],
    'scan':       ['ET SCAN Nmap SYN Scan', 'ET SCAN Masscan Detected', 'ET SCAN UDP Port Sweep'],
    'exploit':    ['ET EXPLOIT EternalBlue Attempt', 'ET EXPLOIT Log4Shell (CVE-2021-44228)'],
    'malware':    ['ET MALWARE C2 Beacon', 'ET TROJAN Cobalt Strike Beacon', 'ET DNS Malware Query (C2)'],
    'policy':     ['ET POLICY Web Crawler', 'ET POLICY SMTP Probe', 'ET POLICY TOR Exit Node'],
}

SOURCES = ['IDS', 'IDS', 'IDS', 'FW', 'DNS']
PORTS = {'bruteforce': [22, 3389, 23], 'scan': [80, 443, 8080], 'exploit': [80, 443, 445], 'malware': [443, 4444], 'policy': [25, 80]}

def _gen_event():
    src  = random.choice(ATTACKERS)
    type_ = random.choice(['bruteforce', 'scan', 'exploit', 'malware', 'policy'])
    sev  = random.choice(['critical', 'critical', 'high', 'high', 'medium', 'medium', 'low'])
    return {
        "id": f"evt_{random.randint(100000, 999999)}_{int(datetime.now().timestamp() * 1000)}",
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "ts": datetime.now().isoformat(),
        "source": random.choice(SOURCES),
        "severity": sev,
        "type": type_,
        "src_ip": f"{random.randint(1, 254)}.{random.randint(0, 254)}.{random.randint(0, 254)}.{random.randint(1, 254)}",
        "src_country": src['country'],
        "src_flag": src['flag'],
        "src_city": src['city'],
        "src_lat": src['lat'] + (random.random() - 0.5) * 2,
        "src_lon": src['lon'] + (random.random() - 0.5) * 2,
        "dest_ip": "10.0.0.1",
        "dest_lat": -15.78,
        "dest_lon": -47.93,
        "signature": random.choice(SIGNATURES[type_]),
        "port": random.choice(PORTS[type_]),
        "proto": 'TCP/UDP' if type_ == 'scan' else 'TCP',
        "asn": f"AS{random.randint(1000, 99999)} · {src['isp']}"
    }

def _demo_map_overview(cfg, period, sev):
    # Gera entre 2 e 6 eventos por chamada para simular tráfego
    events = [_gen_event() for _ in range(random.randint(2, 6))]
    
    # Simula alguns KPIs para UI
    critical_count = sum(1 for e in events if e['severity'] == 'critical')
    top_country = random.choice(["CN", "RU", "US", "NL"]) if events else "--"

    return {
        "ok": True,
        "mode": "demo",
        "providers": {"ids": True, "fw": True, "dns": True},
        "kpis": {
            "active": len(events),
            "critical": critical_count,
            "rate": random.randint(15, 45),
            "top_country": top_country,
            "session_total": random.randint(1500, 5000)
        },
        "events": events,
        "config": {"trail_duration": 15000, "max_events": 200, "rot_speed": 0.05},
        "node": {
            "name": cfg.node_name if cfg else "JG-DEMO",
            "cidr": cfg.cidr if cfg else "192.168.0.0/24",
            "iface": cfg.iface_principal if cfg else "Ethernet"
        },
        "last_update": datetime.now().isoformat()
    }