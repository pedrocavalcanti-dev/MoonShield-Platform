"""
MoonShield — painel/views.py

Painel Aggregator: consolida dados reais de todos os módulos da appliance.

Contrato de _overview_real():
  - Suporta ?period=1h|24h|7d|30d  e  ?sev=all|critico|alto|medio
  - Retorna SOMENTE dados reais; jamais inventa fallback ou demo.
  - Se um módulo não estiver disponível → campo nulo / lista vazia / 0.
"""

import time
from django.core.cache import cache
from datetime import datetime, timedelta, timezone as dt_timezone

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_GET
from autenticacao.models import UserProfile


# ─────────────────────────────────────────────────────────────────────────────
# PERÍODOS VÁLIDOS
# ─────────────────────────────────────────────────────────────────────────────

_PERIODOS = {
    "1h":  {"horas": 1,    "bucket": "minuto",  "bucket_min": 5},
    "24h": {"horas": 24,   "bucket": "hora",    "bucket_min": 60},
    "7d":  {"horas": 168,  "bucket": "dia",     "bucket_min": 1440},
    "30d": {"horas": 720,  "bucket": "dia",     "bucket_min": 1440},
}

_SEV_MAP = {
    # frontend → model
    "critico": "critico",
    "alto":    "alto",
    "medio":   "medio",
}


# ─────────────────────────────────────────────────────────────────────────────
# HELPER: aggregação de incidentes por período
# ─────────────────────────────────────────────────────────────────────────────

def _incidentes_no_periodo(horas: int, sev_filtro: str | None):
    """Retorna o queryset de Incidentes no período com filtro opcional de sev."""
    from incidentes.models import Incidente
    from django.utils import timezone

    desde = timezone.now() - timedelta(hours=horas)
    qs = Incidente.objects.filter(last_seen__gte=desde)
    if sev_filtro and sev_filtro in _SEV_MAP:
        qs = qs.filter(severidade_jg=_SEV_MAP[sev_filtro])
    return qs


def _series_ataques(qs, periodo_cfg: dict, agora: datetime) -> dict:
    """
    Gera séries horárias (ou diárias) de incidentes por severidade.
    Retorna {"labels": [...], "crit": [...], "high": [...], "med": [...]}.
    Usa apenas dados reais — se vazio retorna listas de zeros.
    """
    from django.db.models.functions import TruncHour, TruncDay, TruncMinute
    from django.db.models import Count

    bucket = periodo_cfg["bucket"]
    horas = periodo_cfg["horas"]
    bucket_min = periodo_cfg["bucket_min"]
    n_buckets = max(1, (horas * 60) // bucket_min)

    if bucket == "minuto":
        trunc_fn = TruncMinute("last_seen")
        label_fmt = "%H:%M"
    elif bucket == "hora":
        trunc_fn = TruncHour("last_seen")
        label_fmt = "%Hh"
    else:
        trunc_fn = TruncDay("last_seen")
        label_fmt = "%d/%m"

    # Buckets temporais reais
    from django.utils import timezone
    agora_tz = timezone.now()
    # Para 1h com bucket 5min, gera 12 buckets de 5min
    step = timedelta(minutes=bucket_min)
    inicio = agora_tz - step * n_buckets

    # Índice de bucket → posição na lista
    bucket_idx: dict[datetime, int] = {}
    labels = []
    for i in range(n_buckets):
        ts = inicio + step * i
        # Arredonda para o início do bucket
        if bucket == "minuto":
            key = ts.replace(second=0, microsecond=0)
            # Arredonda para múltiplo de bucket_min minutos
            rounded_min = (key.minute // bucket_min) * bucket_min
            key = key.replace(minute=rounded_min)
        elif bucket == "hora":
            key = ts.replace(minute=0, second=0, microsecond=0)
        else:
            key = ts.replace(hour=0, minute=0, second=0, microsecond=0)
        bucket_idx[key] = i
        ts_local = timezone.localtime(ts)
        labels.append(ts_local.strftime(label_fmt))

    crit = [0] * n_buckets
    high = [0] * n_buckets
    med = [0] * n_buckets

    # Aggregação real por severidade
    for sev_key, target_list in [("critico", crit), ("alto", high), ("medio", med)]:
        rows = (
            qs.filter(severidade_jg=sev_key)
            .annotate(bucket_ts=trunc_fn)
            .values("bucket_ts")
            .annotate(n=Count("id"))
            .order_by("bucket_ts")
        )
        for row in rows:
            ts = row["bucket_ts"]
            if ts is None:
                continue
            # Normaliza tz
            from django.utils import timezone
            if timezone.is_aware(agora_tz) and timezone.is_naive(ts):
                ts = timezone.make_aware(ts)
            elif timezone.is_naive(agora_tz) and timezone.is_aware(ts):
                ts = timezone.make_naive(ts)

            # Arredonda para o bucket
            if bucket == "minuto":
                rounded_min = (ts.minute // bucket_min) * bucket_min
                key = ts.replace(minute=rounded_min, second=0, microsecond=0)
            elif bucket == "hora":
                key = ts.replace(minute=0, second=0, microsecond=0)
            else:
                key = ts.replace(hour=0, minute=0, second=0, microsecond=0)
            # Procura posição aproximada (dentro de ±1 bucket)
            for candidate, idx in bucket_idx.items():
                diff = abs((key - candidate).total_seconds())
                if diff <= bucket_min * 60:
                    target_list[idx] += row["n"]
                    break

    return {"labels": labels, "crit": crit, "high": high, "med": med}


def _timeline_60min(qs_base) -> dict:
    """
    Timeline dos últimos 60 minutos agrupados em buckets de 5 minutos.
    Retorna {"labels": [...], "crit": [...], "high": [...], "med": [...]}.
    Usa queryset já filtrado por período.
    """
    from django.utils import timezone
    from django.db.models.functions import TruncMinute
    from django.db.models import Count
    from datetime import timedelta

    agora = timezone.now()
    # Align to nearest 5 minutes down
    agora_aligned = agora.replace(second=0, microsecond=0, minute=(agora.minute // 5) * 5)
    
    n_buckets = 12
    step = timedelta(minutes=5)
    inicio = agora_aligned - step * (n_buckets - 1)
    
    # Filter using unaligned start just to be safe, but buckets are aligned
    qs60 = qs_base.filter(last_seen__gte=inicio)

    labels = []
    crit = [0] * n_buckets
    high = [0] * n_buckets
    med = [0] * n_buckets

    bucket_starts = []
    for i in range(n_buckets):
        ts = inicio + step * i
        bucket_starts.append(ts)
        # Use localtime for labels if timezone is active
        ts_local = timezone.localtime(ts)
        labels.append(ts_local.strftime("%H:%M"))

    for sev_key, target in [("critico", crit), ("alto", high), ("medio", med)]:
        rows = (
            qs60.filter(severidade_jg=sev_key)
            .annotate(bucket_ts=TruncMinute("last_seen"))
            .values("bucket_ts")
            .annotate(n=Count("id"))
        )
        for row in rows:
            ts = row["bucket_ts"]
            if ts is None:
                continue
            
            # Make sure ts is aware for comparison
            if timezone.is_naive(ts):
                ts = timezone.make_aware(ts)

            # Round to 5 min
            rounded = ts.replace(minute=(ts.minute // 5) * 5, second=0, microsecond=0)
            
            for i, bs in enumerate(bucket_starts):
                if abs((rounded - bs).total_seconds()) < 60:
                    target[i] += row["n"]
                    break

    return {"labels": labels, "crit": crit, "high": high, "med": med}


def _top_ips(qs, limit: int = 7) -> list[dict]:
    """Top IPs atacantes por quantidade de incidentes. Sem GeoIP."""
    from django.db.models import Count, Sum

    rows = (
        qs.values("src_ip")
        .annotate(total=Sum("ocorrencias"))
        .order_by("-total")[:limit]
    )
    result = []
    for i, row in enumerate(rows):
        ip = row["src_ip"]
        if not ip:
            continue
        sev_map = {0: "crit", 1: "high", 2: "high", 3: "med"}
        result.append({
            "rank": i + 1,
            "ip":    ip,
            "count": int(row["total"] or 0),
            "sev":   sev_map.get(i, "med"),
        })
    return result


def _top_ataques(qs, limit: int = 5) -> list[dict]:
    """Top assinaturas/tipos de ataque por frequência."""
    from django.db.models import Count

    rows = (
        qs.exclude(titulo_jg="")
        .values("titulo_jg", "severidade_jg")
        .annotate(n=Count("id"))
        .order_by("-n")[:limit]
    )
    sev_label_map = {
        "critico": "crit",
        "alto": "high",
        "medio": "med",
        "baixo": "low",
        "informativo": "info",
    }
    result = []
    for row in rows:
        result.append({
            "nome":  row["titulo_jg"],
            "sev":   sev_label_map.get(row["severidade_jg"], "info"),
            "count": row["n"],
        })
    return result


def _categorias(qs, total: int) -> list[dict]:
    """Distribuição por categoria JG. Sem percentuais inventados."""
    from django.db.models import Count

    cat_label = {
        "recon":    "Reconhecimento",
        "auth":     "Auth / Brute Force",
        "lateral":  "Lateral Movement",
        "dns":      "DNS / Policy",
        "web":      "Web / HTTP",
        "tls":      "TLS / QUIC",
        "malware":  "Malware / C2",
        "exfil":    "Exfiltração",
        "p2p":      "P2P / Mineração",
        "anomalia": "Anomalia",
        "info":     "Informativo",
    }
    cat_color = {
        "recon":    "#3b82f6",
        "auth":     "#ef4444",
        "lateral":  "#a855f7",
        "dns":      "#06b6d4",
        "web":      "#f97316",
        "tls":      "#8b5cf6",
        "malware":  "#dc2626",
        "exfil":    "#f59e0b",
        "p2p":      "#64748b",
        "anomalia": "#eab308",
        "info":     "#6b7280",
    }
    rows = (
        qs.values("categoria_jg")
        .annotate(n=Count("id"))
        .order_by("-n")
    )
    result = []
    for row in rows:
        cat = row["categoria_jg"]
        count = row["n"]
        if not count:
            continue
        result.append({
            "nome":  cat_label.get(cat, cat),
            "color": cat_color.get(cat, "#6b7280"),
            "count": count,
        })
    return result


def _infra_dispositivos() -> dict:
    """Métricas reais do módulo Dispositivos."""
    from django.utils import timezone
    try:
        from dispositivos.models import Dispositivo
        total = Dispositivo.objects.count()
        online = Dispositivo.objects.filter(status="online").count()
        offline = total - online
        hoje = timezone.now().date()
        novo_hoje = Dispositivo.objects.filter(first_seen__date=hoje).count()
        pct = round((online / total) * 100) if total else 0
        return {
            "online":     online,
            "offline":    offline,
            "total":      total,
            "novo_hoje":  novo_hoje,
            "pct":        pct,
        }
    except Exception:
        return {"online": 0, "offline": 0, "total": 0, "novo_hoje": 0, "pct": 0}


def _infra_firewall(estado_fw: dict) -> dict:
    """
    Dados de infra do Firewall usando apenas o que o backend real provê.
    Sem drops/blocks inventados — se não existirem, ficam como '—'.
    """
    return {
        "operacional":  estado_fw.get("saudavel", False),
        "agent_online": estado_fw.get("agent_online", False),
        "drift":        estado_fw.get("drift", "Nenhum"),
        "status":       estado_fw.get("status", "indisponivel"),
        "status_label": estado_fw.get("status_label", "Indisponível"),
        # Métricas de tráfego: apenas se o backend fornecer no futuro
        "drops":        estado_fw.get("drops", "—"),
        "blocks":       estado_fw.get("blocks", "—"),
        "top_porta":    estado_fw.get("top_porta", "—"),
        "pct":          0,
    }


def _sensores_lista(adguard: dict, suricata: dict, firewall: dict) -> list[dict]:
    """Estrutura de sensores para renderSaude no frontend."""
    def status_to_js(s: dict) -> str:
        if s.get("saudavel"):
            return "ok"
        if s.get("status") in ("atencao", "degradado"):
            return "warn"
        return "err"

    return [
        {
            "nome":   "IDS (Suricata)",
            "desc":   "Detecção de intrusão",
            "status": status_to_js(suricata),
            "icon":   "bi-shield-check",
        },
        {
            "nome":   "DNS (AdGuard)",
            "desc":   "Filtragem DNS",
            "status": status_to_js(adguard),
            "icon":   "bi-globe-americas",
        },
        {
            "nome":   "Firewall (nftables)",
            "desc":   "Controle de tráfego",
            "status": status_to_js(firewall),
            "icon":   "bi-fire",
        },
    ]


def _dns_para_periodo(dns_charts: dict, period: str) -> dict:
    """Expõe histórico DNS somente quando a fonte nativa o cobre por completo."""
    labels = list(dns_charts.get("hours") or [])
    queries = list(dns_charts.get("queries") or [])
    blocked = list(dns_charts.get("bloqueios") or [])
    has_24h_stats = bool(dns_charts.get("stats_history_available"))

    if period == "24h" and has_24h_stats and len(labels) == len(queries) == len(blocked) == 24:
        queries = [int(value or 0) for value in queries]
        blocked = [int(value or 0) for value in blocked]
        return {
            "available": True,
            "labels": labels,
            "queries": queries,
            "blocked": blocked,
            "queries_total": sum(queries),
            "blocked_total": sum(blocked),
        }

    return {
        "available": False,
        "labels": [],
        "queries": [],
        "blocked": [],
        "queries_total": None,
        "blocked_total": None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# AGGREGATOR PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

def _overview_real(cfg, period: str = "24h", sev: str = "all") -> dict:
    """
    Agrega somente dados reais dos módulos da appliance.

    Args:
        cfg:    ConfigSistema (ou None)
        period: "1h" | "24h" | "7d" | "30d"
        sev:    "all" | "critico" | "alto" | "medio"
    """
    cache_key = f"moonshield_overview_{period}_{sev}"
    data = cache.get(cache_key)
    if data:
        return data

    from configuracoes.views import _servicos, _topologia
    from dns.views import _get_adguard_client
    from django.utils import timezone

    # Valida período — padrão 24h se inválido
    periodo_cfg = _PERIODOS.get(period, _PERIODOS["24h"])
    horas = periodo_cfg["horas"]

    # Filtro de severidade para incidentes
    sev_filtro = sev if sev != "all" else None

    # ── Serviços
    topo = _topologia()
    servicos = _servicos(cfg, topo)
    adguard = servicos["adguard"]
    suricata = servicos["suricata"]
    firewall = servicos["firewall"]

    # ── AdGuard metrics
    dns_metrics: dict = {}
    dns_charts: dict = {}
    try:
        client = _get_adguard_client(cfg)
        if client:
            dns_all = client.fetch_all()
            dns_metrics = dns_all.get("metrics") or {}
            dns_charts = dns_all.get("charts") or {}
    except Exception:
        pass

    # ── Incidentes
    qs = _incidentes_no_periodo(horas, sev_filtro)
    total_ameacas = qs.count()

    severidades = {
        "crit": qs.filter(severidade_jg="critico").count(),
        "high": qs.filter(severidade_jg="alto").count(),
        "med":  qs.filter(severidade_jg="medio").count(),
    }

    # ── Séries de ataques por hora/dia
    agora = timezone.now()
    series_att = _series_ataques(qs, periodo_cfg, agora)
    hours_labels = series_att["labels"]

    # ── DNS: só aceita a série nativa completa de 24h do AdGuard.
    # Não há no runtime atual fonte persistida/completa para 1h, 7d ou 30d.
    dns_periodo = _dns_para_periodo(dns_charts, period)

    # Para gráfico de ataques, usa labels reais do período
    # Para gráfico DNS, mantém labels das 24h do AdGuard
    chart_hours = hours_labels if period in ("1h", "24h") else series_att["labels"]

    # ── Timeline 60 min (sempre baseado nos incidentes reais do último 1h)
    tl = _timeline_60min(qs if horas == 1 else _incidentes_no_periodo(1, None))

    # ── Top IPs
    top_ips_lista = _top_ips(qs)

    # ── Top Ataques (signatures)
    top_ataques = _top_ataques(qs)

    # ── Categorias
    categorias = _categorias(qs, total_ameacas)

    # ── Live Feed (últimos 20 incidentes reais)
    feed_qs = qs.order_by("-last_seen")[:20]
    feed = [
        {
            "ts":   inc.last_seen.isoformat(),
            "type": "IDS",
            "sev":  {"critico": "crit", "alto": "high", "medio": "warn"}.get(
                        inc.severidade_jg, "info"),
            "src":  (f"{inc.src_ip}:{inc.src_porta}"
                     if getattr(inc, "src_porta", None)
                     else getattr(inc, "src_ip", "—")) or "—",
            "msg":  getattr(inc, "titulo_jg", None)
                     or getattr(inc, "signature", None)
                     or "Incidente IDS",
        }
        for inc in feed_qs
    ]

    # ── Infra
    disp = _infra_dispositivos()
    fw_infra = _infra_firewall(firewall)

    dns_kpis_do_periodo = dns_periodo["available"]
    dns_queries = (
        dns_periodo["queries_total"]
        if dns_kpis_do_periodo
        else int(dns_metrics.get("queries", 0) or 0)
    )
    dns_bloq = (
        dns_periodo["blocked_total"]
        if dns_kpis_do_periodo
        else int(dns_metrics.get("bloqueios", 0) or 0)
    )
    dns_pct = round((dns_bloq / dns_queries) * 100, 1) if dns_queries else 0.0
    dns_clients = int(dns_metrics.get("clientes", 0) or 0)
    dns_perm = max(0, dns_queries - dns_bloq)

    # ── Sensores estruturados (lista para renderSaude no JS)
    sensores_lista = _sensores_lista(adguard, suricata, firewall)
    sensores_online = sum(1 for s in sensores_lista if s["status"] == "ok")

    result = {
        "ok":      True,
        "mode":    "real",
        "fonte":   "local",
        "periodo": period,
        "sev":     sev,

        "kpis": {
            "ameacas_hoje":     total_ameacas,
            "dns_queries":      dns_queries,
            "dns_bloqueios":    dns_bloq,
            "bloqueio_pct":     dns_pct,
            "dns_period_available": dns_kpis_do_periodo,
            "sensores_online":  sensores_online,
            "sensores_total":   3,
            "severidades":      severidades,
        },

        "charts": {
            # Ataques — séries do período selecionado
            "hours":    chart_hours,
            "attacks":  {
                "crit": series_att["crit"],
                "high": series_att["high"],
                "med":  series_att["med"],
            },
            # DNS — mantém hours como alias para consumidores ainda legados.
            "dns": {
                "labels":            dns_periodo["labels"],
                "hours":             dns_periodo["labels"],
                "queries":           dns_periodo["queries"],
                "blocked":           dns_periodo["blocked"],
                "history_available": dns_periodo["available"],
            },
            # Timeline dos últimos 60min (sempre)
            "timeline": tl,
        },

        "feed": feed,

        "intel": {
            # Top Origens = IPs reais (sem GeoIP — será integrado no Mapa de Ameaças)
            "top_ips":    top_ips_lista,
            "top_ataques": top_ataques,
            "categorias": categorias,
            # origens e ataques mantidos como lista vazia (sem GeoIP)
            "origens":   [],
            "ataques":   [],
        },

        "infra": {
            "dispositivos": disp,
            "firewall":     fw_infra,
            "dns_infra": {
                "bloqueio_pct": dns_pct,
                "clientes":     dns_clients,
                "bloqueios":    dns_bloq,
                "permitidos":   dns_perm,
                # "ameacas DNS" só com fonte real específica — omitido por ora
            },
        },

        "saude": {
            "ids":      suricata,
            "dns":      adguard,
            "firewall": firewall,
            "sensores": sensores_lista,
        },

        "node": {
            "name": getattr(cfg, "node_name", "—") if cfg else "—",
        },

        "last_update": agora.isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# ConfigSistema
# ─────────────────────────────────────────────────────────────────────────────

try:
    from configuracoes.models import ConfigSistema
except ImportError:
    ConfigSistema = None

_BOOT_TIME = time.time()


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
# VIEWS
# ─────────────────────────────────────────────────────────────────────────────

@login_required(login_url="autenticacao:login")
def index(request):
    profile, _ = UserProfile.objects.get_or_create(user=request.user)
    mostrar_boasvindas = request.session.pop("mostrar_boasvindas", False)
    return render(request, "painel/dashboard.html", {
        "profile":            profile,
        "mostrar_boasvindas": mostrar_boasvindas,
    })


@require_GET
@login_required(login_url="autenticacao:login")
def api_overview(request):
    period = request.GET.get("period", "24h").strip()
    sev    = request.GET.get("sev", "all").strip()

    # Valida period — rejeita valores arbitrários
    if period not in _PERIODOS:
        period = "24h"
    if sev not in ("all", "critico", "alto", "medio"):
        sev = "all"

    return JsonResponse(_overview_real(_get_cfg(), period=period, sev=sev))


@require_GET
@login_required(login_url="autenticacao:login")
def api_sensores(request):
    """Topbar — status simples dos 3 sensores."""
    dados = _overview_real(_get_cfg())["saude"]
    return JsonResponse({
        "ids":      "ok" if dados["ids"].get("saudavel") else "offline",
        "dns":      "ok" if dados["dns"].get("saudavel") else "offline",
        "firewall": "ok" if dados["firewall"].get("saudavel") else "offline",
    })


@login_required(login_url="autenticacao:login")
@require_GET
def api_badges(request):
    return JsonResponse({"incidentes": 0, "alertas": 0, "mensagens": 0})


@require_GET
@login_required(login_url="autenticacao:login")
def api_uptime(request):
    uptime_seconds = int(time.time() - _BOOT_TIME)
    return JsonResponse({"uptime_seconds": uptime_seconds, "ok": True})


@require_GET
@login_required(login_url="autenticacao:login")
def api_alertas(request):
    from incidentes.models import Incidente
    alertas = [
        {
            "id":         inc.pk,
            "titulo":     getattr(inc, "titulo_jg", None) or getattr(inc, "signature", None) or "Incidente",
            "descricao":  getattr(inc, "src_ip", None) or "Evento detectado pelo Suricata",
            "severidade": getattr(inc, "severidade_jg", "medio"),
            "tipo":       "ids",
            "timestamp":  inc.last_seen.isoformat(),
            "url":        "/incidentes/",
        }
        for inc in Incidente.objects.order_by("-last_seen")[:20]
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

def _hour_labels() -> list[str]:
    from django.utils import timezone
    now = timezone.now()
    return [f"{(now.hour - 23 + i) % 24:02d}h" for i in range(24)]
