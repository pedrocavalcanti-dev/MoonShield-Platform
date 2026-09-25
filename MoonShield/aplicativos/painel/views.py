import logging
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

_PERIODO_PADRAO = "24h"

_SEV_MAP = {
    # frontend → model
    "critico": "critico",
    "alto":    "alto",
    "medio":   "medio",
}


# ─────────────────────────────────────────────────────────────────────────────
# HELPER: aggregação de incidentes por período
# ─────────────────────────────────────────────────────────────────────────────

def _normalizar_periodo(period: str | None) -> str:
    """Retorna somente um período reconhecido pelo Dashboard."""
    return period if period in _PERIODOS else _PERIODO_PADRAO


def _normalizar_severidade(sev: str | None) -> str:
    """Retorna somente um filtro de severidade reconhecido pelo Dashboard."""
    return sev if sev == "all" or sev in _SEV_MAP else "all"


def _incidentes_no_periodo(horas: int, sev_filtro: str | None, agora: datetime | None = None):
    """Retorna o queryset de Incidentes no período com filtro opcional de sev."""
    from incidentes.models import Incidente
    from django.utils import timezone

    agora = agora or timezone.now()
    desde = agora - timedelta(hours=horas)
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

    if bucket == "minuto":
        trunc_cls = TruncMinute
        label_fmt = "%H:%M"
    elif bucket == "hora":
        trunc_cls = TruncHour
        label_fmt = "%Hh"
    else:
        trunc_cls = TruncDay
        label_fmt = "%d/%m"

    from django.utils import timezone
    from zoneinfo import ZoneInfo
    tzinfo = ZoneInfo('America/Sao_Paulo')
    agora_local = timezone.localtime(agora, tzinfo)
    step = timedelta(minutes=bucket_min)
    inicio_janela = agora_local - timedelta(hours=horas)

    def inicio_do_bucket(ts: datetime) -> datetime:
        if bucket == "minuto":
            return ts.replace(
                minute=(ts.minute // bucket_min) * bucket_min,
                second=0,
                microsecond=0,
            )
        if bucket == "hora":
            return ts.replace(minute=0, second=0, microsecond=0)
        return ts.replace(hour=0, minute=0, second=0, microsecond=0)

    # Inclui os buckets parciais das duas bordas, mas o queryset já está
    # restrito à janela móvel exata. Assim nenhum evento fora do período entra.
    inicio = inicio_do_bucket(inicio_janela)
    fim = inicio_do_bucket(agora_local)

    bucket_idx: dict[datetime, int] = {}
    labels = []
    ts = inicio
    while ts <= fim:
        bucket_idx[ts] = len(labels)
        labels.append(ts.strftime(label_fmt))
        ts += step

    crit = [0] * len(labels)
    high = [0] * len(labels)
    med = [0] * len(labels)

    # Aggregação real por severidade
    for sev_key, target_list in [("critico", crit), ("alto", high), ("medio", med)]:
        rows = (
            qs.filter(severidade_jg=sev_key)
            .annotate(bucket_ts=trunc_cls("last_seen", tzinfo=tzinfo))
            .values("bucket_ts")
            .annotate(n=Count("id"))
            .order_by("bucket_ts")
        )
        for row in rows:
            ts = row["bucket_ts"]
            if ts is None:
                continue
            if timezone.is_naive(ts):
                ts = timezone.make_aware(ts, tzinfo)
            key = inicio_do_bucket(timezone.localtime(ts, tzinfo))
            idx = bucket_idx.get(key)
            if idx is not None:
                target_list[idx] += row["n"]

    return {"labels": labels, "crit": crit, "high": high, "med": med}


def _timeline_60min(qs_base, periodo_cfg: dict | None = None, agora: datetime | None = None) -> dict:
    """
    Timeline da janela selecionada, usando a granularidade do período.
    Retorna {"labels": [...], "crit": [...], "high": [...], "med": [...]}.
    Usa queryset já filtrado por período.
    """
    from django.utils import timezone

    periodo_cfg = periodo_cfg or _PERIODOS["1h"]
    return _series_ataques(qs_base, periodo_cfg, agora or timezone.now())


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
    """Métricas do mesmo inventário PostgreSQL consumido por Dispositivos."""
    from django.utils import timezone
    from dispositivos.models import Dispositivo
    from dispositivos.services import marcar_inventario_stale

    try:
        marcar_inventario_stale()
        total = Dispositivo.objects.count()
        online = Dispositivo.objects.filter(status=Dispositivo.Status.ONLINE).count()
        offline = Dispositivo.objects.filter(status=Dispositivo.Status.OFFLINE).count()
        stale = Dispositivo.objects.filter(status__in=[Dispositivo.Status.STALE, Dispositivo.Status.UNKNOWN]).count()
        hoje = timezone.now().date()
        novo_hoje = Dispositivo.objects.filter(first_seen__date=hoje).count()
    except Exception:
        logging.getLogger(__name__).exception("Falha ao consultar o inventário persistente de dispositivos")
        return {"online": None, "offline": None, "stale": None, "total": None, "novo_hoje": None, "pct": None, "error": True}

    pct = round((online / total) * 100) if total else 0
    return {"online": online, "offline": offline, "stale": stale, "total": total, "novo_hoje": novo_hoje, "pct": pct}
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
    period = _normalizar_periodo(period)
    sev = _normalizar_severidade(sev)
    cache_key = f"moonshield_overview_{period}_{sev}"
    try:
        data = cache.get(cache_key)
    except Exception:
        data = None

    if isinstance(data, dict):
        return data

    from configuracoes.views import _health_snapshot, _topologia
    from dns.views import _get_adguard_client
    from django.utils import timezone

    periodo_cfg = _PERIODOS[period]
    horas = periodo_cfg["horas"]

    # Filtro de severidade para incidentes
    sev_filtro = sev if sev != "all" else None

    # ── Serviços
    topo = _topologia()
    servicos = _health_snapshot(cfg, topo)
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

    agora = timezone.now()

    # ── Incidentes: a mesma janela aware alimenta todas as telemetrias.
    qs = _incidentes_no_periodo(horas, sev_filtro, agora)
    total_ameacas = qs.count()

    severidades = {
        "crit": qs.filter(severidade_jg="critico").count(),
        "high": qs.filter(severidade_jg="alto").count(),
        "med":  qs.filter(severidade_jg="medio").count(),
    }

    # ── Séries de ataques por hora/dia
    series_att = _series_ataques(qs, periodo_cfg, agora)
    hours_labels = series_att["labels"]

    # ── DNS: só aceita a série nativa completa de 24h do AdGuard.
    # Não há no runtime atual fonte persistida/completa para 1h, 7d ou 30d.
    dns_periodo = _dns_para_periodo(dns_charts, period)

    chart_hours = hours_labels

    # ── Timeline: usa exatamente o mesmo queryset, período e severidade.
    tl = _timeline_60min(qs, periodo_cfg, agora)

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
            # Timeline do período selecionado
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

    try:
        cache.set(cache_key, result, 10)
    except Exception:
        pass

    return result


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
    period = _normalizar_periodo(request.GET.get("period", _PERIODO_PADRAO).strip())
    sev = _normalizar_severidade(request.GET.get("sev", "all").strip())

    return JsonResponse(_overview_real(_get_cfg(), period=period, sev=sev))


@require_GET
@login_required(login_url="autenticacao:login")
def api_sensores(request):
    """Topbar - status simples dos 3 sensores."""
    from configuracoes.views import _health_snapshot, _topologia
    topo = _topologia()
    servicos = _health_snapshot(_get_cfg(), topo)
    return JsonResponse({
        "ids":      "ok" if servicos["suricata"].get("saudavel") else "offline",
        "dns":      "ok" if servicos["adguard"].get("saudavel") else "offline",
        "firewall": "ok" if servicos["firewall"].get("saudavel") else "offline",
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
