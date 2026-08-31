"""
dns/views.py — MoonShield  v3
─────────────────────────────────────────────────────────────────────────────
Modo DEMO        → dados simulados sempre
Modo PROD + real → busca dados reais do AdGuard via adguard_client.py
Modo PROD + erro → retorna zeros reais (mode: "prod_offline"), NUNCA mock
─────────────────────────────────────────────────────────────────────────────
"""

import json
import random
import logging
from datetime import datetime, timedelta

from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_GET, require_POST

logger = logging.getLogger(__name__)

try:
    from configuracoes.models import ConfigSistema
except ImportError:
    ConfigSistema = None
    logger.warning("ConfigSistema não encontrado — sempre modo demo.")

try:
    from .services.adguard_client import AdGuardClient, AdGuardError
    from .services.regras import adicionar_regras
    ADGUARD_AVAILABLE = True
except ImportError:
    ADGUARD_AVAILABLE = False
    logger.warning("adguard_client/regras não encontrado — modo prod indisponível.")


# ─────────────────────────────────────────────────────────────────────────────
# HELPER — modo do sistema (mesma lógica do incidentes/views.py)
# ─────────────────────────────────────────────────────────────────────────────

def _get_modo_sistema() -> str:
    """Retorna 'demo' ou 'prod'. Padrão: 'demo' se não conseguir ler."""
    if ConfigSistema:
        try:
            return ConfigSistema.get_solo().modo
        except Exception:
            pass
    return 'demo'


# ─────────────────────────────────────────────────────────────────────────────
# RESPOSTA PROD VAZIA — retorna zeros reais, sem nenhum dado simulado
# ─────────────────────────────────────────────────────────────────────────────

def _prod_empty_response(error: str = None) -> dict:
    """Resposta para PROD quando AdGuard está offline ou não configurado."""
    resp = {
        "ok": True,
        "mode": "prod_offline",
        "metrics": {
            "queries": 0,
            "bloqueios": 0,
            "pctBloq": 0,
            "clientes": 0,
            "latencia": 0,
            "uptime": "—",
            "uptime_seconds": 0,
            "trends": {
                "queries": None,
                "bloqueios": None,
            },
        },
        "health": {
            "api": "offline",
            "running": False,
            "protection_enabled": False,
            "safe_browsing": False,
            "version": "—",
            "uptime": "—",
            "uptime_seconds": 0,
            "dns_port": 53,
            "dns_addresses": [],
            "filters_enabled": 0,
        },
        "charts": {
            "hours": [f"{h:02d}h" for h in range(24)],
            "queries": [0] * 24,
            "bloqueios": [0] * 24,
            "latency": [0] * 24,
            "latency_peak": [0] * 24,
        },
        "top_consultados": [],
        "top_bloqueados": [],
        "clientes": [],
        "filter_count": 0,
        "generated_at": datetime.now().astimezone().isoformat(),
    }
    if error:
        resp["warning"] = error
    return resp


# ─────────────────────────────────────────────────────────────────────────────
# VIEW PRINCIPAL E PÁGINAS
# ─────────────────────────────────────────────────────────────────────────────

@login_required(login_url='autenticacao:login')
def dns_view(request):
    return render(request, 'Adguard/adguard.html')

@login_required(login_url='autenticacao:login')
def feed_view(request):
    return render(request, 'Adguard/feed.html')

@login_required(login_url='autenticacao:login')
def regras_view(request):
    return render(request, 'Adguard/regras.html')


# ─────────────────────────────────────────────────────────────────────────────
# DADOS SIMULADOS (DEMO) — usados SOMENTE em modo demo
# ─────────────────────────────────────────────────────────────────────────────

TOP_CONSULTADOS = [
    {'domain': 'google.com',       'n': 3000},
    {'domain': 'youtube.com',      'n': 2000},
    {'domain': 'api.whatsapp.com', 'n': 1400},
    {'domain': 'netflix.com',      'n': 1100},
    {'domain': 'apple.com',        'n': 900},
    {'domain': 'icloud.com',       'n': 700},
    {'domain': 'spotify.com',      'n': 600},
    {'domain': 'github.com',       'n': 450},
]

TOP_BLOQUEADOS = [
    {'domain': 'doubleclick.net',      'n': 700},
    {'domain': 'ads-twitter.com',      'n': 350},
    {'domain': 'googleadservices.com', 'n': 280},
    {'domain': 'malware-tracker.ru',   'n': 180},
    {'domain': 'tracking-pixel.io',    'n': 140},
    {'domain': 'clickfusion.com',      'n': 120},
    {'domain': 'adnxs.com',            'n': 90},
    {'domain': 'scorecard.com',        'n': 70},
]

DEVICE_EMOJIS = ['📱', '💻', '🖥️', '📺', '🎮', '🔌', '⌚', '🖨️', '📡', '🔊']
DEVICE_NAMES = [
    'iPhone de Pedro', 'MacBook Air', 'Desktop Principal', 'Samsung TV',
    'PlayStation 5', 'Smart Plug Hall', 'Apple Watch', 'HP LaserJet',
    'Roteador AP', 'Echo Dot', 'iPad Ana', 'Notebook Dell',
    'Raspberry Pi', 'Chromecast', 'Nintendo Switch', 'Smart Fridge',
    'Galaxy S24', 'Windows PC', 'Amazon Fire', 'Xbox Series X',
]

DEMO_IPS = [
    '10.0.0.11', '10.0.0.12', '10.0.0.14', '10.0.0.15', '10.0.0.21',
    '10.0.0.22', '10.0.0.31', '10.0.0.32', '10.0.0.41', '10.0.0.50',
    '10.0.0.51', '10.0.0.52', '10.0.0.53', '10.0.0.60', '10.0.0.70',
    '10.0.0.71', '10.0.0.80', '10.0.0.81', '10.0.0.90', '10.0.0.99',
]

DEMO_DOMAINS_ALLOWED = [
    'google.com', 'youtube.com', 'api.whatsapp.com', 'netflix.com',
    'apple.com', 'icloud.com', 'github.com', 'fonts.googleapis.com'
]

DEMO_DOMAINS_BLOCKED = [
    'doubleclick.net', 'ads-twitter.com', 'googleadservices.com',
    'malware-tracker.ru', 'tracking-pixel.io', 'clickfusion.com'
]

DEMO_QUERY_TYPES = ['A', 'A', 'A', 'AAAA', 'AAAA', 'CNAME']


def _gen_clients_demo():
    clients = []
    for i in range(20):
        queries   = random.randint(200, 6000)
        bloqueios = int(queries * random.uniform(0.05, 0.35))
        pct       = round((bloqueios / queries) * 100, 1) if queries else 0
        status    = 'online' if i < 14 else ('offline' if i < 17 else 'suspeito')
        last_seen = 'agora' if i < 14 else f"{random.randint(5, 120)} min atrás"
        mac       = ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
        clients.append({
            'id':        i + 1,
            'emoji':     DEVICE_EMOJIS[i % len(DEVICE_EMOJIS)],
            'name':      DEVICE_NAMES[i],
            'ip':        DEMO_IPS[i],
            'mac':       mac,
            'status':    status,
            'queries':   queries,
            'bloqueios': bloqueios,
            'pct':       pct,
            'lastSeen':  last_seen,
            'reqMin':    round(queries / 1440, 1),
        })
    return clients


def _gen_chart_data_demo(pct_bloq, mult):
    queries_hr   = [random.randint(int(200 * mult), int(2200 * mult)) for _ in range(24)]
    bloqueios_hr = [int(q * (pct_bloq / 100) * random.uniform(0.6, 1.4)) for q in queries_hr]
    latency_hr   = [random.randint(1, 18) for _ in range(24)]
    latency_peak = [v + random.randint(2, 12) for v in latency_hr]
    hours = [f"{(datetime.now().hour - 23 + i) % 24:02d}h" for i in range(24)]
    return {
        "hours":        hours,
        "queries":      queries_hr,
        "bloqueios":    bloqueios_hr,
        "latency":      latency_hr,
        "latency_peak": latency_peak,
    }


def _demo_response(period: str) -> dict:
    mult      = {'1h': 0.08, '24h': 1, '7d': 5.5, '30d': 22}.get(period, 1)
    queries   = int(random.randint(18000, 32000) * mult)
    bloqueios = int(random.randint(1800, 5500)   * mult)
    pct_bloq  = round((bloqueios / queries) * 100, 1) if queries else 0

    return {
        "ok":    True,
        "mode":  "demo",
        "metrics": {
            "queries":   queries,
            "bloqueios": bloqueios,
            "pctBloq":   pct_bloq,
            "clientes":  random.randint(8, 18),
            "latencia":  round(random.uniform(1.2, 8.4), 1),
            "uptime":    f"{random.randint(12, 99)}d {random.randint(0, 23)}h",
        },
        "charts":          _gen_chart_data_demo(pct_bloq, mult / 4),
        "top_consultados": [{"domain": d['domain'], "n": int(d['n'] * mult)} for d in TOP_CONSULTADOS],
        "top_bloqueados":  [{"domain": d['domain'], "n": int(d['n'] * mult)} for d in TOP_BLOQUEADOS],
        "clientes":        _gen_clients_demo(),
    }


def _gen_querylog_demo(limit: int = 50, since: str = None) -> list:
    entries = []
    now = datetime.now()
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", ""))
            delta = now - since_dt
            max_back = max(0, int(delta.total_seconds() - 10))
        except Exception:
            max_back = limit * 8
    else:
        max_back = limit * 8

    timestamps = sorted([random.randint(0, max(1, max_back)) for _ in range(limit)])

    for secs_ago in timestamps:
        t = now - timedelta(seconds=secs_ago)
        if since:
            try:
                since_dt = datetime.fromisoformat(since.replace("Z", ""))
                if t <= since_dt:
                    continue
            except Exception:
                pass

        blocked = random.random() < 0.28
        domain  = random.choice(DEMO_DOMAINS_BLOCKED if blocked else DEMO_DOMAINS_ALLOWED)
        ip      = random.choice(DEMO_IPS)
        qtype   = random.choice(DEMO_QUERY_TYPES)

        entries.append({
            "time":       t.isoformat(),
            "time_fmt":   t.strftime("%H:%M:%S"),
            "ip":         ip,
            "domain":     domain,
            "type":       qtype,
            "blocked":    blocked,
            "status":     "Bloqueado" if blocked else "Processado",
            "elapsed_ms": None if blocked else random.randint(1, 28),
            "filter":     "AdGuard DNS filter" if blocked else "",
        })

    entries.sort(key=lambda e: e["time"], reverse=True)
    return entries[:limit]


# ─────────────────────────────────────────────────────────────────────────────
# CACHE DE INSTÂNCIA DO CLIENTE
# ─────────────────────────────────────────────────────────────────────────────

_adguard_client: "AdGuardClient | None" = None
_adguard_last_signature: tuple = ()


def _get_adguard_client(cfg) -> "AdGuardClient":
    """
    Mantém uma instância reutilizável, mas recria a sessão sempre que
    URL/usuário/senha/HTTPS mudarem. Isso evita autenticação antiga presa
    após salvar novas credenciais no painel.
    """
    global _adguard_client, _adguard_last_signature

    url = (getattr(cfg, "adguard_url", "") or "").strip()
    user = getattr(cfg, "adguard_user", "") or ""
    pwd = getattr(cfg, "adguard_pass", "") or ""
    https = bool(getattr(cfg, "adguard_https", False))

    signature = (url, user, pwd, https)
    if _adguard_client is None or signature != _adguard_last_signature:
        _adguard_client = AdGuardClient(
            url=url,
            user=user,
            password=pwd,
            https=https,
        )
        _adguard_last_signature = signature

    return _adguard_client


def _check_prod_mode(cfg):
    """Valida se a requisição pode ser executada em modo PROD."""
    modo = cfg.modo if cfg else "demo"
    if modo == "demo":
        return JsonResponse({"ok": False, "error": "Ação indisponível no modo Demo."}, status=400)
    if not getattr(cfg, 'dns_enabled', False) or getattr(cfg, 'adguard_mode', '') == "mock":
        return JsonResponse({"ok": False, "error": "AdGuard desativado ou em modo Mock."}, status=400)
    if not ADGUARD_AVAILABLE:
        return JsonResponse({"ok": False, "error": "adguard_client não encontrado."}, status=500)
    if not getattr(cfg, 'adguard_url', ''):
        return JsonResponse({"ok": False, "error": "URL do AdGuard não configurada."}, status=400)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# API: GET /dns/api/data/
# ─────────────────────────────────────────────────────────────────────────────

@require_GET
@login_required(login_url='autenticacao:login')
def api_dns_data(request):
    period = request.GET.get("period", "24h")
    if period not in {"1h", "24h", "7d", "30d"}:
        period = "24h"

    # ── Modo DEMO: sempre dados simulados ────────────────────────────────────
    if _get_modo_sistema() == 'demo':
        return JsonResponse(_demo_response(period))

    # ── Modo PROD ─────────────────────────────────────────────────────────────
    cfg = ConfigSistema.get_solo() if ConfigSistema else None

    # AdGuard não habilitado ou não configurado → zeros reais, sem mock
    if not ADGUARD_AVAILABLE:
        return JsonResponse(_prod_empty_response("adguard_client não instalado no servidor."))

    if not cfg or not getattr(cfg, 'dns_enabled', False):
        return JsonResponse(_prod_empty_response(
            "AdGuard desativado em Configurações → DNS. Ative para ver dados reais."
        ))

    if not getattr(cfg, 'adguard_url', ''):
        return JsonResponse(_prod_empty_response(
            "URL do AdGuard não configurada em Configurações → DNS."
        ))

    # AdGuard habilitado: tenta buscar dados reais
    try:
        client = _get_adguard_client(cfg)
        data   = client.fetch_all()

        return JsonResponse({
            "ok": True,
            "mode": "prod",
            "metrics": data["metrics"],
            "health": data.get("health", {}),
            "charts": data["charts"],
            "top_consultados": data["top_consultados"],
            "top_bloqueados": data["top_bloqueados"],
            "clientes": data["clientes"],
            "filter_count": data.get("filter_count", 0),
            "period_requested": period,
            # O /control/stats do AdGuard trabalha com o intervalo configurado
            # nele. Não fingimos que 7d/30d existem se a API não os fornecer.
            "period_effective": "adguard_stats",
            "generated_at": datetime.now().astimezone().isoformat(),
        })

    except AdGuardError as exc:
        logger.error("AdGuard fetch_all falhou: %s", exc)
        # PROD offline → zeros reais com aviso, NUNCA mock
        return JsonResponse(_prod_empty_response(
            f"AdGuard inacessível: {exc}. Verifique se o serviço está rodando."
        ))

    except Exception as exc:
        logger.exception("Erro inesperado em api_dns_data (prod)")
        return JsonResponse({"ok": False, "mode": "prod", "error": f"Erro interno: {exc}"}, status=500)


# ─────────────────────────────────────────────────────────────────────────────
# API: GET /dns/api/querylog/
# ─────────────────────────────────────────────────────────────────────────────

@require_GET
@login_required(login_url='autenticacao:login')
def api_querylog(request):
    since = request.GET.get("since") or None
    try:
        limit = int(request.GET.get("limit", 50))
    except (TypeError, ValueError):
        limit = 50
    limit = max(1, min(limit, 500))

    # ── Modo DEMO: dados simulados ────────────────────────────────────────────
    if _get_modo_sistema() == 'demo':
        return JsonResponse({
            "ok":      True,
            "mode":    "demo",
            "entries": _gen_querylog_demo(limit=limit, since=since),
        })

    # ── Modo PROD ─────────────────────────────────────────────────────────────
    cfg = ConfigSistema.get_solo() if ConfigSistema else None

    if not ADGUARD_AVAILABLE or not cfg or not getattr(cfg, 'dns_enabled', False) or not getattr(cfg, 'adguard_url', ''):
        # PROD sem AdGuard: feed vazio, sem simulação
        return JsonResponse({"ok": True, "mode": "prod_offline", "entries": []})

    try:
        client  = _get_adguard_client(cfg)
        entries = client.get_querylog_formatted(limit=limit, since=since)
        return JsonResponse({
            "ok": True,
            "mode": "prod",
            "entries": entries,
            "generated_at": datetime.now().astimezone().isoformat(),
        })

    except AdGuardError as exc:
        logger.error("AdGuard querylog falhou: %s", exc)
        # PROD offline: feed vazio, sem simulação
        return JsonResponse({
            "ok":      True,
            "mode":    "prod_offline",
            "entries": [],
            "warning": str(exc),
        })

    except Exception as exc:
        logger.exception("Erro inesperado em api_querylog")
        return JsonResponse({"ok": False, "error": f"Erro interno: {exc}"}, status=500)


# ─────────────────────────────────────────────────────────────────────────────
# POST /dns/api/block/ & POST /dns/api/allow/
# ─────────────────────────────────────────────────────────────────────────────

@login_required(login_url='autenticacao:login')
@require_POST
def api_block_domain(request):
    try:
        domains = json.loads(request.body).get("domains", "").strip()
    except (json.JSONDecodeError, AttributeError):
        return JsonResponse({"ok": False, "error": "JSON inválido."}, status=400)

    if not domains:
        return JsonResponse({"ok": False, "error": "Nenhum domínio informado."}, status=400)

    cfg   = ConfigSistema.get_solo() if ConfigSistema else None
    check = _check_prod_mode(cfg)
    if check: return check

    try:
        client = _get_adguard_client(cfg)
        result = adicionar_regras(client, domains, mode="block")
        return JsonResponse({"ok": True, **result})
    except AdGuardError as exc:
        return JsonResponse({"ok": False, "error": str(exc)}, status=502)
    except Exception as exc:
        logger.exception("api_block_domain erro")
        return JsonResponse({"ok": False, "error": f"Erro interno: {exc}"}, status=500)


@login_required(login_url='autenticacao:login')
@require_POST
def api_allow_domain(request):
    try:
        domains = json.loads(request.body).get("domains", "").strip()
    except (json.JSONDecodeError, AttributeError):
        return JsonResponse({"ok": False, "error": "JSON inválido."}, status=400)

    if not domains:
        return JsonResponse({"ok": False, "error": "Nenhum domínio informado."}, status=400)

    cfg   = ConfigSistema.get_solo() if ConfigSistema else None
    check = _check_prod_mode(cfg)
    if check: return check

    try:
        client = _get_adguard_client(cfg)
        result = adicionar_regras(client, domains, mode="allow")
        return JsonResponse({"ok": True, **result})
    except AdGuardError as exc:
        return JsonResponse({"ok": False, "error": str(exc)}, status=502)
    except Exception as exc:
        logger.exception("api_allow_domain erro")
        return JsonResponse({"ok": False, "error": f"Erro interno: {exc}"}, status=500)


# ─────────────────────────────────────────────────────────────────────────────
# POST /dns/api/flush/ & POST /dns/api/update-filters/
# ─────────────────────────────────────────────────────────────────────────────

@login_required(login_url='autenticacao:login')
@require_POST
def api_flush_cache(request):
    cfg   = ConfigSistema.get_solo() if ConfigSistema else None
    check = _check_prod_mode(cfg)
    if check: return check

    try:
        client = _get_adguard_client(cfg)
        client.flush_cache()
        return JsonResponse({"ok": True, "msg": "Cache DNS limpo com sucesso."})
    except AdGuardError as exc:
        return JsonResponse({"ok": False, "error": str(exc)}, status=502)
    except Exception as exc:
        logger.exception("api_flush_cache erro")
        return JsonResponse({"ok": False, "error": f"Erro interno: {exc}"}, status=500)


@login_required(login_url='autenticacao:login')
@require_POST
def api_update_filters(request):
    cfg   = ConfigSistema.get_solo() if ConfigSistema else None
    check = _check_prod_mode(cfg)
    if check: return check

    try:
        client = _get_adguard_client(cfg)
        result = client.update_filters()
        return JsonResponse({"ok": True, "msg": f"Listas atualizadas. {result.get('updated', 0)} lista(s) renovada(s)."})
    except AdGuardError as exc:
        return JsonResponse({"ok": False, "error": str(exc)}, status=502)
    except Exception as exc:
        logger.exception("api_update_filters erro")
        return JsonResponse({"ok": False, "error": f"Erro interno: {exc}"}, status=500)


# ─────────────────────────────────────────────────────────────────────────────
# GESTÃO DE REGRAS
# ─────────────────────────────────────────────────────────────────────────────

@login_required(login_url='autenticacao:login')
@require_GET
def api_regras_list(request):
    if _get_modo_sistema() == 'demo':
        return JsonResponse({"ok": True, "mode": "demo", "rules": []})

    cfg = ConfigSistema.get_solo() if ConfigSistema else None
    if not ADGUARD_AVAILABLE or not cfg or not getattr(cfg, "adguard_url", ""):
        return JsonResponse({"ok": True, "mode": "prod_offline", "rules": []})

    try:
        client = _get_adguard_client(cfg)
        rules  = client.get_custom_rules()
        return JsonResponse({"ok": True, "mode": "prod", "rules": rules})
    except AdGuardError as exc:
        return JsonResponse({"ok": False, "error": str(exc)}, status=502)
    except Exception as exc:
        logger.exception("api_regras_list erro")
        return JsonResponse({"ok": False, "error": f"Erro interno: {exc}"}, status=500)


@login_required(login_url='autenticacao:login')
@require_POST
def api_regras_salvar(request):
    """Substitui TODAS as regras (usado para deletar múltiplas da tabela)."""
    try:
        rules = json.loads(request.body).get("rules", [])
        if not isinstance(rules, list):
            return JsonResponse({"ok": False, "error": "rules deve ser uma lista."}, status=400)
    except (json.JSONDecodeError, AttributeError):
        return JsonResponse({"ok": False, "error": "JSON inválido."}, status=400)

    cfg   = ConfigSistema.get_solo() if ConfigSistema else None
    check = _check_prod_mode(cfg)
    if check: return check

    try:
        # Remove vazias/duplicadas preservando a ordem. O endpoint é usado
        # pela tela de regras para substituir a lista inteira.
        clean_rules = []
        seen = set()
        for rule in rules:
            if not isinstance(rule, str):
                continue
            rule = rule.strip()
            if not rule or rule in seen:
                continue
            seen.add(rule)
            clean_rules.append(rule)

        client = _get_adguard_client(cfg)
        client.set_custom_rules(clean_rules)
        return JsonResponse({
            "ok": True,
            "total": len(clean_rules),
            "removed_duplicates": max(0, len(rules) - len(clean_rules)),
        })
    except AdGuardError as exc:
        return JsonResponse({"ok": False, "error": str(exc)}, status=502)
    except Exception as exc:
        logger.exception("api_regras_salvar erro")
        return JsonResponse({"ok": False, "error": f"Erro interno: {exc}"}, status=500)