"""Views da área administrativa da MoonShield Appliance."""

import json
from django.core.cache import cache
import logging
from urllib.parse import urlparse

from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.http import require_GET, require_POST

from .models import ConfigSistema
from .utils.quicktests import test_dns_latency, test_internet_access, test_ping_gateway, test_resolve_dns
from .utils.sysinfo import get_sysinfo_real

try:
    from dns.services.adguard_client import AdGuardClient, AdGuardError, AdGuardHTTPError
except ImportError:
    AdGuardClient = None
    AdGuardError = Exception
    AdGuardHTTPError = Exception

try:
    from firewall.services.firewall_status import obter_status_resumido
except ImportError:
    obter_status_resumido = None

try:
    from incidentes.models import ConfiguracaoSuricata
    from incidentes.services.suricata.status import obter_status_stack_completo
except ImportError:
    ConfiguracaoSuricata = None
    obter_status_stack_completo = None

try:
    from rede.services.topologia import obter_topologia
except ImportError:
    obter_topologia = None


logger = logging.getLogger(__name__)


def _topologia() -> dict:
    if not obter_topologia:
        return {"valida": False, "problemas": [], "avisos": []}

    cache_key = "moonshield_topologia"
    data = cache.get(cache_key)
    if data:
        return data

    try:
        data = obter_topologia()
        cache.set(cache_key, data, 10)
        return data
    except Exception as exc:
        logger.exception("Não foi possível obter a topologia oficial: %s", exc)
        return {"valida": False, "problemas": [{"mensagem": "Topologia indisponível."}], "avisos": []}


def _gateway_da_topologia(topologia: dict) -> str:
    wan = (topologia.get("wan") or {}).get("principal") or {}
    real = wan.get("real") or {}
    desejado = wan.get("desejado") or {}
    return str(real.get("gateway") or desejado.get("gateway") or "")


def _ip_de_gerenciamento(topologia: dict) -> str:
    gerenciamento = (topologia.get("gerenciamento") or {}).get("principal") or {}
    return str((gerenciamento.get("real") or {}).get("ipv4") or "—")


def _config_editavel(cfg: ConfigSistema, topologia: dict) -> dict:
    """Serializa somente as preferências editáveis nesta página."""
    return {
        "node": {"name": cfg.node_name, "ambiente": cfg.node_ambiente, "tag": cfg.node_tag, "desc": cfg.node_desc},
        "scanner": {
            "interval": cfg.scan_interval,
            "pingTimeout": cfg.ping_timeout,
            "maxHosts": cfg.max_hosts,
            "method": cfg.scan_method,
            "hostname": cfg.scan_hostname,
            "mac": cfg.scan_mac,
            "oui": cfg.scan_oui,
        },
        "retencao": {"devices": cfg.ret_devices, "logs": cfg.ret_logs, "dns": cfg.ret_dns, "incidents": cfg.ret_incidents},
        "seguranca": {
            "sessionExpiry": cfg.session_expiry,
            "maxLoginAttempts": cfg.max_login_attempts,
            "forceHttps": cfg.force_https,
            "accessLog": cfg.access_log,
            "ipBan": cfg.ip_ban,
            "logLevel": cfg.log_level,
        },
        "rede": topologia,
        "updated_at": cfg.updated_at.isoformat() if cfg.updated_at else None,
    }


def _estado_adguard(cfg: ConfigSistema, topologia: dict) -> dict:
    from dns.views import _get_adguard_client
    from dns.services.adguard_bootstrap import (
        _hosts_dns_iniciais,
        adguard_esta_provisionado,
        inventariar_interfaces_dns,
        upstreams_aprovados,
    )

    instalado = adguard_esta_provisionado()
    base = {
        "tipo": "adguard", "nome": "AdGuard Home", "fonte": "local", "ativo": False,
        "configurado": False,
        "instalado": instalado,
        "saudavel": False, "status": "atencao", "status_label": "Requer atenção",
        "dns_resolver": False, "api": False, "protecao": False, "filtros_ativos": 0, "versao": "?",
    }

    client = _get_adguard_client(cfg)
    if not client:
        return {
            **base,
            "status": "atencao" if instalado else "indisponivel",
            "status_label": "Requer atenção" if instalado else "Componente indisponível",
            "erro": "Integração DNS local não está provisionada.",
        }

    try:
        dados = client.fetch_all()
        health = dados.get("health") or {}
        ativo = bool(health.get("running"))
        api_ok = health.get("api") == "ok"
        protecao = bool(health.get("protection_enabled"))
        porta_dns = int(health.get("dns_port", 0) or 0)
        enderecos_dns = health.get("dns_addresses") or []
        inventario = inventariar_interfaces_dns(topologia)
        hosts_esperados = set(_hosts_dns_iniciais(inventario))
        hosts_reais = set(enderecos_dns)
        listener_ok = bool(
            inventario["interfaces_dns_ativas"]
            and hosts_reais == hosts_esperados
            and not ({"0.0.0.0", "::"} & hosts_reais)
        )
        try:
            upstream_ok = upstreams_aprovados(
                dados.get("dns_info") or {},
                client.testar_upstreams_dns(dados.get("dns_info") or {}),
            )
        except AdGuardError:
            upstream_ok = False

        dns_resolver = bool(ativo and api_ok and listener_ok and upstream_ok)
        configurado = bool(api_ok and protecao and porta_dns == 53 and listener_ok and dns_resolver and upstream_ok)

        status = "operacional" if ativo and configurado else "atencao"
        label = "Operacional" if status == "operacional" else "Requer atenção"
        return {
            **base,
            "ativo": ativo,
            "configurado": configurado,
            "saudavel": status == "operacional",
            "status": status,
            "status_label": label,
            "api": api_ok,
            "protecao": protecao,
            "dns_resolver": dns_resolver,
            "engine_ok": ativo,
            "api_ok": api_ok,
            "listener_ok": listener_ok,
            "resolver_ok": dns_resolver,
            "upstream_ok": upstream_ok,
            "filtros_ativos": int(health.get("filters_enabled", 0) or 0),
            "versao": health.get("version", "?"),
        }
    except AdGuardHTTPError as exc:
        logger.info("API local do AdGuard requer atenção: %s", exc)
        return {
            **base,
            "status": "atencao" if instalado else "indisponivel",
            "status_label": "Requer atenção" if instalado else "Componente indisponível",
            "erro": "API local do AdGuard não respondeu ao contrato esperado.",
        }
    except (AdGuardError, OSError, ValueError) as exc:
        logger.info("AdGuard local indisponível: %s", exc)
        return {
            **base,
            "status": "atencao" if instalado else "indisponivel",
            "status_label": "Requer atenção" if instalado else "Componente indisponível",
            "erro": "API local do AdGuard está indisponível.",
        }
    except Exception as exc:
        logger.exception("Falha ao consultar AdGuard local: %s", exc)
        return {
            **base,
            "status": "atencao" if instalado else "indisponivel",
            "status_label": "Requer atenção" if instalado else "Componente indisponível",
            "erro": "Não foi possível consultar o serviço DNS.",
        }


def _estado_suricata(topologia: dict) -> dict:
    base = {
        "tipo": "suricata", "nome": "Suricata IDS", "fonte": "local", "ativo": False,
        "instalado": False, "configurado": False,
        "saudavel": False, "status": "indisponivel", "status_label": "Indisponível",
        "eve_ativo": False, "monitor_ativo": False, "worker_ativo": False, "versao": "—",
        "interfaces": [], "home_net": list(topologia.get("home_net") or []), "drift": "Nenhum",
    }
    if not obter_status_stack_completo:
        return {**base, "erro": "Status Suricata indisponível."}
    try:
        stack = obter_status_stack_completo(incluir_diagnostico=False) or {}
        suricata = stack.get("suricata") or {}
        monitor = stack.get("monitor") or {}
        worker = (stack.get("servicos") or {}).get("worker_tarefas") or {}
        eve = monitor.get("eve") or {}
        cursor = monitor.get("cursor") or {}
        configuracao = ConfiguracaoSuricata.objects.filter(ativo=True).order_by("-atualizado_em").first() if ConfiguracaoSuricata else None
        interfaces = list(getattr(configuracao, "interfaces_monitoradas", []) or [])
        home_net = base["home_net"]
        ativo = bool(suricata.get("ativo"))
        eve_disponivel = bool(
            eve.get("existe")
            and eve.get("arquivo")
            and eve.get("legivel")
        )
        monitor_ativo = bool(monitor.get("ativo"))
        worker_ativo = bool(worker.get("ativo"))
        cursor_invalido = bool(cursor.get("existe") and not cursor.get("valido"))
        eve_ativo = bool(eve_disponivel and monitor_ativo and not cursor_invalido)
        instalado = bool(suricata.get("instalado"))
        configurado = bool(configuracao and suricata.get("configurado"))
        drift_raw = suricata.get("drift")
        drift = (
            bool(drift_raw.get("tem_drift"))
            if isinstance(drift_raw, dict)
            else bool(drift_raw)
        )
        operacional = bool(
            ativo
            and configurado
            and eve_ativo
            and monitor_ativo
            and worker_ativo
            and not drift
        )
        return {
            **base,
            "instalado": instalado,
            "configurado": configurado,
            "ativo": ativo, "saudavel": operacional,
            "status": "operacional" if operacional else ("atencao" if instalado else "indisponivel"),
            "status_label": "Operacional" if operacional else ("Requer atenção" if instalado else "Componente indisponível"),
            "eve_ativo": eve_ativo, "monitor_ativo": monitor_ativo, "worker_ativo": worker_ativo,
            "versao": str(suricata.get("versao") or getattr(configuracao, "versao_suricata", "") or "—"),
            "interfaces": interfaces, "home_net": home_net,
            "drift": "Detectado" if drift else "Nenhum",
        }
    except Exception as exc:
        logger.exception("Falha ao consultar Suricata: %s", exc)
        return {**base, "erro": "Não foi possível consultar o IDS."}


def _estado_firewall() -> dict:
    base = {
        "tipo": "firewall", "nome": "Firewall MoonShield", "fonte": "local", "ativo": False,
        "instalado": False, "configurado": False,
        "saudavel": False, "status": "indisponivel", "status_label": "Indisponível",
        "engine": "nftables", "agent_online": False, "drift": "Nenhum",
    }
    if not obter_status_resumido:
        return {**base, "erro": "Status do Firewall indisponível."}
    try:
        estado = obter_status_resumido()
        operacional = bool(estado.get("operacional"))
        return {
            **base,
            "instalado": bool(estado.get("instalado")),
            "configurado": bool(estado.get("configurado")),
            "ativo": bool(estado.get("ativo")), "saudavel": operacional,
            "status": estado.get("status") or ("operacional" if operacional else "atencao"),
            "status_label": estado.get("status_label") or ("Operacional" if operacional else "Requer atenção"),
            "agent_online": bool(estado.get("agent_ativo")),
            "drift": "Detectado" if estado.get("drift") else "Nenhum",
        }
    except Exception as exc:
        logger.exception("Falha ao consultar Firewall: %s", exc)
        return {**base, "erro": "Não foi possível consultar o Firewall."}


def _health_snapshot(cfg: ConfigSistema, topologia: dict) -> dict:
    cache_key = "moonshield:health:quick:v1"
    try:
        data = cache.get(cache_key)
    except Exception:
        data = None

    if isinstance(data, dict):
        return data

    # AdGuard Fast
    adguard = {
        "tipo": "adguard", "nome": "AdGuard Home", "saudavel": False,
        "operacional": False, "api": False, "protecao": False, "status": "indisponível"
    }
    try:
        from dns.views import _get_adguard_client
        client = _get_adguard_client(cfg)
        if client:
            status = client.get_status()
            running = bool(status.get("running", False)) if hasattr(status, "get") else False
            protecao = bool(status.get("protection_enabled", False)) if hasattr(status, "get") else False
            adguard["api"] = True
            adguard["protecao"] = protecao
            adguard["saudavel"] = running
            adguard["operacional"] = running
            adguard["status"] = str("operacional" if running else "atencao")
    except Exception:
        pass

    # Suricata Fast
    suricata = {
        "tipo": "suricata", "nome": "Suricata IDS", "saudavel": False,
        "operacional": False, "status": "indisponível"
    }
    try:
        from incidentes.services.suricata.servicos import obter_status_stack
        status = obter_status_stack()
        ativo = bool(status.get("stack_ativa", False)) if hasattr(status, "get") else False
        suricata["saudavel"] = ativo
        suricata["operacional"] = ativo
        suricata["status"] = str("operacional" if ativo else "atencao")
    except Exception:
        pass

    # Firewall Fast
    firewall = {
        "tipo": "firewall", "nome": "Firewall MoonShield", "saudavel": False,
        "operacional": False, "status": "indisponível"
    }
    try:
        from firewall.services.firewall_status import obter_status_resumido
        status = obter_status_resumido()
        op = bool(status.get("operacional", False)) if hasattr(status, "get") else False
        firewall["saudavel"] = op
        firewall["operacional"] = op
        firewall["status"] = str("operacional" if op else "atencao")
    except Exception:
        pass

    estados = (adguard, suricata, firewall)
    data = {
        "adguard": adguard,
        "suricata": suricata,
        "firewall": firewall,
        "resumo": {
            "dns_operacional": bool(adguard["saudavel"]),
            "ids_operacional": bool(suricata["saudavel"]),
            "firewall_operacional": bool(firewall["saudavel"]),
            "servicos_operacionais": int(sum(bool(s["saudavel"]) for s in estados)),
            "status": str("operacional" if all(s["saudavel"] for s in estados) else "atencao"),
        }
    }

    try:
        cache.set(cache_key, data, 10)
    except Exception:
        pass

    return data

def _servicos(cfg: ConfigSistema, topologia: dict) -> dict:
    cache_key = "moonshield_servicos_status"
    data = cache.get(cache_key)
    if data:
        return data

    adguard = _estado_adguard(cfg, topologia)
    suricata = _estado_suricata(topologia)
    firewall = _estado_firewall()
    estados = (adguard, suricata, firewall)
    data = {
        "adguard": adguard,
        "suricata": suricata,
        "firewall": firewall,
        "resumo": {
            "dns_operacional": adguard["saudavel"],
            "ids_operacional": suricata["saudavel"],
            "firewall_operacional": firewall["saudavel"],
            "servicos_operacionais": sum(servico["saudavel"] for servico in estados),
            "status": "operacional" if all(servico["saudavel"] for servico in estados) else "atencao",
        },
    }
    cache.set(cache_key, data, 10)
    return data


@login_required(login_url="autenticacao:login")
def configuracoes_view(request):
    return render(request, "configuracoes/configuracoes.html", {"titulo_pagina": "Configurações da MoonShield Appliance"})


@require_GET
@login_required(login_url="autenticacao:login")
def api_get_config(request):
    cfg = ConfigSistema.get_solo()
    return JsonResponse({"ok": True, "config": _config_editavel(cfg, _topologia())})


@require_POST
@login_required(login_url="autenticacao:login")
def api_salvar_config(request):
    try:
        data = json.loads(request.body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return JsonResponse({"ok": False, "erro": f"JSON inválido: {exc}"}, status=400)

    cfg = ConfigSistema.get_solo()
    node = data.get("node") or {}
    scanner = data.get("scanner") or {}
    retencao = data.get("retencao") or {}
    seguranca = data.get("seguranca") or {}
    cfg.node_name = node.get("name", cfg.node_name)
    cfg.node_ambiente = node.get("ambiente", cfg.node_ambiente)
    cfg.node_tag = node.get("tag", cfg.node_tag)
    cfg.node_desc = node.get("desc", cfg.node_desc)
    cfg.scan_interval = int(scanner.get("interval", cfg.scan_interval))
    cfg.ping_timeout = int(scanner.get("pingTimeout", cfg.ping_timeout))
    cfg.max_hosts = int(scanner.get("maxHosts", cfg.max_hosts))
    cfg.scan_method = scanner.get("method", cfg.scan_method)
    cfg.scan_hostname = bool(scanner.get("hostname", cfg.scan_hostname))
    cfg.scan_mac = bool(scanner.get("mac", cfg.scan_mac))
    cfg.scan_oui = bool(scanner.get("oui", cfg.scan_oui))
    cfg.ret_devices = int(retencao.get("devices", cfg.ret_devices))
    cfg.ret_logs = int(retencao.get("logs", cfg.ret_logs))
    cfg.ret_dns = int(retencao.get("dns", cfg.ret_dns))
    cfg.ret_incidents = int(retencao.get("incidents", cfg.ret_incidents))
    cfg.session_expiry = int(seguranca.get("sessionExpiry", cfg.session_expiry))
    cfg.max_login_attempts = int(seguranca.get("maxLoginAttempts", cfg.max_login_attempts))
    cfg.force_https = bool(seguranca.get("forceHttps", cfg.force_https))
    cfg.access_log = bool(seguranca.get("accessLog", cfg.access_log))
    cfg.ip_ban = bool(seguranca.get("ipBan", cfg.ip_ban))
    if seguranca.get("logLevel") in {"DEBUG", "INFO", "WARNING", "ERROR"}:
        cfg.log_level = seguranca["logLevel"]
    cfg.save()
    return JsonResponse({"ok": True, "updated_at": cfg.updated_at.isoformat(), "msg": "Alterações da appliance salvas."})


@require_GET
@login_required(login_url="autenticacao:login")
def api_servicos(request):
    cfg = ConfigSistema.get_solo()
    dados = _servicos(cfg, _topologia())
    return JsonResponse({
        "ok": True,
        "servicos": {key: dados[key] for key in ("adguard", "suricata", "firewall")},
        "resumo": dados["resumo"],
        "atualizado_em": timezone.now().isoformat(),
    })


@require_GET
@login_required(login_url="autenticacao:login")
def api_sysinfo(request):
    topologia = _topologia()
    return JsonResponse({"ok": True, "sysinfo": get_sysinfo_real(_ip_de_gerenciamento(topologia))})


@require_GET
@login_required(login_url="autenticacao:login")
def api_quick_test(request):
    test = request.GET.get("test", "")
    if test == "ping":
        result = test_ping_gateway(_gateway_da_topologia(_topologia()))
    elif test == "dns":
        result = test_resolve_dns()
    elif test == "latency":
        result = test_dns_latency("127.0.0.1")
    elif test == "internet":
        result = test_internet_access()
    else:
        return JsonResponse({"ok": False, "msg": "Teste desconhecido."}, status=400)
    return JsonResponse(result)
