"""
aplicativos/configuracoes/views.py
────────────────────────────────────────────────────────────────────────────
Regras de negócio de modo:

  DEMO  → providers bloqueados no frontend. Testes de provider retornam mock.

  OPERACIONAL (valor interno: prod) → integrações reais liberadas.

Quick Tests → SEMPRE reais (ping, DNS, internet) independente do modo.

IDS / FW Health Check → consultam o banco para verificar se sensores Linux
                        estão conectados e enviando eventos recentes.
                        Não tentam acessar arquivos locais.
────────────────────────────────────────────────────────────────────────────
"""

import json
import platform

from django.http import JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.http import require_GET, require_POST

from .models import ConfigSistema
from .utils.sysinfo import get_sysinfo_real
from .utils.netinfo import get_interfaces, auto_discover
from .utils.quicktests import (
    test_ping_gateway,
    test_resolve_dns,
    test_dns_latency,
    test_internet_access,
)


# ─────────────────────────────────────────────────────────────────────────────
# PÁGINA PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

def configuracoes_view(request):
    cfg = ConfigSistema.get_solo()
    context = {
        "titulo_pagina": "Configurações — MoonShield",
        "modo_atual": cfg.modo,
        "modo_demo": cfg.modo_demo,
        "modo_operacional": cfg.modo_operacional,
        "modo_label": (
            "Modo Operacional"
            if cfg.modo_operacional
            else "Modo Demonstração"
        ),
    }
    return render(request, "configuracoes/configuracoes.html", context)


# ─────────────────────────────────────────────────────────────────────────────
# API: GET /configuracoes/api/config/
# ─────────────────────────────────────────────────────────────────────────────

@require_GET
def api_get_config(request):
    cfg = ConfigSistema.get_solo()
    return JsonResponse({"ok": True, "config": cfg.to_dict()})


# ─────────────────────────────────────────────────────────────────────────────
# API: POST /configuracoes/api/salvar/
# ─────────────────────────────────────────────────────────────────────────────

@require_POST
def api_salvar_config(request):
    try:
        data = json.loads(request.body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        return JsonResponse({"ok": False, "erro": f"JSON inválido: {e}"}, status=400)

    cfg = ConfigSistema.get_solo()

    # ── Modo Global ─────────────────────────────────────────────────────────
    #
    # Os valores internos continuam:
    #   demo -> Modo Demonstração
    #   prod -> Modo Operacional
    #
    # Mantemos "prod" para não quebrar integrações e códigos existentes.
    modo = data.get("modo", cfg.modo)

    if modo not in ("demo", "prod"):
        return JsonResponse(
            {
                "ok": False,
                "erro": "Modo inválido. Use 'demo' ou 'prod'.",
            },
            status=400,
        )

    cfg.modo = modo

    # ── Identidade do Node ──────────────────────────────────────────────────
    node = data.get("node", {})
    cfg.node_name     = node.get("name",     cfg.node_name)
    cfg.node_ambiente = node.get("ambiente", cfg.node_ambiente)
    cfg.node_tag      = node.get("tag",      cfg.node_tag)
    cfg.node_desc     = node.get("desc",     cfg.node_desc)

    # ── Rede Monitorada ─────────────────────────────────────────────────────
    rede = data.get("rede", {})
    cfg.cidr            = rede.get("cidr",            cfg.cidr)
    cfg.gateway         = rede.get("gateway",         cfg.gateway)
    cfg.dns1            = rede.get("dns1",            cfg.dns1)
    cfg.dns2            = rede.get("dns2",            cfg.dns2)
    cfg.ips_criticos    = rede.get("ips_criticos",    cfg.ips_criticos)
    cfg.excluir_scan    = rede.get("excluir",         cfg.excluir_scan)
    cfg.iface_principal = rede.get("iface_principal", cfg.iface_principal)

    # ── Scanner ─────────────────────────────────────────────────────────────
    scanner = data.get("scanner", {})
    cfg.scan_interval = int(scanner.get("interval",    cfg.scan_interval))
    cfg.ping_timeout  = int(scanner.get("pingTimeout", cfg.ping_timeout))
    cfg.max_hosts     = int(scanner.get("maxHosts",    cfg.max_hosts))
    cfg.scan_method   = scanner.get("method",          cfg.scan_method)
    cfg.scan_hostname = bool(scanner.get("hostname",   cfg.scan_hostname))
    cfg.scan_mac      = bool(scanner.get("mac",        cfg.scan_mac))
    cfg.scan_oui      = bool(scanner.get("oui",        cfg.scan_oui))

    # ── Retenção ────────────────────────────────────────────────────────────
    ret = data.get("retencao", {})
    cfg.ret_devices   = int(ret.get("devices",   cfg.ret_devices))
    cfg.ret_logs      = int(ret.get("logs",      cfg.ret_logs))
    cfg.ret_dns       = int(ret.get("dns",       cfg.ret_dns))
    cfg.ret_incidents = int(ret.get("incidents", cfg.ret_incidents))

    # ── Providers ───────────────────────────────────────────────────────────
    #
    # Modo Demonstração:
    #   - providers reais permanecem desativados;
    #   - o modo interno de cada provider passa a ser "mock";
    #   - credenciais/configurações já salvas não são apagadas.
    #
    # Modo Operacional:
    #   - cada provider é habilitado individualmente pelo usuário;
    #   - trocar o modo global não ativa DNS, IDS ou Firewall automaticamente.
    modo_final = cfg.modo
    providers = data.get("providers", {})

    dns = providers.get("dns", {})
    ids = providers.get("ids", {})
    fw = providers.get("fw", {})

    if modo_final == "demo":
        cfg.dns_enabled = False
        cfg.ids_enabled = False
        cfg.fw_enabled = False

        cfg.adguard_mode = "mock"
        cfg.suricata_mode = "mock"
        cfg.fw_mode = "mock"

    else:
        # DNS / AdGuard
        cfg.dns_enabled = bool(
            dns.get("active", cfg.dns_enabled)
        )
        cfg.adguard_mode = dns.get(
            "mode",
            cfg.adguard_mode if cfg.adguard_mode != "mock" else "real",
        )
        cfg.adguard_url = dns.get(
            "url",
            cfg.adguard_url,
        )
        cfg.adguard_user = dns.get(
            "user",
            cfg.adguard_user,
        )
        cfg.adguard_https = bool(
            dns.get("https", cfg.adguard_https)
        )
        cfg.adguard_interval = int(
            dns.get("interval", cfg.adguard_interval)
        )

        if dns.get("pass"):
            cfg.adguard_pass = dns["pass"]

        # IDS / Suricata
        #
        # A instalação e o estado operacional do Suricata são controlados
        # pelos models próprios do módulo Suricata. Aqui permanecem somente
        # os campos de compatibilidade do provider geral.
        cfg.ids_enabled = bool(
            ids.get("active", cfg.ids_enabled)
        )
        cfg.suricata_mode = ids.get(
            "mode",
            cfg.suricata_mode if cfg.suricata_mode != "mock" else "eve",
        )
        cfg.suricata_eve_path = ids.get(
            "evePath",
            cfg.suricata_eve_path,
        )
        cfg.suricata_interval = int(
            ids.get("interval", cfg.suricata_interval)
        )
        cfg.suricata_min_severity = int(
            ids.get(
                "minSeverity",
                cfg.suricata_min_severity,
            )
        )

        # Firewall
        cfg.fw_enabled = bool(
            fw.get("active", cfg.fw_enabled)
        )
        cfg.fw_mode = fw.get(
            "mode",
            cfg.fw_mode if cfg.fw_mode != "mock" else "nftables",
        )
        cfg.fw_target = fw.get(
            "target",
            cfg.fw_target,
        )
        cfg.fw_host = fw.get(
            "host",
            cfg.fw_host,
        )
        cfg.fw_agente_porta = int(
            fw.get(
                "agente_porta",
                cfg.fw_agente_porta,
            )
        )

        if fw.get("token"):
            cfg.fw_token = fw["token"]

    # ── Segurança ────────────────────────────────────────────────────────────
    seg = data.get("seguranca", {})
    cfg.session_expiry     = int(seg.get("sessionExpiry",    cfg.session_expiry))
    cfg.max_login_attempts = int(seg.get("maxLoginAttempts", cfg.max_login_attempts))
    cfg.force_https        = bool(seg.get("forceHttps",      cfg.force_https))
    cfg.access_log         = bool(seg.get("accessLog",       cfg.access_log))
    cfg.ip_ban             = bool(seg.get("ipBan",           cfg.ip_ban))
    if seg.get("logLevel") in ("DEBUG", "INFO", "WARNING", "ERROR"):
        cfg.log_level = seg["logLevel"]

    cfg.save()

    return JsonResponse(
        {
            "ok": True,
            "modo": cfg.modo,
            "modo_label": (
                "Modo Operacional"
                if cfg.modo_operacional
                else "Modo Demonstração"
            ),
            "modo_demo": cfg.modo_demo,
            "modo_operacional": cfg.modo_operacional,
            "updated_at": cfg.updated_at.isoformat(),
            "msg": (
                "Modo Operacional salvo. Configure cada componente "
                "real individualmente."
                if cfg.modo_operacional
                else "Modo Demonstração salvo. Integrações reais bloqueadas."
            ),
        }
    )


# ─────────────────────────────────────────────────────────────────────────────
# API: GET /configuracoes/api/sysinfo/
# ─────────────────────────────────────────────────────────────────────────────

@require_GET
def api_sysinfo(request):
    cfg = ConfigSistema.get_solo()

    try:
        ifaces   = get_interfaces()
        primary  = next((i for i in ifaces if i["principal"]), ifaces[0] if ifaces else None)
        ip_local = primary["ip"] if primary else "—"
    except Exception:
        ip_local = "—"

    info = get_sysinfo_real(ip_local_principal=ip_local)
    info["modo"] = cfg.modo
    info["modo_label"] = (
        "Modo Operacional"
        if cfg.modo_operacional
        else "Modo Demonstração"
    )

    cfg.detected_sysinfo = info
    cfg.detected_at      = timezone.now()
    cfg.save(update_fields=["detected_sysinfo", "detected_at"])

    return JsonResponse({"ok": True, "sysinfo": info})


# ─────────────────────────────────────────────────────────────────────────────
# API: GET /configuracoes/api/interfaces/
# ─────────────────────────────────────────────────────────────────────────────

@require_GET
def api_interfaces(request):
    cfg = ConfigSistema.get_solo()

    try:
        ifaces = get_interfaces()
    except Exception as e:
        return JsonResponse({"ok": False, "erro": str(e)}, status=500)

    cfg.detected_interfaces = ifaces
    cfg.save(update_fields=["detected_interfaces"])

    return JsonResponse(
        {
            "ok": True,
            "interfaces": ifaces,
            "modo": cfg.modo,
            "modo_label": (
                "Modo Operacional"
                if cfg.modo_operacional
                else "Modo Demonstração"
            ),
        }
    )


# ─────────────────────────────────────────────────────────────────────────────
# API: POST /configuracoes/api/auto-discover/
# ─────────────────────────────────────────────────────────────────────────────

@require_POST
def api_auto_discover(request):
    try:
        data = auto_discover()
        if not data.get("ok"):
            return JsonResponse(data, status=503)
        return JsonResponse(data)
    except Exception as e:
        return JsonResponse({"ok": False, "erro": str(e)}, status=500)


# ─────────────────────────────────────────────────────────────────────────────
# API: POST /configuracoes/api/testar-provider/
# ─────────────────────────────────────────────────────────────────────────────

@require_POST
def api_testar_provider(request):
    try:
        data = json.loads(request.body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return JsonResponse({"ok": False, "erro": "JSON inválido."}, status=400)

    provider = data.get("provider")
    cfg      = ConfigSistema.get_solo()

    # Bloqueia teste real em modo demo
    if cfg.modo == "demo":
        label = {"dns": "AdGuard", "ids": "Suricata IDS", "fw": "Firewall"}.get(provider, provider)
        return JsonResponse({
            "ok":     True,
            "status": "mock",
            "msg":    f"{label} — Mock ativo (modo Demo). Ative o Modo Operacional para testar a integração real.",
        })

    if provider == "dns":
        result = _testar_dns(cfg)
    elif provider == "ids":
        result = _testar_ids()
    elif provider == "fw":
        result = _testar_fw()
    else:
        return JsonResponse({"ok": False, "erro": "Provider inválido."}, status=400)

    return JsonResponse(result)


# ─────────────────────────────────────────────────────────────────────────────
# API: GET /configuracoes/api/quick-test/?test=<tipo>
# ─────────────────────────────────────────────────────────────────────────────

@require_GET
def api_quick_test(request):
    test = request.GET.get("test", "")
    cfg  = ConfigSistema.get_solo()

    if test == "ping":
        result = test_ping_gateway(cfg.gateway)
    elif test == "dns":
        result = test_resolve_dns()
    elif test == "latency":
        result = test_dns_latency(cfg.dns1)
    elif test == "internet":
        result = test_internet_access()
    else:
        return JsonResponse({"ok": False, "msg": f"Teste desconhecido: {test}"}, status=400)

    return JsonResponse(result)


# ─────────────────────────────────────────────────────────────────────────────
# API: GET /configuracoes/api/sensor-status/
#
# Sensores IDS (Suricata) — mesmos que os do painel incidentes.
# ─────────────────────────────────────────────────────────────────────────────

@require_GET
def api_sensor_status(request):
    try:
        from incidentes.models import Sensor

        sensores = Sensor.objects.all().order_by('-last_seen', 'nome')

        lista = []
        for s in sensores:
            segundos = s.segundos_desde_ultimo_evento
            lista.append({
                "id":             s.id,
                "nome":           s.nome,
                "ip":             s.ip,
                "ativo":          s.ativo,
                "online":         s.online,
                "last_seen":      s.last_seen.isoformat() if s.last_seen else None,
                "segundos_atras": segundos,
                "criado_em":      s.criado_em.isoformat(),
            })

        total_online = sum(1 for s in lista if s["online"])

        return JsonResponse({
            "ok":       True,
            "total":    len(lista),
            "online":   total_online,
            "sensores": lista,
        })

    except Exception as exc:
        return JsonResponse({"ok": False, "erro": str(exc)}, status=500)


# ─────────────────────────────────────────────────────────────────────────────
# API: GET /configuracoes/api/fw-sensor-status/
#
# Sensores Firewall (nftables) — mesma estrutura do IDS, mas cruza com
# EventoFirewall para confirmar que o sensor está de fato enviando logs
# de firewall (e não apenas heartbeats gerais do IDS).
#
# Resposta:
# {
#   "ok": true,
#   "total": 1,
#   "online": 1,
#   "sensores": [
#     {
#       "id": 1,
#       "nome": "fw-sensor-1",
#       "ip": "192.168.0.50",
#       "ativo": true,
#       "online": true,
#       "last_seen": "2025-02-22T14:30:00Z",
#       "segundos_atras": 12,
#       "criado_em": "2025-02-10T08:00:00Z",
#       "total_eventos": 8432,
#       "eventos_1h": 142
#     }
#   ]
# }
# ─────────────────────────────────────────────────────────────────────────────

@require_GET
def api_fw_sensor_status(request):
    try:
        from incidentes.models import Sensor
        from firewall.models import EventoFirewall
        from django.db.models import Count

        agora_ts  = timezone.now()
        uma_hora  = agora_ts - timezone.timedelta(hours=1)

        # Sensores que já enviaram pelo menos 1 EventoFirewall
        sensor_ids_fw = (
            EventoFirewall.objects
            .exclude(sensor__isnull=True)
            .values_list('sensor_id', flat=True)
            .distinct()
        )

        sensores = Sensor.objects.filter(id__in=sensor_ids_fw).order_by('-last_seen', 'nome')

        lista = []
        for s in sensores:
            segundos     = s.segundos_desde_ultimo_evento
            total_ev     = EventoFirewall.objects.filter(sensor=s).count()
            eventos_1h   = EventoFirewall.objects.filter(sensor=s, timestamp__gte=uma_hora).count()

            lista.append({
                "id":             s.id,
                "nome":           s.nome,
                "ip":             s.ip,
                "ativo":          s.ativo,
                "online":         s.online,
                "last_seen":      s.last_seen.isoformat() if s.last_seen else None,
                "segundos_atras": segundos,
                "criado_em":      s.criado_em.isoformat(),
                "total_eventos":  total_ev,
                "eventos_1h":     eventos_1h,
            })

        total_online = sum(1 for s in lista if s["online"])

        return JsonResponse({
            "ok":       True,
            "total":    len(lista),
            "online":   total_online,
            "sensores": lista,
        })

    except Exception as exc:
        return JsonResponse({"ok": False, "erro": str(exc)}, status=500)


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS INTERNOS — TESTE DE PROVIDERS (apenas Modo Operacional)
# ─────────────────────────────────────────────────────────────────────────────

def _testar_dns(cfg: ConfigSistema) -> dict:
    """Testa conexão com AdGuard Home."""
    if cfg.adguard_mode == "mock" or not cfg.dns_enabled:
        return {
            "ok":     True,
            "status": "mock",
            "msg":    "Mock ativo — dados simulados. Ative o Modo Operacional e configure o AdGuard Real para testar.",
        }
    if not cfg.adguard_url:
        return {
            "ok":     False,
            "status": "config_incompleta",
            "msg":    "URL do AdGuard não configurada.",
        }
    try:
        import urllib.request
        import base64
        url  = cfg.adguard_url.rstrip("/") + "/control/status"
        req  = urllib.request.Request(url)
        cred = base64.b64encode(f"{cfg.adguard_user}:{cfg.adguard_pass}".encode()).decode()
        req.add_header("Authorization", f"Basic {cred}")
        resp = urllib.request.urlopen(req, timeout=5)
        data = json.loads(resp.read())
        return {
            "ok":     True,
            "status": "ok",
            "msg":    f"AdGuard conectado — versão {data.get('version', '?')}",
        }
    except Exception as e:
        return {
            "ok":     False,
            "status": "erro",
            "msg":    f"Falha ao conectar AdGuard: {e}",
        }


def _testar_ids() -> dict:
    """
    Health check do IDS via banco de dados.
    Verifica se existe algum sensor Suricata conectado e ativo.
    """
    try:
        from incidentes.models import Sensor

        total = Sensor.objects.count()

        if total == 0:
            return {
                "ok":     False,
                "status": "sem_sensor",
                "msg":    (
                    "Nenhum sensor cadastrado. "
                    "Execute o ms_sensor.py no Linux com Suricata para registrar um sensor."
                ),
            }

        online  = [s for s in Sensor.objects.filter(ativo=True) if s.online]
        offline = Sensor.objects.filter(ativo=True).count() - len(online)

        if online:
            mais_recente = sorted(online, key=lambda s: s.last_seen, reverse=True)[0]
            segundos     = mais_recente.segundos_desde_ultimo_evento
            return {
                "ok":     True,
                "status": "ok",
                "msg":    (
                    f"{len(online)} sensor(es) online — "
                    f"{mais_recente.nome} ({mais_recente.ip}) "
                    f"— último evento: {segundos}s atrás"
                ),
                "online":  len(online),
                "offline": offline,
                "total":   total,
            }
        else:
            ultimo = Sensor.objects.filter(ativo=True).order_by('-last_seen').first()
            if ultimo and ultimo.last_seen:
                delta   = int((timezone.now() - ultimo.last_seen).total_seconds())
                minutos = delta // 60
                return {
                    "ok":     False,
                    "status": "offline",
                    "msg":    (
                        f"Sensor(es) offline — {ultimo.nome} ({ultimo.ip}) "
                        f"— último contato: {minutos}min atrás. "
                        f"Verifique se o ms_sensor.py está rodando."
                    ),
                    "online":  0,
                    "offline": offline,
                    "total":   total,
                }
            else:
                return {
                    "ok":     False,
                    "status": "offline",
                    "msg":    "Sensor(es) cadastrado(s) mas nunca conectou. Execute o ms_sensor.py.",
                    "online":  0,
                    "offline": offline,
                    "total":   total,
                }

    except Exception as e:
        return {
            "ok":     False,
            "status": "erro",
            "msg":    f"Erro ao consultar sensores IDS: {e}",
        }


def _testar_fw() -> dict:
    """
    Health check do Firewall via banco de dados.

    Estados:
      - Nenhum Sensor registrado pelo ingest → sem_sensor (warn, não erro)
      - Sensor registrado mas sem EventoFirewall → aguardando (warn)
      - Sensor com eventos recentes (< 5 min)   → ok
      - Sensor com eventos mas antigos          → offline (erro)
    """
    try:
        from firewall.models import EventoFirewall
        from incidentes.models import Sensor
        from django.db.models import Count

        total_eventos = EventoFirewall.objects.count()

        # ── Sem nenhum evento ainda ───────────────────────────────────────────
        # Pode ser: (a) sensor nunca conectou, (b) sensor conectou mas não há
        # tráfego FORWARD ainda. Nos dois casos é "aguardando", não "erro".
        if total_eventos == 0:
            return {
                "ok":     True,       # ← warn, não erro — sensor pode estar rodando
                "status": "warn",
                "msg":    (
                    "Aguardando eventos do sensor nftables. "
                    "Certifique-se de que o ms_firewall.py está rodando e que "
                    "há tráfego passando pelo FORWARD (ip_forward=1)."
                ),
            }

        # ── Tem eventos — verifica sensores associados ────────────────────────
        sensor_ids = (
            EventoFirewall.objects
            .exclude(sensor__isnull=True)
            .values_list('sensor_id', flat=True)
            .distinct()
        )
        sensores_fw = Sensor.objects.filter(id__in=sensor_ids, ativo=True)

        if not sensores_fw.exists():
            # Eventos sem sensor associado (ingest sem autenticação)
            ultimo_ev = EventoFirewall.objects.order_by('-timestamp').first()
            delta     = int((timezone.now() - ultimo_ev.timestamp).total_seconds())
            if delta < 300:
                return {
                    "ok":     True,
                    "status": "ok",
                    "msg":    f"Firewall sensor ativo — último evento: {delta}s atrás ({total_eventos} total)",
                }
            return {
                "ok":     False,
                "status": "offline",
                "msg":    (
                    f"Sensor parado — último evento: {delta // 60}min atrás. "
                    "Verifique se o ms_firewall.py está rodando."
                ),
            }

        online  = [s for s in sensores_fw if s.online]
        offline = sensores_fw.count() - len(online)

        if online:
            mais_recente = sorted(online, key=lambda s: s.last_seen, reverse=True)[0]
            segundos     = mais_recente.segundos_desde_ultimo_evento
            uma_hora     = timezone.now() - timezone.timedelta(hours=1)
            ev_1h        = EventoFirewall.objects.filter(
                sensor=mais_recente,
                timestamp__gte=uma_hora,
            ).count()
            return {
                "ok":     True,
                "status": "ok",
                "msg":    (
                    f"{len(online)} sensor(es) online — "
                    f"{mais_recente.nome} ({mais_recente.ip}) "
                    f"— último evento: {segundos}s atrás"
                    f" — {ev_1h} eventos/1h"
                ),
                "online":         len(online),
                "offline":        offline,
                "total_sensores": sensores_fw.count(),
                "total_eventos":  total_eventos,
            }
        else:
            ultimo = sensores_fw.order_by('-last_seen').first()
            if ultimo and ultimo.last_seen:
                delta   = int((timezone.now() - ultimo.last_seen).total_seconds())
                minutos = delta // 60
                return {
                    "ok":     False,
                    "status": "offline",
                    "msg":    (
                        f"Sensor offline — {ultimo.nome} ({ultimo.ip}) "
                        f"— último contato: {minutos}min atrás. "
                        f"Verifique se o ms_firewall.py está rodando."
                    ),
                    "online":  0,
                    "offline": offline,
                    "total_sensores": sensores_fw.count(),
                }
            return {
                "ok":     False,
                "status": "offline",
                "msg":    "Sensor(es) cadastrado(s) mas sem contato recente. Execute o ms_firewall.py.",
            }

    except Exception as e:
        return {
            "ok":     False,
            "status": "erro",
            "msg":    f"Erro ao consultar sensores de firewall: {e}",
        }


import urllib.request as _urllib
 
@require_POST
def api_testar_agente(request):
    """
    POST /configuracoes/api/testar-agente/
    Body: {"ip": "192.168.0.104", "porta": 8765}
 
    Proxy que testa se o agente Flask está rodando no sensor.
    Faz GET http://IP:porta/status com o token do sensor.
    """
    try:
        data  = json.loads(request.body.decode("utf-8"))
        ip    = data.get("ip", "").strip()
        porta = int(data.get("porta", 8765))
 
        if not ip:
            return JsonResponse({"ok": False, "msg": "IP obrigatório"}, status=400)
 
        # Busca token do sensor pelo IP
        from incidentes.models import Sensor
        sensor = Sensor.objects.filter(ip=ip, ativo=True).order_by('-last_seen').first()
        token  = sensor.token if sensor else ""
 
        url = f"http://{ip}:{porta}/status"
        req = _urllib.Request(url)
        req.add_header("X-MS-TOKEN", token)
 
        try:
            resp    = _urllib.urlopen(req, timeout=4)
            payload = json.loads(resp.read())
            versao  = payload.get("versao", "?")
            uptime  = payload.get("uptime_seg", 0)
            return JsonResponse({
                "ok":     True,
                "msg":    f"Agente v{versao} ativo — uptime {uptime}s",
                "versao": versao,
                "uptime": uptime,
            })
        except Exception as e:
            return JsonResponse({
                "ok":  False,
                "msg": f"Agente não respondeu em {ip}:{porta} — {str(e)[:80]}",
            })
 
    except Exception as e:
        return JsonResponse({"ok": False, "msg": str(e)}, status=500)