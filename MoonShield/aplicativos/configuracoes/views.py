"""
aplicativos/configuracoes/views.py

Módulo de visualizações e APIs REST para as configurações globais do sistema MoonShield.

Organização do arquivo:
  01. Imports
  02. Constantes
  03. Helpers gerais / modo
  04. Helpers de serviços (AdGuard, Suricata, Firewall)
  05. Página principal
  06. Config API (GET / POST salvar)
  07. Serviços API (api_servicos)
  08. Sysinfo
  09. Rede
  10. Quick tests
  11. Compatibilidade legada
  12. Testes AdGuard
"""

# ─────────────────────────────────────────────────────────────────────────────
# 01. IMPORTS
# ─────────────────────────────────────────────────────────────────────────────

import json
import logging
import urllib.request
import urllib.error
import ssl

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

# Imports do módulo Suricata.
#
# IMPORTANTE:
# - ConfiguracaoSuricata vem do model do app incidentes.
# - obter_status_stack_completo NÃO é exportado pelo __init__.py de
#   incidentes.services.suricata; a implementação real está em status.py.
# - Não existe configuracao_model_para_dto no projeto atual.
try:
    from incidentes.models import ConfiguracaoSuricata
except ImportError:
    ConfiguracaoSuricata = None

try:
    from incidentes.services.suricata.status import obter_status_stack_completo
except ImportError:
    obter_status_stack_completo = None

# Logger do módulo
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# 02. CONSTANTES
# ─────────────────────────────────────────────────────────────────────────────

MODO_MAP_ENTRADA = {
    "simulacao": "demo",
    "simulation": "demo",
    "mock": "demo",
    "demo": "demo",
    "real": "prod",
    "production": "prod",
    "prod": "prod",
}


# ─────────────────────────────────────────────────────────────────────────────
# 03. HELPERS GERAIS / MODO
# ─────────────────────────────────────────────────────────────────────────────

def _normalizar_modo_para_banco(modo_str):
    """
    Normaliza a string de modo recebida para os valores armazenados no banco ('demo' ou 'prod').
    """
    if not modo_str:
        return "demo"
    val = str(modo_str).strip().lower()
    return MODO_MAP_ENTRADA.get(val, "demo")


def _normalizar_modo_para_api(modo_banco):
    """
    Normaliza o modo vindo do banco ('demo'/'prod') para o padrão externo ('simulacao'/'real').
    """
    return "real" if modo_banco == "prod" else "simulacao"


# ─────────────────────────────────────────────────────────────────────────────
# 04. HELPERS DE SERVIÇOS
# ─────────────────────────────────────────────────────────────────────────────

def _obter_estado_adguard(cfg):
    """
    Retorna o status consolidado do serviço AdGuard (DNS).
    """
    modo_api = _normalizar_modo_para_api(cfg.modo)

    if modo_api == "simulacao":
        return {
            "disponivel": True,
            "configurado": False,
            "ativo": False,
            "status": "simulado",
            "url": cfg.adguard_url or None,
        }

    # Modo Real
    configurado = bool(cfg.adguard_url)
    ativo = bool(cfg.dns_enabled)

    return {
        "disponivel": True,
        "configurado": configurado,
        "ativo": ativo,
        "status": "operacional" if (configurado and ativo) else "desativado",
        "url": cfg.adguard_url or None,
    }


def _obter_estado_suricata(modo_api):
    """
    Retorna o estado operacional e rápido do Suricata local.
    Reutiliza DTO e status do módulo incidentes.services.suricata.
    """
    if modo_api == "simulacao":
        return {
            "instalado": False,
            "onboarding_concluido": False,
            "instalacao_concluida": False,
            "configurado": False,
            "ativo": False,
            "monitor_ativo": False,
            "worker_ativo": False,
            "eve_ativo": False,
            "versao": None,
            "status": "simulado",
            "acao": "painel_simulado",
        }

    # Modo Real
    if not ConfiguracaoSuricata:
        logger.error("Módulo incidentes.models.ConfiguracaoSuricata não está disponível para import.")
        return {
            "instalado": False,
            "status": "erro",
            "acao": "instalar",
            "erro": "Módulo Suricata não carregado no Django",
        }

    try:
        cfg_suricata = ConfiguracaoSuricata.get_solo()
    except Exception as exc:
        logger.exception("Erro ao obter ConfiguracaoSuricata.get_solo(): %s", exc)
        return {
            "instalado": False,
            "status": "erro",
            "acao": "instalar",
        }

    # ESTADO 1 — NÃO INSTALADO
    if not cfg_suricata or not getattr(cfg_suricata, "suricata_instalado", False):
        return {
            "instalado": False,
            "status": "nao_instalado",
            "acao": "instalar",
        }

    # ESTADO 2 — CONFIGURAÇÃO PENDENTE
    onboarding_concluido = getattr(cfg_suricata, "onboarding_concluido", False)
    instalacao_concluida = getattr(cfg_suricata, "instalacao_concluida", False)

    if not onboarding_concluido or not instalacao_concluida:
        return {
            "instalado": True,
            "onboarding_concluido": onboarding_concluido,
            "instalacao_concluida": instalacao_concluida,
            "status": "configuracao_pendente",
            "acao": "continuar_instalacao",
        }

    # Tenta obter o status rápido usando a implementação REAL existente em
    # incidentes.services.suricata.status.
    #
    # A função do projeto aceita configuração opcional (há chamadas internas sem
    # argumento), portanto não inventamos/construímos DTO aqui. O módulo de
    # Configurações só consulta o health da stack e nunca executa Doctor.
    try:
        if not obter_status_stack_completo:
            raise RuntimeError(
                "obter_status_stack_completo não está disponível em "
                "incidentes.services.suricata.status"
            )

        status_stack = obter_status_stack_completo(
            incluir_diagnostico=False
        ) or {}

        if not isinstance(status_stack, dict):
            logger.warning(
                "Status Suricata retornou formato inesperado: %s",
                type(status_stack).__name__,
            )
            status_stack = {}

    except Exception as exc:
        logger.exception("Erro ao consultar status rápido do Suricata: %s", exc)
        return {
            "instalado": True,
            "onboarding_concluido": onboarding_concluido,
            "instalacao_concluida": instalacao_concluida,
            "configurado": bool(getattr(cfg_suricata, "suricata_configurado", False)),
            "ativo": False,
            "monitor_ativo": False,
            "worker_ativo": False,
            "eve_ativo": False,
            "versao": getattr(cfg_suricata, "versao_suricata", None),
            "status": "atencao",
            "acao": "painel",
        }

    # Avalia os componentes do status retornado
    suricata_info = status_stack.get("suricata", {})
    monitor_info = status_stack.get("monitor", {})
    worker_info = status_stack.get("worker", {})
    eve_info = status_stack.get("eve", {})

    suricata_ativo = suricata_info.get("ativo", False) if isinstance(suricata_info, dict) else False
    monitor_ativo = monitor_info.get("ativo", False) if isinstance(monitor_info, dict) else False
    worker_ativo = worker_info.get("ativo", False) if isinstance(worker_info, dict) else False
    eve_ativo = (
        eve_info.get("saudavel", False) or eve_info.get("ativo", False)
        if isinstance(eve_info, dict) else False
    )

    versao = getattr(cfg_suricata, "versao_suricata", None)

    # ESTADO 3 — OPERACIONAL
    if suricata_ativo and monitor_ativo and worker_ativo and eve_ativo:
        return {
            "instalado": True,
            "configurado": True,
            "ativo": True,
            "monitor_ativo": True,
            "worker_ativo": True,
            "eve_ativo": True,
            "versao": versao,
            "status": "operacional",
            "acao": "painel",
        }

    # ESTADO 4 — INSTALADO COM PROBLEMA
    return {
        "instalado": True,
        "configurado": True,
        "ativo": suricata_ativo,
        "monitor_ativo": monitor_ativo,
        "worker_ativo": worker_ativo,
        "eve_ativo": eve_ativo,
        "versao": versao,
        "status": "atencao",
        "acao": "painel",
    }


def _obter_estado_firewall(modo_api):
    """
    Retorna o status placeholder do Firewall local (nftables).
    """
    if modo_api == "simulacao":
        return {
            "disponivel": False,
            "configurado": False,
            "ativo": False,
            "status": "simulado",
        }

    return {
        "disponivel": False,
        "configurado": False,
        "ativo": False,
        "status": "em_breve",
    }


# ─────────────────────────────────────────────────────────────────────────────
# 05. PÁGINA PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

def configuracoes_view(request):
    """
    Renderiza a página principal de configurações.
    """
    cfg = ConfigSistema.get_solo()
    modo_api = _normalizar_modo_para_api(cfg.modo)

    context = {
        "titulo_pagina": "Configurações — MoonShield",
        "modo_atual": cfg.modo,
        "modo_api": modo_api,
        "modo_demo": (modo_api == "simulacao"),
        "modo_operacional": (modo_api == "real"),
        "modo_label": (
            "Modo Real" if modo_api == "real" else "Modo Simulação"
        ),
    }
    return render(request, "configuracoes/configuracoes.html", context)


# ─────────────────────────────────────────────────────────────────────────────
# 06. CONFIG API (GET / POST SALVAR)
# ─────────────────────────────────────────────────────────────────────────────

@require_GET
def api_get_config(request):
    """
    Retorna as configurações atuais do sistema em JSON.
    """
    cfg = ConfigSistema.get_solo()
    data = cfg.to_dict()
    data["modo_api"] = _normalizar_modo_para_api(cfg.modo)
    return JsonResponse({"ok": True, "config": data})


@require_POST
def api_salvar_config(request):
    """
    Salva as alterações das configurações globais do sistema.
    """
    try:
        data = json.loads(request.body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        return JsonResponse({"ok": False, "erro": f"JSON inválido: {e}"}, status=400)

    cfg = ConfigSistema.get_solo()

    # Normalização do Modo Global
    modo_input = data.get("modo", cfg.modo)
    modo_normalizado = _normalizar_modo_para_banco(modo_input)
    cfg.modo = modo_normalizado

    # Identidade do Node
    node = data.get("node", {})
    cfg.node_name = node.get("name", cfg.node_name)
    cfg.node_ambiente = node.get("ambiente", cfg.node_ambiente)
    cfg.node_tag = node.get("tag", cfg.node_tag)
    cfg.node_desc = node.get("desc", cfg.node_desc)

    # Rede Monitorada
    rede = data.get("rede", {})
    cfg.cidr = rede.get("cidr", cfg.cidr)
    cfg.gateway = rede.get("gateway", cfg.gateway)
    cfg.dns1 = rede.get("dns1", cfg.dns1)
    cfg.dns2 = rede.get("dns2", cfg.dns2)
    cfg.ips_criticos = rede.get("ips_criticos", cfg.ips_criticos)
    cfg.excluir_scan = rede.get("excluir", cfg.excluir_scan)
    cfg.iface_principal = rede.get("iface_principal", cfg.iface_principal)

    # Scanner
    scanner = data.get("scanner", {})
    cfg.scan_interval = int(scanner.get("interval", cfg.scan_interval))
    cfg.ping_timeout = int(scanner.get("pingTimeout", cfg.ping_timeout))
    cfg.max_hosts = int(scanner.get("maxHosts", cfg.max_hosts))
    cfg.scan_method = scanner.get("method", cfg.scan_method)
    cfg.scan_hostname = bool(scanner.get("hostname", cfg.scan_hostname))
    cfg.scan_mac = bool(scanner.get("mac", cfg.scan_mac))
    cfg.scan_oui = bool(scanner.get("oui", cfg.scan_oui))

    # Retenção
    ret = data.get("retencao", {})
    cfg.ret_devices = int(ret.get("devices", cfg.ret_devices))
    cfg.ret_logs = int(ret.get("logs", cfg.ret_logs))
    cfg.ret_dns = int(ret.get("dns", cfg.ret_dns))
    cfg.ret_incidents = int(ret.get("incidents", cfg.ret_incidents))

    # Providers
    providers = data.get("providers", {})
    dns = providers.get("dns", {})
    ids = providers.get("ids", {})
    fw = providers.get("fw", {})

    if modo_normalizado == "demo":
        cfg.dns_enabled = False
        cfg.ids_enabled = False
        cfg.fw_enabled = False

        cfg.adguard_mode = "mock"
        cfg.suricata_mode = "mock"
        cfg.fw_mode = "mock"
    else:
        # DNS / AdGuard
        cfg.dns_enabled = bool(dns.get("active", cfg.dns_enabled))
        cfg.adguard_mode = dns.get(
            "mode", cfg.adguard_mode if cfg.adguard_mode != "mock" else "real"
        )
        cfg.adguard_url = dns.get("url", cfg.adguard_url)
        cfg.adguard_user = dns.get("user", cfg.adguard_user)
        cfg.adguard_https = bool(dns.get("https", cfg.adguard_https))
        cfg.adguard_interval = int(dns.get("interval", cfg.adguard_interval))

        if dns.get("pass"):
            cfg.adguard_pass = dns["pass"]

        # IDS / Suricata
        cfg.ids_enabled = bool(ids.get("active", cfg.ids_enabled))
        cfg.suricata_mode = ids.get(
            "mode", cfg.suricata_mode if cfg.suricata_mode != "mock" else "eve"
        )
        cfg.suricata_eve_path = ids.get("evePath", cfg.suricata_eve_path)
        cfg.suricata_interval = int(ids.get("interval", cfg.suricata_interval))
        cfg.suricata_min_severity = int(ids.get("minSeverity", cfg.suricata_min_severity))

        # Firewall
        cfg.fw_enabled = bool(fw.get("active", cfg.fw_enabled))
        cfg.fw_mode = fw.get(
            "mode", cfg.fw_mode if cfg.fw_mode != "mock" else "nftables"
        )
        cfg.fw_target = fw.get("target", cfg.fw_target)
        cfg.fw_host = fw.get("host", cfg.fw_host)
        cfg.fw_agente_porta = int(fw.get("agente_porta", cfg.fw_agente_porta))

        if fw.get("token"):
            cfg.fw_token = fw["token"]

    # Segurança
    seg = data.get("seguranca", {})
    cfg.session_expiry = int(seg.get("sessionExpiry", cfg.session_expiry))
    cfg.max_login_attempts = int(seg.get("maxLoginAttempts", cfg.max_login_attempts))
    cfg.force_https = bool(seg.get("forceHttps", cfg.force_https))
    cfg.access_log = bool(seg.get("accessLog", cfg.access_log))
    cfg.ip_ban = bool(seg.get("ipBan", cfg.ip_ban))
    if seg.get("logLevel") in ("DEBUG", "INFO", "WARNING", "ERROR"):
        cfg.log_level = seg["logLevel"]

    cfg.save()

    modo_api = _normalizar_modo_para_api(cfg.modo)

    return JsonResponse(
        {
            "ok": True,
            "modo": modo_api,
            "modo_banco": cfg.modo,
            "modo_label": "Modo Real" if modo_api == "real" else "Modo Simulação",
            "updated_at": cfg.updated_at.isoformat(),
            "msg": (
                "Modo Real salvo. Configure cada componente individualmente."
                if modo_api == "real"
                else "Modo Simulação salvo. Integrações reais desativadas."
            ),
        }
    )


# ─────────────────────────────────────────────────────────────────────────────
# 07. SERVIÇOS API
# ─────────────────────────────────────────────────────────────────────────────

@require_GET
def api_servicos(request):
    """
    API agregadora principal para o status de todos os serviços monitorados.
    """
    cfg = ConfigSistema.get_solo()
    modo_api = _normalizar_modo_para_api(cfg.modo)

    servicos = {
        "adguard": _obter_estado_adguard(cfg),
        "suricata": _obter_estado_suricata(modo_api),
        "firewall": _obter_estado_firewall(modo_api),
    }

    return JsonResponse(
        {
            "ok": True,
            "modo": modo_api,
            "servicos": servicos,
        }
    )


# ─────────────────────────────────────────────────────────────────────────────
# 08. SYSINFO
# ─────────────────────────────────────────────────────────────────────────────

@require_GET
def api_sysinfo(request):
    """
    Retorna informações detalhadas do sistema operacional e hardware.
    """
    cfg = ConfigSistema.get_solo()
    modo_api = _normalizar_modo_para_api(cfg.modo)

    try:
        ifaces = get_interfaces()
        primary = next((i for i in ifaces if i.get("principal")), ifaces[0] if ifaces else None)
        ip_local = primary["ip"] if primary else "—"
    except Exception:
        ip_local = "—"

    info = get_sysinfo_real(ip_local_principal=ip_local)
    info["modo"] = modo_api
    info["modo_label"] = "Modo Real" if modo_api == "real" else "Modo Simulação"

    cfg.detected_sysinfo = info
    cfg.detected_at = timezone.now()
    cfg.save(update_fields=["detected_sysinfo", "detected_at"])

    return JsonResponse({"ok": True, "sysinfo": info})


# ─────────────────────────────────────────────────────────────────────────────
# 09. REDE
# ─────────────────────────────────────────────────────────────────────────────

@require_GET
def api_interfaces(request):
    """
    Retorna as interfaces de rede detectadas na máquina.
    """
    cfg = ConfigSistema.get_solo()
    modo_api = _normalizar_modo_para_api(cfg.modo)

    try:
        ifaces = get_interfaces()
    except Exception as e:
        logger.exception("Erro ao obter interfaces de rede: %s", e)
        return JsonResponse({"ok": False, "erro": str(e)}, status=500)

    cfg.detected_interfaces = ifaces
    cfg.save(update_fields=["detected_interfaces"])

    return JsonResponse(
        {
            "ok": True,
            "interfaces": ifaces,
            "modo": modo_api,
            "modo_label": "Modo Real" if modo_api == "real" else "Modo Simulação",
        }
    )


@require_POST
def api_auto_discover(request):
    """
    Executa a autodiscoberta de configurações de rede local.
    """
    try:
        data = auto_discover()
        if not data.get("ok"):
            return JsonResponse(data, status=503)
        return JsonResponse(data)
    except Exception as e:
        logger.exception("Erro na autodiscoberta de rede: %s", e)
        return JsonResponse({"ok": False, "erro": str(e)}, status=500)


# ─────────────────────────────────────────────────────────────────────────────
# 10. QUICK TESTS
# ─────────────────────────────────────────────────────────────────────────────

@require_GET
def api_quick_test(request):
    """
    Executa testes rápidos de conectividade na máquina (Ping, DNS, Latência, Internet).
    Sempre executados em tempo real independente do modo global.
    """
    test = request.GET.get("test", "")
    cfg = ConfigSistema.get_solo()

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
# 11. COMPATIBILIDADE LEGADA
# ─────────────────────────────────────────────────────────────────────────────

@require_GET
def api_sensor_status(request):
    """
    Endpoint de compatibilidade para listar instâncias de Sensor cadastradas.
    Nota: Não deve ser utilizado como verificação de health da stack local do Suricata.
    """
    try:
        from incidentes.models import Sensor

        sensores = Sensor.objects.all().order_by('-last_seen', 'nome')

        lista = []
        for s in sensores:
            segundos = s.segundos_desde_ultimo_evento
            lista.append({
                "id": s.id,
                "nome": s.nome,
                "ip": s.ip,
                "ativo": s.ativo,
                "online": s.online,
                "last_seen": s.last_seen.isoformat() if s.last_seen else None,
                "segundos_atras": segundos,
                "criado_em": s.criado_em.isoformat() if getattr(s, "criado_em", None) else None,
            })

        total_online = sum(1 for s in lista if s["online"])

        return JsonResponse({
            "ok": True,
            "total": len(lista),
            "online": total_online,
            "sensores": lista,
        })

    except Exception as exc:
        logger.exception("Erro na consulta legada de sensores: %s", exc)
        return JsonResponse({"ok": False, "erro": str(exc)}, status=500)


@require_GET
def api_fw_sensor_status(request):
    """
    Endpoint de compatibilidade temporário mantido para preservar rotas existentes.
    """
    return JsonResponse({
        "ok": True,
        "total": 0,
        "online": 0,
        "sensores": [],
        "msg": "Módulo de firewall remoto legado descontinuado. O firewall local utilizará nftables diretamente.",
    })


@require_POST
def api_testar_agente(request):
    """
    Stub de compatibilidade para a rota legada do agente remoto na porta 8765.
    Não executa HTTP externo nem levanta exceções.
    """
    return JsonResponse({
        "ok": False,
        "status": "descontinuado",
        "msg": "O agente HTTP remoto (:8765) foi descontinuado. A nova arquitetura utiliza firewall local via nftables.",
    })


@require_POST
def api_testar_provider(request):
    """
    Endpoint de teste individual de provider.
    """
    try:
        data = json.loads(request.body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return JsonResponse({"ok": False, "erro": "JSON inválido."}, status=400)

    provider = data.get("provider")
    cfg = ConfigSistema.get_solo()
    modo_api = _normalizar_modo_para_api(cfg.modo)

    if modo_api == "simulacao":
        label = {"dns": "AdGuard", "ids": "Suricata IDS", "fw": "Firewall"}.get(provider, provider)
        return JsonResponse({
            "ok": True,
            "status": "simulado",
            "msg": f"{label} — Modo Simulação ativo. Ative o Modo Real para testar a integração.",
        })

    if provider == "dns":
        result = _testar_dns(cfg)
    elif provider == "ids":
        estado = _obter_estado_suricata(modo_api)
        result = {
            "ok": estado.get("ativo", False),
            "status": estado.get("status", "desconhecido"),
            "msg": f"Suricata status: {estado.get('status')}",
            "detalhes": estado,
        }
    elif provider == "fw":
        estado = _obter_estado_firewall(modo_api)
        result = {
            "ok": False,
            "status": estado.get("status", "em_breve"),
            "msg": "Firewall local nftables será suportado em atualização futura.",
            "detalhes": estado,
        }
    else:
        return JsonResponse({"ok": False, "erro": "Provider inválido."}, status=400)

    return JsonResponse(result)


# ─────────────────────────────────────────────────────────────────────────────
# 12. TESTES ADGUARD
# ─────────────────────────────────────────────────────────────────────────────

def _testar_dns(cfg):
    """
    Testa a conexão real com a API do AdGuard Home.
    """
    if not cfg.adguard_url:
        return {"ok": False, "msg": "URL do AdGuard não configurada."}

    url = cfg.adguard_url.rstrip('/') + '/control/status'
    
    try:
        req = urllib.request.Request(url)
        
        if cfg.adguard_user and cfg.adguard_pass:
            import base64
            credentials = f"{cfg.adguard_user}:{cfg.adguard_pass}"
            encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
            req.add_header("Authorization", f"Basic {encoded_credentials}")

        ctx = ssl.create_default_context()

        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            if resp.status == 200:
                return {
                    "ok": True,
                    "status": "operacional",
                    "msg": "Conexão com AdGuard Home realizada com sucesso.",
                }
            return {
                "ok": False,
                "status": "erro",
                "msg": f"AdGuard retornou HTTP Status {resp.status}.",
            }

    except urllib.error.HTTPError as e:
        return {"ok": False, "status": "erro", "msg": f"Erro HTTP AdGuard: {e.code} - {e.reason}"}
    except urllib.error.URLError as e:
        return {"ok": False, "status": "erro", "msg": f"Falha na conexão com AdGuard: {e.reason}"}
    except Exception as e:
        logger.exception("Exceção ao testar AdGuard Home: %s", e)
        return {"ok": False, "status": "erro", "msg": f"Erro inesperado: {str(e)}"}