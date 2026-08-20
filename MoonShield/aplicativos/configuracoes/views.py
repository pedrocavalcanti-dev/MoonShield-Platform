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

# -----------------------------------------------------------------------------
# 04. HELPERS DE SERVIÇOS
# -----------------------------------------------------------------------------

def _obter_estado_adguard(cfg):
    """
    Retorna o estado consolidado do AdGuard Home.

    Regras:
    - Modo Simulação nunca tenta representar integração real.
    - Modo Real informa se o conector está configurado/ativado.
    - A conexão real continua sendo validada pela ação de teste do provider.
    """

    modo_api = _normalizar_modo_para_api(cfg.modo)

    if modo_api == "simulacao":
        return {
            "tipo": "adguard",
            "nome": "AdGuard Home",
            "modo": "simulacao",
            "fonte": "simulada",

            "disponivel": True,
            "configurado": False,
            "conectado": False,
            "ativo": False,
            "saudavel": False,

            "status": "simulado",
            "status_label": "Simulado",

            "url": cfg.adguard_url or None,
            "ultima_verificacao": None,
        }

    configurado = bool(
        cfg.adguard_url
    )

    ativo = bool(
        cfg.dns_enabled
    )

    operacional = bool(
        configurado
        and ativo
    )

    return {
        "tipo": "adguard",
        "nome": "AdGuard Home",
        "modo": "real",
        "fonte": "remota",

        "disponivel": True,
        "configurado": configurado,
        "conectado": operacional,
        "ativo": ativo,
        "saudavel": operacional,

        "status": (
            "operacional"
            if operacional
            else "desativado"
        ),

        "status_label": (
            "Operacional"
            if operacional
            else "Desativado"
        ),

        "url": (
            cfg.adguard_url
            or None
        ),

        "ultima_verificacao": None,
    }


def _estado_suricata_base(
    *,
    modo,
    status,
    status_label,
    acao,
    instalado=False,
    configurado=False,
    onboarding_concluido=False,
    instalacao_concluida=False,
    ativo=False,
    monitor_ativo=False,
    worker_ativo=False,
    eve_ativo=False,
    versao=None,
    saudavel=False,
    erro="",
):
    """
    Monta o contrato único de estado do Suricata.

    O objetivo é impedir que cada tela do frontend tente descobrir
    por conta própria se o Suricata está instalado, ativo ou saudável.

    Toda decisão operacional deve nascer no backend.
    """

    return {
        "tipo": "suricata",
        "nome": "Suricata IDS",

        "modo": modo,

        # Suricata é um componente local deste host.
        "fonte": (
            "simulada"
            if modo == "simulacao"
            else "local"
        ),

        # Estado de instalação / preparação.
        "instalado": bool(
            instalado
        ),

        "configurado": bool(
            configurado
        ),

        "onboarding_concluido": bool(
            onboarding_concluido
        ),

        "instalacao_concluida": bool(
            instalacao_concluida
        ),

        # Componentes operacionais.
        "ativo": bool(
            ativo
        ),

        "monitor_ativo": bool(
            monitor_ativo
        ),

        "worker_ativo": bool(
            worker_ativo
        ),

        "eve_ativo": bool(
            eve_ativo
        ),

        # Saúde consolidada.
        "saudavel": bool(
            saudavel
        ),

        # Estado já decidido pelo backend.
        "status": status,
        "status_label": status_label,

        # Ação que o frontend deve executar.
        "acao": acao,

        # Informações auxiliares.
        "versao": versao,

        "erro": (
            erro
            or ""
        ),

        # Estrutura pronta para cards/resumos.
        "componentes": {
            "suricata": {
                "ativo": bool(
                    ativo
                ),
            },

            "monitor": {
                "ativo": bool(
                    monitor_ativo
                ),
            },

            "worker": {
                "ativo": bool(
                    worker_ativo
                ),
            },

            "eve": {
                "ativo": bool(
                    eve_ativo
                ),
            },
        },
    }


def _obter_estado_suricata(
    modo_api,
):
    """
    Retorna o estado consolidado do Suricata local.

    IMPORTANTE:

    Esta função é a fonte de verdade do Suricata para o módulo
    Configurações.

    Ela NÃO:

    - executa diagnóstico profundo;
    - executa suricata -T;
    - instala componentes;
    - reinicia serviços.

    Apenas consulta o estado operacional rápido já implementado no
    módulo incidentes.services.suricata.status.
    """

    # ------------------------------------------------------------------
    # MODO SIMULAÇÃO
    # ------------------------------------------------------------------

    if modo_api == "simulacao":
        return _estado_suricata_base(
            modo="simulacao",

            status="simulado",
            status_label="Simulado",

            acao="painel_simulado",

            instalado=False,
            configurado=False,

            onboarding_concluido=False,
            instalacao_concluida=False,

            ativo=False,
            monitor_ativo=False,
            worker_ativo=False,
            eve_ativo=False,

            versao=None,

            saudavel=False,
        )

    # ------------------------------------------------------------------
    # MODO REAL — IMPORT DO MÓDULO
    # ------------------------------------------------------------------

    if not ConfiguracaoSuricata:
        logger.error(
            "ConfiguracaoSuricata não está disponível para import."
        )

        return _estado_suricata_base(
            modo="real",

            status="erro",
            status_label="Erro",

            acao="instalar",

            saudavel=False,

            erro=(
                "Módulo ConfiguracaoSuricata "
                "não pôde ser carregado."
            ),
        )

    # ------------------------------------------------------------------
    # CARREGA CONFIGURAÇÃO DO SENSOR
    # ------------------------------------------------------------------

    try:
        cfg_suricata = (
            ConfiguracaoSuricata.objects
            .filter(ativo=True)
            .order_by("-atualizado_em")
            .first()
        )

    except Exception as exc:
        logger.exception(
            "Erro ao obter configuração ativa do Suricata: %s",
            exc,
        )

        return _estado_suricata_base(
            modo="real",

            status="erro",
            status_label="Erro",

            acao="painel",

            saudavel=False,

            erro=str(
                exc
            ),
        )

    # ------------------------------------------------------------------
    # NÃO INSTALADO
    # ------------------------------------------------------------------

    instalado = bool(
        cfg_suricata
        and getattr(
            cfg_suricata,
            "suricata_instalado",
            False,
        )
    )

    if not instalado:
        return _estado_suricata_base(
            modo="real",

            status="nao_instalado",
            status_label="Não instalado",

            acao="instalar",

            instalado=False,

            saudavel=False,
        )

    # ------------------------------------------------------------------
    # ESTADO PERSISTIDO
    # ------------------------------------------------------------------

    onboarding_concluido = bool(
        getattr(
            cfg_suricata,
            "onboarding_concluido",
            False,
        )
    )

    instalacao_concluida = bool(
        getattr(
            cfg_suricata,
            "instalacao_concluida",
            False,
        )
    )

    configurado = bool(
        getattr(
            cfg_suricata,
            "suricata_configurado",
            False,
        )
    )

    versao_persistida = getattr(
        cfg_suricata,
        "versao_suricata",
        None,
    )

    # ------------------------------------------------------------------
    # INSTALADO MAS ONBOARDING/INSTALAÇÃO NÃO CONCLUÍDOS
    # ------------------------------------------------------------------

    if (
        not onboarding_concluido
        or not instalacao_concluida
    ):
        return _estado_suricata_base(
            modo="real",

            status="configuracao_pendente",
            status_label="Configuração pendente",

            acao="continuar_instalacao",

            instalado=True,
            configurado=configurado,

            onboarding_concluido=(
                onboarding_concluido
            ),

            instalacao_concluida=(
                instalacao_concluida
            ),

            versao=versao_persistida,

            saudavel=False,
        )

    # ------------------------------------------------------------------
    # CONSULTA RÁPIDA DA STACK REAL
    # ------------------------------------------------------------------

    try:
        if not obter_status_stack_completo:
            raise RuntimeError(
                "obter_status_stack_completo "
                "não está disponível."
            )

        status_stack = (
            obter_status_stack_completo(
                incluir_diagnostico=False
            )
            or {}
        )

        if not isinstance(
            status_stack,
            dict,
        ):
            logger.warning(
                "Status Suricata retornou formato inesperado: %s",
                type(
                    status_stack
                ).__name__,
            )

            status_stack = {}

    except Exception as exc:
        logger.exception(
            "Erro ao consultar status rápido do Suricata: %s",
            exc,
        )

        return _estado_suricata_base(
            modo="real",

            status="atencao",
            status_label="Requer atenção",

            acao="painel",

            instalado=True,
            configurado=configurado,

            onboarding_concluido=(
                onboarding_concluido
            ),

            instalacao_concluida=(
                instalacao_concluida
            ),

            ativo=False,
            monitor_ativo=False,
            worker_ativo=False,
            eve_ativo=False,

            versao=versao_persistida,

            saudavel=False,

            erro=(
                "Não foi possível consultar "
                "o estado operacional da stack."
            ),
        )

    # ------------------------------------------------------------------
    # COMPONENTES DA STACK
    # ------------------------------------------------------------------

    suricata_info = status_stack.get(
        "suricata",
        {},
    )

    monitor_info = status_stack.get(
        "monitor",
        {},
    )

    servicos_info = status_stack.get(
        "servicos",
        {},
    )

    if not isinstance(
        suricata_info,
        dict,
    ):
        suricata_info = {}

    if not isinstance(
        monitor_info,
        dict,
    ):
        monitor_info = {}

    if not isinstance(
        servicos_info,
        dict,
    ):
        servicos_info = {}

    worker_info = servicos_info.get(
        "worker_tarefas",
        {},
    )

    if not isinstance(
        worker_info,
        dict,
    ):
        worker_info = {}

    eve_info = suricata_info.get(
        "eve",
        {},
    )

    if not isinstance(
        eve_info,
        dict,
    ):
        eve_info = {}

    # ------------------------------------------------------------------
    # MOTOR SURICATA
    # ------------------------------------------------------------------

    suricata_ativo = bool(
        suricata_info.get(
            "ativo",
            False,
        )
    )

    # ------------------------------------------------------------------
    # MONITOR MOONSHIELD
    # ------------------------------------------------------------------

    monitor_ativo = bool(
        monitor_info.get(
            "ativo",
            False,
        )
    )

    # ------------------------------------------------------------------
    # WORKER DE TAREFAS
    # ------------------------------------------------------------------

    worker_ativo = bool(
        worker_info.get(
            "ativo",
            False,
        )
    )

    # ------------------------------------------------------------------
    # EVE
    # ------------------------------------------------------------------

    eve_ativo = bool(
        eve_info.get(
            "existe",
            False,
        )
        and eve_info.get(
            "legivel",
            False,
        )
        and eve_info.get(
            "atualizando",
            False,
        )
    )

    # ------------------------------------------------------------------
    # VERSÃO
    # ------------------------------------------------------------------

    versao = (
        suricata_info.get(
            "versao"
        )
        or versao_persistida
    )

    # ------------------------------------------------------------------
    # CONFIGURAÇÃO
    # ------------------------------------------------------------------

    configurado = bool(
        configurado
        or status_stack.get(
            "configurado",
            False,
        )
    )

    # ------------------------------------------------------------------
    # SAÚDE CONSOLIDADA
    # ------------------------------------------------------------------

    saudavel = bool(
        instalado
        and configurado
        and onboarding_concluido
        and instalacao_concluida
        and suricata_ativo
        and monitor_ativo
        and worker_ativo
        and eve_ativo
    )

    # ------------------------------------------------------------------
    # OPERACIONAL
    # ------------------------------------------------------------------

    if saudavel:
        return _estado_suricata_base(
            modo="real",

            status="operacional",
            status_label="Operacional",

            acao="painel",

            instalado=True,
            configurado=True,

            onboarding_concluido=True,
            instalacao_concluida=True,

            ativo=True,
            monitor_ativo=True,
            worker_ativo=True,
            eve_ativo=True,

            versao=versao,

            saudavel=True,
        )

    # ------------------------------------------------------------------
    # INSTALADO, MAS ALGUM COMPONENTE PRECISA DE ATENÇÃO
    # ------------------------------------------------------------------

    return _estado_suricata_base(
        modo="real",

        status="atencao",
        status_label="Requer atenção",

        acao="painel",

        instalado=True,

        configurado=(
            configurado
        ),

        onboarding_concluido=(
            onboarding_concluido
        ),

        instalacao_concluida=(
            instalacao_concluida
        ),

        ativo=(
            suricata_ativo
        ),

        monitor_ativo=(
            monitor_ativo
        ),

        worker_ativo=(
            worker_ativo
        ),

        eve_ativo=(
            eve_ativo
        ),

        versao=(
            versao
        ),

        saudavel=False,
    )


def _obter_estado_firewall(
    modo_api,
):
    """
    Retorna o estado consolidado do Firewall.

    A integração nftables ainda não foi implementada.
    Portanto o backend deve ser explícito e nunca apresentar
    o Firewall como operacional artificialmente.
    """

    if modo_api == "simulacao":
        return {
            "tipo": "firewall",
            "nome": "Firewall",

            "modo": "simulacao",
            "fonte": "simulada",

            "disponivel": False,
            "configurado": False,
            "ativo": False,
            "saudavel": False,

            "status": "simulado",
            "status_label": "Simulado",

            "ultima_verificacao": None,
        }

    return {
        "tipo": "firewall",
        "nome": "Firewall",

        "modo": "real",
        "fonte": "local",

        "disponivel": False,
        "configurado": False,
        "ativo": False,
        "saudavel": False,

        "status": "em_breve",
        "status_label": "Em desenvolvimento",

        "ultima_verificacao": None,
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
    API agregadora principal dos serviços do MoonShield.

    Esta rota é a fonte de verdade para a tela de Configurações.

    Em Modo Simulação:
        retorna estados simulados.

    Em Modo Real:
        AdGuard   -> integração remota;
        Suricata  -> stack Linux local real;
        Firewall  -> placeholder nftables enquanto não implementado.

    IMPORTANTE:
        esta API nunca executa diagnóstico profundo,
        suricata -T, instalação ou reinício.
    """

    cfg = (
        ConfigSistema.get_solo()
    )

    modo_api = (
        _normalizar_modo_para_api(
            cfg.modo
        )
    )

    adguard = (
        _obter_estado_adguard(
            cfg
        )
    )

    suricata = (
        _obter_estado_suricata(
            modo_api
        )
    )

    firewall = (
        _obter_estado_firewall(
            modo_api
        )
    )

    servicos = {
        "adguard": adguard,
        "suricata": suricata,
        "firewall": firewall,
    }

    # ----------------------------------------------------------
    # RESUMO GLOBAL
    # ----------------------------------------------------------

    if modo_api == "simulacao":
        resumo = {
            "modo": "simulacao",

            "ids_operacional": False,
            "dns_operacional": False,
            "firewall_operacional": False,

            "ids_saudavel": False,

            "servicos_operacionais": 0,

            "status": "simulado",
        }

    else:
        ids_operacional = bool(
            suricata.get(
                "status"
            ) == "operacional"
            and suricata.get(
                "saudavel",
                False,
            )
        )

        dns_operacional = bool(
            adguard.get(
                "status"
            ) == "operacional"
            and adguard.get(
                "saudavel",
                False,
            )
        )

        firewall_operacional = bool(
            firewall.get(
                "status"
            ) == "operacional"
            and firewall.get(
                "saudavel",
                False,
            )
        )

        servicos_operacionais = sum(
            [
                ids_operacional,
                dns_operacional,
                firewall_operacional,
            ]
        )

        resumo = {
            "modo": "real",

            "ids_operacional": (
                ids_operacional
            ),

            "dns_operacional": (
                dns_operacional
            ),

            "firewall_operacional": (
                firewall_operacional
            ),

            "ids_saudavel": bool(
                suricata.get(
                    "saudavel",
                    False,
                )
            ),

            "servicos_operacionais": (
                servicos_operacionais
            ),

            "status": (
                "operacional"
                if ids_operacional
                else "atencao"
            ),
        }

    return JsonResponse(
        {
            "ok": True,

            "modo": (
                modo_api
            ),

            "modo_label": (
                "Modo Real"
                if modo_api == "real"
                else "Modo Simulação"
            ),

            "servicos": (
                servicos
            ),

            "resumo": (
                resumo
            ),

            "atualizado_em": (
                timezone.now().isoformat()
            ),
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

        operacional = bool(
            estado.get("status") == "operacional"
            and estado.get("saudavel", False)
        )

        result = {
            "ok": operacional,
            "status": estado.get(
                "status",
                "desconhecido",
            ),
            "msg": (
                "Suricata local operacional e integrado ao MoonShield."
                if operacional
                else (
                    estado.get("erro")
                    or "A stack local do Suricata requer atenção."
                )
            ),
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