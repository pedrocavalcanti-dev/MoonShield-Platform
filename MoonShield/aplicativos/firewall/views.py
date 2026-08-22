"""
MoonShield Platform — Firewall / Views
======================================

Views da nova arquitetura local do Firewall.

Fluxo privilegiado:

    Browser
      ↓
    Django views
      ↓
    services/
      ↓
    agent_client.py
      ↓
    /run/moonshield/agent.sock
      ↓
    MoonShield-Agent
      ↓
    nftables

Fluxo de eventos:

    nftables
      ↓
    MoonShield-Agent monitor
      ↓
    /var/log/moonshield/firewall/events.jsonl
      ↓
    processar_eventos_firewall
      ↓
    EventoFirewall

IMPORTANTE:
- nenhuma view executa `nft`;
- nenhuma view acessa porta 8765;
- nenhuma view usa Sensor/token para Firewall;
- não existem endpoints de pending/confirm/ingest do Agent.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Callable

from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.db import transaction
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.decorators.http import (
    require_GET,
    require_http_methods,
    require_POST,
)

from .auxiliares import (
    allow_to_dict,
    block_to_dict,
    demo_data,
    evento_to_log,
    geo_to_dict,
    get_modo,
    nat_to_dict,
    prod_data,
    prod_waiting,
    regra_para_nft_inline,
    rule_to_dict,
    sync_status,
    validar_regra_segura,
)
from .models import (
    AllowlistEntry,
    BlocklistEntry,
    ConfiguracaoFirewall,
    EventoFirewall,
    GeoblockEntry,
    NatEntry,
    RegraFirewall,
    TarefaFirewall,
)
from .services import agent_client
from .services.firewall_install import (
    desinstalar_firewall,
    instalar_firewall,
    precheck_instalacao,
    reparar_firewall,
)
from .services.firewall_rules import (
    aplicar_regras_pendentes,
    bloquear_ip as service_bloquear_ip,
    liberar_ip as service_liberar_ip,
    obter_emergency_linux,
    obter_regras_linux,
    rollback as service_rollback,
)
from .services.firewall_status import (
    obter_diagnostico,
    obter_estado_firewall,
    obter_interfaces,
)


logger = logging.getLogger(__name__)


LOGIN_URL = "autenticacao:login"


# =============================================================================
# PÁGINAS HTML
# =============================================================================

@login_required(login_url=LOGIN_URL)
def firewall_view(request):
    return render(
        request,
        "firewall/firewall.html",
    )


@login_required(login_url=LOGIN_URL)
def feed_view(request):
    return render(
        request,
        "firewall/feed.html",
    )


@login_required(login_url=LOGIN_URL)
def regras_view(request):
    return render(
        request,
        "firewall/regras.html",
    )


@login_required(login_url=LOGIN_URL)
def instalacao_view(request):
    return render(
        request,
        "firewall/instalacao.html",
        {
            "precheck": precheck_instalacao(),
        },
    )


# =============================================================================
# HELPERS — JSON / ERROS
# =============================================================================

def _json_body(
    request,
    *,
    aceitar_vazio: bool = True,
) -> tuple[dict[str, Any] | None, JsonResponse | None]:
    raw = request.body or b""

    if not raw.strip():
        if aceitar_vazio:
            return {}, None

        return None, JsonResponse(
            {
                "ok": False,
                "erro": "Corpo JSON obrigatório.",
            },
            status=400,
        )

    try:
        dados = json.loads(
            raw.decode("utf-8")
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ):
        return None, JsonResponse(
            {
                "ok": False,
                "erro": "JSON inválido.",
            },
            status=400,
        )

    if not isinstance(
        dados,
        dict,
    ):
        return None, JsonResponse(
            {
                "ok": False,
                "erro": "O JSON deve ser um objeto.",
            },
            status=400,
        )

    return dados, None


def _bool(
    valor: Any,
    *,
    default: bool = False,
) -> bool:
    if valor is None:
        return default

    if isinstance(
        valor,
        bool,
    ):
        return valor

    return str(
        valor
    ).strip().lower() in {
        "1",
        "true",
        "yes",
        "sim",
        "on",
        "ativo",
        "enabled",
    }


def _int(
    valor: Any,
    *,
    default: int,
    minimo: int | None = None,
    maximo: int | None = None,
) -> int:
    try:
        numero = int(
            valor
        )
    except (
        TypeError,
        ValueError,
    ):
        numero = default

    if minimo is not None:
        numero = max(
            minimo,
            numero,
        )

    if maximo is not None:
        numero = min(
            maximo,
            numero,
        )

    return numero


def _validation_error_payload(
    exc: ValidationError,
) -> dict[str, Any]:
    if hasattr(
        exc,
        "message_dict",
    ):
        detalhes = exc.message_dict
    else:
        detalhes = {
            "non_field_errors": exc.messages,
        }

    return {
        "ok": False,
        "erro": "Dados inválidos.",
        "detalhes": detalhes,
    }


def _modo_real_obrigatorio() -> JsonResponse | None:
    if get_modo() == "demo":
        return JsonResponse(
            {
                "ok": False,
                "codigo": "modo_simulacao",
                "erro": (
                    "Esta operação modifica o Firewall real e só pode "
                    "ser executada no modo REAL."
                ),
            },
            status=409,
        )

    return None


# =============================================================================
# HELPERS — CONFIG / STATUS
# =============================================================================

def _persistir_estado(
    estado: dict[str, Any],
    *,
    erro: str = "",
) -> None:
    try:
        cfg = ConfiguracaoFirewall.get_solo()
        cfg.atualizar_status(
            estado,
            erro=erro,
        )
    except Exception:
        logger.exception(
            "Não foi possível persistir o estado consolidado do Firewall."
        )


def _sincronizar_config_topologia(
    *,
    interface_wan: str,
    interface_lan: str,
    interface_mgmt: str,
    home_net: str,
) -> ConfiguracaoFirewall:
    cfg = ConfiguracaoFirewall.get_solo()

    cfg.interface_wan = str(
        interface_wan
        or ""
    )[:32]

    cfg.interface_lan = str(
        interface_lan
        or ""
    )[:32]

    cfg.interface_mgmt = str(
        interface_mgmt
        or ""
    )[:32]

    cfg.home_net = str(
        home_net
        or ""
    )[:64]

    cfg.save(
        update_fields=[
            "interface_wan",
            "interface_lan",
            "interface_mgmt",
            "home_net",
            "atualizado_em",
        ]
    )

    return cfg


# =============================================================================
# HELPERS — TAREFAS
# =============================================================================

def _tarefa_to_dict(
    tarefa: TarefaFirewall,
) -> dict[str, Any]:
    return {
        "id": tarefa.id,
        "tipo": tarefa.tipo,
        "tipo_label": tarefa.get_tipo_display(),
        "status": tarefa.status,
        "status_label": tarefa.get_status_display(),
        "progresso": tarefa.progresso,
        "etapa_atual": tarefa.etapa_atual,
        "mensagem": tarefa.mensagem,
        "payload": tarefa.payload,
        "resultado": tarefa.resultado,
        "logs": tarefa.logs,
        "erro": tarefa.erro,
        "snapshot_id": tarefa.snapshot_id,
        "iniciado_em": (
            tarefa.iniciado_em.isoformat()
            if tarefa.iniciado_em
            else None
        ),
        "finalizado_em": (
            tarefa.finalizado_em.isoformat()
            if tarefa.finalizado_em
            else None
        ),
        "duracao_segundos": tarefa.duracao_segundos,
        "criado_em": tarefa.criado_em.isoformat(),
        "atualizado_em": tarefa.atualizado_em.isoformat(),
        "concluida": tarefa.concluida,
    }


def _extrair_snapshot_id(
    resultado: dict[str, Any],
) -> str:
    candidatos: list[Any] = [
        resultado.get(
            "snapshot_id"
        ),
    ]

    agent = resultado.get(
        "resultado_agent"
    )

    if isinstance(
        agent,
        dict,
    ):
        candidatos.append(
            agent.get(
                "snapshot_id"
            )
        )

    for item in candidatos:
        if item:
            return str(
                item
            )[:100]

    return ""


def _executar_tarefa_sincrona(
    *,
    tipo: str,
    payload: dict[str, Any],
    etapa: str,
    funcao: Callable[[], dict[str, Any]],
) -> tuple[TarefaFirewall, dict[str, Any]]:
    """
    Registro de tarefa já preparado para UI.

    Por enquanto a execução é síncrona.
    Quando criarmos um worker de TarefaFirewall, este contrato pode continuar.
    """
    tarefa = TarefaFirewall.objects.create(
        tipo=tipo,
        payload=payload,
    )

    tarefa.iniciar(
        etapa=etapa,
        mensagem="Operação iniciada.",
    )

    tarefa.adicionar_log(
        f"Iniciando: {etapa}"
    )

    try:
        resultado = funcao()

        if not isinstance(
            resultado,
            dict,
        ):
            resultado = {
                "ok": False,
                "erro": "Service retornou resposta inválida.",
            }

        snapshot_id = _extrair_snapshot_id(
            resultado
        )

        if snapshot_id:
            tarefa.snapshot_id = snapshot_id
            tarefa.save(
                update_fields=[
                    "snapshot_id",
                    "atualizado_em",
                ]
            )

        if resultado.get(
            "ok"
        ):
            tarefa.adicionar_log(
                "Operação concluída com sucesso."
            )

            tarefa.finalizar_sucesso(
                resultado=resultado,
                mensagem=str(
                    resultado.get(
                        "mensagem"
                    )
                    or "Operação concluída."
                ),
            )

        else:
            erro = str(
                resultado.get(
                    "erro"
                )
                or resultado.get(
                    "mensagem"
                )
                or "Operação falhou."
            )

            tarefa.adicionar_log(
                erro,
                nivel="erro",
            )

            tarefa.finalizar_erro(
                erro,
                resultado=resultado,
                mensagem="Operação não concluída.",
            )

        return tarefa, resultado

    except Exception as exc:
        logger.exception(
            "Erro inesperado executando tarefa Firewall %s",
            tipo,
        )

        resultado = {
            "ok": False,
            "codigo": "erro_interno",
            "erro": str(exc),
        }

        tarefa.adicionar_log(
            str(exc),
            nivel="erro",
        )

        tarefa.finalizar_erro(
            str(exc),
            resultado=resultado,
            mensagem="Erro interno.",
        )

        return tarefa, resultado


# =============================================================================
# API — DATA GERAL
# =============================================================================

@require_GET
@login_required(login_url=LOGIN_URL)
def api_fw_data(request):
    period = str(
        request.GET.get(
            "period",
            "24h",
        )
    )

    if get_modo() == "demo":
        return JsonResponse(
            demo_data(
                period
            )
        )

    try:
        has_data = EventoFirewall.objects.exists()
    except Exception:
        has_data = False

    dados = (
        prod_data(
            period
        )
        if has_data
        else prod_waiting()
    )

    return JsonResponse(
        dados
    )


# =============================================================================
# API — STATUS / DIAGNÓSTICO / INTERFACES
# =============================================================================

@require_GET
@login_required(login_url=LOGIN_URL)
def api_status(request):
    if get_modo() == "demo":
        return JsonResponse(
            {
                "ok": True,
                "fonte": "simulacao",
                "modo": "simulacao",
                "agent_ativo": False,
                "agent_disponivel": False,
                "instalado": False,
                "configurado": False,
                "ativo": False,
                "operacional": False,
                "saudavel": False,
                "status": "simulacao",
                "status_label": "Simulação",
            }
        )

    estado = obter_estado_firewall(
        incluir_detalhes=True
    )

    _persistir_estado(
        estado,
        erro=(
            (
                estado.get("erro")
                or {}
            ).get(
                "mensagem",
                "",
            )
            if isinstance(
                estado.get("erro"),
                dict,
            )
            else ""
        ),
    )

    return JsonResponse(
        estado,
        status=(
            200
            if estado.get("ok")
            else 503
        ),
    )


@require_GET
@login_required(login_url=LOGIN_URL)
def api_diagnostico(request):
    bloqueio = _modo_real_obrigatorio()

    if bloqueio:
        return bloqueio

    resultado = obter_diagnostico()

    try:
        cfg = ConfiguracaoFirewall.get_solo()
        cfg.ultimo_diagnostico = resultado
        cfg.save(
            update_fields=[
                "ultimo_diagnostico",
                "atualizado_em",
            ]
        )
    except Exception:
        logger.exception(
            "Falha ao persistir diagnóstico do Firewall."
        )

    return JsonResponse(
        resultado,
        status=(
            200
            if resultado.get("ok")
            else 503
        ),
    )


@require_GET
@login_required(login_url=LOGIN_URL)
def api_interfaces(request):
    if get_modo() == "demo":
        return JsonResponse(
            {
                "ok": True,
                "fonte": "simulacao",
                "interfaces": [
                    {
                        "nome": "WAN",
                        "ip": "203.0.113.10",
                        "rede": "203.0.113.0/24",
                        "up": True,
                        "papeis": [
                            "WAN"
                        ],
                    },
                    {
                        "nome": "MGMT",
                        "ip": "10.20.0.10",
                        "rede": "10.20.0.0/24",
                        "up": True,
                        "papeis": [
                            "MGMT"
                        ],
                    },
                    {
                        "nome": "LAN",
                        "ip": "10.10.0.1",
                        "rede": "10.10.0.0/24",
                        "up": True,
                        "papeis": [
                            "LAN"
                        ],
                    },
                ],
                "mapeamento": {
                    "WAN": "WAN",
                    "MGMT": "MGMT",
                    "LAN": "LAN",
                },
            }
        )

    resultado = obter_interfaces()

    return JsonResponse(
        resultado,
        status=(
            200
            if resultado.get("ok")
            else 503
        ),
    )


# =============================================================================
# API — FEED
# =============================================================================

@require_GET
@login_required(login_url=LOGIN_URL)
def api_fw_feed(request):
    limite = _int(
        request.GET.get(
            "limit",
            50,
        ),
        default=50,
        minimo=1,
        maximo=200,
    )

    if get_modo() == "demo":
        dados = demo_data(
            "24h"
        )

        return JsonResponse(
            {
                "ok": True,
                "mode": "demo",
                "modo": "simulacao",
                "interfaces": [
                    {
                        "nome": "WAN",
                        "ip": "203.0.113.10",
                        "up": True,
                    },
                    {
                        "nome": "MGMT",
                        "ip": "10.20.0.10",
                        "up": True,
                    },
                    {
                        "nome": "LAN",
                        "ip": "10.10.0.1",
                        "up": True,
                    },
                ],
                "eventos": dados.get(
                    "logs",
                    [],
                )[:limite],
            }
        )

    qs = EventoFirewall.objects.order_by(
        "-timestamp"
    )

    since = str(
        request.GET.get(
            "since",
            ""
        )
        or ""
    ).strip()

    if since:
        ts = parse_datetime(
            since
        )

        if ts is None:
            try:
                ts = datetime.fromisoformat(
                    since
                )
            except ValueError:
                ts = None

        if ts is not None:
            if timezone.is_naive(
                ts
            ):
                ts = timezone.make_aware(
                    ts
                )

            qs = qs.filter(
                timestamp__gt=ts
            )

    eventos = list(
        qs[:limite]
    )

    interfaces = obter_interfaces()

    payload_eventos = [
        evento_to_log(
            e
        )
        for e in reversed(
            eventos
        )
    ]

    return JsonResponse(
        {
            "ok": True,
            "mode": "prod",
            "modo": "real",
            "fonte": "local",
            "interfaces": interfaces.get(
                "interfaces",
                [],
            ),
            "eventos": payload_eventos,
        }
    )


# =============================================================================
# API — INSTALAÇÃO
# =============================================================================

@require_POST
@login_required(login_url=LOGIN_URL)
def api_install(request):
    bloqueio = _modo_real_obrigatorio()

    if bloqueio:
        return bloqueio

    dados, erro_response = _json_body(
        request
    )

    if erro_response:
        return erro_response

    interface_wan = str(
        dados.get(
            "interface_wan"
        )
        or dados.get(
            "wan"
        )
        or ""
    ).strip()

    interface_lan = str(
        dados.get(
            "interface_lan"
        )
        or dados.get(
            "lan"
        )
        or ""
    ).strip()

    interface_mgmt = str(
        dados.get(
            "interface_mgmt"
        )
        or dados.get(
            "mgmt"
        )
        or ""
    ).strip()

    home_net = str(
        dados.get(
            "home_net"
        )
        or ""
    ).strip()

    payload = {
        "interface_wan": interface_wan,
        "interface_lan": interface_lan,
        "interface_mgmt": interface_mgmt,
        "home_net": home_net,
        "instalar_pacote": _bool(
            dados.get(
                "instalar_pacote"
            ),
            default=True,
        ),
    }

    tarefa, resultado = _executar_tarefa_sincrona(
        tipo=TarefaFirewall.Tipo.INSTALAR,
        payload=payload,
        etapa="Instalando Firewall",
        funcao=lambda: instalar_firewall(
            **payload
        ),
    )

    if resultado.get(
        "ok"
    ):
        cfg = _sincronizar_config_topologia(
            interface_wan=interface_wan,
            interface_lan=interface_lan,
            interface_mgmt=interface_mgmt,
            home_net=home_net,
        )

        cfg.onboarding_concluido = True
        cfg.instalacao_concluida = True
        cfg.save(
            update_fields=[
                "onboarding_concluido",
                "instalacao_concluida",
                "atualizado_em",
            ]
        )

        estado = resultado.get(
            "estado"
        )

        if isinstance(
            estado,
            dict,
        ):
            _persistir_estado(
                estado
            )

    return JsonResponse(
        {
            "ok": bool(
                resultado.get(
                    "ok"
                )
            ),
            "tarefa": _tarefa_to_dict(
                tarefa
            ),
            "resultado": resultado,
        },
        status=(
            200
            if resultado.get("ok")
            else 400
        ),
    )


@require_POST
@login_required(login_url=LOGIN_URL)
def api_repair(request):
    bloqueio = _modo_real_obrigatorio()

    if bloqueio:
        return bloqueio

    dados, erro_response = _json_body(
        request
    )

    if erro_response:
        return erro_response

    payload = {
        "interface_wan": dados.get(
            "interface_wan"
        ),
        "interface_lan": dados.get(
            "interface_lan"
        ),
        "interface_mgmt": dados.get(
            "interface_mgmt"
        ),
        "home_net": dados.get(
            "home_net"
        ),
    }

    tarefa, resultado = _executar_tarefa_sincrona(
        tipo=TarefaFirewall.Tipo.REPARAR,
        payload=payload,
        etapa="Reparando Firewall",
        funcao=lambda: reparar_firewall(
            **payload
        ),
    )

    estado = resultado.get(
        "estado"
    )

    if (
        resultado.get("ok")
        and isinstance(
            estado,
            dict,
        )
    ):
        _persistir_estado(
            estado
        )

    return JsonResponse(
        {
            "ok": bool(
                resultado.get(
                    "ok"
                )
            ),
            "tarefa": _tarefa_to_dict(
                tarefa
            ),
            "resultado": resultado,
        },
        status=(
            200
            if resultado.get("ok")
            else 400
        ),
    )


@require_POST
@login_required(login_url=LOGIN_URL)
def api_uninstall(request):
    bloqueio = _modo_real_obrigatorio()

    if bloqueio:
        return bloqueio

    dados, erro_response = _json_body(
        request
    )

    if erro_response:
        return erro_response

    confirmar = _bool(
        dados.get(
            "confirmar"
        )
    )

    payload = {
        "confirmar": confirmar,
        "remover_config": _bool(
            dados.get(
                "remover_config"
            )
        ),
    }

    tarefa, resultado = _executar_tarefa_sincrona(
        tipo=TarefaFirewall.Tipo.DESINSTALAR,
        payload=payload,
        etapa="Desinstalando Firewall",
        funcao=lambda: desinstalar_firewall(
            **payload
        ),
    )

    if resultado.get(
        "ok"
    ):
        try:
            cfg = ConfiguracaoFirewall.get_solo()
            cfg.instalacao_concluida = False
            cfg.operacional = False
            cfg.ativo = False
            cfg.tabela_instalada = False
            cfg.save(
                update_fields=[
                    "instalacao_concluida",
                    "operacional",
                    "ativo",
                    "tabela_instalada",
                    "atualizado_em",
                ]
            )
        except Exception:
            logger.exception(
                "Falha atualizando ConfiguracaoFirewall após uninstall."
            )

    return JsonResponse(
        {
            "ok": bool(
                resultado.get(
                    "ok"
                )
            ),
            "tarefa": _tarefa_to_dict(
                tarefa
            ),
            "resultado": resultado,
        },
        status=(
            200
            if resultado.get("ok")
            else 400
        ),
    )


# =============================================================================
# API — TAREFAS
# =============================================================================

@require_GET
@login_required(login_url=LOGIN_URL)
def api_tasks(request):
    limite = _int(
        request.GET.get(
            "limit",
            20,
        ),
        default=20,
        minimo=1,
        maximo=100,
    )

    status_filtro = str(
        request.GET.get(
            "status",
            ""
        )
        or ""
    ).strip()

    qs = TarefaFirewall.objects.all()

    if status_filtro:
        qs = qs.filter(
            status=status_filtro
        )

    tarefas = [
        _tarefa_to_dict(
            tarefa
        )
        for tarefa in qs[:limite]
    ]

    return JsonResponse(
        {
            "ok": True,
            "tarefas": tarefas,
            "total": len(
                tarefas
            ),
        }
    )


@require_GET
@login_required(login_url=LOGIN_URL)
def api_task_detail(
    request,
    task_id: int,
):
    tarefa = get_object_or_404(
        TarefaFirewall,
        pk=task_id,
    )

    return JsonResponse(
        {
            "ok": True,
            "tarefa": _tarefa_to_dict(
                tarefa
            ),
        }
    )


# =============================================================================
# API — REGRAS
# =============================================================================

@require_http_methods(
    [
        "GET",
        "POST",
    ]
)
@login_required(login_url=LOGIN_URL)
def api_rules(request):
    if request.method == "GET":
        regras = (
            RegraFirewall.objects
            .filter(
                deletado=False
            )
            .order_by(
                "priority",
                "id",
            )
        )

        return JsonResponse(
            {
                "ok": True,
                "rules": [
                    rule_to_dict(
                        regra
                    )
                    for regra in regras
                ],
                "sync": sync_status(),
            }
        )

    bloqueio = _modo_real_obrigatorio()

    if bloqueio:
        return bloqueio

    dados, erro_response = _json_body(
        request,
        aceitar_vazio=False,
    )

    if erro_response:
        return erro_response

    seguro, motivo = validar_regra_segura(
        dados
    )

    if not seguro:
        return JsonResponse(
            {
                "ok": False,
                "erro": motivo,
            },
            status=400,
        )

    regra_nova = RegraFirewall(
        priority=_int(
            dados.get(
                "priority"
            ),
            default=500,
            minimo=-10000,
            maximo=10000,
        ),
        action=str(
            dados.get(
                "action"
            )
            or RegraFirewall.Acao.DENY
        ).strip(),
        iface=str(
            dados.get(
                "iface"
            )
            or RegraFirewall.Interface.ANY
        ).strip(),
        dir=str(
            dados.get(
                "dir"
            )
            or RegraFirewall.Direcao.IN
        ).strip(),
        proto=str(
            dados.get(
                "proto"
            )
            or RegraFirewall.Protocolo.TCP
        ).strip(),
        src=str(
            dados.get(
                "src"
            )
            or "any"
        ).strip() or "any",
        dst=str(
            dados.get(
                "dst"
            )
            or "any"
        ).strip() or "any",
        port=str(
            dados.get(
                "port"
            )
            or "any"
        ).strip() or "any",
        desc=str(
            dados.get(
                "desc"
            )
            or ""
        ).strip()[:255],
        enabled=_bool(
            dados.get(
                "enabled"
            ),
            default=True,
        ),
        log=_bool(
            dados.get(
                "log"
            ),
            default=True,
        ),
        pendente=True,
        sincronizada=False,
        deletado=False,
    )

    try:
        # Primeiro valida o objeto sem persistir. Só depois procuramos uma
        # regra semanticamente idêntica já existente.
        regra_nova.full_clean()

        with transaction.atomic():
            regra = (
                RegraFirewall.objects
                .select_for_update()
                .filter(
                    priority=regra_nova.priority,
                    action=regra_nova.action,
                    iface=regra_nova.iface,
                    dir=regra_nova.dir,
                    proto=regra_nova.proto,
                    src=regra_nova.src,
                    dst=regra_nova.dst,
                    port=regra_nova.port,
                    desc=regra_nova.desc,
                    enabled=regra_nova.enabled,
                    log=regra_nova.log,
                    deletado=False,
                )
                .order_by("id")
                .first()
            )

            criada_nova = regra is None

            if criada_nova:
                regra = regra_nova
                regra.save()
            else:
                # A mesma regra já existe. Não criamos outra linha no banco.
                # Apenas a recolocamos como pendente para uma nova tentativa.
                regra.pendente = True
                regra.sincronizada = False
                regra.sincronizada_em = None
                regra.ultimo_erro = ""
                regra.save(
                    update_fields=[
                        "pendente",
                        "sincronizada",
                        "sincronizada_em",
                        "ultimo_erro",
                        "atualizado_em",
                    ]
                )

    except ValidationError as exc:
        return JsonResponse(
            _validation_error_payload(
                exc
            ),
            status=400,
        )


    sync_result = aplicar_regras_pendentes()

    regra_refresh = RegraFirewall.objects.filter(
        pk=regra.pk
    ).first()

    return JsonResponse(
        {
            "ok": True,
            "aplicado": bool(
                sync_result.get(
                    "ok"
                )
            ),
            "rule": (
                rule_to_dict(
                    regra_refresh
                )
                if regra_refresh
                else {
                    "id": regra.pk,
                    "deletado": True,
                }
            ),
            "sync_result": sync_result,
            "sync": sync_status(),
            "reutilizada": not criada_nova,
        },
        status=(201 if criada_nova else 200),
    )


@login_required(login_url=LOGIN_URL)
@require_http_methods(
    [
        "GET",
        "PUT",
        "PATCH",
        "DELETE",
    ]
)
def api_rule_detail(
    request,
    rule_id: int,
):
    regra = get_object_or_404(
        RegraFirewall,
        pk=rule_id,
    )

    if request.method == "GET":
        return JsonResponse(
            {
                "ok": True,
                "rule": rule_to_dict(
                    regra
                ),
            }
        )

    bloqueio = _modo_real_obrigatorio()

    if bloqueio:
        return bloqueio

    if request.method == "DELETE":
        regra.marcar_deletada()

        sync_result = aplicar_regras_pendentes()

        return JsonResponse(
            {
                "ok": True,
                "aplicado": bool(
                    sync_result.get(
                        "ok"
                    )
                ),
                "rule_id": rule_id,
                "removida_runtime": bool(
                    sync_result.get(
                        "ok"
                    )
                ),
                "sync_result": sync_result,
                "sync": sync_status(),
            }
        )

    dados, erro_response = _json_body(
        request,
        aceitar_vazio=False,
    )

    if erro_response:
        return erro_response

    payload_check = {
        "action": dados.get(
            "action",
            regra.action,
        ),
        "iface": dados.get(
            "iface",
            regra.iface,
        ),
        "src": dados.get(
            "src",
            regra.src,
        ),
        "dst": dados.get(
            "dst",
            regra.dst,
        ),
        "port": dados.get(
            "port",
            regra.port,
        ),
    }

    seguro, motivo = validar_regra_segura(
        payload_check
    )

    if not seguro:
        return JsonResponse(
            {
                "ok": False,
                "erro": motivo,
            },
            status=400,
        )

    campos = {
        "priority",
        "action",
        "iface",
        "dir",
        "proto",
        "src",
        "dst",
        "port",
        "desc",
        "enabled",
        "log",
    }

    for campo in campos:
        if campo not in dados:
            continue

        valor = dados[
            campo
        ]

        if campo == "priority":
            valor = _int(
                valor,
                default=regra.priority,
                minimo=-10000,
                maximo=10000,
            )

        elif campo in {
            "enabled",
            "log",
        }:
            valor = _bool(
                valor,
                default=getattr(
                    regra,
                    campo,
                ),
            )

        elif campo == "desc":
            valor = str(
                valor
                or ""
            )[:255]

        else:
            valor = str(
                valor
                or ""
            )

        setattr(
            regra,
            campo,
            valor,
        )

    regra.pendente = True
    regra.sincronizada = False
    regra.sincronizada_em = None
    regra.deletado = False
    regra.ultimo_erro = ""

    try:
        regra.full_clean()
        regra.save()

    except ValidationError as exc:
        return JsonResponse(
            _validation_error_payload(
                exc
            ),
            status=400,
        )

    sync_result = aplicar_regras_pendentes()

    regra_refresh = RegraFirewall.objects.filter(
        pk=regra.pk
    ).first()

    return JsonResponse(
        {
            "ok": True,
            "aplicado": bool(
                sync_result.get(
                    "ok"
                )
            ),
            "rule": (
                rule_to_dict(
                    regra_refresh
                )
                if regra_refresh
                else None
            ),
            "sync_result": sync_result,
            "sync": sync_status(),
        }
    )


@require_POST
@login_required(login_url=LOGIN_URL)
def api_apply_rules(request):
    bloqueio = _modo_real_obrigatorio()

    if bloqueio:
        return bloqueio

    payload = {
        "total_pendentes": RegraFirewall.objects.filter(
            pendente=True
        ).count(),
    }

    tarefa, resultado = _executar_tarefa_sincrona(
        tipo=TarefaFirewall.Tipo.APLICAR_REGRAS,
        payload=payload,
        etapa="Aplicando regras",
        funcao=aplicar_regras_pendentes,
    )

    return JsonResponse(
        {
            "ok": bool(
                resultado.get(
                    "ok"
                )
            ),
            "tarefa": _tarefa_to_dict(
                tarefa
            ),
            "resultado": resultado,
            "sync": sync_status(),
        },
        status=(
            200
            if resultado.get("ok")
            else 502
        ),
    )


@require_POST
@login_required(login_url=LOGIN_URL)
def api_push_rules(request):
    """
    Alias temporário do endpoint antigo.

    Não existe mais push HTTP para sensor.
    """
    return api_apply_rules(
        request
    )


# =============================================================================
# API — ROLLBACK
# =============================================================================

@require_POST
@login_required(login_url=LOGIN_URL)
def api_rollback(request):
    bloqueio = _modo_real_obrigatorio()

    if bloqueio:
        return bloqueio

    dados, erro_response = _json_body(
        request
    )

    if erro_response:
        return erro_response

    snapshot_id = str(
        dados.get(
            "snapshot_id"
        )
        or ""
    ).strip()

    payload = {
        "snapshot_id": snapshot_id,
    }

    tarefa, resultado = _executar_tarefa_sincrona(
        tipo=TarefaFirewall.Tipo.ROLLBACK,
        payload=payload,
        etapa="Executando rollback",
        funcao=lambda: service_rollback(
            snapshot_id=(
                snapshot_id
                or None
            )
        ),
    )

    return JsonResponse(
        {
            "ok": bool(
                resultado.get(
                    "ok"
                )
            ),
            "tarefa": _tarefa_to_dict(
                tarefa
            ),
            "resultado": resultado,
        },
        status=(
            200
            if resultado.get("ok")
            else 502
        ),
    )


# =============================================================================
# API — BLOQUEIO RÁPIDO / EMERGÊNCIA
# =============================================================================

def _executar_block_request(
    request,
) -> JsonResponse:
    dados, erro_response = _json_body(
        request,
        aceitar_vazio=False,
    )

    if erro_response:
        return erro_response

    ip = str(
        dados.get(
            "ip"
        )
        or ""
    ).strip()

    if not ip:
        return JsonResponse(
            {
                "ok": False,
                "erro": "IP obrigatório.",
            },
            status=400,
        )

    seguro, motivo_seg = validar_regra_segura(
        {
            "action": "deny",
            "iface": dados.get(
                "iface",
                "any",
            ),
            "src": ip,
            "dst": "any",
            "port": dados.get(
                "porta",
                "any",
            ),
        }
    )

    if not seguro:
        return JsonResponse(
            {
                "ok": False,
                "erro": motivo_seg,
            },
            status=400,
        )

    resultado = service_bloquear_ip(
        ip,
        motivo=str(
            dados.get(
                "motivo"
            )
            or dados.get(
                "reason"
            )
            or "Bloqueio manual"
        )[:255],
        source=str(
            dados.get(
                "source"
            )
            or "Manual"
        ),
        expires=str(
            dados.get(
                "expires"
            )
            or "∞"
        ),
        iface=str(
            dados.get(
                "iface"
            )
            or ""
        ),
        porta=dados.get(
            "porta"
        ),
        proto=str(
            dados.get(
                "proto"
            )
            or "any"
        ),
    )

    return JsonResponse(
        resultado,
        status=(
            201
            if resultado.get("ok")
            else 502
        ),
    )


@require_POST
@login_required(login_url=LOGIN_URL)
def api_block(request):
    bloqueio = _modo_real_obrigatorio()

    if bloqueio:
        return bloqueio

    return _executar_block_request(
        request
    )


@require_POST
@login_required(login_url=LOGIN_URL)
def api_bloqueio_rapido(request):
    bloqueio = _modo_real_obrigatorio()

    if bloqueio:
        return bloqueio

    return _executar_block_request(
        request
    )


@require_POST
@login_required(login_url=LOGIN_URL)
def api_unblock(request):
    bloqueio = _modo_real_obrigatorio()

    if bloqueio:
        return bloqueio

    dados, erro_response = _json_body(
        request,
        aceitar_vazio=False,
    )

    if erro_response:
        return erro_response

    ip = str(
        dados.get(
            "ip"
        )
        or ""
    ).strip()

    if not ip:
        return JsonResponse(
            {
                "ok": False,
                "erro": "IP obrigatório.",
            },
            status=400,
        )

    resultado = service_liberar_ip(
        ip,
        remover_blocklist=_bool(
            dados.get(
                "remover_blocklist"
            ),
            default=True,
        ),
    )

    return JsonResponse(
        resultado,
        status=(
            200
            if resultado.get("ok")
            else 502
        ),
    )


# =============================================================================
# API — EXPORT NFT
# =============================================================================

@require_GET
@login_required(login_url=LOGIN_URL)
def api_export_nft(request):
    """
    Exporta uma REFERÊNCIA somente leitura.

    Não entregamos mais um script com `flush` pronto para aplicação manual,
    pois a aplicação privilegiada pertence exclusivamente ao Agent.
    """
    agora = datetime.now()

    regras_db = (
        RegraFirewall.objects
        .filter(
            enabled=True,
            deletado=False,
        )
        .order_by(
            "priority",
            "id",
        )
    )

    runtime = obter_regras_linux()

    linhas = [
        "# MoonShield Firewall — export de referência",
        f"# Gerado em: {agora.strftime('%Y-%m-%d %H:%M:%S')}",
        "#",
        "# IMPORTANTE:",
        "# Este arquivo é somente para auditoria/diagnóstico.",
        "# NÃO aplique este arquivo manualmente com nft -f.",
        "# O estado do Firewall deve ser alterado pelo Django -> Agent IPC.",
        "#",
        "",
        "# Estado desejado no Django",
    ]

    for regra in regras_db:
        expressao = regra_para_nft_inline(
            regra
        )

        linhas.append(
            f"# [{regra.id}] prioridade={regra.priority} "
            f"{regra.action.upper()} {regra.desc}"
        )

        if expressao:
            # Comentado propositalmente para o arquivo não ser executável.
            linhas.append(
                "# add rule inet moonshield ms_rules "
                + expressao
            )

    linhas.extend(
        [
            "",
            "# Estado observado no Agent / ms_rules",
        ]
    )

    for item in runtime.get(
        "regras",
        [],
    ):
        if isinstance(
            item,
            dict,
        ):
            expr = item.get(
                "expressao",
                "",
            )
            handle = item.get(
                "handle"
            )

            linhas.append(
                f"# handle={handle or '-'} | {expr}"
            )

    conteudo = "\n".join(
        linhas
    ) + "\n"

    filename = (
        "moonshield-firewall-reference-"
        f"{agora.strftime('%Y%m%d-%H%M%S')}.nft.txt"
    )

    response = HttpResponse(
        conteudo,
        content_type="text/plain; charset=utf-8",
    )

    response[
        "Content-Disposition"
    ] = (
        f'attachment; filename="{filename}"'
    )

    return response


# =============================================================================
# API — NAT
# =============================================================================

@login_required(login_url=LOGIN_URL)
@require_http_methods(
    [
        "GET",
        "POST",
    ]
)
def api_nat(request):
    if request.method == "GET":
        entries = [
            nat_to_dict(
                item
            )
            for item in NatEntry.objects.all()
        ]

        return JsonResponse(
            {
                "ok": True,
                "entries": entries,
                "runtime_applied": False,
                "aviso": (
                    "O cadastro NAT está preservado no Django, "
                    "mas a aplicação nftables de NAT ainda não foi habilitada "
                    "na arquitetura nova."
                ),
            }
        )

    dados, erro_response = _json_body(
        request,
        aceitar_vazio=False,
    )

    if erro_response:
        return erro_response

    n = NatEntry(
        name=str(
            dados.get(
                "name"
            )
            or "Port Forward"
        )[:100],
        iface=str(
            dados.get(
                "iface"
            )
            or "WAN"
        ),
        wan_port=str(
            dados.get(
                "wan_port"
            )
            or ""
        ),
        lan_ip=str(
            dados.get(
                "lan_ip"
            )
            or ""
        ),
        lan_port=str(
            dados.get(
                "lan_port"
            )
            or ""
        ),
        proto=str(
            dados.get(
                "proto"
            )
            or "TCP"
        ),
        enabled=_bool(
            dados.get(
                "enabled"
            ),
            default=True,
        ),
    )

    try:
        n.full_clean()
        n.save()
    except ValidationError as exc:
        return JsonResponse(
            _validation_error_payload(
                exc
            ),
            status=400,
        )

    return JsonResponse(
        {
            "ok": True,
            "nat": nat_to_dict(
                n
            ),
            "runtime_applied": False,
        },
        status=201,
    )


@login_required(login_url=LOGIN_URL)
@require_http_methods(
    [
        "GET",
        "PUT",
        "PATCH",
        "DELETE",
    ]
)
def api_nat_detail(
    request,
    nat_id: int,
):
    n = get_object_or_404(
        NatEntry,
        pk=nat_id,
    )

    if request.method == "GET":
        return JsonResponse(
            {
                "ok": True,
                "nat": nat_to_dict(
                    n
                ),
                "runtime_applied": False,
            }
        )

    if request.method == "DELETE":
        n.delete()

        return JsonResponse(
            {
                "ok": True,
                "runtime_applied": False,
            }
        )

    dados, erro_response = _json_body(
        request,
        aceitar_vazio=False,
    )

    if erro_response:
        return erro_response

    for campo in (
        "name",
        "iface",
        "wan_port",
        "lan_ip",
        "lan_port",
        "proto",
        "enabled",
    ):
        if campo not in dados:
            continue

        valor = dados[
            campo
        ]

        if campo == "enabled":
            valor = _bool(
                valor,
                default=n.enabled,
            )

        setattr(
            n,
            campo,
            valor,
        )

    try:
        n.full_clean()
        n.save()
    except ValidationError as exc:
        return JsonResponse(
            _validation_error_payload(
                exc
            ),
            status=400,
        )

    return JsonResponse(
        {
            "ok": True,
            "nat": nat_to_dict(
                n
            ),
            "runtime_applied": False,
        }
    )


# =============================================================================
# API — BLOCKLIST
# =============================================================================

@login_required(login_url=LOGIN_URL)
@require_http_methods(
    [
        "GET",
        "POST",
    ]
)
def api_blocklist(request):
    if request.method == "GET":
        entries = [
            block_to_dict(
                item
            )
            for item in BlocklistEntry.objects.all()
        ]

        return JsonResponse(
            {
                "ok": True,
                "entries": entries,
            }
        )

    bloqueio = _modo_real_obrigatorio()

    if bloqueio:
        return bloqueio

    return _executar_block_request(
        request
    )


@login_required(login_url=LOGIN_URL)
@require_http_methods(
    [
        "DELETE",
    ]
)
def api_blocklist_detail(
    request,
    entry_id: int,
):
    bloqueio = _modo_real_obrigatorio()

    if bloqueio:
        return bloqueio

    entry = get_object_or_404(
        BlocklistEntry,
        pk=entry_id,
    )

    ip = entry.ip

    resultado = service_liberar_ip(
        ip,
        remover_blocklist=True,
    )

    return JsonResponse(
        resultado,
        status=(
            200
            if resultado.get("ok")
            else 502
        ),
    )


# =============================================================================
# API — ALLOWLIST
# =============================================================================

@login_required(login_url=LOGIN_URL)
@require_http_methods(
    [
        "GET",
        "POST",
    ]
)
def api_allowlist(request):
    if request.method == "GET":
        return JsonResponse(
            {
                "ok": True,
                "entries": [
                    allow_to_dict(
                        item
                    )
                    for item in AllowlistEntry.objects.all()
                ],
                "runtime_applied": False,
            }
        )

    dados, erro_response = _json_body(
        request,
        aceitar_vazio=False,
    )

    if erro_response:
        return erro_response

    ip = str(
        dados.get(
            "ip"
        )
        or ""
    ).strip()

    if not ip:
        return JsonResponse(
            {
                "ok": False,
                "erro": "IP/rede obrigatório.",
            },
            status=400,
        )

    entry = AllowlistEntry(
        ip=ip,
        reason=str(
            dados.get(
                "reason"
            )
            or "Liberação manual"
        )[:255],
    )

    try:
        entry.full_clean()
        entry.save()
    except ValidationError as exc:
        return JsonResponse(
            _validation_error_payload(
                exc
            ),
            status=400,
        )

    return JsonResponse(
        {
            "ok": True,
            "entry": allow_to_dict(
                entry
            ),
            "runtime_applied": False,
            "aviso": (
                "Allowlist persistida no Django. "
                "A aplicação dedicada de allowlist no Agent será integrada "
                "na fase de sets/listas."
            ),
        },
        status=201,
    )


@login_required(login_url=LOGIN_URL)
@require_http_methods(
    [
        "GET",
        "DELETE",
    ]
)
def api_allowlist_detail(
    request,
    entry_id: int,
):
    entry = get_object_or_404(
        AllowlistEntry,
        pk=entry_id,
    )

    if request.method == "GET":
        return JsonResponse(
            {
                "ok": True,
                "entry": allow_to_dict(
                    entry
                ),
                "runtime_applied": False,
            }
        )

    entry.delete()

    return JsonResponse(
        {
            "ok": True,
            "runtime_applied": False,
        }
    )


# =============================================================================
# API — GEOBLOCK
# =============================================================================

@login_required(login_url=LOGIN_URL)
@require_http_methods(
    [
        "GET",
        "POST",
    ]
)
def api_geoblock(request):
    if request.method == "GET":
        return JsonResponse(
            {
                "ok": True,
                "entries": [
                    geo_to_dict(
                        item
                    )
                    for item in GeoblockEntry.objects.all()
                ],
                "runtime_applied": False,
            }
        )

    dados, erro_response = _json_body(
        request,
        aceitar_vazio=False,
    )

    if erro_response:
        return erro_response

    code = str(
        dados.get(
            "code"
        )
        or ""
    ).strip().upper()

    if not code:
        return JsonResponse(
            {
                "ok": False,
                "erro": "Código do país obrigatório.",
            },
            status=400,
        )

    entry, criada = GeoblockEntry.objects.get_or_create(
        code=code,
        defaults={
            "country": str(
                dados.get(
                    "country"
                )
                or code
            )[:100],
            "dir": str(
                dados.get(
                    "dir"
                )
                or GeoblockEntry.Direcao.IN
            ),
            "enabled": _bool(
                dados.get(
                    "enabled"
                ),
                default=True,
            ),
        },
    )

    return JsonResponse(
        {
            "ok": True,
            "entry": geo_to_dict(
                entry
            ),
            "created": criada,
            "runtime_applied": False,
            "aviso": (
                "GeoBlock está persistido no Django. "
                "A aplicação via nft sets será integrada em fase própria."
            ),
        },
        status=(
            201
            if criada
            else 200
        ),
    )


@login_required(login_url=LOGIN_URL)
@require_http_methods(
    [
        "GET",
        "PUT",
        "PATCH",
        "DELETE",
    ]
)
def api_geoblock_detail(
    request,
    entry_id: int,
):
    entry = get_object_or_404(
        GeoblockEntry,
        pk=entry_id,
    )

    if request.method == "GET":
        return JsonResponse(
            {
                "ok": True,
                "entry": geo_to_dict(
                    entry
                ),
                "runtime_applied": False,
            }
        )

    if request.method == "DELETE":
        entry.delete()

        return JsonResponse(
            {
                "ok": True,
                "runtime_applied": False,
            }
        )

    dados, erro_response = _json_body(
        request,
        aceitar_vazio=False,
    )

    if erro_response:
        return erro_response

    for campo in (
        "country",
        "dir",
        "enabled",
    ):
        if campo not in dados:
            continue

        valor = dados[
            campo
        ]

        if campo == "enabled":
            valor = _bool(
                valor,
                default=entry.enabled,
            )

        setattr(
            entry,
            campo,
            valor,
        )

    try:
        entry.full_clean()
        entry.save()
    except ValidationError as exc:
        return JsonResponse(
            _validation_error_payload(
                exc
            ),
            status=400,
        )

    return JsonResponse(
        {
            "ok": True,
            "entry": geo_to_dict(
                entry
            ),
            "runtime_applied": False,
        }
    )