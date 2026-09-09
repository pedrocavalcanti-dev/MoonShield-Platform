"""
MoonShield Platform — Firewall / Rules Service
=============================================

Camada de negócio entre os models Django e o MoonShield-Agent.

Responsabilidades:
- serializar RegraFirewall;
- aplicar regras ativas localmente via IPC;
- atualizar pendente/sincronizada;
- tratar soft-delete;
- executar bloqueio/liberação emergencial;
- expor regras efetivamente carregadas no Linux.

Este módulo NÃO:
- usa Sensor;
- usa HTTP;
- usa token;
- executa nft diretamente.
"""

from __future__ import annotations

import logging
from typing import Any

from django.db import transaction

from firewall.models import (
    BlocklistEntry,
    RegraFirewall,
)

from . import agent_client
from .firewall_status import (
    obter_contexto_firewall_rede,
    obter_estado_firewall,
)


logger = logging.getLogger(__name__)

VERSAO_RULES_SERVICE = "1.1"


# =============================================================================
# SERIALIZAÇÃO
# =============================================================================

def regra_para_payload(
    regra: RegraFirewall,
) -> dict[str, Any]:
    return {
        "id": regra.id,
        "priority": regra.priority,
        "action": regra.action,
        "iface": regra.iface,
        "dir": regra.dir,
        "proto": regra.proto,
        "src": regra.src,
        "dst": regra.dst,
        "port": regra.port,
        "desc": regra.desc,
        "enabled": regra.enabled,
        "log": regra.log,
    }


def listar_regras_para_agent() -> list[dict[str, Any]]:
    qs = (
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

    return [
        regra_para_payload(regra)
        for regra in qs
    ]


# =============================================================================
# APLICAÇÃO
# =============================================================================

def aplicar_regras_pendentes() -> dict[str, Any]:
    """
    Reaplica o conjunto completo de regras ativas.

    Mesmo que apenas uma regra tenha mudado, enviamos o estado desejado inteiro.
    O Agent aplica de forma transacional.
    """
    topologia_rede = obter_contexto_firewall_rede()

    if not topologia_rede.get("ok"):
        erro_topologia = topologia_rede.get("erro") or {}

        return {
            "ok": False,
            "codigo": str(
                erro_topologia.get("codigo")
                or "topologia_rede_incompleta"
            ),
            "erro": str(
                erro_topologia.get("mensagem")
                or "Topologia oficial da Rede incompleta."
            ),
            "topologia": topologia_rede,
        }

    estado = obter_estado_firewall(
        incluir_detalhes=False
    )

    if not estado.get("agent_disponivel"):
        return {
            "ok": False,
            "codigo": "agent_indisponivel",
            "erro": "MoonShield-Agent indisponível.",
            "estado": estado,
        }

    if not estado.get("instalado"):
        return {
            "ok": False,
            "codigo": "firewall_nao_instalado",
            "erro": "Firewall ainda não está instalado.",
            "estado": estado,
        }

    regras = listar_regras_para_agent()

    # A aplicação nunca deriva topologia do status observado do Agent.
    # WAN/LAN/MGMT/HOME_NET são congelados a partir do Network Control.
    config = dict(
        topologia_rede.get("config_agent")
        or {}
    )
    iface_map = dict(
        topologia_rede.get("iface_map")
        or {}
    )

    try:
        resultado = agent_client.aplicar_regras(
            regras,
            iface_map=iface_map,
            config=config,
        )

    except agent_client.OperacaoAgentFalhou as exc:
        logger.warning(
            "Agent recusou aplicação das regras: %s",
            exc,
        )

        return {
            "ok": False,
            "codigo": exc.codigo,
            "erro": str(exc),
            "detalhes": exc.detalhes,
            "resposta_agent": exc.resposta,
        }

    except agent_client.ErroAgent as exc:
        logger.error(
            "Falha IPC ao aplicar regras: %s",
            exc,
        )

        return {
            "ok": False,
            "codigo": "agent_indisponivel",
            "erro": str(exc),
        }

    # Só alteramos banco após confirmação real do Agent.
    with transaction.atomic():
        RegraFirewall.objects.filter(
            enabled=True,
            deletado=False,
        ).update(
            pendente=False,
            sincronizada=True,
        )

        RegraFirewall.objects.filter(
            enabled=False,
            deletado=False,
        ).update(
            pendente=False,
            sincronizada=False,
        )

        # Soft-deletes só somem do banco depois de o Agent confirmar
        # que o conjunto sem elas foi aplicado.
        RegraFirewall.objects.filter(
            deletado=True
        ).delete()

    return {
        "ok": True,
        "mensagem": resultado.get(
            "mensagem",
            "Regras aplicadas.",
        ),
        "total_regras": len(regras),
        "resultado_agent": resultado,
        "topologia_fonte": "rede",
        "topologia": {
            "interface_wan": topologia_rede.get("interface_wan", ""),
            "interface_lan": topologia_rede.get("interface_lan", ""),
            "interface_mgmt": topologia_rede.get("interface_mgmt", ""),
            "home_net": topologia_rede.get("home_net", ""),
            "redes_internas": topologia_rede.get("redes_internas", []),
        },
        "sync": obter_sync_status(),
    }


def aplicar_todas() -> dict[str, Any]:
    return aplicar_regras_pendentes()


# =============================================================================
# STATUS DE SINCRONIZAÇÃO
# =============================================================================

def obter_sync_status() -> dict[str, Any]:
    total = RegraFirewall.objects.filter(
        deletado=False
    ).count()

    pendentes = RegraFirewall.objects.filter(
        pendente=True
    ).count()

    sincronizadas = RegraFirewall.objects.filter(
        sincronizada=True,
        deletado=False,
    ).count()

    deletadas_pendentes = RegraFirewall.objects.filter(
        deletado=True
    ).count()

    return {
        "total": total,
        "pendentes": pendentes,
        "sincronizadas": sincronizadas,
        "deletadas_pendentes": deletadas_pendentes,
        "em_sync": (
            pendentes == 0
            and deletadas_pendentes == 0
        ),
    }


# =============================================================================
# ALTERAÇÕES DE ESTADO
# =============================================================================

def marcar_regra_pendente(
    regra: RegraFirewall,
) -> None:
    regra.pendente = True
    regra.sincronizada = False

    regra.save(
        update_fields=[
            "pendente",
            "sincronizada",
            "atualizado_em",
        ]
    )


def marcar_regra_para_exclusao(
    regra: RegraFirewall,
) -> None:
    regra.deletado = True
    regra.pendente = True
    regra.sincronizada = False

    regra.save(
        update_fields=[
            "deletado",
            "pendente",
            "sincronizada",
            "atualizado_em",
        ]
    )


# =============================================================================
# FIREWALL REAL
# =============================================================================

def obter_regras_linux() -> dict[str, Any]:
    try:
        return {
            "ok": True,
            **agent_client.regras_linux(),
        }

    except agent_client.ErroAgent as exc:
        return {
            "ok": False,
            "regras": [],
            "total": 0,
            "erro": str(exc),
        }


def obter_emergency_linux() -> dict[str, Any]:
    try:
        return {
            "ok": True,
            **agent_client.emergency(),
        }

    except agent_client.ErroAgent as exc:
        return {
            "ok": False,
            "regras": [],
            "total": 0,
            "erro": str(exc),
        }


# =============================================================================
# BLOQUEIO RÁPIDO
# =============================================================================

def bloquear_ip(
    ip: str,
    *,
    motivo: str = "Bloqueio manual",
    source: str = "Manual",
    expires: str = "∞",
    iface: str = "",
    porta: str | int | None = None,
    proto: str = "any",
) -> dict[str, Any]:
    ip = str(ip or "").strip()

    if not ip:
        return {
            "ok": False,
            "codigo": "ip_obrigatorio",
            "erro": "IP obrigatório.",
        }

    try:
        resultado = agent_client.bloquear_ip(
            ip,
            motivo=motivo,
            iface=iface,
            porta=porta,
            proto=proto,
            expires=expires,
        )

    except agent_client.OperacaoAgentFalhou as exc:
        return {
            "ok": False,
            "codigo": exc.codigo,
            "erro": str(exc),
            "detalhes": exc.detalhes,
        }

    except agent_client.ErroAgent as exc:
        return {
            "ok": False,
            "codigo": "agent_indisponivel",
            "erro": str(exc),
        }

    block_entry, criada = BlocklistEntry.objects.get_or_create(
        ip=ip,
        defaults={
            "reason": motivo[:255],
            "source": source,
            "expires": expires,
        },
    )

    if not criada:
        atualizou = False

        if motivo and block_entry.reason != motivo[:255]:
            block_entry.reason = motivo[:255]
            atualizou = True

        if expires and block_entry.expires != expires:
            block_entry.expires = expires
            atualizou = True

        if atualizou:
            block_entry.save()

    return {
        "ok": True,
        "ip": ip,
        "blocklist_id": block_entry.id,
        "criada": criada,
        "resultado_agent": resultado,
    }


def liberar_ip(
    ip: str,
    *,
    remover_blocklist: bool = True,
) -> dict[str, Any]:
    ip = str(ip or "").strip()

    if not ip:
        return {
            "ok": False,
            "codigo": "ip_obrigatorio",
            "erro": "IP obrigatório.",
        }

    try:
        resultado = agent_client.liberar_ip(
            ip
        )

    except agent_client.OperacaoAgentFalhou as exc:
        return {
            "ok": False,
            "codigo": exc.codigo,
            "erro": str(exc),
            "detalhes": exc.detalhes,
        }

    except agent_client.ErroAgent as exc:
        return {
            "ok": False,
            "codigo": "agent_indisponivel",
            "erro": str(exc),
        }

    removidos_db = 0

    if remover_blocklist:
        removidos_db, _ = BlocklistEntry.objects.filter(
            ip=ip
        ).delete()

    return {
        "ok": True,
        "ip": ip,
        "blocklist_removidos": removidos_db,
        "resultado_agent": resultado,
    }


# =============================================================================
# ROLLBACK
# =============================================================================

def rollback(
    *,
    snapshot_id: str | None = None,
) -> dict[str, Any]:
    try:
        resultado = agent_client.rollback(
            snapshot_id=snapshot_id
        )

        return {
            "ok": True,
            "resultado_agent": resultado,
        }

    except agent_client.OperacaoAgentFalhou as exc:
        return {
            "ok": False,
            "codigo": exc.codigo,
            "erro": str(exc),
            "detalhes": exc.detalhes,
        }

    except agent_client.ErroAgent as exc:
        return {
            "ok": False,
            "codigo": "agent_indisponivel",
            "erro": str(exc),
        }