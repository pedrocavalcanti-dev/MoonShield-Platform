"""
MoonShield Agent — Firewall / AutoBan
=====================================

AutoBan totalmente LOCAL.

Arquitetura NOVA:
    evento nftables
        ↓
    monitoramento.py
        ↓
    autoban.py
        ↓
    aplicador.bloquear_ip()
        ↓
    nftables / ms_emergency

Este módulo NÃO:
- usa HTTP;
- chama Django;
- usa token;
- usa sensor;
- depende de Moon_url.

Os eventos de AutoBan são gravados localmente para posterior ingestão
pelo Django/worker.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from firewall.nucleo.aplicador import (
    bloquear_ip,
    liberar_ip,
)


logger = logging.getLogger(__name__)


# =============================================================================
# CONSTANTES
# =============================================================================

VERSAO_AUTOBAN = "3.0"

DIRETORIO_LOG = Path("/var/log/moonshield/firewall")
ARQUIVO_AUTOBAN = DIRETORIO_LOG / "autoban.jsonl"

DEFAULTS: dict[str, Any] = {
    "habilitado": True,

    "janela_seg": 30,
    "threshold": 15,

    "expire_seg": 3600,

    "portas_sensiveis": [
        22,
        23,
        3389,
        5900,
    ],

    "peso_porta_sensivel": 2,

    # Eventos permitidos podem ser usados como sinal de scan, mas por padrão
    # trabalhamos principalmente com eventos bloqueados/rejeitados.
    "contar_permitidos": False,

    # Nunca bloquear endereços privados/local-management automaticamente.
    "ignorar_privados": True,
}


# =============================================================================
# ESTADO
# =============================================================================

_lock = threading.RLock()
_counter_lock = threading.RLock()
_log_lock = threading.RLock()

_config: dict[str, Any] = dict(
    DEFAULTS
)

_hit_counter: dict[str, list[float]] = defaultdict(
    list
)

_bans_ativos: dict[str, dict[str, Any]] = {}

_timers: dict[str, threading.Timer] = {}

_stats: dict[str, Any] = {
    "total_bans": 0,
    "bans_sessao": 0,
    "falhas": 0,

    "ultimo_ban": "—",
    "ultimo_ip": "—",
    "ultimo_motivo": "—",

    "versao": VERSAO_AUTOBAN,
}


# =============================================================================
# API PÚBLICA
# =============================================================================

def configurar(
    cfg: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Carrega configuração a partir de:

        cfg["autoban"]

    ou, se o dict já representar o AutoBan, diretamente dele.
    """
    global _config

    cfg = cfg or {}

    recebido = cfg.get(
        "autoban"
    )

    if not isinstance(
        recebido,
        dict,
    ):
        recebido = cfg

    novo = {
        **DEFAULTS,
        **(
            recebido
            if isinstance(
                recebido,
                dict,
            )
            else {}
        ),
    }

    novo["habilitado"] = _bool(
        novo.get(
            "habilitado",
            True,
        )
    )

    novo["janela_seg"] = _int_min(
        novo.get(
            "janela_seg",
            30,
        ),
        1,
        30,
    )

    novo["threshold"] = _int_min(
        novo.get(
            "threshold",
            15,
        ),
        1,
        15,
    )

    novo["expire_seg"] = max(
        0,
        _int(
            novo.get(
                "expire_seg",
                3600,
            ),
            3600,
        ),
    )

    novo["peso_porta_sensivel"] = _int_min(
        novo.get(
            "peso_porta_sensivel",
            2,
        ),
        1,
        2,
    )

    portas = novo.get(
        "portas_sensiveis",
        DEFAULTS["portas_sensiveis"],
    )

    if not isinstance(
        portas,
        list,
    ):
        portas = list(
            DEFAULTS[
                "portas_sensiveis"
            ]
        )

    novo["portas_sensiveis"] = [
        p
        for p in {
            _int(
                valor,
                -1,
            )
            for valor in portas
        }
        if 1 <= p <= 65535
    ]

    novo["contar_permitidos"] = _bool(
        novo.get(
            "contar_permitidos",
            False,
        )
    )

    novo["ignorar_privados"] = _bool(
        novo.get(
            "ignorar_privados",
            True,
        )
    )

    with _lock:
        _config = novo

    return obter_config()


def obter_config() -> dict[str, Any]:
    with _lock:
        return dict(
            _config
        )


def obter_stats() -> dict[str, Any]:
    with _lock:
        ativos = [
            dict(
                item
            )
            for item in _bans_ativos.values()
        ]

        return {
            **_stats,
            "ips_ativos": len(
                ativos
            ),
            "ativos": ativos,
            "habilitado": bool(
                _config.get(
                    "habilitado",
                    True,
                )
            ),
        }


def listar_bans_ativos() -> list[dict[str, Any]]:
    with _lock:
        return [
            dict(
                item
            )
            for item in _bans_ativos.values()
        ]


def registrar_evento(
    ev: dict[str, Any],
    cfg: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """
    Analisa um evento e, se atingir o threshold, bloqueia o IP.

    Retorna:
        None                     -> nenhuma ação
        {"banido": False, ...}   -> tentativa sem ban
        {"banido": True, ...}    -> ban executado
    """
    if cfg:
        # Permite atualizar configuração em runtime.
        if isinstance(
            cfg.get("autoban"),
            dict,
        ):
            configurar(
                cfg
            )

    ab = obter_config()

    if not ab[
        "habilitado"
    ]:
        return None

    if not isinstance(
        ev,
        dict,
    ):
        return None

    src_ip = str(
        ev.get(
            "src_ip"
        )
        or ""
    ).strip()

    if not src_ip:
        return None

    try:
        addr = ipaddress.ip_address(
            src_ip
        )
    except ValueError:
        return None

    if _ip_protegido(
        addr,
        ab,
    ):
        return None

    with _lock:
        if src_ip in _bans_ativos:
            return {
                "banido": False,
                "motivo": "ja_banido",
                "ip": src_ip,
            }

    acao = str(
        ev.get(
            "acao"
        )
        or ""
    ).upper()

    if (
        not ab[
            "contar_permitidos"
        ]
        and acao in {
            "ALLOW",
            "ACCEPT",
            "LOG",
        }
    ):
        return None

    agora = time.time()

    janela = int(
        ab[
            "janela_seg"
        ]
    )

    threshold = int(
        ab[
            "threshold"
        ]
    )

    porta = ev.get(
        "dst_port"
    )

    peso = (
        int(
            ab[
                "peso_porta_sensivel"
            ]
        )
        if porta in ab[
            "portas_sensiveis"
        ]
        else 1
    )

    with _counter_lock:
        anteriores = _hit_counter[
            src_ip
        ]

        recentes = [
            ts
            for ts in anteriores
            if agora - ts < janela
        ]

        recentes.extend(
            [agora] * peso
        )

        _hit_counter[
            src_ip
        ] = recentes

        hits = len(
            recentes
        )

    if hits < threshold:
        return {
            "banido": False,
            "ip": src_ip,
            "hits": hits,
            "threshold": threshold,
        }

    return _executar_ban(
        ip=src_ip,
        hits=hits,
        janela=janela,
        ev=ev,
        ab_cfg=ab,
    )


def banir_agora(
    ip: str,
    *,
    motivo: str = "autoban_manual",
    expire_seg: int | None = None,
) -> dict[str, Any]:
    """
    Helper para testes ou integração futura.
    """
    ab = obter_config()

    if expire_seg is not None:
        ab[
            "expire_seg"
        ] = max(
            0,
            int(
                expire_seg
            ),
        )

    evento = {
        "src_ip": ip,
        "dst_port": None,
        "proto": "any",
        "iface_entrada": "",
        "flags_tcp": "",
    }

    return _executar_ban(
        ip=ip,
        hits=1,
        janela=0,
        ev=evento,
        ab_cfg=ab,
        motivo_forcado=motivo,
    )


def liberar_ban(
    ip: str,
    *,
    motivo: str = "liberacao_manual",
) -> dict[str, Any]:
    resultado = liberar_ip(
        {
            "ip": ip,
        }
    )

    if resultado.get(
        "ok"
    ):
        _cancelar_timer(
            ip
        )

        with _lock:
            anterior = _bans_ativos.pop(
                ip,
                None,
            )

        with _counter_lock:
            _hit_counter.pop(
                ip,
                None,
            )

        _registrar_evento_autoban(
            {
                "acao": "UNBAN",
                "ip": ip,
                "motivo": motivo,
                "anterior": anterior,
                "resultado": resultado,
            }
        )

    return resultado


def limpar_contadores() -> None:
    with _counter_lock:
        _hit_counter.clear()


# =============================================================================
# BAN
# =============================================================================

def _executar_ban(
    *,
    ip: str,
    hits: int,
    janela: int,
    ev: dict[str, Any],
    ab_cfg: dict[str, Any],
    motivo_forcado: str | None = None,
) -> dict[str, Any]:
    try:
        addr = ipaddress.ip_address(
            ip
        )
    except ValueError:
        return {
            "banido": False,
            "ok": False,
            "codigo": "ip_invalido",
            "erro": "IP inválido.",
        }

    if _ip_protegido(
        addr,
        ab_cfg,
    ):
        return {
            "banido": False,
            "ok": False,
            "codigo": "ip_protegido",
            "erro": "AutoBan recusou um IP protegido.",
        }

    with _lock:
        if ip in _bans_ativos:
            return {
                "banido": False,
                "ok": True,
                "codigo": "ja_banido",
                "ip": ip,
            }

    motivo = (
        motivo_forcado
        or _detectar_motivo(
            ev
        )
    )

    logger.warning(
        "[autoban] banindo %s | %s hits/%ss | %s",
        ip,
        hits,
        janela,
        motivo,
    )

    resultado_nft = bloquear_ip(
        {
            "ip": ip,
            "motivo": (
                f"AutoBan: {motivo}"
            ),
        }
    )

    if not resultado_nft.get(
        "ok"
    ):
        with _lock:
            _stats[
                "falhas"
            ] += 1

        _registrar_evento_autoban(
            {
                "acao": "BAN_FALHOU",
                "ip": ip,
                "motivo": motivo,
                "hits": hits,
                "janela_seg": janela,
                "evento_origem": ev,
                "resultado": resultado_nft,
            }
        )

        return {
            "banido": False,
            "ok": False,
            "ip": ip,
            "motivo": motivo,
            "resultado": resultado_nft,
        }

    criado_em = _agora_iso()

    expire_seg = max(
        0,
        int(
            ab_cfg.get(
                "expire_seg",
                0,
            )
        ),
    )

    expira_em = (
        time.time()
        + expire_seg
        if expire_seg > 0
        else None
    )

    registro = {
        "ip": ip,
        "motivo": motivo,
        "hits": hits,
        "janela_seg": janela,
        "criado_em": criado_em,
        "expire_seg": expire_seg,
        "expira_em_epoch": expira_em,

        "porta": ev.get(
            "dst_port"
        ),

        "proto": ev.get(
            "proto"
        ),

        "iface": (
            ev.get(
                "iface_entrada"
            )
            or ev.get(
                "iface"
            )
            or ""
        ),
    }

    with _lock:
        _bans_ativos[
            ip
        ] = registro

        _stats[
            "total_bans"
        ] += 1

        _stats[
            "bans_sessao"
        ] += 1

        _stats[
            "ultimo_ban"
        ] = criado_em

        _stats[
            "ultimo_ip"
        ] = ip

        _stats[
            "ultimo_motivo"
        ] = motivo

    if expire_seg > 0:
        _agendar_expiracao(
            ip,
            expire_seg,
        )

    _registrar_evento_autoban(
        {
            "acao": "BAN",
            **registro,
            "evento_origem": ev,
            "resultado": resultado_nft,
        }
    )

    return {
        "banido": True,
        "ok": True,
        "ip": ip,
        "motivo": motivo,
        "hits": hits,
        "expire_seg": expire_seg,
        "resultado": resultado_nft,
    }


# =============================================================================
# EXPIRAÇÃO
# =============================================================================

def _agendar_expiracao(
    ip: str,
    segundos: int,
) -> None:
    _cancelar_timer(
        ip
    )

    timer = threading.Timer(
        segundos,
        _expirar_ban,
        args=(
            ip,
        ),
    )

    timer.name = (
        f"moonshield-autoban-expire-{ip}"
    )

    timer.daemon = True

    with _lock:
        _timers[
            ip
        ] = timer

    timer.start()


def _cancelar_timer(
    ip: str,
) -> None:
    with _lock:
        timer = _timers.pop(
            ip,
            None,
        )

    if timer:
        try:
            timer.cancel()
        except Exception:
            pass


def _expirar_ban(
    ip: str,
) -> None:
    try:
        resultado = liberar_ip(
            {
                "ip": ip,
            }
        )

        with _lock:
            registro = _bans_ativos.pop(
                ip,
                None,
            )

            _timers.pop(
                ip,
                None,
            )

        with _counter_lock:
            _hit_counter.pop(
                ip,
                None,
            )

        _registrar_evento_autoban(
            {
                "acao": "EXPIRE",
                "ip": ip,
                "registro": registro,
                "resultado": resultado,
            }
        )

        logger.info(
            "[autoban] ban expirado: %s",
            ip,
        )

    except Exception as exc:
        logger.exception(
            "[autoban] falha ao expirar %s: %s",
            ip,
            exc,
        )


# =============================================================================
# DETECÇÃO
# =============================================================================

def _detectar_motivo(
    ev: dict[str, Any],
) -> str:
    porta = ev.get(
        "dst_port"
    )

    if porta == 22:
        return "brute_force_ssh"

    if porta == 23:
        return "tentativa_telnet"

    if porta == 3389:
        return "brute_force_rdp"

    if porta == 5900:
        return "brute_force_vnc"

    flags = {
        item.strip().upper()
        for item in str(
            ev.get(
                "flags_tcp"
            )
            or ""
        ).split(",")
        if item.strip()
    }

    if (
        "SYN" in flags
        and "ACK" not in flags
    ):
        return "port_scan_syn"

    proto = str(
        ev.get(
            "proto"
        )
        or ""
    ).upper()

    if proto == "ICMP":
        return "icmp_threshold"

    return "threshold_excedido"


def _ip_protegido(
    addr: ipaddress._BaseAddress,
    cfg: dict[str, Any],
) -> bool:
    if (
        addr.is_loopback
        or addr.is_unspecified
        or addr.is_multicast
        or addr.is_link_local
    ):
        return True

    if (
        cfg.get(
            "ignorar_privados",
            True,
        )
        and addr.is_private
    ):
        return True

    return False


# =============================================================================
# AUDITORIA LOCAL
# =============================================================================

def _registrar_evento_autoban(
    payload: dict[str, Any],
) -> None:
    try:
        DIRETORIO_LOG.mkdir(
            parents=True,
            exist_ok=True,
        )

        try:
            os.chmod(
                DIRETORIO_LOG,
                0o750,
            )
        except PermissionError:
            pass

        envelope = {
            "schema": 1,
            "tipo_evento": "autoban",
            "gravado_em": _agora_iso(),
            "evento": payload,
        }

        raw = (
            json.dumps(
                envelope,
                ensure_ascii=False,
                separators=(",", ":"),
                default=str,
            )
            + "\n"
        ).encode(
            "utf-8"
        )

        with _log_lock:
            fd = os.open(
                ARQUIVO_AUTOBAN,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_APPEND,
                0o640,
            )

            try:
                os.write(
                    fd,
                    raw,
                )
            finally:
                os.close(
                    fd
                )

    except Exception as exc:
        logger.warning(
            "[autoban] não foi possível gravar auditoria local: %s",
            exc,
        )


# =============================================================================
# HELPERS
# =============================================================================

def _bool(
    valor: Any,
) -> bool:
    if isinstance(
        valor,
        bool,
    ):
        return valor

    if valor is None:
        return False

    return str(
        valor
    ).strip().lower() in {
        "1",
        "true",
        "sim",
        "yes",
        "on",
        "ativo",
        "enabled",
    }


def _int(
    valor: Any,
    padrao: int,
) -> int:
    try:
        return int(
            valor
        )
    except (
        TypeError,
        ValueError,
    ):
        return padrao


def _int_min(
    valor: Any,
    minimo: int,
    padrao: int,
) -> int:
    return max(
        minimo,
        _int(
            valor,
            padrao,
        ),
    )


def _agora_iso() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()