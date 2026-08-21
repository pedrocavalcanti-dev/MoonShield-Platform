"""
MoonShield Agent — Firewall / Monitoramento
===========================================

Monitor local do nftables.

Arquitetura NOVA:
    nftables LOG
        ↓
    kernel / journald
        ↓
    firewall.nucleo.analisador
        ↓
    events.jsonl local
        ↓
    Django/worker local (depois)

Este módulo NÃO:
- faz HTTP;
- usa Moon_url;
- usa sensor_nome;
- usa token;
- envia heartbeat;
- chama /firewall/api/ingest/.

Também integra o AutoBan localmente, sem depender do Django.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from firewall.nucleo.analisador import (
    VERSAO_ANALISADOR,
    parsear_linha,
)
from firewall.monitoramento import autoban


logger = logging.getLogger(__name__)


# =============================================================================
# CONSTANTES
# =============================================================================

VERSAO_MONITORAMENTO = "3.0"

DIRETORIO_LOG = Path("/var/log/moonshield/firewall")
ARQUIVO_EVENTOS = DIRETORIO_LOG / "events.jsonl"
ARQUIVO_ERROS = DIRETORIO_LOG / "monitor-errors.log"

MAX_LOG_BYTES = 50 * 1024 * 1024
MAX_ROTACOES = 5

JOURNAL_RESTART_DELAY = 2.0

# `short-iso-precise` ajuda o analisador a preservar timestamp.
JOURNAL_CMD = [
    "journalctl",
    "-f",
    "-k",
    "-o",
    "short-iso-precise",
    "--grep",
    "MS-",
    "--no-pager",
]


# =============================================================================
# ESTADO
# =============================================================================

_stats_lock = threading.RLock()

_fw_stats: dict[str, Any] = {
    "rodando": False,
    "vistos": 0,
    "parseados": 0,
    "gravados": 0,
    "ignorados": 0,
    "erros": 0,

    "drops_sessao": 0,
    "allows_sessao": 0,
    "rejects_sessao": 0,

    "autobans_sessao": 0,

    "ultimo": "—",
    "ultimo_src_ip": "—",
    "ultimo_dst_ip": "—",
    "ultima_acao": "—",

    "arquivo_eventos": str(ARQUIVO_EVENTOS),
    "pid_journalctl": None,
    "reinicios_journalctl": 0,

    "versao_monitoramento": VERSAO_MONITORAMENTO,
    "versao_analisador": VERSAO_ANALISADOR,
}

_thread_ref: threading.Thread | None = None
_proc_ref: subprocess.Popen | None = None
_proc_lock = threading.RLock()
_write_lock = threading.RLock()


# =============================================================================
# API PÚBLICA
# =============================================================================

def obter_stats() -> dict[str, Any]:
    with _stats_lock:
        stats = dict(_fw_stats)

    try:
        stats["arquivo_bytes"] = (
            ARQUIVO_EVENTOS.stat().st_size
            if ARQUIVO_EVENTOS.exists()
            else 0
        )
    except Exception:
        stats["arquivo_bytes"] = 0

    stats["autoban"] = autoban.obter_stats()
    return stats


def esta_rodando() -> bool:
    with _stats_lock:
        return bool(_fw_stats["rodando"])


def iniciar_monitoramento(
    cfg: dict[str, Any] | None,
    parar: threading.Event,
    *args,
    **kwargs,
) -> threading.Thread:
    """
    Inicia o monitor em thread.

    `*args/**kwargs` são aceitos apenas para não quebrar imediatamente
    chamadas antigas que ainda passavam session/session_lock durante a migração.
    Eles são ignorados e podem ser removidos depois.
    """
    global _thread_ref

    if esta_rodando() and _thread_ref and _thread_ref.is_alive():
        return _thread_ref

    cfg = cfg or {}

    _preparar_logs()

    with _stats_lock:
        _fw_stats.update({
            "rodando": True,
            "vistos": 0,
            "parseados": 0,
            "gravados": 0,
            "ignorados": 0,
            "erros": 0,
            "drops_sessao": 0,
            "allows_sessao": 0,
            "rejects_sessao": 0,
            "autobans_sessao": 0,
            "ultimo": "—",
            "ultimo_src_ip": "—",
            "ultimo_dst_ip": "—",
            "ultima_acao": "—",
            "pid_journalctl": None,
            "reinicios_journalctl": 0,
        })

    autoban.configurar(cfg)

    thread = threading.Thread(
        target=_loop_firewall,
        args=(cfg, parar),
        name="moonshield-firewall-monitor",
        daemon=True,
    )
    _thread_ref = thread
    thread.start()
    return thread


def parar_monitoramento() -> None:
    global _proc_ref

    with _stats_lock:
        _fw_stats["rodando"] = False

    with _proc_lock:
        proc = _proc_ref

    if proc is not None:
        try:
            proc.terminate()
        except Exception:
            pass


def processar_linha(
    linha: str,
    cfg: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """
    Função pública útil para testes sem `journalctl -f`.

    Parseia, grava e envia o evento ao AutoBan.
    """
    with _stats_lock:
        _fw_stats["vistos"] += 1

    evento = parsear_linha(linha)

    if not evento:
        with _stats_lock:
            _fw_stats["ignorados"] += 1
        return None

    with _stats_lock:
        _fw_stats["parseados"] += 1

    _atualizar_stats_evento(evento)

    try:
        _gravar_evento(evento)

        with _stats_lock:
            _fw_stats["gravados"] += 1
            _fw_stats["ultimo"] = _agora_iso()

    except Exception as exc:
        _registrar_erro(
            f"Falha ao gravar evento: {exc}"
        )
        return evento

    try:
        resultado_ban = autoban.registrar_evento(
            evento,
            cfg or {},
        )

        if resultado_ban and resultado_ban.get("banido"):
            with _stats_lock:
                _fw_stats["autobans_sessao"] += 1

    except Exception as exc:
        _registrar_erro(
            f"AutoBan falhou: {exc}"
        )

    return evento


def obter_caminho_eventos() -> str:
    return str(ARQUIVO_EVENTOS)


# =============================================================================
# LOOP
# =============================================================================

def _loop_firewall(
    cfg: dict[str, Any],
    parar: threading.Event,
) -> None:
    global _proc_ref

    journalctl = shutil.which("journalctl")

    if not journalctl:
        _registrar_erro(
            "journalctl não encontrado."
        )
        with _stats_lock:
            _fw_stats["rodando"] = False
        return

    cmd = list(JOURNAL_CMD)
    cmd[0] = journalctl

    try:
        while not parar.is_set():
            proc = None

            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    errors="replace",
                )

                with _proc_lock:
                    _proc_ref = proc

                with _stats_lock:
                    _fw_stats["pid_journalctl"] = proc.pid

                logger.info(
                    "[fw-monitor] journalctl iniciado pid=%s",
                    proc.pid,
                )

                if proc.stdout is None:
                    raise RuntimeError(
                        "stdout do journalctl indisponível."
                    )

                while not parar.is_set():
                    linha = proc.stdout.readline()

                    if linha:
                        processar_linha(
                            linha.strip(),
                            cfg,
                        )
                        continue

                    retorno = proc.poll()

                    if retorno is not None:
                        stderr = ""

                        try:
                            if proc.stderr:
                                stderr = (
                                    proc.stderr.read()
                                    or ""
                                ).strip()
                        except Exception:
                            pass

                        raise RuntimeError(
                            f"journalctl encerrou rc={retorno}"
                            + (
                                f": {stderr[:500]}"
                                if stderr
                                else ""
                            )
                        )

                    time.sleep(0.05)

            except Exception as exc:
                if not parar.is_set():
                    _registrar_erro(
                        f"Monitor reiniciando: {exc}"
                    )

                    with _stats_lock:
                        _fw_stats["reinicios_journalctl"] += 1

                    parar.wait(
                        JOURNAL_RESTART_DELAY
                    )

            finally:
                if proc is not None:
                    _encerrar_proc(proc)

                with _proc_lock:
                    _proc_ref = None

                with _stats_lock:
                    _fw_stats["pid_journalctl"] = None

    finally:
        with _stats_lock:
            _fw_stats["rodando"] = False

        logger.info(
            "[fw-monitor] monitor encerrado"
        )


# =============================================================================
# EVENTOS
# =============================================================================

def _gravar_evento(
    evento: dict[str, Any],
) -> None:
    _preparar_logs()
    _rotacionar_se_necessario()

    envelope = {
        "schema": 1,
        "tipo_evento": "firewall",
        "gravado_em": _agora_iso(),
        "evento": evento,
    }

    linha = (
        json.dumps(
            envelope,
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        )
        + "\n"
    ).encode("utf-8")

    # O_APPEND + uma única escrita ajuda a manter append consistente.
    with _write_lock:
        fd = os.open(
            ARQUIVO_EVENTOS,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_APPEND,
            0o640,
        )

        try:
            os.write(
                fd,
                linha,
            )
        finally:
            os.close(
                fd
            )


def _atualizar_stats_evento(
    evento: dict[str, Any],
) -> None:
    acao = str(
        evento.get("acao")
        or ""
    ).upper()

    with _stats_lock:
        if acao in {
            "DROP",
            "DENY",
        }:
            _fw_stats["drops_sessao"] += 1

        elif acao == "REJECT":
            _fw_stats["rejects_sessao"] += 1

        elif acao in {
            "ALLOW",
            "ACCEPT",
            "LOG",
        }:
            _fw_stats["allows_sessao"] += 1

        _fw_stats["ultimo_src_ip"] = (
            evento.get("src_ip")
            or "—"
        )

        _fw_stats["ultimo_dst_ip"] = (
            evento.get("dst_ip")
            or "—"
        )

        _fw_stats["ultima_acao"] = (
            acao
            or "—"
        )


# =============================================================================
# LOGS / ROTAÇÃO
# =============================================================================

def _preparar_logs() -> None:
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


def _rotacionar_se_necessario() -> None:
    try:
        if (
            not ARQUIVO_EVENTOS.exists()
            or ARQUIVO_EVENTOS.stat().st_size < MAX_LOG_BYTES
        ):
            return

        with _write_lock:
            # event.jsonl.4 -> .5, etc.
            for indice in range(
                MAX_ROTACOES - 1,
                0,
                -1,
            ):
                origem = Path(
                    f"{ARQUIVO_EVENTOS}.{indice}"
                )

                destino = Path(
                    f"{ARQUIVO_EVENTOS}.{indice + 1}"
                )

                if origem.exists():
                    origem.replace(
                        destino
                    )

            primeiro = Path(
                f"{ARQUIVO_EVENTOS}.1"
            )

            ARQUIVO_EVENTOS.replace(
                primeiro
            )

    except Exception as exc:
        _registrar_erro(
            f"Falha na rotação de log: {exc}"
        )


def _registrar_erro(
    mensagem: str,
) -> None:
    logger.error(
        "[fw-monitor] %s",
        mensagem,
    )

    with _stats_lock:
        _fw_stats["erros"] += 1
        _fw_stats["ultimo"] = (
            f"ERRO: {str(mensagem)[:180]}"
        )

    try:
        _preparar_logs()

        texto = (
            f"{_agora_iso()} | "
            f"{mensagem}\n"
        )

        with open(
            ARQUIVO_ERROS,
            "a",
            encoding="utf-8",
        ) as fp:
            fp.write(
                texto
            )

    except Exception:
        pass


# =============================================================================
# PROCESSO
# =============================================================================

def _encerrar_proc(
    proc: subprocess.Popen,
) -> None:
    try:
        if proc.poll() is None:
            proc.terminate()

            try:
                proc.wait(
                    timeout=3
                )
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(
                    timeout=2
                )
    except Exception:
        pass


def _agora_iso() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()