"""
MoonShield Agent — Rede / Configuração
======================================

Configuração central do módulo de Rede.

Responsabilidades:
- definir caminhos e limites;
- identificar backend disponível;
- fornecer instância do backend;
- expor informações básicas do ambiente.

Não aplica alterações na rede.
"""

from __future__ import annotations

import os
import platform
import shutil
import threading
from pathlib import Path
from typing import Any

from rede.backends.base import BackendIndisponivel, BackendRede
from rede.backends.networkmanager import NetworkManagerBackend


VERSAO_MODULO_REDE = "1.0"

ETC_MOONSHIELD = Path("/etc/moonshield")
VAR_LIB_MOONSHIELD = Path("/var/lib/moonshield")
VAR_LOG_MOONSHIELD = Path("/var/log/moonshield")
RUN_MOONSHIELD = Path("/run/moonshield")

ETC_REDE = ETC_MOONSHIELD / "rede"
VAR_LIB_REDE = VAR_LIB_MOONSHIELD / "rede"
VAR_LOG_REDE = VAR_LOG_MOONSHIELD / "rede"
RUN_REDE = RUN_MOONSHIELD / "rede"

ARQUIVO_CONFIG_REDE = ETC_REDE / "network.json"
DIRETORIO_SNAPSHOTS = VAR_LIB_REDE / "snapshots"
DIRETORIO_ALTERACOES = VAR_LIB_REDE / "changes"
ARQUIVO_ESTADO_REDE = VAR_LIB_REDE / "state.json"

ROLLBACK_PADRAO_SEGUNDOS = 60
ROLLBACK_MINIMO_SEGUNDOS = 15
ROLLBACK_MAXIMO_SEGUNDOS = 600

BACKEND_PADRAO = "networkmanager"

_backend_lock = threading.RLock()
_backend_cache: BackendRede | None = None


# =============================================================================
# AMBIENTE
# =============================================================================

def eh_linux() -> bool:
    return platform.system().lower() == "linux"


def eh_root() -> bool:
    if not hasattr(os, "geteuid"):
        return False
    return os.geteuid() == 0


def comando_existe(nome: str) -> bool:
    return shutil.which(nome) is not None


def obter_info_ambiente() -> dict[str, Any]:
    return {
        "sistema": platform.system(),
        "release": platform.release(),
        "arquitetura": platform.machine(),
        "hostname": platform.node(),
        "linux": eh_linux(),
        "root": eh_root(),
        "nmcli": shutil.which("nmcli"),
        "ip": shutil.which("ip"),
        "nft": shutil.which("nft"),
    }


# =============================================================================
# DIRETÓRIOS
# =============================================================================

def garantir_diretorios() -> dict[str, str]:
    caminhos = (
        ETC_REDE,
        VAR_LIB_REDE,
        VAR_LOG_REDE,
        RUN_REDE,
        DIRETORIO_SNAPSHOTS,
        DIRETORIO_ALTERACOES,
    )

    for caminho in caminhos:
        caminho.mkdir(parents=True, exist_ok=True)

    return {
        "config": str(ETC_REDE),
        "estado": str(VAR_LIB_REDE),
        "logs": str(VAR_LOG_REDE),
        "runtime": str(RUN_REDE),
        "snapshots": str(DIRETORIO_SNAPSHOTS),
        "alteracoes": str(DIRETORIO_ALTERACOES),
    }


# =============================================================================
# BACKEND
# =============================================================================

def detectar_backend() -> str | None:
    if comando_existe("nmcli"):
        return "networkmanager"
    return None


def criar_backend(nome: str | None = None) -> BackendRede:
    backend_nome = (nome or detectar_backend() or BACKEND_PADRAO).strip().lower()

    if backend_nome in {"networkmanager", "network-manager", "nm", "nmcli"}:
        backend = NetworkManagerBackend()

        if not backend.disponivel():
            raise BackendIndisponivel(
                "NetworkManager não está disponível ou não está ativo.",
                detalhes={
                    "backend": "networkmanager",
                    "nmcli": backend.nmcli,
                    "ip": backend.ip,
                },
            )

        return backend

    raise BackendIndisponivel(
        f"Backend de rede não suportado: {backend_nome}",
        detalhes={"backend": backend_nome},
    )


def obter_backend(*, renovar: bool = False) -> BackendRede:
    global _backend_cache

    with _backend_lock:
        if renovar or _backend_cache is None:
            _backend_cache = criar_backend()

        return _backend_cache


def limpar_cache_backend() -> None:
    global _backend_cache

    with _backend_lock:
        _backend_cache = None


# =============================================================================
# STATUS
# =============================================================================

def obter_configuracao_modulo() -> dict[str, Any]:
    backend_detectado = detectar_backend()

    return {
        "versao": VERSAO_MODULO_REDE,
        "backend_padrao": BACKEND_PADRAO,
        "backend_detectado": backend_detectado,
        "rollback": {
            "padrao_segundos": ROLLBACK_PADRAO_SEGUNDOS,
            "minimo_segundos": ROLLBACK_MINIMO_SEGUNDOS,
            "maximo_segundos": ROLLBACK_MAXIMO_SEGUNDOS,
        },
        "caminhos": {
            "config": str(ARQUIVO_CONFIG_REDE),
            "estado": str(ARQUIVO_ESTADO_REDE),
            "snapshots": str(DIRETORIO_SNAPSHOTS),
            "alteracoes": str(DIRETORIO_ALTERACOES),
            "logs": str(VAR_LOG_REDE),
        },
        "ambiente": obter_info_ambiente(),
    }


__all__ = [
    "VERSAO_MODULO_REDE",
    "ETC_REDE",
    "VAR_LIB_REDE",
    "VAR_LOG_REDE",
    "RUN_REDE",
    "ARQUIVO_CONFIG_REDE",
    "ARQUIVO_ESTADO_REDE",
    "DIRETORIO_SNAPSHOTS",
    "DIRETORIO_ALTERACOES",
    "ROLLBACK_PADRAO_SEGUNDOS",
    "ROLLBACK_MINIMO_SEGUNDOS",
    "ROLLBACK_MAXIMO_SEGUNDOS",
    "BACKEND_PADRAO",
    "eh_linux",
    "eh_root",
    "comando_existe",
    "obter_info_ambiente",
    "garantir_diretorios",
    "detectar_backend",
    "criar_backend",
    "obter_backend",
    "limpar_cache_backend",
    "obter_configuracao_modulo",
]