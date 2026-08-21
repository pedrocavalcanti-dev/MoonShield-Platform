"""
MoonShield Agent — Firewall / Status
====================================

Fonte de verdade local para o estado operacional do Firewall MoonShield.

Este módulo NÃO altera o sistema.
Ele apenas inspeciona:

- Linux / root;
- disponibilidade e versão do nftables;
- existência da tabela `inet moonshield`;
- chains obrigatórias;
- interfaces WAN/LAN/MGMT;
- HOME_NET;
- regras carregadas;
- bloqueios emergenciais;
- diretórios/arquivos do MoonShield;
- IPC local do Agent;
- estado consolidado da stack.

O Django deve consultar este módulo por IPC através de:

    firewall.status
    firewall.interfaces
    firewall.rules
    firewall.emergency
    firewall.diagnostico

Nenhum healthcheck executa instalação, flush, apply ou rollback.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import stat
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from firewall.nucleo.seguranca import (
    CHAIN_EMERGENCY,
    CHAIN_FORWARD,
    CHAIN_INPUT,
    CHAIN_OUTPUT,
    CHAIN_RULES,
    CHAIN_SYSTEM,
    TABELA_FAMILIA,
    TABELA_NOME,
    ContextoSeguranca,
    detectar_contexto,
    nft_disponivel,
    nft_versao,
    validar_topologia,
)


VERSAO_STATUS = "1.0"

TIMEOUT_COMANDO = 8

DIRETORIO_CONFIG = Path("/etc/moonshield/firewall")
ARQUIVO_CONFIG = DIRETORIO_CONFIG / "firewall.json"

DIRETORIO_STATE = Path("/var/lib/moonshield/firewall")
DIRETORIO_SNAPSHOTS = DIRETORIO_STATE / "snapshots"

SOCKET_AGENT = Path("/run/moonshield/agent.sock")

CHAINS_OBRIGATORIAS = (
    CHAIN_SYSTEM,
    CHAIN_EMERGENCY,
    CHAIN_RULES,
    CHAIN_INPUT,
    CHAIN_FORWARD,
    CHAIN_OUTPUT,
)


# =============================================================================
# CONFIGURAÇÃO
# =============================================================================

def carregar_config_local() -> dict[str, Any]:
    """
    Carrega somente a configuração local do Firewall Agent.

    Não consulta Django e não usa HTTP.
    """
    try:
        if not ARQUIVO_CONFIG.exists():
            return {}

        dados = json.loads(
            ARQUIVO_CONFIG.read_text(
                encoding="utf-8",
            )
        )

        return (
            dados
            if isinstance(dados, dict)
            else {}
        )

    except Exception:
        return {}


# =============================================================================
# STATUS PRINCIPAL
# =============================================================================

def obter_status(
    dados: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Retorna o status consolidado do Firewall local.

    `dados` pode opcionalmente conter:
        {"config": {...}}

    para consulta antes de a configuração estar persistida.
    """
    dados = dados or {}

    cfg = dados.get("config")

    if not isinstance(cfg, dict):
        cfg = carregar_config_local()

    contexto = detectar_contexto(
        cfg
    )

    topo = validar_topologia(
        contexto,
        exigir_wan=False,
        exigir_lan=False,
        exigir_mgmt=False,
    )

    nft_ok = nft_disponivel()
    tabela = _obter_tabela()
    chains = tabela.get(
        "chains",
        {},
    )

    chains_faltando = [
        nome
        for nome in CHAINS_OBRIGATORIAS
        if not chains.get(
            nome,
            False,
        )
    ]

    config_existe = ARQUIVO_CONFIG.exists()

    instalado = bool(
        nft_ok
        and tabela.get(
            "existe",
            False,
        )
    )

    configurado = bool(
        config_existe
        and topo.ok
        and contexto.interface_wan
        and contexto.interface_lan
    )

    operacional = bool(
        instalado
        and configurado
        and not chains_faltando
    )

    if not nft_ok:
        status = "nao_instalado"
        status_label = "nftables não instalado"

    elif not tabela.get(
        "existe",
        False,
    ):
        status = "nao_instalado"
        status_label = "Firewall não instalado"

    elif not configurado:
        status = "configuracao_pendente"
        status_label = "Configuração pendente"

    elif chains_faltando:
        status = "atencao"
        status_label = "Requer reparo"

    else:
        status = "operacional"
        status_label = "Operacional"

    interfaces = obter_interfaces(
        {
            "config": cfg,
        }
    )

    return {
        "ok": True,
        "versao_status": VERSAO_STATUS,

        "status": status,
        "status_label": status_label,

        "instalado": instalado,
        "configurado": configurado,
        "operacional": operacional,
        "saudavel": operacional,

        "nftables": {
            "instalado": nft_ok,
            "versao": nft_versao(),
        },

        "tabela": tabela,

        "chains": {
            "obrigatorias": list(
                CHAINS_OBRIGATORIAS
            ),
            "faltando": chains_faltando,
            "ok": not chains_faltando,
        },

        "configuracao": {
            "arquivo": str(
                ARQUIVO_CONFIG
            ),
            "existe": config_existe,
            "dados": cfg,
        },

        "topologia": {
            "ok": topo.ok,
            "erros": topo.erros,
            "avisos": topo.avisos,

            "wan": contexto.interface_wan,
            "lan": contexto.interface_lan,
            "mgmt": contexto.interface_mgmt,
            "home_net": contexto.home_net,
            "ip_local": contexto.ip_local,
            "gateway": contexto.gateway,
            "rede_mgmt": contexto.rede_mgmt,
        },

        "interfaces": interfaces.get(
            "interfaces",
            [],
        ),

        "ipc": _obter_status_socket(),

        "paths": {
            "config": str(
                DIRETORIO_CONFIG
            ),
            "state": str(
                DIRETORIO_STATE
            ),
            "snapshots": str(
                DIRETORIO_SNAPSHOTS
            ),
        },

        "atualizado_em": _agora_iso(),
    }


# =============================================================================
# INTERFACES
# =============================================================================

def obter_interfaces(
    dados: dict[str, Any] | None = None,
) -> dict[str, Any]:
    dados = dados or {}

    cfg = dados.get(
        "config",
    )

    if not isinstance(
        cfg,
        dict,
    ):
        cfg = carregar_config_local()

    contexto = detectar_contexto(
        cfg
    )

    interfaces: list[dict[str, Any]] = []

    base = Path(
        "/sys/class/net"
    )

    try:
        nomes = sorted(
            item.name
            for item in base.iterdir()
            if item.name != "lo"
        )

    except Exception:
        nomes = []

    for nome in nomes:
        ip = _ip_da_interface(
            nome
        )

        rede = _rede_da_interface(
            nome
        )

        estado = _estado_interface(
            nome
        )

        papeis: list[str] = []

        if nome == contexto.interface_wan:
            papeis.append(
                "WAN"
            )

        if nome == contexto.interface_lan:
            papeis.append(
                "LAN"
            )

        if nome == contexto.interface_mgmt:
            papeis.append(
                "MGMT"
            )

        interfaces.append(
            {
                "nome": nome,
                "estado": estado,
                "up": (
                    estado == "up"
                    or bool(
                        ip
                    )
                ),
                "ip": ip,
                "rede": rede,
                "papeis": papeis,
            }
        )

    return {
        "ok": True,
        "interfaces": interfaces,

        "mapeamento": {
            "WAN": contexto.interface_wan,
            "LAN": contexto.interface_lan,
            "MGMT": contexto.interface_mgmt,
        },

        "home_net": contexto.home_net,
        "gateway": contexto.gateway,

        "total": len(
            interfaces
        ),
    }


def listar_interfaces(
    dados: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return obter_interfaces(
        dados
    )


# =============================================================================
# REGRAS
# =============================================================================

def obter_regras(
    dados: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Lista a chain administrativa `ms_rules`.

    Não retorna dump de tabelas externas.
    """
    return _listar_chain(
        CHAIN_RULES
    )


def listar_regras(
    dados: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return obter_regras(
        dados
    )


def obter_emergency(
    dados: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return _listar_chain(
        CHAIN_EMERGENCY
    )


def listar_emergency(
    dados: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return obter_emergency(
        dados
    )


# =============================================================================
# DIAGNÓSTICO
# =============================================================================

def diagnosticar(
    dados: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Diagnóstico rápido e somente leitura.

    NÃO executa mudanças.
    NÃO executa instalação.
    NÃO executa flush/apply.
    """
    inicio = time.monotonic()

    status = obter_status(
        dados
    )

    checks: list[dict[str, Any]] = []

    def add(
        ident: str,
        titulo: str,
        ok: bool,
        detalhe: str,
        *,
        critico: bool = False,
    ) -> None:
        checks.append(
            {
                "id": ident,
                "titulo": titulo,
                "ok": bool(
                    ok
                ),
                "status": (
                    "ok"
                    if ok
                    else (
                        "critico"
                        if critico
                        else "aviso"
                    )
                ),
                "detalhe": detalhe,
                "critico": critico,
            }
        )

    nft_info = status[
        "nftables"
    ]

    add(
        "linux",
        "Sistema Linux",
        os.name == "posix",
        os.uname().sysname
        if hasattr(
            os,
            "uname",
        )
        else os.name,
        critico=True,
    )

    add(
        "root",
        "Privilégios do Agent",
        (
            os.geteuid() == 0
            if hasattr(
                os,
                "geteuid",
            )
            else False
        ),
        "Executando como root."
        if (
            hasattr(
                os,
                "geteuid",
            )
            and os.geteuid() == 0
        )
        else "O Agent não está executando como root.",
        critico=True,
    )

    add(
        "nftables",
        "Binário nftables",
        nft_info[
            "instalado"
        ],
        nft_info[
            "versao"
        ]
        or "nft não encontrado.",
        critico=True,
    )

    tabela = status[
        "tabela"
    ]

    add(
        "tabela",
        "Tabela MoonShield",
        tabela[
            "existe"
        ],
        (
            f"{TABELA_FAMILIA} {TABELA_NOME}"
            if tabela[
                "existe"
            ]
            else "Tabela ainda não instalada."
        ),
        critico=True,
    )

    add(
        "chains",
        "Chains obrigatórias",
        status[
            "chains"
        ][
            "ok"
        ],
        (
            "Todas presentes."
            if status[
                "chains"
            ][
                "ok"
            ]
            else (
                "Faltando: "
                + ", ".join(
                    status[
                        "chains"
                    ][
                        "faltando"
                    ]
                )
            )
        ),
        critico=True,
    )

    topologia = status[
        "topologia"
    ]

    add(
        "wan",
        "Interface WAN",
        bool(
            topologia[
                "wan"
            ]
        ),
        topologia[
            "wan"
        ]
        or "Não definida.",
        critico=True,
    )

    add(
        "lan",
        "Interface LAN",
        bool(
            topologia[
                "lan"
            ]
        ),
        topologia[
            "lan"
        ]
        or "Não definida.",
        critico=True,
    )

    add(
        "mgmt",
        "Interface de Gerenciamento",
        bool(
            topologia[
                "mgmt"
            ]
        ),
        topologia[
            "mgmt"
        ]
        or "Não definida. Opcional, porém recomendada.",
        critico=False,
    )

    add(
        "home_net",
        "HOME_NET",
        bool(
            topologia[
                "home_net"
            ]
        ),
        topologia[
            "home_net"
        ]
        or "Não definido.",
        critico=False,
    )

    ipc = status[
        "ipc"
    ]

    add(
        "ipc",
        "Socket IPC local",
        ipc[
            "existe"
        ],
        ipc[
            "caminho"
        ],
        critico=False,
    )

    total = len(
        checks
    )

    total_ok = sum(
        1
        for item in checks
        if item[
            "ok"
        ]
    )

    criticos = sum(
        1
        for item in checks
        if (
            not item[
                "ok"
            ]
            and item[
                "critico"
            ]
        )
    )

    return {
        "ok": (
            criticos == 0
        ),
        "pronto": (
            criticos == 0
        ),
        "total_checks": total,
        "total_ok": total_ok,
        "total_falhas": (
            total
            - total_ok
        ),
        "total_criticos": criticos,
        "itens": checks,
        "status": status,
        "duracao_segundos": round(
            time.monotonic()
            - inicio,
            4,
        ),
        "executado_em": _agora_iso(),
    }


def executar_diagnostico(
    dados: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return diagnosticar(
        dados
    )


# =============================================================================
# HELPERS NFT
# =============================================================================

def _obter_tabela() -> dict[str, Any]:
    nft = shutil.which(
        "nft"
    )

    if not nft:
        return {
            "existe": False,
            "chains": {
                nome: False
                for nome in CHAINS_OBRIGATORIAS
            },
            "bytes": 0,
            "erro": "nft não encontrado.",
        }

    try:
        result = subprocess.run(
            [
                nft,
                "-a",
                "list",
                "table",
                TABELA_FAMILIA,
                TABELA_NOME,
            ],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_COMANDO,
            check=False,
        )

    except Exception as exc:
        return {
            "existe": False,
            "chains": {
                nome: False
                for nome in CHAINS_OBRIGATORIAS
            },
            "bytes": 0,
            "erro": str(
                exc
            ),
        }

    if result.returncode != 0:
        return {
            "existe": False,
            "chains": {
                nome: False
                for nome in CHAINS_OBRIGATORIAS
            },
            "bytes": 0,
            "erro": (
                result.stderr.strip()
                or ""
            ),
        }

    saida = result.stdout or ""

    chains = {
        nome: (
            f"chain {nome}" in saida
        )
        for nome in CHAINS_OBRIGATORIAS
    }

    return {
        "existe": True,
        "familia": TABELA_FAMILIA,
        "nome": TABELA_NOME,
        "chains": chains,
        "bytes": len(
            saida.encode(
                "utf-8",
                errors="replace",
            )
        ),
        "erro": "",
    }


def _listar_chain(
    chain: str,
) -> dict[str, Any]:
    nft = shutil.which(
        "nft"
    )

    if not nft:
        return {
            "ok": False,
            "erro": "nft não encontrado.",
            "chain": chain,
            "regras": [],
            "total": 0,
        }

    try:
        result = subprocess.run(
            [
                nft,
                "-a",
                "list",
                "chain",
                TABELA_FAMILIA,
                TABELA_NOME,
                chain,
            ],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_COMANDO,
            check=False,
        )

    except Exception as exc:
        return {
            "ok": False,
            "erro": str(
                exc
            ),
            "chain": chain,
            "regras": [],
            "total": 0,
        }

    if result.returncode != 0:
        return {
            "ok": False,
            "erro": (
                result.stderr.strip()
                or "Chain indisponível."
            ),
            "chain": chain,
            "regras": [],
            "total": 0,
        }

    regras: list[dict[str, Any]] = []

    for linha in (
        result.stdout
        or ""
    ).splitlines():
        texto = linha.strip()

        if (
            not texto
            or texto.startswith(
                "table "
            )
            or texto.startswith(
                "chain "
            )
            or texto in {
                "{",
                "}",
            }
        ):
            continue

        handle = None

        if "# handle" in texto:
            antes, depois = texto.rsplit(
                "# handle",
                1,
            )

            texto = antes.strip()

            try:
                handle = int(
                    depois.strip().split()[0]
                )
            except Exception:
                handle = None

        regras.append(
            {
                "expressao": texto,
                "handle": handle,
            }
        )

    return {
        "ok": True,
        "chain": chain,
        "regras": regras,
        "total": len(
            regras
        ),
    }


# =============================================================================
# HELPERS DE SISTEMA
# =============================================================================

def _obter_status_socket() -> dict[str, Any]:
    existe = False
    socket_valido = False
    modo = None

    try:
        st = os.lstat(
            SOCKET_AGENT
        )

        existe = True
        socket_valido = stat.S_ISSOCK(
            st.st_mode
        )

        modo = oct(
            stat.S_IMODE(
                st.st_mode
            )
        )

    except FileNotFoundError:
        pass

    except Exception:
        pass

    return {
        "caminho": str(
            SOCKET_AGENT
        ),
        "existe": existe,
        "socket_valido": socket_valido,
        "modo": modo,
    }


def _estado_interface(
    nome: str,
) -> str:
    try:
        return Path(
            "/sys/class/net",
            nome,
            "operstate",
        ).read_text(
            encoding="utf-8"
        ).strip()

    except Exception:
        return "unknown"


def _ip_da_interface(
    nome: str,
) -> str:
    ip_bin = shutil.which(
        "ip"
    )

    if not ip_bin:
        return ""

    try:
        result = subprocess.run(
            [
                ip_bin,
                "-4",
                "-o",
                "addr",
                "show",
                "dev",
                nome,
            ],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )

    except Exception:
        return ""

    if result.returncode != 0:
        return ""

    partes = result.stdout.split()

    try:
        idx = partes.index(
            "inet"
        )

        return partes[
            idx + 1
        ].split(
            "/",
            1,
        )[0]

    except Exception:
        return ""


def _rede_da_interface(
    nome: str,
) -> str:
    ip_bin = shutil.which(
        "ip"
    )

    if not ip_bin:
        return ""

    try:
        result = subprocess.run(
            [
                ip_bin,
                "-4",
                "-o",
                "addr",
                "show",
                "dev",
                nome,
            ],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )

    except Exception:
        return ""

    if result.returncode != 0:
        return ""

    partes = result.stdout.split()

    try:
        idx = partes.index(
            "inet"
        )

        return partes[
            idx + 1
        ]

    except Exception:
        return ""


def _agora_iso() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()