"""
MoonShield Agent — Firewall / Instalador
========================================

Instalador PRIVILEGIADO do Firewall MoonShield no Linux.

IMPORTANTE SOBRE A ARQUITETURA
------------------------------
A tela de instalação, onboarding, progresso e tarefas pertencem ao Django.

Este arquivo fica no MoonShield-Agent porque somente o Agent deve executar:

- apt-get/install do nftables;
- criação de diretórios em /etc e /var/lib;
- criação da tabela `inet moonshield`;
- validação via `nft -c`;
- aplicação de regras base;
- reparo local;
- remoção controlada.

Portanto:

    Django = interface + orquestração + tarefa + logs
    Agent  = execução privilegiada Linux

O Django deve chamar este instalador via IPC local.

SEGURANÇA
---------
- somente nftables;
- NÃO migra iptables automaticamente;
- NÃO executa `iptables`;
- NÃO executa `flush ruleset`;
- NÃO altera tabelas nftables de terceiros;
- NÃO habilita/desabilita regras de terceiros;
- políticas iniciais são ACCEPT;
- cria somente `table inet moonshield`;
- protege MGMT através de `ms_system`;
- snapshot antes de alteração;
- `nft -c` antes de aplicar.

Este módulo usa somente biblioteca padrão.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from firewall.nucleo.rollback import (
    criar_snapshot,
    restaurar,
    tabela_existe,
)
from firewall.nucleo.seguranca import (
    CHAIN_EMERGENCY,
    CHAIN_FORWARD,
    CHAIN_INPUT,
    CHAIN_OUTPUT,
    CHAIN_RULES,
    CHAIN_SYSTEM,
    TABELA_FAMILIA,
    TABELA_NOME,
    detectar_contexto,
    gerar_regras_sistema,
    validar_script_nft,
    validar_topologia,
)
from firewall.nucleo.status import obter_status


VERSAO_INSTALADOR = "1.0"

TIMEOUT_COMANDO = 120
TIMEOUT_NFT = 30

DIRETORIO_CONFIG = Path(
    "/etc/moonshield/firewall"
)

ARQUIVO_CONFIG = (
    DIRETORIO_CONFIG
    / "firewall.json"
)

DIRETORIO_STATE = Path(
    "/var/lib/moonshield/firewall"
)

DIRETORIO_RUNTIME = Path(
    "/run/moonshield"
)

ARQUIVO_BASE = (
    DIRETORIO_CONFIG
    / "base.nft"
)

ARQUIVO_RULES = (
    DIRETORIO_CONFIG
    / "rules.nft"
)

ARQUIVO_NAT = (
    DIRETORIO_CONFIG
    / "nat.nft"
)


# =============================================================================
# API PÚBLICA
# =============================================================================

def instalar(
    dados: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Instala/prepara o Firewall local.

    Payload recomendado:
        {
            "config": {
                "interface_wan": "enp0s3",
                "interface_lan": "enp0s9",
                "interface_mgmt": "enp0s8",
                "home_net": "10.10.0.0/24"
            },
            "instalar_pacote": true
        }

    A instalação inicial mantém policy ACCEPT.
    """
    inicio = time.monotonic()

    dados = dados or {}

    cfg = dados.get(
        "config"
    )

    if not isinstance(
        cfg,
        dict,
    ):
        cfg = {}

    instalar_pacote = _bool(
        dados.get(
            "instalar_pacote",
            True,
        )
    )

    if not _linux():
        return _erro(
            "sistema_nao_suportado",
            "MoonShield Firewall requer Linux.",
            inicio,
        )

    if not _root():
        return _erro(
            "root_necessario",
            "A instalação deve ser executada pelo MoonShield-Agent como root.",
            inicio,
        )

    etapas: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # 1. nftables
    # ------------------------------------------------------------------

    nft = shutil.which(
        "nft"
    )

    if not nft:
        if not instalar_pacote:
            return _erro(
                "nftables_ausente",
                "nftables não está instalado.",
                inicio,
            )

        resultado_pacote = (
            _instalar_nftables()
        )

        etapas.append(
            {
                "etapa": "instalar_nftables",
                **resultado_pacote,
            }
        )

        if not resultado_pacote[
            "ok"
        ]:
            return _erro(
                "instalacao_nftables_falhou",
                resultado_pacote.get(
                    "erro",
                    "Falha ao instalar nftables.",
                ),
                inicio,
                etapas=etapas,
            )

        nft = shutil.which(
            "nft"
        )

    if not nft:
        return _erro(
            "nftables_indisponivel",
            "nft continua indisponível após instalação.",
            inicio,
            etapas=etapas,
        )

    etapas.append(
        {
            "etapa": "nftables",
            "ok": True,
            "mensagem": "nftables disponível.",
            "versao": _versao_nft(
                nft
            ),
        }
    )

    # ------------------------------------------------------------------
    # 2. Diretórios
    # ------------------------------------------------------------------

    try:
        _criar_diretorios()

        etapas.append(
            {
                "etapa": "diretorios",
                "ok": True,
                "mensagem": "Diretórios MoonShield preparados.",
            }
        )

    except Exception as exc:
        return _erro(
            "diretorios_falharam",
            str(
                exc
            ),
            inicio,
            etapas=etapas,
        )

    # ------------------------------------------------------------------
    # 3. Topologia
    # ------------------------------------------------------------------

    contexto = detectar_contexto(
        cfg
    )

    topologia = validar_topologia(
        contexto,
        exigir_wan=True,
        exigir_lan=True,
        exigir_mgmt=False,
    )

    etapas.append(
        {
            "etapa": "topologia",
            "ok": topologia.ok,
            "detalhes": topologia.para_dict(),
        }
    )

    if not topologia.ok:
        return _erro(
            "topologia_invalida",
            "WAN/LAN não estão prontas para instalação.",
            inicio,
            etapas=etapas,
            detalhes=topologia.para_dict(),
        )

    # ------------------------------------------------------------------
    # 4. iptables — SOMENTE DETECÇÃO
    # ------------------------------------------------------------------

    legado = _detectar_iptables()

    etapas.append(
        {
            "etapa": "iptables",
            "ok": True,
            "mensagem": (
                "iptables detectado; nenhuma regra será alterada."
                if legado[
                    "detectado"
                ]
                else "iptables não detectado."
            ),
            "detalhes": legado,
        }
    )

    # ------------------------------------------------------------------
    # 5. Persistência da config
    # ------------------------------------------------------------------

    config_final = {
        "versao": 1,

        "interface_wan": contexto.interface_wan,
        "interface_lan": contexto.interface_lan,
        "interface_mgmt": contexto.interface_mgmt,

        "home_net": contexto.home_net,

        "ip_local": contexto.ip_local,
        "gateway": contexto.gateway,
        "rede_mgmt": contexto.rede_mgmt,

        "tabela": (
            f"{TABELA_FAMILIA} "
            f"{TABELA_NOME}"
        ),

        "instalado_em": _agora_iso(),
    }

    try:
        _salvar_config(
            config_final
        )

        etapas.append(
            {
                "etapa": "configuracao",
                "ok": True,
                "arquivo": str(
                    ARQUIVO_CONFIG
                ),
            }
        )

    except Exception as exc:
        return _erro(
            "configuracao_falhou",
            str(
                exc
            ),
            inicio,
            etapas=etapas,
        )

    # ------------------------------------------------------------------
    # 6. Gera base segura
    # ------------------------------------------------------------------

    script = _gerar_base(
        contexto
    )

    validacao_textual = validar_script_nft(
        script,
        permitir_delete_table_moonshield=True,
    )

    if not validacao_textual.ok:
        return _erro(
            "base_insegura",
            "Configuração base rejeitada pela segurança.",
            inicio,
            etapas=etapas,
            detalhes=validacao_textual.para_dict(),
        )

    ARQUIVO_BASE.write_text(
        script,
        encoding="utf-8",
    )

    # Mantém arquivos separados preparados para as próximas fases.
    if not ARQUIVO_RULES.exists():
        ARQUIVO_RULES.write_text(
            "# MoonShield Firewall — regras administrativas\n",
            encoding="utf-8",
        )

    if not ARQUIVO_NAT.exists():
        ARQUIVO_NAT.write_text(
            "# MoonShield Firewall — NAT (não configurado)\n",
            encoding="utf-8",
        )

    etapas.append(
        {
            "etapa": "gerar_base",
            "ok": True,
            "arquivo": str(
                ARQUIVO_BASE
            ),
        }
    )

    # ------------------------------------------------------------------
    # 7. Snapshot
    # ------------------------------------------------------------------

    try:
        snapshot = criar_snapshot(
            "antes_instalacao_firewall",
            metadados={
                "operacao": "instalar",
            },
        )

        snapshot_id = (
            snapshot[
                "snapshot"
            ][
                "id"
            ]
        )

        etapas.append(
            {
                "etapa": "snapshot",
                "ok": True,
                "snapshot_id": snapshot_id,
            }
        )

    except Exception as exc:
        return _erro(
            "snapshot_falhou",
            str(
                exc
            ),
            inicio,
            etapas=etapas,
        )

    # ------------------------------------------------------------------
    # 8. nft -c
    # ------------------------------------------------------------------

    check = _nft_check(
        nft,
        script,
    )

    etapas.append(
        {
            "etapa": "validar_nft",
            **check,
        }
    )

    if not check[
        "ok"
    ]:
        return _erro(
            "validacao_nft_falhou",
            check.get(
                "erro",
                "nft -c rejeitou a configuração.",
            ),
            inicio,
            etapas=etapas,
            snapshot_id=snapshot_id,
        )

    # ------------------------------------------------------------------
    # 9. Apply
    # ------------------------------------------------------------------

    apply = _nft_apply(
        nft,
        script,
    )

    etapas.append(
        {
            "etapa": "aplicar_base",
            **apply,
        }
    )

    if not apply[
        "ok"
    ]:
        rollback = restaurar(
            snapshot_id
        )

        return _erro(
            "apply_falhou",
            apply.get(
                "erro",
                "Falha ao aplicar firewall.",
            ),
            inicio,
            etapas=etapas,
            snapshot_id=snapshot_id,
            rollback=rollback,
        )

    # ------------------------------------------------------------------
    # 10. Status final
    # ------------------------------------------------------------------

    status = obter_status()

    etapas.append(
        {
            "etapa": "healthcheck",
            "ok": bool(
                status.get(
                    "operacional"
                )
            ),
            "status": status.get(
                "status"
            ),
        }
    )

    if not status.get(
        "instalado",
        False,
    ):
        rollback = restaurar(
            snapshot_id
        )

        return _erro(
            "healthcheck_falhou",
            "A tabela foi aplicada, mas o healthcheck não confirmou a instalação.",
            inicio,
            etapas=etapas,
            snapshot_id=snapshot_id,
            rollback=rollback,
            detalhes=status,
        )

    duracao = (
        time.monotonic()
        - inicio
    )

    return {
        "ok": True,
        "status": "sucesso",
        "mensagem": "MoonShield Firewall instalado com segurança.",

        "snapshot_id": snapshot_id,

        "configuracao": config_final,

        "status_firewall": status,

        "iptables": legado,

        "etapas": etapas,

        "duracao_segundos": round(
            duracao,
            3,
        ),
    }


def instalar_firewall(
    dados: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return instalar(
        dados
    )


# =============================================================================
# REPARO
# =============================================================================

def reparar(
    dados: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Reaplica a base MoonShield usando a configuração persistida.

    Não altera iptables.
    Não altera tabelas externas.
    """
    dados = dados or {}

    cfg = _carregar_config()

    if not cfg:
        cfg = dados.get(
            "config",
            {}
        )

    if not isinstance(
        cfg,
        dict,
    ):
        cfg = {}

    payload = dict(
        dados
    )

    payload[
        "config"
    ] = cfg

    # Não precisa instalar pacote se já existe.
    payload[
        "instalar_pacote"
    ] = True

    return instalar(
        payload
    )


def reparar_firewall(
    dados: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return reparar(
        dados
    )


# =============================================================================
# DESINSTALAÇÃO
# =============================================================================

def desinstalar(
    dados: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Remove SOMENTE `table inet moonshield`.

    O pacote nftables não é removido.
    iptables não é alterado.
    Config e snapshots são preservados por padrão.

    Para apagar config local:
        {"remover_config": true}
    """
    inicio = time.monotonic()

    dados = dados or {}

    if not _bool(
        dados.get(
            "confirmar"
        )
    ):
        return _erro(
            "confirmacao_necessaria",
            "Desinstalação exige confirmar=true.",
            inicio,
        )

    if not _root():
        return _erro(
            "root_necessario",
            "MoonShield-Agent precisa executar como root.",
            inicio,
        )

    nft = shutil.which(
        "nft"
    )

    if not nft:
        return _erro(
            "nft_indisponivel",
            "nft não encontrado.",
            inicio,
        )

    try:
        snapshot = criar_snapshot(
            "antes_desinstalacao_firewall",
            metadados={
                "operacao": "desinstalar",
            },
        )

        snapshot_id = (
            snapshot[
                "snapshot"
            ][
                "id"
            ]
        )

    except Exception as exc:
        return _erro(
            "snapshot_falhou",
            str(
                exc
            ),
            inicio,
        )

    if tabela_existe():
        result = subprocess.run(
            [
                nft,
                "delete",
                "table",
                TABELA_FAMILIA,
                TABELA_NOME,
            ],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_NFT,
            check=False,
        )

        if result.returncode != 0:
            return _erro(
                "remocao_tabela_falhou",
                (
                    result.stderr.strip()
                    or "Falha ao remover tabela MoonShield."
                ),
                inicio,
                snapshot_id=snapshot_id,
            )

    if _bool(
        dados.get(
            "remover_config",
            False,
        )
    ):
        try:
            ARQUIVO_CONFIG.unlink(
                missing_ok=True
            )

            ARQUIVO_BASE.unlink(
                missing_ok=True
            )

            ARQUIVO_RULES.unlink(
                missing_ok=True
            )

            ARQUIVO_NAT.unlink(
                missing_ok=True
            )

        except Exception:
            pass

    return {
        "ok": True,
        "status": "sucesso",
        "mensagem": "Tabela MoonShield removida.",
        "snapshot_id": snapshot_id,
        "pacote_nftables_preservado": True,
        "iptables_preservado": True,
        "duracao_segundos": round(
            time.monotonic()
            - inicio,
            3,
        ),
    }


def remover(
    dados: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return desinstalar(
        dados
    )


def remover_regras(
    dados: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return desinstalar(
        dados
    )


# =============================================================================
# STATUS / COMPATIBILIDADE
# =============================================================================

def obter_status_instalacao() -> dict[str, Any]:
    return obter_status()


def listar_regras() -> dict[str, Any]:
    from firewall.nucleo.status import (
        obter_regras,
    )

    return obter_regras()


# =============================================================================
# BASE NFT
# =============================================================================

def _gerar_base(
    contexto,
) -> str:
    """
    Cria firewall base em policy ACCEPT.

    O enforcement administrativo virá por ms_rules.
    A primeira instalação não fecha tráfego por padrão.
    """
    linhas: list[str] = []

    if tabela_existe():
        linhas.append(
            f"delete table "
            f"{TABELA_FAMILIA} "
            f"{TABELA_NOME}"
        )

    linhas.extend(
        [
            f"table {TABELA_FAMILIA} {TABELA_NOME} {{",

            f"    chain {CHAIN_SYSTEM} {{",
            "    }",

            f"    chain {CHAIN_EMERGENCY} {{",
            "    }",

            f"    chain {CHAIN_RULES} {{",
            "    }",

            f"    chain {CHAIN_INPUT} {{",
            "        type filter hook input priority 0; policy accept;",
            f"        jump {CHAIN_SYSTEM}",
            f"        jump {CHAIN_EMERGENCY}",
            f"        jump {CHAIN_RULES}",
            "    }",

            f"    chain {CHAIN_FORWARD} {{",
            "        type filter hook forward priority 0; policy accept;",
            f"        jump {CHAIN_SYSTEM}",
            f"        jump {CHAIN_EMERGENCY}",
            f"        jump {CHAIN_RULES}",
            "    }",

            f"    chain {CHAIN_OUTPUT} {{",
            "        type filter hook output priority 0; policy accept;",
            f"        jump {CHAIN_SYSTEM}",
            f"        jump {CHAIN_EMERGENCY}",
            f"        jump {CHAIN_RULES}",
            "    }",

            "}",
        ]
    )

    # Regras essenciais do sistema entram depois da criação da tabela.
    for regra in gerar_regras_sistema(
        contexto
    ):
        linhas.append(
            f"add rule "
            f"{TABELA_FAMILIA} "
            f"{TABELA_NOME} "
            f"{CHAIN_SYSTEM} "
            f"{regra}"
        )

    return (
        "\n".join(
            linhas
        )
        + "\n"
    )


# =============================================================================
# INSTALAÇÃO DE PACOTE
# =============================================================================

def _instalar_nftables() -> dict[str, Any]:
    """
    Instala somente o pacote nftables.

    NÃO executa:
        systemctl enable nftables
        systemctl disable iptables
        iptables-save
        iptables-restore
        flush ruleset

    A persistência do MoonShield pertence ao Agent.
    """
    apt = shutil.which(
        "apt-get"
    )

    if not apt:
        return {
            "ok": False,
            "erro": (
                "Gerenciador apt-get não encontrado. "
                "Instale nftables manualmente."
            ),
        }

    env = os.environ.copy()

    env[
        "DEBIAN_FRONTEND"
    ] = "noninteractive"

    try:
        update = subprocess.run(
            [
                apt,
                "update",
            ],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_COMANDO,
            check=False,
            env=env,
        )

        if update.returncode != 0:
            return {
                "ok": False,
                "erro": (
                    update.stderr.strip()
                    or update.stdout.strip()
                    or "apt-get update falhou."
                ),
            }

        install = subprocess.run(
            [
                apt,
                "install",
                "-y",
                "nftables",
            ],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_COMANDO,
            check=False,
            env=env,
        )

        if install.returncode != 0:
            return {
                "ok": False,
                "erro": (
                    install.stderr.strip()
                    or install.stdout.strip()
                    or "apt-get install nftables falhou."
                ),
            }

        return {
            "ok": True,
            "mensagem": "Pacote nftables instalado.",
        }

    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "erro": "Instalação nftables excedeu o tempo limite.",
        }

    except Exception as exc:
        return {
            "ok": False,
            "erro": str(
                exc
            ),
        }


# =============================================================================
# NFT CHECK / APPLY
# =============================================================================

def _nft_check(
    nft: str,
    script: str,
) -> dict[str, Any]:
    path = _arquivo_temporario(
        script
    )

    try:
        result = subprocess.run(
            [
                nft,
                "-c",
                "-f",
                path,
            ],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_NFT,
            check=False,
        )

        return {
            "ok": (
                result.returncode == 0
            ),
            "codigo": result.returncode,
            "stdout": (
                result.stdout
                or ""
            ).strip(),
            "stderr": (
                result.stderr
                or ""
            ).strip(),
            "erro": (
                ""
                if result.returncode == 0
                else (
                    result.stderr.strip()
                    or result.stdout.strip()
                    or "nft -c falhou."
                )
            ),
        }

    finally:
        try:
            os.unlink(
                path
            )
        except FileNotFoundError:
            pass


def _nft_apply(
    nft: str,
    script: str,
) -> dict[str, Any]:
    path = _arquivo_temporario(
        script
    )

    try:
        result = subprocess.run(
            [
                nft,
                "-f",
                path,
            ],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_NFT,
            check=False,
        )

        return {
            "ok": (
                result.returncode == 0
            ),
            "codigo": result.returncode,
            "stdout": (
                result.stdout
                or ""
            ).strip(),
            "stderr": (
                result.stderr
                or ""
            ).strip(),
            "erro": (
                ""
                if result.returncode == 0
                else (
                    result.stderr.strip()
                    or result.stdout.strip()
                    or "nft -f falhou."
                )
            ),
        }

    finally:
        try:
            os.unlink(
                path
            )
        except FileNotFoundError:
            pass


# =============================================================================
# FILESYSTEM
# =============================================================================

def _criar_diretorios() -> None:
    for path in (
        DIRETORIO_CONFIG,
        DIRETORIO_STATE,
        DIRETORIO_STATE / "snapshots",
        DIRETORIO_RUNTIME,
    ):
        path.mkdir(
            parents=True,
            exist_ok=True,
        )

    for path in (
        DIRETORIO_CONFIG,
        DIRETORIO_STATE,
        DIRETORIO_STATE / "snapshots",
        DIRETORIO_RUNTIME,
    ):
        try:
            os.chmod(
                path,
                0o750,
            )
        except PermissionError:
            pass


def _salvar_config(
    cfg: dict[str, Any],
) -> None:
    _criar_diretorios()

    temporario = (
        ARQUIVO_CONFIG
        .with_suffix(
            ".json.tmp"
        )
    )

    temporario.write_text(
        json.dumps(
            cfg,
            ensure_ascii=False,
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )

    try:
        os.chmod(
            temporario,
            0o640,
        )
    except PermissionError:
        pass

    os.replace(
        temporario,
        ARQUIVO_CONFIG,
    )


def _carregar_config() -> dict[str, Any]:
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
            if isinstance(
                dados,
                dict,
            )
            else {}
        )

    except Exception:
        return {}


def _arquivo_temporario(
    script: str,
) -> str:
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        suffix=".nft",
        prefix="moonshield-installer-",
        delete=False,
    ) as fp:
        fp.write(
            script
        )

        return fp.name


# =============================================================================
# IPTABLES — DETECÇÃO APENAS
# =============================================================================

def _detectar_iptables() -> dict[str, Any]:
    """
    O MoonShield NÃO migra nem altera iptables automaticamente.
    """
    iptables = shutil.which(
        "iptables"
    )

    if not iptables:
        return {
            "detectado": False,
            "binario": None,
            "versao": "",
            "alterado": False,
        }

    try:
        result = subprocess.run(
            [
                iptables,
                "--version",
            ],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )

        versao = (
            result.stdout
            or result.stderr
            or ""
        ).strip()

    except Exception:
        versao = ""

    return {
        "detectado": True,
        "binario": iptables,
        "versao": versao,
        "alterado": False,
        "mensagem": (
            "iptables foi detectado e será preservado."
        ),
    }


# =============================================================================
# HELPERS
# =============================================================================

def _versao_nft(
    nft: str,
) -> str:
    try:
        result = subprocess.run(
            [
                nft,
                "--version",
            ],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )

        return (
            result.stdout
            or result.stderr
            or ""
        ).strip()

    except Exception:
        return ""


def _linux() -> bool:
    return (
        os.name == "posix"
        and Path(
            "/proc"
        ).exists()
    )


def _root() -> bool:
    return (
        os.geteuid() == 0
        if hasattr(
            os,
            "geteuid",
        )
        else False
    )


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
    }


def _agora_iso() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def _erro(
    codigo: str,
    erro: str,
    inicio: float,
    *,
    etapas: list[dict[str, Any]] | None = None,
    snapshot_id: str | None = None,
    rollback: dict[str, Any] | None = None,
    detalhes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "ok": False,
        "status": "erro",
        "codigo": codigo,
        "erro": str(
            erro
        ),
        "etapas": etapas or [],
        "snapshot_id": snapshot_id,
        "rollback": rollback,
        "detalhes": detalhes or {},
        "duracao_segundos": round(
            time.monotonic()
            - inicio,
            3,
        ),
    }