"""
MoonShield Agent — Firewall / Rollback
======================================

Gerencia snapshots e restauração segura exclusivamente da tabela:

    table inet moonshield

Objetivos:
- nunca executar `flush ruleset`;
- nunca tocar em tabelas de terceiros;
- salvar snapshot antes de qualquer aplicação;
- validar snapshot antes de restaurar;
- manter histórico limitado;
- fornecer rollback automático ao aplicador.py.

Os snapshots ficam em:

    /var/lib/moonshield/firewall/snapshots/

Formato:
    *.nft        -> dump da tabela MoonShield
    *.json       -> metadados do snapshot

Este módulo usa somente biblioteca padrão.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from firewall.nucleo.seguranca import (
    TABELA_FAMILIA,
    TABELA_NOME,
    validar_script_nft,
)


VERSAO_ROLLBACK = "1.0"

BASE_STATE = Path("/var/lib/moonshield/firewall")
DIRETORIO_SNAPSHOTS = BASE_STATE / "snapshots"
ARQUIVO_ULTIMO = BASE_STATE / "ultimo_snapshot.json"

MAX_SNAPSHOTS = 20
TIMEOUT_NFT = 20

_lock = threading.RLock()


@dataclass(slots=True)
class SnapshotFirewall:
    id: str
    nft_path: str
    meta_path: str
    criado_em: str
    motivo: str
    existe_tabela: bool
    bytes: int

    def para_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "nft_path": self.nft_path,
            "meta_path": self.meta_path,
            "criado_em": self.criado_em,
            "motivo": self.motivo,
            "existe_tabela": self.existe_tabela,
            "bytes": self.bytes,
        }


def _agora_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def _nft_bin() -> str:
    nft = shutil.which("nft")
    if not nft:
        raise RuntimeError("Comando nft não encontrado.")
    return nft


def _garantir_diretorios() -> None:
    BASE_STATE.mkdir(parents=True, exist_ok=True)
    DIRETORIO_SNAPSHOTS.mkdir(parents=True, exist_ok=True)

    try:
        os.chmod(BASE_STATE, 0o750)
        os.chmod(DIRETORIO_SNAPSHOTS, 0o750)
    except PermissionError:
        pass


def tabela_existe() -> bool:
    nft = shutil.which("nft")
    if not nft:
        return False

    try:
        r = subprocess.run(
            [nft, "list", "table", TABELA_FAMILIA, TABELA_NOME],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_NFT,
            check=False,
        )
        return r.returncode == 0
    except Exception:
        return False


def exportar_tabela() -> tuple[bool, str]:
    """
    Retorna:
        (True, script)  se tabela existe
        (False, "")     se tabela ainda não existe
    """
    nft = _nft_bin()

    r = subprocess.run(
        [nft, "list", "table", TABELA_FAMILIA, TABELA_NOME],
        capture_output=True,
        text=True,
        timeout=TIMEOUT_NFT,
        check=False,
    )

    if r.returncode != 0:
        return False, ""

    return True, (r.stdout or "").strip() + "\n"


def criar_snapshot(
    motivo: str = "antes_aplicacao",
    *,
    metadados: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Salva o estado atual da tabela MoonShield.

    Se a tabela ainda não existe, salva snapshot lógico com existe_tabela=False.
    Isso permite rollback correto da primeira instalação/aplicação.
    """
    with _lock:
        _garantir_diretorios()

        existe, script = exportar_tabela()
        snapshot_id = _stamp()

        nft_path = DIRETORIO_SNAPSHOTS / f"{snapshot_id}.nft"
        meta_path = DIRETORIO_SNAPSHOTS / f"{snapshot_id}.json"

        if existe:
            validacao = validar_script_nft(
                script,
                permitir_delete_table_moonshield=True,
            )
            if not validacao.ok:
                raise RuntimeError(
                    "Snapshot atual foi rejeitado pela validação de segurança: "
                    + "; ".join(validacao.erros)
                )

            nft_path.write_text(script, encoding="utf-8")
        else:
            nft_path.write_text(
                "# MoonShield snapshot: tabela inexistente\n",
                encoding="utf-8",
            )

        meta = {
            "id": snapshot_id,
            "criado_em": _agora_iso(),
            "motivo": str(motivo or "snapshot"),
            "existe_tabela": existe,
            "nft_path": str(nft_path),
            "meta_path": str(meta_path),
            "bytes": nft_path.stat().st_size,
            "metadados": metadados or {},
            "versao_rollback": VERSAO_ROLLBACK,
        }

        meta_path.write_text(
            json.dumps(meta, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )

        ARQUIVO_ULTIMO.write_text(
            json.dumps(
                {"id": snapshot_id, "meta_path": str(meta_path)},
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        _limpar_antigos()

        return {
            "ok": True,
            "snapshot": meta,
        }


def listar_snapshots() -> list[dict[str, Any]]:
    _garantir_diretorios()

    itens: list[dict[str, Any]] = []

    for meta_path in sorted(
        DIRETORIO_SNAPSHOTS.glob("*.json"),
        reverse=True,
    ):
        try:
            dados = json.loads(meta_path.read_text(encoding="utf-8"))
            if isinstance(dados, dict):
                itens.append(dados)
        except Exception:
            continue

    return itens


def obter_ultimo_snapshot() -> dict[str, Any] | None:
    _garantir_diretorios()

    try:
        ponteiro = json.loads(
            ARQUIVO_ULTIMO.read_text(encoding="utf-8")
        )
        meta_path = Path(ponteiro["meta_path"])
        if not meta_path.exists():
            return None

        dados = json.loads(meta_path.read_text(encoding="utf-8"))
        return dados if isinstance(dados, dict) else None
    except Exception:
        snapshots = listar_snapshots()
        return snapshots[0] if snapshots else None


def restaurar_ultimo(dados: dict[str, Any] | None = None) -> dict[str, Any]:
    dados = dados or {}

    snapshot_id = str(dados.get("snapshot_id") or "").strip()

    if snapshot_id:
        return restaurar(snapshot_id=snapshot_id)

    ultimo = obter_ultimo_snapshot()
    if not ultimo:
        return {
            "ok": False,
            "codigo": "snapshot_inexistente",
            "erro": "Nenhum snapshot disponível para rollback.",
        }

    return restaurar(snapshot_id=ultimo["id"])


def rollback(dados: dict[str, Any] | None = None) -> dict[str, Any]:
    return restaurar_ultimo(dados)


def restaurar(
    snapshot_id: str,
) -> dict[str, Any]:
    """
    Restaura exatamente a tabela MoonShield registrada no snapshot.

    Processo:
    1. localiza snapshot;
    2. valida conteúdo;
    3. cria arquivo temporário;
    4. nft -c -f;
    5. remove apenas `table inet moonshield`;
    6. restaura snapshot se ela existia.
    """
    with _lock:
        _garantir_diretorios()

        meta_path = DIRETORIO_SNAPSHOTS / f"{snapshot_id}.json"
        nft_path = DIRETORIO_SNAPSHOTS / f"{snapshot_id}.nft"

        if not meta_path.exists():
            return {
                "ok": False,
                "codigo": "snapshot_inexistente",
                "erro": f"Snapshot não encontrado: {snapshot_id}",
            }

        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception as exc:
            return {
                "ok": False,
                "codigo": "snapshot_corrompido",
                "erro": f"Metadados inválidos: {exc}",
            }

        existe_tabela = bool(meta.get("existe_tabela"))

        nft = _nft_bin()

        # Se no snapshot a tabela não existia, rollback significa remover
        # somente a nossa tabela atual.
        if not existe_tabela:
            remocao = _remover_tabela_atual()
            return {
                "ok": remocao["ok"],
                "snapshot_id": snapshot_id,
                "restaurado": True,
                "tabela_existia_snapshot": False,
                "mensagem": (
                    "Rollback concluído: tabela MoonShield removida."
                    if remocao["ok"]
                    else remocao.get("erro", "Falha no rollback.")
                ),
            }

        if not nft_path.exists():
            return {
                "ok": False,
                "codigo": "snapshot_corrompido",
                "erro": "Arquivo NFT do snapshot não existe.",
            }

        script = nft_path.read_text(encoding="utf-8")

        seguranca = validar_script_nft(
            script,
            permitir_delete_table_moonshield=True,
        )
        if not seguranca.ok:
            return {
                "ok": False,
                "codigo": "snapshot_inseguro",
                "erro": "Snapshot rejeitado pela validação de segurança.",
                "detalhes": seguranca.para_dict(),
            }

        # Cria script transacional:
        # remove SOMENTE nossa tabela e recria com conteúdo do snapshot.
        candidato = (
            f"delete table {TABELA_FAMILIA} {TABELA_NOME}\n"
            + script
        )

        # nft -c reclamaria se tabela atual não existir no delete.
        # Nesse caso, valida apenas o snapshot e aplica remoção opcional.
        existe_atual = tabela_existe()

        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".nft",
            prefix="moonshield-rollback-",
            delete=False,
        ) as fp:
            if existe_atual:
                fp.write(candidato)
            else:
                fp.write(script)
            tmp = fp.name

        try:
            check = subprocess.run(
                [nft, "-c", "-f", tmp],
                capture_output=True,
                text=True,
                timeout=TIMEOUT_NFT,
                check=False,
            )

            if check.returncode != 0:
                return {
                    "ok": False,
                    "codigo": "rollback_validacao_falhou",
                    "erro": (
                        check.stderr.strip()
                        or check.stdout.strip()
                        or "nft -c rejeitou o snapshot."
                    ),
                }

            apply = subprocess.run(
                [nft, "-f", tmp],
                capture_output=True,
                text=True,
                timeout=TIMEOUT_NFT,
                check=False,
            )

            if apply.returncode != 0:
                return {
                    "ok": False,
                    "codigo": "rollback_apply_falhou",
                    "erro": (
                        apply.stderr.strip()
                        or apply.stdout.strip()
                        or "nft falhou ao restaurar snapshot."
                    ),
                }

            return {
                "ok": True,
                "snapshot_id": snapshot_id,
                "restaurado": True,
                "tabela_existia_snapshot": True,
                "mensagem": "Rollback da tabela MoonShield concluído.",
            }

        finally:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass


def _remover_tabela_atual() -> dict[str, Any]:
    if not tabela_existe():
        return {
            "ok": True,
            "mensagem": "Tabela MoonShield já não existe.",
        }

    nft = _nft_bin()

    r = subprocess.run(
        [nft, "delete", "table", TABELA_FAMILIA, TABELA_NOME],
        capture_output=True,
        text=True,
        timeout=TIMEOUT_NFT,
        check=False,
    )

    if r.returncode != 0:
        return {
            "ok": False,
            "erro": r.stderr.strip() or "Falha ao remover tabela MoonShield.",
        }

    return {
        "ok": True,
        "mensagem": "Tabela MoonShield removida.",
    }


def _limpar_antigos() -> None:
    metas = sorted(
        DIRETORIO_SNAPSHOTS.glob("*.json"),
        reverse=True,
    )

    excedentes = metas[MAX_SNAPSHOTS:]

    for meta_path in excedentes:
        snapshot_id = meta_path.stem
        nft_path = DIRETORIO_SNAPSHOTS / f"{snapshot_id}.nft"

        try:
            meta_path.unlink(missing_ok=True)
            nft_path.unlink(missing_ok=True)
        except Exception:
            pass


def healthcheck() -> dict[str, Any]:
    _garantir_diretorios()

    snapshots = listar_snapshots()

    return {
        "ok": True,
        "versao": VERSAO_ROLLBACK,
        "diretorio": str(DIRETORIO_SNAPSHOTS),
        "total_snapshots": len(snapshots),
        "ultimo_snapshot": snapshots[0] if snapshots else None,
        "tabela_existe": tabela_existe(),
    }