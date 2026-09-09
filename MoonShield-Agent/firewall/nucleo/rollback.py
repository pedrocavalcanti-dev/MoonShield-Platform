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
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from firewall.nucleo.seguranca import (
    TABELA_FAMILIA,
    TABELA_NOME,
    validar_script_nft,
)


VERSAO_ROLLBACK = "2.0"

BASE_STATE = Path("/var/lib/moonshield/firewall")
DIRETORIO_SNAPSHOTS = BASE_STATE / "snapshots"
ARQUIVO_ULTIMO = BASE_STATE / "ultimo_snapshot.json"
DIRETORIO_SAFE_APPLY = BASE_STATE / "safe_apply"
ARQUIVO_ATIVO = DIRETORIO_SAFE_APPLY / "active.json"

MAX_SNAPSHOTS = 20
TIMEOUT_SAFE_APPLY_PADRAO = 60
TIMEOUT_SAFE_APPLY_MIN = 5
TIMEOUT_SAFE_APPLY_MAX = 900
TIMEOUT_NFT = 20

logger = logging.getLogger(__name__)

_lock = threading.RLock()
_timers: dict[str, threading.Timer] = {}
_RE_ALTERACAO_ID = re.compile(r"^[A-Za-z0-9_.:@-]{1,128}$")

STATUS_APLICANDO = "applying"
STATUS_AGUARDANDO = "waiting_confirmation"
STATUS_CONFIRMADA = "confirmed"
STATUS_REVERTENDO = "rolling_back"
STATUS_REVERTIDA = "rolled_back"
STATUS_CANCELADA = "cancelled"
STATUS_EXPIRADA = "expired_rolled_back"
STATUS_FALHOU_REVERTIDA = "failed_rolled_back"
STATUS_ROLLBACK_FALHOU = "rollback_failed"
STATUS_FALHOU = "failed"
STATUS_ATIVOS = {STATUS_APLICANDO, STATUS_AGUARDANDO, STATUS_REVERTENDO, STATUS_ROLLBACK_FALHOU}


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
    DIRETORIO_SAFE_APPLY.mkdir(parents=True, exist_ok=True)

    try:
        os.chmod(BASE_STATE, 0o750)
        os.chmod(DIRETORIO_SNAPSHOTS, 0o750)
        os.chmod(DIRETORIO_SAFE_APPLY, 0o750)
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



# =============================================================================
# SAFE APPLY PERSISTENTE
# =============================================================================

def _normalizar_alteracao_id(valor: Any) -> str:
    alteracao_id = str(valor or "").strip()
    if not alteracao_id or not _RE_ALTERACAO_ID.fullmatch(alteracao_id):
        raise ValueError("Identificador de alteração inválido.")
    return alteracao_id


def _normalizar_timeout(valor: Any) -> int:
    try:
        timeout = int(valor)
    except (TypeError, ValueError):
        timeout = TIMEOUT_SAFE_APPLY_PADRAO

    if timeout < TIMEOUT_SAFE_APPLY_MIN or timeout > TIMEOUT_SAFE_APPLY_MAX:
        raise ValueError(
            f"timeout_segundos deve ficar entre {TIMEOUT_SAFE_APPLY_MIN} "
            f"e {TIMEOUT_SAFE_APPLY_MAX}."
        )
    return timeout


def _estado_path(alteracao_id: str) -> Path:
    return DIRETORIO_SAFE_APPLY / f"{_normalizar_alteracao_id(alteracao_id)}.json"


def _escrever_json_atomico(path: Path, dados: dict[str, Any]) -> None:
    _garantir_diretorios()
    fd, tmp = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
        text=True,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fp:
            json.dump(dados, fp, ensure_ascii=False, indent=2, default=str)
            fp.write("\n")
            fp.flush()
            os.fsync(fp.fileno())
        try:
            os.chmod(tmp, 0o640)
        except PermissionError:
            pass
        os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def _ler_json(path: Path) -> dict[str, Any] | None:
    try:
        dados = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None
    return dados if isinstance(dados, dict) else None


def _ler_estado(alteracao_id: str) -> dict[str, Any] | None:
    return _ler_json(_estado_path(alteracao_id))


def _salvar_estado(estado: dict[str, Any]) -> None:
    alteracao_id = _normalizar_alteracao_id(estado.get("alteracao_id"))
    estado["alteracao_id"] = alteracao_id
    estado["atualizado_em"] = _agora_iso()
    _escrever_json_atomico(_estado_path(alteracao_id), estado)


def _definir_ativo(alteracao_id: str) -> None:
    _escrever_json_atomico(
        ARQUIVO_ATIVO,
        {"alteracao_id": _normalizar_alteracao_id(alteracao_id)},
    )


def _limpar_ativo_se(alteracao_id: str) -> None:
    ativo = _ler_json(ARQUIVO_ATIVO) or {}
    if str(ativo.get("alteracao_id") or "") != alteracao_id:
        return
    try:
        ARQUIVO_ATIVO.unlink()
    except FileNotFoundError:
        pass


def _obter_id_ativo() -> str | None:
    ativo = _ler_json(ARQUIVO_ATIVO) or {}
    valor = str(ativo.get("alteracao_id") or "").strip()
    if not valor:
        return None
    try:
        return _normalizar_alteracao_id(valor)
    except ValueError:
        return None


def _cancelar_timer(alteracao_id: str) -> None:
    timer = _timers.pop(alteracao_id, None)
    if timer is not None:
        timer.cancel()


def existe_alteracao_pendente() -> bool:
    with _lock:
        alteracao_id = _obter_id_ativo()
        if not alteracao_id:
            return False
        estado = _ler_estado(alteracao_id)
        if not estado:
            _limpar_ativo_se(alteracao_id)
            return False
        return str(estado.get("status") or "") in STATUS_ATIVOS


def obter_alteracao_ativa() -> dict[str, Any] | None:
    with _lock:
        alteracao_id = _obter_id_ativo()
        if not alteracao_id:
            return None
        return _ler_estado(alteracao_id)


def registrar_alteracao_aplicando(
    *,
    alteracao_id: str,
    snapshot_id: str,
    timeout_segundos: int = TIMEOUT_SAFE_APPLY_PADRAO,
    metadados: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Reserva o pipeline antes da mutação nft e persiste o snapshot de retorno."""
    with _lock:
        _garantir_diretorios()
        alteracao_id = _normalizar_alteracao_id(alteracao_id)
        snapshot_id = str(snapshot_id or "").strip()
        timeout = _normalizar_timeout(timeout_segundos)

        if not snapshot_id:
            raise ValueError("snapshot_id é obrigatório para Safe Apply.")

        ativo_id = _obter_id_ativo()
        if ativo_id:
            ativo = _ler_estado(ativo_id)
            if ativo and str(ativo.get("status") or "") in STATUS_ATIVOS:
                raise RuntimeError(
                    f"Já existe alteração de Firewall em andamento: {ativo_id}."
                )
            _limpar_ativo_se(ativo_id)

        agora = _agora_iso()
        estado = {
            "versao": 1,
            "alteracao_id": alteracao_id,
            "snapshot_id": snapshot_id,
            "status": STATUS_APLICANDO,
            "criado_em": agora,
            "atualizado_em": agora,
            "aplicado_em": None,
            "expira_em": None,
            "expira_em_epoch": None,
            "finalizado_em": None,
            "timeout_segundos": timeout,
            "motivo_finalizacao": "",
            "erro": "",
            "rollback": None,
            "metadados": dict(metadados or {}),
        }
        _salvar_estado(estado)
        _definir_ativo(alteracao_id)
        return obter_status_alteracao(alteracao_id=alteracao_id)


def armar_rollback_pendente(
    *,
    alteracao_id: str,
    timeout_segundos: int | None = None,
) -> dict[str, Any]:
    """Muda applying -> waiting_confirmation e cria timer daemon de rollback."""
    with _lock:
        alteracao_id = _normalizar_alteracao_id(alteracao_id)
        estado = _ler_estado(alteracao_id)
        if not estado:
            raise RuntimeError(f"Alteração de Firewall não encontrada: {alteracao_id}.")

        if str(estado.get("status") or "") != STATUS_APLICANDO:
            raise RuntimeError(
                f"Alteração {alteracao_id} não está em estado applying."
            )

        timeout = _normalizar_timeout(
            timeout_segundos
            if timeout_segundos is not None
            else estado.get("timeout_segundos")
        )
        agora = datetime.now(timezone.utc)
        expira = agora + timedelta(seconds=timeout)

        estado.update({
            "status": STATUS_AGUARDANDO,
            "aplicado_em": agora.isoformat(),
            "expira_em": expira.isoformat(),
            "expira_em_epoch": expira.timestamp(),
            "timeout_segundos": timeout,
            "erro": "",
        })
        _salvar_estado(estado)
        _definir_ativo(alteracao_id)
        _agendar_timer_locked(alteracao_id, timeout)

        return obter_status_alteracao(alteracao_id=alteracao_id)


def _agendar_timer_locked(alteracao_id: str, segundos: float) -> None:
    _cancelar_timer(alteracao_id)
    timer = threading.Timer(
        max(0.05, float(segundos)),
        _callback_timeout,
        args=(alteracao_id,),
    )
    timer.daemon = True
    timer.name = f"moonshield-fw-rollback-{alteracao_id[:24]}"
    _timers[alteracao_id] = timer
    timer.start()


def _callback_timeout(alteracao_id: str) -> None:
    try:
        resultado = _reverter_alteracao(
            alteracao_id=alteracao_id,
            motivo="Tempo de confirmação do Safe Apply expirou.",
            status_final=STATUS_EXPIRADA,
        )
        if resultado.get("ok"):
            logger.warning(
                "[firewall] rollback automático por timeout | alteracao_id=%s",
                alteracao_id,
            )
        else:
            logger.error(
                "[firewall] rollback automático falhou | alteracao_id=%s erro=%s",
                alteracao_id,
                resultado.get("erro"),
            )
    except Exception:
        logger.exception(
            "[firewall] exceção no rollback automático | alteracao_id=%s",
            alteracao_id,
        )


def marcar_alteracao_falhou(
    *,
    alteracao_id: str,
    erro: str,
    rollback: dict[str, Any] | None = None,
) -> dict[str, Any]:
    with _lock:
        alteracao_id = _normalizar_alteracao_id(alteracao_id)
        estado = _ler_estado(alteracao_id)
        if not estado:
            return {
                "ok": False,
                "codigo": "alteracao_inexistente",
                "erro": f"Alteração não encontrada: {alteracao_id}",
            }

        _cancelar_timer(alteracao_id)
        rb_ok = bool(rollback and rollback.get("ok"))
        if rollback is None:
            status = STATUS_FALHOU
        elif rb_ok:
            status = STATUS_FALHOU_REVERTIDA
        else:
            status = STATUS_ROLLBACK_FALHOU

        estado.update({
            "status": status,
            "finalizado_em": _agora_iso() if status != STATUS_ROLLBACK_FALHOU else None,
            "erro": str(erro or "Falha durante Safe Apply."),
            "rollback": rollback,
            "motivo_finalizacao": "falha_aplicacao",
        })
        _salvar_estado(estado)

        if status != STATUS_ROLLBACK_FALHOU:
            _limpar_ativo_se(alteracao_id)

        return obter_status_alteracao(alteracao_id=alteracao_id)


def confirmar_alteracao(*, alteracao_id: str) -> dict[str, Any]:
    with _lock:
        alteracao_id = _normalizar_alteracao_id(alteracao_id)
        estado = _ler_estado(alteracao_id)
        if not estado:
            return {
                "ok": False,
                "codigo": "alteracao_inexistente",
                "erro": f"Alteração de Firewall não encontrada: {alteracao_id}",
            }

        status = str(estado.get("status") or "")
        if status == STATUS_CONFIRMADA:
            return obter_status_alteracao(alteracao_id=alteracao_id)
        if status != STATUS_AGUARDANDO:
            return {
                "ok": False,
                "codigo": "estado_confirmacao_invalido",
                "erro": f"Alteração {alteracao_id} está em estado {status!r}.",
                "estado": obter_status_alteracao(alteracao_id=alteracao_id),
            }

        expira_epoch = float(estado.get("expira_em_epoch") or 0)
        if expira_epoch and time.time() >= expira_epoch:
            rb = _reverter_alteracao(
                alteracao_id=alteracao_id,
                motivo="Confirmação recebida após expiração do Safe Apply.",
                status_final=STATUS_EXPIRADA,
            )
            return {
                "ok": False,
                "codigo": "alteracao_expirada",
                "erro": "Prazo de confirmação expirou; rollback executado.",
                "rollback": rb,
            }

        _cancelar_timer(alteracao_id)
        estado.update({
            "status": STATUS_CONFIRMADA,
            "finalizado_em": _agora_iso(),
            "motivo_finalizacao": "confirmada",
            "erro": "",
        })
        _salvar_estado(estado)
        _limpar_ativo_se(alteracao_id)

        resultado = obter_status_alteracao(alteracao_id=alteracao_id)
        resultado["mensagem"] = "Alteração de Firewall confirmada; rollback desarmado."
        return resultado


def _reverter_alteracao(
    *,
    alteracao_id: str,
    motivo: str,
    status_final: str,
) -> dict[str, Any]:
    with _lock:
        alteracao_id = _normalizar_alteracao_id(alteracao_id)
        estado = _ler_estado(alteracao_id)
        if not estado:
            return {
                "ok": False,
                "codigo": "alteracao_inexistente",
                "erro": f"Alteração de Firewall não encontrada: {alteracao_id}",
            }

        status_atual = str(estado.get("status") or "")
        if status_atual in {
            STATUS_CONFIRMADA,
            STATUS_REVERTIDA,
            STATUS_CANCELADA,
            STATUS_EXPIRADA,
            STATUS_FALHOU_REVERTIDA,
        }:
            return {
                "ok": False,
                "codigo": "alteracao_finalizada",
                "erro": f"Alteração {alteracao_id} já está finalizada: {status_atual}.",
                "estado": obter_status_alteracao(alteracao_id=alteracao_id),
            }

        snapshot_id = str(estado.get("snapshot_id") or "").strip()
        if not snapshot_id:
            return {
                "ok": False,
                "codigo": "snapshot_ausente",
                "erro": "Alteração não possui snapshot para rollback.",
            }

        _cancelar_timer(alteracao_id)
        estado.update({
            "status": STATUS_REVERTENDO,
            "motivo_finalizacao": str(motivo or "rollback"),
        })
        _salvar_estado(estado)

        rb = restaurar(snapshot_id=snapshot_id)

        if rb.get("ok"):
            estado.update({
                "status": status_final,
                "finalizado_em": _agora_iso(),
                "erro": "",
                "rollback": rb,
            })
            _salvar_estado(estado)
            _limpar_ativo_se(alteracao_id)
            return {
                "ok": True,
                "alteracao_id": alteracao_id,
                "status": status_final,
                "snapshot_id": snapshot_id,
                "rollback": rb,
                "mensagem": "Rollback de Firewall concluído.",
            }

        estado.update({
            "status": STATUS_ROLLBACK_FALHOU,
            "erro": str(rb.get("erro") or "Falha ao restaurar snapshot."),
            "rollback": rb,
        })
        _salvar_estado(estado)
        _definir_ativo(alteracao_id)
        return {
            "ok": False,
            "codigo": "rollback_falhou",
            "erro": estado["erro"],
            "alteracao_id": alteracao_id,
            "snapshot_id": snapshot_id,
            "rollback": rb,
        }


def reverter_alteracao(
    *,
    alteracao_id: str,
    motivo: str = "Rollback solicitado pelo controlador MoonShield.",
) -> dict[str, Any]:
    return _reverter_alteracao(
        alteracao_id=alteracao_id,
        motivo=motivo,
        status_final=STATUS_REVERTIDA,
    )


def cancelar_alteracao(*, alteracao_id: str) -> dict[str, Any]:
    return _reverter_alteracao(
        alteracao_id=alteracao_id,
        motivo="Safe Apply cancelado pelo controlador MoonShield.",
        status_final=STATUS_CANCELADA,
    )


def obter_status_alteracao(*, alteracao_id: str) -> dict[str, Any]:
    with _lock:
        alteracao_id = _normalizar_alteracao_id(alteracao_id)
        estado = _ler_estado(alteracao_id)
        if not estado:
            return {
                "ok": False,
                "codigo": "alteracao_inexistente",
                "erro": f"Alteração de Firewall não encontrada: {alteracao_id}",
            }

        status = str(estado.get("status") or "")
        expira_epoch = float(estado.get("expira_em_epoch") or 0)
        segundos_restantes = None
        if status == STATUS_AGUARDANDO and expira_epoch:
            segundos_restantes = max(0, int(expira_epoch - time.time()))

        return {
            "ok": True,
            "alteracao_id": alteracao_id,
            "status": status,
            "snapshot_id": estado.get("snapshot_id"),
            "criado_em": estado.get("criado_em"),
            "aplicado_em": estado.get("aplicado_em"),
            "expira_em": estado.get("expira_em"),
            "finalizado_em": estado.get("finalizado_em"),
            "timeout_segundos": estado.get("timeout_segundos"),
            "segundos_restantes": segundos_restantes,
            "aguardando_confirmacao": status == STATUS_AGUARDANDO,
            "rollback_armado": status == STATUS_AGUARDANDO,
            "motivo_finalizacao": estado.get("motivo_finalizacao") or "",
            "erro": estado.get("erro") or "",
            "rollback": estado.get("rollback"),
            "metadados": estado.get("metadados") or {},
        }


def inicializar_rollback_pendente() -> dict[str, Any]:
    """Recupera Safe Apply depois de restart do Agent, antes do socket abrir."""
    with _lock:
        _garantir_diretorios()
        resultado: dict[str, Any] = {
            "recuperadas": [],
            "revertidas": [],
            "erros": [],
        }

        alteracao_id = _obter_id_ativo()
        if not alteracao_id:
            return resultado

        estado = _ler_estado(alteracao_id)
        if not estado:
            _limpar_ativo_se(alteracao_id)
            resultado["erros"].append({
                "alteracao_id": alteracao_id,
                "erro": "Arquivo de estado do Safe Apply não encontrado.",
            })
            return resultado

        status = str(estado.get("status") or "")

        if status == STATUS_AGUARDANDO:
            expira_epoch = float(estado.get("expira_em_epoch") or 0)
            restante = expira_epoch - time.time()
            if expira_epoch and restante > 0:
                _agendar_timer_locked(alteracao_id, restante)
                resultado["recuperadas"].append(alteracao_id)
                return resultado

            rb = _reverter_alteracao(
                alteracao_id=alteracao_id,
                motivo="Safe Apply expirado durante indisponibilidade/restart do Agent.",
                status_final=STATUS_EXPIRADA,
            )
            if rb.get("ok"):
                resultado["revertidas"].append(alteracao_id)
            else:
                resultado["erros"].append({
                    "alteracao_id": alteracao_id,
                    "erro": rb.get("erro") or "Rollback recuperado falhou.",
                })
            return resultado

        # Se o processo caiu entre o snapshot e o armamento do timer, não existe
        # confirmação segura de que o apply terminou. A única recuperação correta
        # é voltar ao snapshot anterior.
        if status in {STATUS_APLICANDO, STATUS_REVERTENDO, STATUS_ROLLBACK_FALHOU}:
            rb = _reverter_alteracao(
                alteracao_id=alteracao_id,
                motivo=f"Recuperação conservadora após restart (estado anterior: {status}).",
                status_final=STATUS_REVERTIDA,
            )
            if rb.get("ok"):
                resultado["revertidas"].append(alteracao_id)
            else:
                resultado["erros"].append({
                    "alteracao_id": alteracao_id,
                    "erro": rb.get("erro") or "Rollback de recuperação falhou.",
                })
            return resultado

        _limpar_ativo_se(alteracao_id)
        return resultado

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