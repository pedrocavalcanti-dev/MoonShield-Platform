"""
MoonShield Agent — Rede / Rollback
==================================

Controle persistente do Safe Apply.

O rollback pertence ao MoonShield Agent, não ao navegador e não ao Django.

Fluxo:
1. snapshot é criado;
2. rollback é armado ANTES da alteração;
3. alteração é aplicada;
4. começa janela de confirmação;
5. confirmação cancela rollback;
6. timeout, cancelamento ou falha restaura o snapshot.

O estado fica persistido em /var/lib/moonshield/rede/changes/.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .configuracao import DIRETORIO_ALTERACOES, garantir_diretorios
from .snapshot import restaurar_snapshot


WATCHDOG_APLICACAO_SEGUNDOS = 180

STATUS_ATIVOS = {
    "applying",
    "waiting_confirmation",
}

STATUS_FINAIS = {
    "confirmed",
    "reverted",
    "failed",
    "cancelled",
}

_lock = threading.RLock()
_timers: dict[str, threading.Event] = {}


class RollbackErro(RuntimeError):
    def __init__(self, mensagem: str, *, codigo: str = "rollback_erro", detalhes: dict[str, Any] | None = None):
        super().__init__(mensagem)
        self.codigo = codigo
        self.detalhes = detalhes or {}


class AlteracaoNaoEncontrada(RollbackErro):
    def __init__(self, alteracao_id: str):
        super().__init__(
            f"Alteração não encontrada: {alteracao_id}",
            codigo="alteracao_nao_encontrada",
            detalhes={"alteracao_id": alteracao_id},
        )


def _agora_epoch() -> float:
    return time.time()


def _iso(epoch: float | None = None) -> str:
    return datetime.fromtimestamp(epoch or _agora_epoch(), timezone.utc).isoformat()


def _validar_id(alteracao_id: Any) -> str:
    valor = str(alteracao_id or "").strip()

    if not valor or len(valor) > 128:
        raise RollbackErro("Identificador de alteração inválido.", codigo="alteracao_id_invalido")

    if any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.:" for c in valor):
        raise RollbackErro(
            "Identificador de alteração contém caracteres inválidos.",
            codigo="alteracao_id_invalido",
        )

    return valor


def _caminho(alteracao_id: str) -> Path:
    return DIRETORIO_ALTERACOES / f"{_validar_id(alteracao_id)}.json"


def _salvar_estado(estado: dict[str, Any]) -> None:
    garantir_diretorios()
    caminho = _caminho(estado["alteracao_id"])
    temporario = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(DIRETORIO_ALTERACOES),
            prefix=f".{estado['alteracao_id']}.",
            suffix=".tmp",
            delete=False,
        ) as arquivo:
            temporario = Path(arquivo.name)
            json.dump(estado, arquivo, ensure_ascii=False, indent=2, sort_keys=True)
            arquivo.flush()
            os.fsync(arquivo.fileno())

        os.chmod(temporario, 0o600)
        os.replace(temporario, caminho)

    except OSError as exc:
        if temporario:
            try:
                temporario.unlink(missing_ok=True)
            except OSError:
                pass

        raise RollbackErro(
            f"Não foi possível persistir estado da alteração: {exc}",
            codigo="estado_alteracao_salvar_falhou",
        ) from exc


def _carregar_estado(alteracao_id: str) -> dict[str, Any]:
    caminho = _caminho(alteracao_id)

    if not caminho.exists():
        raise AlteracaoNaoEncontrada(alteracao_id)

    try:
        with caminho.open("r", encoding="utf-8") as arquivo:
            estado = json.load(arquivo)
    except (OSError, json.JSONDecodeError) as exc:
        raise RollbackErro(
            f"Não foi possível carregar estado da alteração: {exc}",
            codigo="estado_alteracao_leitura_falhou",
        ) from exc

    if not isinstance(estado, dict):
        raise RollbackErro("Estado da alteração possui formato inválido.", codigo="estado_alteracao_invalido")

    return estado


def _segundos_restantes(estado: dict[str, Any]) -> int:
    expira = estado.get("expira_epoch")

    if expira is None:
        return 0

    try:
        return max(0, int(float(expira) - _agora_epoch()))
    except (TypeError, ValueError):
        return 0


def _cancelar_timer(alteracao_id: str) -> None:
    with _lock:
        evento = _timers.pop(alteracao_id, None)
        if evento:
            evento.set()


def _agendar_timer(alteracao_id: str) -> None:
    alteracao_id = _validar_id(alteracao_id)
    _cancelar_timer(alteracao_id)

    with _lock:
        estado = _carregar_estado(alteracao_id)

        if estado.get("status") not in STATUS_ATIVOS:
            return

        segundos = _segundos_restantes(estado)

        if segundos <= 0:
            threading.Thread(
                target=_rollback_timeout,
                args=(alteracao_id,),
                daemon=True,
                name=f"ms-net-rollback-{alteracao_id[:12]}",
            ).start()
            return

        evento = threading.Event()
        _timers[alteracao_id] = evento

        def worker() -> None:
            expirou = not evento.wait(segundos)

            with _lock:
                if _timers.get(alteracao_id) is evento:
                    _timers.pop(alteracao_id, None)

            if expirou:
                _rollback_timeout(alteracao_id)

        threading.Thread(
            target=worker,
            daemon=True,
            name=f"ms-net-rollback-{alteracao_id[:12]}",
        ).start()


def armar_rollback(
    alteracao_id: str,
    *,
    snapshot_id: str,
    timeout_segundos: int,
    tipo: str,
    metadados: dict[str, Any] | None = None,
) -> dict[str, Any]:
    alteracao_id = _validar_id(alteracao_id)
    agora = _agora_epoch()

    # Antes da aplicação usamos um watchdog maior. Após a aplicação bem
    # sucedida, marcar_aguardando_confirmacao reinicia o prazo para o timeout
    # real solicitado pelo Django.
    expira = agora + WATCHDOG_APLICACAO_SEGUNDOS

    estado = {
        "alteracao_id": alteracao_id,
        "tipo": tipo,
        "status": "applying",
        "snapshot_id": snapshot_id,
        "timeout_segundos": int(timeout_segundos),
        "criado_em": _iso(agora),
        "aplicacao_iniciada_em": _iso(agora),
        "aplicado_em": None,
        "confirmado_em": None,
        "rollback_iniciado_em": None,
        "revertido_em": None,
        "cancelado_em": None,
        "expira_epoch": expira,
        "expira_em": _iso(expira),
        "motivo_rollback": None,
        "resultado_aplicacao": None,
        "resultado_rollback": None,
        "erro": None,
        "metadados": dict(metadados or {}),
    }

    with _lock:
        _salvar_estado(estado)

    _agendar_timer(alteracao_id)
    return obter_status_alteracao(alteracao_id)


def registrar_resultado_aplicacao(alteracao_id: str, resultado: dict[str, Any]) -> dict[str, Any]:
    with _lock:
        estado = _carregar_estado(alteracao_id)

        if estado.get("status") != "applying":
            raise RollbackErro(
                "Alteração não está em estado de aplicação.",
                codigo="estado_alteracao_invalido",
                detalhes={"status": estado.get("status")},
            )

        estado["resultado_aplicacao"] = resultado
        _salvar_estado(estado)

    return estado


def marcar_aguardando_confirmacao(alteracao_id: str) -> dict[str, Any]:
    agora = _agora_epoch()

    with _lock:
        estado = _carregar_estado(alteracao_id)

        if estado.get("status") != "applying":
            raise RollbackErro(
                "Alteração não está em aplicação.",
                codigo="estado_alteracao_invalido",
                detalhes={"status": estado.get("status")},
            )

        timeout = int(estado.get("timeout_segundos") or 60)
        expira = agora + timeout

        estado["status"] = "waiting_confirmation"
        estado["aplicado_em"] = _iso(agora)
        estado["expira_epoch"] = expira
        estado["expira_em"] = _iso(expira)
        _salvar_estado(estado)

    _agendar_timer(alteracao_id)
    return obter_status_alteracao(alteracao_id)


def confirmar_alteracao(alteracao_id: str) -> dict[str, Any]:
    alteracao_id = _validar_id(alteracao_id)

    with _lock:
        estado = _carregar_estado(alteracao_id)

        if estado.get("status") == "confirmed":
            return _enriquecer_estado(estado)

        if estado.get("status") != "waiting_confirmation":
            raise RollbackErro(
                "A alteração não está aguardando confirmação.",
                codigo="alteracao_nao_confirmavel",
                detalhes={"status": estado.get("status")},
            )

        if _segundos_restantes(estado) <= 0:
            expirou = True
        else:
            expirou = False

        if not expirou:
            estado["status"] = "confirmed"
            estado["confirmado_em"] = _iso()
            estado["expira_epoch"] = None
            estado["expira_em"] = None
            _salvar_estado(estado)

    if expirou:
        return reverter_alteracao(
            alteracao_id=alteracao_id,
            motivo="Prazo de confirmação expirado antes da confirmação.",
        )

    _cancelar_timer(alteracao_id)
    return obter_status_alteracao(alteracao_id)


def _executar_reversao(alteracao_id: str, motivo: str, *, status_final: str) -> dict[str, Any]:
    alteracao_id = _validar_id(alteracao_id)

    with _lock:
        estado = _carregar_estado(alteracao_id)
        status_atual = estado.get("status")

        if status_atual in {"reverted", "cancelled"}:
            return _enriquecer_estado(estado)

        if status_atual == "confirmed":
            raise RollbackErro(
                "Alteração já foi confirmada e não pode ser revertida pelo Safe Apply.",
                codigo="alteracao_ja_confirmada",
            )

        if status_atual not in STATUS_ATIVOS and status_atual != "rollback":
            raise RollbackErro(
                "Alteração não está em estado reversível.",
                codigo="alteracao_nao_reversivel",
                detalhes={"status": status_atual},
            )

        if status_atual != "rollback":
            estado["status"] = "rollback"
            estado["rollback_iniciado_em"] = _iso()
            estado["motivo_rollback"] = motivo
            _salvar_estado(estado)

        snapshot_id = estado.get("snapshot_id")

    _cancelar_timer(alteracao_id)

    try:
        resultado = restaurar_snapshot(snapshot_id)

        with _lock:
            estado = _carregar_estado(alteracao_id)
            estado["status"] = status_final
            estado["resultado_rollback"] = resultado
            estado["revertido_em"] = _iso()
            estado["expira_epoch"] = None
            estado["expira_em"] = None

            if status_final == "cancelled":
                estado["cancelado_em"] = _iso()

            _salvar_estado(estado)

        return obter_status_alteracao(alteracao_id)

    except Exception as exc:
        with _lock:
            estado = _carregar_estado(alteracao_id)
            estado["status"] = "failed"
            estado["erro"] = {
                "codigo": getattr(exc, "codigo", "rollback_falhou"),
                "mensagem": str(exc),
                "detalhes": getattr(exc, "detalhes", {}),
            }
            estado["expira_epoch"] = None
            estado["expira_em"] = None
            _salvar_estado(estado)

        raise RollbackErro(
            f"Rollback da alteração falhou: {exc}",
            codigo="rollback_falhou",
            detalhes={
                "alteracao_id": alteracao_id,
                "snapshot_id": snapshot_id,
                "erro": str(exc),
            },
        ) from exc


def reverter_alteracao(alteracao_id: str, motivo: str = "Rollback solicitado.") -> dict[str, Any]:
    return _executar_reversao(
        alteracao_id,
        motivo,
        status_final="reverted",
    )


def cancelar_alteracao(alteracao_id: str) -> dict[str, Any]:
    alteracao_id = _validar_id(alteracao_id)

    with _lock:
        estado = _carregar_estado(alteracao_id)

        if estado.get("status") == "cancelled":
            return _enriquecer_estado(estado)

        if estado.get("status") == "confirmed":
            raise RollbackErro(
                "Alteração já confirmada não pode ser cancelada.",
                codigo="alteracao_ja_confirmada",
            )

    return _executar_reversao(
        alteracao_id,
        "Alteração cancelada pelo controlador MoonShield.",
        status_final="cancelled",
    )


def _rollback_timeout(alteracao_id: str) -> None:
    try:
        with _lock:
            estado = _carregar_estado(alteracao_id)

            if estado.get("status") not in STATUS_ATIVOS:
                return

            if _segundos_restantes(estado) > 0:
                _agendar_timer(alteracao_id)
                return

        reverter_alteracao(
            alteracao_id,
            motivo="Rollback automático: prazo de segurança expirado.",
        )

    except Exception:
        # O estado de falha é persistido por _executar_reversao quando possível.
        pass


def _enriquecer_estado(estado: dict[str, Any]) -> dict[str, Any]:
    resultado = dict(estado)
    resultado["segundos_restantes"] = (
        _segundos_restantes(estado)
        if estado.get("status") in STATUS_ATIVOS
        else 0
    )
    resultado["aguardando_confirmacao"] = estado.get("status") == "waiting_confirmation"
    resultado["finalizada"] = estado.get("status") in STATUS_FINAIS
    return resultado


def obter_status_alteracao(alteracao_id: str) -> dict[str, Any]:
    alteracao_id = _validar_id(alteracao_id)

    with _lock:
        estado = _carregar_estado(alteracao_id)

    if estado.get("status") in STATUS_ATIVOS and _segundos_restantes(estado) <= 0:
        try:
            return reverter_alteracao(
                alteracao_id,
                motivo="Rollback automático: prazo de segurança expirado.",
            )
        except Exception:
            with _lock:
                estado = _carregar_estado(alteracao_id)

    return _enriquecer_estado(estado)


def listar_alteracoes() -> list[dict[str, Any]]:
    garantir_diretorios()
    resultado = []

    for caminho in DIRETORIO_ALTERACOES.glob("*.json"):
        try:
            with caminho.open("r", encoding="utf-8") as arquivo:
                estado = json.load(arquivo)

            if isinstance(estado, dict):
                resultado.append(_enriquecer_estado(estado))
        except Exception:
            continue

    resultado.sort(key=lambda item: item.get("criado_em") or "", reverse=True)
    return resultado


def obter_alteracao_ativa() -> dict[str, Any] | None:
    for estado in listar_alteracoes():
        if estado.get("status") in STATUS_ATIVOS:
            return estado
    return None


def inicializar_rollback_pendente() -> dict[str, Any]:
    """
    Deve ser chamado quando o servidor do MoonShield Agent iniciar.

    Recupera timers persistidos caso o Agent tenha sido reiniciado durante
    uma alteração ainda não confirmada.
    """

    recuperadas = []
    revertidas = []
    erros = []

    for estado in listar_alteracoes():
        if estado.get("status") not in STATUS_ATIVOS:
            continue

        alteracao_id = estado["alteracao_id"]

        try:
            if _segundos_restantes(estado) <= 0:
                reverter_alteracao(
                    alteracao_id,
                    motivo="Rollback automático após reinicialização do Agent.",
                )
                revertidas.append(alteracao_id)
            else:
                _agendar_timer(alteracao_id)
                recuperadas.append(alteracao_id)
        except Exception as exc:
            erros.append({
                "alteracao_id": alteracao_id,
                "erro": str(exc),
            })

    return {
        "ok": not erros,
        "recuperadas": recuperadas,
        "revertidas": revertidas,
        "erros": erros,
    }


__all__ = [
    "RollbackErro",
    "AlteracaoNaoEncontrada",
    "STATUS_ATIVOS",
    "STATUS_FINAIS",
    "armar_rollback",
    "registrar_resultado_aplicacao",
    "marcar_aguardando_confirmacao",
    "confirmar_alteracao",
    "reverter_alteracao",
    "cancelar_alteracao",
    "obter_status_alteracao",
    "obter_alteracao_ativa",
    "listar_alteracoes",
    "inicializar_rollback_pendente",
]