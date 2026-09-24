"""Atualização privilegiada e transacional dos rulesets do Suricata."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from suricata.servico import reiniciar


YAML_PATH = Path("/etc/suricata/suricata.yaml")
RULES_MS_SOURCE = Path(__file__).parent / "regras_ms.rules"
RULES_MS_DEST = Path("/var/lib/suricata/rules/moonshield/ms.rules")
RULES_ET_DEST = Path("/var/lib/suricata/rules/suricata.rules")
BACKUP_DIR = Path("/var/lib/moonshield/suricata/backups/rules")

TIMEOUT_UPDATE = 900
TIMEOUT_VALIDATE = 120


def atualizar(dados: dict[str, Any] | None = None) -> dict[str, Any]:
    """Atualiza rulesets oficiais sem aceitar caminhos arbitrários do cliente."""
    inicio = time.monotonic()
    try:
        opcoes = _normalizar_opcoes(dados)
    except ValueError as exc:
        return _falha("regras_payload_invalido", str(exc), inicio)

    resultado = _resultado_base(opcoes)
    backups: dict[str, dict[str, Any]] = {}

    try:
        if opcoes["atualizar_moonshield"]:
            backups["moonshield"] = _criar_backup(RULES_MS_DEST)
            ms = _atualizar_moonshield()
            resultado["moonshield"].update(ms)
            if not ms["ok"]:
                raise _FalhaAtualizacao(ms["codigo"], ms["erro"])

        if opcoes["atualizar_et"]:
            backups["et_open"] = _criar_backup(RULES_ET_DEST)
            et = _atualizar_et_open()
            resultado["et_open"].update(et)
            if not et["ok"]:
                raise _FalhaAtualizacao(et["codigo"], et["erro"])

        if opcoes["validar_depois"]:
            validacao = _validar_suricata()
            resultado["validacao"].update(validacao)
            if not validacao["ok"]:
                rollback = _restaurar(backups)
                resultado["rollback"] = rollback
                resultado["validacao_rollback"] = _validar_suricata()
                raise _FalhaAtualizacao(
                    "regras_validacao_falhou",
                    validacao["erro"],
                )

        if opcoes["reiniciar_depois"]:
            reinicio = reiniciar({})
            resultado["reinicio"] = reinicio
            if not reinicio.get("ok"):
                rollback = _restaurar(backups)
                resultado["rollback"] = rollback
                resultado["validacao_rollback"] = _validar_suricata()
                if rollback.get("ok"):
                    resultado["reinicio_rollback"] = reiniciar({})
                raise _FalhaAtualizacao(
                    "regras_restart_falhou",
                    str(reinicio.get("erro") or "Suricata não reiniciou."),
                )

        resultado.update(
            {
                "ok": True,
                "mensagem": _mensagem_sucesso(resultado),
                "duracao_segundos": round(time.monotonic() - inicio, 3),
            }
        )
        return resultado
    except _FalhaAtualizacao as exc:
        resultado.update(
            {
                "ok": False,
                "codigo": exc.codigo,
                "erro": exc.mensagem,
                "mensagem": "Atualização de rulesets não foi concluída.",
                "duracao_segundos": round(time.monotonic() - inicio, 3),
            }
        )
        if "rollback" not in resultado and backups:
            resultado["rollback"] = _restaurar(backups)
        return resultado
    except Exception as exc:
        resultado.update(
            {
                "ok": False,
                "codigo": "regras_update_falhou",
                "erro": str(exc),
                "mensagem": "Atualização de rulesets não foi concluída.",
                "duracao_segundos": round(time.monotonic() - inicio, 3),
            }
        )
        if backups:
            resultado["rollback"] = _restaurar(backups)
        return resultado


def _normalizar_opcoes(dados: dict[str, Any] | None) -> dict[str, bool]:
    dados = dados or {}
    if not isinstance(dados, dict):
        raise ValueError("Dados da atualização precisam ser um objeto JSON.")

    permitidas = {
        "atualizar_moonshield",
        "atualizar_et",
        "validar_depois",
        "reiniciar_depois",
    }
    desconhecidas = set(dados) - permitidas
    if desconhecidas:
        raise ValueError(
            "Campos não permitidos: " + ", ".join(sorted(desconhecidas))
        )

    opcoes = {
        "atualizar_moonshield": dados.get("atualizar_moonshield", True),
        "atualizar_et": dados.get("atualizar_et", True),
        "validar_depois": dados.get("validar_depois", True),
        "reiniciar_depois": dados.get("reiniciar_depois", False),
    }
    if not all(isinstance(valor, bool) for valor in opcoes.values()):
        raise ValueError("As opções da atualização precisam ser booleanas.")
    if opcoes["reiniciar_depois"] and not opcoes["validar_depois"]:
        raise ValueError("Reinício exige validação aprovada na mesma operação.")
    return opcoes


def _resultado_base(opcoes: dict[str, bool]) -> dict[str, Any]:
    return {
        "solicitado": dict(opcoes),
        "caminhos": {
            "yaml": str(YAML_PATH),
            "moonshield_origem": str(RULES_MS_SOURCE),
            "moonshield_destino": str(RULES_MS_DEST),
            "et_open_destino": str(RULES_ET_DEST),
        },
        "moonshield": {
            "solicitada": opcoes["atualizar_moonshield"],
            "executada": False,
            "mudou": False,
        },
        "et_open": {
            "solicitada": opcoes["atualizar_et"],
            "executada": False,
            "mudou": False,
            "versao_suricata_update": "",
        },
        "validacao": {
            "solicitada": opcoes["validar_depois"],
            "executada": False,
            "aprovada": False,
        },
        "reinicio": {
            "solicitado": opcoes["reiniciar_depois"],
            "executado": False,
        },
    }


def _atualizar_moonshield() -> dict[str, Any]:
    if not RULES_MS_SOURCE.is_file() or RULES_MS_SOURCE.stat().st_size == 0:
        return _operacao_falhou(
            "regras_moonshield_origem_ausente",
            "Asset oficial MoonShield ausente ou vazio.",
        )

    conteudo = _sem_bom(RULES_MS_SOURCE.read_bytes())
    antes = _hash_arquivo(RULES_MS_DEST)
    depois_esperado = _hash_bytes(conteudo)
    mudou = antes != depois_esperado
    if mudou:
        _escrever_atomico(RULES_MS_DEST, conteudo)

    return {
        "ok": True,
        "executada": True,
        "mudou": mudou,
        "hash_antes": antes,
        "hash_depois": _hash_arquivo(RULES_MS_DEST),
    }


def _atualizar_et_open() -> dict[str, Any]:
    binario = shutil.which("suricata-update")
    if not binario:
        return _operacao_falhou(
            "suricata_update_indisponivel",
            "suricata-update não está disponível no PATH.",
        )

    versao = _executar([binario, "--version"], timeout=30)
    if versao.returncode != 0:
        return _operacao_falhou(
            "suricata_update_versao_falhou",
            _saida_erro(versao),
        )

    antes = _hash_arquivo(RULES_ET_DEST)
    update = _executar([binario, "--no-reload"], timeout=TIMEOUT_UPDATE)
    if update.returncode != 0:
        return _operacao_falhou(
            "suricata_update_falhou",
            _saida_erro(update),
            versao=_primeira_linha(versao.stdout),
            hash_antes=antes,
        )

    return {
        "ok": True,
        "executada": True,
        "mudou": antes != _hash_arquivo(RULES_ET_DEST),
        "hash_antes": antes,
        "hash_depois": _hash_arquivo(RULES_ET_DEST),
        "versao_suricata_update": _primeira_linha(versao.stdout),
        "saida_resumo": _ultimas_linhas(update.stdout, update.stderr),
    }


def _validar_suricata() -> dict[str, Any]:
    binario = shutil.which("suricata")
    if not binario:
        return {
            "ok": False,
            "executada": True,
            "aprovada": False,
            "erro": "Binário suricata não encontrado.",
        }
    if not YAML_PATH.is_file():
        return {
            "ok": False,
            "executada": True,
            "aprovada": False,
            "erro": "suricata.yaml oficial não encontrado.",
        }

    processo = _executar(
        [binario, "-T", "-c", str(YAML_PATH)],
        timeout=TIMEOUT_VALIDATE,
    )
    aprovado = processo.returncode == 0
    return {
        "ok": aprovado,
        "executada": True,
        "aprovada": aprovado,
        "returncode": processo.returncode,
        "erro": "" if aprovado else _saida_erro(processo),
        "saida_resumo": _ultimas_linhas(processo.stdout, processo.stderr),
    }


def _criar_backup(destino: Path) -> dict[str, Any]:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    if not destino.exists():
        return {"existia": False, "backup": ""}

    with tempfile.NamedTemporaryFile(
        dir=str(BACKUP_DIR),
        prefix=f"{destino.name}.",
        suffix=".bak",
        delete=False,
    ) as arquivo:
        backup = Path(arquivo.name)
    shutil.copy2(destino, backup)
    return {"existia": True, "backup": str(backup)}


def _restaurar(backups: dict[str, dict[str, Any]]) -> dict[str, Any]:
    erros: list[str] = []
    destinos = {
        "moonshield": RULES_MS_DEST,
        "et_open": RULES_ET_DEST,
    }
    for nome, backup in backups.items():
        destino = destinos[nome]
        try:
            if backup.get("existia"):
                _escrever_atomico(destino, Path(backup["backup"]).read_bytes())
            else:
                destino.unlink(missing_ok=True)
        except Exception as exc:
            erros.append(f"{nome}: {exc}")
    return {"executado": bool(backups), "ok": not erros, "erros": erros}


def _escrever_atomico(destino: Path, conteudo: bytes) -> None:
    destino.parent.mkdir(parents=True, exist_ok=True)
    stat_anterior = destino.stat() if destino.exists() else None
    with tempfile.NamedTemporaryFile(dir=str(destino.parent), delete=False) as arquivo:
        arquivo.write(conteudo)
        arquivo.flush()
        os.fsync(arquivo.fileno())
        temporario = Path(arquivo.name)
    try:
        if stat_anterior is not None:
            os.chmod(temporario, stat_anterior.st_mode & 0o777)
            if os.name == "posix":
                os.chown(
                    temporario,
                    stat_anterior.st_uid,
                    stat_anterior.st_gid,
                )
        else:
            os.chmod(temporario, 0o644)
        os.replace(temporario, destino)
    except Exception:
        temporario.unlink(missing_ok=True)
        raise


def _hash_arquivo(path: Path) -> str:
    return _hash_bytes(path.read_bytes()) if path.is_file() else ""


def _hash_bytes(conteudo: bytes) -> str:
    return hashlib.sha256(conteudo).hexdigest()


def _sem_bom(conteudo: bytes) -> bytes:
    return conteudo[3:] if conteudo.startswith(b"\xef\xbb\xbf") else conteudo


def _executar(argumentos: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argumentos, capture_output=True, text=True, timeout=timeout, check=False)


def _operacao_falhou(codigo: str, erro: str, **dados: Any) -> dict[str, Any]:
    return {"ok": False, "codigo": codigo, "erro": erro, **dados}


def _falha(codigo: str, erro: str, inicio: float) -> dict[str, Any]:
    return {"ok": False, "codigo": codigo, "erro": erro, "duracao_segundos": round(time.monotonic() - inicio, 3)}


def _saida_erro(processo: subprocess.CompletedProcess[str]) -> str:
    return (processo.stderr or processo.stdout or "Comando falhou sem saída.").strip()[-2000:]


def _primeira_linha(texto: str) -> str:
    return next((linha.strip() for linha in (texto or "").splitlines() if linha.strip()), "")


def _ultimas_linhas(stdout: str, stderr: str) -> list[str]:
    return [linha for linha in (stdout + "\n" + stderr).splitlines() if linha.strip()][-20:]


def _mensagem_sucesso(resultado: dict[str, Any]) -> str:
    if not resultado["moonshield"]["solicitada"] and not resultado["et_open"]["solicitada"]:
        return "Nenhum ruleset foi selecionado; estado atual validado quando solicitado."
    return "Rulesets atualizados e validação concluída quando solicitada."


class _FalhaAtualizacao(Exception):
    def __init__(self, codigo: str, mensagem: str):
        self.codigo = codigo
        self.mensagem = mensagem
        super().__init__(mensagem)
