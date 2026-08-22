"""
MoonShield Agent — Rede / Snapshot
==================================

Snapshots técnicos usados pelo Safe Apply.

Um snapshot pode conter:
- perfis NetworkManager das interfaces;
- estado do IPv4 forwarding;
- rotas observadas;
- estado da tabela NAT MoonShield.

Os snapshots são armazenados em:

    /var/lib/moonshield/rede/snapshots/

O arquivo é escrito atomicamente e com permissão 0600.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .configuracao import DIRETORIO_SNAPSHOTS, garantir_diretorios, obter_backend
from .nat import exportar_estado_nat, restaurar_estado_nat
from .roteamento import definir_ipv4_forward, obter_ipv4_forward


VERSAO_SNAPSHOT = 1

ID_RE = re.compile(
    r"^[A-Za-z0-9_.:-]{1,128}$"
)


# =============================================================================
# EXCEÇÕES
# =============================================================================

class SnapshotErro(RuntimeError):
    def __init__(
        self,
        mensagem: str,
        *,
        codigo: str = "snapshot_erro",
        detalhes: dict[str, Any] | None = None,
    ):
        super().__init__(mensagem)
        self.codigo = codigo
        self.detalhes = detalhes or {}


class SnapshotNaoEncontrado(SnapshotErro):
    def __init__(self, snapshot_id: str):
        super().__init__(
            f"Snapshot não encontrado: {snapshot_id}",
            codigo="snapshot_nao_encontrado",
            detalhes={
                "snapshot_id": snapshot_id,
            },
        )


# =============================================================================
# HELPERS
# =============================================================================

def _agora_iso() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def _validar_id(
    snapshot_id: Any,
) -> str:
    valor = str(
        snapshot_id
        or ""
    ).strip()

    if not valor:
        raise SnapshotErro(
            "Identificador do snapshot não informado.",
            codigo="snapshot_id_invalido",
        )

    if not ID_RE.fullmatch(valor):
        raise SnapshotErro(
            "Identificador do snapshot inválido.",
            codigo="snapshot_id_invalido",
            detalhes={
                "snapshot_id": valor,
            },
        )

    return valor


def _caminho(
    snapshot_id: str,
) -> Path:
    snapshot_id = _validar_id(
        snapshot_id
    )

    return DIRETORIO_SNAPSHOTS / (
        snapshot_id + ".json"
    )


def _serializavel(
    valor: Any,
) -> Any:
    if hasattr(
        valor,
        "para_dict",
    ):
        return valor.para_dict()

    return valor


# =============================================================================
# INTERFACES
# =============================================================================

def _interfaces_padrao() -> list[str]:
    backend = obter_backend()

    interfaces = backend.listar_interfaces(
        incluir_loopback=False
    )

    return [
        str(item["nome"])
        for item in interfaces
        if item.get("gerenciavel", True)
        and item.get("nome")
    ]


def _normalizar_interfaces(
    interfaces: list[str] | None,
) -> list[str]:
    if interfaces is None:
        return _interfaces_padrao()

    if not isinstance(
        interfaces,
        list,
    ):
        raise SnapshotErro(
            "'interfaces' precisa ser uma lista.",
            codigo="snapshot_interfaces_invalidas",
        )

    resultado = []

    for interface in interfaces:
        nome = str(
            interface
            or ""
        ).strip()

        if not nome:
            continue

        if nome not in resultado:
            resultado.append(nome)

    return resultado


# =============================================================================
# SALVAR
# =============================================================================

def salvar_snapshot(
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(
        snapshot,
        dict,
    ):
        raise SnapshotErro(
            "Conteúdo de snapshot inválido."
        )

    snapshot_id = _validar_id(
        snapshot.get("id")
    )

    garantir_diretorios()

    caminho = _caminho(
        snapshot_id
    )

    conteudo = json.dumps(
        snapshot,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )

    temporario = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(
                DIRETORIO_SNAPSHOTS
            ),
            prefix=f".{snapshot_id}.",
            suffix=".tmp",
            delete=False,
        ) as arquivo:
            temporario = Path(
                arquivo.name
            )

            arquivo.write(
                conteudo
            )

            arquivo.flush()
            os.fsync(
                arquivo.fileno()
            )

        os.chmod(
            temporario,
            0o600,
        )

        os.replace(
            temporario,
            caminho,
        )

    except OSError as exc:
        if temporario:
            try:
                temporario.unlink(
                    missing_ok=True
                )
            except OSError:
                pass

        raise SnapshotErro(
            f"Não foi possível salvar snapshot: {exc}",
            codigo="snapshot_salvar_falhou",
            detalhes={
                "caminho": str(caminho),
            },
        ) from exc

    return {
        "ok": True,
        "id": snapshot_id,
        "caminho": str(caminho),
    }


# =============================================================================
# CRIAR
# =============================================================================

def criar_snapshot(
    snapshot_id: str,
    *,
    interfaces: list[str] | None = None,
    incluir_roteamento: bool = True,
    incluir_nat: bool = True,
    metadados: dict[str, Any] | None = None,
) -> dict[str, Any]:
    snapshot_id = _validar_id(
        snapshot_id
    )

    backend = obter_backend()

    interfaces = _normalizar_interfaces(
        interfaces
    )

    backend_snapshot = backend.criar_snapshot(
        interfaces
    )

    snapshot: dict[str, Any] = {
        "versao": VERSAO_SNAPSHOT,
        "id": snapshot_id,
        "criado_em": _agora_iso(),
        "backend": backend.nome,
        "interfaces": interfaces,
        "backend_snapshot": _serializavel(
            backend_snapshot
        ),
        "roteamento": None,
        "nat": None,
        "metadados": dict(
            metadados
            or {}
        ),
    }

    if incluir_roteamento:
        snapshot["roteamento"] = {
            "ipv4_forward": obter_ipv4_forward(),
            "rotas_observadas": backend.obter_rotas(),
        }

    if incluir_nat:
        snapshot["nat"] = exportar_estado_nat()

    salvar_snapshot(
        snapshot
    )

    return snapshot


# =============================================================================
# CARREGAR
# =============================================================================

def carregar_snapshot(
    snapshot_id: str,
) -> dict[str, Any]:
    caminho = _caminho(
        snapshot_id
    )

    if not caminho.exists():
        raise SnapshotNaoEncontrado(
            snapshot_id
        )

    try:
        with caminho.open(
            "r",
            encoding="utf-8",
        ) as arquivo:
            dados = json.load(
                arquivo
            )
    except (
        OSError,
        json.JSONDecodeError,
    ) as exc:
        raise SnapshotErro(
            f"Não foi possível carregar snapshot: {exc}",
            codigo="snapshot_leitura_falhou",
            detalhes={
                "snapshot_id": snapshot_id,
            },
        ) from exc

    if not isinstance(
        dados,
        dict,
    ):
        raise SnapshotErro(
            "Formato de snapshot inválido.",
            codigo="snapshot_formato_invalido",
        )

    return dados


# =============================================================================
# RESTAURAR
# =============================================================================

def restaurar_snapshot(
    snapshot_id: str,
) -> dict[str, Any]:
    snapshot = carregar_snapshot(
        snapshot_id
    )

    backend = obter_backend()

    backend_nome = snapshot.get(
        "backend"
    )

    if backend_nome != backend.nome:
        raise SnapshotErro(
            "Backend atual é diferente do backend registrado no snapshot.",
            codigo="snapshot_backend_incompativel",
            detalhes={
                "snapshot": backend_nome,
                "atual": backend.nome,
            },
        )

    resultados: dict[str, Any] = {
        "interfaces": None,
        "roteamento": None,
        "nat": None,
    }

    backend_snapshot = snapshot.get(
        "backend_snapshot"
    )

    if backend_snapshot:
        resultados["interfaces"] = (
            backend.restaurar_snapshot(
                backend_snapshot
            )
        )

    roteamento = snapshot.get(
        "roteamento"
    )

    if isinstance(
        roteamento,
        dict,
    ):
        forward = bool(
            roteamento.get(
                "ipv4_forward",
                False,
            )
        )

        resultados["roteamento"] = (
            definir_ipv4_forward(
                forward
            )
        )

    nat = snapshot.get(
        "nat"
    )

    if isinstance(
        nat,
        dict,
    ):
        resultados["nat"] = (
            restaurar_estado_nat(
                nat
            )
        )

    return {
        "ok": True,
        "snapshot_id": snapshot_id,
        "restaurado_em": _agora_iso(),
        "resultados": resultados,
    }


# =============================================================================
# REMOVER
# =============================================================================

def remover_snapshot(
    snapshot_id: str,
) -> dict[str, Any]:
    caminho = _caminho(
        snapshot_id
    )

    if not caminho.exists():
        return {
            "ok": True,
            "removido": False,
            "snapshot_id": snapshot_id,
        }

    try:
        caminho.unlink()
    except OSError as exc:
        raise SnapshotErro(
            f"Não foi possível remover snapshot: {exc}",
            codigo="snapshot_remocao_falhou",
        ) from exc

    return {
        "ok": True,
        "removido": True,
        "snapshot_id": snapshot_id,
    }


# =============================================================================
# LISTAGEM
# =============================================================================

def listar_snapshots() -> list[dict[str, Any]]:
    garantir_diretorios()

    resultado = []

    for caminho in sorted(
        DIRETORIO_SNAPSHOTS.glob(
            "*.json"
        )
    ):
        try:
            stat = caminho.stat()

            resultado.append({
                "id": caminho.stem,
                "caminho": str(caminho),
                "tamanho": stat.st_size,
                "modificado_em": datetime.fromtimestamp(
                    stat.st_mtime,
                    timezone.utc,
                ).isoformat(),
            })

        except OSError:
            continue

    return resultado


def snapshot_existe(
    snapshot_id: str,
) -> bool:
    return _caminho(
        snapshot_id
    ).exists()


__all__ = [
    "VERSAO_SNAPSHOT",
    "SnapshotErro",
    "SnapshotNaoEncontrado",
    "criar_snapshot",
    "salvar_snapshot",
    "carregar_snapshot",
    "restaurar_snapshot",
    "remover_snapshot",
    "listar_snapshots",
    "snapshot_existe",
]