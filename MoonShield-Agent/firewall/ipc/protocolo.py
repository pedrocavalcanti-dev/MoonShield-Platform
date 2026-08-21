"""
MoonShield Agent — Protocolo IPC local
======================================

Protocolo simples, versionado e seguro para comunicação local entre
MoonShield Platform (Django) e MoonShield-Agent via Unix Domain Socket.

Transporte:
    AF_UNIX / SOCK_STREAM
    /run/moonshield/agent.sock

Enquadramento:
    1 mensagem JSON UTF-8 por linha (NDJSON)
    Cada conexão processa uma requisição e recebe uma resposta.

IMPORTANTE:
- Este protocolo NÃO usa HTTP.
- Este protocolo NÃO expõe porta TCP.
- Autorização é feita pelas permissões do socket Unix.
- O servidor mantém uma allowlist explícita de ações aceitas.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from typing import Any


VERSAO_PROTOCOLO = 1
SOCKET_PADRAO = "/run/moonshield/agent.sock"
MAX_MENSAGEM_BYTES = 2 * 1024 * 1024
ENCODING = "utf-8"

_RE_ID = re.compile(r"^[A-Za-z0-9_.:@-]{1,128}$")
_RE_ACAO = re.compile(r"^[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)+$")

ACOES = frozenset({
    "system.ping",
    "system.info",
    "firewall.status",
    "firewall.interfaces",
    "firewall.rules",
    "firewall.emergency",
    "firewall.diagnostico",
    "firewall.install",
    "firewall.repair",
    "firewall.uninstall",
    "firewall.apply",
    "firewall.rollback",
    "firewall.block",
    "firewall.unblock",
})

ALIASES_ACAO = {
    "ping": "system.ping",
    "status": "firewall.status",
    "interfaces": "firewall.interfaces",
    "regras": "firewall.rules",
    "emergency": "firewall.emergency",
    "diagnostico": "firewall.diagnostico",
    "instalar": "firewall.install",
    "reparar": "firewall.repair",
    "desinstalar": "firewall.uninstall",
    "aplicar": "firewall.apply",
    "rollback": "firewall.rollback",
    "bloquear": "firewall.block",
    "liberar": "firewall.unblock",
}


class ErroProtocolo(ValueError):
    """Erro de formato, validação ou enquadramento do protocolo."""


class AcaoNaoPermitida(ErroProtocolo):
    """Ação não pertence à allowlist do protocolo."""


@dataclass(slots=True, frozen=True)
class RequisicaoIPC:
    id: str
    acao: str
    dados: dict[str, Any]
    versao: int = VERSAO_PROTOCOLO

    def para_dict(self) -> dict[str, Any]:
        return {
            "versao": self.versao,
            "id": self.id,
            "acao": self.acao,
            "dados": self.dados,
        }


@dataclass(slots=True, frozen=True)
class RespostaIPC:
    id: str
    acao: str
    ok: bool
    dados: dict[str, Any]
    erro: dict[str, Any] | None = None
    versao: int = VERSAO_PROTOCOLO

    def para_dict(self) -> dict[str, Any]:
        return {
            "versao": self.versao,
            "id": self.id,
            "acao": self.acao,
            "ok": self.ok,
            "dados": self.dados,
            "erro": self.erro,
        }


def novo_id() -> str:
    return uuid.uuid4().hex


def normalizar_acao(acao: Any) -> str:
    valor = str(acao or "").strip().lower()
    if not valor:
        raise ErroProtocolo("Campo 'acao' é obrigatório.")

    valor = ALIASES_ACAO.get(valor, valor)

    if not _RE_ACAO.fullmatch(valor):
        raise ErroProtocolo("Formato de ação inválido.")

    if valor not in ACOES:
        raise AcaoNaoPermitida(f"Ação não permitida: {valor}")

    return valor


def validar_id(valor: Any) -> str:
    if valor is None or str(valor).strip() == "":
        return novo_id()

    valor = str(valor).strip()
    if not _RE_ID.fullmatch(valor):
        raise ErroProtocolo("Campo 'id' inválido.")
    return valor


def validar_dados(valor: Any) -> dict[str, Any]:
    if valor is None:
        return {}
    if not isinstance(valor, dict):
        raise ErroProtocolo("Campo 'dados' deve ser um objeto JSON.")
    return valor


def validar_versao(valor: Any) -> int:
    if valor is None:
        return VERSAO_PROTOCOLO

    try:
        versao = int(valor)
    except (TypeError, ValueError):
        raise ErroProtocolo("Versão do protocolo inválida.") from None

    if versao != VERSAO_PROTOCOLO:
        raise ErroProtocolo(
            f"Versão incompatível. Recebida={versao}, suportada={VERSAO_PROTOCOLO}."
        )
    return versao


def decodificar_requisicao(raw: bytes | str) -> RequisicaoIPC:
    if isinstance(raw, bytes):
        if len(raw) > MAX_MENSAGEM_BYTES:
            raise ErroProtocolo("Mensagem excede o limite permitido.")
        try:
            texto = raw.decode(ENCODING)
        except UnicodeDecodeError:
            raise ErroProtocolo("Mensagem não está em UTF-8 válido.") from None
    else:
        texto = str(raw)
        if len(texto.encode(ENCODING)) > MAX_MENSAGEM_BYTES:
            raise ErroProtocolo("Mensagem excede o limite permitido.")

    texto = texto.strip()
    if not texto:
        raise ErroProtocolo("Mensagem vazia.")

    try:
        payload = json.loads(texto)
    except json.JSONDecodeError as exc:
        raise ErroProtocolo(
            f"JSON inválido na posição {exc.pos}: {exc.msg}"
        ) from None

    if not isinstance(payload, dict):
        raise ErroProtocolo("A raiz da mensagem deve ser um objeto JSON.")

    return RequisicaoIPC(
        id=validar_id(payload.get("id")),
        acao=normalizar_acao(payload.get("acao")),
        dados=validar_dados(payload.get("dados")),
        versao=validar_versao(payload.get("versao")),
    )


def decodificar_resposta(raw: bytes | str) -> RespostaIPC:
    if isinstance(raw, bytes):
        if len(raw) > MAX_MENSAGEM_BYTES:
            raise ErroProtocolo("Resposta excede o limite permitido.")
        try:
            texto = raw.decode(ENCODING)
        except UnicodeDecodeError:
            raise ErroProtocolo("Resposta não está em UTF-8 válido.") from None
    else:
        texto = str(raw)

    try:
        payload = json.loads(texto.strip())
    except json.JSONDecodeError as exc:
        raise ErroProtocolo(f"Resposta JSON inválida: {exc.msg}") from None

    if not isinstance(payload, dict):
        raise ErroProtocolo("A raiz da resposta deve ser um objeto JSON.")

    ok = payload.get("ok")
    if not isinstance(ok, bool):
        raise ErroProtocolo("Campo 'ok' da resposta deve ser booleano.")

    erro = payload.get("erro")
    if erro is not None and not isinstance(erro, dict):
        raise ErroProtocolo("Campo 'erro' deve ser objeto JSON ou null.")

    return RespostaIPC(
        id=validar_id(payload.get("id")),
        acao=normalizar_acao(payload.get("acao")),
        ok=ok,
        dados=validar_dados(payload.get("dados")),
        erro=erro,
        versao=validar_versao(payload.get("versao")),
    )


def _serializar(payload: dict[str, Any]) -> bytes:
    try:
        texto = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        )
    except (TypeError, ValueError) as exc:
        raise ErroProtocolo(f"Falha ao serializar mensagem: {exc}") from exc

    raw = (texto + "\n").encode(ENCODING)
    if len(raw) > MAX_MENSAGEM_BYTES:
        raise ErroProtocolo("Mensagem serializada excede o limite permitido.")
    return raw


def codificar_requisicao(
    acao: str,
    dados: dict[str, Any] | None = None,
    *,
    req_id: str | None = None,
) -> bytes:
    req = RequisicaoIPC(
        id=validar_id(req_id),
        acao=normalizar_acao(acao),
        dados=validar_dados(dados),
    )
    return _serializar(req.para_dict())


def codificar_resposta(resposta: RespostaIPC) -> bytes:
    return _serializar(resposta.para_dict())


def resposta_ok(
    requisicao: RequisicaoIPC,
    dados: dict[str, Any] | None = None,
) -> RespostaIPC:
    return RespostaIPC(
        id=requisicao.id,
        acao=requisicao.acao,
        ok=True,
        dados=validar_dados(dados),
        erro=None,
    )


def resposta_erro(
    requisicao: RequisicaoIPC | None,
    *,
    codigo: str,
    mensagem: str,
    detalhes: dict[str, Any] | None = None,
    req_id: str | None = None,
    acao: str | None = None,
) -> RespostaIPC:
    if requisicao is not None:
        final_id = requisicao.id
        final_acao = requisicao.acao
    else:
        final_id = validar_id(req_id)
        final_acao = "system.ping"
        if acao:
            try:
                final_acao = normalizar_acao(acao)
            except ErroProtocolo:
                pass

    return RespostaIPC(
        id=final_id,
        acao=final_acao,
        ok=False,
        dados={},
        erro={
            "codigo": str(codigo or "erro"),
            "mensagem": str(mensagem or "Erro desconhecido."),
            "detalhes": detalhes or {},
        },
    )