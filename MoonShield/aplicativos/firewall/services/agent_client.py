"""
MoonShield Platform — Firewall / Agent Client
=============================================

Cliente IPC local usado pelo Django para conversar com o MoonShield-Agent.

Arquitetura:

    Django
      ↓
    aplicativos.firewall.services.agent_client
      ↓
    Unix Domain Socket
      ↓
    /run/moonshield/agent.sock
      ↓
    MoonShield-Agent
      ↓
    nftables / Linux

IMPORTANTE:
- NÃO usa HTTP.
- NÃO usa requests.
- NÃO usa IP de sensor.
- NÃO usa porta 8765.
- NÃO usa X-MS-TOKEN.
- NÃO executa `nft` diretamente no processo Django.
- Toda operação privilegiada pertence ao MoonShield-Agent.

O protocolo deve permanecer compatível com:
    MoonShield-Agent/firewall/ipc/protocolo.py
"""

from __future__ import annotations

import json
import logging
import os
import socket
import uuid
from dataclasses import dataclass
from typing import Any

from django.conf import settings


logger = logging.getLogger(__name__)


# =============================================================================
# CONFIGURAÇÃO
# =============================================================================

VERSAO_PROTOCOLO = 1

SOCKET_PADRAO = "/run/moonshield/agent.sock"

TIMEOUT_PADRAO = 8.0
TIMEOUT_OPERACAO_LONGA = 180.0

MAX_RESPOSTA_BYTES = 4 * 1024 * 1024  # 4 MiB

ENCODING = "utf-8"


# =============================================================================
# EXCEÇÕES
# =============================================================================

class ErroAgent(RuntimeError):
    """Erro base da integração Django ↔ MoonShield-Agent."""


class AgentIndisponivel(ErroAgent):
    """Socket local não existe, não conecta ou Agent não está ativo."""


class AgentTimeout(ErroAgent):
    """MoonShield-Agent excedeu o timeout esperado."""


class ErroProtocoloAgent(ErroAgent):
    """Resposta IPC inválida ou incompatível."""


class OperacaoAgentFalhou(ErroAgent):
    """Agent respondeu corretamente, porém recusou/falhou na operação."""

    def __init__(
        self,
        mensagem: str,
        *,
        codigo: str = "operacao_falhou",
        detalhes: dict[str, Any] | None = None,
        resposta: dict[str, Any] | None = None,
    ):
        super().__init__(mensagem)
        self.codigo = codigo
        self.detalhes = detalhes or {}
        self.resposta = resposta or {}


# =============================================================================
# RESULTADO
# =============================================================================

@dataclass(slots=True, frozen=True)
class ResultadoAgent:
    ok: bool
    acao: str
    request_id: str
    dados: dict[str, Any]
    erro: dict[str, Any] | None
    resposta_raw: dict[str, Any]

    @property
    def codigo_erro(self) -> str:
        if not self.erro:
            return ""
        return str(self.erro.get("codigo") or "")

    @property
    def mensagem_erro(self) -> str:
        if not self.erro:
            return ""
        return str(
            self.erro.get("mensagem")
            or self.erro.get("erro")
            or "Operação falhou."
        )


# =============================================================================
# CAMINHO DO SOCKET
# =============================================================================

def obter_socket_path() -> str:
    """
    Ordem de prioridade:

    1. settings.MOONSHIELD_AGENT_SOCKET
    2. variável MOONSHIELD_AGENT_SOCKET
    3. /run/moonshield/agent.sock
    """
    valor_settings = getattr(
        settings,
        "MOONSHIELD_AGENT_SOCKET",
        "",
    )

    if valor_settings:
        return str(valor_settings).strip()

    valor_env = os.getenv(
        "MOONSHIELD_AGENT_SOCKET",
        "",
    ).strip()

    if valor_env:
        return valor_env

    return SOCKET_PADRAO


def socket_existe() -> bool:
    caminho = obter_socket_path()
    return os.path.exists(caminho)


# =============================================================================
# CHAMADA PRINCIPAL
# =============================================================================

def chamar(
    acao: str,
    dados: dict[str, Any] | None = None,
    *,
    timeout: float | None = None,
    levantar_erro_operacao: bool = False,
) -> ResultadoAgent:
    """
    Executa uma chamada IPC síncrona.

    Por padrão, erros de transporte/protocolo lançam exceção.
    Uma resposta válida com ok=False é retornada como ResultadoAgent.

    Se levantar_erro_operacao=True, ok=False também lança OperacaoAgentFalhou.
    """
    acao = str(acao or "").strip()

    if not acao:
        raise ValueError("Ação IPC é obrigatória.")

    if dados is None:
        dados = {}

    if not isinstance(dados, dict):
        raise TypeError("dados deve ser um dict.")

    request_id = uuid.uuid4().hex

    payload = {
        "versao": VERSAO_PROTOCOLO,
        "id": request_id,
        "acao": acao,
        "dados": dados,
    }

    raw = (
        json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        )
        + "\n"
    ).encode(ENCODING)

    resposta = _trocar_mensagem(
        raw,
        timeout=(
            TIMEOUT_PADRAO
            if timeout is None
            else float(timeout)
        ),
    )

    resultado = _validar_resposta(
        resposta,
        acao_esperada=acao,
        request_id_esperado=request_id,
    )

    if (
        levantar_erro_operacao
        and not resultado.ok
    ):
        raise OperacaoAgentFalhou(
            resultado.mensagem_erro,
            codigo=resultado.codigo_erro or "operacao_falhou",
            detalhes=(
                resultado.erro.get("detalhes", {})
                if resultado.erro
                else {}
            ),
            resposta=resultado.resposta_raw,
        )

    return resultado


def chamar_dados(
    acao: str,
    dados: dict[str, Any] | None = None,
    *,
    timeout: float | None = None,
) -> dict[str, Any]:
    """
    Atalho: executa e retorna somente `dados`.

    Qualquer ok=False gera OperacaoAgentFalhou.
    """
    resultado = chamar(
        acao,
        dados,
        timeout=timeout,
        levantar_erro_operacao=True,
    )
    return resultado.dados


# =============================================================================
# TRANSPORTE
# =============================================================================

def _trocar_mensagem(
    payload: bytes,
    *,
    timeout: float,
) -> dict[str, Any]:
    caminho = obter_socket_path()

    if os.name != "posix":
        raise AgentIndisponivel(
            "MoonShield-Agent IPC local só está disponível no host Linux."
        )

    if not os.path.exists(caminho):
        raise AgentIndisponivel(
            f"Socket do MoonShield-Agent não encontrado: {caminho}"
        )

    cliente = socket.socket(
        socket.AF_UNIX,
        socket.SOCK_STREAM,
    )

    cliente.settimeout(timeout)

    try:
        cliente.connect(caminho)
        cliente.sendall(payload)

        raw = _receber_linha(
            cliente,
            max_bytes=MAX_RESPOSTA_BYTES,
        )

    except socket.timeout as exc:
        raise AgentTimeout(
            f"MoonShield-Agent excedeu {timeout:.1f}s."
        ) from exc

    except FileNotFoundError as exc:
        raise AgentIndisponivel(
            f"Socket do MoonShield-Agent não encontrado: {caminho}"
        ) from exc

    except ConnectionRefusedError as exc:
        raise AgentIndisponivel(
            "MoonShield-Agent recusou a conexão local."
        ) from exc

    except PermissionError as exc:
        raise AgentIndisponivel(
            "Django não possui permissão para acessar o socket "
            f"do MoonShield-Agent: {caminho}"
        ) from exc

    except OSError as exc:
        raise AgentIndisponivel(
            f"Falha ao conectar ao MoonShield-Agent: {exc}"
        ) from exc

    finally:
        try:
            cliente.close()
        except Exception:
            pass

    try:
        texto = raw.decode(ENCODING)
    except UnicodeDecodeError as exc:
        raise ErroProtocoloAgent(
            "MoonShield-Agent retornou dados que não são UTF-8 válido."
        ) from exc

    try:
        resposta = json.loads(
            texto.strip()
        )
    except json.JSONDecodeError as exc:
        raise ErroProtocoloAgent(
            f"MoonShield-Agent retornou JSON inválido: {exc.msg}"
        ) from exc

    if not isinstance(resposta, dict):
        raise ErroProtocoloAgent(
            "Resposta do MoonShield-Agent deve ser um objeto JSON."
        )

    return resposta


def _receber_linha(
    cliente: socket.socket,
    *,
    max_bytes: int,
) -> bytes:
    buffer = bytearray()

    while True:
        bloco = cliente.recv(
            min(
                65536,
                max_bytes + 1,
            )
        )

        if not bloco:
            break

        buffer.extend(bloco)

        if len(buffer) > max_bytes:
            raise ErroProtocoloAgent(
                "Resposta do MoonShield-Agent excedeu o limite permitido."
            )

        pos = buffer.find(b"\n")

        if pos >= 0:
            return bytes(
                buffer[:pos]
            )

    if not buffer:
        raise ErroProtocoloAgent(
            "MoonShield-Agent encerrou a conexão sem resposta."
        )

    return bytes(buffer)


# =============================================================================
# VALIDAÇÃO DE RESPOSTA
# =============================================================================

def _validar_resposta(
    resposta: dict[str, Any],
    *,
    acao_esperada: str,
    request_id_esperado: str,
) -> ResultadoAgent:
    versao = resposta.get("versao")

    try:
        versao = int(versao)
    except (TypeError, ValueError):
        raise ErroProtocoloAgent(
            "Resposta sem versão de protocolo válida."
        ) from None

    if versao != VERSAO_PROTOCOLO:
        raise ErroProtocoloAgent(
            f"Versão IPC incompatível: Agent={versao}, "
            f"Django={VERSAO_PROTOCOLO}."
        )

    resposta_id = str(
        resposta.get("id")
        or ""
    ).strip()

    if resposta_id != request_id_esperado:
        raise ErroProtocoloAgent(
            "ID da resposta não corresponde à requisição."
        )

    resposta_acao = str(
        resposta.get("acao")
        or ""
    ).strip()

    if resposta_acao != acao_esperada:
        raise ErroProtocoloAgent(
            f"Ação da resposta diverge da requisição: "
            f"{resposta_acao!r} != {acao_esperada!r}."
        )

    ok = resposta.get("ok")

    if not isinstance(ok, bool):
        raise ErroProtocoloAgent(
            "Campo 'ok' da resposta deve ser booleano."
        )

    dados = resposta.get("dados")

    if dados is None:
        dados = {}

    if not isinstance(dados, dict):
        raise ErroProtocoloAgent(
            "Campo 'dados' da resposta deve ser um objeto."
        )

    erro = resposta.get("erro")

    if erro is not None and not isinstance(erro, dict):
        raise ErroProtocoloAgent(
            "Campo 'erro' da resposta deve ser objeto ou null."
        )

    return ResultadoAgent(
        ok=ok,
        acao=resposta_acao,
        request_id=resposta_id,
        dados=dados,
        erro=erro,
        resposta_raw=resposta,
    )


# =============================================================================
# AÇÕES DO SISTEMA
# =============================================================================

def ping() -> dict[str, Any]:
    return chamar_dados(
        "system.ping"
    )


def info() -> dict[str, Any]:
    return chamar_dados(
        "system.info"
    )


def agente_disponivel() -> bool:
    try:
        dados = ping()
        return bool(
            dados.get("pong")
        )
    except ErroAgent:
        return False


# =============================================================================
# FIREWALL — LEITURA
# =============================================================================

def status() -> dict[str, Any]:
    return chamar_dados(
        "firewall.status"
    )


def interfaces() -> dict[str, Any]:
    return chamar_dados(
        "firewall.interfaces"
    )


def regras_linux() -> dict[str, Any]:
    return chamar_dados(
        "firewall.rules"
    )


def emergency() -> dict[str, Any]:
    return chamar_dados(
        "firewall.emergency"
    )


def diagnostico() -> dict[str, Any]:
    return chamar_dados(
        "firewall.diagnostico",
        timeout=30.0,
    )


# =============================================================================
# FIREWALL — INSTALAÇÃO
# =============================================================================

def instalar(
    *,
    config: dict[str, Any],
    instalar_pacote: bool = True,
) -> dict[str, Any]:
    return chamar_dados(
        "firewall.install",
        {
            "config": config,
            "instalar_pacote": bool(instalar_pacote),
        },
        timeout=TIMEOUT_OPERACAO_LONGA,
    )


def reparar(
    *,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {}

    if config:
        payload["config"] = config

    return chamar_dados(
        "firewall.repair",
        payload,
        timeout=TIMEOUT_OPERACAO_LONGA,
    )


def desinstalar(
    *,
    confirmar: bool,
    remover_config: bool = False,
) -> dict[str, Any]:
    return chamar_dados(
        "firewall.uninstall",
        {
            "confirmar": bool(confirmar),
            "remover_config": bool(remover_config),
        },
        timeout=TIMEOUT_OPERACAO_LONGA,
    )


# =============================================================================
# FIREWALL — REGRAS
# =============================================================================

def aplicar_regras(
    regras: list[dict[str, Any]],
    *,
    iface_map: dict[str, str] | None = None,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(regras, list):
        raise TypeError("regras deve ser uma lista.")

    payload: dict[str, Any] = {
        "regras": regras,
        "iface_map": iface_map or {},
    }

    if config:
        payload["config"] = config

    return chamar_dados(
        "firewall.apply",
        payload,
        timeout=TIMEOUT_OPERACAO_LONGA,
    )


def rollback(
    *,
    snapshot_id: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {}

    if snapshot_id:
        payload["snapshot_id"] = str(
            snapshot_id
        )

    return chamar_dados(
        "firewall.rollback",
        payload,
        timeout=TIMEOUT_OPERACAO_LONGA,
    )


# =============================================================================
# FIREWALL — EMERGÊNCIA
# =============================================================================

def bloquear_ip(
    ip: str,
    *,
    motivo: str = "Bloqueio manual",
    iface: str = "",
    porta: str | int | None = None,
    proto: str = "",
    expires: str = "",
) -> dict[str, Any]:
    ip = str(ip or "").strip()

    if not ip:
        raise ValueError("IP é obrigatório.")

    payload = {
        "ip": ip,
        "motivo": str(motivo or "Bloqueio manual"),
        "iface": str(iface or ""),
        "porta": (
            ""
            if porta is None
            else str(porta)
        ),
        "proto": str(proto or ""),
        "expires": str(expires or ""),
    }

    return chamar_dados(
        "firewall.block",
        payload,
        timeout=20.0,
    )


def liberar_ip(
    ip: str,
) -> dict[str, Any]:
    ip = str(ip or "").strip()

    if not ip:
        raise ValueError("IP é obrigatório.")

    return chamar_dados(
        "firewall.unblock",
        {
            "ip": ip,
        },
        timeout=20.0,
    )


# =============================================================================
# STATUS SEGURO PARA UI
# =============================================================================

def status_seguro() -> dict[str, Any]:
    """
    Nunca lança exceção.

    Útil para páginas/status onde Agent offline deve virar estado de UI,
    e não HTTP 500.
    """
    try:
        dados_ping = ping()
        dados_status = status()

        return {
            "ok": True,
            "agent_disponivel": True,
            "ping": dados_ping,
            "firewall": dados_status,
            "erro": None,
        }

    except AgentIndisponivel as exc:
        return {
            "ok": False,
            "agent_disponivel": False,
            "ping": {},
            "firewall": {},
            "erro": {
                "codigo": "agent_indisponivel",
                "mensagem": str(exc),
            },
        }

    except AgentTimeout as exc:
        return {
            "ok": False,
            "agent_disponivel": False,
            "ping": {},
            "firewall": {},
            "erro": {
                "codigo": "agent_timeout",
                "mensagem": str(exc),
            },
        }

    except ErroAgent as exc:
        return {
            "ok": False,
            "agent_disponivel": False,
            "ping": {},
            "firewall": {},
            "erro": {
                "codigo": "agent_erro",
                "mensagem": str(exc),
            },
        }