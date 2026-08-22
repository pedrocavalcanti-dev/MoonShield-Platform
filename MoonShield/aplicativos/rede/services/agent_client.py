"""
MoonShield Network
==================

Cliente IPC do módulo de Rede.

Responsabilidade:

    Django
      ↓
    AgentClient
      ↓
    Unix Socket
      ↓
    MoonShield-Agent

Este arquivo é o ÚNICO ponto do app Django Rede que deve conhecer
o socket do Agent.

O Django NÃO executa:

    nmcli
    ip
    nft
    sysctl

diretamente.

Contrato IPC V1:

Requisição:

{
    "versao": 1,
    "modulo": "rede",
    "acao": "network.inventory",
    "request_id": "...",
    "dados": {}
}

Resposta:

{
    "ok": true,
    "request_id": "...",
    "dados": {}
}
"""

from __future__ import annotations

import json
import socket
import uuid
from typing import Any

from django.conf import settings

from rede.dominio.constantes import (
    AGENT_SOCKET_PADRAO,
    TIMEOUT_AGENT_PADRAO,
    VERSAO_CONTRATO_REDE,
)

from rede.dominio.erros import (
    AgentIndisponivelErro,
    AgentOperacaoRecusadaErro,
    AgentRespostaInvalidaErro,
    AgentTimeoutErro,
)


# =============================================================================
# TIMEOUTS
# =============================================================================

TIMEOUT_OPERACAO_MEDIA = 30.0
TIMEOUT_OPERACAO_LONGA = 180.0

ACOES_TIMEOUT_MEDIO = {
    "network.change.confirm",
    "network.change.cancel",
    "network.change.status",
}

ACOES_TIMEOUT_LONGO = {
    "network.change.apply",
    "network.change.rollback",
}


# =============================================================================
# CLIENTE
# =============================================================================

class AgentClient:
    """
    Cliente IPC síncrono do MoonShield-Agent.

    Cada chamada abre uma conexão curta com o socket,
    envia uma requisição, recebe a resposta e fecha.
    """

    def __init__(self, *, socket_path: str | None = None, timeout: int | float | None = None):
        self.socket_path = socket_path or getattr(
            settings,
            "MOONSHIELD_AGENT_SOCKET",
            AGENT_SOCKET_PADRAO,
        )

        self.timeout = timeout if timeout is not None else getattr(
            settings,
            "MOONSHIELD_AGENT_TIMEOUT",
            TIMEOUT_AGENT_PADRAO,
        )

    # =========================================================================
    # REQUISIÇÃO
    # =========================================================================

    def requisitar(
        self,
        acao: str,
        dados: dict | None = None,
        *,
        timeout: int | float | None = None,
    ) -> dict:
        """
        Envia uma operação ao Agent.

        O timeout pode ser informado manualmente. Quando omitido,
        operações longas como apply/rollback recebem timeout maior.
        """

        acao = str(acao or "").strip()

        if not acao:
            raise ValueError("Ação IPC não informada.")

        request_id = str(uuid.uuid4())

        payload = {
            "versao": VERSAO_CONTRATO_REDE,
            "modulo": "rede",
            "acao": acao,
            "request_id": request_id,
            "dados": dados or {},
        }

        timeout_resolvido = self._resolver_timeout(
            acao,
            timeout,
        )

        resposta = self._enviar(
            payload,
            timeout=timeout_resolvido,
        )

        self._validar_resposta(
            resposta,
            request_id=request_id,
        )

        if not resposta.get("ok", False):
            erro = resposta.get("erro")

            if isinstance(erro, dict):
                codigo = str(
                    erro.get("codigo")
                    or "agent_operacao_recusada"
                )

                mensagem = str(
                    erro.get("mensagem")
                    or erro.get("erro")
                    or "Operação recusada pelo Agent."
                )

                detalhes = erro.get("detalhes")

                if not isinstance(detalhes, dict):
                    detalhes = {}

                detalhes = {
                    "codigo": codigo,
                    **detalhes,
                }

            else:
                mensagem = str(
                    erro
                    or resposta.get("mensagem")
                    or "Operação recusada pelo Agent."
                )

                detalhes = resposta.get("detalhes")

                if not isinstance(detalhes, dict):
                    detalhes = {}

            raise AgentOperacaoRecusadaErro(
                mensagem,
                detalhes=detalhes,
            )

        resultado = resposta.get(
            "dados",
            {},
        )

        if resultado is None:
            return {}

        if not isinstance(resultado, dict):
            raise AgentRespostaInvalidaErro(
                "O campo 'dados' da resposta do Agent deve ser um objeto JSON."
            )

        return resultado

    # =========================================================================
    # TIMEOUT
    # =========================================================================

    def _resolver_timeout(
        self,
        acao: str,
        timeout: int | float | None,
    ) -> float:
        """
        Resolve timeout por tipo de operação.

        Operações de leitura:
            timeout padrão.

        Operações de confirmação/status de alteração:
            timeout médio.

        Apply/Rollback:
            timeout longo.
        """

        if timeout is not None:
            return self._validar_timeout(
                timeout
            )

        if acao in ACOES_TIMEOUT_LONGO:
            configurado = getattr(
                settings,
                "MOONSHIELD_AGENT_TIMEOUT_LONGO",
                TIMEOUT_OPERACAO_LONGA,
            )

            return self._validar_timeout(
                configurado
            )

        if acao in ACOES_TIMEOUT_MEDIO:
            configurado = getattr(
                settings,
                "MOONSHIELD_AGENT_TIMEOUT_MEDIO",
                TIMEOUT_OPERACAO_MEDIA,
            )

            return self._validar_timeout(
                configurado
            )

        return self._validar_timeout(
            self.timeout
        )

    @staticmethod
    def _validar_timeout(
        timeout: int | float,
    ) -> float:
        try:
            valor = float(
                timeout
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "Timeout do MoonShield-Agent é inválido."
            ) from exc

        if valor <= 0:
            raise ValueError(
                "Timeout do MoonShield-Agent deve ser maior que zero."
            )

        return valor

    # =========================================================================
    # STATUS
    # =========================================================================

    def status(self) -> dict:
        """Consulta estado básico do Agent de Rede."""

        return self.requisitar(
            "network.status"
        )

    def disponivel(self) -> bool:
        """
        Retorna True quando o Agent responde.

        Não propaga exceções.
        """

        try:
            self.status()
            return True
        except Exception:
            return False

    # =========================================================================
    # SOCKET
    # =========================================================================

    def _enviar(
        self,
        payload: dict,
        *,
        timeout: float,
    ) -> dict:
        """
        Envia JSON terminado por newline e aguarda uma resposta JSON.
        """

        if not hasattr(socket, "AF_UNIX"):
            raise AgentIndisponivelErro(
                "Este sistema não possui suporte a Unix Domain Socket."
            )

        mensagem = (
            json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            + "\n"
        ).encode(
            "utf-8"
        )

        cliente = socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        )

        cliente.settimeout(
            timeout
        )

        try:
            cliente.connect(
                self.socket_path
            )

            cliente.sendall(
                mensagem
            )

            bruto = self._receber_linha(
                cliente
            )

        except socket.timeout as exc:
            raise AgentTimeoutErro(
                "Timeout ao comunicar com MoonShield-Agent.",
                detalhes={
                    "socket": self.socket_path,
                    "timeout": timeout,
                    "acao": payload.get("acao"),
                },
            ) from exc

        except (
            FileNotFoundError,
            ConnectionRefusedError,
            ConnectionResetError,
            OSError,
        ) as exc:
            raise AgentIndisponivelErro(
                "MoonShield-Agent indisponível para o módulo de Rede.",
                detalhes={
                    "socket": self.socket_path,
                    "erro": str(exc),
                    "acao": payload.get("acao"),
                },
            ) from exc

        finally:
            try:
                cliente.close()
            except Exception:
                pass

        if not bruto:
            raise AgentRespostaInvalidaErro(
                "MoonShield-Agent retornou resposta vazia."
            )

        try:
            resposta = json.loads(
                bruto
            )

        except json.JSONDecodeError as exc:
            raise AgentRespostaInvalidaErro(
                "MoonShield-Agent retornou JSON inválido.",
                detalhes={
                    "resposta": bruto[:500],
                },
            ) from exc

        if not isinstance(resposta, dict):
            raise AgentRespostaInvalidaErro(
                "Resposta IPC deve ser um objeto JSON."
            )

        return resposta

    @staticmethod
    def _receber_linha(
        cliente: socket.socket,
        *,
        limite: int = 2 * 1024 * 1024,
    ) -> str:
        """
        Lê até newline ou EOF.

        Limite:
            2 MB por resposta IPC.
        """

        partes: list[bytes] = []
        total = 0

        while True:
            bloco = cliente.recv(
                65536
            )

            if not bloco:
                break

            partes.append(
                bloco
            )

            total += len(
                bloco
            )

            if total > limite:
                raise AgentRespostaInvalidaErro(
                    "Resposta do Agent excedeu o limite permitido."
                )

            if b"\n" in bloco:
                break

        dados = b"".join(
            partes
        )

        if b"\n" in dados:
            dados = dados.split(
                b"\n",
                1,
            )[0]

        return dados.decode(
            "utf-8",
            errors="replace",
        ).strip()

    # =========================================================================
    # VALIDAÇÃO
    # =========================================================================

    @staticmethod
    def _validar_resposta(
        resposta: dict,
        *,
        request_id: str,
    ) -> None:
        """
        Confirma estrutura mínima da resposta.
        """

        if "ok" not in resposta:
            raise AgentRespostaInvalidaErro(
                "Resposta do Agent não possui o campo obrigatório 'ok'."
            )

        resposta_id = (
            resposta.get("request_id")
            or resposta.get("id")
        )

        # Durante desenvolvimento ainda aceitamos resposta sem identificador.
        if resposta_id and resposta_id != request_id:
            raise AgentRespostaInvalidaErro(
                "request_id da resposta não corresponde à requisição enviada."
            )


# =============================================================================
# INSTÂNCIA PADRÃO
# =============================================================================

client = AgentClient()


# =============================================================================
# HELPERS
# =============================================================================

def requisitar_agent(
    acao: str,
    dados: dict | None = None,
    *,
    timeout: int | float | None = None,
) -> dict:
    """
    Atalho para a instância padrão.
    """

    return client.requisitar(
        acao,
        dados,
        timeout=timeout,
    )


def agent_disponivel() -> bool:
    return client.disponivel()