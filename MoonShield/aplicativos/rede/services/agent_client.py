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
# CLIENTE
# =============================================================================


class AgentClient:
    """
    Cliente IPC síncrono do MoonShield-Agent.

    Cada chamada abre uma conexão curta com o socket,
    envia uma requisição, recebe a resposta e fecha.
    """

    def __init__(
        self,
        *,
        socket_path: str | None = None,
        timeout: int | float | None = None,
    ):
        self.socket_path = (
            socket_path
            or getattr(
                settings,
                "MOONSHIELD_AGENT_SOCKET",
                AGENT_SOCKET_PADRAO,
            )
        )

        self.timeout = (
            timeout
            if timeout is not None
            else getattr(
                settings,
                "MOONSHIELD_AGENT_TIMEOUT",
                TIMEOUT_AGENT_PADRAO,
            )
        )

    # =========================================================================
    # REQUISIÇÃO
    # =========================================================================

    def requisitar(
        self,
        acao: str,
        dados: dict | None = None,
    ) -> dict:
        """
        Envia uma operação ao Agent.

        Retorna apenas o conteúdo de "dados" da resposta.

        Exemplo:

            client.requisitar(
                "network.inventory"
            )
        """

        acao = str(
            acao or ""
        ).strip()

        if not acao:
            raise ValueError(
                "Ação IPC não informada."
            )

        request_id = str(
            uuid.uuid4()
        )

        payload = {
            "versao": VERSAO_CONTRATO_REDE,
            "modulo": "rede",
            "acao": acao,
            "request_id": request_id,
            "dados": dados or {},
        }

        resposta = self._enviar(
            payload
        )

        self._validar_resposta(
            resposta,
            request_id=request_id,
        )

        if not resposta.get(
            "ok",
            False,
        ):
            erro = (
                resposta.get("erro")
                or resposta.get("mensagem")
                or "Operação recusada pelo Agent."
            )

            raise AgentOperacaoRecusadaErro(
                str(erro),
                detalhes=resposta.get(
                    "detalhes"
                ),
            )

        resultado = resposta.get(
            "dados",
            {},
        )

        if resultado is None:
            return {}

        if not isinstance(
            resultado,
            dict,
        ):
            raise AgentRespostaInvalidaErro(
                (
                    "O campo 'dados' da resposta do "
                    "Agent deve ser um objeto JSON."
                )
            )

        return resultado

    # =========================================================================
    # STATUS
    # =========================================================================

    def status(self) -> dict:
        """
        Consulta estado básico do Agent de Rede.
        """

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
    ) -> dict:
        """
        Envia JSON terminado por newline e aguarda uma resposta JSON.
        """

        if not hasattr(
            socket,
            "AF_UNIX",
        ):
            raise AgentIndisponivelErro(
                (
                    "Este sistema não possui suporte "
                    "a Unix Domain Socket."
                )
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
            float(self.timeout)
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
                (
                    "Timeout ao comunicar com "
                    "MoonShield-Agent."
                ),
                detalhes={
                    "socket": self.socket_path,
                    "timeout": self.timeout,
                },
            ) from exc

        except (
            FileNotFoundError,
            ConnectionRefusedError,
            ConnectionResetError,
            OSError,
        ) as exc:
            raise AgentIndisponivelErro(
                (
                    "MoonShield-Agent indisponível "
                    "para o módulo de Rede."
                ),
                detalhes={
                    "socket": self.socket_path,
                    "erro": str(exc),
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

        if not isinstance(
            resposta,
            dict,
        ):
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

        Limite atual:
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
                    (
                        "Resposta do Agent excedeu "
                        "o limite permitido."
                    )
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
                (
                    "Resposta do Agent não possui "
                    "o campo obrigatório 'ok'."
                )
            )

        resposta_id = resposta.get(
            "request_id"
        )

        # Durante desenvolvimento aceitamos Agent antigo
        # que ainda não devolva request_id.
        if (
            resposta_id
            and resposta_id != request_id
        ):
            raise AgentRespostaInvalidaErro(
                (
                    "request_id da resposta não corresponde "
                    "à requisição enviada."
                )
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
) -> dict:
    """
    Atalho para a instância padrão.
    """

    return client.requisitar(
        acao,
        dados,
    )


def agent_disponivel() -> bool:
    return client.disponivel()