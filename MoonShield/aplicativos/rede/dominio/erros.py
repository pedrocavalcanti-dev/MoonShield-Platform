"""
MoonShield Network
==================

Exceções específicas do domínio de Rede.

Ter erros próprios permite que:

    domínio
        ↓
    services
        ↓
    API

consigam transportar erros de forma previsível sem depender de textos
soltos ou exceções genéricas.
"""

from __future__ import annotations

from typing import Any


# =============================================================================
# BASE
# =============================================================================


class RedeErro(Exception):
    """
    Erro base do módulo de Rede.
    """

    codigo = "rede_erro"

    def __init__(
        self,
        mensagem: str,
        *,
        detalhes: Any = None,
    ):
        self.mensagem = str(
            mensagem or "Erro de rede."
        )

        self.detalhes = detalhes

        super().__init__(
            self.mensagem
        )

    def para_dict(self) -> dict:
        """
        Serialização padrão para APIs/logs.
        """

        resposta = {
            "erro": True,
            "codigo": self.codigo,
            "mensagem": self.mensagem,
        }

        if self.detalhes is not None:
            resposta["detalhes"] = self.detalhes

        return resposta


# =============================================================================
# VALIDAÇÃO
# =============================================================================


class ValidacaoRedeErro(RedeErro):
    codigo = "rede_validacao"


class ConfiguracaoRedeInvalidaErro(
    ValidacaoRedeErro
):
    codigo = "rede_configuracao_invalida"


class InterfaceInvalidaErro(
    ValidacaoRedeErro
):
    codigo = "rede_interface_invalida"


class InterfaceNaoEncontradaErro(
    RedeErro
):
    codigo = "rede_interface_nao_encontrada"


class ConflitoInterfaceErro(
    ValidacaoRedeErro
):
    codigo = "rede_conflito_interface"


class PapelInterfaceInvalidoErro(
    ValidacaoRedeErro
):
    codigo = "rede_papel_invalido"


class ModoIPv4InvalidoErro(
    ValidacaoRedeErro
):
    codigo = "rede_ipv4_modo_invalido"


class IPv4InvalidoErro(
    ValidacaoRedeErro
):
    codigo = "rede_ipv4_invalido"


class PrefixoIPv4InvalidoErro(
    ValidacaoRedeErro
):
    codigo = "rede_prefixo_invalido"


class CIDRInvalidoErro(
    ValidacaoRedeErro
):
    codigo = "rede_cidr_invalido"


class GatewayInvalidoErro(
    ValidacaoRedeErro
):
    codigo = "rede_gateway_invalido"


class MTUInvalidoErro(
    ValidacaoRedeErro
):
    codigo = "rede_mtu_invalido"


class MetricaInvalidaErro(
    ValidacaoRedeErro
):
    codigo = "rede_metrica_invalida"


class TopologiaInvalidaErro(
    ValidacaoRedeErro
):
    codigo = "rede_topologia_invalida"


# =============================================================================
# BACKEND
# =============================================================================


class BackendRedeErro(RedeErro):
    codigo = "rede_backend_erro"


class BackendNaoSuportadoErro(
    BackendRedeErro
):
    codigo = "rede_backend_nao_suportado"


class NetworkManagerErro(
    BackendRedeErro
):
    codigo = "rede_networkmanager_erro"


# =============================================================================
# AGENT
# =============================================================================


class AgentRedeErro(RedeErro):
    codigo = "rede_agent_erro"


class AgentIndisponivelErro(
    AgentRedeErro
):
    codigo = "rede_agent_indisponivel"


class AgentTimeoutErro(
    AgentRedeErro
):
    codigo = "rede_agent_timeout"


class AgentRespostaInvalidaErro(
    AgentRedeErro
):
    codigo = "rede_agent_resposta_invalida"


class AgentOperacaoRecusadaErro(
    AgentRedeErro
):
    codigo = "rede_agent_operacao_recusada"


# =============================================================================
# APLICAÇÃO
# =============================================================================


class AplicacaoRedeErro(RedeErro):
    codigo = "rede_aplicacao_falhou"


class RoteamentoErro(RedeErro):
    codigo = "rede_roteamento_erro"


class NatErro(RedeErro):
    codigo = "rede_nat_erro"


# =============================================================================
# SNAPSHOT / ROLLBACK
# =============================================================================


class SnapshotRedeErro(RedeErro):
    codigo = "rede_snapshot_erro"


class SnapshotNaoEncontradoErro(
    SnapshotRedeErro
):
    codigo = "rede_snapshot_nao_encontrado"


class RollbackRedeErro(RedeErro):
    codigo = "rede_rollback_erro"


# =============================================================================
# ALTERAÇÕES
# =============================================================================


class AlteracaoRedeErro(RedeErro):
    codigo = "rede_alteracao_erro"


class AlteracaoNaoEncontradaErro(
    AlteracaoRedeErro
):
    codigo = "rede_alteracao_nao_encontrada"


class AlteracaoExpiradaErro(
    AlteracaoRedeErro
):
    codigo = "rede_alteracao_expirada"


class AlteracaoEstadoInvalidoErro(
    AlteracaoRedeErro
):
    codigo = "rede_alteracao_estado_invalido"


# =============================================================================
# PERMISSÃO
# =============================================================================


class PermissaoRedeErro(RedeErro):
    codigo = "rede_permissao_negada"