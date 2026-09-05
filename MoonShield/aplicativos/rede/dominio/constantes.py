"""
MoonShield Network
==================

Constantes centrais do domínio de Rede.

Nada deste módulo deve executar comandos ou acessar banco.
"""

from __future__ import annotations

from .tipos import (
    BackendRede,
    ModoIPv4,
    PapelInterface,
)


# =============================================================================
# IDENTIDADE
# =============================================================================


MODULO_REDE = "rede"

VERSAO_CONTRATO_REDE = 1


# =============================================================================
# IPv4
# =============================================================================


IPV4_PREFIXO_MINIMO = 0
IPV4_PREFIXO_MAXIMO = 32


# =============================================================================
# MTU
# =============================================================================


MTU_PADRAO = 1500

MTU_MINIMO = 576

MTU_MAXIMO = 65535


# =============================================================================
# MÉTRICA
# =============================================================================


METRICA_PADRAO = 100

METRICA_MINIMA = 0

METRICA_MAXIMA = 4_294_967_295


# =============================================================================
# ROLLBACK
# =============================================================================


ROLLBACK_AUTOMATICO_PADRAO = True

TEMPO_CONFIRMACAO_PADRAO = 60

TEMPO_CONFIRMACAO_MINIMO = 15

TEMPO_CONFIRMACAO_MAXIMO = 600


# =============================================================================
# INTERFACES
# =============================================================================


NOME_INTERFACE_MAXIMO = 64

DESCRICAO_INTERFACE_MAXIMA = 120


# Prefixos que jamais devem aparecer como interface física gerenciável
# normal pelo painel.
#
# "lo" é excluída explicitamente.
#
INTERFACES_IGNORADAS = {
    "lo",
}


# =============================================================================
# PAPÉIS
# =============================================================================


PAPEIS_INTERFACE_VALIDOS = {
    papel.value
    for papel in PapelInterface
}


PAPEIS_PRINCIPAIS = {
    PapelInterface.WAN.value,
    PapelInterface.LAN.value,
}


# Papéis que participam da topologia administrada pelo MoonShield. Interfaces
# apenas detectadas permanecem no inventário, mas não compõem políticas.
PAPEIS_GERENCIADOS = {
    papel.value
    for papel in PapelInterface
    if papel != PapelInterface.NAO_ATRIBUIDA
}


# Na V1, somente LANs administradas formam as redes internas e o HOME_NET.
PAPEIS_HOME_NET = {
    PapelInterface.LAN.value,
}


PAPEIS_COM_ROTA_DEFAULT = {
    PapelInterface.WAN.value,
}


PAPEIS_COM_ACESSO_GERENCIAMENTO = {
    PapelInterface.LAN.value,
    PapelInterface.MGMT.value,
    PapelInterface.CUSTOM.value,
}


# WAN pode ter acesso administrativo durante instalação/LAB,
# mas isso não será obrigatório nem recomendado em produção.
#
PAPEIS_GERENCIAMENTO_RECOMENDADO = {
    PapelInterface.LAN.value,
    PapelInterface.MGMT.value,
}


# =============================================================================
# MODOS IPv4
# =============================================================================


MODOS_IPV4_VALIDOS = {
    modo.value
    for modo in ModoIPv4
}


# =============================================================================
# BACKENDS
# =============================================================================


BACKENDS_REDE_VALIDOS = {
    backend.value
    for backend in BackendRede
}


BACKEND_REDE_V1 = (
    BackendRede.NETWORK_MANAGER.value
)


# =============================================================================
# NETWORKMANAGER
# =============================================================================


NETWORKMANAGER_SERVICE = "NetworkManager"

NETWORKMANAGER_EXECUTAVEL = "nmcli"


# =============================================================================
# IPC
# =============================================================================


# Caminho esperado na instalação Linux.
#
# O Django não abrirá isso diretamente a partir do domínio.
# A constante existe apenas como padrão da plataforma.
#
AGENT_SOCKET_PADRAO = (
    "/run/moonshield/agent.sock"
)


# =============================================================================
# NAT
# =============================================================================


NFT_TABLE_NAT = "moonshield_nat"

NFT_CHAIN_POSTROUTING = "postrouting"


# IMPORTANTE:
#
# O módulo de Rede administra NAT.
#
# Políticas ALLOW / DENY / FORWARD de segurança continuam pertencendo
# ao módulo Firewall.
#
# Portanto não criamos ms_forward/netforge aqui.


# =============================================================================
# DIAGNÓSTICO
# =============================================================================


TIMEOUT_DIAGNOSTICO_PADRAO = 5

TIMEOUT_AGENT_PADRAO = 10


# Endereço utilizado apenas como teste de conectividade IP.
# O Agent poderá substituir isso/configurar posteriormente.
#
IP_TESTE_INTERNET_PADRAO = "1.1.1.1"


# =============================================================================
# LIMITES DE HISTÓRICO
# =============================================================================


LIMITE_EVENTOS_API_PADRAO = 100

LIMITE_ALTERACOES_API_PADRAO = 100
