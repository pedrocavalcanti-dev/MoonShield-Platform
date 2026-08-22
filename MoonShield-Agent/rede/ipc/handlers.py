"""
MoonShield Agent — Rede / IPC Handlers
======================================

Dispatcher IPC do módulo de Rede.

Fluxo:
    Django
      ↓
    /run/moonshield/agent.sock
      ↓
    servidor IPC principal
      ↓
    rede.ipc.handlers
      ↓
    rede.nucleo.*
      ↓
    backends / Linux

Este módulo:
- valida o envelope IPC;
- normaliza ações;
- preserva request_id;
- chama o núcleo de Rede;
- padroniza respostas e erros.

Este módulo NÃO executa diretamente:
- nmcli;
- ip;
- nft;
- alterações de arquivos do sistema;
- rollback técnico.
"""

from __future__ import annotations

import importlib
import logging
import uuid
from collections.abc import Callable
from typing import Any


logger = logging.getLogger(__name__)

VERSAO_PROTOCOLO = 1
MODULO_REDE = "rede"
MAX_REQUEST_ID = 128
MAX_STRING_ERRO = 4096
MAX_PROFUNDIDADE = 8

CHAVES_SENSIVEIS = {
    "password",
    "passwd",
    "senha",
    "secret",
    "segredo",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "csrf",
    "private_key",
    "chave_privada",
}


# =============================================================================
# EXCEÇÕES
# =============================================================================

class ErroHandlerRede(RuntimeError):
    """Erro controlado do dispatcher IPC de Rede."""

    def __init__(self, mensagem: str, *, codigo: str = "erro_handler_rede", detalhes: dict[str, Any] | None = None):
        super().__init__(mensagem)
        self.codigo = codigo
        self.detalhes = detalhes or {}


class RequisicaoRedeInvalida(ErroHandlerRede):
    def __init__(self, mensagem: str, *, detalhes: dict[str, Any] | None = None):
        super().__init__(mensagem, codigo="requisicao_rede_invalida", detalhes=detalhes)


class AcaoRedeInvalida(ErroHandlerRede):
    def __init__(self, acao: str):
        super().__init__(
            f"Ação de Rede não suportada: {acao or '(vazia)'}",
            codigo="acao_rede_invalida",
            detalhes={"acao": acao},
        )


class ImplementacaoRedeIndisponivel(ErroHandlerRede):
    def __init__(self, modulo: str, funcao: str):
        super().__init__(
            f"Implementação de Rede indisponível: rede.nucleo.{modulo}.{funcao}",
            codigo="implementacao_rede_indisponivel",
            detalhes={"modulo": modulo, "funcao": funcao},
        )


# =============================================================================
# AÇÕES
# =============================================================================

ACOES_OFICIAIS = frozenset({
    "status",
    "inventory",
    "diagnostics",
    "routing.status",
    "nat.status",
    "change.apply",
    "change.confirm",
    "change.rollback",
    "change.status",
    "change.cancel",
})

ALIASES_ACAO = {
    # Status
    "network.status": "status",
    "rede.status": "status",

    # Inventário
    "inventario": "inventory",
    "inventário": "inventory",
    "inventory.status": "inventory",
    "network.inventory": "inventory",
    "rede.inventory": "inventory",
    "rede.inventario": "inventory",

    # Diagnóstico
    "diagnostico": "diagnostics",
    "diagnóstico": "diagnostics",
    "network.diagnostics": "diagnostics",
    "rede.diagnostics": "diagnostics",
    "rede.diagnostico": "diagnostics",

    # Roteamento
    "routing": "routing.status",
    "roteamento": "routing.status",
    "network.routing.status": "routing.status",
    "rede.routing.status": "routing.status",
    "rede.roteamento.status": "routing.status",

    # NAT
    "nat": "nat.status",
    "network.nat.status": "nat.status",
    "rede.nat.status": "nat.status",

    # Safe Apply
    "network.change.apply": "change.apply",
    "rede.change.apply": "change.apply",
    "alteracao.aplicar": "change.apply",

    "network.change.confirm": "change.confirm",
    "rede.change.confirm": "change.confirm",
    "alteracao.confirmar": "change.confirm",

    "network.change.rollback": "change.rollback",
    "rede.change.rollback": "change.rollback",
    "alteracao.rollback": "change.rollback",
    "alteracao.reverter": "change.rollback",

    "network.change.status": "change.status",
    "rede.change.status": "change.status",
    "alteracao.status": "change.status",

    "network.change.cancel": "change.cancel",
    "rede.change.cancel": "change.cancel",
    "alteracao.cancelar": "change.cancel",
}


# =============================================================================
# IMPORT DINÂMICO DO NÚCLEO
# =============================================================================

def _resolver_funcao(modulo: str, funcao: str) -> Callable[..., Any]:
    caminho = f"rede.nucleo.{modulo}"

    try:
        modulo_python = importlib.import_module(caminho)
    except Exception as exc:
        logger.exception("Falha ao importar módulo %s", caminho)
        raise ImplementacaoRedeIndisponivel(modulo, funcao) from exc

    alvo = getattr(modulo_python, funcao, None)

    if not callable(alvo):
        raise ImplementacaoRedeIndisponivel(modulo, funcao)

    return alvo


# =============================================================================
# NORMALIZAÇÃO DO ENVELOPE
# =============================================================================

def normalizar_acao(acao: Any) -> str:
    if not isinstance(acao, str):
        raise RequisicaoRedeInvalida("Campo 'acao' precisa ser uma string.")

    valor = acao.strip().lower()

    if not valor:
        raise RequisicaoRedeInvalida("Campo 'acao' não pode ficar vazio.")

    valor = ALIASES_ACAO.get(valor, valor)

    if valor not in ACOES_OFICIAIS:
        raise AcaoRedeInvalida(valor)

    return valor


def normalizar_modulo(modulo: Any) -> str:
    if modulo is None:
        return MODULO_REDE

    if not isinstance(modulo, str):
        raise RequisicaoRedeInvalida("Campo 'modulo' precisa ser uma string.")

    valor = modulo.strip().lower()

    if valor in {"rede", "network", "networking"}:
        return MODULO_REDE

    raise RequisicaoRedeInvalida(
        "Requisição enviada para módulo incorreto.",
        detalhes={"modulo_recebido": valor, "modulo_esperado": MODULO_REDE},
    )


def normalizar_versao(versao: Any) -> int:
    if versao is None:
        return VERSAO_PROTOCOLO

    try:
        valor = int(versao)
    except (TypeError, ValueError) as exc:
        raise RequisicaoRedeInvalida(
            "Versão do protocolo inválida.",
            detalhes={"versao": versao},
        ) from exc

    if valor != VERSAO_PROTOCOLO:
        raise RequisicaoRedeInvalida(
            "Versão de protocolo não suportada.",
            detalhes={"recebida": valor, "suportada": VERSAO_PROTOCOLO},
        )

    return valor


def normalizar_dados(dados: Any) -> dict[str, Any]:
    if dados is None:
        return {}

    if not isinstance(dados, dict):
        raise RequisicaoRedeInvalida("Campo 'dados' precisa ser um objeto JSON.")

    return dados


def normalizar_request_id(request_id: Any) -> str:
    if request_id is None:
        return str(uuid.uuid4())

    valor = str(request_id).strip()

    if not valor:
        return str(uuid.uuid4())

    if len(valor) > MAX_REQUEST_ID:
        raise RequisicaoRedeInvalida(
            "request_id excede o tamanho máximo.",
            detalhes={"maximo": MAX_REQUEST_ID},
        )

    return valor


# =============================================================================
# ALTERAÇÃO
# =============================================================================

def _obter_id_alteracao(dados: dict[str, Any], *, obrigatorio: bool = True) -> str | None:
    valor = dados.get("alteracao_id") or dados.get("id") or dados.get("uuid")

    if valor is None or valor == "":
        if obrigatorio:
            raise RequisicaoRedeInvalida(
                "Identificador da alteração não informado.",
                detalhes={"campo_esperado": "alteracao_id"},
            )
        return None

    valor = str(valor).strip()

    if not valor:
        if obrigatorio:
            raise RequisicaoRedeInvalida("Identificador da alteração está vazio.")
        return None

    if len(valor) > MAX_REQUEST_ID:
        raise RequisicaoRedeInvalida("Identificador da alteração excede o tamanho máximo.")

    return valor


# =============================================================================
# STATUS
# =============================================================================

def _acao_status(dados: dict[str, Any]) -> dict[str, Any]:
    executar = _resolver_funcao("inventario", "obter_status_rede")
    return executar()


# =============================================================================
# INVENTÁRIO
# =============================================================================

def _acao_inventory(dados: dict[str, Any]) -> dict[str, Any]:
    executar = _resolver_funcao("inventario", "obter_inventario")

    incluir_loopback = dados.get("incluir_loopback", False)

    if isinstance(incluir_loopback, str):
        incluir_loopback = incluir_loopback.strip().lower() in {"1", "true", "yes", "sim", "on"}
    else:
        incluir_loopback = bool(incluir_loopback)

    return executar(incluir_loopback=incluir_loopback)


# =============================================================================
# DIAGNÓSTICO
# =============================================================================

def _acao_diagnostics(dados: dict[str, Any]) -> dict[str, Any]:
    executar = _resolver_funcao("diagnostico", "executar_diagnostico")
    return executar(opcoes=dados)


# =============================================================================
# ROTEAMENTO
# =============================================================================

def _acao_routing_status(dados: dict[str, Any]) -> dict[str, Any]:
    executar = _resolver_funcao("roteamento", "obter_status_roteamento")
    return executar()


# =============================================================================
# NAT
# =============================================================================

def _acao_nat_status(dados: dict[str, Any]) -> dict[str, Any]:
    executar = _resolver_funcao("nat", "obter_status_nat")
    return executar()


# =============================================================================
# SAFE APPLY — APPLY
# =============================================================================

def _acao_change_apply(dados: dict[str, Any]) -> dict[str, Any]:
    executar = _resolver_funcao("aplicador", "aplicar_alteracao")

    payload = dict(dados)
    alteracao_id = _obter_id_alteracao(payload, obrigatorio=False)

    if alteracao_id:
        payload["alteracao_id"] = alteracao_id

    return executar(payload)


# =============================================================================
# SAFE APPLY — CONFIRM
# =============================================================================

def _acao_change_confirm(dados: dict[str, Any]) -> dict[str, Any]:
    alteracao_id = _obter_id_alteracao(dados)
    executar = _resolver_funcao("rollback", "confirmar_alteracao")

    return executar(alteracao_id=alteracao_id)


# =============================================================================
# SAFE APPLY — ROLLBACK
# =============================================================================

def _acao_change_rollback(dados: dict[str, Any]) -> dict[str, Any]:
    alteracao_id = _obter_id_alteracao(dados)

    motivo = str(
        dados.get("motivo")
        or "Rollback solicitado pelo controlador MoonShield."
    ).strip()

    executar = _resolver_funcao("rollback", "reverter_alteracao")

    return executar(
        alteracao_id=alteracao_id,
        motivo=motivo,
    )


# =============================================================================
# SAFE APPLY — STATUS
# =============================================================================

def _acao_change_status(dados: dict[str, Any]) -> dict[str, Any]:
    alteracao_id = _obter_id_alteracao(dados)
    executar = _resolver_funcao("rollback", "obter_status_alteracao")

    return executar(alteracao_id=alteracao_id)


# =============================================================================
# SAFE APPLY — CANCEL
# =============================================================================

def _acao_change_cancel(dados: dict[str, Any]) -> dict[str, Any]:
    alteracao_id = _obter_id_alteracao(dados)
    executar = _resolver_funcao("rollback", "cancelar_alteracao")

    return executar(alteracao_id=alteracao_id)


# =============================================================================
# DISPATCH TABLE
# =============================================================================

_HANDLERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "status": _acao_status,
    "inventory": _acao_inventory,
    "diagnostics": _acao_diagnostics,
    "routing.status": _acao_routing_status,
    "nat.status": _acao_nat_status,
    "change.apply": _acao_change_apply,
    "change.confirm": _acao_change_confirm,
    "change.rollback": _acao_change_rollback,
    "change.status": _acao_change_status,
    "change.cancel": _acao_change_cancel,
}


# =============================================================================
# EXECUÇÃO
# =============================================================================

def executar_acao_rede(acao: str, dados: dict[str, Any] | None = None) -> dict[str, Any]:
    acao = normalizar_acao(acao)
    dados = normalizar_dados(dados)

    handler = _HANDLERS.get(acao)

    if handler is None:
        raise AcaoRedeInvalida(acao)

    resultado = handler(dados)

    if resultado is None:
        return {}

    if not isinstance(resultado, dict):
        raise ErroHandlerRede(
            "O núcleo de Rede retornou um formato inválido.",
            codigo="resposta_nucleo_invalida",
            detalhes={
                "acao": acao,
                "tipo": type(resultado).__name__,
            },
        )

    return resultado


# =============================================================================
# SANITIZAÇÃO
# =============================================================================

def _sanitizar(valor: Any, *, profundidade: int = 0) -> Any:
    if profundidade >= MAX_PROFUNDIDADE:
        return "[limite_de_profundidade]"

    if valor is None or isinstance(valor, (bool, int, float)):
        return valor

    if isinstance(valor, str):
        if len(valor) <= MAX_STRING_ERRO:
            return valor
        return valor[:MAX_STRING_ERRO] + "...[truncado]"

    if isinstance(valor, dict):
        resultado = {}

        for chave, conteudo in valor.items():
            chave_texto = str(chave)

            if chave_texto.lower() in CHAVES_SENSIVEIS:
                resultado[chave_texto] = "[redacted]"
                continue

            resultado[chave_texto] = _sanitizar(
                conteudo,
                profundidade=profundidade + 1,
            )

        return resultado

    if isinstance(valor, (list, tuple, set)):
        return [
            _sanitizar(item, profundidade=profundidade + 1)
            for item in valor
        ]

    return _sanitizar(
        str(valor),
        profundidade=profundidade + 1,
    )


# =============================================================================
# RESPOSTAS
# =============================================================================

def _resposta_sucesso(request_id: str, dados: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": True,
        "request_id": request_id,
        "dados": _sanitizar(dados),
    }


def _resposta_erro(
    request_id: str,
    *,
    codigo: str,
    mensagem: str,
    detalhes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "ok": False,
        "request_id": request_id,
        "erro": {
            "codigo": codigo,
            "mensagem": mensagem,
            "detalhes": _sanitizar(detalhes or {}),
        },
    }


# =============================================================================
# EXCEÇÕES → IPC
# =============================================================================

def _erro_de_excecao(exc: Exception) -> tuple[str, str, dict[str, Any]]:
    codigo = getattr(exc, "codigo", None) or "erro_interno_rede"
    detalhes = getattr(exc, "detalhes", None)

    if not isinstance(detalhes, dict):
        detalhes = {}

    mensagem = str(exc).strip() or "Falha interna no módulo de Rede."

    return str(codigo), mensagem, detalhes


# =============================================================================
# HANDLER PRINCIPAL
# =============================================================================

def tratar_requisicao_rede(requisicao: dict[str, Any]) -> dict[str, Any]:
    """
    Entrada principal do módulo de Rede.

    Esta função nunca deve deixar exceções escaparem para o servidor IPC.
    """

    request_id = ""

    try:
        if not isinstance(requisicao, dict):
            raise RequisicaoRedeInvalida(
                "Requisição IPC precisa ser um objeto JSON."
            )

        request_id = normalizar_request_id(
            requisicao.get("request_id")
        )

        normalizar_versao(
            requisicao.get("versao")
        )

        normalizar_modulo(
            requisicao.get("modulo")
        )

        acao = normalizar_acao(
            requisicao.get("acao")
        )

        dados = normalizar_dados(
            requisicao.get("dados")
        )

        logger.info(
            "Rede IPC request_id=%s acao=%s",
            request_id,
            acao,
        )

        resultado = executar_acao_rede(
            acao,
            dados,
        )

        logger.info(
            "Rede IPC concluído request_id=%s acao=%s",
            request_id,
            acao,
        )

        return _resposta_sucesso(
            request_id,
            resultado,
        )

    except ErroHandlerRede as exc:
        codigo, mensagem, detalhes = _erro_de_excecao(exc)

        logger.warning(
            "Rede IPC recusado request_id=%s codigo=%s mensagem=%s",
            request_id or "-",
            codigo,
            mensagem,
        )

        return _resposta_erro(
            request_id or str(uuid.uuid4()),
            codigo=codigo,
            mensagem=mensagem,
            detalhes=detalhes,
        )

    except Exception as exc:
        codigo, mensagem, detalhes = _erro_de_excecao(exc)

        logger.exception(
            "Falha interna Rede IPC request_id=%s codigo=%s",
            request_id or "-",
            codigo,
        )

        return _resposta_erro(
            request_id or str(uuid.uuid4()),
            codigo=codigo,
            mensagem=mensagem,
            detalhes=detalhes,
        )


# =============================================================================
# ALIASES PARA O SERVIDOR IPC
# =============================================================================

def handler_rede(requisicao: dict[str, Any]) -> dict[str, Any]:
    return tratar_requisicao_rede(requisicao)


def handle(requisicao: dict[str, Any]) -> dict[str, Any]:
    return tratar_requisicao_rede(requisicao)


def dispatch(requisicao: dict[str, Any]) -> dict[str, Any]:
    return tratar_requisicao_rede(requisicao)


# =============================================================================
# UTILIDADES
# =============================================================================

def suporta_acao(acao: str) -> bool:
    try:
        normalizar_acao(acao)
        return True
    except ErroHandlerRede:
        return False


def listar_acoes() -> list[str]:
    return sorted(ACOES_OFICIAIS)


# =============================================================================
# EXPORT
# =============================================================================

__all__ = [
    "VERSAO_PROTOCOLO",
    "MODULO_REDE",
    "ACOES_OFICIAIS",
    "ErroHandlerRede",
    "RequisicaoRedeInvalida",
    "AcaoRedeInvalida",
    "ImplementacaoRedeIndisponivel",
    "normalizar_acao",
    "executar_acao_rede",
    "tratar_requisicao_rede",
    "handler_rede",
    "handle",
    "dispatch",
    "suporta_acao",
    "listar_acoes",
]