"""
MoonShield Agent — Firewall / IPC Handlers
==========================================

Dispatcher oficial das ações firewall.* recebidas pelo servidor IPC único.

Fluxo:
    Django
      ↓
    /run/moonshield/agent.sock
      ↓
    firewall.ipc.servidor
      ↓
    firewall.ipc.handlers
      ↓
    firewall.nucleo.*
      ↓
    nftables / Linux

Responsabilidades:
- normalizar e validar ações do Firewall;
- validar payloads mínimos;
- encaminhar dados completos ao núcleo;
- preservar compatibilidade temporária com firewall.apply/firewall.rollback;
- expor o contrato firewall.change.* que será concluído no A9 Lote 4.

Este módulo NÃO executa nft, shell, systemctl ou alterações privilegiadas diretamente.
"""

from __future__ import annotations

import importlib
import logging
import uuid
from collections.abc import Callable
from typing import Any


logger = logging.getLogger(__name__)

VERSAO_PROTOCOLO = 1
MODULO_FIREWALL = "firewall"
MAX_REQUEST_ID = 128
MAX_STRING_ERRO = 4096
MAX_PROFUNDIDADE = 8

CHAVES_SENSIVEIS = {
    "password", "passwd", "senha", "secret", "segredo", "token",
    "api_key", "apikey", "authorization", "cookie", "csrf",
    "private_key", "chave_privada",
}


class ErroHandlerFirewall(RuntimeError):
    def __init__(
        self,
        mensagem: str,
        *,
        codigo: str = "erro_handler_firewall",
        detalhes: dict[str, Any] | None = None,
    ):
        super().__init__(mensagem)
        self.codigo = codigo
        self.detalhes = detalhes or {}


class RequisicaoFirewallInvalida(ErroHandlerFirewall):
    def __init__(self, mensagem: str, *, detalhes: dict[str, Any] | None = None):
        super().__init__(
            mensagem,
            codigo="requisicao_firewall_invalida",
            detalhes=detalhes,
        )


class AcaoFirewallInvalida(ErroHandlerFirewall):
    def __init__(self, acao: str):
        super().__init__(
            f"Ação de Firewall não suportada: {acao or '(vazia)'}",
            codigo="acao_firewall_invalida",
            detalhes={"acao": acao},
        )


class ImplementacaoFirewallIndisponivel(ErroHandlerFirewall):
    def __init__(self, modulo: str, funcoes: list[str] | tuple[str, ...]):
        super().__init__(
            (
                "Implementação do Firewall indisponível: "
                f"firewall.nucleo.{modulo} ({', '.join(funcoes)})"
            ),
            codigo="implementacao_firewall_indisponivel",
            detalhes={"modulo": modulo, "funcoes": list(funcoes)},
        )


ACOES_OFICIAIS = frozenset({
    "status",
    "interfaces",
    "rules",
    "emergency",
    "diagnostics",
    "install",
    "repair",
    "uninstall",
    "apply",       # legado temporário
    "rollback",    # legado temporário
    "block",
    "unblock",
    "change.apply",
    "change.confirm",
    "change.rollback",
    "change.status",
    "change.cancel",
})

ALIASES_ACAO = {
    "firewall.status": "status",
    "firewall.interfaces": "interfaces",
    "firewall.rules": "rules",
    "firewall.emergency": "emergency",
    "firewall.diagnostico": "diagnostics",
    "firewall.diagnostics": "diagnostics",
    "firewall.install": "install",
    "firewall.repair": "repair",
    "firewall.uninstall": "uninstall",
    "firewall.apply": "apply",
    "firewall.rollback": "rollback",
    "firewall.block": "block",
    "firewall.unblock": "unblock",
    "firewall.change.apply": "change.apply",
    "firewall.change.confirm": "change.confirm",
    "firewall.change.rollback": "change.rollback",
    "firewall.change.status": "change.status",
    "firewall.change.cancel": "change.cancel",
}


def _resolver_funcao(
    modulo: str,
    funcoes: str | list[str] | tuple[str, ...],
) -> Callable[..., Any]:
    nomes = [funcoes] if isinstance(funcoes, str) else list(funcoes)
    caminho = f"firewall.nucleo.{modulo}"

    try:
        modulo_python = importlib.import_module(caminho)
    except Exception as exc:
        logger.exception("Falha ao importar módulo %s", caminho)
        raise ImplementacaoFirewallIndisponivel(modulo, nomes) from exc

    for nome in nomes:
        alvo = getattr(modulo_python, nome, None)
        if callable(alvo):
            return alvo

    raise ImplementacaoFirewallIndisponivel(modulo, nomes)


def normalizar_acao(acao: Any) -> str:
    if not isinstance(acao, str):
        raise RequisicaoFirewallInvalida("Campo 'acao' precisa ser uma string.")

    valor = acao.strip().lower()
    if not valor:
        raise RequisicaoFirewallInvalida("Campo 'acao' não pode ficar vazio.")

    valor = ALIASES_ACAO.get(valor, valor)

    if valor not in ACOES_OFICIAIS:
        raise AcaoFirewallInvalida(valor)

    return valor


def normalizar_modulo(modulo: Any) -> str:
    if modulo is None:
        return MODULO_FIREWALL

    if not isinstance(modulo, str):
        raise RequisicaoFirewallInvalida("Campo 'modulo' precisa ser uma string.")

    valor = modulo.strip().lower()
    if valor in {"firewall", "fw"}:
        return MODULO_FIREWALL

    raise RequisicaoFirewallInvalida(
        "Requisição enviada para módulo incorreto.",
        detalhes={"modulo_recebido": valor, "modulo_esperado": MODULO_FIREWALL},
    )


def normalizar_versao(versao: Any) -> int:
    if versao is None:
        return VERSAO_PROTOCOLO

    try:
        valor = int(versao)
    except (TypeError, ValueError) as exc:
        raise RequisicaoFirewallInvalida(
            "Versão do protocolo inválida.",
            detalhes={"versao": versao},
        ) from exc

    if valor != VERSAO_PROTOCOLO:
        raise RequisicaoFirewallInvalida(
            "Versão de protocolo não suportada.",
            detalhes={"recebida": valor, "suportada": VERSAO_PROTOCOLO},
        )

    return valor


def normalizar_dados(dados: Any) -> dict[str, Any]:
    if dados is None:
        return {}
    if not isinstance(dados, dict):
        raise RequisicaoFirewallInvalida(
            "Campo 'dados' precisa ser um objeto JSON."
        )
    return dados


def normalizar_request_id(request_id: Any) -> str:
    if request_id is None:
        return str(uuid.uuid4())

    valor = str(request_id).strip()
    if not valor:
        return str(uuid.uuid4())

    if len(valor) > MAX_REQUEST_ID:
        raise RequisicaoFirewallInvalida(
            "request_id excede o tamanho máximo.",
            detalhes={"maximo": MAX_REQUEST_ID},
        )

    return valor


def _obter_id_alteracao(
    dados: dict[str, Any],
    *,
    obrigatorio: bool = True,
) -> str | None:
    valor = dados.get("alteracao_id") or dados.get("id") or dados.get("uuid")

    if valor is None or valor == "":
        if obrigatorio:
            raise RequisicaoFirewallInvalida(
                "Identificador da alteração não informado.",
                detalhes={"campo_esperado": "alteracao_id"},
            )
        return None

    valor = str(valor).strip()
    if not valor:
        if obrigatorio:
            raise RequisicaoFirewallInvalida(
                "Identificador da alteração está vazio."
            )
        return None

    if len(valor) > MAX_REQUEST_ID:
        raise RequisicaoFirewallInvalida(
            "Identificador da alteração excede o tamanho máximo."
        )

    return valor


def _acao_status(dados: dict[str, Any]) -> dict[str, Any]:
    executar = _resolver_funcao("status", ("obter_status",))
    return executar(dados)


def _acao_interfaces(dados: dict[str, Any]) -> dict[str, Any]:
    executar = _resolver_funcao("status", ("obter_interfaces", "listar_interfaces"))
    return executar(dados)


def _acao_rules(dados: dict[str, Any]) -> dict[str, Any]:
    executar = _resolver_funcao("status", ("obter_regras", "listar_regras"))
    return executar(dados)


def _acao_emergency(dados: dict[str, Any]) -> dict[str, Any]:
    executar = _resolver_funcao("status", ("obter_emergency", "listar_emergency"))
    return executar(dados)


def _acao_diagnostics(dados: dict[str, Any]) -> dict[str, Any]:
    executar = _resolver_funcao("status", ("diagnosticar", "executar_diagnostico"))
    return executar(dados)


def _acao_install(dados: dict[str, Any]) -> dict[str, Any]:
    executar = _resolver_funcao(
        "instalador",
        ("instalar", "instalar_firewall", "instalar_regras"),
    )
    return executar(dados)


def _acao_repair(dados: dict[str, Any]) -> dict[str, Any]:
    executar = _resolver_funcao("instalador", ("reparar", "reparar_firewall"))
    return executar(dados)


def _acao_uninstall(dados: dict[str, Any]) -> dict[str, Any]:
    if not _bool(dados.get("confirmar")):
        raise RequisicaoFirewallInvalida(
            "A desinstalação exige dados.confirmar=true."
        )

    executar = _resolver_funcao(
        "instalador",
        ("desinstalar", "remover", "remover_regras"),
    )
    return executar(dados)


def _normalizar_payload_regras(dados: dict[str, Any]) -> dict[str, Any]:
    payload = dict(dados)
    regras = payload.get("regras", payload.get("rules", []))
    iface_map = payload.get("iface_map") or {}

    if not isinstance(regras, list):
        raise RequisicaoFirewallInvalida("dados.regras deve ser uma lista.")

    if not isinstance(iface_map, dict):
        raise RequisicaoFirewallInvalida(
            "dados.iface_map deve ser um objeto."
        )

    config = payload.get("config")
    if config is not None and not isinstance(config, dict):
        raise RequisicaoFirewallInvalida(
            "dados.config deve ser um objeto."
        )

    payload["regras"] = regras
    payload["iface_map"] = iface_map
    return payload


def _acao_apply_legado(dados: dict[str, Any]) -> dict[str, Any]:
    """
    Compatibilidade temporária com o Django atual.

    NÃO é Safe Apply. O fluxo oficial novo é firewall.change.apply e será
    concluído no A9 Lote 4.
    """
    executar = _resolver_funcao("aplicador", ("aplicar", "aplicar_regras"))
    return executar(_normalizar_payload_regras(dados))


def _acao_rollback_legado(dados: dict[str, Any]) -> dict[str, Any]:
    executar = _resolver_funcao("rollback", ("restaurar_ultimo", "rollback"))
    return executar(dados)


def _acao_block(dados: dict[str, Any]) -> dict[str, Any]:
    if not str(dados.get("ip") or "").strip():
        raise RequisicaoFirewallInvalida("Campo dados.ip é obrigatório.")

    executar = _resolver_funcao("aplicador", ("bloquear_ip", "bloquear"))
    return executar(dados)


def _acao_unblock(dados: dict[str, Any]) -> dict[str, Any]:
    if not str(dados.get("ip") or "").strip():
        raise RequisicaoFirewallInvalida("Campo dados.ip é obrigatório.")

    executar = _resolver_funcao(
        "aplicador",
        ("liberar_ip", "desbloquear_ip", "liberar"),
    )
    return executar(dados)


def _acao_change_apply(dados: dict[str, Any]) -> dict[str, Any]:
    payload = _normalizar_payload_regras(dados)
    alteracao_id = _obter_id_alteracao(payload, obrigatorio=False)
    if alteracao_id:
        payload["alteracao_id"] = alteracao_id

    executar = _resolver_funcao("aplicador", ("aplicar_alteracao",))
    return executar(payload)


def _acao_change_confirm(dados: dict[str, Any]) -> dict[str, Any]:
    alteracao_id = _obter_id_alteracao(dados)
    executar = _resolver_funcao("rollback", ("confirmar_alteracao",))
    return executar(alteracao_id=alteracao_id)


def _acao_change_rollback(dados: dict[str, Any]) -> dict[str, Any]:
    alteracao_id = _obter_id_alteracao(dados)
    motivo = str(
        dados.get("motivo")
        or "Rollback solicitado pelo controlador MoonShield."
    ).strip()

    executar = _resolver_funcao("rollback", ("reverter_alteracao",))
    return executar(alteracao_id=alteracao_id, motivo=motivo)


def _acao_change_status(dados: dict[str, Any]) -> dict[str, Any]:
    alteracao_id = _obter_id_alteracao(dados)
    executar = _resolver_funcao("rollback", ("obter_status_alteracao",))
    return executar(alteracao_id=alteracao_id)


def _acao_change_cancel(dados: dict[str, Any]) -> dict[str, Any]:
    alteracao_id = _obter_id_alteracao(dados)
    executar = _resolver_funcao("rollback", ("cancelar_alteracao",))
    return executar(alteracao_id=alteracao_id)


_HANDLERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "status": _acao_status,
    "interfaces": _acao_interfaces,
    "rules": _acao_rules,
    "emergency": _acao_emergency,
    "diagnostics": _acao_diagnostics,
    "install": _acao_install,
    "repair": _acao_repair,
    "uninstall": _acao_uninstall,
    "apply": _acao_apply_legado,
    "rollback": _acao_rollback_legado,
    "block": _acao_block,
    "unblock": _acao_unblock,
    "change.apply": _acao_change_apply,
    "change.confirm": _acao_change_confirm,
    "change.rollback": _acao_change_rollback,
    "change.status": _acao_change_status,
    "change.cancel": _acao_change_cancel,
}


def _normalizar_resultado(resultado: Any, *, acao: str) -> dict[str, Any]:
    if resultado is None:
        return {}

    if not isinstance(resultado, dict):
        raise ErroHandlerFirewall(
            "O núcleo do Firewall retornou um formato inválido.",
            codigo="resposta_nucleo_firewall_invalida",
            detalhes={"acao": acao, "tipo": type(resultado).__name__},
        )

    if resultado.get("ok") is False:
        mensagem = (
            resultado.get("erro")
            or resultado.get("error")
            or resultado.get("mensagem")
            or "Operação recusada pelo núcleo do Firewall."
        )
        codigo = str(resultado.get("codigo") or "firewall_operacao_falhou")
        detalhes = {
            chave: valor
            for chave, valor in resultado.items()
            if chave not in {"ok", "erro", "error", "mensagem", "codigo"}
        }
        raise ErroHandlerFirewall(
            str(mensagem),
            codigo=codigo,
            detalhes=detalhes,
        )

    return resultado


def executar_acao_firewall(
    acao: str,
    dados: dict[str, Any] | None = None,
) -> dict[str, Any]:
    acao = normalizar_acao(acao)
    dados = normalizar_dados(dados)

    handler = _HANDLERS.get(acao)
    if handler is None:
        raise AcaoFirewallInvalida(acao)

    return _normalizar_resultado(handler(dados), acao=acao)


def _sanitizar(valor: Any, *, profundidade: int = 0) -> Any:
    if profundidade >= MAX_PROFUNDIDADE:
        return "[limite_de_profundidade]"

    if valor is None or isinstance(valor, (bool, int, float)):
        return valor

    if isinstance(valor, str):
        return (
            valor
            if len(valor) <= MAX_STRING_ERRO
            else valor[:MAX_STRING_ERRO] + "...[truncado]"
        )

    if isinstance(valor, dict):
        resultado = {}
        for chave, conteudo in valor.items():
            chave_texto = str(chave)
            if chave_texto.lower() in CHAVES_SENSIVEIS:
                resultado[chave_texto] = "[redacted]"
            else:
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

    return _sanitizar(str(valor), profundidade=profundidade + 1)


def _erro_de_excecao(exc: Exception) -> tuple[str, str, dict[str, Any]]:
    codigo = getattr(exc, "codigo", None) or "erro_interno_firewall"
    detalhes = getattr(exc, "detalhes", None)
    if not isinstance(detalhes, dict):
        detalhes = {}

    mensagem = str(exc).strip() or "Falha interna no módulo Firewall."
    return str(codigo), mensagem, detalhes


def tratar_requisicao_firewall(
    requisicao: dict[str, Any],
) -> dict[str, Any]:
    request_id = ""

    try:
        if not isinstance(requisicao, dict):
            raise RequisicaoFirewallInvalida(
                "Requisição IPC precisa ser um objeto JSON."
            )

        request_id = normalizar_request_id(requisicao.get("request_id"))
        normalizar_versao(requisicao.get("versao"))
        normalizar_modulo(requisicao.get("modulo"))
        acao = normalizar_acao(requisicao.get("acao"))
        dados = normalizar_dados(requisicao.get("dados"))

        resultado = executar_acao_firewall(acao, dados)

        return {
            "ok": True,
            "request_id": request_id,
            "dados": _sanitizar(resultado),
        }

    except Exception as exc:
        codigo, mensagem, detalhes = _erro_de_excecao(exc)
        return {
            "ok": False,
            "request_id": request_id or str(uuid.uuid4()),
            "erro": {
                "codigo": codigo,
                "mensagem": mensagem,
                "detalhes": _sanitizar(detalhes),
            },
        }


def handler_firewall(requisicao: dict[str, Any]) -> dict[str, Any]:
    return tratar_requisicao_firewall(requisicao)


def handle(requisicao: dict[str, Any]) -> dict[str, Any]:
    return tratar_requisicao_firewall(requisicao)


def dispatch(requisicao: dict[str, Any]) -> dict[str, Any]:
    return tratar_requisicao_firewall(requisicao)


def suporta_acao(acao: str) -> bool:
    try:
        normalizar_acao(acao)
        return True
    except ErroHandlerFirewall:
        return False


def listar_acoes() -> list[str]:
    return sorted(ACOES_OFICIAIS)


def _bool(valor: Any) -> bool:
    if isinstance(valor, bool):
        return valor
    if valor is None:
        return False
    return str(valor).strip().lower() in {
        "1", "true", "sim", "yes", "on", "ativo", "enabled",
    }


__all__ = [
    "VERSAO_PROTOCOLO",
    "MODULO_FIREWALL",
    "ACOES_OFICIAIS",
    "ErroHandlerFirewall",
    "RequisicaoFirewallInvalida",
    "AcaoFirewallInvalida",
    "ImplementacaoFirewallIndisponivel",
    "normalizar_acao",
    "executar_acao_firewall",
    "tratar_requisicao_firewall",
    "handler_firewall",
    "handle",
    "dispatch",
    "suporta_acao",
    "listar_acoes",
]
