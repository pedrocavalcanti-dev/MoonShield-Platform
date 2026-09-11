"""
MoonShield Agent — Suricata / IPC Handlers
==========================================

Dispatcher oficial das ações suricata.* recebidas pelo
servidor IPC único do MoonShield-Agent.

Fluxo:

    Django
      ↓
    /run/moonshield/agent.sock
      ↓
    firewall.ipc.servidor
      ↓
    suricata.ipc.handlers
      ↓
    suricata.*
      ↓
    Suricata / systemd / Linux

Responsabilidades:
- validar e normalizar ações;
- validar payloads básicos;
- encaminhar operações ao núcleo Suricata;
- normalizar respostas;
- transformar falhas do núcleo em erros IPC controlados.

Este módulo NÃO:
- executa shell;
- executa systemctl diretamente;
- decide WAN/LAN/MGMT;
- descobre HOME_NET;
- escolhe interfaces de captura automaticamente;
- altera arquivos diretamente.

A topologia é responsabilidade do Control Plane / módulo Rede.
"""

from __future__ import annotations

import importlib
import logging
import uuid
from collections.abc import Callable
from typing import Any


logger = logging.getLogger(__name__)


VERSAO_PROTOCOLO = 1
MODULO_SURICATA = "suricata"

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


class ErroHandlerSuricata(RuntimeError):
    """Erro controlado do dispatcher IPC Suricata."""

    def __init__(
        self,
        mensagem: str,
        *,
        codigo: str = "erro_handler_suricata",
        detalhes: dict[str, Any] | None = None,
    ):
        super().__init__(mensagem)
        self.codigo = codigo
        self.detalhes = detalhes or {}


class RequisicaoSuricataInvalida(
    ErroHandlerSuricata
):
    def __init__(
        self,
        mensagem: str,
        *,
        detalhes: dict[str, Any] | None = None,
    ):
        super().__init__(
            mensagem,
            codigo="requisicao_suricata_invalida",
            detalhes=detalhes,
        )


class AcaoSuricataInvalida(
    ErroHandlerSuricata
):
    def __init__(self, acao: str):
        super().__init__(
            (
                "Ação Suricata não suportada: "
                f"{acao or '(vazia)'}"
            ),
            codigo="acao_suricata_invalida",
            detalhes={"acao": acao},
        )


class ImplementacaoSuricataIndisponivel(
    ErroHandlerSuricata
):
    def __init__(
        self,
        modulo: str,
        funcoes: list[str] | tuple[str, ...],
    ):
        super().__init__(
            (
                "Implementação Suricata indisponível: "
                f"suricata.{modulo} "
                f"({', '.join(funcoes)})"
            ),
            codigo="implementacao_suricata_indisponivel",
            detalhes={
                "modulo": modulo,
                "funcoes": list(funcoes),
            },
        )


ACOES_OFICIAIS = frozenset({
    "status",
    "diagnostics",
    "config.validate",
    "config.apply",
    "service.status",
    "service.start",
    "service.stop",
    "service.restart",
})


ALIASES_ACAO = {
    "suricata.status": "status",

    "suricata.diagnostics": "diagnostics",
    "suricata.diagnostico": "diagnostics",

    "suricata.config.validate": "config.validate",
    "suricata.config.apply": "config.apply",

    "suricata.service.status": "service.status",
    "suricata.service.start": "service.start",
    "suricata.service.stop": "service.stop",
    "suricata.service.restart": "service.restart",
}


def _resolver_funcao(
    modulo: str,
    funcoes: str | list[str] | tuple[str, ...],
) -> Callable[..., Any]:
    nomes = (
        [funcoes]
        if isinstance(funcoes, str)
        else list(funcoes)
    )

    caminho = f"suricata.{modulo}"

    try:
        modulo_python = importlib.import_module(
            caminho
        )
    except Exception as exc:
        logger.exception(
            "Falha ao importar módulo %s",
            caminho,
        )

        raise ImplementacaoSuricataIndisponivel(
            modulo,
            nomes,
        ) from exc

    for nome in nomes:
        alvo = getattr(
            modulo_python,
            nome,
            None,
        )

        if callable(alvo):
            return alvo

    raise ImplementacaoSuricataIndisponivel(
        modulo,
        nomes,
    )


def normalizar_acao(
    acao: Any,
) -> str:
    if not isinstance(acao, str):
        raise RequisicaoSuricataInvalida(
            "Campo 'acao' precisa ser uma string."
        )

    valor = acao.strip().lower()

    if not valor:
        raise RequisicaoSuricataInvalida(
            "Campo 'acao' não pode ficar vazio."
        )

    valor = ALIASES_ACAO.get(
        valor,
        valor,
    )

    if valor not in ACOES_OFICIAIS:
        raise AcaoSuricataInvalida(
            valor
        )

    return valor


def normalizar_modulo(
    modulo: Any,
) -> str:
    if modulo is None:
        return MODULO_SURICATA

    if not isinstance(modulo, str):
        raise RequisicaoSuricataInvalida(
            "Campo 'modulo' precisa ser uma string."
        )

    valor = modulo.strip().lower()

    if valor in {
        "suricata",
        "ids",
    }:
        return MODULO_SURICATA

    raise RequisicaoSuricataInvalida(
        "Requisição enviada para módulo incorreto.",
        detalhes={
            "modulo_recebido": valor,
            "modulo_esperado": MODULO_SURICATA,
        },
    )


def normalizar_versao(
    versao: Any,
) -> int:
    if versao is None:
        return VERSAO_PROTOCOLO

    try:
        valor = int(versao)
    except (TypeError, ValueError) as exc:
        raise RequisicaoSuricataInvalida(
            "Versão do protocolo inválida.",
            detalhes={"versao": versao},
        ) from exc

    if valor != VERSAO_PROTOCOLO:
        raise RequisicaoSuricataInvalida(
            "Versão de protocolo não suportada.",
            detalhes={
                "recebida": valor,
                "suportada": VERSAO_PROTOCOLO,
            },
        )

    return valor


def normalizar_dados(
    dados: Any,
) -> dict[str, Any]:
    if dados is None:
        return {}

    if not isinstance(dados, dict):
        raise RequisicaoSuricataInvalida(
            "Campo 'dados' precisa ser um objeto JSON."
        )

    return dados


def normalizar_request_id(
    request_id: Any,
) -> str:
    if request_id is None:
        return str(uuid.uuid4())

    valor = str(request_id).strip()

    if not valor:
        return str(uuid.uuid4())

    if len(valor) > MAX_REQUEST_ID:
        raise RequisicaoSuricataInvalida(
            "request_id excede o tamanho máximo.",
            detalhes={
                "maximo": MAX_REQUEST_ID,
            },
        )

    return valor


def _config_diagnostico(
    dados: dict[str, Any],
) -> dict[str, Any]:
    """
    Diagnóstico aceita tanto:

        dados = {"config": {...}}

    quanto:

        dados = {...config...}
    """

    config = dados.get("config")

    if config is None:
        return dict(dados)

    if not isinstance(config, dict):
        raise RequisicaoSuricataInvalida(
            "dados.config precisa ser um objeto JSON."
        )

    return dict(config)


def _acao_status(
    dados: dict[str, Any],
) -> dict[str, Any]:
    executar = _resolver_funcao(
        "status",
        (
            "obter_status",
            "status",
        ),
    )

    return executar(dados)


def _acao_diagnostics(
    dados: dict[str, Any],
) -> dict[str, Any]:
    executar = _resolver_funcao(
        "diagnostico",
        (
            "obter_diagnostico",
            "executar_diagnostico",
        ),
    )

    return executar(
        _config_diagnostico(dados)
    )


def _acao_config_validate(
    dados: dict[str, Any],
) -> dict[str, Any]:
    executar = _resolver_funcao(
        "aplicador",
        "validar",
    )

    return executar(dados)


def _acao_config_apply(
    dados: dict[str, Any],
) -> dict[str, Any]:
    executar = _resolver_funcao(
        "aplicador",
        "aplicar",
    )

    return executar(dados)


def _acao_service_status(
    dados: dict[str, Any],
) -> dict[str, Any]:
    executar = _resolver_funcao(
        "servico",
        "obter_status",
    )

    return executar(dados)


def _acao_service_start(
    dados: dict[str, Any],
) -> dict[str, Any]:
    executar = _resolver_funcao(
        "servico",
        "iniciar",
    )

    return executar(dados)


def _acao_service_stop(
    dados: dict[str, Any],
) -> dict[str, Any]:
    executar = _resolver_funcao(
        "servico",
        "parar",
    )

    return executar(dados)


def _acao_service_restart(
    dados: dict[str, Any],
) -> dict[str, Any]:
    executar = _resolver_funcao(
        "servico",
        "reiniciar",
    )

    return executar(dados)


_HANDLERS: dict[
    str,
    Callable[
        [dict[str, Any]],
        dict[str, Any],
    ],
] = {
    "status": _acao_status,
    "diagnostics": _acao_diagnostics,

    "config.validate": _acao_config_validate,
    "config.apply": _acao_config_apply,

    "service.status": _acao_service_status,
    "service.start": _acao_service_start,
    "service.stop": _acao_service_stop,
    "service.restart": _acao_service_restart,
}


def _normalizar_resultado(
    resultado: Any,
    *,
    acao: str,
) -> dict[str, Any]:
    if resultado is None:
        return {}

    if not isinstance(resultado, dict):
        raise ErroHandlerSuricata(
            "O núcleo Suricata retornou formato inválido.",
            codigo="resposta_nucleo_suricata_invalida",
            detalhes={
                "acao": acao,
                "tipo": type(resultado).__name__,
            },
        )

    if resultado.get("ok") is False:
        mensagem = (
            resultado.get("erro")
            or resultado.get("error")
            or resultado.get("mensagem")
            or "Operação recusada pelo núcleo Suricata."
        )

        codigo = str(
            resultado.get("codigo")
            or "suricata_operacao_falhou"
        )

        detalhes = {
            chave: valor
            for chave, valor in resultado.items()
            if chave not in {
                "ok",
                "erro",
                "error",
                "mensagem",
                "codigo",
            }
        }

        raise ErroHandlerSuricata(
            str(mensagem),
            codigo=codigo,
            detalhes=detalhes,
        )

    return resultado


def executar_acao_suricata(
    acao: str,
    dados: dict[str, Any] | None = None,
) -> dict[str, Any]:
    acao = normalizar_acao(
        acao
    )

    dados = normalizar_dados(
        dados
    )

    handler = _HANDLERS.get(
        acao
    )

    if handler is None:
        raise AcaoSuricataInvalida(
            acao
        )

    return _normalizar_resultado(
        handler(dados),
        acao=acao,
    )


def _sanitizar(
    valor: Any,
    *,
    profundidade: int = 0,
) -> Any:
    if profundidade >= MAX_PROFUNDIDADE:
        return "[limite_de_profundidade]"

    if valor is None or isinstance(
        valor,
        (
            bool,
            int,
            float,
        ),
    ):
        return valor

    if isinstance(valor, str):
        if len(valor) <= MAX_STRING_ERRO:
            return valor

        return (
            valor[:MAX_STRING_ERRO]
            + "...[truncado]"
        )

    if isinstance(valor, dict):
        resultado: dict[str, Any] = {}

        for chave, conteudo in valor.items():
            chave_texto = str(chave)

            if (
                chave_texto.lower()
                in CHAVES_SENSIVEIS
            ):
                resultado[chave_texto] = (
                    "[redacted]"
                )
            else:
                resultado[chave_texto] = (
                    _sanitizar(
                        conteudo,
                        profundidade=(
                            profundidade + 1
                        ),
                    )
                )

        return resultado

    if isinstance(
        valor,
        (
            list,
            tuple,
            set,
        ),
    ):
        return [
            _sanitizar(
                item,
                profundidade=profundidade + 1,
            )
            for item in valor
        ]

    return _sanitizar(
        str(valor),
        profundidade=profundidade + 1,
    )


def _erro_de_excecao(
    exc: Exception,
) -> tuple[
    str,
    str,
    dict[str, Any],
]:
    codigo = (
        getattr(
            exc,
            "codigo",
            None,
        )
        or "erro_interno_suricata"
    )

    detalhes = getattr(
        exc,
        "detalhes",
        None,
    )

    if not isinstance(
        detalhes,
        dict,
    ):
        detalhes = {}

    mensagem = (
        str(exc).strip()
        or "Falha interna no módulo Suricata."
    )

    return (
        str(codigo),
        mensagem,
        detalhes,
    )


def tratar_requisicao_suricata(
    requisicao: dict[str, Any],
) -> dict[str, Any]:
    request_id = ""

    try:
        if not isinstance(
            requisicao,
            dict,
        ):
            raise RequisicaoSuricataInvalida(
                (
                    "Requisição IPC precisa "
                    "ser um objeto JSON."
                )
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

        resultado = executar_acao_suricata(
            acao,
            dados,
        )

        return {
            "ok": True,
            "request_id": request_id,
            "dados": _sanitizar(
                resultado
            ),
        }

    except Exception as exc:
        (
            codigo,
            mensagem,
            detalhes,
        ) = _erro_de_excecao(
            exc
        )

        return {
            "ok": False,
            "request_id": (
                request_id
                or str(uuid.uuid4())
            ),
            "erro": {
                "codigo": codigo,
                "mensagem": mensagem,
                "detalhes": _sanitizar(
                    detalhes
                ),
            },
        }


def handler_suricata(
    requisicao: dict[str, Any],
) -> dict[str, Any]:
    return tratar_requisicao_suricata(
        requisicao
    )


def handle(
    requisicao: dict[str, Any],
) -> dict[str, Any]:
    return tratar_requisicao_suricata(
        requisicao
    )


def dispatch(
    requisicao: dict[str, Any],
) -> dict[str, Any]:
    return tratar_requisicao_suricata(
        requisicao
    )


def suporta_acao(
    acao: str,
) -> bool:
    try:
        normalizar_acao(
            acao
        )
        return True
    except ErroHandlerSuricata:
        return False


def listar_acoes() -> list[str]:
    return sorted(
        ACOES_OFICIAIS
    )


__all__ = [
    "VERSAO_PROTOCOLO",
    "MODULO_SURICATA",
    "ACOES_OFICIAIS",
    "ErroHandlerSuricata",
    "RequisicaoSuricataInvalida",
    "AcaoSuricataInvalida",
    "ImplementacaoSuricataIndisponivel",
    "normalizar_acao",
    "executar_acao_suricata",
    "tratar_requisicao_suricata",
    "handler_suricata",
    "handle",
    "dispatch",
    "suporta_acao",
    "listar_acoes",
]