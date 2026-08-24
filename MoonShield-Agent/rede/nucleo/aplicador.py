"""
MoonShield Agent — Rede / Aplicador
===================================

Orquestrador de alterações de Rede.

Ordem de segurança:

    validar
      ↓
    snapshot
      ↓
    ARMAR ROLLBACK
      ↓
    aplicar
      ↓
    verificar
      ↓
    aguardar confirmação

Em qualquer falha após o rollback ser armado, o snapshot é restaurado.
"""

from __future__ import annotations

import logging
import threading
import uuid
from typing import Any

from .configuracao import obter_backend
from .nat import aplicar_regras_nat, obter_status_nat
from .rollback import (
    armar_rollback,
    marcar_aguardando_confirmacao,
    obter_alteracao_ativa,
    registrar_resultado_aplicacao,
    reverter_alteracao,
)
from .roteamento import configurar_rotas, definir_ipv4_forward, obter_ipv4_forward
from .snapshot import criar_snapshot
from .validacao import validar_alteracao


logger = logging.getLogger(__name__)

_apply_lock = threading.RLock()


class AplicacaoRedeErro(RuntimeError):
    def __init__(
        self,
        mensagem: str,
        *,
        codigo: str = "aplicacao_rede_falhou",
        detalhes: dict[str, Any] | None = None,
    ):
        super().__init__(mensagem)
        self.codigo = codigo
        self.detalhes = detalhes or {}


def _gerar_id() -> str:
    return str(uuid.uuid4())


def _interfaces_impactadas(plano: dict[str, Any]) -> list[str]:
    interfaces: list[str] = []

    def adicionar(nome: Any) -> None:
        nome = str(nome or "").strip()
        if nome and nome not in interfaces:
            interfaces.append(nome)

    for item in plano.get("interfaces") or []:
        adicionar(item.get("nome"))

    roteamento = plano.get("roteamento") or {}

    for nome in roteamento.get("interfaces_alvo") or []:
        adicionar(nome)

    for rota in roteamento.get("rotas") or []:
        adicionar(rota.get("interface_nome"))

    nat = plano.get("nat") or {}

    for regra in nat.get("regras") or []:
        adicionar(regra.get("interface_origem"))
        adicionar(regra.get("interface_saida"))

    return interfaces


def _resumo_interface(item: dict[str, Any]) -> dict[str, Any]:
    configuracao = item.get("configuracao") or {}

    return {
        "nome": item.get("nome"),
        "conexao": item.get("conexao"),
        "habilitada": configuracao.get("habilitada"),
        "ipv4_modo": configuracao.get("ipv4_modo"),
        "ipv4_endereco": configuracao.get("ipv4_endereco"),
        "ipv4_prefixo": configuracao.get("ipv4_prefixo"),
        "gateway": configuracao.get("gateway") or configuracao.get("ipv4_gateway"),
        "mtu": configuracao.get("mtu"),
    }


def _aplicar_interfaces(plano: dict[str, Any]) -> list[dict[str, Any]]:
    backend = obter_backend()
    resultados: list[dict[str, Any]] = []
    interfaces = plano.get("interfaces") or []

    logger.info(
        "[rede.apply] iniciando aplicação de interfaces | total=%s",
        len(interfaces),
    )

    for item in interfaces:
        nome = item["nome"]
        configuracao = item["configuracao"]
        conexao = item.get("conexao")

        logger.info(
            "[rede.apply] aplicando interface | interface=%s configuracao=%s",
            nome,
            _resumo_interface(item),
        )

        resultado = backend.aplicar_interface(
            nome,
            configuracao,
            conexao=conexao,
        )

        logger.info(
            "[rede.apply] interface aplicada | interface=%s resultado=%s",
            nome,
            resultado,
        )

        resultados.append(resultado)

    logger.info(
        "[rede.apply] aplicação de interfaces concluída | total=%s",
        len(resultados),
    )

    return resultados


def _aplicar_roteamento(plano: dict[str, Any]) -> dict[str, Any] | None:
    roteamento = plano.get("roteamento")

    if not isinstance(roteamento, dict):
        return None

    logger.info(
        "[rede.apply] iniciando aplicação de roteamento | ipv4_forward=%s rotas=%s",
        roteamento.get("ipv4_forward"),
        len(roteamento.get("rotas") or []),
    )

    resultado: dict[str, Any] = {}

    if roteamento.get("ipv4_forward") is not None:
        logger.info(
            "[rede.apply] configurando ipv4_forward | valor=%s",
            roteamento["ipv4_forward"],
        )

        resultado["ipv4_forward"] = definir_ipv4_forward(
            roteamento["ipv4_forward"]
        )

    if roteamento.get("rotas") is not None:
        logger.info(
            "[rede.apply] configurando rotas | total=%s interfaces_alvo=%s",
            len(roteamento.get("rotas") or []),
            roteamento.get("interfaces_alvo") or [],
        )

        resultado_rotas = configurar_rotas(
            roteamento["rotas"],
            interfaces_alvo=roteamento.get("interfaces_alvo") or [],
        )

        resultado["rotas"] = resultado_rotas

        # Alterações persistentes em ipv4.routes precisam ser reativadas para
        # refletirem no estado operacional imediatamente.
        backend = obter_backend()
        ativacoes = []

        for item in resultado_rotas.get("interfaces") or []:
            interface = item.get("interface")
            conexao = item.get("conexao")

            if not interface:
                continue

            logger.info(
                "[rede.apply] reativando interface após alteração de rota | interface=%s conexao=%s",
                interface,
                conexao,
            )

            ativacoes.append(
                backend.ativar_interface(
                    interface,
                    conexao=conexao,
                )
            )

        resultado["ativacoes"] = ativacoes

    logger.info(
        "[rede.apply] roteamento aplicado | resultado=%s",
        resultado,
    )

    return resultado


def _aplicar_nat(plano: dict[str, Any]) -> dict[str, Any] | None:
    nat = plano.get("nat")

    if not isinstance(nat, dict) or not nat.get("aplicar"):
        return None

    regras = nat.get("regras") or []

    logger.info(
        "[rede.apply] aplicando NAT | regras=%s",
        len(regras),
    )

    resultado = aplicar_regras_nat(regras)

    logger.info(
        "[rede.apply] NAT aplicado | resultado=%s",
        resultado,
    )

    return resultado


def _verificar_interfaces(plano: dict[str, Any]) -> list[dict[str, Any]]:
    backend = obter_backend()
    resultados: list[dict[str, Any]] = []

    for item in plano.get("interfaces") or []:
        nome = item["nome"]
        esperado = item["configuracao"]

        logger.info(
            "[rede.apply] verificando interface | interface=%s",
            nome,
        )

        atual = backend.obter_interface(nome)

        verificacao = {
            "interface": nome,
            "existe": True,
            "ok": True,
            "esperado": {
                "habilitada": esperado.get("habilitada"),
                "ipv4_modo": esperado.get("ipv4_modo"),
                "ipv4_endereco": esperado.get("ipv4_endereco"),
                "ipv4_prefixo": esperado.get("ipv4_prefixo"),
            },
            "observado": {
                "estado_link": atual.get("estado_link"),
                "ipv4_atual": atual.get("ipv4_atual"),
                "prefixo_atual": atual.get("prefixo_atual"),
                "gateway_atual": atual.get("gateway_atual"),
            },
        }

        if esperado.get("habilitada") and esperado.get("ipv4_modo") == "static":
            if atual.get("ipv4_atual") != esperado.get("ipv4_endereco"):
                verificacao["ok"] = False
                verificacao["erro"] = (
                    "Endereço IPv4 aplicado não corresponde ao solicitado."
                )

            if atual.get("prefixo_atual") != esperado.get("ipv4_prefixo"):
                verificacao["ok"] = False
                verificacao["erro"] = (
                    "Prefixo IPv4 aplicado não corresponde ao solicitado."
                )

        logger.info(
            "[rede.apply] verificação da interface | interface=%s ok=%s esperado=%s observado=%s",
            nome,
            verificacao["ok"],
            verificacao["esperado"],
            verificacao["observado"],
        )

        resultados.append(verificacao)

    return resultados


def _verificar_roteamento(plano: dict[str, Any]) -> dict[str, Any] | None:
    roteamento = plano.get("roteamento")

    if not isinstance(roteamento, dict):
        return None

    resultado = {
        "ok": True,
        "ipv4_forward": obter_ipv4_forward(),
    }

    esperado_forward = roteamento.get("ipv4_forward")

    if esperado_forward is not None and resultado["ipv4_forward"] != esperado_forward:
        resultado["ok"] = False
        resultado["erro"] = (
            "Estado de IPv4 forwarding não corresponde ao solicitado."
        )

    backend = obter_backend()
    resultado["rotas"] = backend.obter_rotas()

    logger.info(
        "[rede.apply] verificação de roteamento | ok=%s ipv4_forward=%s",
        resultado["ok"],
        resultado["ipv4_forward"],
    )

    return resultado


def _verificar_nat(plano: dict[str, Any]) -> dict[str, Any] | None:
    nat = plano.get("nat")

    if not isinstance(nat, dict) or not nat.get("aplicar"):
        return None

    status = obter_status_nat()

    esperado = len([
        regra
        for regra in nat.get("regras") or []
        if regra.get("ativa", True)
    ])

    resultado = {
        "ok": status.get("total_regras", 0) == esperado,
        "esperado": esperado,
        "observado": status.get("total_regras", 0),
        "status": status,
    }

    logger.info(
        "[rede.apply] verificação NAT | ok=%s esperado=%s observado=%s",
        resultado["ok"],
        resultado["esperado"],
        resultado["observado"],
    )

    return resultado


def _verificar_resultado(plano: dict[str, Any]) -> dict[str, Any]:
    logger.info("[rede.apply] iniciando verificação pós-aplicação")

    interfaces = _verificar_interfaces(plano)
    roteamento = _verificar_roteamento(plano)
    nat = _verificar_nat(plano)

    falhas: list[dict[str, Any]] = [
        item
        for item in interfaces
        if not item.get("ok")
    ]

    if roteamento and not roteamento.get("ok"):
        falhas.append({
            "componente": "roteamento",
            "erro": roteamento.get("erro"),
        })

    if nat and not nat.get("ok"):
        falhas.append({
            "componente": "nat",
            "erro": (
                "Quantidade de regras NAT aplicada não corresponde "
                "ao estado solicitado."
            ),
        })

    resultado = {
        "ok": not falhas,
        "interfaces": interfaces,
        "roteamento": roteamento,
        "nat": nat,
        "falhas": falhas,
    }

    if resultado["ok"]:
        logger.info("[rede.apply] verificação pós-aplicação concluída | ok=true")
    else:
        logger.error(
            "[rede.apply] verificação pós-aplicação falhou | falhas=%s",
            falhas,
        )

    return resultado


def _aplicar_plano(plano: dict[str, Any]) -> dict[str, Any]:
    resultado = {
        "interfaces": None,
        "roteamento": None,
        "nat": None,
        "verificacao": None,
    }

    # Interfaces primeiro para que LAN/WAN estejam no estado correto antes
    # das rotas e do NAT.
    if plano.get("interfaces"):
        resultado["interfaces"] = _aplicar_interfaces(plano)

    if plano.get("roteamento") is not None:
        resultado["roteamento"] = _aplicar_roteamento(plano)

    if plano.get("nat") is not None:
        resultado["nat"] = _aplicar_nat(plano)

    resultado["verificacao"] = _verificar_resultado(plano)

    if not resultado["verificacao"]["ok"]:
        raise AplicacaoRedeErro(
            "A verificação pós-aplicação detectou divergências.",
            codigo="verificacao_pos_aplicacao_falhou",
            detalhes={
                "verificacao": resultado["verificacao"],
            },
        )

    return resultado


def aplicar_alteracao(payload: dict[str, Any]) -> dict[str, Any]:
    """
    Entrada principal para network.change.apply.

    O rollback é armado antes da primeira alteração operacional.
    """

    with _apply_lock:
        logger.info(
            "[rede.apply] requisição recebida | campos=%s",
            sorted(payload.keys()),
        )

        # ---------------------------------------------------------------------
        # 1. VALIDAÇÃO
        # ---------------------------------------------------------------------
        logger.info("[rede.apply] etapa=VALIDATE | iniciando")

        try:
            plano = validar_alteracao(payload)
        except Exception as exc:
            logger.exception(
                "[rede.apply] etapa=VALIDATE | falhou | codigo=%s mensagem=%s",
                getattr(exc, "codigo", type(exc).__name__),
                str(exc),
            )
            raise

        alteracao_id = plano.get("alteracao_id") or _gerar_id()
        plano["alteracao_id"] = alteracao_id

        interfaces = _interfaces_impactadas(plano)

        logger.info(
            "[rede.apply] etapa=VALIDATE | concluída | change_id=%s tipo=%s interfaces=%s timeout=%s",
            alteracao_id,
            plano.get("tipo"),
            interfaces,
            plano.get("timeout_segundos"),
        )

        for item in plano.get("interfaces") or []:
            logger.info(
                "[rede.apply] plano de interface | change_id=%s interface=%s configuracao=%s",
                alteracao_id,
                item.get("nome"),
                _resumo_interface(item),
            )

        # ---------------------------------------------------------------------
        # 2. ALTERAÇÃO ATIVA
        # ---------------------------------------------------------------------
        logger.info(
            "[rede.apply] etapa=ACTIVE_CHECK | change_id=%s",
            alteracao_id,
        )

        ativa = obter_alteracao_ativa()

        if ativa:
            logger.warning(
                "[rede.apply] alteração ativa encontrada | solicitada=%s ativa=%s status=%s restantes=%s",
                alteracao_id,
                ativa.get("alteracao_id"),
                ativa.get("status"),
                ativa.get("segundos_restantes"),
            )

        if ativa and ativa.get("alteracao_id") != alteracao_id:
            raise AplicacaoRedeErro(
                "Já existe uma alteração de Rede aguardando conclusão.",
                codigo="alteracao_rede_em_andamento",
                detalhes={
                    "alteracao_ativa": ativa.get("alteracao_id"),
                    "status": ativa.get("status"),
                    "segundos_restantes": ativa.get("segundos_restantes"),
                },
            )

        logger.info(
            "[rede.apply] etapa=ACTIVE_CHECK | concluída | change_id=%s",
            alteracao_id,
        )

        # ---------------------------------------------------------------------
        # 3. SNAPSHOT
        # ---------------------------------------------------------------------
        snapshot_id = alteracao_id

        logger.info(
            "[rede.apply] etapa=SNAPSHOT | criando | change_id=%s interfaces=%s",
            alteracao_id,
            interfaces,
        )

        try:
            snapshot = criar_snapshot(
                snapshot_id,
                interfaces=interfaces or None,
                incluir_roteamento=True,
                incluir_nat=True,
                metadados={
                    "alteracao_id": alteracao_id,
                    "tipo": plano["tipo"],
                },
            )
        except Exception as exc:
            logger.exception(
                "[rede.apply] etapa=SNAPSHOT | falhou | change_id=%s mensagem=%s",
                alteracao_id,
                str(exc),
            )
            raise

        logger.info(
            "[rede.apply] etapa=SNAPSHOT | concluída | change_id=%s snapshot_id=%s",
            alteracao_id,
            snapshot_id,
        )

        # ---------------------------------------------------------------------
        # 4. ARMAR ROLLBACK
        # ---------------------------------------------------------------------
        logger.info(
            "[rede.apply] etapa=ARM_ROLLBACK | armando | change_id=%s timeout=%s",
            alteracao_id,
            plano["timeout_segundos"],
        )

        try:
            estado_rollback = armar_rollback(
                alteracao_id,
                snapshot_id=snapshot_id,
                timeout_segundos=plano["timeout_segundos"],
                tipo=plano["tipo"],
                metadados={
                    "interfaces": interfaces,
                },
            )
        except Exception as exc:
            logger.exception(
                "[rede.apply] etapa=ARM_ROLLBACK | falhou | change_id=%s mensagem=%s",
                alteracao_id,
                str(exc),
            )
            raise

        logger.info(
            "[rede.apply] etapa=ARM_ROLLBACK | concluída | change_id=%s status=%s expira_em=%s",
            alteracao_id,
            estado_rollback.get("status"),
            estado_rollback.get("expira_em"),
        )

        # ---------------------------------------------------------------------
        # 5. APLICAÇÃO
        # ---------------------------------------------------------------------
        try:
            logger.info(
                "[rede.apply] etapa=APPLY | iniciando | change_id=%s",
                alteracao_id,
            )

            resultado = _aplicar_plano(plano)

            logger.info(
                "[rede.apply] etapa=APPLY | concluída | change_id=%s",
                alteracao_id,
            )

            # -----------------------------------------------------------------
            # 6. REGISTRAR RESULTADO
            # -----------------------------------------------------------------
            logger.info(
                "[rede.apply] etapa=REGISTER_RESULT | change_id=%s",
                alteracao_id,
            )

            registrar_resultado_aplicacao(
                alteracao_id,
                resultado,
            )

            # -----------------------------------------------------------------
            # 7. AGUARDAR CONFIRMAÇÃO
            # -----------------------------------------------------------------
            logger.info(
                "[rede.apply] etapa=WAIT_CONFIRM | armando janela de confirmação | change_id=%s",
                alteracao_id,
            )

            estado = marcar_aguardando_confirmacao(
                alteracao_id
            )

            logger.info(
                "[rede.apply] etapa=WAIT_CONFIRM | aguardando confirmação | change_id=%s expira_em=%s segundos=%s",
                alteracao_id,
                estado.get("expira_em"),
                estado.get("segundos_restantes"),
            )

            return {
                "ok": True,
                "alteracao_id": alteracao_id,
                "tipo": plano["tipo"],
                "status": estado.get("status"),
                "snapshot_id": snapshot_id,
                "expira_em": estado.get("expira_em"),
                "segundos_restantes": estado.get("segundos_restantes"),
                "aguardando_confirmacao": True,
                "resultado": resultado,
                "snapshot": {
                    "id": snapshot.get("id"),
                    "criado_em": snapshot.get("criado_em"),
                    "interfaces": snapshot.get("interfaces"),
                },
            }

        except Exception as exc:
            codigo_original = getattr(
                exc,
                "codigo",
                "aplicacao_rede_falhou",
            )

            logger.exception(
                "[rede.apply] etapa=APPLY | FALHA | change_id=%s codigo=%s mensagem=%s",
                alteracao_id,
                codigo_original,
                str(exc),
            )

            rollback_resultado = None
            rollback_erro = None

            # -----------------------------------------------------------------
            # 8. ROLLBACK AUTOMÁTICO
            # -----------------------------------------------------------------
            logger.warning(
                "[rede.apply] etapa=ROLLBACK | iniciando rollback automático | change_id=%s snapshot_id=%s",
                alteracao_id,
                snapshot_id,
            )

            try:
                rollback_resultado = reverter_alteracao(
                    alteracao_id,
                    motivo=(
                        "Rollback automático após falha na aplicação: "
                        f"{exc}"
                    ),
                )

                logger.warning(
                    "[rede.apply] etapa=ROLLBACK | concluído | change_id=%s status=%s",
                    alteracao_id,
                    rollback_resultado.get("status"),
                )

            except Exception as rollback_exc:
                rollback_erro = {
                    "codigo": getattr(
                        rollback_exc,
                        "codigo",
                        "rollback_falhou",
                    ),
                    "mensagem": str(rollback_exc),
                    "detalhes": getattr(
                        rollback_exc,
                        "detalhes",
                        {},
                    ),
                }

                logger.exception(
                    "[rede.apply] etapa=ROLLBACK | FALHOU | change_id=%s codigo=%s mensagem=%s",
                    alteracao_id,
                    rollback_erro["codigo"],
                    rollback_erro["mensagem"],
                )

            raise AplicacaoRedeErro(
                f"Falha ao aplicar alteração de Rede: {exc}",
                codigo=codigo_original,
                detalhes={
                    "alteracao_id": alteracao_id,
                    "erro_original": {
                        "codigo": getattr(
                            exc,
                            "codigo",
                            "erro_aplicacao",
                        ),
                        "mensagem": str(exc),
                        "detalhes": getattr(
                            exc,
                            "detalhes",
                            {},
                        ),
                    },
                    "rollback": rollback_resultado,
                    "rollback_erro": rollback_erro,
                },
            ) from exc


__all__ = [
    "AplicacaoRedeErro",
    "aplicar_alteracao",
]