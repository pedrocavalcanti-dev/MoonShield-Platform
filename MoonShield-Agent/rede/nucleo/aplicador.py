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


_apply_lock = threading.RLock()


class AplicacaoRedeErro(RuntimeError):
    def __init__(self, mensagem: str, *, codigo: str = "aplicacao_rede_falhou", detalhes: dict[str, Any] | None = None):
        super().__init__(mensagem)
        self.codigo = codigo
        self.detalhes = detalhes or {}


def _gerar_id() -> str:
    return str(uuid.uuid4())


def _interfaces_impactadas(plano: dict[str, Any]) -> list[str]:
    interfaces = []

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


def _aplicar_interfaces(plano: dict[str, Any]) -> list[dict[str, Any]]:
    backend = obter_backend()
    resultados = []

    for item in plano.get("interfaces") or []:
        resultado = backend.aplicar_interface(
            item["nome"],
            item["configuracao"],
            conexao=item.get("conexao"),
        )

        resultados.append(resultado)

    return resultados


def _aplicar_roteamento(plano: dict[str, Any]) -> dict[str, Any] | None:
    roteamento = plano.get("roteamento")

    if not isinstance(roteamento, dict):
        return None

    resultado: dict[str, Any] = {}

    if roteamento.get("ipv4_forward") is not None:
        resultado["ipv4_forward"] = definir_ipv4_forward(
            roteamento["ipv4_forward"]
        )

    if roteamento.get("rotas") is not None:
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

            ativacoes.append(
                backend.ativar_interface(
                    interface,
                    conexao=conexao,
                )
            )

        resultado["ativacoes"] = ativacoes

    return resultado


def _aplicar_nat(plano: dict[str, Any]) -> dict[str, Any] | None:
    nat = plano.get("nat")

    if not isinstance(nat, dict) or not nat.get("aplicar"):
        return None

    return aplicar_regras_nat(
        nat.get("regras") or []
    )


def _verificar_interfaces(plano: dict[str, Any]) -> list[dict[str, Any]]:
    backend = obter_backend()
    resultados = []

    for item in plano.get("interfaces") or []:
        nome = item["nome"]
        esperado = item["configuracao"]
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
                verificacao["erro"] = "Endereço IPv4 aplicado não corresponde ao solicitado."

            if atual.get("prefixo_atual") != esperado.get("ipv4_prefixo"):
                verificacao["ok"] = False
                verificacao["erro"] = "Prefixo IPv4 aplicado não corresponde ao solicitado."

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
        resultado["erro"] = "Estado de IPv4 forwarding não corresponde ao solicitado."

    backend = obter_backend()
    resultado["rotas"] = backend.obter_rotas()

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

    return {
        "ok": status.get("total_regras", 0) == esperado,
        "esperado": esperado,
        "observado": status.get("total_regras", 0),
        "status": status,
    }


def _verificar_resultado(plano: dict[str, Any]) -> dict[str, Any]:
    interfaces = _verificar_interfaces(plano)
    roteamento = _verificar_roteamento(plano)
    nat = _verificar_nat(plano)

    falhas = [
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
            "erro": "Quantidade de regras NAT aplicada não corresponde ao estado solicitado.",
        })

    return {
        "ok": not falhas,
        "interfaces": interfaces,
        "roteamento": roteamento,
        "nat": nat,
        "falhas": falhas,
    }


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
        plano = validar_alteracao(payload)

        alteracao_id = plano.get("alteracao_id") or _gerar_id()
        plano["alteracao_id"] = alteracao_id

        ativa = obter_alteracao_ativa()

        if ativa and ativa.get("alteracao_id") != alteracao_id:
            raise AplicacaoRedeErro(
                "Já existe uma alteração de Rede aguardando conclusão.",
                codigo="alteracao_rede_em_andamento",
                detalhes={
                    "alteracao_ativa": ativa.get("alteracao_id"),
                    "status": ativa.get("status"),
                },
            )

        interfaces = _interfaces_impactadas(plano)
        snapshot_id = alteracao_id

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

        # Invariante crítica: o rollback precisa estar armado ANTES da
        # primeira operação que possa alterar a conectividade.
        armar_rollback(
            alteracao_id,
            snapshot_id=snapshot_id,
            timeout_segundos=plano["timeout_segundos"],
            tipo=plano["tipo"],
            metadados={
                "interfaces": interfaces,
            },
        )

        try:
            resultado = _aplicar_plano(plano)

            registrar_resultado_aplicacao(
                alteracao_id,
                resultado,
            )

            estado = marcar_aguardando_confirmacao(
                alteracao_id
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
            rollback_resultado = None
            rollback_erro = None

            try:
                rollback_resultado = reverter_alteracao(
                    alteracao_id,
                    motivo=f"Rollback automático após falha na aplicação: {exc}",
                )
            except Exception as rollback_exc:
                rollback_erro = {
                    "codigo": getattr(rollback_exc, "codigo", "rollback_falhou"),
                    "mensagem": str(rollback_exc),
                    "detalhes": getattr(rollback_exc, "detalhes", {}),
                }

            raise AplicacaoRedeErro(
                f"Falha ao aplicar alteração de Rede: {exc}",
                codigo=getattr(exc, "codigo", "aplicacao_rede_falhou"),
                detalhes={
                    "alteracao_id": alteracao_id,
                    "erro_original": {
                        "codigo": getattr(exc, "codigo", "erro_aplicacao"),
                        "mensagem": str(exc),
                        "detalhes": getattr(exc, "detalhes", {}),
                    },
                    "rollback": rollback_resultado,
                    "rollback_erro": rollback_erro,
                },
            ) from exc


__all__ = [
    "AplicacaoRedeErro",
    "aplicar_alteracao",
]