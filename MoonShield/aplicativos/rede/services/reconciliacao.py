"""Orquestra leitura e reconciliação do estado observado de Rede."""

from __future__ import annotations

from django.db import transaction

from rede.dominio.erros import AgentRespostaInvalidaErro, InterfaceNaoEncontradaErro
from rede.dominio.tipos import EstadoSincronizacao
from rede.models import InterfaceRede
from rede.services.interfaces import serializar_interface, sincronizar_inventario
from rede.services.inventario import obter_inventario


_ESTADOS_SAFE_APPLY = {
    EstadoSincronizacao.APPLYING.value,
    EstadoSincronizacao.WAITING_CONFIRMATION.value,
}


def reconciliar_interfaces(*, inventario: dict | None = None) -> dict:
    """
    Consulta uma vez o Agent, persiste somente o observado e recalcula estados.

    Falhas globais do Agent são propagadas antes da transação; assim, o último
    estado observado persistido não é apagado por indisponibilidade temporária.
    """
    if inventario is None:
        inventario = obter_inventario()

    if not isinstance(inventario, dict):
        raise AgentRespostaInvalidaErro("Inventário devolvido pelo Agent é inválido.")

    with transaction.atomic():
        protegidas = {
            interface.pk: interface.estado_sincronizacao
            for interface in InterfaceRede.objects.select_for_update().filter(
                estado_sincronizacao__in=_ESTADOS_SAFE_APPLY
            )
        }
        sincronizar_inventario(inventario)
        _restaurar_estados_safe_apply(protegidas)
        interfaces = list(InterfaceRede.objects.order_by("papel", "-principal", "nome"))

    itens_observados = inventario.get("interfaces", [])
    total_observado = len(itens_observados) if isinstance(itens_observados, list) else 0

    return {
        "backend": inventario.get("backend"),
        "total_observado": total_observado,
        "total": len(interfaces),
        "interfaces": [serializar_interface(interface) for interface in interfaces],
    }


def reconciliar_interface(nome: str, *, inventario: dict | None = None) -> dict:
    """Reconcilia o inventário completo e retorna uma interface conhecida."""
    resultado = reconciliar_interfaces(inventario=inventario)
    nome = str(nome or "").strip()

    for interface in resultado["interfaces"]:
        if interface["nome"] == nome:
            return interface

    raise InterfaceNaoEncontradaErro(
        f"Interface '{nome}' não está cadastrada no MoonShield.",
        detalhes={"interface": nome},
    )


def obter_estado_reconciliado(nome: str | None = None) -> dict:
    """Retorna o último estado reconciliado, sem consultar o Agent novamente."""
    queryset = InterfaceRede.objects.order_by("papel", "-principal", "nome")

    if nome is None:
        interfaces = list(queryset)
        return {
            "total": len(interfaces),
            "interfaces": [serializar_interface(interface) for interface in interfaces],
        }

    try:
        interface = queryset.get(nome=str(nome).strip())
    except InterfaceRede.DoesNotExist as exc:
        raise InterfaceNaoEncontradaErro(
            f"Interface '{nome}' não está cadastrada no MoonShield.",
            detalhes={"interface": nome},
        ) from exc

    return serializar_interface(interface)


def _restaurar_estados_safe_apply(protegidas: dict[int, str]) -> None:
    """Não deixa uma leitura substituir estados transitórios de Safe Apply."""
    if not protegidas:
        return

    for interface in InterfaceRede.objects.select_for_update().filter(pk__in=protegidas):
        estado = protegidas[interface.pk]
        if (
            interface.estado_sincronizacao == estado
            and not interface.sincronizada
            and interface.pendente
        ):
            continue

        interface.estado_sincronizacao = estado
        interface.sincronizada = False
        interface.pendente = True
        interface.save(update_fields=[
            "estado_sincronizacao",
            "sincronizada",
            "pendente",
            "atualizado_em",
        ])
