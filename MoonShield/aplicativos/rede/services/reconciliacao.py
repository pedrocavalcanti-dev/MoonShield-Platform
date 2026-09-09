"""
MoonShield Network — Reconciliação / Drift
==========================================

Orquestra leitura e reconciliação do estado observado de Rede.

Princípios:
- Django continua sendo o Control Plane;
- Agent/Linux continuam sendo a fonte do estado observado;
- reconciliação NÃO aplica alterações no Linux;
- desired state nunca é sobrescrito silenciosamente pelo observed;
- estados transitórios do Safe Apply são preservados;
- recursos externos ao namespace MoonShield não são tratados como propriedade
  do MoonShield;
- detectar drift não promove artificialmente revisão aplicada.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from django.db import transaction

from rede.dominio.erros import (
    AgentRespostaInvalidaErro,
    InterfaceNaoEncontradaErro,
)
from rede.dominio.tipos import (
    EstadoSincronizacao,
    PapelInterface,
)
from rede.models import (
    ConfiguracaoRoteamento,
    InterfaceRede,
    RegraNat,
    RotaEstatica,
)
from rede.services.interfaces import (
    serializar_interface,
    sincronizar_inventario,
)
from rede.services.inventario import obter_inventario
from rede.services.nat import obter_estado_nat_real
from rede.services.roteamento import obter_estado_roteamento_real


_ESTADOS_SAFE_APPLY = {
    EstadoSincronizacao.APPLYING.value,
    EstadoSincronizacao.WAITING_CONFIRMATION.value,
}

_ESTADOS_DRIFT_INTERFACE = {
    EstadoSincronizacao.DRIFTED.value,
    EstadoSincronizacao.MISSING.value,
}

_ESTADOS_PENDENTES_INTERFACE = {
    EstadoSincronizacao.PENDING_APPLY.value,
    EstadoSincronizacao.APPLYING.value,
    EstadoSincronizacao.WAITING_CONFIRMATION.value,
}


# =============================================================================
# API PÚBLICA — COMPATIBILIDADE
# =============================================================================


def reconciliar_interfaces(*, inventario: dict | None = None) -> dict:
    """
    Consulta uma vez o Agent, persiste somente o observado e recalcula estados.

    Falhas globais do Agent são propagadas antes da transação; assim, o último
    estado observado persistido não é apagado por indisponibilidade temporária.

    Esta função mantém o contrato anterior: reconcilia somente interfaces.
    O A8 completo é exposto por ``reconciliar_rede``.
    """
    if inventario is None:
        inventario = obter_inventario()

    _validar_dict_agent(
        inventario,
        "Inventário devolvido pelo Agent é inválido.",
    )

    with transaction.atomic():
        protegidas = {
            interface.pk: interface.estado_sincronizacao
            for interface in InterfaceRede.objects.select_for_update().filter(
                estado_sincronizacao__in=_ESTADOS_SAFE_APPLY
            )
        }
        sincronizar_inventario(inventario)
        _restaurar_estados_safe_apply(protegidas)
        interfaces = list(
            InterfaceRede.objects.order_by(
                "papel",
                "-principal",
                "nome",
            )
        )

    itens_observados = inventario.get("interfaces", [])
    total_observado = (
        len(itens_observados)
        if isinstance(itens_observados, list)
        else 0
    )

    return {
        "backend": inventario.get("backend"),
        "total_observado": total_observado,
        "total": len(interfaces),
        "interfaces": [
            serializar_interface(interface)
            for interface in interfaces
        ],
    }


def reconciliar_interface(
    nome: str,
    *,
    inventario: dict | None = None,
) -> dict:
    """Reconcilia o inventário completo e retorna uma interface conhecida."""
    resultado = reconciliar_interfaces(
        inventario=inventario
    )
    nome = str(nome or "").strip()

    for interface in resultado["interfaces"]:
        if interface["nome"] == nome:
            return interface

    raise InterfaceNaoEncontradaErro(
        f"Interface '{nome}' não está cadastrada no MoonShield.",
        detalhes={"interface": nome},
    )


def obter_estado_reconciliado(
    nome: str | None = None,
) -> dict:
    """Retorna o último estado de interfaces reconciliado, sem consultar o Agent."""
    queryset = InterfaceRede.objects.order_by(
        "papel",
        "-principal",
        "nome",
    )

    if nome is None:
        interfaces = list(queryset)
        return {
            "total": len(interfaces),
            "interfaces": [
                serializar_interface(interface)
                for interface in interfaces
            ],
        }

    try:
        interface = queryset.get(
            nome=str(nome).strip()
        )
    except InterfaceRede.DoesNotExist as exc:
        raise InterfaceNaoEncontradaErro(
            f"Interface '{nome}' não está cadastrada no MoonShield.",
            detalhes={"interface": nome},
        ) from exc

    return serializar_interface(interface)


# =============================================================================
# A8 — RECONCILIAÇÃO COMPLETA
# =============================================================================


def reconciliar_rede(
    *,
    inventario: dict | None = None,
    roteamento: dict | None = None,
    nat: dict | None = None,
) -> dict:
    """
    Faz uma leitura consistente de interfaces + roteamento + NAT e produz
    relatório de desired x observed.

    IMPORTANTE:
    - não chama Safe Apply;
    - não executa nmcli/ip/nft/sysctl diretamente;
    - não altera desired state;
    - não promove revisao_aplicada;
    - somente ajusta flags auxiliares de RotaEstatica/RegraNat a partir da
      observação real, para que uma reaplicação posterior possa ser planejada.
    """

    # Todas as leituras privilegiadas acontecem ANTES de qualquer escrita no DB.
    # Assim, uma falha de uma das fontes não deixa uma reconciliação global
    # parcialmente persistida.
    if inventario is None:
        inventario = obter_inventario()
    if roteamento is None:
        roteamento = obter_estado_roteamento_real()
    if nat is None:
        nat = obter_estado_nat_real()

    _validar_dict_agent(
        inventario,
        "Inventário devolvido pelo Agent é inválido.",
    )
    _validar_dict_agent(
        roteamento,
        "Estado de roteamento devolvido pelo Agent é inválido.",
    )
    _validar_dict_agent(
        nat,
        "Estado NAT devolvido pelo Agent é inválido.",
    )

    with transaction.atomic():
        resultado_interfaces = reconciliar_interfaces(
            inventario=inventario
        )
        relatorio_interfaces = _relatorio_interfaces(
            resultado_interfaces["interfaces"]
        )
        relatorio_roteamento = _reconciliar_roteamento(
            roteamento
        )
        relatorio_nat = _reconciliar_nat(
            nat
        )

    total_drifts = (
        relatorio_interfaces["total_drift"]
        + relatorio_roteamento["total_drift"]
        + relatorio_nat["total_drift"]
    )
    total_pendencias = (
        relatorio_interfaces["total_pendencias"]
        + relatorio_roteamento["total_pendencias"]
        + relatorio_nat["total_pendencias"]
    )
    total_erros = relatorio_interfaces["total_erros"]

    drift = total_drifts > 0
    sincronizado = (
        total_drifts == 0
        and total_pendencias == 0
        and total_erros == 0
    )

    return {
        "backend": resultado_interfaces.get("backend"),
        "drift": drift,
        "sincronizado": sincronizado,
        "resumo": {
            "total_drift": total_drifts,
            "total_pendencias": total_pendencias,
            "total_erros": total_erros,
        },
        # Preserva o bloco completo já usado pelo painel/API.
        "interfaces": {
            **relatorio_interfaces,
            "total_observado": resultado_interfaces["total_observado"],
            "total": resultado_interfaces["total"],
            "itens": resultado_interfaces["interfaces"],
        },
        "roteamento": relatorio_roteamento,
        "nat": relatorio_nat,
    }


# =============================================================================
# INTERFACES — RELATÓRIO DE DRIFT
# =============================================================================


def _relatorio_interfaces(
    interfaces: list[dict[str, Any]],
) -> dict[str, Any]:
    divergencias = []
    pendencias = []
    erros = []

    for interface in interfaces:
        estado = str(
            interface.get("estado_sincronizacao")
            or ""
        ).strip()

        item = {
            "id": interface.get("id"),
            "nome": interface.get("nome"),
            "estado": estado,
            "revisao_desejada": interface.get(
                "revisao_desejada"
            ),
            "revisao_aplicada": interface.get(
                "revisao_aplicada"
            ),
            "diferencas": _diferencas_interface(
                interface
            ),
        }

        if estado in _ESTADOS_DRIFT_INTERFACE:
            divergencias.append(item)
        elif estado in _ESTADOS_PENDENTES_INTERFACE:
            pendencias.append(item)
        elif estado == EstadoSincronizacao.ERROR.value:
            item["erro"] = interface.get(
                "ultimo_erro"
            )
            erros.append(item)

    return {
        "drift": bool(divergencias),
        "total_drift": len(divergencias),
        "total_pendencias": len(pendencias),
        "total_erros": len(erros),
        "divergencias": divergencias,
        "pendencias": pendencias,
        "erros": erros,
    }


def _diferencas_interface(
    interface: dict[str, Any],
) -> list[dict[str, Any]]:
    """Explica diferenças técnicas sem inventar estado que o Agent não observou."""
    desejado = (
        interface.get("desejado")
        if isinstance(interface.get("desejado"), dict)
        else {}
    )
    real = (
        interface.get("real")
        if isinstance(interface.get("real"), dict)
        else {}
    )
    estado = str(
        interface.get("estado_sincronizacao")
        or ""
    ).strip()

    if estado == EstadoSincronizacao.MISSING.value:
        return [{
            "campo": "presenca",
            "desejado": True,
            "observado": False,
        }]

    diferencas: list[dict[str, Any]] = []

    habilitada = bool(
        desejado.get("habilitada", True)
    )
    link_up = str(
        real.get("estado_link") or ""
    ).lower() == "up"

    if habilitada != link_up:
        diferencas.append({
            "campo": "habilitada",
            "desejado": habilitada,
            "observado": link_up,
        })

    # Se a interface deveria estar desligada, o restante do estado operacional
    # não é exigido para considerar o link coerente.
    if not habilitada:
        return diferencas

    modo = str(
        desejado.get("ipv4_modo") or ""
    ).lower()
    enderecos = real.get("enderecos_ipv4")
    if not isinstance(enderecos, list):
        enderecos = []

    if modo == "disabled":
        if enderecos or real.get("ipv4"):
            diferencas.append({
                "campo": "ipv4",
                "desejado": [],
                "observado": enderecos or [real.get("ipv4")],
            })

    elif modo == "static":
        endereco = desejado.get("ipv4_endereco")
        prefixo = desejado.get("ipv4_prefixo")
        cidr_desejado = (
            _normalizar_cidr(
                f"{endereco}/{prefixo}"
            )
            if endereco and prefixo is not None
            else None
        )
        cidrs_observados = {
            cidr
            for valor in enderecos
            if (cidr := _normalizar_cidr(valor))
        }

        # Compatibilidade com estado observado legado de um único IPv4.
        if not cidrs_observados and real.get("ipv4"):
            valor = real.get("ipv4")
            prefixo_real = real.get("prefixo")
            if prefixo_real is not None:
                valor = f"{valor}/{prefixo_real}"
            normalizado = _normalizar_cidr(valor)
            if normalizado:
                cidrs_observados.add(normalizado)

        if cidr_desejado and cidr_desejado not in cidrs_observados:
            diferencas.append({
                "campo": "ipv4",
                "desejado": cidr_desejado,
                "observado": sorted(cidrs_observados),
            })

        gateway_desejado = _texto_ou_none(
            desejado.get("gateway")
        )
        gateway_real = _texto_ou_none(
            real.get("gateway")
        )
        if (
            gateway_desejado
            and gateway_desejado != gateway_real
        ):
            diferencas.append({
                "campo": "gateway",
                "desejado": gateway_desejado,
                "observado": gateway_real,
            })

    elif modo == "dhcp":
        # Em DHCP não comparamos lease/IP dinâmico. Quando a interface foi
        # declarada rota padrão, a ausência de gateway é uma divergência útil.
        if (
            desejado.get("rota_padrao")
            and not real.get("gateway")
        ):
            diferencas.append({
                "campo": "rota_padrao",
                "desejado": True,
                "observado": False,
            })

    mtu_desejado = _inteiro_ou_none(
        desejado.get("mtu")
    )
    mtu_real = _inteiro_ou_none(
        real.get("mtu")
    )
    if (
        mtu_desejado is not None
        and mtu_real is not None
        and mtu_desejado != mtu_real
    ):
        diferencas.append({
            "campo": "mtu",
            "desejado": mtu_desejado,
            "observado": mtu_real,
        })

    return diferencas


# =============================================================================
# ROTEAMENTO
# =============================================================================


def _reconciliar_roteamento(
    observado: dict[str, Any],
) -> dict[str, Any]:
    config = ConfiguracaoRoteamento.atual()

    # Mesmo contrato efetivo do Apply: NAT ativo exige forwarding.
    nat_exige_forward = RegraNat.objects.filter(
        ativa=True
    ).exists()
    ipv4_forward_desejado = (
        bool(config.ipv4_forward)
        or nat_exige_forward
    )
    ipv4_forward_observado = bool(
        observado.get("ipv4_forward")
    )
    forward_ok = (
        ipv4_forward_desejado
        == ipv4_forward_observado
    )

    rotas_observadas = observado.get(
        "rotas",
        [],
    )
    if not isinstance(rotas_observadas, list):
        raise AgentRespostaInvalidaErro(
            "O estado de roteamento deve conter uma lista de rotas."
        )

    identidades_observadas = {
        identidade
        for item in rotas_observadas
        if isinstance(item, dict)
        if (identidade := _identidade_rota_dict(item))
    }

    # -------------------------------------------------------------------------
    # ROTA DEFAULT
    # -------------------------------------------------------------------------
    interface_default = (
        InterfaceRede.objects
        .exclude(
            papel=PapelInterface.NAO_ATRIBUIDA.value
        )
        .filter(
            rota_padrao=True
        )
        .order_by(
            "-principal",
            "nome",
        )
        .first()
    )

    rota_default_observada = observado.get(
        "rota_default"
    )
    if not isinstance(
        rota_default_observada,
        dict,
    ):
        rota_default_observada = next(
            (
                rota
                for rota in rotas_observadas
                if isinstance(rota, dict)
                and (
                    rota.get("default")
                    or str(rota.get("destino") or "").lower()
                    in {"default", "0.0.0.0/0"}
                )
            ),
            None,
        )

    relatorio_default = _comparar_rota_default(
        interface_default,
        rota_default_observada,
    )

    # -------------------------------------------------------------------------
    # ROTAS ESTÁTICAS
    # -------------------------------------------------------------------------
    relatorio_rotas = []
    total_drift_rotas = 0
    total_pendencias_rotas = 0

    rotas_desejadas = list(
        RotaEstatica.objects
        .select_for_update(of=("self",))
        .select_related("interface")
        .order_by(
            "metrica",
            "destino",
            "id",
        )
    )

    for rota in rotas_desejadas:
        identidade = _identidade_rota_model(rota)
        presente = (
            identidade in identidades_observadas
        )
        era_pendente = bool(rota.pendente)
        era_sincronizada = bool(
            rota.sincronizada
        )

        if rota.ativa:
            if era_sincronizada:
                # A rota já foi promovida por uma confirmação anterior.
                # Podemos detectar drift sem perder o marcador de ownership.
                if presente:
                    status = EstadoSincronizacao.SYNCED.value
                    sincronizada = True
                    pendente = False
                else:
                    status = EstadoSincronizacao.DRIFTED.value
                    sincronizada = True
                    pendente = True
            else:
                # Desired novo/alterado nunca é promovido por simples observação.
                # A promoção continua pertencendo à confirmação do Safe Apply.
                status = EstadoSincronizacao.PENDING_APPLY.value
                sincronizada = False
                pendente = True
        else:
            if era_pendente:
                # Tombstone ainda não confirmado. Não concluir remoção apenas
                # porque a rota desapareceu externamente.
                status = EstadoSincronizacao.PENDING_APPLY.value
                sincronizada = era_sincronizada
                pendente = True
            else:
                # Remoção já confirmada. Uma rota externa com a mesma identidade
                # não é adotada pelo MoonShield.
                status = "removed"
                sincronizada = False
                pendente = False

        campos_alterados = []
        if rota.sincronizada != sincronizada:
            rota.sincronizada = sincronizada
            campos_alterados.append(
                "sincronizada"
            )
        if rota.pendente != pendente:
            rota.pendente = pendente
            campos_alterados.append(
                "pendente"
            )

        if status in {
            EstadoSincronizacao.SYNCED.value,
            "removed",
        } and rota.ultimo_erro:
            rota.ultimo_erro = ""
            campos_alterados.append(
                "ultimo_erro"
            )

        if campos_alterados:
            campos_alterados.append(
                "atualizado_em"
            )
            rota.save(
                update_fields=campos_alterados
            )

        if status == EstadoSincronizacao.DRIFTED.value:
            total_drift_rotas += 1
        elif status == EstadoSincronizacao.PENDING_APPLY.value:
            total_pendencias_rotas += 1

        relatorio_rotas.append({
            "id": rota.pk,
            "nome": rota.nome,
            "ativa": rota.ativa,
            "status": status,
            "presente": presente,
            "desejado": {
                "destino": identidade[0],
                "gateway": identidade[1],
                "interface": identidade[2],
                "metrica": identidade[3],
            },
        })

    total_drift = (
        (0 if forward_ok else 1)
        + (1 if relatorio_default["status"] == EstadoSincronizacao.DRIFTED.value else 0)
        + total_drift_rotas
    )
    total_pendencias = (
        (1 if relatorio_default["status"] == EstadoSincronizacao.PENDING_APPLY.value else 0)
        + total_pendencias_rotas
    )

    return {
        "drift": total_drift > 0,
        "total_drift": total_drift,
        "total_pendencias": total_pendencias,
        "ipv4_forward": {
            "sincronizado": forward_ok,
            "desejado": ipv4_forward_desejado,
            "observado": ipv4_forward_observado,
            "configurado": bool(
                config.ipv4_forward
            ),
            "exigido_por_nat": nat_exige_forward,
        },
        "rota_default": relatorio_default,
        "rotas_estaticas": {
            "total": len(relatorio_rotas),
            "total_drift": total_drift_rotas,
            "total_pendencias": total_pendencias_rotas,
            "itens": relatorio_rotas,
            # Rotas não cadastradas no Control Plane são deliberadamente
            # ignoradas: não há ownership suficiente para classificá-las como
            # drift ou removê-las.
            "rotas_externas_ignoradas": True,
        },
    }


def _comparar_rota_default(
    interface: InterfaceRede | None,
    observada: dict[str, Any] | None,
) -> dict[str, Any]:
    if interface is None:
        return {
            "gerenciada": False,
            "status": "not_managed",
            "sincronizado": True,
            "desejado": None,
            "observado": observada,
        }

    desejado = {
        "interface": interface.nome,
        "gateway": _texto_ou_none(
            interface.gateway
        ),
        "metrica": _inteiro_ou_none(
            interface.metrica
        ),
    }

    if not observada:
        sincronizado = False
    else:
        sincronizado = (
            str(observada.get("interface") or "")
            == interface.nome
        )

        gateway_desejado = desejado["gateway"]
        if (
            sincronizado
            and gateway_desejado
            and gateway_desejado
            != _texto_ou_none(
                observada.get("gateway")
            )
        ):
            sincronizado = False

        metrica_desejada = desejado["metrica"]
        metrica_observada = _inteiro_ou_none(
            observada.get("metrica")
        )
        if (
            sincronizado
            and metrica_desejada is not None
            and metrica_observada is not None
            and metrica_desejada != metrica_observada
        ):
            sincronizado = False

    if sincronizado:
        status = EstadoSincronizacao.SYNCED.value
    elif (
        interface.revisao_desejada
        > interface.revisao_aplicada
    ):
        status = EstadoSincronizacao.PENDING_APPLY.value
    else:
        status = EstadoSincronizacao.DRIFTED.value

    return {
        "gerenciada": True,
        "status": status,
        "sincronizado": sincronizado,
        "desejado": desejado,
        "observado": observada,
    }


# =============================================================================
# NAT
# =============================================================================


def _reconciliar_nat(
    observado: dict[str, Any],
) -> dict[str, Any]:
    regras_observadas = observado.get(
        "regras",
        [],
    )
    if not isinstance(
        regras_observadas,
        list,
    ):
        raise AgentRespostaInvalidaErro(
            "O estado NAT deve conter uma lista de regras."
        )

    por_id: dict[str, list[dict[str, Any]]] = {}
    for regra in regras_observadas:
        if not isinstance(regra, dict):
            continue
        identificador = _texto_ou_none(
            regra.get("id")
        )
        if identificador is not None:
            por_id.setdefault(
                identificador,
                [],
            ).append(regra)

    desejadas = list(
        RegraNat.objects
        .select_for_update(of=("self",))
        .select_related(
            "interface_origem",
            "interface_saida",
        )
        .order_by(
            "prioridade",
            "id",
        )
    )

    relatorio = []
    ids_desejados = set()
    total_drift = 0
    total_pendencias = 0

    for regra in desejadas:
        identidade = _identidade_nat_model(
            regra
        )
        identificador = identidade[0]
        ids_desejados.add(
            identificador
        )

        candidatas = por_id.get(
            identificador,
            [],
        )
        observada_exata = next(
            (
                item
                for item in candidatas
                if _identidade_nat_dict(item)
                == identidade
            ),
            None,
        )
        existe_mesmo_id = bool(
            candidatas
        )
        era_pendente = bool(
            regra.pendente
        )
        era_sincronizada = bool(
            regra.sincronizada
        )

        if regra.ativa:
            if era_sincronizada:
                if observada_exata is not None:
                    status = EstadoSincronizacao.SYNCED.value
                    sincronizada = True
                    pendente = False
                else:
                    status = EstadoSincronizacao.DRIFTED.value
                    sincronizada = True
                    pendente = True
            else:
                # Desired novo/alterado não é promovido por simples observação.
                # A promoção continua pertencendo à confirmação do Safe Apply.
                status = EstadoSincronizacao.PENDING_APPLY.value
                sincronizada = False
                pendente = True
        else:
            if era_pendente:
                # Não concluir tombstone por observação externa.
                status = EstadoSincronizacao.PENDING_APPLY.value
                sincronizada = era_sincronizada
                pendente = True
            elif existe_mesmo_id:
                # A tabela moonshield_nat é namespace exclusivo do MoonShield:
                # regra reaparecida após remoção confirmada é drift.
                status = EstadoSincronizacao.DRIFTED.value
                sincronizada = False
                pendente = True
            else:
                status = "removed"
                sincronizada = False
                pendente = False

        campos_alterados = []
        if regra.sincronizada != sincronizada:
            regra.sincronizada = sincronizada
            campos_alterados.append(
                "sincronizada"
            )
        if regra.pendente != pendente:
            regra.pendente = pendente
            campos_alterados.append(
                "pendente"
            )

        if status in {
            EstadoSincronizacao.SYNCED.value,
            "removed",
        } and regra.ultimo_erro:
            regra.ultimo_erro = ""
            campos_alterados.append(
                "ultimo_erro"
            )

        if campos_alterados:
            campos_alterados.append(
                "atualizado_em"
            )
            regra.save(
                update_fields=campos_alterados
            )

        if status == EstadoSincronizacao.DRIFTED.value:
            total_drift += 1
        elif status == EstadoSincronizacao.PENDING_APPLY.value:
            total_pendencias += 1

        relatorio.append({
            "id": regra.pk,
            "nome": regra.nome,
            "ativa": regra.ativa,
            "status": status,
            "presente": observada_exata is not None,
            "mesmo_id_presente": existe_mesmo_id,
            "desejado": {
                "id": identidade[0],
                "tipo": identidade[1],
                "interface_origem": identidade[2],
                "interface_saida": identidade[3],
                "origem_cidr": identidade[4],
            },
            "observado": (
                observada_exata
                or (
                    candidatas[0]
                    if candidatas
                    else None
                )
            ),
        })

    # A tabela moonshield_nat é namespace exclusivo do MoonShield. Portanto
    # regras observadas sem correspondente no Control Plane são drift real.
    inesperadas = [
        regra
        for regra in regras_observadas
        if isinstance(regra, dict)
        and (
            _texto_ou_none(
                regra.get("id")
            )
            not in ids_desejados
        )
    ]

    if inesperadas:
        total_drift += len(
            inesperadas
        )

    return {
        "drift": total_drift > 0,
        "total_drift": total_drift,
        "total_pendencias": total_pendencias,
        "tabela": observado.get(
            "tabela"
        ),
        "tabela_existe": bool(
            observado.get(
                "tabela_existe",
                observado.get("ativo", False),
            )
        ),
        "total_observado": len(
            regras_observadas
        ),
        "regras": relatorio,
        "regras_inesperadas": inesperadas,
    }


# =============================================================================
# IDENTIDADES / NORMALIZAÇÃO
# =============================================================================


def _identidade_rota_model(
    rota: RotaEstatica,
) -> tuple[str, str | None, str, int]:
    return (
        _normalizar_destino(
            rota.destino
        ),
        _normalizar_ip(
            rota.gateway
        ),
        str(
            rota.interface.nome
            if rota.interface
            else ""
        ),
        int(
            rota.metrica
        ),
    )


def _identidade_rota_dict(
    rota: dict[str, Any],
) -> tuple[str, str | None, str, int] | None:
    destino = rota.get(
        "destino"
    )
    interface = _texto_ou_none(
        rota.get("interface")
        or rota.get("interface_nome")
    )

    if not destino or not interface:
        return None

    try:
        destino_normalizado = _normalizar_destino(
            destino
        )
    except ValueError:
        return None

    metrica = _inteiro_ou_none(
        rota.get("metrica")
    )
    if metrica is None:
        metrica = 100

    return (
        destino_normalizado,
        _normalizar_ip(
            rota.get("gateway")
        ),
        interface,
        metrica,
    )


def _identidade_nat_model(
    regra: RegraNat,
) -> tuple[str, str, str, str, str | None]:
    return (
        str(regra.pk),
        str(regra.tipo),
        regra.interface_origem.nome,
        regra.interface_saida.nome,
        _normalizar_rede_ou_none(
            regra.origem_cidr
        ),
    )


def _identidade_nat_dict(
    regra: dict[str, Any],
) -> tuple[str, str, str, str, str | None] | None:
    identificador = _texto_ou_none(
        regra.get("id")
    )
    origem = _texto_ou_none(
        regra.get("interface_origem")
        or regra.get("origem_interface")
    )
    saida = _texto_ou_none(
        regra.get("interface_saida")
        or regra.get("saida_interface")
    )

    if (
        identificador is None
        or origem is None
        or saida is None
    ):
        return None

    tipo = str(
        regra.get("tipo")
        or "masquerade"
    ).strip().lower()

    return (
        identificador,
        tipo,
        origem,
        saida,
        _normalizar_rede_ou_none(
            regra.get("rede_origem")
            or regra.get("origem_cidr")
        ),
    )


def _normalizar_destino(
    valor: Any,
) -> str:
    texto = str(
        valor or ""
    ).strip().lower()

    if texto == "default":
        return "0.0.0.0/0"

    return str(
        ipaddress.ip_network(
            texto,
            strict=False,
        )
    )


def _normalizar_cidr(
    valor: Any,
) -> str | None:
    texto = _texto_ou_none(
        valor
    )
    if texto is None:
        return None

    try:
        return str(
            ipaddress.ip_interface(
                texto
            )
        )
    except ValueError:
        return None


def _normalizar_rede_ou_none(
    valor: Any,
) -> str | None:
    texto = _texto_ou_none(
        valor
    )
    if texto is None:
        return None

    try:
        return str(
            ipaddress.ip_network(
                texto,
                strict=False,
            )
        )
    except ValueError:
        return texto


def _normalizar_ip(
    valor: Any,
) -> str | None:
    texto = _texto_ou_none(
        valor
    )
    if texto is None:
        return None

    try:
        return str(
            ipaddress.ip_address(
                texto
            )
        )
    except ValueError:
        return texto


def _texto_ou_none(
    valor: Any,
) -> str | None:
    texto = str(
        valor or ""
    ).strip()
    return texto or None


def _inteiro_ou_none(
    valor: Any,
) -> int | None:
    if valor in (
        None,
        "",
    ):
        return None

    try:
        return int(
            valor
        )
    except (
        TypeError,
        ValueError,
    ):
        return None


def _validar_dict_agent(
    valor: Any,
    mensagem: str,
) -> None:
    if not isinstance(
        valor,
        dict,
    ):
        raise AgentRespostaInvalidaErro(
            mensagem
        )


# =============================================================================
# SAFE APPLY
# =============================================================================


def _restaurar_estados_safe_apply(
    protegidas: dict[int, str],
) -> None:
    """Não deixa uma leitura substituir estados transitórios de Safe Apply."""
    if not protegidas:
        return

    for interface in (
        InterfaceRede.objects
        .select_for_update()
        .filter(
            pk__in=protegidas
        )
    ):
        estado = protegidas[
            interface.pk
        ]

        if (
            interface.estado_sincronizacao
            == estado
            and not interface.sincronizada
            and interface.pendente
        ):
            continue

        interface.estado_sincronizacao = (
            estado
        )
        interface.sincronizada = False
        interface.pendente = True

        interface.save(
            update_fields=[
                "estado_sincronizacao",
                "sincronizada",
                "pendente",
                "atualizado_em",
            ]
        )


__all__ = [
    "reconciliar_interfaces",
    "reconciliar_interface",
    "obter_estado_reconciliado",
    "reconciliar_rede",
]
