"""
MoonShield Network
==================

Serviço de interfaces de rede.

Responsabilidades:

    Agent/Linux
        ↓
    inventário real
        ↓
    InterfaceRede
        ↓
    estado desejado x estado observado

Este serviço:

- sincroniza interfaces detectadas;
- preserva configurações desejadas;
- salva WAN/LAN/MGMT/DMZ/CUSTOM;
- monta payload para o Agent;
- identifica divergências.

Este serviço NÃO executa nmcli diretamente.
"""

from __future__ import annotations

from typing import Any

from django.db import transaction
from django.utils import timezone

from rede.dominio.erros import (
    ConfiguracaoRedeInvalidaErro,
    InterfaceNaoEncontradaErro,
)

from rede.dominio.tipos import (
    EstadoLink,
    ModoIPv4,
    PapelInterface,
)

from rede.dominio.validacoes import (
    validar_configuracao_interface,
    validar_nome_interface,
)

from rede.models import (
    InterfaceRede,
)

from rede.services.inventario import (
    obter_inventario,
)


# =============================================================================
# SERIALIZAÇÃO
# =============================================================================


def serializar_interface(
    interface: InterfaceRede,
) -> dict:
    """
    Retorno completo para API/painel.
    """

    return {
        "id": interface.pk,

        # ---------------------------------------------------------------------
        # IDENTIDADE
        # ---------------------------------------------------------------------

        "nome": interface.nome,

        "descricao": (
            interface.descricao
        ),

        "mac_address": (
            interface.mac_address
        ),

        # ---------------------------------------------------------------------
        # CONFIGURAÇÃO DESEJADA
        # ---------------------------------------------------------------------

        "desejado": {
            "papel": interface.papel,

            "principal": (
                interface.principal
            ),

            "habilitada": (
                interface.habilitada
            ),

            "acesso_gerenciamento": (
                interface
                .acesso_gerenciamento
            ),

            "ipv4_modo": (
                interface.ipv4_modo
            ),

            "ipv4_endereco": (
                interface.ipv4_endereco
            ),

            "ipv4_prefixo": (
                interface.ipv4_prefixo
            ),

            "gateway": (
                interface.gateway
            ),

            "rota_padrao": (
                interface.rota_padrao
            ),

            "metrica": (
                interface.metrica
            ),

            "mtu": interface.mtu,
        },

        # ---------------------------------------------------------------------
        # ESTADO REAL
        # ---------------------------------------------------------------------

        "real": {
            "estado_link": (
                interface.estado_link
            ),

            "carrier": (
                interface.carrier
            ),

            "ipv4": (
                interface.ipv4_atual
            ),

            "prefixo": (
                interface.prefixo_atual
            ),

            "gateway": (
                interface.gateway_atual
            ),

            "metrica": (
                interface.metrica_atual
            ),

            "mtu": (
                interface.mtu_atual
            ),

            "backend": (
                interface.backend
            ),

            "conexao_nome": (
                interface.conexao_nome
            ),

            "conexao_uuid": (
                interface.conexao_uuid
            ),
        },

        # ---------------------------------------------------------------------
        # SINCRONIZAÇÃO
        # ---------------------------------------------------------------------

        "sincronizada": (
            interface.sincronizada
        ),

        "pendente": (
            interface.pendente
        ),

        "ultimo_erro": (
            interface.ultimo_erro
        ),

        "detectada_em": (
            interface.detectada_em.isoformat()
            if interface.detectada_em
            else None
        ),

        "aplicada_em": (
            interface.aplicada_em.isoformat()
            if interface.aplicada_em
            else None
        ),

        "criado_em": (
            interface.criado_em.isoformat()
        ),

        "atualizado_em": (
            interface.atualizado_em.isoformat()
        ),
    }


# =============================================================================
# CONSULTAS
# =============================================================================


def listar_interfaces() -> list[dict]:
    """
    Lista interfaces recalculando a flag de sincronização com o último estado
    real conhecido. Isso impede que `pendente=True` antigo sobreviva quando
    desired state e estado observado já são equivalentes.
    """
    queryset = InterfaceRede.objects.all()

    resultado = []
    for interface in queryset:
        _atualizar_flags_sincronizacao(interface, salvar=True)
        resultado.append(serializar_interface(interface))

    return resultado


def obter_interface_por_id(
    interface_id: int,
) -> InterfaceRede:
    try:
        return InterfaceRede.objects.get(
            pk=interface_id
        )

    except InterfaceRede.DoesNotExist as exc:
        raise InterfaceNaoEncontradaErro(
            (
                f"Interface #{interface_id} "
                "não encontrada."
            )
        ) from exc


def obter_interface_por_nome(
    nome: str,
) -> InterfaceRede:
    nome = validar_nome_interface(
        nome
    )

    try:
        return InterfaceRede.objects.get(
            nome=nome
        )

    except InterfaceRede.DoesNotExist as exc:
        raise InterfaceNaoEncontradaErro(
            (
                f"Interface '{nome}' não está "
                "cadastrada no MoonShield."
            )
        ) from exc


# =============================================================================
# INVENTÁRIO → BANCO
# =============================================================================


@transaction.atomic
def sincronizar_inventario(
    inventario: dict | None = None,
) -> list[InterfaceRede]:
    """
    Atualiza o ESTADO REAL das interfaces.

    MUITO IMPORTANTE:

    Esta função NÃO sobrescreve o estado desejado.

    Exemplo:

    Banco:
        enp0s8 deve ser LAN 10.10.0.1/24

    Linux:
        enp0s8 ainda sem IP

    Resultado:
        configuração desejada permanece;
        estado real é atualizado;
        interface fica pendente/divergente.
    """

    if inventario is None:
        inventario = obter_inventario()

    itens = inventario.get(
        "interfaces",
        [],
    )

    backend_global = inventario.get(
        "backend",
        "unknown",
    )

    if not isinstance(
        itens,
        list,
    ):
        itens = []

    agora = timezone.now()

    detectadas: set[str] = set()

    resultado: list[
        InterfaceRede
    ] = []

    for item in itens:
        if not isinstance(
            item,
            dict,
        ):
            continue

        nome = str(
            item.get(
                "name",
                "",
            )
        ).strip()

        if not nome:
            continue

        # loopback jamais será criada como
        # interface administrável.
        if nome == "lo":
            continue

        detectadas.add(
            nome
        )

        interface, criada = (
            InterfaceRede.objects
            .select_for_update()
            .get_or_create(
                nome=nome
            )
        )

        # ---------------------------------------------------------------------
        # IDENTIDADE REAL
        # ---------------------------------------------------------------------

        interface.mac_address = str(
            item.get(
                "mac",
                "",
            )
            or ""
        ).strip()

        # ---------------------------------------------------------------------
        # LINK
        # ---------------------------------------------------------------------

        estado = str(
            item.get(
                "state",
                "unknown",
            )
            or "unknown"
        ).lower()

        if estado not in {
            EstadoLink.UP.value,
            EstadoLink.DOWN.value,
            EstadoLink.DESCONHECIDO.value,
        }:
            estado = (
                EstadoLink.DESCONHECIDO.value
            )

        interface.estado_link = estado

        interface.carrier = item.get(
            "carrier"
        )

        # ---------------------------------------------------------------------
        # IPv4 REAL
        # ---------------------------------------------------------------------

        interface.ipv4_atual = (
            item.get(
                "ipv4"
            )
            or None
        )

        interface.prefixo_atual = (
            item.get(
                "prefix"
            )
        )

        interface.gateway_atual = (
            item.get(
                "gateway"
            )
            or None
        )

        interface.metrica_atual = (
            item.get(
                "metric"
            )
        )

        interface.mtu_atual = (
            item.get(
                "mtu"
            )
        )

        # ---------------------------------------------------------------------
        # BACKEND
        # ---------------------------------------------------------------------

        interface.backend = str(
            item.get(
                "backend",
                backend_global,
            )
            or "unknown"
        )

        interface.conexao_nome = str(
            item.get(
                "connection_name",
                "",
            )
            or ""
        )

        interface.conexao_uuid = str(
            item.get(
                "connection_uuid",
                "",
            )
            or ""
        )

        interface.detectada_em = agora

        # ---------------------------------------------------------------------
        # SINCRONIZAÇÃO
        # ---------------------------------------------------------------------

        _atualizar_flags_sincronizacao(
            interface,
            salvar=False,
        )

        interface.save()

        resultado.append(
            interface
        )

    # =========================================================================
    # INTERFACES QUE SUMIRAM
    # =========================================================================

    existentes = (
        InterfaceRede.objects
        .exclude(
            nome__in=detectadas
        )
        .select_for_update()
    )

    for interface in existentes:
        interface.estado_link = (
            EstadoLink.DESCONHECIDO.value
        )

        interface.carrier = None

        interface.ipv4_atual = None
        interface.prefixo_atual = None
        interface.gateway_atual = None
        interface.metrica_atual = None

        interface.sincronizada = False

        if (
            interface.papel
            != PapelInterface.NAO_ATRIBUIDA.value
        ):
            interface.pendente = True

            interface.ultimo_erro = (
                "Interface não detectada no último inventário."
            )

        interface.save()

    return resultado


# =============================================================================
# COMPARAÇÃO DE ESTADO
# =============================================================================


def _estado_corresponde_desejado(
    interface: InterfaceRede,
) -> bool:
    """
    Comparação conservadora entre PostgreSQL e Linux.
    """

    # Interface ainda não administrada.
    if (
        interface.papel
        == PapelInterface.NAO_ATRIBUIDA.value
    ):
        return True

    # -------------------------------------------------------------------------
    # DESABILITADA
    # -------------------------------------------------------------------------

    if not interface.habilitada:
        return (
            interface.estado_link
            != EstadoLink.UP.value
        )

    # Configuração deseja interface ligada.
    if (
        interface.estado_link
        != EstadoLink.UP.value
    ):
        return False

    # -------------------------------------------------------------------------
    # IPv4 DESABILITADO
    # -------------------------------------------------------------------------

    if (
        interface.ipv4_modo
        == ModoIPv4.DISABLED.value
    ):
        return not bool(
            interface.ipv4_atual
        )

    # -------------------------------------------------------------------------
    # DHCP
    # -------------------------------------------------------------------------

    if (
        interface.ipv4_modo
        == ModoIPv4.DHCP.value
    ):
        # Não exigimos um IP imediato porque DHCP
        # pode estar aguardando lease.
        #
        # Mas se a WAN fornece rota default,
        # esperamos um gateway.
        if (
            interface.rota_padrao
            and not interface.gateway_atual
        ):
            return False

        if (
            interface.mtu_atual is not None
            and interface.mtu
            != interface.mtu_atual
        ):
            return False

        return True

    # -------------------------------------------------------------------------
    # STATIC
    # -------------------------------------------------------------------------

    if (
        interface.ipv4_modo
        == ModoIPv4.STATIC.value
    ):
        if (
            interface.ipv4_endereco
            != interface.ipv4_atual
        ):
            return False

        if (
            interface.ipv4_prefixo
            != interface.prefixo_atual
        ):
            return False

        if (
            interface.gateway
            and interface.gateway
            != interface.gateway_atual
        ):
            return False

        if (
            interface.mtu_atual is not None
            and interface.mtu
            != interface.mtu_atual
        ):
            return False

        return True

    return False


def _atualizar_flags_sincronizacao(
    interface: InterfaceRede,
    *,
    salvar: bool = False,
) -> bool:
    """
    Recalcula sincronizada/pendente usando somente estado desejado x último
    estado real conhecido.

    Papel/descrição/acesso de gerenciamento são metadados do control plane e
    não criam drift Linux por si só. A comparação técnica permanece centralizada
    em `_estado_corresponde_desejado`.
    """
    sincronizada = _estado_corresponde_desejado(interface)
    pendente = (
        False
        if interface.papel == PapelInterface.NAO_ATRIBUIDA.value
        else not sincronizada
    )

    alterou = (
        interface.sincronizada != sincronizada
        or interface.pendente != pendente
    )

    interface.sincronizada = sincronizada
    interface.pendente = pendente

    if sincronizada:
        interface.ultimo_erro = ""

    if salvar and (alterou or sincronizada):
        interface.save(
            update_fields=[
                "sincronizada",
                "pendente",
                "ultimo_erro",
                "atualizado_em",
            ]
        )

    return sincronizada


# =============================================================================
# SALVAR ESTADO DESEJADO
# =============================================================================


@transaction.atomic
def salvar_configuracao_interface(
    nome: str,
    dados: dict[str, Any],
    *,
    inventario: dict | None = None,
    validar_existencia: bool = False,
) -> InterfaceRede:
    """
    Salva configuração desejada.

    NÃO executa nmcli.

    Exemplo:

        salvar_configuracao_interface(
            "enp0s8",
            {
                "papel": "lan",
                "principal": True,
                "ipv4_modo": "static",
                "ipv4_endereco": "10.10.0.1",
                "ipv4_prefixo": 24,
                "gateway": None,
                "rota_padrao": False,
                "metrica": 100,
                "mtu": 1500,
                "habilitada": True,
                "acesso_gerenciamento": True,
            },
        )
    """

    nome = validar_nome_interface(
        nome
    )

    payload = dict(
        dados
    )

    payload[
        "interface"
    ] = nome

    inventario_validacao = None

    if validar_existencia:
        if inventario is None:
            inventario = obter_inventario()

        inventario_validacao = (
            inventario
        )

    normalizado = (
        validar_configuracao_interface(
            payload,
            inventario=(
                inventario_validacao
            ),
        )
    )

    principal = bool(
        dados.get(
            "principal",
            False,
        )
    )

    interface, criada = (
        InterfaceRede.objects
        .select_for_update()
        .get_or_create(
            nome=nome
        )
    )

    novo_papel = normalizado[
        "papel"
    ]

    # =========================================================================
    # PRINCIPAL ÚNICA POR PAPEL
    # =========================================================================

    if principal:
        InterfaceRede.objects.filter(
            papel=novo_papel,
            principal=True,
        ).exclude(
            pk=interface.pk
        ).update(
            principal=False,
            pendente=True,
            sincronizada=False,
        )

    # =========================================================================
    # ROTA DEFAULT ÚNICA
    # =========================================================================

    if normalizado[
        "rota_padrao"
    ]:
        InterfaceRede.objects.filter(
            rota_padrao=True
        ).exclude(
            pk=interface.pk
        ).update(
            rota_padrao=False,
            pendente=True,
            sincronizada=False,
        )

    # =========================================================================
    # CONFIGURAÇÃO
    # =========================================================================

    interface.papel = novo_papel

    interface.principal = (
        principal
    )

    interface.habilitada = (
        normalizado[
            "habilitada"
        ]
    )

    interface.acesso_gerenciamento = (
        normalizado[
            "acesso_gerenciamento"
        ]
    )

    interface.ipv4_modo = (
        normalizado[
            "ipv4_modo"
        ]
    )

    interface.ipv4_endereco = (
        normalizado[
            "ipv4_endereco"
        ]
    )

    interface.ipv4_prefixo = (
        normalizado[
            "ipv4_prefixo"
        ]
    )

    interface.gateway = (
        normalizado[
            "gateway"
        ]
    )

    interface.rota_padrao = (
        normalizado[
            "rota_padrao"
        ]
    )

    interface.metrica = (
        normalizado[
            "metrica"
        ]
    )

    interface.mtu = (
        normalizado[
            "mtu"
        ]
    )

    if "descricao" in dados:
        interface.descricao = str(
            dados.get(
                "descricao",
                "",
            )
            or ""
        ).strip()

    # -------------------------------------------------------------------------
    # SINCRONIZAÇÃO / DRIFT
    # -------------------------------------------------------------------------
    # Salvar o mesmo desired state que já existe no Linux não deve criar uma
    # pendência artificial nem habilitar "Aplicar" sem necessidade.
    interface.sincronizada = _estado_corresponde_desejado(interface)
    interface.pendente = (
        False
        if interface.papel == PapelInterface.NAO_ATRIBUIDA.value
        else not interface.sincronizada
    )
    interface.ultimo_erro = ""

    interface.full_clean()
    interface.save()

    return interface


# =============================================================================
# PAYLOAD INDIVIDUAL
# =============================================================================


def montar_payload_interface(
    interface: InterfaceRede,
) -> dict:
    """
    Formato oficial Django → Agent.
    """

    return {
        "id": interface.pk,

        "interface": (
            interface.nome
        ),

        "papel": (
            interface.papel
        ),

        "principal": (
            interface.principal
        ),

        "habilitada": (
            interface.habilitada
        ),

        "acesso_gerenciamento": (
            interface.acesso_gerenciamento
        ),

        "ipv4": {
            "modo": (
                interface.ipv4_modo
            ),

            "endereco": (
                interface.ipv4_endereco
            ),

            "prefixo": (
                interface.ipv4_prefixo
            ),

            "gateway": (
                interface.gateway
            ),

            "rota_padrao": (
                interface.rota_padrao
            ),

            "metrica": (
                interface.metrica
            ),
        },

        "mtu": interface.mtu,
    }


# =============================================================================
# PAYLOAD COMPLETO
# =============================================================================


def montar_payload_interfaces() -> dict:
    """
    Retorna todas as interfaces administradas pelo MoonShield.

    Interfaces UNASSIGNED não são enviadas para aplicação.
    """

    queryset = (
        InterfaceRede.objects
        .exclude(
            papel=(
                PapelInterface
                .NAO_ATRIBUIDA
                .value
            )
        )
        .order_by(
            "papel",
            "-principal",
            "nome",
        )
    )

    return {
        "interfaces": [
            montar_payload_interface(
                interface
            )
            for interface in queryset
        ]
    }


# =============================================================================
# STATUS
# =============================================================================


def marcar_interface_sincronizada(
    interface: InterfaceRede,
) -> None:
    interface.sincronizada = True
    interface.pendente = False
    interface.ultimo_erro = ""
    interface.aplicada_em = timezone.now()

    interface.save(
        update_fields=[
            "sincronizada",
            "pendente",
            "ultimo_erro",
            "aplicada_em",
            "atualizado_em",
        ]
    )


def marcar_interface_erro(
    interface: InterfaceRede,
    erro: str,
) -> None:
    interface.sincronizada = False
    interface.pendente = True

    interface.ultimo_erro = str(
        erro or ""
    )

    interface.save(
        update_fields=[
            "sincronizada",
            "pendente",
            "ultimo_erro",
            "atualizado_em",
        ]
    )