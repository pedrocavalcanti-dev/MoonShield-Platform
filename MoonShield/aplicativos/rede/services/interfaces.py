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

from ipaddress import IPv4Interface
from typing import Any

from django.db import transaction
from django.utils import timezone

from rede.dominio.erros import (
    ConfiguracaoRedeInvalidaErro,
    InterfaceNaoEncontradaErro,
)

from rede.dominio.tipos import (
    EstadoLink,
    EstadoSincronizacao,
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

            "enderecos_ipv4": interface.enderecos_ipv4 or [],

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

        "estado_sincronizacao": interface.estado_sincronizacao,

        "revisao_desejada": interface.revisao_desejada,

        "revisao_aplicada": interface.revisao_aplicada,

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

        nome = str(item.get("nome", item.get("name", "")) or "").strip()

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
            item.get("mac_address", item.get("mac", "")) or ""
        ).strip()

        # ---------------------------------------------------------------------
        # LINK
        # ---------------------------------------------------------------------

        estado = str(
            item.get("estado_link", item.get("state", "unknown"))
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

        interface.carrier = item.get("carrier")

        # ---------------------------------------------------------------------
        # IPv4 REAL
        # ---------------------------------------------------------------------

        enderecos_ipv4 = _normalizar_enderecos_ipv4(item)
        interface.enderecos_ipv4 = enderecos_ipv4
        interface.ipv4_atual = item.get("ipv4_atual") or _ipv4_sem_prefixo(
            enderecos_ipv4[0] if enderecos_ipv4 else None
        )
        interface.prefixo_atual = item.get("prefixo_atual", item.get("prefix"))
        if interface.prefixo_atual is None and enderecos_ipv4:
            interface.prefixo_atual = _prefixo_ipv4(enderecos_ipv4[0])

        interface.gateway_atual = item.get("gateway_atual", item.get("gateway")) or None
        interface.metrica_atual = item.get("metrica_atual", item.get("metric"))
        interface.mtu_atual = item.get("mtu_atual", item.get("mtu"))

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

        interface.conexao_nome = str(item.get("conexao", item.get("connection_name", "")) or "")
        interface.conexao_uuid = str(item.get("connection_uuid", "") or "")

        interface.detectada_em = agora

        if interface.estado_sincronizacao == EstadoSincronizacao.MISSING.value:
            interface.estado_sincronizacao = ""

        # ---------------------------------------------------------------------
        # SINCRONIZAÇÃO
        # ---------------------------------------------------------------------

        _atualizar_estado_sincronizacao(interface, salvar=False)

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

        interface.enderecos_ipv4 = []
        interface.ipv4_atual = None
        interface.prefixo_atual = None
        interface.gateway_atual = None
        interface.metrica_atual = None

        if interface.papel == PapelInterface.NAO_ATRIBUIDA.value:
            interface.estado_sincronizacao = EstadoSincronizacao.UNMANAGED.value
            interface.sincronizada = False
            interface.pendente = False
            interface.ultimo_erro = ""
        else:
            interface.estado_sincronizacao = EstadoSincronizacao.MISSING.value
            interface.sincronizada = False
            interface.pendente = True
            interface.ultimo_erro = ""

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
            interface.enderecos_ipv4 or interface.ipv4_atual
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
        if interface.enderecos_ipv4:
            cidrs_observados = set()
            for endereco in _normalizar_enderecos_ipv4({"enderecos_ipv4": interface.enderecos_ipv4}):
                if "/" not in endereco:
                    continue
                try:
                    cidrs_observados.add(str(IPv4Interface(endereco.strip())))
                except ValueError:
                    continue
            cidr_desejado = f"{interface.ipv4_endereco}/{interface.ipv4_prefixo}"
            if cidr_desejado not in cidrs_observados:
                return False
        elif (
            interface.ipv4_endereco != interface.ipv4_atual
            or interface.ipv4_prefixo != interface.prefixo_atual
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
    return _atualizar_estado_sincronizacao(interface, salvar=salvar)


def _atualizar_estado_sincronizacao(
    interface: InterfaceRede,
    *,
    salvar: bool = False,
) -> bool:
    """Calcula o estado explícito e mantém os booleanos legados."""
    corresponde = _estado_corresponde_desejado(interface)

    if interface.papel == PapelInterface.NAO_ATRIBUIDA.value:
        estado = EstadoSincronizacao.UNMANAGED.value
    elif interface.estado_sincronizacao == EstadoSincronizacao.MISSING.value:
        estado = EstadoSincronizacao.MISSING.value
    elif interface.ultimo_erro and not corresponde:
        estado = EstadoSincronizacao.ERROR.value
    elif interface.estado_sincronizacao in {
        EstadoSincronizacao.APPLYING.value,
        EstadoSincronizacao.WAITING_CONFIRMATION.value,
    }:
        estado = interface.estado_sincronizacao
    elif interface.revisao_desejada > interface.revisao_aplicada:
        estado = EstadoSincronizacao.PENDING_APPLY.value
    elif corresponde:
        estado = EstadoSincronizacao.SYNCED.value
    else:
        estado = EstadoSincronizacao.DRIFTED.value

    sincronizada = estado == EstadoSincronizacao.SYNCED.value
    pendente = (
        False
        if interface.papel == PapelInterface.NAO_ATRIBUIDA.value
        else not sincronizada
    )

    alterou = (
        interface.estado_sincronizacao != estado
        or interface.sincronizada != sincronizada
        or interface.pendente != pendente
    )

    interface.estado_sincronizacao = estado
    interface.sincronizada = sincronizada
    interface.pendente = pendente

    if sincronizada and interface.ultimo_erro:
        interface.ultimo_erro = ""

    if salvar and (alterou or sincronizada):
        interface.save(
            update_fields=[
                "estado_sincronizacao",
                "sincronizada",
                "pendente",
                "ultimo_erro",
                "atualizado_em",
            ]
        )

    return sincronizada


def _normalizar_enderecos_ipv4(item: dict) -> list[str]:
    """Aceita inventário atual do Agent e o formato legado do Django."""
    bruto = item.get("ipv4")
    if bruto is None:
        bruto = item.get("enderecos_ipv4", item.get("addresses", []))
    if isinstance(bruto, str):
        bruto = [bruto]
    if not isinstance(bruto, list):
        bruto = []

    resultado = []
    for endereco in bruto:
        if isinstance(endereco, dict):
            valor = endereco.get("endereco", endereco.get("address", endereco.get("ip")))
            prefixo = endereco.get("prefixo", endereco.get("prefix"))
            if valor and prefixo is not None and "/" not in str(valor):
                valor = f"{valor}/{prefixo}"
        else:
            valor = endereco
        if valor and ":" not in str(valor):
            resultado.append(str(valor))
    return resultado


def _ipv4_sem_prefixo(endereco: str | None) -> str | None:
    return str(endereco).split("/", 1)[0] if endereco else None


def _prefixo_ipv4(endereco: str | None) -> int | None:
    if not endereco or "/" not in str(endereco):
        return None
    try:
        return int(str(endereco).rsplit("/", 1)[1])
    except (TypeError, ValueError):
        return None


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

    interface, criada = (
        InterfaceRede.objects
        .select_for_update()
        .get_or_create(
            nome=nome
        )
    )

    desejado_anterior = (
        interface.habilitada,
        interface.ipv4_modo,
        interface.ipv4_endereco,
        interface.ipv4_prefixo,
        interface.gateway,
        interface.rota_padrao,
        interface.metrica,
        interface.mtu,
    )

    principal = bool(
        dados.get(
            "principal",
            False,
        )
    )

    novo_papel = normalizado[
        "papel"
    ]

    # =========================================================================
    # PRINCIPAL ÚNICA POR PAPEL
    # =========================================================================

    if principal:
        outras_principais = InterfaceRede.objects.select_for_update().filter(
            papel=novo_papel,
            principal=True,
        ).exclude(
            pk=interface.pk
        )
        for outra in outras_principais:
            outra.principal = False
            # Metadado: preserva as revisões operacionais e recalcula os flags.
            _atualizar_estado_sincronizacao(outra, salvar=False)
            outra.save()

    # =========================================================================
    # ROTA DEFAULT ÚNICA
    # =========================================================================

    if normalizado[
        "rota_padrao"
    ]:
        outras_rotas_default = InterfaceRede.objects.select_for_update().filter(
            rota_padrao=True
        ).exclude(
            pk=interface.pk
        )
        for outra in outras_rotas_default:
            outra.rota_padrao = False
            outra.revisao_desejada += 1
            _atualizar_estado_sincronizacao(outra, salvar=False)
            outra.save()

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
    # Somente mudanças operacionais exigem uma nova aplicação no Agent.
    # Papel, principal, acesso de gerenciamento e descrição são metadados.
    desejado_novo = (
        normalizado["habilitada"],
        normalizado["ipv4_modo"],
        normalizado["ipv4_endereco"],
        normalizado["ipv4_prefixo"],
        normalizado["gateway"],
        normalizado["rota_padrao"],
        normalizado["metrica"],
        normalizado["mtu"],
    )
    if desejado_anterior != desejado_novo:
        interface.revisao_desejada += 1

    interface.ultimo_erro = ""
    _atualizar_estado_sincronizacao(interface, salvar=False)

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
    interface.estado_sincronizacao = EstadoSincronizacao.SYNCED.value
    interface.sincronizada = True
    interface.pendente = False
    interface.ultimo_erro = ""
    interface.revisao_aplicada = interface.revisao_desejada
    interface.aplicada_em = timezone.now()

    interface.save(
        update_fields=[
            "sincronizada",
            "pendente",
            "ultimo_erro",
            "estado_sincronizacao",
            "revisao_aplicada",
            "aplicada_em",
            "atualizado_em",
        ]
    )


def marcar_interface_erro(
    interface: InterfaceRede,
    erro: str,
) -> None:
    interface.estado_sincronizacao = EstadoSincronizacao.ERROR.value
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
            "estado_sincronizacao",
            "atualizado_em",
        ]
    )
