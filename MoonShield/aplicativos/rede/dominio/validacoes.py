"""
MoonShield Network
==================

Validações puras do domínio de Rede.

Este módulo:

    ✓ valida IP
    ✓ valida CIDR
    ✓ valida gateway
    ✓ valida prefixo
    ✓ valida MTU
    ✓ valida métrica
    ✓ valida papel
    ✓ valida modo IPv4
    ✓ valida interface
    ✓ valida configuração completa
    ✓ detecta conflito/sobreposição de redes
    ✓ valida topologia WAN/LAN

Este módulo NÃO:

    ✗ executa nmcli
    ✗ executa ip
    ✗ executa nft
    ✗ acessa banco
    ✗ conversa com Agent
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping
from typing import Any


from .constantes import (
    INTERFACES_IGNORADAS,
    METRICA_MAXIMA,
    METRICA_MINIMA,
    MTU_MAXIMO,
    MTU_MINIMO,
    NOME_INTERFACE_MAXIMO,
    PAPEIS_COM_ROTA_DEFAULT,
    TEMPO_CONFIRMACAO_MAXIMO,
    TEMPO_CONFIRMACAO_MINIMO,
)

from .erros import (
    CIDRInvalidoErro,
    ConfiguracaoRedeInvalidaErro,
    ConflitoInterfaceErro,
    GatewayInvalidoErro,
    InterfaceInvalidaErro,
    InterfaceNaoEncontradaErro,
    IPv4InvalidoErro,
    MetricaInvalidaErro,
    ModoIPv4InvalidoErro,
    MTUInvalidoErro,
    PapelInterfaceInvalidoErro,
    PrefixoIPv4InvalidoErro,
    TopologiaInvalidaErro,
)

from .tipos import (
    ModoIPv4,
    PapelInterface,
    enum_ou_none,
)


# =============================================================================
# REGEX
# =============================================================================


_RE_NOME_INTERFACE = re.compile(
    r"^[A-Za-z0-9_.:@-]+$"
)


# =============================================================================
# HELPERS
# =============================================================================


def _texto(valor: Any) -> str:
    """
    Normaliza valor textual.
    """

    if valor is None:
        return ""

    return str(valor).strip()


def _bool(valor: Any) -> bool:
    """
    Conversão simples e previsível para boolean.
    """

    if isinstance(valor, bool):
        return valor

    if isinstance(valor, int):
        return valor != 0

    texto = _texto(valor).lower()

    return texto in {
        "1",
        "true",
        "yes",
        "sim",
        "on",
    }


def _inteiro(
    valor: Any,
    *,
    nome: str,
) -> int:
    """
    Converte valor para int ou dispara erro genérico de configuração.
    """

    try:
        return int(valor)
    except (TypeError, ValueError):
        raise ConfiguracaoRedeInvalidaErro(
            f"{nome} deve ser um número inteiro."
        )


# =============================================================================
# INTERFACE
# =============================================================================


def normalizar_nome_interface(
    nome: Any,
) -> str:
    return _texto(nome)


def validar_nome_interface(
    nome: Any,
) -> str:
    """
    Valida somente o formato do nome da interface.

    Não verifica se ela existe no Linux.
    """

    nome = normalizar_nome_interface(
        nome
    )

    if not nome:
        raise InterfaceInvalidaErro(
            "Nome da interface não informado."
        )

    if len(nome) > NOME_INTERFACE_MAXIMO:
        raise InterfaceInvalidaErro(
            (
                "Nome da interface excede "
                f"{NOME_INTERFACE_MAXIMO} caracteres."
            )
        )

    if nome in INTERFACES_IGNORADAS:
        raise InterfaceInvalidaErro(
            (
                f"A interface '{nome}' não pode ser "
                "administrada como interface de rede."
            )
        )

    if not _RE_NOME_INTERFACE.fullmatch(
        nome
    ):
        raise InterfaceInvalidaErro(
            (
                f"Nome de interface inválido: "
                f"'{nome}'."
            )
        )

    return nome


def extrair_nomes_inventario(
    inventario: Any,
) -> set[str]:
    """
    Extrai nomes de interface de diferentes formatos.

    Aceita:

        ["enp0s3", "enp0s8"]

    ou:

        [
            {"name": "enp0s3"},
            {"name": "enp0s8"},
        ]

    ou:

        {
            "interfaces": [
                {"name": "enp0s3"},
                {"name": "enp0s8"},
            ]
        }

    Também entende a chave "nome".
    """

    if inventario is None:
        return set()

    if isinstance(
        inventario,
        Mapping,
    ):
        if "interfaces" in inventario:
            inventario = (
                inventario["interfaces"]
            )
        else:
            inventario = [
                inventario
            ]

    if isinstance(
        inventario,
        str,
    ):
        inventario = [
            inventario
        ]

    nomes: set[str] = set()

    try:
        itens = list(
            inventario
        )
    except TypeError:
        return nomes

    for item in itens:
        nome = ""

        if isinstance(
            item,
            str,
        ):
            nome = item

        elif isinstance(
            item,
            Mapping,
        ):
            nome = (
                item.get("name")
                or item.get("nome")
                or item.get("interface")
                or ""
            )

        nome = _texto(
            nome
        )

        if nome:
            nomes.add(
                nome
            )

    return nomes


def validar_interface_existe(
    nome: Any,
    inventario: Any,
) -> str:
    """
    Confirma que uma interface está presente no inventário
    devolvido pelo Agent.
    """

    nome = validar_nome_interface(
        nome
    )

    existentes = extrair_nomes_inventario(
        inventario
    )

    if nome not in existentes:
        raise InterfaceNaoEncontradaErro(
            (
                f"Interface '{nome}' não encontrada "
                "no sistema."
            ),
            detalhes={
                "interface": nome,
                "disponiveis": sorted(
                    existentes
                ),
            },
        )

    return nome


# =============================================================================
# PAPEL
# =============================================================================


def validar_papel_interface(
    valor: Any,
) -> PapelInterface:
    papel = enum_ou_none(
        valor,
        PapelInterface,
    )

    if papel is None:
        raise PapelInterfaceInvalidoErro(
            f"Papel de interface inválido: '{valor}'."
        )

    return papel


# =============================================================================
# MODO IPv4
# =============================================================================


def validar_modo_ipv4(
    valor: Any,
) -> ModoIPv4:
    modo = enum_ou_none(
        valor,
        ModoIPv4,
    )

    if modo is None:
        raise ModoIPv4InvalidoErro(
            f"Modo IPv4 inválido: '{valor}'."
        )

    return modo


# =============================================================================
# IPv4
# =============================================================================


def validar_ipv4(
    valor: Any,
    *,
    obrigatorio: bool = True,
) -> str | None:
    """
    Valida IPv4 sem prefixo.
    """

    texto = _texto(
        valor
    )

    if not texto:
        if obrigatorio:
            raise IPv4InvalidoErro(
                "Endereço IPv4 não informado."
            )

        return None

    try:
        endereco = ipaddress.IPv4Address(
            texto
        )
    except ipaddress.AddressValueError:
        raise IPv4InvalidoErro(
            f"Endereço IPv4 inválido: '{texto}'."
        )

    return str(
        endereco
    )


def validar_prefixo_ipv4(
    valor: Any,
    *,
    obrigatorio: bool = True,
) -> int | None:
    """
    Prefixos IPv4 válidos:

        0 até 32
    """

    if valor in (
        None,
        "",
    ):
        if obrigatorio:
            raise PrefixoIPv4InvalidoErro(
                "Prefixo IPv4 não informado."
            )

        return None

    try:
        prefixo = int(
            valor
        )
    except (TypeError, ValueError):
        raise PrefixoIPv4InvalidoErro(
            f"Prefixo IPv4 inválido: '{valor}'."
        )

    if not 0 <= prefixo <= 32:
        raise PrefixoIPv4InvalidoErro(
            (
                "Prefixo IPv4 deve estar "
                "entre 0 e 32."
            )
        )

    return prefixo


def validar_cidr(
    valor: Any,
    *,
    obrigatorio: bool = True,
) -> str | None:
    """
    Aceita:

        10.10.0.0/24

    Também normaliza:

        10.10.0.15/24

    para:

        10.10.0.0/24
    """

    texto = _texto(
        valor
    )

    if not texto:
        if obrigatorio:
            raise CIDRInvalidoErro(
                "Rede CIDR não informada."
            )

        return None

    try:
        rede = ipaddress.IPv4Network(
            texto,
            strict=False,
        )
    except ValueError:
        raise CIDRInvalidoErro(
            f"Rede CIDR inválida: '{texto}'."
        )

    return str(
        rede
    )


def construir_rede_ipv4(
    endereco: Any,
    prefixo: Any,
) -> ipaddress.IPv4Network:
    """
    Retorna objeto IPv4Network correspondente
    ao endereço/prefixo.
    """

    ip = validar_ipv4(
        endereco
    )

    pref = validar_prefixo_ipv4(
        prefixo
    )

    return ipaddress.IPv4Network(
        f"{ip}/{pref}",
        strict=False,
    )


# =============================================================================
# GATEWAY
# =============================================================================


def validar_gateway(
    gateway: Any,
    *,
    endereco: Any = None,
    prefixo: Any = None,
    obrigatorio: bool = False,
) -> str | None:
    """
    Valida gateway.

    Se endereço + prefixo forem informados,
    confirma que o gateway pertence à mesma rede.
    """

    texto = _texto(
        gateway
    )

    if not texto:
        if obrigatorio:
            raise GatewayInvalidoErro(
                "Gateway não informado."
            )

        return None

    try:
        gateway_ip = (
            ipaddress.IPv4Address(
                texto
            )
        )
    except ipaddress.AddressValueError:
        raise GatewayInvalidoErro(
            f"Gateway inválido: '{texto}'."
        )

    if (
        endereco not in (
            None,
            "",
        )
        and prefixo not in (
            None,
            "",
        )
    ):
        rede = construir_rede_ipv4(
            endereco,
            prefixo,
        )

        if gateway_ip not in rede:
            raise GatewayInvalidoErro(
                (
                    f"Gateway {gateway_ip} não pertence "
                    f"à rede {rede}."
                ),
                detalhes={
                    "gateway": str(
                        gateway_ip
                    ),
                    "rede": str(
                        rede
                    ),
                },
            )

        if gateway_ip == rede.network_address:
            raise GatewayInvalidoErro(
                (
                    f"Gateway {gateway_ip} é o endereço "
                    "da própria rede."
                )
            )

        if gateway_ip == rede.broadcast_address:
            raise GatewayInvalidoErro(
                (
                    f"Gateway {gateway_ip} é o endereço "
                    "de broadcast da rede."
                )
            )

    return str(
        gateway_ip
    )


# =============================================================================
# MTU
# =============================================================================


def validar_mtu(
    valor: Any,
) -> int:
    try:
        mtu = int(
            valor
        )
    except (TypeError, ValueError):
        raise MTUInvalidoErro(
            f"MTU inválido: '{valor}'."
        )

    if not MTU_MINIMO <= mtu <= MTU_MAXIMO:
        raise MTUInvalidoErro(
            (
                f"MTU deve estar entre "
                f"{MTU_MINIMO} e {MTU_MAXIMO}."
            )
        )

    return mtu


# =============================================================================
# MÉTRICA
# =============================================================================


def validar_metrica(
    valor: Any,
) -> int:
    try:
        metrica = int(
            valor
        )
    except (TypeError, ValueError):
        raise MetricaInvalidaErro(
            f"Métrica inválida: '{valor}'."
        )

    if not (
        METRICA_MINIMA
        <= metrica
        <= METRICA_MAXIMA
    ):
        raise MetricaInvalidaErro(
            (
                "Métrica deve estar entre "
                f"{METRICA_MINIMA} e "
                f"{METRICA_MAXIMA}."
            )
        )

    return metrica


# =============================================================================
# TEMPO DE CONFIRMAÇÃO
# =============================================================================


def validar_tempo_confirmacao(
    valor: Any,
) -> int:
    tempo = _inteiro(
        valor,
        nome="Tempo de confirmação",
    )

    if not (
        TEMPO_CONFIRMACAO_MINIMO
        <= tempo
        <= TEMPO_CONFIRMACAO_MAXIMO
    ):
        raise ConfiguracaoRedeInvalidaErro(
            (
                "Tempo de confirmação deve estar "
                f"entre {TEMPO_CONFIRMACAO_MINIMO} "
                f"e {TEMPO_CONFIRMACAO_MAXIMO} segundos."
            )
        )

    return tempo


# =============================================================================
# CONFIGURAÇÃO COMPLETA DE INTERFACE
# =============================================================================


def validar_configuracao_interface(
    config: Mapping[str, Any],
    *,
    inventario: Any = None,
) -> dict:
    """
    Valida e normaliza configuração desejada de uma interface.

    Entrada esperada:

        {
            "interface": "enp0s8",
            "papel": "lan",
            "ipv4_modo": "static",
            "ipv4_endereco": "10.10.0.1",
            "ipv4_prefixo": 24,
            "gateway": None,
            "rota_padrao": False,
            "metrica": 100,
            "mtu": 1500,
            "habilitada": True,
            "acesso_gerenciamento": True,
        }

    Retorna um NOVO dict normalizado.
    """

    if not isinstance(
        config,
        Mapping,
    ):
        raise ConfiguracaoRedeInvalidaErro(
            "Configuração da interface deve ser um objeto."
        )

    nome = (
        config.get("interface")
        or config.get("nome")
    )

    nome = validar_nome_interface(
        nome
    )

    if inventario is not None:
        validar_interface_existe(
            nome,
            inventario,
        )

    papel = validar_papel_interface(
        config.get(
            "papel",
            PapelInterface.NAO_ATRIBUIDA.value,
        )
    )

    modo = validar_modo_ipv4(
        config.get(
            "ipv4_modo",
            ModoIPv4.DHCP.value,
        )
    )

    habilitada = _bool(
        config.get(
            "habilitada",
            True,
        )
    )

    acesso_gerenciamento = _bool(
        config.get(
            "acesso_gerenciamento",
            False,
        )
    )

    rota_padrao = _bool(
        config.get(
            "rota_padrao",
            False,
        )
    )

    metrica = validar_metrica(
        config.get(
            "metrica",
            100,
        )
    )

    mtu = validar_mtu(
        config.get(
            "mtu",
            1500,
        )
    )

    endereco = None
    prefixo = None
    gateway = None

    # -------------------------------------------------------------------------
    # INTERFACE DESABILITADA
    # -------------------------------------------------------------------------

    if (
        modo
        == ModoIPv4.DISABLED
    ):
        if rota_padrao:
            raise ConfiguracaoRedeInvalidaErro(
                (
                    "Interface IPv4 desativada não "
                    "pode fornecer rota padrão."
                )
            )

    # -------------------------------------------------------------------------
    # DHCP
    # -------------------------------------------------------------------------

    elif (
        modo
        == ModoIPv4.DHCP
    ):
        # Em DHCP, endereço e prefixo são obtidos
        # pelo backend/servidor DHCP.
        endereco = None
        prefixo = None

        # Gateway configurado manualmente em perfil DHCP
        # não é permitido nesta primeira versão.
        if _texto(
            config.get("gateway")
        ):
            raise ConfiguracaoRedeInvalidaErro(
                (
                    "Gateway manual não deve ser informado "
                    "quando a interface utiliza DHCP."
                )
            )

    # -------------------------------------------------------------------------
    # STATIC
    # -------------------------------------------------------------------------

    elif (
        modo
        == ModoIPv4.STATIC
    ):
        endereco = validar_ipv4(
            config.get(
                "ipv4_endereco"
            )
        )

        prefixo = validar_prefixo_ipv4(
            config.get(
                "ipv4_prefixo"
            )
        )

        gateway = validar_gateway(
            config.get(
                "gateway"
            ),
            endereco=endereco,
            prefixo=prefixo,
            obrigatorio=False,
        )

    # -------------------------------------------------------------------------
    # ROTA DEFAULT
    # -------------------------------------------------------------------------

    if rota_padrao:
        if (
            papel.value
            not in PAPEIS_COM_ROTA_DEFAULT
        ):
            raise ConfiguracaoRedeInvalidaErro(
                (
                    "Somente uma interface WAN pode "
                    "fornecer rota padrão na V1."
                ),
                detalhes={
                    "interface": nome,
                    "papel": papel.value,
                },
            )

    # -------------------------------------------------------------------------
    # GATEWAY EM INTERFACE NÃO WAN
    # -------------------------------------------------------------------------

    if (
        gateway
        and papel != PapelInterface.WAN
    ):
        raise ConfiguracaoRedeInvalidaErro(
            (
                "Gateway de interface é permitido somente "
                "em WAN nesta versão do MoonShield."
            ),
            detalhes={
                "interface": nome,
                "papel": papel.value,
                "gateway": gateway,
            },
        )

    # -------------------------------------------------------------------------
    # RESULTADO
    # -------------------------------------------------------------------------

    return {
        "interface": nome,
        "papel": papel.value,
        "ipv4_modo": modo.value,
        "ipv4_endereco": endereco,
        "ipv4_prefixo": prefixo,
        "gateway": gateway,
        "rota_padrao": rota_padrao,
        "metrica": metrica,
        "mtu": mtu,
        "habilitada": habilitada,
        "acesso_gerenciamento": (
            acesso_gerenciamento
        ),
    }


# =============================================================================
# TOPOLOGIA
# =============================================================================


def validar_topologia_interfaces(
    interfaces: Iterable[
        Mapping[str, Any]
    ],
    *,
    exigir_wan_lan: bool = False,
) -> list[dict]:
    """
    Valida um conjunto completo de interfaces.

    Regras:

        - interface não pode aparecer duas vezes;
        - somente uma interface principal por papel gerenciado;
        - apenas uma rota default;
        - redes IPv4 estáticas não podem se sobrepor;
        - opcionalmente exige WAN + LAN.

    Retorna todas as configurações normalizadas.
    """

    normalizadas: list[dict] = []

    nomes: set[str] = set()

    for config in interfaces:
        item = validar_configuracao_interface(
            config
        )

        nome = item["interface"]

        if nome in nomes:
            raise ConflitoInterfaceErro(
                (
                    f"Interface '{nome}' aparece mais "
                    "de uma vez na configuração."
                )
            )

        nomes.add(
            nome
        )

        # Mantém campo principal se enviado.
        item["principal"] = _bool(
            config.get(
                "principal",
                False,
            )
        )

        normalizadas.append(
            item
        )

    # -------------------------------------------------------------------------
    # PRINCIPAIS
    # -------------------------------------------------------------------------

    wan_principais = [
        item
        for item in normalizadas
        if (
            item["papel"]
            == PapelInterface.WAN.value
            and item["principal"]
        )
    ]

    lan_principais = [
        item
        for item in normalizadas
        if (
            item["papel"]
            == PapelInterface.LAN.value
            and item["principal"]
        )
    ]

    if len(
        wan_principais
    ) > 1:
        raise TopologiaInvalidaErro(
            "Existe mais de uma WAN principal."
        )

    if len(
        lan_principais
    ) > 1:
        raise TopologiaInvalidaErro(
            "Existe mais de uma LAN principal."
        )

    for item in normalizadas:
        if (
            item["papel"] == PapelInterface.NAO_ATRIBUIDA.value
            and item["principal"]
        ):
            raise TopologiaInvalidaErro(
                "Interface não atribuída não pode ser principal."
            )

    for papel in (
        PapelInterface.MGMT.value,
        PapelInterface.DMZ.value,
        PapelInterface.CUSTOM.value,
    ):
        principais = [
            item
            for item in normalizadas
            if item["papel"] == papel and item["principal"]
        ]

        if len(principais) > 1:
            raise TopologiaInvalidaErro(
                f"Existe mais de uma interface principal com papel '{papel}'."
            )

    # -------------------------------------------------------------------------
    # ROTA DEFAULT
    # -------------------------------------------------------------------------

    defaults = [
        item
        for item in normalizadas
        if item["rota_padrao"]
    ]

    if len(
        defaults
    ) > 1:
        raise TopologiaInvalidaErro(
            (
                "Somente uma interface pode possuir "
                "rota padrão na V1."
            )
        )

    # -------------------------------------------------------------------------
    # WAN/LAN OBRIGATÓRIAS
    # -------------------------------------------------------------------------

    if exigir_wan_lan:
        possui_wan = any(
            item["papel"]
            == PapelInterface.WAN.value
            for item in normalizadas
        )

        possui_lan = any(
            item["papel"]
            == PapelInterface.LAN.value
            for item in normalizadas
        )

        faltando = []

        if not possui_wan:
            faltando.append(
                "WAN"
            )

        if not possui_lan:
            faltando.append(
                "LAN"
            )

        if faltando:
            raise TopologiaInvalidaErro(
                (
                    "Topologia incompleta. "
                    "Interfaces obrigatórias ausentes: "
                    + ", ".join(
                        faltando
                    )
                )
            )

    # -------------------------------------------------------------------------
    # SOBREPOSIÇÃO DE REDES
    # -------------------------------------------------------------------------

    validar_sobreposicao_redes(
        normalizadas
    )

    return normalizadas


# =============================================================================
# CONFLITO DE REDES
# =============================================================================


def validar_sobreposicao_redes(
    interfaces: Iterable[
        Mapping[str, Any]
    ],
) -> None:
    """
    Impede configurações como:

        WAN
        192.168.0.100/24

        LAN
        192.168.0.1/24

    pois ambas pertencem à mesma rede.

    Exemplo correto:

        WAN
        192.168.0.100/24

        LAN
        10.10.0.1/24
    """

    redes: list[
        tuple[
            str,
            ipaddress.IPv4Network,
        ]
    ] = []

    for config in interfaces:
        modo = (
            config.get(
                "ipv4_modo"
            )
        )

        if (
            modo
            != ModoIPv4.STATIC.value
        ):
            continue

        endereco = config.get(
            "ipv4_endereco"
        )

        prefixo = config.get(
            "ipv4_prefixo"
        )

        if (
            not endereco
            or prefixo is None
        ):
            continue

        rede = construir_rede_ipv4(
            endereco,
            prefixo,
        )

        nome = _texto(
            config.get(
                "interface"
            )
            or config.get(
                "nome"
            )
        )

        redes.append(
            (
                nome,
                rede,
            )
        )

    for indice, (
        iface_a,
        rede_a,
    ) in enumerate(
        redes
    ):
        for (
            iface_b,
            rede_b,
        ) in redes[
            indice + 1:
        ]:
            if rede_a.overlaps(
                rede_b
            ):
                raise ConflitoInterfaceErro(
                    (
                        "As redes configuradas se sobrepõem: "
                        f"{iface_a} ({rede_a}) e "
                        f"{iface_b} ({rede_b})."
                    ),
                    detalhes={
                        "interface_a": iface_a,
                        "rede_a": str(
                            rede_a
                        ),
                        "interface_b": iface_b,
                        "rede_b": str(
                            rede_b
                        ),
                    },
                )


# =============================================================================
# ROTA ESTÁTICA
# =============================================================================


def validar_rota_estatica(
    config: Mapping[str, Any],
) -> dict:
    """
    Valida uma rota estática.

    Exemplo:

        {
            "destino": "10.20.0.0/16",
            "gateway": "10.10.0.254",
            "interface": "enp0s8",
            "metrica": 100,
        }
    """

    if not isinstance(
        config,
        Mapping,
    ):
        raise ConfiguracaoRedeInvalidaErro(
            "Configuração de rota inválida."
        )

    destino = validar_cidr(
        config.get(
            "destino"
        )
    )

    gateway = validar_gateway(
        config.get(
            "gateway"
        ),
        obrigatorio=False,
    )

    interface = _texto(
        config.get(
            "interface"
        )
    )

    if interface:
        interface = validar_nome_interface(
            interface
        )

    if (
        not gateway
        and not interface
    ):
        raise ConfiguracaoRedeInvalidaErro(
            (
                "Rota estática deve possuir gateway "
                "ou interface de saída."
            )
        )

    metrica = validar_metrica(
        config.get(
            "metrica",
            100,
        )
    )

    return {
        "destino": destino,
        "gateway": gateway,
        "interface": interface or None,
        "metrica": metrica,
        "ativa": _bool(
            config.get(
                "ativa",
                True,
            )
        ),
    }


# =============================================================================
# NAT
# =============================================================================


def validar_nat_masquerade(
    config: Mapping[str, Any],
) -> dict:
    """
    Valida NAT MASQUERADE.

    Entrada:

        {
            "interface_origem": "enp0s8",
            "interface_saida": "enp0s3",
            "origem_cidr": "10.10.0.0/24",
            "ativa": True,
        }
    """

    if not isinstance(
        config,
        Mapping,
    ):
        raise ConfiguracaoRedeInvalidaErro(
            "Configuração NAT inválida."
        )

    origem = validar_nome_interface(
        config.get(
            "interface_origem"
        )
    )

    saida = validar_nome_interface(
        config.get(
            "interface_saida"
        )
    )

    if origem == saida:
        raise ConflitoInterfaceErro(
            (
                "Interface de origem e interface "
                "de saída do NAT não podem ser iguais."
            )
        )

    origem_cidr = validar_cidr(
        config.get(
            "origem_cidr"
        ),
        obrigatorio=False,
    )

    return {
        "tipo": "masquerade",
        "interface_origem": origem,
        "interface_saida": saida,
        "origem_cidr": origem_cidr or "",
        "ativa": _bool(
            config.get(
                "ativa",
                True,
            )
        ),
    }
