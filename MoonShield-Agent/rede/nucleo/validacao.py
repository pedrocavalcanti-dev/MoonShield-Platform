"""
MoonShield Agent — Rede / Validação
===================================

Validação técnica de alterações antes de qualquer modificação no Linux.

O Agent não decide WAN/LAN/MGMT. Os papéis e regras de negócio pertencem ao
Django. Aqui são verificadas apenas segurança técnica, formato, interfaces,
endereçamento, rotas, NAT e parâmetros do Safe Apply.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from rede.backends.base import normalizar_configuracao_interface, normalizar_rota
from .configuracao import (
    ROLLBACK_MAXIMO_SEGUNDOS,
    ROLLBACK_MINIMO_SEGUNDOS,
    ROLLBACK_PADRAO_SEGUNDOS,
    obter_backend,
)
from .nat import normalizar_regra_nat


INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")

TIPOS_ALTERACAO = {
    "interface",
    "routing",
    "roteamento",
    "route",
    "rota",
    "nat",
    "general",
    "geral",
}

ALIASES_TIPO = {
    "roteamento": "routing",
    "route": "routing",
    "rota": "routing",
    "geral": "general",
}


class ValidacaoRedeErro(RuntimeError):
    def __init__(
        self,
        mensagem: str,
        *,
        codigo: str = "validacao_rede_falhou",
        detalhes: dict[str, Any] | None = None,
    ):
        super().__init__(mensagem)
        self.codigo = codigo
        self.detalhes = detalhes or {}


# =============================================================================
# HELPERS
# =============================================================================

def _bool(valor: Any, padrao: bool = False) -> bool:
    if isinstance(valor, bool):
        return valor

    if isinstance(valor, (int, float)):
        return valor != 0

    if valor is None:
        return padrao

    texto = str(valor).strip().lower()

    if texto in {
        "1",
        "true",
        "yes",
        "sim",
        "on",
        "ativo",
        "enabled",
    }:
        return True

    if texto in {
        "0",
        "false",
        "no",
        "nao",
        "não",
        "off",
        "inativo",
        "disabled",
    }:
        return False

    return padrao


def _inteiro(valor: Any, padrao: int) -> int:
    try:
        return int(valor)
    except (TypeError, ValueError):
        return padrao


def _primeiro_valor(
    payload: dict[str, Any],
    *chaves: str,
) -> Any:
    for chave in chaves:
        if chave in payload and payload[chave] is not None:
            return payload[chave]

    return None


# =============================================================================
# INTERFACES
# =============================================================================

def _validar_interface_nome(nome: Any) -> str:
    valor = str(nome or "").strip()

    if not valor:
        raise ValidacaoRedeErro(
            "Nome da interface não informado.",
            codigo="interface_nao_informada",
        )

    if not INTERFACE_RE.fullmatch(valor):
        raise ValidacaoRedeErro(
            "Nome de interface inválido.",
            codigo="interface_nome_invalido",
            detalhes={
                "interface": valor,
            },
        )

    if valor == "lo":
        raise ValidacaoRedeErro(
            "A interface loopback não pode ser gerenciada por este fluxo.",
            codigo="interface_loopback_bloqueada",
        )

    return valor


def _interfaces_existentes() -> dict[str, dict[str, Any]]:
    backend = obter_backend()

    return {
        item["nome"]: item
        for item in backend.listar_interfaces(
            incluir_loopback=False
        )
        if item.get("nome")
    }


# =============================================================================
# IPV4
# =============================================================================

def _validar_ipv4(
    valor: Any,
    campo: str,
) -> str | None:
    texto = str(valor or "").strip()

    if not texto:
        return None

    try:
        endereco = ipaddress.ip_address(
            texto
        )
    except ValueError as exc:
        raise ValidacaoRedeErro(
            f"{campo} contém um IPv4 inválido.",
            codigo="ipv4_invalido",
            detalhes={
                "campo": campo,
                "valor": texto,
            },
        ) from exc

    if endereco.version != 4:
        raise ValidacaoRedeErro(
            f"{campo} precisa ser IPv4.",
            codigo="ipv4_invalido",
            detalhes={
                "campo": campo,
                "valor": texto,
            },
        )

    return str(endereco)


# =============================================================================
# SAFE APPLY
# =============================================================================

def _normalizar_timeout(
    payload: dict[str, Any],
) -> int:
    requer_confirmacao = _bool(
        payload.get(
            "confirmation_required"
        ),
        True,
    )

    valor = _primeiro_valor(
        payload,
        "timeout_segundos",
        "rollback_segundos",
        "confirmacao_segundos",
        "tempo_confirmacao",
        "confirmation_timeout",
    )

    if valor is None:
        valor = (
            ROLLBACK_PADRAO_SEGUNDOS
        )

    segundos = _inteiro(
        valor,
        ROLLBACK_PADRAO_SEGUNDOS,
    )

    if (
        not requer_confirmacao
        and segundos <= 0
    ):
        return 0

    if (
        segundos
        < ROLLBACK_MINIMO_SEGUNDOS
        or segundos
        > ROLLBACK_MAXIMO_SEGUNDOS
    ):
        raise ValidacaoRedeErro(
            (
                "Tempo de confirmação do "
                "Safe Apply fora dos limites permitidos."
            ),
            codigo="timeout_rollback_invalido",
            detalhes={
                "valor": segundos,
                "minimo": (
                    ROLLBACK_MINIMO_SEGUNDOS
                ),
                "maximo": (
                    ROLLBACK_MAXIMO_SEGUNDOS
                ),
            },
        )

    return segundos


def _normalizar_tipo(
    payload: dict[str, Any],
) -> str:
    tipo = str(
        payload.get("tipo")
        or payload.get("type")
        or "general"
    ).strip().lower()

    if tipo not in TIPOS_ALTERACAO:
        raise ValidacaoRedeErro(
            (
                "Tipo de alteração não "
                f"suportado: {tipo}"
            ),
            codigo="tipo_alteracao_invalido",
            detalhes={
                "tipo": tipo,
            },
        )

    return ALIASES_TIPO.get(
        tipo,
        tipo,
    )


# =============================================================================
# ADAPTAÇÃO DO CONTRATO DJANGO → BACKEND
# =============================================================================

def _adaptar_configuracao_interface(
    configuracao: dict[str, Any],
) -> dict[str, Any]:
    """
    Converte o contrato enviado pelo Django para o formato plano
    utilizado internamente pelo backend de Rede.

    Django:

        {
            "habilitada": True,
            "ipv4": {
                "modo": "static",
                "endereco": "10.10.0.1",
                "prefixo": 24,
                "gateway": None,
                "rota_padrao": False,
                "metrica": 100
            },
            "mtu": 1500
        }

    Backend:

        {
            "habilitada": True,
            "ipv4_modo": "static",
            "ipv4_endereco": "10.10.0.1",
            "ipv4_prefixo": 24,
            "gateway": None,
            "rota_padrao": False,
            "metrica": 100,
            "mtu": 1500
        }

    Se o payload já vier no formato plano, os campos planos
    têm prioridade.
    """

    resultado = dict(
        configuracao
    )

    ipv4 = resultado.get(
        "ipv4"
    )

    if ipv4 is None:
        return resultado

    if not isinstance(
        ipv4,
        dict,
    ):
        raise ValidacaoRedeErro(
            (
                "Campo 'ipv4' da interface "
                "precisa ser um objeto."
            ),
            codigo=(
                "ipv4_configuracao_invalida"
            ),
        )

    aliases = {
        "ipv4_modo": (
            "modo",
            "mode",
        ),
        "ipv4_endereco": (
            "endereco",
            "address",
        ),
        "ipv4_prefixo": (
            "prefixo",
            "prefix",
        ),
        "gateway": (
            "gateway",
        ),
        "rota_padrao": (
            "rota_padrao",
            "default_route",
        ),
        "metrica": (
            "metrica",
            "metric",
        ),
    }

    for destino, origens in aliases.items():
        # Se já existe campo plano,
        # ele é considerado autoritativo.
        if destino in resultado:
            continue

        for origem in origens:
            if origem in ipv4:
                resultado[
                    destino
                ] = ipv4[
                    origem
                ]
                break

    return resultado


# =============================================================================
# CONFIGURAÇÃO DE INTERFACE
# =============================================================================

def validar_configuracao_interface(
    nome: str,
    configuracao: dict[str, Any],
    *,
    interfaces_existentes: (
        dict[str, dict[str, Any]]
        | None
    ) = None,
) -> dict[str, Any]:
    nome = _validar_interface_nome(
        nome
    )

    existentes = (
        interfaces_existentes
        or _interfaces_existentes()
    )

    if nome not in existentes:
        raise ValidacaoRedeErro(
            (
                "Interface não encontrada "
                f"no sistema: {nome}"
            ),
            codigo="interface_nao_encontrada",
            detalhes={
                "interface": nome,
            },
        )

    if not isinstance(
        configuracao,
        dict,
    ):
        raise ValidacaoRedeErro(
            (
                "Configuração da interface "
                "precisa ser um objeto."
            ),
            codigo=(
                "configuracao_interface_invalida"
            ),
            detalhes={
                "interface": nome,
            },
        )

    # -------------------------------------------------------------------------
    # CORREÇÃO CRÍTICA
    # -------------------------------------------------------------------------
    #
    # O Django envia IPv4 aninhado:
    #
    #     ipv4: {
    #         modo: static,
    #         endereco: 10.10.0.1,
    #         prefixo: 24
    #     }
    #
    # O backend trabalha internamente com:
    #
    #     ipv4_modo
    #     ipv4_endereco
    #     ipv4_prefixo
    #
    # Portanto precisamos adaptar ANTES de chamar
    # normalizar_configuracao_interface().
    # -------------------------------------------------------------------------

    configuracao_backend = (
        _adaptar_configuracao_interface(
            configuracao
        )
    )

    config = (
        normalizar_configuracao_interface(
            configuracao_backend
        )
    )

    modo = config[
        "ipv4_modo"
    ]

    # -------------------------------------------------------------------------
    # STATIC
    # -------------------------------------------------------------------------

    if modo == "static":
        endereco = _validar_ipv4(
            config.get(
                "ipv4_endereco"
            ),
            "ipv4_endereco",
        )

        gateway = _validar_ipv4(
            config.get(
                "gateway"
            ),
            "gateway",
        )

        prefixo = config.get(
            "ipv4_prefixo"
        )

        if not endereco:
            raise ValidacaoRedeErro(
                (
                    "Endereço IPv4 estático "
                    "não informado."
                ),
                codigo=(
                    "ipv4_estatico_ausente"
                ),
                detalhes={
                    "interface": nome,
                },
            )

        try:
            rede = ipaddress.ip_network(
                f"{endereco}/{prefixo}",
                strict=False,
            )
        except ValueError as exc:
            raise ValidacaoRedeErro(
                "Rede IPv4 estática inválida.",
                codigo=(
                    "rede_estatica_invalida"
                ),
                detalhes={
                    "interface": nome,
                    "endereco": endereco,
                    "prefixo": prefixo,
                },
            ) from exc

        if (
            gateway
            and ipaddress.ip_address(
                gateway
            )
            == ipaddress.ip_address(
                endereco
            )
        ):
            raise ValidacaoRedeErro(
                (
                    "Gateway não pode ser igual "
                    "ao endereço da própria interface."
                ),
                codigo="gateway_invalido",
                detalhes={
                    "interface": nome,
                    "gateway": gateway,
                },
            )

        if (
            config["rota_padrao"]
            and not gateway
        ):
            raise ValidacaoRedeErro(
                (
                    "Interface estática marcada "
                    "como rota padrão precisa "
                    "possuir gateway."
                ),
                codigo=(
                    "gateway_obrigatorio"
                ),
                detalhes={
                    "interface": nome,
                },
            )

        config[
            "ipv4_endereco"
        ] = endereco

        config[
            "gateway"
        ] = gateway

        config[
            "rede_ipv4"
        ] = str(
            rede
        )

    # -------------------------------------------------------------------------
    # DHCP
    # -------------------------------------------------------------------------

    elif modo == "dhcp":
        # Precisamos consultar o payload já adaptado,
        # porque o gateway também pode ter vindo de ipv4.gateway.
        gateway_original = (
            configuracao_backend.get(
                "gateway"
            )
        )

        if gateway_original:
            raise ValidacaoRedeErro(
                (
                    "Gateway manual não deve "
                    "ser informado para IPv4 DHCP."
                ),
                codigo=(
                    "gateway_dhcp_invalido"
                ),
                detalhes={
                    "interface": nome,
                },
            )

    # -------------------------------------------------------------------------
    # MTU
    # -------------------------------------------------------------------------

    mtu = config.get(
        "mtu"
    )

    if (
        mtu is not None
        and not 576
        <= int(mtu)
        <= 9216
    ):
        raise ValidacaoRedeErro(
            (
                "MTU fora do intervalo "
                "permitido."
            ),
            codigo="mtu_invalido",
            detalhes={
                "interface": nome,
                "mtu": mtu,
            },
        )

    return {
        "nome": nome,
        "conexao": (
            configuracao.get(
                "conexao"
            )
            or configuracao.get(
                "connection"
            )
        ),
        "configuracao": config,
    }


# =============================================================================
# EXTRAÇÃO DE INTERFACES
# =============================================================================

def _extrair_interfaces(
    payload: dict[str, Any],
    configuracao: dict[str, Any],
) -> list[Any]:
    """
    Aceita:

        desired.interfaces = [...]
        desired.interface = {...}

    E formatos legados:

        payload.interfaces = [...]
        payload.interface = {...}
    """

    interfaces = configuracao.get(
        "interfaces"
    )

    if interfaces is None:
        interfaces = payload.get(
            "interfaces"
        )

    if interfaces is not None:
        if not isinstance(
            interfaces,
            list,
        ):
            raise ValidacaoRedeErro(
                (
                    "'interfaces' precisa "
                    "ser uma lista."
                ),
                codigo=(
                    "interfaces_invalidas"
                ),
            )

        return interfaces

    # O contrato atual do Django usa:
    #
    # desired: {
    #     interface: {...}
    # }

    interface = configuracao.get(
        "interface"
    )

    if interface is None:
        interface = payload.get(
            "interface"
        )

    if (
        interface is None
        and "nome" in configuracao
    ):
        interface = configuracao

    if interface is None:
        return []

    if isinstance(
        interface,
        str,
    ):
        item = dict(
            configuracao
        )

        item.pop(
            "interface",
            None,
        )

        item[
            "nome"
        ] = interface

        return [
            item
        ]

    if isinstance(
        interface,
        dict,
    ):
        return [
            dict(
                interface
            )
        ]

    raise ValidacaoRedeErro(
        "Formato de interface inválido.",
        codigo=(
            "interface_payload_invalido"
        ),
    )


def _validar_interfaces(
    payload: dict[str, Any],
    configuracao: dict[str, Any],
) -> list[dict[str, Any]]:
    existentes = (
        _interfaces_existentes()
    )

    resultado: list[
        dict[str, Any]
    ] = []

    for item in _extrair_interfaces(
        payload,
        configuracao,
    ):
        if not isinstance(
            item,
            dict,
        ):
            raise ValidacaoRedeErro(
                (
                    "Item de interface "
                    "inválido."
                ),
                codigo=(
                    "interface_payload_invalido"
                ),
            )

        nome = (
            item.get("nome")
            or item.get("name")
            or item.get("interface")
        )

        config = item.get(
            "configuracao"
        )

        if not isinstance(
            config,
            dict,
        ):
            config = {
                chave: valor
                for chave, valor
                in item.items()
                if chave not in {
                    "nome",
                    "name",
                    "interface",
                    "conexao",
                    "connection",
                }
            }

        if (
            item.get(
                "conexao"
            )
            and "conexao"
            not in config
        ):
            config[
                "conexao"
            ] = item[
                "conexao"
            ]

        if (
            item.get(
                "connection"
            )
            and "connection"
            not in config
        ):
            config[
                "connection"
            ] = item[
                "connection"
            ]

        resultado.append(
            validar_configuracao_interface(
                nome,
                config,
                interfaces_existentes=(
                    existentes
                ),
            )
        )

    return resultado


# =============================================================================
# REDES SOBREPOSTAS
# =============================================================================

def _validar_sobreposicao_redes(
    interfaces: list[
        dict[str, Any]
    ],
) -> None:
    estaticas = []

    for item in interfaces:
        config = item[
            "configuracao"
        ]

        if (
            config.get(
                "ipv4_modo"
            )
            != "static"
        ):
            continue

        rede = ipaddress.ip_network(
            (
                f"{config['ipv4_endereco']}"
                f"/{config['ipv4_prefixo']}"
            ),
            strict=False,
        )

        estaticas.append(
            (
                item["nome"],
                rede,
            )
        )

    for indice, (
        nome_a,
        rede_a,
    ) in enumerate(
        estaticas
    ):
        for nome_b, rede_b in (
            estaticas[
                indice + 1:
            ]
        ):
            if (
                nome_a != nome_b
                and rede_a.overlaps(
                    rede_b
                )
            ):
                raise ValidacaoRedeErro(
                    (
                        "Duas interfaces estáticas "
                        "da alteração possuem redes "
                        "sobrepostas."
                    ),
                    codigo=(
                        "redes_sobrepostas"
                    ),
                    detalhes={
                        "interface_a": nome_a,
                        "rede_a": str(
                            rede_a
                        ),
                        "interface_b": nome_b,
                        "rede_b": str(
                            rede_b
                        ),
                    },
                )


# =============================================================================
# ROTAS
# =============================================================================

def _validar_rotas(
    rotas: Any,
    existentes: dict[
        str,
        dict[str, Any],
    ],
) -> list[dict[str, Any]]:
    if rotas is None:
        return []

    if not isinstance(
        rotas,
        list,
    ):
        raise ValidacaoRedeErro(
            (
                "'rotas' precisa ser "
                "uma lista."
            ),
            codigo="rotas_invalidas",
        )

    resultado: list[
        dict[str, Any]
    ] = []

    for rota_original in rotas:
        if not isinstance(
            rota_original,
            dict,
        ):
            raise ValidacaoRedeErro(
                "Rota estática inválida.",
                codigo="rota_invalida",
            )

        rota = normalizar_rota(
            rota_original
        )

        try:
            rede = ipaddress.ip_network(
                rota[
                    "destino"
                ],
                strict=False,
            )
        except ValueError as exc:
            raise ValidacaoRedeErro(
                (
                    "Destino de rota "
                    "inválido."
                ),
                codigo=(
                    "destino_rota_invalido"
                ),
                detalhes={
                    "destino": rota[
                        "destino"
                    ],
                },
            ) from exc

        if rede.version != 4:
            raise ValidacaoRedeErro(
                (
                    "Somente rotas IPv4 são "
                    "suportadas no V1."
                ),
                codigo=(
                    "rota_ipv6_nao_suportada"
                ),
            )

        if str(
            rede
        ) == "0.0.0.0/0":
            raise ValidacaoRedeErro(
                (
                    "Rota default deve ser "
                    "configurada pela interface "
                    "WAN, não como rota estática."
                ),
                codigo=(
                    "rota_default_estatica_bloqueada"
                ),
            )

        rota[
            "destino"
        ] = str(
            rede
        )

        if rota.get(
            "gateway"
        ):
            rota[
                "gateway"
            ] = _validar_ipv4(
                rota[
                    "gateway"
                ],
                "gateway_rota",
            )

        interface = (
            _validar_interface_nome(
                rota.get(
                    "interface_nome"
                )
            )
        )

        if interface not in existentes:
            raise ValidacaoRedeErro(
                (
                    "Interface da rota "
                    "não encontrada: "
                    f"{interface}"
                ),
                codigo=(
                    "interface_rota_nao_encontrada"
                ),
                detalhes={
                    "interface": interface,
                },
            )

        rota[
            "interface_nome"
        ] = interface

        resultado.append(
            rota
        )

    return resultado


# =============================================================================
# NAT
# =============================================================================

def _validar_nat(
    regras: Any,
    existentes: dict[
        str,
        dict[str, Any],
    ],
) -> list[dict[str, Any]]:
    if regras is None:
        return []

    if not isinstance(
        regras,
        list,
    ):
        raise ValidacaoRedeErro(
            (
                "'regras' de NAT precisa "
                "ser uma lista."
            ),
            codigo=(
                "nat_regras_invalidas"
            ),
        )

    resultado: list[
        dict[str, Any]
    ] = []

    for regra_original in regras:
        if not isinstance(
            regra_original,
            dict,
        ):
            raise ValidacaoRedeErro(
                "Regra NAT inválida.",
                codigo="nat_regra_invalida",
            )

        regra = normalizar_regra_nat(
            regra_original
        )

        entrada = regra[
            "interface_origem"
        ]

        saida = regra[
            "interface_saida"
        ]

        if entrada == saida:
            raise ValidacaoRedeErro(
                (
                    "Interface de origem e saída "
                    "do NAT precisam ser diferentes."
                ),
                codigo=(
                    "nat_interfaces_iguais"
                ),
                detalhes={
                    "interface": entrada,
                },
            )

        if entrada not in existentes:
            raise ValidacaoRedeErro(
                (
                    "Interface de origem NAT "
                    "não encontrada: "
                    f"{entrada}"
                ),
                codigo=(
                    "nat_interface_origem_nao_encontrada"
                ),
            )

        if saida not in existentes:
            raise ValidacaoRedeErro(
                (
                    "Interface de saída NAT "
                    "não encontrada: "
                    f"{saida}"
                ),
                codigo=(
                    "nat_interface_saida_nao_encontrada"
                ),
            )

        resultado.append(
            regra
        )

    return resultado


# =============================================================================
# VALIDAÇÃO PRINCIPAL
# =============================================================================

def validar_alteracao(
    payload: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(
        payload,
        dict,
    ):
        raise ValidacaoRedeErro(
            (
                "Payload da alteração "
                "precisa ser um objeto."
            ),
            codigo="payload_invalido",
        )

    tipo = _normalizar_tipo(
        payload
    )

    timeout = _normalizar_timeout(
        payload
    )

    configuracao = (
        payload.get(
            "configuracao"
        )
        or payload.get(
            "estado_desejado"
        )
        or payload.get(
            "desired"
        )
        or {}
    )

    if not isinstance(
        configuracao,
        dict,
    ):
        raise ValidacaoRedeErro(
            (
                "'configuracao' precisa "
                "ser um objeto."
            ),
            codigo=(
                "configuracao_invalida"
            ),
        )

    existentes = (
        _interfaces_existentes()
    )

    interfaces = (
        _validar_interfaces(
            payload,
            configuracao,
        )
        if tipo in {
            "interface",
            "general",
        }
        else []
    )

    _validar_sobreposicao_redes(
        interfaces
    )

    # =========================================================================
    # ROTEAMENTO
    # =========================================================================

    roteamento_origem = (
        configuracao.get(
            "roteamento"
        )
    )

    if roteamento_origem is None:
        roteamento_origem = (
            configuracao.get(
                "routing"
            )
        )

    if (
        roteamento_origem is None
        and tipo == "routing"
    ):
        roteamento_origem = (
            configuracao
        )

    roteamento = None

    if isinstance(
        roteamento_origem,
        dict,
    ):
        forward_presente = (
            "ipv4_forward"
            in roteamento_origem
        )

        rotas_presentes = (
            "rotas"
            in roteamento_origem
        )

        rotas = _validar_rotas(
            (
                roteamento_origem.get(
                    "rotas"
                )
                if rotas_presentes
                else None
            ),
            existentes,
        )

        interfaces_alvo = (
            roteamento_origem.get(
                "interfaces_alvo"
            )
            or []
        )

        if not isinstance(
            interfaces_alvo,
            list,
        ):
            raise ValidacaoRedeErro(
                (
                    "'interfaces_alvo' precisa "
                    "ser uma lista."
                ),
                codigo=(
                    "interfaces_alvo_invalidas"
                ),
            )

        interfaces_alvo = [
            _validar_interface_nome(
                item
            )
            for item
            in interfaces_alvo
        ]

        for rota in rotas:
            nome_interface = (
                rota[
                    "interface_nome"
                ]
            )

            if (
                nome_interface
                not in interfaces_alvo
            ):
                interfaces_alvo.append(
                    nome_interface
                )

        roteamento = {
            "ipv4_forward": (
                _bool(
                    roteamento_origem.get(
                        "ipv4_forward"
                    )
                )
                if forward_presente
                else None
            ),
            "rotas": (
                rotas
                if rotas_presentes
                else None
            ),
            "interfaces_alvo": (
                interfaces_alvo
            ),
        }

    # =========================================================================
    # NAT
    # =========================================================================

    nat_origem = configuracao.get(
        "nat"
    )

    if (
        nat_origem is None
        and tipo == "nat"
    ):
        nat_origem = configuracao

    nat = None

    if isinstance(
        nat_origem,
        dict,
    ):
        regras_presentes = (
            "regras"
            in nat_origem
        )

        regras = _validar_nat(
            (
                nat_origem.get(
                    "regras"
                )
                if regras_presentes
                else []
            ),
            existentes,
        )

        nat = {
            "regras": regras,
            "aplicar": (
                regras_presentes
            ),
        }

    # =========================================================================
    # CONTEÚDO OBRIGATÓRIO
    # =========================================================================

    if (
        tipo == "interface"
        and not interfaces
    ):
        raise ValidacaoRedeErro(
            (
                "Alteração de interface "
                "sem interface informada."
            ),
            codigo="interface_ausente",
            detalhes={
                "chaves_payload": sorted(
                    str(chave)
                    for chave
                    in payload.keys()
                ),
                "chaves_desired": sorted(
                    str(chave)
                    for chave
                    in configuracao.keys()
                ),
            },
        )

    if (
        tipo == "routing"
        and roteamento is None
    ):
        raise ValidacaoRedeErro(
            (
                "Alteração de roteamento "
                "sem configuração."
            ),
            codigo=(
                "roteamento_ausente"
            ),
        )

    if (
        tipo == "nat"
        and nat is None
    ):
        raise ValidacaoRedeErro(
            (
                "Alteração NAT sem "
                "configuração."
            ),
            codigo="nat_ausente",
        )

    if (
        tipo == "general"
        and not interfaces
        and roteamento is None
        and nat is None
    ):
        raise ValidacaoRedeErro(
            (
                "Alteração geral não "
                "possui operações."
            ),
            codigo="alteracao_vazia",
        )

    # =========================================================================
    # ID
    # =========================================================================

    alteracao_id = str(
        payload.get(
            "alteracao_id"
        )
        or payload.get(
            "change_id"
        )
        or payload.get(
            "id"
        )
        or ""
    ).strip()

    return {
        "alteracao_id": (
            alteracao_id
            or None
        ),
        "tipo": tipo,
        "timeout_segundos": timeout,
        "interfaces": interfaces,
        "roteamento": roteamento,
        "nat": nat,
        "metadados": dict(
            payload.get(
                "metadados"
            )
            or payload.get(
                "metadata"
            )
            or {}
        ),
    }


__all__ = [
    "ValidacaoRedeErro",
    "validar_configuracao_interface",
    "validar_alteracao",
]