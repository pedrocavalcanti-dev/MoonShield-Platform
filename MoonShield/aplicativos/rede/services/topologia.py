"""Topologia lógica oficial construída a partir do estado persistido de Rede."""

from __future__ import annotations

from ipaddress import IPv4Interface, IPv4Network
from typing import Iterable

from rede.dominio.constantes import PAPEIS_GERENCIADOS, PAPEIS_HOME_NET
from rede.dominio.tipos import EstadoSincronizacao, ModoIPv4, PapelInterface
from rede.models import InterfaceRede
from rede.services.interfaces import serializar_interface


def obter_topologia() -> dict:
    """Monta a topologia sobre o último estado reconciliado no PostgreSQL."""
    interfaces = InterfaceRede.objects.order_by("papel", "-principal", "nome")
    return _montar_topologia(serializar_interface(interface) for interface in interfaces)


def obter_wan_principal() -> dict | None:
    return obter_topologia()["wan"]["principal"]


def obter_lan_principal() -> dict | None:
    return obter_topologia()["lan"]["principal"]


def obter_mgmt_principal() -> dict | None:
    return obter_topologia()["mgmt"]["principal"]


def obter_redes_internas() -> dict:
    return obter_topologia()["redes_internas"]


def obter_home_net() -> list[str]:
    return obter_topologia()["home_net"]


def _montar_topologia(interfaces: Iterable[dict]) -> dict:
    """Organiza interfaces serializadas sem consultar Agent ou executar comandos."""
    grupos = {papel.value: [] for papel in PapelInterface}
    problemas: list[dict] = []
    avisos: list[dict] = []

    for interface in interfaces:
        papel = _papel(interface)
        grupos.get(papel, grupos[PapelInterface.NAO_ATRIBUIDA.value]).append(interface)

    wan_principal = _principal(grupos[PapelInterface.WAN.value], "wan", problemas, avisos)
    lan_principal = _principal(grupos[PapelInterface.LAN.value], "lan", problemas, avisos)
    mgmt_principal = _principal(
        grupos[PapelInterface.MGMT.value],
        "mgmt",
        problemas,
        avisos,
        obrigatorio=False,
    )

    interfaces_home_net = [
        interface
        for papel in PapelInterface
        if papel.value in PAPEIS_HOME_NET
        for interface in grupos[papel.value]
    ]
    redes_desejadas, redes_observadas = _redes_internas(interfaces_home_net, problemas, avisos)
    gerenciamento = _gerenciamento(
        grupos,
        wan_principal=wan_principal,
        lan_principal=lan_principal,
        mgmt_principal=mgmt_principal,
        avisos=avisos,
    )
    _avisos_operacionais(grupos, avisos)

    return {
        "valida": not problemas,
        "problemas": problemas,
        "avisos": avisos,
        "wan": {"principal": wan_principal, "interfaces": grupos[PapelInterface.WAN.value]},
        "lan": {"principal": lan_principal, "interfaces": grupos[PapelInterface.LAN.value]},
        "mgmt": {"principal": mgmt_principal, "interfaces": grupos[PapelInterface.MGMT.value]},
        "dmz": grupos[PapelInterface.DMZ.value],
        "custom": grupos[PapelInterface.CUSTOM.value],
        "unassigned": grupos[PapelInterface.NAO_ATRIBUIDA.value],
        "gerenciamento": gerenciamento,
        "redes_internas": {
            "desejadas": redes_desejadas,
            "observadas": redes_observadas,
        },
        "home_net": redes_desejadas,
    }


def _papel(interface: dict) -> str:
    papel = interface.get("desejado", {}).get("papel")
    papel = str(papel or PapelInterface.NAO_ATRIBUIDA.value)
    return papel if papel in PAPEIS_GERENCIADOS else PapelInterface.NAO_ATRIBUIDA.value


def _habilitada(interface: dict) -> bool:
    return bool(interface.get("desejado", {}).get("habilitada", True))


def _principal(
    interfaces: list[dict],
    papel: str,
    problemas: list[dict],
    avisos: list[dict],
    *,
    obrigatorio: bool = True,
) -> dict | None:
    principais = [interface for interface in interfaces if interface.get("desejado", {}).get("principal")]

    if len(principais) > 1:
        destino = problemas if obrigatorio else avisos
        destino.append({
            "codigo": f"multiplas_{papel}_principais",
            "mensagem": f"Existe mais de uma interface {papel.upper()} principal.",
        })
        return None

    if principais:
        principal = principais[0]
    elif len(interfaces) == 1:
        principal = interfaces[0]
        avisos.append({
            "codigo": f"{papel}_principal_assumida",
            "mensagem": f"A única interface {papel.upper()} foi usada como principal.",
            "interface": principal["nome"],
        })
    elif interfaces:
        destino = problemas if obrigatorio else avisos
        destino.append({
            "codigo": f"{papel}_principal_ausente",
            "mensagem": f"Defina a interface {papel.upper()} principal.",
        })
        return None
    elif obrigatorio:
        problemas.append({
            "codigo": f"nenhuma_{papel}",
            "mensagem": f"Nenhuma interface {papel.upper()} foi configurada.",
        })
        return None
    else:
        return None

    if not _habilitada(principal):
        destino = problemas if obrigatorio else avisos
        destino.append({
            "codigo": f"{papel}_principal_desabilitada",
            "mensagem": f"A interface {papel.upper()} principal está desabilitada.",
            "interface": principal["nome"],
        })

    return principal


def _redes_internas(lans: list[dict], problemas: list[dict], avisos: list[dict]) -> tuple[list[str], list[str]]:
    desejadas: set[IPv4Network] = set()
    observadas: set[IPv4Network] = set()

    for interface in lans:
        if not _habilitada(interface):
            avisos.append({
                "codigo": "lan_desabilitada",
                "mensagem": "LAN desabilitada não compõe redes internas.",
                "interface": interface["nome"],
            })
            continue

        desejado = interface.get("desejado", {})
        if desejado.get("ipv4_modo") == ModoIPv4.STATIC.value:
            rede = _rede_ipv4(desejado.get("ipv4_endereco"), desejado.get("ipv4_prefixo"))
            if rede is None:
                problemas.append({
                    "codigo": "lan_ipv4_estatico_invalido",
                    "mensagem": "LAN estática exige IPv4 e prefixo válidos.",
                    "interface": interface["nome"],
                })
            else:
                desejadas.add(rede)

        real = interface.get("real", {})
        enderecos = real.get("enderecos_ipv4")
        if not isinstance(enderecos, list) or not enderecos:
            enderecos = [(real.get("ipv4"), real.get("prefixo"))]

        for endereco in enderecos:
            if isinstance(endereco, tuple):
                rede = _rede_ipv4(*endereco)
            else:
                rede = _rede_ipv4(endereco, real.get("prefixo"))

            if rede is None:
                if endereco:
                    avisos.append({
                        "codigo": "ipv4_observado_invalido",
                        "mensagem": "IPv4 observado inválido foi ignorado na topologia.",
                        "interface": interface["nome"],
                        "endereco": str(endereco),
                    })
                continue
            observadas.add(rede)

    return _serializar_redes(desejadas), _serializar_redes(observadas)


def _rede_ipv4(endereco, prefixo=None) -> IPv4Network | None:
    valor = str(endereco or "").strip()
    if not valor:
        return None

    if "/" not in valor:
        if prefixo is None:
            return None
        valor = f"{valor}/{prefixo}"

    try:
        return IPv4Interface(valor).network
    except (TypeError, ValueError):
        return None


def _serializar_redes(redes: set[IPv4Network]) -> list[str]:
    return [str(rede) for rede in sorted(redes, key=lambda rede: (int(rede.network_address), rede.prefixlen))]


def _gerenciamento(grupos: dict[str, list[dict]], *, wan_principal: dict | None, lan_principal: dict | None, mgmt_principal: dict | None, avisos: list[dict]) -> dict:
    interfaces = [
        interface
        for papel in PapelInterface
        if papel.value in PAPEIS_GERENCIADOS
        for interface in grupos[papel.value]
        if interface.get("desejado", {}).get("acesso_gerenciamento")
    ]

    preferidas = (mgmt_principal, lan_principal, wan_principal)
    principal = next((interface for interface in preferidas if interface in interfaces), None)

    if principal is None and len(interfaces) == 1:
        principal = interfaces[0]
    elif principal is None and len(interfaces) > 1:
        avisos.append({
            "codigo": "gerenciamento_principal_ambiguo",
            "mensagem": "Há mais de uma interface com acesso de gerenciamento.",
        })

    return {"principal": principal, "interfaces": interfaces}


def _avisos_operacionais(grupos: dict[str, list[dict]], avisos: list[dict]) -> None:
    for papel in PapelInterface:
        if papel.value not in PAPEIS_GERENCIADOS:
            continue

        for interface in grupos[papel.value]:
            estado = interface.get("estado_sincronizacao")
            if estado == EstadoSincronizacao.MISSING.value:
                avisos.append({
                    "codigo": "interface_ausente",
                    "mensagem": "Interface gerenciada não foi observada pelo Agent.",
                    "interface": interface["nome"],
                })
            elif estado == EstadoSincronizacao.DRIFTED.value:
                avisos.append({
                    "codigo": "interface_divergente",
                    "mensagem": "Estado observado diverge da configuração desejada.",
                    "interface": interface["nome"],
                })
