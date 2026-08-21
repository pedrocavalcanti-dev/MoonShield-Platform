"""
MoonShield Platform — Firewall / auxiliares.py
==============================================

Helpers de apresentação, serialização, métricas e compatibilidade temporária
do módulo de Firewall.

ARQUITETURA ATUAL:

    Views Django
        ├── auxiliares.py              -> serialização / dashboard / simulação
        └── services/
            ├── agent_client.py        -> IPC Unix Socket
            ├── firewall_status.py     -> status consolidado
            ├── firewall_install.py    -> instalação/orquestração
            ├── firewall_rules.py      -> aplicação/bloqueios
            └── ingestao_local.py      -> eventos locais

Este arquivo NÃO:
- usa HTTP para falar com Agent;
- usa Sensor como destino do Firewall;
- usa porta 8765;
- usa X-MS-TOKEN;
- executa nftables;
- executa subprocess para detectar IP crítico;
- aplica regras diretamente.

Ele continua existindo porque ainda é útil para:
- serializers usados pelo frontend;
- métricas e gráficos;
- dados de simulação;
- compatibilidade temporária com algumas chamadas antigas de views.py.

Depois da reescrita de views.py/urls.py, os wrappers marcados como LEGADO podem
ser removidos em uma etapa posterior.
"""

from __future__ import annotations

import ipaddress
import random
import uuid
from datetime import datetime, timedelta
from typing import Any

from django.db.models import Count, Sum
from django.db.models.functions import TruncHour
from django.utils import timezone

from .models import (
    AllowlistEntry,
    BlocklistEntry,
    ConfiguracaoFirewall,
    EventoFirewall,
    GeoblockEntry,
    NatEntry,
    RegraFirewall,
)

from .services import agent_client
from .services.firewall_rules import (
    aplicar_regras_pendentes,
    obter_sync_status,
)
from .services.firewall_status import (
    obter_estado_firewall,
)


# =============================================================================
# MODO / PERÍODO
# =============================================================================

def get_modo() -> str:
    """
    Compatibilidade temporária com views antigas.

    Retorna:
        "demo" -> SIMULAÇÃO
        "prod" -> REAL

    O frontend novo deve trabalhar conceitualmente apenas com:
        SIMULAÇÃO / REAL
    """
    try:
        from configuracoes.models import ConfigSistema

        cfg = ConfigSistema.get_solo()
        valor = str(
            getattr(cfg, "modo", "")
            or ""
        ).strip().lower()

        if valor in {
            "real",
            "prod",
            "producao",
            "produção",
        }:
            return "prod"

        if valor in {
            "simulacao",
            "simulação",
            "demo",
        }:
            return "demo"

    except Exception:
        pass

    return "demo"


def get_modo_atual() -> str:
    """
    Contrato novo:
        simulacao
        real
    """
    return (
        "real"
        if get_modo() == "prod"
        else "simulacao"
    )


def delta_horas(
    period: str,
) -> int:
    return {
        "1h": 1,
        "24h": 24,
        "7d": 168,
        "30d": 720,
    }.get(
        str(period or "24h"),
        24,
    )


# =============================================================================
# TOPOLOGIA / INTERFACES
# =============================================================================

def _iface_map_local() -> dict[str, str]:
    """
    Obtém o mapa lógico conhecido pelo Django.

    NÃO adivinha WAN/LAN pela ordem das interfaces.
    """
    try:
        cfg = ConfiguracaoFirewall.get_solo()

        mapa: dict[str, str] = {}

        if cfg.interface_wan:
            mapa["WAN"] = cfg.interface_wan

        if cfg.interface_lan:
            mapa["LAN"] = cfg.interface_lan

        if cfg.interface_mgmt:
            mapa["MGMT"] = cfg.interface_mgmt

        return mapa

    except Exception:
        return {}


def map_iface(
    raw: str,
) -> str:
    """
    Converte nome físico conhecido para rótulo lógico.

    Exemplo no ambiente atual:
        enp0s3 -> WAN
        enp0s8 -> MGMT
        enp0s9 -> LAN

    A função NÃO hardcoda esses nomes: usa ConfiguracaoFirewall.
    """
    valor = str(
        raw
        or ""
    ).strip()

    if not valor:
        return "—"

    upper = valor.upper()

    if upper in {
        "WAN",
        "LAN",
        "MGMT",
        "VPN",
    }:
        return upper

    mapa = _iface_map_local()

    for logica, fisica in mapa.items():
        if valor == fisica:
            return logica

    lower = valor.lower()

    # VPN pode ser inferida pelo próprio nome sem assumir topologia física.
    if any(
        token in lower
        for token in (
            "tun",
            "tap",
            "wg",
            "vpn",
            "ipsec",
        )
    ):
        return "VPN"

    # Se não conhecemos o papel, mostramos a interface real.
    return valor


# =============================================================================
# SERIALIZERS
# =============================================================================

def rule_to_dict(
    r: RegraFirewall,
) -> dict[str, Any]:
    return {
        "id": r.id,
        "enabled": r.enabled,
        "priority": r.priority,
        "action": r.action,
        "iface": r.iface,
        "dir": r.dir,
        "proto": r.proto,
        "src": r.src,
        "dst": r.dst,
        "port": r.port,
        "desc": r.desc,
        "log": r.log,

        "pendente": r.pendente,
        "sincronizada": r.sincronizada,
        "deletado": r.deletado,

        "ultimo_erro": getattr(
            r,
            "ultimo_erro",
            "",
        ),

        "sincronizada_em": (
            r.sincronizada_em.isoformat()
            if getattr(
                r,
                "sincronizada_em",
                None,
            )
            else None
        ),

        "criado_em": (
            r.criado_em.isoformat()
            if r.criado_em
            else None
        ),

        "atualizado_em": (
            r.atualizado_em.isoformat()
            if r.atualizado_em
            else None
        ),
    }


def nat_to_dict(
    n: NatEntry,
) -> dict[str, Any]:
    return {
        "id": n.id,
        "name": n.name,
        "iface": n.iface,
        "wan_port": n.wan_port,
        "lan_ip": str(n.lan_ip),
        "lan_port": n.lan_port,
        "proto": n.proto,
        "enabled": n.enabled,
        "criado_em": (
            n.criado_em.isoformat()
            if n.criado_em
            else None
        ),
        "atualizado_em": (
            n.atualizado_em.isoformat()
            if getattr(
                n,
                "atualizado_em",
                None,
            )
            else None
        ),
    }


def block_to_dict(
    b: BlocklistEntry,
) -> dict[str, Any]:
    return {
        "id": b.id,
        "ip": b.ip,
        "reason": b.reason,
        "source": b.source,
        "date": b.criado_em.strftime(
            "%Y-%m-%d"
        ),
        "expires": b.expires,
        "criado_em": b.criado_em.isoformat(),
    }


def allow_to_dict(
    a: AllowlistEntry,
) -> dict[str, Any]:
    return {
        "id": a.id,
        "ip": a.ip,
        "reason": a.reason,
        "date": a.criado_em.strftime(
            "%Y-%m-%d"
        ),
        "criado_em": a.criado_em.isoformat(),
    }


def geo_to_dict(
    g: GeoblockEntry,
) -> dict[str, Any]:
    return {
        "id": g.id,
        "country": g.country,
        "code": g.code,
        "dir": g.dir,
        "enabled": g.enabled,
        "criado_em": (
            g.criado_em.isoformat()
            if g.criado_em
            else None
        ),
    }


def evento_to_log(
    e: EventoFirewall,
) -> dict[str, Any]:
    return {
        "id": str(e.id),
        "timestamp": e.timestamp.isoformat(),
        "time": e.timestamp.strftime(
            "%H:%M:%S"
        ),
        "action": e.acao,
        "iface": map_iface(
            e.iface
        ),
        "iface_raw": e.iface,
        "iface_saida": e.iface_saida,
        "src_ip": str(e.src_ip),
        "src_port": (
            str(e.src_port)
            if e.src_port is not None
            else "—"
        ),
        "dst_ip": str(
            e.dst_ip
            or "—"
        ),
        "dst_port": (
            str(e.dst_port)
            if e.dst_port is not None
            else "—"
        ),
        "proto": e.proto,
        "rule_id": 0,
        "rule_desc": (
            f"{e.prefixo} {e.chain}".strip()
            or "—"
        ),
        "bytes": e.tamanho or 0,
        "ttl": e.ttl,
        "flags_tcp": e.flags_tcp,
        "prefixo": e.prefixo,
        "reason": (
            e.flags_tcp
            or e.chain
            or "—"
        ),
        "source": (
            "local"
            if e.sensor_id is None
            else "legado"
        ),
    }


# =============================================================================
# SINCRONIZAÇÃO
# =============================================================================

def sync_status() -> dict[str, Any]:
    """
    Status novo: Django ↔ Agent/nftables.
    """
    try:
        status = obter_sync_status()

        return {
            "total": status.get(
                "total",
                0,
            ),
            "pendentes": status.get(
                "pendentes",
                0,
            ),
            "aplicadas": status.get(
                "sincronizadas",
                0,
            ),
            "sincronizadas": status.get(
                "sincronizadas",
                0,
            ),
            "deletadas_pendentes": status.get(
                "deletadas_pendentes",
                0,
            ),
            "em_sync": status.get(
                "em_sync",
                False,
            ),
            "fonte": "local",
        }

    except Exception:
        total = RegraFirewall.objects.filter(
            deletado=False
        ).count()

        pendentes = RegraFirewall.objects.filter(
            pendente=True
        ).count()

        aplicadas = RegraFirewall.objects.filter(
            sincronizada=True,
            deletado=False,
        ).count()

        deletadas = RegraFirewall.objects.filter(
            deletado=True
        ).count()

        return {
            "total": total,
            "pendentes": pendentes,
            "aplicadas": aplicadas,
            "sincronizadas": aplicadas,
            "deletadas_pendentes": deletadas,
            "em_sync": (
                pendentes == 0
                and deletadas == 0
            ),
            "fonte": "local",
        }


# =============================================================================
# COMPATIBILIDADE TEMPORÁRIA — SENSOR ANTIGO
# =============================================================================

def get_sensor_firewall():
    """
    LEGADO.

    O Firewall novo não usa Sensor.
    Mantido temporariamente apenas para views.py antigo importar sem quebrar.
    """
    return None


def notificar_agente(
    endpoint: str,
    payload: dict,
) -> tuple[bool, str]:
    """
    LEGADO COMPATÍVEL.

    Antigamente fazia HTTP para o sensor Linux.
    Agora roteia operações conhecidas para agent_client via Unix Socket.

    Remover depois da nova views.py.
    """
    endpoint = str(
        endpoint
        or ""
    ).strip().lower()

    payload = (
        payload
        if isinstance(
            payload,
            dict,
        )
        else {}
    )

    try:
        if endpoint in {
            "/aplicar",
            "/apply",
            "aplicar",
            "apply",
        }:
            rules = (
                payload.get("rules")
                or payload.get("regras")
                or []
            )

            result = agent_client.aplicar_regras(
                rules,
                iface_map=(
                    payload.get(
                        "iface_map"
                    )
                    or {}
                ),
                config=(
                    payload.get(
                        "config"
                    )
                    or None
                ),
            )

            total = (
                result.get("total_regras")
                or len(rules)
            )

            return (
                True,
                f"{total} regra(s) aplicada(s) localmente",
            )

        if endpoint in {
            "/bloquear",
            "/block",
            "block",
        }:
            ip = str(
                payload.get("ip")
                or ""
            ).strip()

            if not ip:
                return (
                    False,
                    "IP obrigatório",
                )

            agent_client.bloquear_ip(
                ip,
                motivo=str(
                    payload.get("motivo")
                    or payload.get("reason")
                    or "Bloqueio manual"
                ),
            )

            return (
                True,
                f"{ip} bloqueado",
            )

        if endpoint in {
            "/desbloquear",
            "/unblock",
            "unblock",
        }:
            ip = str(
                payload.get("ip")
                or ""
            ).strip()

            if not ip:
                return (
                    False,
                    "IP obrigatório",
                )

            agent_client.liberar_ip(
                ip
            )

            return (
                True,
                f"{ip} liberado",
            )

        return (
            False,
            f"Endpoint legado não suportado: {endpoint}",
        )

    except Exception as exc:
        return (
            False,
            str(exc),
        )


def push_regras_ao_agente() -> tuple[bool, str]:
    """
    LEGADO COMPATÍVEL.

    Agora chama firewall_rules.py diretamente.
    Não cria thread e não usa HTTP.
    """
    try:
        resultado = aplicar_regras_pendentes()

        if resultado.get(
            "ok"
        ):
            total = resultado.get(
                "total_regras",
                0,
            )

            return (
                True,
                f"{total} regra(s) aplicada(s) no nftables",
            )

        return (
            False,
            str(
                resultado.get(
                    "erro"
                )
                or resultado.get(
                    "mensagem"
                )
                or "Falha ao aplicar regras."
            ),
        )

    except Exception as exc:
        return (
            False,
            str(exc),
        )


# =============================================================================
# VALIDAÇÃO LEVE DE REGRA NO DJANGO
# =============================================================================

def validar_regra_segura(
    payload: dict,
) -> tuple[bool, str]:
    """
    Validação preventiva para UX.

    A validação de segurança DEFINITIVA continua sendo feita pelo:
        MoonShield-Agent/firewall/nucleo/seguranca.py

    O Django não tenta detectar gateway/sensor/IP crítico localmente.
    """
    if not isinstance(
        payload,
        dict,
    ):
        return (
            False,
            "Regra inválida.",
        )

    action = str(
        payload.get(
            "action"
        )
        or "deny"
    ).strip().lower()

    if action not in {
        "deny",
        "drop",
        "reject",
    }:
        return (
            True,
            "",
        )

    iface = str(
        payload.get(
            "iface"
        )
        or "any"
    ).strip()

    src = str(
        payload.get(
            "src"
        )
        or "any"
    ).strip()

    dst = str(
        payload.get(
            "dst"
        )
        or "any"
    ).strip()

    port = str(
        payload.get(
            "port"
        )
        or "any"
    ).strip()

    # Proteção explícita da interface de gerenciamento.
    if (
        iface == "MGMT"
        and src == "any"
        and dst == "any"
        and port == "any"
    ):
        return (
            False,
            "Regra recusada: um bloqueio genérico na interface "
            "de gerenciamento pode interromper o acesso ao MoonShield.",
        )

    # Um deny sem qualquer critério e em ANY é perigoso para a própria máquina.
    if (
        iface == "any"
        and src == "any"
        and dst == "any"
        and port == "any"
    ):
        return (
            False,
            "Regra recusada: bloqueio global sem critérios pode "
            "interromper gerenciamento e serviços do MoonShield.",
        )

    for campo, valor in (
        ("origem", src),
        ("destino", dst),
    ):
        if valor == "any":
            continue

        for item in (
            parte.strip()
            for parte in valor.split(",")
            if parte.strip()
        ):
            try:
                if "/" in item:
                    ipaddress.ip_network(
                        item,
                        strict=False,
                    )
                else:
                    ipaddress.ip_address(
                        item
                    )
            except ValueError:
                return (
                    False,
                    f"Endereço de {campo} inválido: {item}",
                )

    return (
        True,
        "",
    )


# =============================================================================
# EXPORT / PREVIEW NFT — SOMENTE VISUALIZAÇÃO
# =============================================================================

def regra_para_nft_inline(
    r: RegraFirewall,
    iface_map: dict | None = None,
) -> str | None:
    """
    Gera apenas uma representação textual para preview/export.

    NÃO é utilizada para aplicar regra.
    A geração/aplicação real pertence ao MoonShield-Agent.
    """
    partes: list[str] = []

    mapa = {
        **_iface_map_local(),
        **(
            iface_map
            if isinstance(
                iface_map,
                dict,
            )
            else {}
        ),
    }

    iface_nome = mapa.get(
        r.iface,
        (
            ""
            if r.iface == "any"
            else r.iface
        ),
    )

    if iface_nome:
        direcao = (
            "oifname"
            if r.dir == "out"
            else "iifname"
        )

        partes.append(
            f'{direcao} "{iface_nome}"'
        )

    if r.src and r.src != "any":
        partes.append(
            _endereco_preview(
                "saddr",
                r.src,
            )
        )

    if r.dst and r.dst != "any":
        partes.append(
            _endereco_preview(
                "daddr",
                r.dst,
            )
        )

    proto = str(
        r.proto
        or "any"
    ).lower()

    if proto == "icmp":
        partes.append(
            "ip protocol icmp"
        )

    elif proto == "icmpv6":
        partes.append(
            "ip6 nexthdr icmpv6"
        )

    elif proto in {
        "tcp",
        "udp",
    }:
        port = str(
            r.port
            or "any"
        )

        if port != "any":
            partes.append(
                f"{proto} dport {port}"
            )
        else:
            partes.append(
                f"meta l4proto {proto}"
            )

    if r.log:
        prefixo = (
            "MS-FW-ALLOW: "
            if r.action == "allow"
            else "MS-FW-DROP: "
        )

        partes.append(
            f'log prefix "{prefixo}" counter'
        )

    partes.append(
        "accept"
        if r.action == "allow"
        else "drop"
    )

    return (
        " ".join(
            parte
            for parte in partes
            if parte
        )
        or None
    )


def _endereco_preview(
    direcao: str,
    valor: str,
) -> str:
    try:
        primeiro = str(
            valor
        ).split(
            ",",
            1,
        )[0].strip()

        objeto = (
            ipaddress.ip_network(
                primeiro,
                strict=False,
            )
            if "/" in primeiro
            else ipaddress.ip_address(
                primeiro
            )
        )

        familia = (
            "ip6"
            if objeto.version == 6
            else "ip"
        )

    except Exception:
        familia = "ip"

    return (
        f"{familia} {direcao} {valor}"
    )


# =============================================================================
# DADOS DE SIMULAÇÃO
# =============================================================================

_SRC_IPS = [
    "185.22.11.4",
    "45.142.212.5",
    "91.108.4.12",
    "198.51.100.4",
    "103.235.46.3",
    "77.88.55.88",
    "185.220.101.2",
    "194.165.16.4",
    "5.188.86.172",
    "46.148.127.9",
]

_DST_IPS = [
    "10.10.0.10",
    "10.10.0.21",
    "10.10.0.5",
    "10.10.0.15",
    "10.10.0.100",
]

_PORTS = [
    "22",
    "80",
    "443",
    "3389",
    "8080",
    "23",
    "21",
    "25",
    "53",
    "3306",
    "1194",
    "161",
]

_IFACES = [
    "WAN",
    "LAN",
    "MGMT",
]

_PROTOS = [
    "TCP",
    "UDP",
    "ICMP",
]

_REASONS = [
    "Policy match",
    "Port scan detected",
    "Brute force limit",
    "GeoBlock",
    "Default deny",
    "Rate limit SSH",
    "Blocklist match",
    "Auto-ban",
]

_RULE_DESCS = {
    100: "HTTPS Inbound WAN",
    101: "HTTP Inbound WAN",
    102: "Bloquear SSH externo",
    103: "Bloquear Telnet",
    104: "Bloquear RDP externo",
    105: "LAN -> HTTPS out",
    106: "LAN -> DNS out",
    107: "Bloquear SMTP saída",
    108: "OpenVPN Tunnel",
    109: "Permitir ICMP Ping",
    110: "Bloquear range TOR",
    111: "LAN -> Proxy",
    112: "Bloquear SNMP externo",
    113: "Gateway LAN livre",
    114: "Default deny WAN",
    115: "Rate limit SSH",
}


def _ri(
    a: int,
    b: int,
) -> int:
    return random.randint(
        a,
        b,
    )


def _pick(
    lst: list,
):
    return random.choice(
        lst
    )


def _arr(
    n: int,
    a: int,
    b: int,
) -> list[int]:
    return [
        _ri(
            a,
            b,
        )
        for _ in range(
            n
        )
    ]


def _hour_labels_demo() -> list[str]:
    h = datetime.now().hour

    return [
        f"{(h - 23 + i) % 24:02d}h"
        for i in range(
            24
        )
    ]


def _gen_log() -> dict[str, Any]:
    d = datetime.now()
    rule_id = _ri(
        100,
        115,
    )

    return {
        "id": str(
            uuid.uuid4()
        ),
        "time": (
            f"{d.hour:02d}:"
            f"{d.minute:02d}:"
            f"{d.second:02d}"
        ),
        "action": _pick(
            [
                "DENY",
                "DENY",
                "DROP",
                "DROP",
                "ALLOW",
            ]
        ),
        "iface": _pick(
            _IFACES
        ),
        "src_ip": _pick(
            _SRC_IPS
        ),
        "dst_ip": _pick(
            _DST_IPS
        ),
        "dst_port": _pick(
            _PORTS
        ),
        "proto": _pick(
            _PROTOS
        ),
        "rule_id": rule_id,
        "rule_desc": _RULE_DESCS.get(
            rule_id,
            "Regra genérica",
        ),
        "bytes": _ri(
            64,
            65535,
        ),
        "reason": _pick(
            _REASONS
        ),
    }


def demo_data(
    period: str,
) -> dict[str, Any]:
    mult = {
        "1h": 0.15,
        "24h": 1,
        "7d": 4.5,
        "30d": 18,
    }.get(
        period,
        1,
    )

    src_ips_demo = _SRC_IPS[
        :5
    ]

    return {
        "ok": True,
        "mode": "demo",
        "modo": "simulacao",
        "fonte": "simulacao",

        "metrics": {
            "traffic_in": int(
                _ri(
                    800,
                    2800,
                )
                * mult
            ),
            "traffic_out": int(
                _ri(
                    200,
                    900,
                )
                * mult
            ),
            "conexoes": _ri(
                80,
                450,
            ),
            "drops": int(
                _ri(
                    1200,
                    4800,
                )
                * mult
            ),
            "allows": int(
                _ri(
                    8000,
                    28000,
                )
                * mult
            ),
            "top_port": _pick(
                _PORTS
            ),
            "top_port_hits": _ri(
                300,
                900,
            ),
            "top_ip": _pick(
                _SRC_IPS
            ),
            "top_ip_hits": _ri(
                80,
                400,
            ),
            "cpu": _ri(
                8,
                28,
            ),
            "ram": _ri(
                30,
                55,
            ),
        },

        "charts": {
            "hours": _hour_labels_demo(),
            "traffic_in": _arr(
                24,
                10,
                180,
            ),
            "traffic_out": _arr(
                24,
                5,
                80,
            ),
            "drops": _arr(
                24,
                20,
                500,
            ),
            "denies": _arr(
                24,
                10,
                200,
            ),
        },

        "top_ips": [
            {
                "ip": src_ips_demo[0],
                "hits": _ri(
                    200,
                    500,
                ),
            },
            {
                "ip": src_ips_demo[1],
                "hits": _ri(
                    100,
                    200,
                ),
            },
            {
                "ip": src_ips_demo[2],
                "hits": _ri(
                    50,
                    120,
                ),
            },
            {
                "ip": src_ips_demo[3],
                "hits": _ri(
                    20,
                    60,
                ),
            },
            {
                "ip": src_ips_demo[4],
                "hits": _ri(
                    5,
                    25,
                ),
            },
        ],

        "rules": [
            rule_to_dict(
                r
            )
            for r in RegraFirewall.objects.filter(
                deletado=False
            ).order_by(
                "priority",
                "id",
            )
        ],

        "logs": [
            _gen_log()
            for _ in range(
                80
            )
        ],

        "nat": [
            nat_to_dict(
                n
            )
            for n in NatEntry.objects.all()
        ],

        "blocklist": [
            block_to_dict(
                b
            )
            for b in BlocklistEntry.objects.all()
        ],

        "allowlist": [
            allow_to_dict(
                a
            )
            for a in AllowlistEntry.objects.all()
        ],

        "geoblock": [
            geo_to_dict(
                g
            )
            for g in GeoblockEntry.objects.all()
        ],

        "sync": sync_status(),

        "firewall": {
            "fonte": "simulacao",
            "status": "simulacao",
            "status_label": "Simulação",
            "operacional": True,
        },

        "last_update": datetime.now().isoformat(),
    }


# =============================================================================
# DADOS REAIS / PRODUÇÃO
# =============================================================================

def prod_waiting() -> dict[str, Any]:
    agora_ts = timezone.now()

    hour_labels = [
        (
            agora_ts
            - timedelta(
                hours=23 - i
            )
        ).strftime(
            "%Hh"
        )
        for i in range(
            24
        )
    ]

    return {
        "ok": True,
        "mode": "prod",
        "modo": "real",
        "fonte": "local",
        "waiting": True,
        "msg": (
            "Modo Real ativo. Aguardando eventos locais "
            "do MoonShield-Agent."
        ),

        "metrics": {
            "traffic_in": 0,
            "traffic_out": 0,
            "conexoes": 0,
            "drops": 0,
            "allows": 0,
            "top_port": "—",
            "top_port_hits": 0,
            "top_ip": "—",
            "top_ip_hits": 0,
            "cpu": 0,
            "ram": 0,
        },

        "charts": {
            "hours": hour_labels,
            "traffic_in": [
                0
            ] * 24,
            "traffic_out": [
                0
            ] * 24,
            "drops": [
                0
            ] * 24,
            "denies": [
                0
            ] * 24,
        },

        "rules": [
            rule_to_dict(
                r
            )
            for r in RegraFirewall.objects.filter(
                deletado=False
            ).order_by(
                "priority",
                "id",
            )
        ],

        "logs": [],

        "nat": [
            nat_to_dict(
                n
            )
            for n in NatEntry.objects.all()
        ],

        "blocklist": [
            block_to_dict(
                b
            )
            for b in BlocklistEntry.objects.all()
        ],

        "allowlist": [
            allow_to_dict(
                a
            )
            for a in AllowlistEntry.objects.all()
        ],

        "geoblock": [
            geo_to_dict(
                g
            )
            for g in GeoblockEntry.objects.all()
        ],

        "sync": sync_status(),

        "firewall": obter_estado_firewall(
            incluir_detalhes=False
        ),

        "last_update": agora_ts.isoformat(),
    }


def prod_data(
    period: str,
) -> dict[str, Any]:
    delta_h = delta_horas(
        period
    )

    agora_ts = timezone.now()

    desde = (
        agora_ts
        - timedelta(
            hours=delta_h
        )
    )

    qs = EventoFirewall.objects.filter(
        timestamp__gte=desde
    )

    drops = qs.filter(
        acao__in=[
            "DROP",
            "DENY",
        ]
    ).count()

    allows = qs.filter(
        acao__in=[
            "ALLOW",
            "LOG",
        ]
    ).count()

    total_bytes = (
        qs.aggregate(
            s=Sum(
                "tamanho"
            )
        )["s"]
        or 0
    )

    traffic_mb = max(
        0,
        total_bytes
        // 1_048_576,
    )

    traffic_in = int(
        traffic_mb
        * 0.7
    )

    traffic_out = int(
        traffic_mb
        * 0.3
    )

    recente = (
        agora_ts
        - timedelta(
            minutes=5
        )
    )

    conexoes = (
        EventoFirewall.objects
        .filter(
            timestamp__gte=recente,
            acao__in=[
                "ALLOW",
                "LOG",
            ],
        )
        .values(
            "src_ip"
        )
        .distinct()
        .count()
    )

    top_port_row = (
        qs
        .filter(
            acao__in=[
                "DROP",
                "DENY",
            ]
        )
        .exclude(
            dst_port__isnull=True
        )
        .values(
            "dst_port"
        )
        .annotate(
            n=Count(
                "dst_port"
            )
        )
        .order_by(
            "-n"
        )
        .first()
    )

    top_port = (
        str(
            top_port_row[
                "dst_port"
            ]
        )
        if top_port_row
        else "—"
    )

    top_port_hits = (
        top_port_row[
            "n"
        ]
        if top_port_row
        else 0
    )

    top_ip_row = (
        qs
        .filter(
            acao__in=[
                "DROP",
                "DENY",
            ]
        )
        .values(
            "src_ip"
        )
        .annotate(
            n=Count(
                "src_ip"
            )
        )
        .order_by(
            "-n"
        )
        .first()
    )

    top_ip = (
        str(
            top_ip_row[
                "src_ip"
            ]
        )
        if top_ip_row
        else "—"
    )

    top_ip_hits = (
        top_ip_row[
            "n"
        ]
        if top_ip_row
        else 0
    )

    top_ips = [
        {
            "ip": str(
                row[
                    "src_ip"
                ]
            ),
            "hits": row[
                "hits"
            ],
        }
        for row in (
            qs
            .filter(
                acao__in=[
                    "DROP",
                    "DENY",
                ]
            )
            .values(
                "src_ip"
            )
            .annotate(
                hits=Count(
                    "src_ip"
                )
            )
            .order_by(
                "-hits"
            )[:5]
        )
    ]

    qs_24 = EventoFirewall.objects.filter(
        timestamp__gte=(
            agora_ts
            - timedelta(
                hours=24
            )
        )
    )

    hourly = (
        qs_24
        .annotate(
            hora=TruncHour(
                "timestamp"
            )
        )
        .values(
            "hora",
            "acao",
        )
        .annotate(
            n=Count(
                "id"
            ),
            total_bytes=Sum(
                "tamanho"
            ),
        )
        .order_by(
            "hora"
        )
    )

    hour_data: dict[str, dict[str, int]] = {}

    for row in hourly:
        hora = row.get(
            "hora"
        )

        if hora is None:
            continue

        lbl = hora.strftime(
            "%Hh"
        )

        if lbl not in hour_data:
            hour_data[
                lbl
            ] = {
                "in": 0,
                "out": 0,
                "drops": 0,
                "denies": 0,
            }

        b = (
            row.get(
                "total_bytes"
            )
            or 0
        ) // 1_048_576

        if row[
            "acao"
        ] in (
            "ALLOW",
            "LOG",
        ):
            hour_data[
                lbl
            ][
                "in"
            ] += int(
                b
                * 0.7
            )

            hour_data[
                lbl
            ][
                "out"
            ] += int(
                b
                * 0.3
            )

        elif row[
            "acao"
        ] == "DROP":
            hour_data[
                lbl
            ][
                "drops"
            ] += row[
                "n"
            ]

        elif row[
            "acao"
        ] == "DENY":
            hour_data[
                lbl
            ][
                "denies"
            ] += row[
                "n"
            ]

    hour_labels = [
        (
            agora_ts
            - timedelta(
                hours=23 - i
            )
        ).strftime(
            "%Hh"
        )
        for i in range(
            24
        )
    ]

    chart_in = [
        hour_data.get(
            h,
            {},
        ).get(
            "in",
            0,
        )
        for h in hour_labels
    ]

    chart_out = [
        hour_data.get(
            h,
            {},
        ).get(
            "out",
            0,
        )
        for h in hour_labels
    ]

    chart_drops = [
        hour_data.get(
            h,
            {},
        ).get(
            "drops",
            0,
        )
        for h in hour_labels
    ]

    chart_denies = [
        hour_data.get(
            h,
            {},
        ).get(
            "denies",
            0,
        )
        for h in hour_labels
    ]

    rules = [
        rule_to_dict(
            r
        )
        for r in RegraFirewall.objects.filter(
            deletado=False
        ).order_by(
            "priority",
            "id",
        )
    ]

    nat = [
        nat_to_dict(
            n
        )
        for n in NatEntry.objects.all()
    ]

    blocklist = [
        block_to_dict(
            b
        )
        for b in BlocklistEntry.objects.all()
    ]

    allowlist = [
        allow_to_dict(
            a
        )
        for a in AllowlistEntry.objects.all()
    ]

    geoblock = [
        geo_to_dict(
            g
        )
        for g in GeoblockEntry.objects.all()
    ]

    logs = [
        evento_to_log(
            e
        )
        for e in (
            EventoFirewall.objects
            .filter(
                timestamp__gte=desde
            )
            .order_by(
                "-timestamp"
            )[:100]
        )
    ]

    firewall_status = obter_estado_firewall(
        incluir_detalhes=False
    )

    return {
        "ok": True,
        "mode": "prod",
        "modo": "real",
        "fonte": "local",

        "metrics": {
            "traffic_in": traffic_in,
            "traffic_out": traffic_out,
            "conexoes": conexoes,
            "drops": drops,
            "allows": allows,
            "top_port": top_port,
            "top_port_hits": top_port_hits,
            "top_ip": top_ip,
            "top_ip_hits": top_ip_hits,

            # CPU/RAM podem ser adicionados depois pelo Agent status.
            "cpu": 0,
            "ram": 0,
        },

        "charts": {
            "hours": hour_labels,
            "traffic_in": chart_in,
            "traffic_out": chart_out,
            "drops": chart_drops,
            "denies": chart_denies,
        },

        "top_ips": top_ips,
        "rules": rules,
        "logs": logs,
        "nat": nat,
        "blocklist": blocklist,
        "allowlist": allowlist,
        "geoblock": geoblock,

        "sync": sync_status(),

        "firewall": firewall_status,

        "last_update": agora_ts.isoformat(),
    }