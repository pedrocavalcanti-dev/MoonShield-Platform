"""
MoonShield Agent — Firewall / Analisador
========================================

Parser local dos eventos gerados pelo nftables no kernel/journald.

Este módulo NÃO envia HTTP e NÃO acessa Django.
Ele apenas transforma linhas do kernel em eventos estruturados que o módulo
monitoramento.py poderá gravar localmente.

Pipeline esperado:

    nftables LOG
        ↓
    kernel / journald
        ↓
    analisador.py
        ↓
    evento normalizado
        ↓
    monitoramento.py
        ↓
    /var/log/moonshield/firewall/events.jsonl

Prefixos oficiais MoonShield Firewall:
    MS-FW-ALLOW
    MS-FW-DROP
    MS-FW-REJECT
    MS-FW-SYSTEM

Compatibilidade temporária com prefixos antigos:
    MS-FWD
    MS-INPUT
    MS-DROP
    MS-OUT
    MS-REJ

O parser é tolerante a campos ausentes e nunca lança exceção para uma linha
inválida: `parsear_linha()` retorna None nesses casos.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any


# =============================================================================
# VERSÃO
# =============================================================================

VERSAO_ANALISADOR = "3.0"


# =============================================================================
# PREFIXOS
# =============================================================================

PREFIXOS_OFICIAIS = frozenset({
    "MS-FW-ALLOW",
    "MS-FW-DROP",
    "MS-FW-REJECT",
    "MS-FW-SYSTEM",
})

PREFIXOS_LEGADOS = frozenset({
    "MS-FWD",
    "MS-INPUT",
    "MS-DROP",
    "MS-OUT",
    "MS-REJ",
})

PREFIXOS_RECONHECIDOS = (
    PREFIXOS_OFICIAIS
    | PREFIXOS_LEGADOS
)

PREFIXO_FILTRO = "MS-"


# =============================================================================
# REGEX
# =============================================================================

_RE_CAMPO = re.compile(
    r"([A-Za-z0-9_]+)=([^\s]+)"
)

_RE_PREFIXO = re.compile(
    r"\b("
    + "|".join(
        re.escape(p)
        for p in sorted(
            PREFIXOS_RECONHECIDOS,
            key=len,
            reverse=True,
        )
    )
    + r")(?::|\s|$)"
)

_RE_JOURNAL_TS = re.compile(
    r"^(?P<mes>[A-Z][a-z]{2})\s+"
    r"(?P<dia>\d{1,2})\s+"
    r"(?P<hora>\d{2}:\d{2}:\d{2})"
)

_RE_SYSLOG_TS = re.compile(
    r"^(?P<ano>\d{4})-(?P<mes>\d{2})-(?P<dia>\d{2})"
    r"[T\s]"
    r"(?P<hora>\d{2}:\d{2}:\d{2}(?:\.\d+)?)"
)

_RE_HANDLE = re.compile(
    r"#\s*handle\s+(\d+)"
)

_RE_MAC = re.compile(
    r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$"
)


# =============================================================================
# FLAGS
# =============================================================================

_FLAGS_TCP = frozenset({
    "SYN",
    "ACK",
    "FIN",
    "RST",
    "URG",
    "PSH",
    "ECE",
    "CWR",
})


# =============================================================================
# MAPAS
# =============================================================================

_MAPA_PREFIXO = {
    # Oficiais
    "MS-FW-ALLOW": (
        "ALLOW",
        "FILTER",
    ),
    "MS-FW-DROP": (
        "DROP",
        "FILTER",
    ),
    "MS-FW-REJECT": (
        "REJECT",
        "FILTER",
    ),
    "MS-FW-SYSTEM": (
        "LOG",
        "SYSTEM",
    ),

    # Legados
    "MS-FWD": (
        "LOG",
        "FORWARD",
    ),
    "MS-INPUT": (
        "LOG",
        "INPUT",
    ),
    "MS-DROP": (
        "DROP",
        "INPUT",
    ),
    "MS-OUT": (
        "LOG",
        "OUTPUT",
    ),
    "MS-REJ": (
        "REJECT",
        "INPUT",
    ),
}


# =============================================================================
# INTERFACE PÚBLICA
# =============================================================================

def parsear_linha(
    linha: str,
) -> dict[str, Any] | None:
    """
    Parseia uma linha do kernel/journald.

    Retorna:
        dict normalizado
        None se a linha não pertencer ao MoonShield ou for inválida.
    """
    if not isinstance(
        linha,
        str,
    ):
        return None

    if PREFIXO_FILTRO not in linha:
        return None

    try:
        return _extrair_campos(
            linha
        )
    except Exception:
        return None


def parsear_linhas(
    linhas,
) -> list[dict[str, Any]]:
    """
    Converte várias linhas e ignora as que não gerarem evento.
    """
    eventos: list[dict[str, Any]] = []

    for linha in linhas:
        evento = parsear_linha(
            str(
                linha
            )
        )

        if evento:
            eventos.append(
                evento
            )

    return eventos


def parece_evento_moonshield(
    linha: str,
) -> bool:
    """
    Filtro barato para monitoramento.py.
    """
    return (
        isinstance(
            linha,
            str,
        )
        and PREFIXO_FILTRO in linha
        and _RE_PREFIXO.search(
            linha
        ) is not None
    )


# =============================================================================
# PARSER
# =============================================================================

def _extrair_campos(
    linha: str,
) -> dict[str, Any] | None:
    match = _RE_PREFIXO.search(
        linha
    )

    if not match:
        return None

    prefixo = match.group(
        1
    )

    if prefixo not in PREFIXOS_RECONHECIDOS:
        return None

    acao_padrao, chain_padrao = _MAPA_PREFIXO[
        prefixo
    ]

    campos = {
        chave.upper(): valor
        for chave, valor in _RE_CAMPO.findall(
            linha
        )
    }

    src_ip = _normalizar_ip(
        campos.get(
            "SRC",
            "",
        )
    )

    dst_ip = _normalizar_ip(
        campos.get(
            "DST",
            "",
        )
    )

    # Alguns logs de sistema podem não conter SRC/DST.
    # Eventos de tráfego precisam de pelo menos um dos dois.
    if (
        prefixo != "MS-FW-SYSTEM"
        and not src_ip
        and not dst_ip
    ):
        return None

    proto = _normalizar_proto(
        campos.get(
            "PROTO",
            "",
        )
    )

    chain = (
        campos.get(
            "CHAIN",
            ""
        ).strip().upper()
        or chain_padrao
    )

    acao = _inferir_acao(
        prefixo=prefixo,
        linha=linha,
        campos=campos,
        padrao=acao_padrao,
    )

    iface_entrada = _normalizar_iface(
        campos.get(
            "IN",
            "",
        )
    )

    iface_saida = _normalizar_iface(
        campos.get(
            "OUT",
            "",
        )
    )

    src_port = _porta_ou_none(
        campos.get(
            "SPT"
        )
        or campos.get(
            "SPORT"
        )
    )

    dst_port = _porta_ou_none(
        campos.get(
            "DPT"
        )
        or campos.get(
            "DPORT"
        )
    )

    evento = {
        "timestamp": _extrair_timestamp(
            linha
        ),
        "timestamp_epoch": _agora_epoch(),

        "origem": "nftables",
        "subsystem": "firewall",
        "versao_parser": VERSAO_ANALISADOR,

        "prefixo": prefixo,
        "prefixo_oficial": (
            prefixo in PREFIXOS_OFICIAIS
        ),
        "legado": (
            prefixo in PREFIXOS_LEGADOS
        ),

        "acao": acao,
        "chain": chain,
        "proto": proto,

        "src_ip": src_ip,
        "src_port": src_port,

        "dst_ip": dst_ip,
        "dst_port": dst_port,

        "iface_entrada": iface_entrada,
        "iface_saida": iface_saida,

        # Alias temporário útil para o Django antigo.
        "iface": (
            iface_entrada
            or iface_saida
        ),

        "tamanho": _int_ou_none(
            campos.get(
                "LEN"
            )
        ),

        "ttl": _int_ou_none(
            campos.get(
                "TTL"
            )
        ),

        "hop_limit": _int_ou_none(
            campos.get(
                "HOPLIMIT"
            )
            or campos.get(
                "HL"
            )
        ),

        "tos": campos.get(
            "TOS",
            "",
        ),

        "prec": campos.get(
            "PREC",
            "",
        ),

        "id_ip": _int_ou_none(
            campos.get(
                "ID"
            )
        ),

        "window": _int_ou_none(
            campos.get(
                "WINDOW"
            )
        ),

        "res": campos.get(
            "RES",
            "",
        ),

        "urgp": _int_ou_none(
            campos.get(
                "URGP"
            )
        ),

        "flags_tcp": _extrair_flags(
            linha
        ),

        "mac_src": _mac_ou_vazio(
            campos.get(
                "MACSRC"
            )
            or campos.get(
                "SRCMAC"
            )
        ),

        "mac_dst": _mac_ou_vazio(
            campos.get(
                "MACDST"
            )
            or campos.get(
                "DSTMAC"
            )
        ),

        "uid": _int_ou_none(
            campos.get(
                "UID"
            )
        ),

        "gid": _int_ou_none(
            campos.get(
                "GID"
            )
        ),

        "mark": campos.get(
            "MARK",
            "",
        ),

        "handle": _extrair_handle(
            linha
        ),

        "raw": linha.strip(),
    }

    evento[
        "familia_ip"
    ] = _detectar_familia(
        src_ip,
        dst_ip,
    )

    evento[
        "direcao"
    ] = _inferir_direcao(
        chain=chain,
        iface_entrada=iface_entrada,
        iface_saida=iface_saida,
    )

    evento[
        "severidade"
    ] = _inferir_severidade(
        evento
    )

    evento[
        "bloqueado"
    ] = (
        evento[
            "acao"
        ] in {
            "DROP",
            "DENY",
            "REJECT",
        }
    )

    evento[
        "permitido"
    ] = (
        evento[
            "acao"
        ] in {
            "ALLOW",
            "ACCEPT",
        }
    )

    evento[
        "chave_evento"
    ] = _montar_chave_evento(
        evento
    )

    return evento


# =============================================================================
# NORMALIZAÇÕES
# =============================================================================

def _normalizar_ip(
    valor: str,
) -> str:
    texto = str(
        valor
        or ""
    ).strip()

    if not texto:
        return ""

    try:
        return str(
            ipaddress.ip_address(
                texto
            )
        )
    except ValueError:
        return ""


def _normalizar_proto(
    valor: str,
) -> str:
    proto = str(
        valor
        or ""
    ).strip().upper()

    aliases = {
        "6": "TCP",
        "17": "UDP",
        "1": "ICMP",
        "58": "ICMPV6",
        "IPV6-ICMP": "ICMPV6",
    }

    return aliases.get(
        proto,
        proto,
    )


def _normalizar_iface(
    valor: str,
) -> str:
    iface = str(
        valor
        or ""
    ).strip()

    if iface in {
        "?",
        "-",
    }:
        return ""

    # Limite defensivo.
    return iface[
        :64
    ]


def _inferir_acao(
    *,
    prefixo: str,
    linha: str,
    campos: dict[str, str],
    padrao: str,
) -> str:
    acao_campo = (
        campos.get(
            "ACTION"
        )
        or campos.get(
            "VERDICT"
        )
        or ""
    ).strip().upper()

    if acao_campo in {
        "ALLOW",
        "ACCEPT",
        "DROP",
        "DENY",
        "REJECT",
        "LOG",
    }:
        return acao_campo

    upper = linha.upper()

    # Ordem importante: REJECT/DROP antes de ACCEPT.
    if " REJECT " in upper:
        return "REJECT"

    if " DROP " in upper:
        return "DROP"

    if " DENY " in upper:
        return "DENY"

    if " ACCEPT " in upper:
        return "ACCEPT"

    if " ALLOW " in upper:
        return "ALLOW"

    return padrao


# =============================================================================
# TIMESTAMP
# =============================================================================

def _extrair_timestamp(
    linha: str,
) -> str:
    """
    Tenta preservar timestamp do journald/syslog.
    Em caso de dúvida usa UTC atual.
    """
    agora = datetime.now(
        timezone.utc
    )

    match_iso = _RE_SYSLOG_TS.search(
        linha
    )

    if match_iso:
        try:
            texto = (
                f"{match_iso.group('ano')}-"
                f"{match_iso.group('mes')}-"
                f"{match_iso.group('dia')}T"
                f"{match_iso.group('hora')}"
            )

            dt = datetime.fromisoformat(
                texto
            )

            if dt.tzinfo is None:
                dt = dt.replace(
                    tzinfo=timezone.utc
                )

            return dt.isoformat()

        except Exception:
            pass

    match_journal = _RE_JOURNAL_TS.search(
        linha
    )

    if match_journal:
        try:
            texto = (
                f"{agora.year} "
                f"{match_journal.group('mes')} "
                f"{match_journal.group('dia')} "
                f"{match_journal.group('hora')}"
            )

            dt = datetime.strptime(
                texto,
                "%Y %b %d %H:%M:%S",
            ).replace(
                tzinfo=timezone.utc
            )

            return dt.isoformat()

        except Exception:
            pass

    return agora.isoformat()


def _agora_epoch() -> float:
    return datetime.now(
        timezone.utc
    ).timestamp()


# =============================================================================
# CAMPOS
# =============================================================================

def _int_ou_none(
    valor: Any,
) -> int | None:
    if valor is None:
        return None

    try:
        return int(
            str(
                valor
            ).strip()
        )
    except (
        ValueError,
        TypeError,
    ):
        return None


def _porta_ou_none(
    valor: Any,
) -> int | None:
    porta = _int_ou_none(
        valor
    )

    if porta is None:
        return None

    if (
        0
        <= porta
        <= 65535
    ):
        return porta

    return None


def _extrair_flags(
    linha: str,
) -> str:
    tokens = {
        token.strip(
            "[](),;"
        ).upper()
        for token in linha.split()
    }

    flags = sorted(
        _FLAGS_TCP
        & tokens
    )

    return ",".join(
        flags
    )


def _extrair_handle(
    linha: str,
) -> int | None:
    match = _RE_HANDLE.search(
        linha
    )

    if not match:
        return None

    return _int_ou_none(
        match.group(
            1
        )
    )


def _mac_ou_vazio(
    valor: Any,
) -> str:
    texto = str(
        valor
        or ""
    ).strip()

    if not texto:
        return ""

    if _RE_MAC.fullmatch(
        texto
    ):
        return texto.lower()

    return ""


# =============================================================================
# ENRIQUECIMENTO LOCAL
# =============================================================================

def _detectar_familia(
    src_ip: str,
    dst_ip: str,
) -> str:
    for valor in (
        src_ip,
        dst_ip,
    ):
        if not valor:
            continue

        try:
            versao = ipaddress.ip_address(
                valor
            ).version

            return (
                "IPv6"
                if versao == 6
                else "IPv4"
            )

        except ValueError:
            continue

    return ""


def _inferir_direcao(
    *,
    chain: str,
    iface_entrada: str,
    iface_saida: str,
) -> str:
    chain = str(
        chain
        or ""
    ).upper()

    if chain == "INPUT":
        return "IN"

    if chain == "OUTPUT":
        return "OUT"

    if chain == "FORWARD":
        return "FORWARD"

    if iface_entrada and iface_saida:
        return "FORWARD"

    if iface_entrada:
        return "IN"

    if iface_saida:
        return "OUT"

    return "UNKNOWN"


def _inferir_severidade(
    evento: dict[str, Any],
) -> str:
    acao = str(
        evento.get(
            "acao",
            "",
        )
    ).upper()

    porta = evento.get(
        "dst_port"
    )

    if acao in {
        "DROP",
        "DENY",
        "REJECT",
    }:
        if porta in {
            22,
            23,
            3389,
            5900,
        }:
            return "alta"

        return "media"

    if (
        evento.get(
            "prefixo"
        )
        == "MS-FW-SYSTEM"
    ):
        return "baixa"

    return "info"


def _montar_chave_evento(
    evento: dict[str, Any],
) -> str:
    """
    Chave textual estável o suficiente para agrupamento local.
    O hash definitivo pode ser calculado no monitor/Django.
    """
    campos = [
        evento.get(
            "acao",
            "",
        ),
        evento.get(
            "chain",
            "",
        ),
        evento.get(
            "proto",
            "",
        ),
        evento.get(
            "src_ip",
            "",
        ),
        evento.get(
            "src_port",
            "",
        ),
        evento.get(
            "dst_ip",
            "",
        ),
        evento.get(
            "dst_port",
            "",
        ),
        evento.get(
            "iface_entrada",
            "",
        ),
        evento.get(
            "iface_saida",
            "",
        ),
    ]

    return "|".join(
        str(
            campo
            if campo is not None
            else ""
        )
        for campo in campos
    )


# =============================================================================
# DIAGNÓSTICO DO PARSER
# =============================================================================

def diagnosticar_linha(
    linha: str,
) -> dict[str, Any]:
    """
    Útil para teste manual no Linux.
    """
    if PREFIXO_FILTRO not in str(
        linha
    ):
        return {
            "ok": False,
            "motivo": "Linha não contém prefixo MoonShield.",
            "evento": None,
        }

    evento = parsear_linha(
        linha
    )

    if evento is None:
        return {
            "ok": False,
            "motivo": "Linha não pôde ser parseada.",
            "evento": None,
        }

    return {
        "ok": True,
        "versao": VERSAO_ANALISADOR,
        "evento": evento,
    }