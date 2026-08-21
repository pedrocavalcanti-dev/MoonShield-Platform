"""
MoonShield Platform — Firewall / Ingestão Local
==============================================

Lê eventos produzidos localmente pelo MoonShield-Agent:

    /var/log/moonshield/firewall/events.jsonl

e persiste em:

    EventoFirewall

Também mantém cursor local para que o Django não reprocesse o arquivo inteiro.

IMPORTANTE:
- NÃO usa HTTP.
- NÃO usa receptor/sensor.
- NÃO usa token.
- NÃO depende de /firewall/api/ingest/.
- É pensado para ser chamado pelo management command:
      processar_eventos_firewall.py

Formato esperado por linha:
    {
        "schema": 1,
        "tipo_evento": "firewall",
        "gravado_em": "...",
        "evento": {...}
    }
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone as dt_timezone
from pathlib import Path
from typing import Any

from django.conf import settings
from django.db import IntegrityError
from django.utils import timezone

from firewall.models import EventoFirewall


logger = logging.getLogger(__name__)


VERSAO_INGESTAO_LOCAL = "1.0"

ARQUIVO_EVENTOS_PADRAO = Path(
    "/var/log/moonshield/firewall/events.jsonl"
)

CURSOR_NOME = "firewall_events.cursor"

MAX_LINHA_BYTES = 1024 * 1024

ACOES_VALIDAS = {
    "ALLOW",
    "ACCEPT",
    "DROP",
    "DENY",
    "REJECT",
    "LOG",
}


# =============================================================================
# RESULTADO
# =============================================================================

@dataclass(slots=True)
class ResultadoIngestao:
    processados: int = 0
    inseridos: int = 0
    duplicados: int = 0
    ignorados: int = 0
    erros: int = 0
    bytes_lidos: int = 0
    cursor_inicial: int = 0
    cursor_final: int = 0
    arquivo: str = ""

    def para_dict(self) -> dict[str, Any]:
        return {
            "ok": self.erros == 0,
            "processados": self.processados,
            "inseridos": self.inseridos,
            "duplicados": self.duplicados,
            "ignorados": self.ignorados,
            "erros": self.erros,
            "bytes_lidos": self.bytes_lidos,
            "cursor_inicial": self.cursor_inicial,
            "cursor_final": self.cursor_final,
            "arquivo": self.arquivo,
            "versao": VERSAO_INGESTAO_LOCAL,
        }


# =============================================================================
# CAMINHOS
# =============================================================================

def obter_arquivo_eventos() -> Path:
    valor = getattr(
        settings,
        "MOONSHIELD_FIREWALL_EVENTS_FILE",
        "",
    )

    if valor:
        return Path(
            str(valor)
        )

    env = os.getenv(
        "MOONSHIELD_FIREWALL_EVENTS_FILE",
        "",
    ).strip()

    if env:
        return Path(
            env
        )

    return ARQUIVO_EVENTOS_PADRAO


def obter_cursor_path() -> Path:
    valor = getattr(
        settings,
        "MOONSHIELD_FIREWALL_CURSOR_FILE",
        "",
    )

    if valor:
        path = Path(
            str(valor)
        )
        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        return path

    base_dir = Path(
        getattr(
            settings,
            "BASE_DIR",
            Path.cwd(),
        )
    )

    cursor_dir = (
        base_dir
        / "var"
        / "cursors"
    )

    cursor_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    return (
        cursor_dir
        / CURSOR_NOME
    )


# =============================================================================
# CURSOR
# =============================================================================

def ler_cursor() -> int:
    path = obter_cursor_path()

    try:
        valor = int(
            path.read_text(
                encoding="utf-8",
            ).strip()
            or "0"
        )
        return max(
            0,
            valor,
        )
    except Exception:
        return 0


def salvar_cursor(
    posicao: int,
) -> None:
    path = obter_cursor_path()

    temporario = path.with_suffix(
        path.suffix + ".tmp"
    )

    temporario.write_text(
        str(
            max(
                0,
                int(
                    posicao
                ),
            )
        ),
        encoding="utf-8",
    )

    os.replace(
        temporario,
        path,
    )


def resetar_cursor() -> None:
    salvar_cursor(
        0
    )


# =============================================================================
# PROCESSAMENTO
# =============================================================================

def processar_novos_eventos(
    *,
    limite: int = 1000,
) -> dict[str, Any]:
    arquivo = obter_arquivo_eventos()

    resultado = ResultadoIngestao(
        arquivo=str(
            arquivo
        )
    )

    if not arquivo.exists():
        return {
            **resultado.para_dict(),
            "ok": True,
            "arquivo_existe": False,
        }

    tamanho = arquivo.stat().st_size
    cursor = ler_cursor()

    # Arquivo rotacionado/truncado.
    if cursor > tamanho:
        logger.info(
            "Cursor do Firewall maior que o arquivo; reiniciando."
        )
        cursor = 0

    resultado.cursor_inicial = cursor

    with arquivo.open(
        "rb"
    ) as fp:
        fp.seek(
            cursor
        )

        while resultado.processados < limite:
            pos_antes = fp.tell()
            raw = fp.readline()

            if not raw:
                break

            pos_depois = fp.tell()
            resultado.bytes_lidos += (
                pos_depois
                - pos_antes
            )

            # Linha incompleta sendo escrita pelo Agent.
            if not raw.endswith(b"\n"):
                fp.seek(
                    pos_antes
                )
                break

            if len(raw) > MAX_LINHA_BYTES:
                resultado.erros += 1
                resultado.processados += 1
                continue

            try:
                texto = raw.decode(
                    "utf-8"
                )
                envelope = json.loads(
                    texto
                )
            except Exception:
                resultado.erros += 1
                resultado.processados += 1
                continue

            resultado.processados += 1

            evento = _extrair_evento(
                envelope
            )

            if not evento:
                resultado.ignorados += 1
                continue

            try:
                status = salvar_evento(
                    evento
                )

                if status == "inserido":
                    resultado.inseridos += 1

                elif status == "duplicado":
                    resultado.duplicados += 1

                else:
                    resultado.ignorados += 1

            except Exception:
                logger.exception(
                    "Erro ao persistir evento de Firewall."
                )
                resultado.erros += 1

        resultado.cursor_final = fp.tell()

    salvar_cursor(
        resultado.cursor_final
    )

    return {
        **resultado.para_dict(),
        "arquivo_existe": True,
    }


# =============================================================================
# EVENTO
# =============================================================================

def salvar_evento(
    evento: dict[str, Any],
) -> str:
    normalizado = normalizar_evento(
        evento
    )

    if not normalizado:
        return "ignorado"

    event_hash = _event_hash(
        normalizado
    )

    try:
        EventoFirewall.objects.create(
            sensor=None,
            timestamp=normalizado[
                "timestamp"
            ],
            acao=normalizado[
                "acao"
            ],
            chain=normalizado[
                "chain"
            ],
            proto=normalizado[
                "proto"
            ],
            src_ip=normalizado[
                "src_ip"
            ],
            src_port=normalizado[
                "src_port"
            ],
            dst_ip=normalizado[
                "dst_ip"
            ],
            dst_port=normalizado[
                "dst_port"
            ],
            iface=normalizado[
                "iface"
            ],
            iface_saida=normalizado[
                "iface_saida"
            ],
            tamanho=normalizado[
                "tamanho"
            ],
            ttl=normalizado[
                "ttl"
            ],
            flags_tcp=normalizado[
                "flags_tcp"
            ],
            prefixo=normalizado[
                "prefixo"
            ],
            event_hash=event_hash,
            raw_json=evento,
        )

        return "inserido"

    except IntegrityError:
        return "duplicado"


def normalizar_evento(
    evento: dict[str, Any],
) -> dict[str, Any] | None:
    if not isinstance(
        evento,
        dict,
    ):
        return None

    src_ip = _ip_ou_none(
        evento.get(
            "src_ip"
        )
    )

    if not src_ip:
        return None

    dst_ip = _ip_ou_none(
        evento.get(
            "dst_ip"
        )
    )

    acao = str(
        evento.get(
            "acao"
        )
        or "LOG"
    ).upper()

    # O model atual não possui REJECT/ACCEPT.
    if acao == "REJECT":
        acao = "DENY"

    elif acao == "ACCEPT":
        acao = "ALLOW"

    if acao not in {
        "ALLOW",
        "DROP",
        "DENY",
        "LOG",
    }:
        acao = "LOG"

    timestamp = _parse_timestamp(
        evento.get(
            "timestamp"
        )
    )

    iface_entrada = str(
        evento.get(
            "iface_entrada"
        )
        or evento.get(
            "iface"
        )
        or ""
    )[:30]

    iface_saida = str(
        evento.get(
            "iface_saida"
        )
        or ""
    )[:30]

    return {
        "timestamp": timestamp,
        "acao": acao,
        "chain": str(
            evento.get(
                "chain"
            )
            or ""
        )[:20],
        "proto": str(
            evento.get(
                "proto"
            )
            or ""
        )[:10],
        "src_ip": src_ip,
        "src_port": _porta(
            evento.get(
                "src_port"
            )
        ),
        "dst_ip": dst_ip,
        "dst_port": _porta(
            evento.get(
                "dst_port"
            )
        ),
        "iface": iface_entrada,
        "iface_saida": iface_saida,
        "tamanho": _int_ou_none(
            evento.get(
                "tamanho"
            )
        ),
        "ttl": _int_ou_none(
            evento.get(
                "ttl"
            )
        ),
        "flags_tcp": str(
            evento.get(
                "flags_tcp"
            )
            or ""
        )[:50],
        "prefixo": str(
            evento.get(
                "prefixo"
            )
            or ""
        )[:20],
    }


# =============================================================================
# HELPERS
# =============================================================================

def _extrair_evento(
    envelope: Any,
) -> dict[str, Any] | None:
    if not isinstance(
        envelope,
        dict,
    ):
        return None

    # Formato novo do Agent.
    if isinstance(
        envelope.get(
            "evento"
        ),
        dict,
    ):
        return envelope[
            "evento"
        ]

    # Compatibilidade útil para testes manuais.
    if "src_ip" in envelope:
        return envelope

    return None


def _parse_timestamp(
    valor: Any,
):
    if isinstance(
        valor,
        datetime,
    ):
        dt = valor
    else:
        texto = str(
            valor
            or ""
        ).strip()

        if not texto:
            return timezone.now()

        try:
            dt = datetime.fromisoformat(
                texto.replace(
                    "Z",
                    "+00:00",
                )
            )
        except ValueError:
            return timezone.now()

    if dt.tzinfo is None:
        dt = dt.replace(
            tzinfo=dt_timezone.utc
        )

    return dt


def _ip_ou_none(
    valor: Any,
) -> str | None:
    texto = str(
        valor
        or ""
    ).strip()

    if not texto:
        return None

    try:
        return str(
            ipaddress.ip_address(
                texto
            )
        )
    except ValueError:
        return None


def _porta(
    valor: Any,
) -> int | None:
    numero = _int_ou_none(
        valor
    )

    if numero is None:
        return None

    if 0 <= numero <= 65535:
        return numero

    return None


def _int_ou_none(
    valor: Any,
) -> int | None:
    try:
        if valor is None or valor == "":
            return None

        return int(
            valor
        )

    except (
        TypeError,
        ValueError,
    ):
        return None


def _event_hash(
    evento: dict[str, Any],
) -> str:
    ts = evento[
        "timestamp"
    ]

    if hasattr(
        ts,
        "isoformat",
    ):
        ts_texto = ts.isoformat()
    else:
        ts_texto = str(
            ts
        )

    raw = "|".join(
        [
            str(
                evento.get(
                    "acao",
                    ""
                )
            ),
            str(
                evento.get(
                    "src_ip",
                    ""
                )
            ),
            str(
                evento.get(
                    "src_port",
                    ""
                )
            ),
            str(
                evento.get(
                    "dst_ip",
                    ""
                )
            ),
            str(
                evento.get(
                    "dst_port",
                    ""
                )
            ),
            str(
                evento.get(
                    "proto",
                    ""
                )
            ),
            ts_texto,
            str(
                evento.get(
                    "prefixo",
                    ""
                )
            ),
        ]
    )

    return hashlib.sha256(
        raw.encode(
            "utf-8"
        )
    ).hexdigest()