"""
MoonShield Platform — Management Command / processar_eventos_firewall
=====================================================================

Worker local de ingestão dos eventos do MoonShield Firewall.

Origem:
    /var/log/moonshield/firewall/events.jsonl

Destino:
    EventoFirewall

Cursor:
    <BASE_DIR>/var/cursors/firewall_events.cursor

Este command NÃO:
- usa HTTP;
- recebe POST do Agent;
- usa Sensor;
- usa token;
- executa nftables.

Uso:

    python gerenciar.py processar_eventos_firewall

    python gerenciar.py processar_eventos_firewall --once

    python gerenciar.py processar_eventos_firewall --interval 1

    python gerenciar.py processar_eventos_firewall --batch 500

    python gerenciar.py processar_eventos_firewall --reset-cursor --once
"""

from __future__ import annotations

import logging
import signal
import time
from typing import Any

from django.core.management.base import (
    BaseCommand,
    CommandError,
)

from firewall.services.ingestao_local import (
    obter_arquivo_eventos,
    obter_cursor_path,
    processar_novos_eventos,
    resetar_cursor,
)


logger = logging.getLogger(__name__)


VERSAO_WORKER = "1.0"

INTERVALO_PADRAO = 1.0
INTERVALO_MIN = 0.2
INTERVALO_MAX = 60.0

BATCH_PADRAO = 1000
BATCH_MIN = 1
BATCH_MAX = 10000


class Command(BaseCommand):
    help = (
        "Processa continuamente os eventos locais do MoonShield Firewall "
        "e grava em EventoFirewall."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--once",
            action="store_true",
            help=(
                "Processa somente os eventos disponíveis agora "
                "e encerra."
            ),
        )

        parser.add_argument(
            "--interval",
            type=float,
            default=INTERVALO_PADRAO,
            help=(
                f"Intervalo entre ciclos em segundos "
                f"(padrão: {INTERVALO_PADRAO})."
            ),
        )

        parser.add_argument(
            "--batch",
            type=int,
            default=BATCH_PADRAO,
            help=(
                f"Máximo de linhas processadas por ciclo "
                f"(padrão: {BATCH_PADRAO})."
            ),
        )

        parser.add_argument(
            "--reset-cursor",
            action="store_true",
            help=(
                "Reseta o cursor para zero antes de iniciar. "
                "Pode reprocessar o arquivo inteiro."
            ),
        )

        parser.add_argument(
            "--quiet",
            action="store_true",
            help=(
                "Mostra apenas erros, mudanças relevantes e resumo final."
            ),
        )

        parser.add_argument(
            "--stop-on-error",
            action="store_true",
            help=(
                "Encerra o worker se um ciclo registrar erro de ingestão."
            ),
        )

    def handle(self, *args, **options):
        once = bool(
            options.get("once")
        )

        quiet = bool(
            options.get("quiet")
        )

        stop_on_error = bool(
            options.get("stop_on_error")
        )

        intervalo = _normalizar_intervalo(
            options.get("interval")
        )

        batch = _normalizar_batch(
            options.get("batch")
        )

        if options.get(
            "reset_cursor"
        ):
            resetar_cursor()

            self.stdout.write(
                self.style.WARNING(
                    "Cursor do Firewall resetado para 0."
                )
            )

        arquivo = obter_arquivo_eventos()
        cursor_path = obter_cursor_path()

        self.stdout.write(
            self.style.SUCCESS(
                "MoonShield Firewall Event Worker "
                f"v{VERSAO_WORKER} iniciado"
            )
        )

        self.stdout.write(
            f"Eventos : {arquivo}"
        )

        self.stdout.write(
            f"Cursor  : {cursor_path}"
        )

        self.stdout.write(
            f"Batch   : {batch}"
        )

        self.stdout.write(
            f"Intervalo: {intervalo:.2f}s"
        )

        if not arquivo.exists():
            self.stdout.write(
                self.style.WARNING(
                    "Arquivo de eventos ainda não existe. "
                    "O worker aguardará o MoonShield-Agent."
                )
            )

        parar = _FlagParada()
        _registrar_sinais(
            parar
        )

        totais = {
            "ciclos": 0,
            "processados": 0,
            "inseridos": 0,
            "duplicados": 0,
            "ignorados": 0,
            "erros": 0,
            "bytes_lidos": 0,
        }

        ultimo_cursor = None

        try:
            while not parar.ativo:
                inicio = time.monotonic()

                try:
                    resultado = processar_novos_eventos(
                        limite=batch
                    )

                except KeyboardInterrupt:
                    parar.ativo = True
                    break

                except Exception as exc:
                    totais[
                        "erros"
                    ] += 1

                    logger.exception(
                        "Falha fatal em processar_eventos_firewall"
                    )

                    self.stderr.write(
                        self.style.ERROR(
                            f"[ERRO] {type(exc).__name__}: {exc}"
                        )
                    )

                    if (
                        once
                        or stop_on_error
                    ):
                        break

                    _esperar_interrompivel(
                        parar,
                        intervalo,
                    )

                    continue

                totais[
                    "ciclos"
                ] += 1

                for chave in (
                    "processados",
                    "inseridos",
                    "duplicados",
                    "ignorados",
                    "erros",
                    "bytes_lidos",
                ):
                    totais[
                        chave
                    ] += int(
                        resultado.get(
                            chave,
                            0,
                        )
                        or 0
                    )

                cursor_atual = resultado.get(
                    "cursor_final"
                )

                houve_trabalho = bool(
                    resultado.get(
                        "processados",
                        0,
                    )
                )

                houve_erro = bool(
                    resultado.get(
                        "erros",
                        0,
                    )
                )

                if houve_trabalho:
                    _imprimir_resultado(
                        self,
                        resultado,
                    )

                elif (
                    not quiet
                    and cursor_atual != ultimo_cursor
                ):
                    self.stdout.write(
                        f"[IDLE] cursor={cursor_atual}"
                    )

                ultimo_cursor = cursor_atual

                if (
                    stop_on_error
                    and houve_erro
                ):
                    raise CommandError(
                        "Ingestão registrou erro e --stop-on-error está ativo."
                    )

                if once:
                    # Em --once, continua drenando o arquivo enquanto
                    # o batch vier completamente cheio.
                    if int(
                        resultado.get(
                            "processados",
                            0,
                        )
                    ) >= batch:
                        continue

                    break

                decorrido = (
                    time.monotonic()
                    - inicio
                )

                espera = max(
                    0.0,
                    intervalo - decorrido,
                )

                _esperar_interrompivel(
                    parar,
                    espera,
                )

        finally:
            self.stdout.write("")

            self.stdout.write(
                self.style.WARNING(
                    "MoonShield Firewall Event Worker encerrado"
                )
            )

            self.stdout.write(
                " | ".join(
                    [
                        f"Ciclos={totais['ciclos']}",
                        f"Processados={totais['processados']}",
                        f"Inseridos={totais['inseridos']}",
                        f"Duplicados={totais['duplicados']}",
                        f"Ignorados={totais['ignorados']}",
                        f"Erros={totais['erros']}",
                    ]
                )
            )


# =============================================================================
# SAÍDA
# =============================================================================

def _imprimir_resultado(
    command: Command,
    resultado: dict[str, Any],
) -> None:
    processados = int(
        resultado.get(
            "processados",
            0,
        )
        or 0
    )

    inseridos = int(
        resultado.get(
            "inseridos",
            0,
        )
        or 0
    )

    duplicados = int(
        resultado.get(
            "duplicados",
            0,
        )
        or 0
    )

    ignorados = int(
        resultado.get(
            "ignorados",
            0,
        )
        or 0
    )

    erros = int(
        resultado.get(
            "erros",
            0,
        )
        or 0
    )

    cursor = resultado.get(
        "cursor_final",
        0,
    )

    texto = (
        f"[EVENTOS] "
        f"proc={processados} | "
        f"novos={inseridos} | "
        f"dup={duplicados} | "
        f"ign={ignorados} | "
        f"erros={erros} | "
        f"cursor={cursor}"
    )

    if erros:
        command.stderr.write(
            command.style.ERROR(
                texto
            )
        )

    elif inseridos:
        command.stdout.write(
            command.style.SUCCESS(
                texto
            )
        )

    else:
        command.stdout.write(
            texto
        )


# =============================================================================
# LOOP / SINAIS
# =============================================================================

class _FlagParada:
    ativo: bool = False


def _registrar_sinais(
    flag: _FlagParada,
) -> None:
    def handler(
        signum,
        frame,
    ):
        flag.ativo = True

    for sig in (
        signal.SIGTERM,
        signal.SIGINT,
    ):
        try:
            signal.signal(
                sig,
                handler,
            )
        except Exception:
            pass


def _esperar_interrompivel(
    flag: _FlagParada,
    segundos: float,
) -> None:
    fim = (
        time.monotonic()
        + segundos
    )

    while (
        not flag.ativo
        and time.monotonic() < fim
    ):
        restante = (
            fim
            - time.monotonic()
        )

        time.sleep(
            min(
                0.25,
                max(
                    0.0,
                    restante,
                ),
            )
        )


def _normalizar_intervalo(
    valor: Any,
) -> float:
    try:
        numero = float(
            valor
        )
    except (
        TypeError,
        ValueError,
    ):
        numero = INTERVALO_PADRAO

    return max(
        INTERVALO_MIN,
        min(
            INTERVALO_MAX,
            numero,
        ),
    )


def _normalizar_batch(
    valor: Any,
) -> int:
    try:
        numero = int(
            valor
        )
    except (
        TypeError,
        ValueError,
    ):
        numero = BATCH_PADRAO

    return max(
        BATCH_MIN,
        min(
            BATCH_MAX,
            numero,
        ),
    )