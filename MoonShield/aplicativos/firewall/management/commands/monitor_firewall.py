"""
MoonShield Platform — Management Command / monitor_firewall
===========================================================

Monitor de saúde do Firewall local.

Responsabilidades:
- consultar periodicamente o MoonShield-Agent via Unix Socket;
- consolidar o estado real do nftables/Firewall;
- registrar mudanças relevantes de status;
- permitir execução contínua ou única;
- NÃO aplicar regras;
- NÃO executar nft;
- NÃO usar HTTP/Sensor/token.

Uso:

    python gerenciar.py monitor_firewall

    python gerenciar.py monitor_firewall --interval 10

    python gerenciar.py monitor_firewall --once

    python gerenciar.py monitor_firewall --verbose-status

Arquitetura:

    management command
        ↓
    firewall_status.py
        ↓
    agent_client.py
        ↓
    /run/moonshield/agent.sock
        ↓
    MoonShield-Agent
"""

from __future__ import annotations

import json
import logging
import signal
import time
from typing import Any

from django.core.management.base import BaseCommand

from firewall.services.firewall_status import (
    obter_estado_firewall,
)


logger = logging.getLogger(__name__)


VERSAO_MONITOR = "1.0"

INTERVALO_PADRAO = 15
INTERVALO_MIN = 2
INTERVALO_MAX = 3600


class Command(BaseCommand):
    help = (
        "Monitora continuamente o estado local do MoonShield Firewall "
        "via MoonShield-Agent."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--interval",
            type=int,
            default=INTERVALO_PADRAO,
            help=(
                f"Intervalo entre verificações em segundos "
                f"(padrão: {INTERVALO_PADRAO})."
            ),
        )

        parser.add_argument(
            "--once",
            action="store_true",
            help="Executa uma única verificação e encerra.",
        )

        parser.add_argument(
            "--verbose-status",
            action="store_true",
            help="Exibe o JSON consolidado completo a cada verificação.",
        )

        parser.add_argument(
            "--quiet",
            action="store_true",
            help=(
                "Não imprime verificações sem mudança; "
                "continua registrando mudanças e erros."
            ),
        )

    def handle(self, *args, **options):
        intervalo = _normalizar_intervalo(
            options.get("interval")
        )

        once = bool(
            options.get("once")
        )

        verbose_status = bool(
            options.get("verbose_status")
        )

        quiet = bool(
            options.get("quiet")
        )

        parar = _FlagParada()
        _registrar_sinais(
            parar
        )

        self.stdout.write(
            self.style.SUCCESS(
                "MoonShield Firewall Monitor "
                f"v{VERSAO_MONITOR} iniciado"
            )
        )

        self.stdout.write(
            f"Intervalo: {intervalo}s | "
            f"Modo: {'uma verificação' if once else 'contínuo'}"
        )

        ultimo_resumo: tuple[Any, ...] | None = None
        verificacoes = 0
        mudancas = 0
        erros = 0

        try:
            while not parar.ativo:
                inicio = time.monotonic()
                verificacoes += 1

                try:
                    estado = obter_estado_firewall(
                        incluir_detalhes=verbose_status
                    )

                    resumo = _assinatura_estado(
                        estado
                    )

                    mudou = (
                        ultimo_resumo is None
                        or resumo != ultimo_resumo
                    )

                    if mudou:
                        mudancas += 1
                        _registrar_mudanca(
                            self,
                            estado,
                            anterior=ultimo_resumo,
                        )

                    elif not quiet:
                        _imprimir_resumo(
                            self,
                            estado,
                            prefixo="OK",
                        )

                    if verbose_status:
                        self.stdout.write(
                            json.dumps(
                                estado,
                                ensure_ascii=False,
                                indent=2,
                                default=str,
                            )
                        )

                    ultimo_resumo = resumo

                except KeyboardInterrupt:
                    parar.ativo = True
                    break

                except Exception as exc:
                    erros += 1

                    logger.exception(
                        "Erro inesperado no monitor do Firewall"
                    )

                    self.stderr.write(
                        self.style.ERROR(
                            f"[ERRO] {type(exc).__name__}: {exc}"
                        )
                    )

                if once:
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
                    "MoonShield Firewall Monitor encerrado"
                )
            )

            self.stdout.write(
                f"Verificações: {verificacoes} | "
                f"Mudanças: {mudancas} | "
                f"Erros: {erros}"
            )


# =============================================================================
# STATUS
# =============================================================================

def _assinatura_estado(
    estado: dict[str, Any],
) -> tuple[Any, ...]:
    erro = estado.get(
        "erro"
    )

    if isinstance(
        erro,
        dict,
    ):
        erro_codigo = erro.get(
            "codigo"
        )
    else:
        erro_codigo = None

    return (
        bool(
            estado.get(
                "agent_disponivel"
            )
        ),
        bool(
            estado.get(
                "nftables_instalado"
            )
        ),
        bool(
            estado.get(
                "instalado"
            )
        ),
        bool(
            estado.get(
                "configurado"
            )
        ),
        bool(
            estado.get(
                "tabela_instalada"
            )
        ),
        bool(
            estado.get(
                "chains_ok"
            )
        ),
        bool(
            estado.get(
                "operacional"
            )
        ),
        str(
            estado.get(
                "status"
            )
            or ""
        ),
        str(
            estado.get(
                "interface_wan"
            )
            or ""
        ),
        str(
            estado.get(
                "interface_lan"
            )
            or ""
        ),
        str(
            estado.get(
                "interface_mgmt"
            )
            or ""
        ),
        erro_codigo,
    )


def _registrar_mudanca(
    command: Command,
    estado: dict[str, Any],
    *,
    anterior: tuple[Any, ...] | None,
) -> None:
    status = str(
        estado.get(
            "status"
        )
        or "desconhecido"
    )

    label = str(
        estado.get(
            "status_label"
        )
        or status
    )

    operacional = bool(
        estado.get(
            "operacional"
        )
    )

    if operacional:
        linha = command.style.SUCCESS(
            f"[MUDANÇA] Firewall: {label}"
        )
    elif estado.get(
        "agent_disponivel"
    ):
        linha = command.style.WARNING(
            f"[MUDANÇA] Firewall: {label}"
        )
    else:
        linha = command.style.ERROR(
            f"[MUDANÇA] Firewall: {label}"
        )

    command.stdout.write(
        linha
    )

    _imprimir_resumo(
        command,
        estado,
        prefixo="STATUS",
    )

    logger.info(
        "Firewall status mudou | anterior=%s | atual=%s",
        anterior,
        _assinatura_estado(
            estado
        ),
    )


def _imprimir_resumo(
    command: Command,
    estado: dict[str, Any],
    *,
    prefixo: str,
) -> None:
    agent = (
        "ON"
        if estado.get(
            "agent_disponivel"
        )
        else "OFF"
    )

    nft = (
        "ON"
        if estado.get(
            "nftables_instalado"
        )
        else "OFF"
    )

    tabela = (
        "ON"
        if estado.get(
            "tabela_instalada"
        )
        else "OFF"
    )

    chains = (
        "OK"
        if estado.get(
            "chains_ok"
        )
        else "ERRO"
    )

    wan = (
        estado.get(
            "interface_wan"
        )
        or "—"
    )

    lan = (
        estado.get(
            "interface_lan"
        )
        or "—"
    )

    mgmt = (
        estado.get(
            "interface_mgmt"
        )
        or "—"
    )

    command.stdout.write(
        f"[{prefixo}] "
        f"Agent={agent} | "
        f"nft={nft} | "
        f"Tabela={tabela} | "
        f"Chains={chains} | "
        f"WAN={wan} | "
        f"LAN={lan} | "
        f"MGMT={mgmt}"
    )

    erro = estado.get(
        "erro"
    )

    if isinstance(
        erro,
        dict,
    ) and erro.get(
        "mensagem"
    ):
        command.stderr.write(
            command.style.ERROR(
                f"  Erro: {erro['mensagem']}"
            )
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
                0.5,
                max(
                    0.0,
                    restante,
                ),
            )
        )


def _normalizar_intervalo(
    valor: Any,
) -> int:
    try:
        valor = int(
            valor
        )
    except (
        TypeError,
        ValueError,
    ):
        valor = INTERVALO_PADRAO

    return max(
        INTERVALO_MIN,
        min(
            INTERVALO_MAX,
            valor,
        ),
    )