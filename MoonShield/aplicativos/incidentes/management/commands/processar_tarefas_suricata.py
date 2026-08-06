"""
Worker automático das tarefas do Suricata.

Uso contínuo:
    python gerenciar.py processar_tarefas_suricata

Executar apenas uma tarefa e encerrar:
    python gerenciar.py processar_tarefas_suricata --once
"""

from __future__ import annotations

import fcntl
import logging
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import IO, Optional

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import close_old_connections
from django.utils import timezone

from incidentes.models import StatusTarefaSuricata, TarefaSuricata


logger = logging.getLogger(__name__)

STATUS_FINAIS = {
    StatusTarefaSuricata.SUCESSO,
    StatusTarefaSuricata.ERRO,
    StatusTarefaSuricata.CANCELADO,
    StatusTarefaSuricata.IGNORADO,
}


class Command(BaseCommand):
    help = (
        "Processa automaticamente as tarefas pendentes do Suricata. "
        "Projetado para execução contínua como serviço systemd."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--once",
            action="store_true",
            help="Processa no máximo uma tarefa e encerra.",
        )
        parser.add_argument(
            "--intervalo",
            type=float,
            default=2.0,
            help="Intervalo, em segundos, entre consultas ao banco. Padrão: 2.",
        )
        parser.add_argument(
            "--timeout",
            type=int,
            default=3600,
            help="Tempo máximo, em segundos, para cada tarefa. Padrão: 3600.",
        )
        parser.add_argument(
            "--lock-file",
            default="/run/moonshield-suricata-worker.lock",
            help=(
                "Arquivo de bloqueio que impede dois workers simultâneos. "
                "Padrão: /run/moonshield-suricata-worker.lock"
            ),
        )
        parser.add_argument(
            "--tarefa-id",
            default="",
            help="Processa somente a tarefa informada, desde que esteja pendente.",
        )

    def handle(self, *args, **options):
        self._encerrar = False

        once = bool(options["once"])
        intervalo = max(float(options["intervalo"]), 0.5)
        timeout = max(int(options["timeout"]), 60)
        lock_file = str(options["lock_file"]).strip()
        tarefa_id = str(options["tarefa_id"]).strip()

        self._validar_ambiente()
        self._registrar_sinais()

        with self._adquirir_lock(lock_file):
            self.stdout.write(
                self.style.SUCCESS(
                    "[MoonShield] Worker automático do Suricata iniciado."
                )
            )

            while not self._encerrar:
                close_old_connections()

                tarefa = self._buscar_tarefa_pendente(tarefa_id=tarefa_id)

                if tarefa is None:
                    if once or tarefa_id:
                        self.stdout.write(
                            "[MoonShield] Nenhuma tarefa pendente encontrada."
                        )
                        return

                    self._aguardar(intervalo)
                    continue

                self._processar_tarefa(tarefa=tarefa, timeout=timeout)

                if once or tarefa_id:
                    return

            self.stdout.write(
                self.style.WARNING(
                    "[MoonShield] Worker encerrado por solicitação do sistema."
                )
            )

    def _validar_ambiente(self) -> None:
        if os.name != "posix":
            raise CommandError(
                "O worker automático do Suricata exige um sistema Linux/Unix."
            )

        if hasattr(os, "geteuid") and os.geteuid() != 0:
            raise CommandError(
                "O worker precisa ser executado como root para instalar pacotes, "
                "alterar o Suricata e controlar serviços systemd."
            )

        gerenciar = self._caminho_gerenciar()
        if not gerenciar.exists():
            raise CommandError(
                f"Arquivo gerenciar.py não encontrado em: {gerenciar}"
            )

    def _registrar_sinais(self) -> None:
        def solicitar_encerramento(signum, _frame):
            logger.info(
                "Sinal %s recebido; o worker encerrará após a operação atual.",
                signum,
            )
            self._encerrar = True

        signal.signal(signal.SIGTERM, solicitar_encerramento)
        signal.signal(signal.SIGINT, solicitar_encerramento)

    def _adquirir_lock(self, caminho: str):
        class LockContext:
            def __init__(self, path: str):
                self.path = Path(path)
                self.handle: Optional[IO[str]] = None

            def __enter__(self):
                try:
                    self.path.parent.mkdir(parents=True, exist_ok=True)
                    self.handle = self.path.open("a+", encoding="utf-8")
                    fcntl.flock(
                        self.handle.fileno(),
                        fcntl.LOCK_EX | fcntl.LOCK_NB,
                    )
                    self.handle.seek(0)
                    self.handle.truncate()
                    self.handle.write(str(os.getpid()))
                    self.handle.flush()
                    return self
                except BlockingIOError as exc:
                    raise CommandError(
                        "Já existe outro worker do Suricata em execução."
                    ) from exc
                except OSError as exc:
                    raise CommandError(
                        f"Não foi possível criar o lock {self.path}: {exc}"
                    ) from exc

            def __exit__(self, exc_type, exc, tb):
                if self.handle is not None:
                    try:
                        fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
                    finally:
                        self.handle.close()

                try:
                    self.path.unlink(missing_ok=True)
                except OSError:
                    logger.warning(
                        "Não foi possível remover o arquivo de lock %s.",
                        self.path,
                    )

        return LockContext(caminho)

    def _buscar_tarefa_pendente(
        self,
        tarefa_id: str = "",
    ) -> Optional[TarefaSuricata]:
        queryset = TarefaSuricata.objects.filter(
            status=StatusTarefaSuricata.PENDENTE
        )

        if tarefa_id:
            queryset = queryset.filter(pk=tarefa_id)

        return queryset.order_by("criado_em", "pk").first()

    def _processar_tarefa(
        self,
        tarefa: TarefaSuricata,
        timeout: int,
    ) -> None:
        tarefa_id = str(tarefa.pk)
        tipo = str(tarefa.tipo)

        self.stdout.write(
            self.style.NOTICE(
                f"[MoonShield] Processando tarefa {tarefa_id} ({tipo})."
            )
        )

        comando = [
            sys.executable,
            str(self._caminho_gerenciar()),
            "executar_tarefa_suricata",
            tipo,
            "--tarefa-id",
            tarefa_id,
            "--formato",
            "json",
            "--nao-confirmar",
        ]

        logger.info(
            "Iniciando tarefa Suricata %s do tipo %s.",
            tarefa_id,
            tipo,
        )

        try:
            resultado = subprocess.run(
                comando,
                cwd=str(settings.BASE_DIR),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=self._ambiente_subprocesso(),
            )
        except subprocess.TimeoutExpired as exc:
            mensagem = (
                f"A tarefa excedeu o tempo máximo de {timeout} segundos."
            )
            self._marcar_erro_se_necessario(tarefa_id, mensagem)
            raise CommandError(mensagem) from exc
        except OSError as exc:
            mensagem = f"Falha ao iniciar o executor da tarefa: {exc}"
            self._marcar_erro_se_necessario(tarefa_id, mensagem)
            raise CommandError(mensagem) from exc

        stdout = (resultado.stdout or "").strip()
        stderr = (resultado.stderr or "").strip()

        if stdout:
            self.stdout.write(stdout)

        if stderr:
            self.stderr.write(stderr)

        close_old_connections()
        tarefa_atual = TarefaSuricata.objects.get(pk=tarefa_id)

        if resultado.returncode != 0:
            mensagem = (
                stderr
                or stdout
                or f"Executor terminou com código {resultado.returncode}."
            )
            self._marcar_erro_se_necessario(tarefa_id, mensagem)
            raise CommandError(
                f"Tarefa {tarefa_id} falhou com código "
                f"{resultado.returncode}."
            )

        if tarefa_atual.status not in STATUS_FINAIS:
            mensagem = (
                "O executor terminou sem finalizar o estado da tarefa. "
                f"Estado encontrado: {tarefa_atual.status}."
            )
            self._marcar_erro_se_necessario(tarefa_id, mensagem)
            raise CommandError(mensagem)

        if tarefa_atual.status == StatusTarefaSuricata.SUCESSO:
            self.stdout.write(
                self.style.SUCCESS(
                    f"[MoonShield] Tarefa {tarefa_id} concluída com sucesso."
                )
            )
            return

        self.stdout.write(
            self.style.WARNING(
                f"[MoonShield] Tarefa {tarefa_id} finalizada com status "
                f"{tarefa_atual.status}."
            )
        )

    def _marcar_erro_se_necessario(
        self,
        tarefa_id: str,
        mensagem: str,
    ) -> None:
        close_old_connections()

        tarefa = TarefaSuricata.objects.filter(pk=tarefa_id).first()
        if tarefa is None or tarefa.status in STATUS_FINAIS:
            return

        mensagem_limpa = str(mensagem).strip()
        if len(mensagem_limpa) > 8000:
            mensagem_limpa = mensagem_limpa[-8000:]

        campos = {
            "status": StatusTarefaSuricata.ERRO,
            "finalizado_em": timezone.now(),
        }

        nomes_campos = {
            campo.name
            for campo in TarefaSuricata._meta.get_fields()
            if getattr(campo, "concrete", False)
        }

        if "erro" in nomes_campos:
            campos["erro"] = mensagem_limpa

        if "mensagem" in nomes_campos:
            campos["mensagem"] = (
                "O worker automático detectou uma falha na execução."
            )

        TarefaSuricata.objects.filter(pk=tarefa_id).update(**campos)

    def _caminho_gerenciar(self) -> Path:
        return Path(settings.BASE_DIR) / "gerenciar.py"

    def _ambiente_subprocesso(self) -> dict[str, str]:
        ambiente = os.environ.copy()
        ambiente["PYTHONUNBUFFERED"] = "1"
        return ambiente

    def _aguardar(self, segundos: float) -> None:
        limite = time.monotonic() + segundos

        while not self._encerrar and time.monotonic() < limite:
            time.sleep(min(0.25, max(limite - time.monotonic(), 0)))