#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""

import os
import sys
from pathlib import Path


def _deve_bootstrap_worker() -> bool:
    """Executa o bootstrap uma única vez no processo pai do runserver."""
    if len(sys.argv) < 2 or sys.argv[1] != "runserver":
        return False

    # O autoreload do Django cria um processo filho com RUN_MAIN=true.
    # Fazemos o bootstrap somente no processo pai.
    return os.environ.get("RUN_MAIN") != "true"


def _bootstrap_worker_suricata() -> None:
    """
    Cria, habilita e inicia automaticamente o worker de tarefas Suricata.

    Uma falha aqui é exibida no terminal, mas não impede o Django de subir.
    """
    try:
        import django

        django.setup()

        from incidentes.services.suricata.servicos import (
            garantir_worker_tarefas,
        )

        base_dir = Path(__file__).resolve().parent
        python_executavel = Path(sys.executable).resolve()
        gerenciar_path = Path(__file__).resolve()

        print(
            "[MoonShield] Verificando worker automático do Suricata..."
        )

        resultado = garantir_worker_tarefas(
            base_dir=base_dir,
            python_executavel=python_executavel,
            gerenciar_path=gerenciar_path,
        )

        if resultado.get("sucesso"):
            pid = resultado.get("pid")

            sufixo_pid = f" PID={pid}" if pid else ""

            print(
                "[MoonShield] Worker Suricata pronto: "
                "instalado, habilitado e ativo."
                + sufixo_pid
            )
            return

        if resultado.get("ignorado"):
            print(
                "[MoonShield] Bootstrap do worker ignorado: "
                f"{resultado.get('motivo', 'motivo não informado')}"
            )
            return

        print(
            "[MoonShield] ATENÇÃO: não foi possível preparar "
            "o worker Suricata: "
            f"{resultado.get('erro', 'erro não informado')}"
        )

    except Exception as exc:
        print(
            "[MoonShield] ATENÇÃO: falha inesperada "
            f"no bootstrap do worker: {exc}"
        )


def main() -> None:
    """Run administrative tasks."""
    os.environ.setdefault(
        "DJANGO_SETTINGS_MODULE",
        "config.settings",
    )

    try:
        from django.core.management import (
            execute_from_command_line,
        )
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc

    if _deve_bootstrap_worker():
        _bootstrap_worker_suricata()

    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()