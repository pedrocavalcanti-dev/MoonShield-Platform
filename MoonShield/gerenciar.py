#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""

import os
import sys
from pathlib import Path


def _eh_runserver() -> bool:
    return (
        len(sys.argv) >= 2
        and sys.argv[1] == "runserver"
    )


def _processo_pai_runserver() -> bool:
    """
    O autoreload do Django cria um processo filho com RUN_MAIN=true.

    Os bootstraps de infraestrutura rodam apenas no processo pai para
    evitar duas tentativas simultâneas de systemctl/socket.
    """
    if not _eh_runserver():
        return False

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
        python_executavel = Path(sys.executable)
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

            sufixo_pid = (
                f" PID={pid}"
                if pid
                else ""
            )

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


def _bootstrap_moonshield_agent() -> None:
    """
    Garante automaticamente a infraestrutura mínima do MoonShield-Agent.

    Importante:
    - só atua em Linux;
    - requer root para criar grupo/service/diretórios;
    - é idempotente;
    - NÃO instala o Firewall;
    - NÃO cria regras nftables;
    - NÃO impede o Django de subir caso falhe.

    O instalador web do Firewall continua sendo responsável por nftables,
    topologia, tabela/chains e regras.
    """
    try:
        from django.core.management import call_command

        print(
            "[MoonShield] Verificando MoonShield-Agent local..."
        )

        call_command(
            "instalar_moonshield",
            automatico=True,
            verbosity=0,
        )

        print(
            "[MoonShield] Bootstrap do MoonShield-Agent finalizado."
        )

    except Exception as exc:
        print(
            "[MoonShield] ATENÇÃO: falha no bootstrap "
            f"do MoonShield-Agent: {exc}"
        )


def _bootstrap_runserver() -> None:
    """
    Bootstraps seguros executados uma única vez antes do runserver.

    A ordem é intencional:
      1. infraestrutura do Agent;
      2. worker do Suricata.

    Nenhum deles pode impedir o servidor Django de iniciar.
    """
    _bootstrap_moonshield_agent()
    _bootstrap_worker_suricata()


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

    if _processo_pai_runserver():
        try:
            import django

            django.setup()

            _bootstrap_runserver()

        except Exception as exc:
            # Última barreira de proteção:
            # infraestrutura nunca deve impedir o runserver de subir.
            print(
                "[MoonShield] ATENÇÃO: bootstrap inicial "
                f"não concluído: {exc}"
            )

    execute_from_command_line(
        sys.argv
    )


if __name__ == "__main__":
    main()