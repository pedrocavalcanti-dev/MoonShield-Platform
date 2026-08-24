#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""

import os
import shutil
import subprocess
import sys
from pathlib import Path


def _eh_runserver() -> bool:
    return len(sys.argv) >= 2 and sys.argv[1] == "runserver"


def _processo_pai_runserver() -> bool:
    """
    O autoreload do Django cria um processo filho com RUN_MAIN=true.

    Os bootstraps de infraestrutura rodam apenas no processo pai para
    evitar duas tentativas simultâneas de systemctl/socket/apt.
    """
    if not _eh_runserver():
        return False

    return os.environ.get("RUN_MAIN") != "true"


def _executar_comando_sistema(
    comando: list[str],
    timeout: int = 300,
) -> subprocess.CompletedProcess:
    """
    Executa comandos locais de infraestrutura sem shell=True.

    stdout/stderr são capturados para evitar poluição excessiva do terminal.
    """
    return subprocess.run(
        comando,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _servico_ativo(nome: str) -> bool:
    """Retorna True quando um serviço systemd está ativo."""
    if shutil.which("systemctl") is None:
        return False

    resultado = _executar_comando_sistema(
        ["systemctl", "is-active", "--quiet", nome],
        timeout=20,
    )

    return resultado.returncode == 0


def _bootstrap_networkmanager() -> None:
    """
    Garante a dependência básica de rede usada pelo MoonShield.

    Responsabilidades:
    - atua somente em Linux;
    - detecta se nmcli/NetworkManager já estão disponíveis;
    - instala `network-manager` automaticamente via apt-get quando ausente;
    - habilita e inicia o serviço NetworkManager;
    - é idempotente;
    - NÃO altera /etc/network/interfaces;
    - NÃO altera IPs;
    - NÃO altera rotas;
    - NÃO assume interfaces automaticamente;
    - NÃO impede o Django de subir em caso de falha.
    """
    if os.name != "posix":
        print(
            "[MoonShield] NetworkManager: bootstrap ignorado "
            "(sistema não Linux)."
        )
        return

    print(
        "[MoonShield] Verificando NetworkManager..."
    )

    nmcli = shutil.which("nmcli")

    if nmcli is None:
        print(
            "[MoonShield] NetworkManager não encontrado. "
            "Preparando instalação automática..."
        )

        if hasattr(os, "geteuid") and os.geteuid() != 0:
            print(
                "[MoonShield] ATENÇÃO: NetworkManager não está instalado "
                "e o processo não possui privilégios root."
            )
            print(
                "[MoonShield] Execute uma vez como root ou instale "
                "manualmente: apt-get install -y network-manager"
            )
            return

        apt_get = shutil.which("apt-get")

        if apt_get is None:
            print(
                "[MoonShield] ATENÇÃO: apt-get não encontrado. "
                "Não foi possível instalar o NetworkManager automaticamente."
            )
            return

        print(
            "[MoonShield] Atualizando índice de pacotes..."
        )

        resultado_update = _executar_comando_sistema(
            [apt_get, "update"],
            timeout=600,
        )

        if resultado_update.returncode != 0:
            erro = (
                resultado_update.stderr.strip()
                or resultado_update.stdout.strip()
                or "erro não informado"
            )

            print(
                "[MoonShield] ATENÇÃO: apt-get update falhou: "
                f"{erro}"
            )
            return

        print(
            "[MoonShield] Instalando NetworkManager..."
        )

        resultado_install = _executar_comando_sistema(
            [
                apt_get,
                "install",
                "-y",
                "network-manager",
            ],
            timeout=900,
        )

        if resultado_install.returncode != 0:
            erro = (
                resultado_install.stderr.strip()
                or resultado_install.stdout.strip()
                or "erro não informado"
            )

            print(
                "[MoonShield] ATENÇÃO: instalação do NetworkManager "
                f"falhou: {erro}"
            )
            return

        nmcli = shutil.which("nmcli")

        if nmcli is None:
            print(
                "[MoonShield] ATENÇÃO: pacote network-manager foi "
                "instalado, mas nmcli ainda não foi localizado."
            )
            return

        print(
            "[MoonShield] NetworkManager instalado com sucesso."
        )

    if shutil.which("systemctl") is None:
        print(
            "[MoonShield] ATENÇÃO: systemctl não encontrado. "
            "NetworkManager instalado, mas o serviço não pôde ser validado."
        )
        return

    if not _servico_ativo("NetworkManager"):
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            print(
                "[MoonShield] ATENÇÃO: NetworkManager está instalado, "
                "mas não está ativo e o processo não possui root."
            )
            return

        print(
            "[MoonShield] Habilitando NetworkManager..."
        )

        resultado_servico = _executar_comando_sistema(
            [
                "systemctl",
                "enable",
                "--now",
                "NetworkManager",
            ],
            timeout=60,
        )

        if resultado_servico.returncode != 0:
            erro = (
                resultado_servico.stderr.strip()
                or resultado_servico.stdout.strip()
                or "erro não informado"
            )

            print(
                "[MoonShield] ATENÇÃO: não foi possível iniciar "
                f"o NetworkManager: {erro}"
            )
            return

    if _servico_ativo("NetworkManager"):
        print(
            "[MoonShield] NetworkManager pronto: instalado, "
            "habilitado e ativo."
        )
    else:
        print(
            "[MoonShield] ATENÇÃO: NetworkManager foi encontrado, "
            "mas o serviço não está ativo."
        )


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
      1. NetworkManager;
      2. infraestrutura do Agent;
      3. worker do Suricata.

    Nenhum deles pode impedir o servidor Django de iniciar.
    """
    _bootstrap_networkmanager()
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