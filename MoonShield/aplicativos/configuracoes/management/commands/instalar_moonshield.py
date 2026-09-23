from __future__ import annotations

import grp
import json
import os
import platform
import pwd
import shutil
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    """
    Prepara a infraestrutura mínima do MoonShield-Agent no Linux.

    Este comando NÃO instala o Firewall/nftables.
    Ele apenas garante o que precisa existir para o instalador web funcionar:

      - grupo moonshield;
      - diretórios de runtime/dados/logs/configuração;
      - serviço systemd moonshield-agent.service;
      - serviço habilitado/iniciado;
      - /run/moonshield/agent.sock disponível;
      - teste simples de conexão no Unix Socket.

    É idempotente:
      - pode ser executado várias vezes;
      - não recria grupo se já existe;
      - não reinicia o Agent se o service já está ativo e correto;
      - não falha o Django quando usado em modo automático.
    """

    help = "Instala/repara a infraestrutura mínima do MoonShield-Agent."

    SERVICE_NAME = "moonshield-agent.service"
    SERVICE_PATH = Path("/etc/systemd/system/moonshield-agent.service")

    WORKER_SERVICE_NAME = "moonshield-suricata-worker.service"
    WORKER_SERVICE_PATH = Path("/etc/systemd/system/moonshield-suricata-worker.service")

    MONITOR_SERVICE_NAME = "moonshield-suricata-monitor.service"
    MONITOR_SERVICE_PATH = Path("/etc/systemd/system/moonshield-suricata-monitor.service")

    SOCKET_DIR = Path("/run/moonshield")
    SOCKET_PATH = SOCKET_DIR / "agent.sock"

    ETC_DIR = Path("/etc/moonshield")
    DATA_DIR = Path("/var/lib/moonshield")
    LOG_DIR = Path("/var/log/moonshield")

    GROUP_NAME = "moonshield"

    def add_arguments(self, parser):
        parser.add_argument(
            "--automatico",
            action="store_true",
            help=(
                "Modo silencioso/seguro para bootstrap durante o runserver. "
                "Erros são reportados, mas não levantados."
            ),
        )

        parser.add_argument(
            "--forcar-service",
            action="store_true",
            help="Regrava o arquivo systemd mesmo se o conteúdo atual estiver correto.",
        )

    def handle(self, *args, **options):
        automatico = bool(options.get("automatico"))
        forcar_service = bool(options.get("forcar_service"))

        try:
            resultado = self._executar(
                automatico=automatico,
                forcar_service=forcar_service,
            )
        except Exception as exc:
            if automatico:
                self._warn(
                    f"Bootstrap do MoonShield-Agent não concluído: {exc}"
                )
                return

            raise

        if not automatico:
            self.stdout.write("")
            if resultado.get("ok"):
                self.stdout.write(
                    self.style.SUCCESS(
                        "[MoonShield] MoonShield-Agent pronto."
                    )
                )
            else:
                self.stdout.write(
                    self.style.WARNING(
                        "[MoonShield] Bootstrap concluído com atenção."
                    )
                )

    # ------------------------------------------------------------------
    # Fluxo principal
    # ------------------------------------------------------------------

    def _executar(
        self,
        *,
        automatico: bool,
        forcar_service: bool,
    ) -> dict:
        if os.name != "posix" or platform.system().lower() != "linux":
            self._info(
                "MoonShield-Agent local ignorado: disponível somente no Linux.",
                automatico,
            )
            return {
                "ok": True,
                "ignorado": True,
                "motivo": "host_nao_linux",
            }

        if os.geteuid() != 0:
            self._warn(
                "Bootstrap do MoonShield-Agent ignorado: "
                "o processo não está executando como root."
            )
            return {
                "ok": False,
                "ignorado": True,
                "motivo": "sem_root",
            }

        paths = self._resolver_paths()

        self._info("Verificando infraestrutura do MoonShield-Agent...", automatico)

        self._garantir_grupo()
        self._garantir_diretorios()

        # A appliance precisa provisionar o monitor tanto no bootstrap
        # automático quanto na execução explícita do instalador.
        monitor_content = self._preparar_monitor(paths)
        monitor_changed = self._garantir_monitor_service(
            monitor_content, forcar=forcar_service,
        )

        service_changed = self._garantir_service(
            paths=paths,
            forcar=forcar_service,
        )

        worker_changed = self._garantir_worker_service(
            paths=paths,
            forcar=forcar_service,
        )

        self._systemctl(["daemon-reload"], obrigatorio=True)

        if service_changed:
            self._info(
                "Arquivo moonshield-agent.service atualizado.",
                automatico,
            )

        if worker_changed:
            self._info(
                "Arquivo moonshield-suricata-worker.service atualizado.",
                automatico,
            )

        self._systemctl(
            ["enable", self.SERVICE_NAME],
            obrigatorio=True,
        )

        self._systemctl(
            ["enable", self.WORKER_SERVICE_NAME],
            obrigatorio=True,
        )

        ativo_antes = self._service_is_active()

        if not ativo_antes:
            self._info(
                "Iniciando MoonShield-Agent...",
                automatico,
            )
            self._systemctl(
                ["start", self.SERVICE_NAME],
                obrigatorio=True,
            )
        elif service_changed:
            self._info(
                "Reiniciando MoonShield-Agent após atualização do service...",
                automatico,
            )
            self._systemctl(
                ["restart", self.SERVICE_NAME],
                obrigatorio=True,
            )
        else:
            self._ok(
                "MoonShield-Agent já estava ativo.",
                automatico,
            )

        self._systemctl(["start", self.WORKER_SERVICE_NAME], obrigatorio=False)
        if worker_changed:
            self._systemctl(["restart", self.WORKER_SERVICE_NAME], obrigatorio=False)

        self._ativar_monitor(alterado=monitor_changed)

        adguard = self._provisionar_adguard(automatico=automatico)

        socket_ok = self._aguardar_socket(timeout=6.0)

        if not socket_ok:
            logs = self._journal_tail()
            detalhe = (
                "\nÚltimas linhas do service:\n"
                + logs
                if logs
                else ""
            )

            raise RuntimeError(
                f"{self.SOCKET_PATH} não foi criado pelo Agent."
                + detalhe
            )

        erro_socket = self._validar_permissoes_socket()

        if erro_socket:
            raise RuntimeError(erro_socket)

        if not self._teste_socket():
            raise RuntimeError(
                "Unix Socket foi criado, mas não respondeu ao system.ping."
            )

        self._ok(
            f"IPC disponível em {self.SOCKET_PATH}",
            automatico,
        )

        self._validar_pos_instalacao(paths)

        return {
            "ok": True,
            "service": self.SERVICE_NAME,
            "socket": str(self.SOCKET_PATH),
            "agent_dir": str(paths["agent_dir"]),
            "python": str(paths["python"]),
            "adguard": adguard,
        }

    # ------------------------------------------------------------------
    # Descoberta de caminhos
    # ------------------------------------------------------------------

    def _resolver_paths(self) -> dict:
        """
        Resolve tudo a partir deste arquivo/repositório.

        Estrutura esperada:

          MoonShield-Platform/
          ├── .venv/
          ├── MoonShield/
          │   └── gerenciar.py
          └── MoonShield-Agent/
              └── firewall/ipc/servidor.py
        """

        gerenciar = self._resolver_gerenciar()
        django_dir = gerenciar.parent
        repo_root = django_dir.parent
        agent_dir = repo_root / "MoonShield-Agent"

        servidor = agent_dir / "firewall" / "ipc" / "servidor.py"

        if not servidor.exists():
            raise RuntimeError(
                "Servidor IPC não encontrado em "
                f"{servidor}"
            )

        python_atual = Path(sys.executable)

        # Usa exatamente o executável que iniciou o Django.
        # Não usar .resolve(): o Python do venv pode ser symlink para /usr/bin/python3.
        python_exec = python_atual

        if not python_exec.exists():
            raise RuntimeError(
                f"Python atual não encontrado: {python_exec}"
            )

        return {
            "repo_root": repo_root,
            "django_dir": django_dir,
            "gerenciar": gerenciar,
            "agent_dir": agent_dir,
            "servidor": servidor,
            "python": python_exec,
        }

    def _resolver_gerenciar(self) -> Path:
        """
        Tenta obter gerenciar.py pelo cwd e depois pela estrutura do app.
        """

        cwd_candidate = Path.cwd() / "gerenciar.py"
        if cwd_candidate.exists():
            return cwd_candidate.resolve()

        # .../MoonShield/aplicativos/configuracoes/management/commands/
        # -> sobe até MoonShield/
        here = Path(__file__).resolve()

        for parent in here.parents:
            candidate = parent / "gerenciar.py"
            if candidate.exists():
                return candidate.resolve()

        raise RuntimeError(
            "Não foi possível localizar gerenciar.py."
        )

    # ------------------------------------------------------------------
    # Grupo / diretórios
    # ------------------------------------------------------------------

    def _garantir_grupo(self) -> None:
        try:
            grp.getgrnam(self.GROUP_NAME)
            return
        except KeyError:
            pass

        proc = subprocess.run(
            [
                "groupadd",
                "--system",
                self.GROUP_NAME,
            ],
            capture_output=True,
            text=True,
        )

        if proc.returncode != 0:
            # Corrida entre dois bootstraps: se agora existe, está ok.
            try:
                grp.getgrnam(self.GROUP_NAME)
                return
            except KeyError:
                raise RuntimeError(
                    "Não foi possível criar o grupo moonshield: "
                    + (proc.stderr.strip() or proc.stdout.strip())
                )

    def _garantir_diretorios(self) -> None:
        gid = grp.getgrnam(self.GROUP_NAME).gr_gid

        specs = (
            (self.ETC_DIR, 0o750),
            (self.DATA_DIR, 0o750),
            (self.LOG_DIR, 0o750),
            (self.SOCKET_DIR, 0o750),
        )

        for path, mode in specs:
            path.mkdir(
                parents=True,
                exist_ok=True,
            )

            os.chown(
                path,
                0,
                gid,
            )

            os.chmod(
                path,
                mode,
            )

    # ------------------------------------------------------------------
    # systemd
    # ------------------------------------------------------------------

    def _service_content(self, paths: dict) -> str:
        python_exec = paths["python"]
        agent_dir = paths["agent_dir"]

        return f"""[Unit]
Description=MoonShield Agent IPC
After=network.target nftables.service
Wants=network.target

[Service]
Type=simple
User=root
Group={self.GROUP_NAME}

WorkingDirectory={agent_dir}
Environment=PYTHONUNBUFFERED=1

ExecStart={python_exec} -m firewall.ipc.servidor

Restart=on-failure
RestartSec=2
TimeoutStopSec=10
KillSignal=SIGTERM

RuntimeDirectory=moonshield
RuntimeDirectoryMode=0750

NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
"""

    def _garantir_service(
        self,
        *,
        paths: dict,
        forcar: bool,
    ) -> bool:
        desired = self._service_content(paths)

        current = ""

        if self.SERVICE_PATH.exists():
            try:
                current = self.SERVICE_PATH.read_text(
                    encoding="utf-8"
                )
            except OSError:
                current = ""

        if not forcar and current == desired:
            return False

        tmp = self.SERVICE_PATH.with_suffix(".service.tmp")

        tmp.write_text(
            desired,
            encoding="utf-8",
        )

        os.chmod(
            tmp,
            0o644,
        )

        os.replace(
            tmp,
            self.SERVICE_PATH,
        )

        return True


    def _worker_service_content(self, paths: dict) -> str:
        python_exec = paths["python"]
        agent_dir = paths["agent_dir"]
        gerenciar = agent_dir.parent / "MoonShield" / "gerenciar.py"
        work_dir = gerenciar.parent

        return f"""[Unit]
Description=MoonShield Suricata Background Worker
After=network.target moonshield-agent.service postgresql.service
Wants=network.target

[Service]
Type=simple
User={self.GROUP_NAME}
Group={self.GROUP_NAME}

WorkingDirectory={work_dir}
Environment=PYTHONUNBUFFERED=1

ExecStart={python_exec} {gerenciar} processar_tarefas_suricata --lock-file=/run/moonshield-suricata-worker/worker.lock

Restart=on-failure
RestartSec=5
TimeoutStopSec=10
KillSignal=SIGTERM

RuntimeDirectory=moonshield-suricata-worker
RuntimeDirectoryMode=0750

NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
"""

    def _garantir_worker_service(
        self,
        *,
        paths: dict,
        forcar: bool,
    ) -> bool:
        desired = self._worker_service_content(paths)
        current = ""

        if self.WORKER_SERVICE_PATH.exists():
            try:
                current = self.WORKER_SERVICE_PATH.read_text(encoding="utf-8")
            except OSError:
                pass

        if not forcar and current == desired:
            return False

        tmp = self.WORKER_SERVICE_PATH.with_suffix(".service.tmp")
        tmp.write_text(desired, encoding="utf-8")
        os.chmod(tmp, 0o644)
        os.replace(tmp, self.WORKER_SERVICE_PATH)

        return True

    def _preparar_monitor(self, paths: dict) -> str:
        """Prepara o monitor na instalação explícita e no bootstrap automático."""
        if (
            paths["django_dir"] != Path("/opt/moonshield/source/MoonShield")
            or paths["python"] != Path("/opt/moonshield/venv/bin/python")
        ):
            raise RuntimeError("O monitor requer os paths oficiais da appliance.")

        source = paths["repo_root"] / "deploy/systemd" / self.MONITOR_SERVICE_NAME
        desired = source.read_text(encoding="utf-8")
        setfacl = shutil.which("setfacl")
        if not setfacl:
            raise RuntimeError(
                "A imagem da appliance precisa incluir o pacote acl (setfacl). "
                "Nenhum pacote será baixado pelo instalador."
            )

        try:
            usuario = pwd.getpwnam(self.GROUP_NAME)
        except KeyError:
            subprocess.run(
                ["useradd", "--system", "--gid", self.GROUP_NAME,
                 "--home-dir", str(self.DATA_DIR), "--no-create-home",
                 "--shell", "/usr/sbin/nologin", self.GROUP_NAME],
                check=True, capture_output=True, text=True,
            )
            usuario = pwd.getpwnam(self.GROUP_NAME)
        gid = grp.getgrnam(self.GROUP_NAME).gr_gid
        if usuario.pw_uid == 0:
            raise RuntimeError("O usuário moonshield não pode ter UID 0.")

        # Preserva os caminhos consumidos pelo status/diagnostico existentes.
        # A ordem garante que o pai (var) pertença ao usuário correto antes do filho.
        for directory, filename in (
            (paths["django_dir"] / "var", None),
            (paths["django_dir"] / "var/cursors", "suricata_eve.cursor"),
            (paths["django_dir"] / "logs", "moonshield.log"),
        ):
            directory.mkdir(parents=True, exist_ok=True)
            os.chown(directory, usuario.pw_uid, gid)
            os.chmod(directory, 0o750)

            if filename:
                existing = directory / filename
                if existing.exists():
                    os.chown(existing, usuario.pw_uid, gid)
                    os.chmod(existing, 0o640)

        # Não cria EVE vazio nem muda o owner/group dos logs do Suricata.
        # A ACL default cobre arquivos recriados no diretório após rotação.
        eve = Path("/var/log/suricata/eve.json")
        eve.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        subprocess.run(
            [setfacl, "-m", "u:moonshield:--x,d:u:moonshield:r--", str(eve.parent)],
            check=True, capture_output=True, text=True,
        )
        if eve.exists():
            subprocess.run(
                [setfacl, "-m", "u:moonshield:r--", str(eve)],
                check=True, capture_output=True, text=True,
            )
        return desired

    def _garantir_monitor_service(self, desired: str, *, forcar: bool) -> bool:
        current = (
            self.MONITOR_SERVICE_PATH.read_text(encoding="utf-8")
            if self.MONITOR_SERVICE_PATH.exists() else ""
        )
        if not forcar and current == desired:
            return False
        tmp = self.MONITOR_SERVICE_PATH.with_suffix(".service.tmp")
        tmp.write_text(desired, encoding="utf-8")
        os.chmod(tmp, 0o644)
        os.replace(tmp, self.MONITOR_SERVICE_PATH)
        return True

    def _ativar_monitor(self, *, alterado: bool) -> None:
        self._systemctl(["enable", self.MONITOR_SERVICE_NAME], obrigatorio=True)
        ativo = self._systemctl(
            ["is-active", "--quiet", self.MONITOR_SERVICE_NAME], obrigatorio=False,
        ).returncode == 0
        if not ativo or alterado:
            acao = "restart" if ativo else "start"
            self._systemctl([acao, self.MONITOR_SERVICE_NAME], obrigatorio=True)

    def _provisionar_adguard(self, *, automatico: bool) -> dict:
        """Provisiona o engine DNS sem depender da interface HTML nativa."""
        from dns.services.adguard_bootstrap import provisionar_adguard
        from rede.services.topologia import obter_topologia

        def controlar_servico(args: list[str]) -> None:
            self._systemctl(args, obrigatorio=True)

        def servico_ativo(nome: str) -> bool:
            return self._systemctl(
                ["is-active", "--quiet", nome],
                obrigatorio=False,
            ).returncode == 0

        resultado = provisionar_adguard(
            topologia=obter_topologia(),
            controlar_servico=controlar_servico,
            servico_ativo=servico_ativo,
        )
        self._ok("AdGuard Home local provisionado.", automatico)
        return resultado

    def _systemctl(

        self,
        args: list[str],
        *,
        obrigatorio: bool,
    ) -> subprocess.CompletedProcess:
        systemctl = shutil.which("systemctl")

        if not systemctl:
            raise RuntimeError(
                "systemctl não está disponível neste host."
            )

        proc = subprocess.run(
            [systemctl, *args],
            capture_output=True,
            text=True,
        )

        if obrigatorio and proc.returncode != 0:
            raise RuntimeError(
                f"systemctl {' '.join(args)} falhou: "
                + (
                    proc.stderr.strip()
                    or proc.stdout.strip()
                    or f"exit={proc.returncode}"
                )
            )

        return proc

    def _service_is_active(self) -> bool:
        proc = self._systemctl(
            [
                "is-active",
                "--quiet",
                self.SERVICE_NAME,
            ],
            obrigatorio=False,
        )

        return proc.returncode == 0

    # ------------------------------------------------------------------
    # Socket
    # ------------------------------------------------------------------

    def _aguardar_socket(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            if self.SOCKET_PATH.exists():
                try:
                    mode = self.SOCKET_PATH.stat().st_mode
                    if stat.S_ISSOCK(mode):
                        return True
                except OSError:
                    pass

            if not self._service_is_active():
                return False

            time.sleep(0.15)

        return False

    def _validar_permissoes_socket(self) -> str | None:
        """
        Confirma que o Agent, e não o bootstrap Django, definiu o socket
        como root:moonshield 0660. O grupo permite acesso controlado ao
        Gunicorn/Django quando seu serviço recebe SupplementaryGroups=moonshield.
        """

        if not self.SOCKET_PATH.exists():
            return f"Socket do Agent não encontrado: {self.SOCKET_PATH}"

        gid = grp.getgrnam(self.GROUP_NAME).gr_gid
        stat_socket = self.SOCKET_PATH.stat()

        if not stat.S_ISSOCK(stat_socket.st_mode):
            return f"Caminho do Agent não é Unix Socket: {self.SOCKET_PATH}"

        mode = stat.S_IMODE(stat_socket.st_mode)

        if mode != 0o660:
            return (
                "Permissão insegura ou inválida no socket do Agent: "
                f"esperado 0660, encontrado {mode:04o}."
            )

        if stat_socket.st_uid != 0 or stat_socket.st_gid != gid:
            return (
                "Owner/group inválido no socket do Agent: esperado "
                f"root:{self.GROUP_NAME}."
            )

        return None

    def _teste_socket(self) -> bool:
        """
        Confirma a prontidão do Agent com uma requisição IPC válida.

        Uma conexão AF_UNIX aberta e fechada sem mensagem é inválida no
        protocolo e gera ruído no journal do Agent. O bootstrap usa o ping
        permitido pelo contrato para validar socket e dispatcher juntos.
        """

        request_id = "bootstrap-readiness"
        requisicao = {
            "versao": 1,
            "id": request_id,
            "acao": "system.ping",
            "dados": {},
        }

        mensagem = (
            json.dumps(
                requisicao,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")

        client = socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        )

        client.settimeout(1.5)

        try:
            client.connect(
                str(self.SOCKET_PATH)
            )
            client.sendall(mensagem)

            resposta = bytearray()

            while b"\n" not in resposta:
                bloco = client.recv(4096)

                if not bloco:
                    return False

                resposta.extend(bloco)

                if len(resposta) > 65536:
                    return False

            payload = json.loads(
                bytes(resposta).split(b"\n", 1)[0].decode("utf-8")
            )

            return (
                isinstance(payload, dict)
                and payload.get("id") == request_id
                and payload.get("acao") == "system.ping"
                and payload.get("ok") is True
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return False
        finally:
            client.close()

    # ------------------------------------------------------------------
    # Diagnóstico
    # ------------------------------------------------------------------

    def _journal_tail(self) -> str:
        journalctl = shutil.which("journalctl")

        if not journalctl:
            return ""

        proc = subprocess.run(
            [
                journalctl,
                "-u",
                self.SERVICE_NAME,
                "-n",
                "20",
                "--no-pager",
            ],
            capture_output=True,
            text=True,
        )

        if proc.returncode != 0:
            return ""

        return proc.stdout.strip()

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------

    def _info(self, message: str, automatico: bool) -> None:
        if not automatico:
            self.stdout.write(
                f"[MoonShield] {message}"
            )

    def _ok(self, message: str, automatico: bool) -> None:
        if not automatico:
            self.stdout.write(
                self.style.SUCCESS(
                    f"[MoonShield] {message}"
                )
            )

    def _warn(self, message: str) -> None:
        self.stdout.write(
            self.style.WARNING(
                f"[MoonShield] ATENÇÃO: {message}"
            )
        )

    def _validar_pos_instalacao(self, paths: dict) -> None:
        """TAREFA 5: Validações Pós-Instalação."""
        var_dir = paths["django_dir"] / "var"
        cursors_dir = var_dir / "cursors"

        if not var_dir.is_dir():
            raise RuntimeError(f"Validação falhou: Diretório {var_dir} não existe.")
        if not cursors_dir.is_dir():
            raise RuntimeError(f"Validação falhou: Diretório {cursors_dir} não existe.")

        res_w = subprocess.run(
            ["su", "-s", "/bin/sh", "moonshield", "-c", f"test -w {cursors_dir}"],
            capture_output=True
        )
        if res_w.returncode != 0:
            raise RuntimeError(f"Validação falhou: Usuário moonshield não consegue escrever em {cursors_dir}.")

        eve = Path("/var/log/suricata/eve.json")
        if eve.exists():
            res_r = subprocess.run(
                ["su", "-s", "/bin/sh", "moonshield", "-c", f"test -r {eve}"],
                capture_output=True
            )
            if res_r.returncode != 0:
                raise RuntimeError(f"Validação falhou: Usuário moonshield não consegue ler {eve}.")

        units = [
            self.MONITOR_SERVICE_NAME,
            self.WORKER_SERVICE_NAME,
            self.SERVICE_NAME,
            "moonshield-web.service",
        ]

        for unit in units:
            check = self._systemctl(["is-enabled", unit], obrigatorio=False)
            if check.returncode != 0:
                check2 = subprocess.run(["systemctl", "list-unit-files", unit], capture_output=True, text=True)
                if check2.returncode != 0 or "0 unit files listed" in check2.stdout:
                    self._warn(f"Validação alerta: Unit {unit} não localizada no systemd.")
