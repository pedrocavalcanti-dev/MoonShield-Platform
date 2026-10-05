#!/usr/bin/env python3
"""Local read-only appliance console with narrowly allowlisted actions."""

from __future__ import annotations

import base64
import curses
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import tempfile
import textwrap
import time


TITLE = "MOONSHIELD"
CONFIG = Path("/etc/moonshield/appliance.conf")
BUILD_INFO = Path("/etc/moonshield/build-info")
PUBLIC_KEY = Path("/etc/moonshield/support/maintenance_public.pem")
MAINTENANCE_DIR = Path("/run/moonshield")
SERVICES = {
    "Web": "moonshield-web.service",
    "Agent": "moonshield-agent.service",
    "Suricata monitor": "moonshield-suricata-monitor.service",
    "Suricata worker": "moonshield-suricata-worker.service",
    "Nginx": "nginx.service",
    "PostgreSQL": "postgresql.service",
    "Suricata": "suricata.service",
    "AdGuard Home": "AdGuardHome.service",
    "NetworkManager": "NetworkManager.service",
    "nftables": "nftables.service",
}
RESTARTABLE = {
    "moonshield-web.service",
    "moonshield-agent.service",
    "moonshield-suricata-monitor.service",
    "moonshield-suricata-worker.service",
}
FAILURE_LIMIT = 3
COOLDOWN_SECONDS = 30

C_ACCENT = 1
C_MUTED = 2
C_OK = 3
C_WARN = 4
C_ERROR = 5
C_SELECTED = 6


def cp(index: int) -> int:
    return curses.color_pair(index) if curses.has_colors() else 0


def init_colors(screen) -> None:
    if not curses.has_colors():
        return
    try:
        curses.start_color()
        try:
            curses.use_default_colors()
        except curses.error:
            pass
        bg = curses.COLOR_BLACK
        curses.init_pair(C_ACCENT, curses.COLOR_MAGENTA, bg)
        curses.init_pair(C_MUTED, curses.COLOR_CYAN, bg)
        curses.init_pair(C_OK, curses.COLOR_GREEN, bg)
        curses.init_pair(C_WARN, curses.COLOR_YELLOW, bg)
        curses.init_pair(C_ERROR, curses.COLOR_RED, bg)
        curses.init_pair(C_SELECTED, curses.COLOR_WHITE, curses.COLOR_MAGENTA)
        screen.bkgd(" ", 0)
    except curses.error:
        pass


def selected_attr() -> int:
    return (cp(C_SELECTED) | curses.A_BOLD) if curses.has_colors() else curses.A_REVERSE



def command(args: list[str], timeout: float = 3.0) -> str:
    try:
        result = subprocess.run(
            args, check=False, capture_output=True, text=True, timeout=timeout,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def service_active(unit: str) -> bool:
    try:
        return subprocess.run(
            ["systemctl", "is-active", "--quiet", unit], check=False,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3.0,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
        ).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def file_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            key, sep, value = line.partition("=")
            if sep and key and key not in values:
                values[key] = value.strip()
    except OSError:
        pass
    return values


def config_values() -> dict[str, str]:
    return file_values(CONFIG)


def uptime_text() -> str:
    try:
        seconds = int(float(Path("/proc/uptime").read_text().split()[0]))
    except (OSError, ValueError, IndexError):
        return "indisponivel"
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes = seconds // 60
    return f"{days}d {hours:02}h {minutes:02}m"


def version() -> str:
    return build_values().get("MoonShieldVersion", config_values().get("MOONSHIELD_VERSION", "indisponivel"))


def build_values() -> dict[str, str]:
    return file_values(BUILD_INFO)


def build() -> str:
    return build_values().get("GitCommit", "indisponivel")[:12]


def interfaces() -> list[tuple[str, str, str]]:
    result = command(["ip", "-o", "-4", "addr", "show"])
    rows: list[tuple[str, str, str]] = []
    for line in result.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        name = fields[1].split("@", 1)[0]
        try:
            state = Path("/sys/class/net", name, "operstate").read_text().strip().upper()
        except OSError:
            state = "UNKNOWN"
        address = fields[fields.index("inet") + 1] if "inet" in fields else "sem IPv4"
        rows.append((name, address, state))
    return rows


def default_route() -> str:
    route = command(["ip", "-4", "route", "show", "default"])
    return route or "não identificado"


def dns_servers() -> str:
    values = command(["resolvectl", "dns"])
    if values:
        servers = []
        for line in values.splitlines():
            parts = line.split(":", 1)
            if len(parts) == 2:
                servers.extend(parts[1].split())
        if servers:
            return ", ".join(dict.fromkeys(servers))
    try:
        servers = [line.split()[1] for line in Path("/etc/resolv.conf").read_text().splitlines()
                   if line.startswith("nameserver ")]
        return ", ".join(dict.fromkeys(servers)) or "não identificado"
    except (OSError, IndexError):
        return "não identificado"


def management_ip() -> str:
    values = config_values()
    configured = values.get("MOONSHIELD_MGMT_IP", values.get("MOONSHIELD_MANAGEMENT_IP", ""))
    try:
        return str(ipaddress.ip_address(configured)) if configured else "não identificado"
    except ValueError:
        return "não identificado"


def lan_ip() -> str:
    configured = config_values().get("MOONSHIELD_LAN_IP", "")
    try:
        return str(ipaddress.ip_address(configured)) if configured else "não identificado"
    except ValueError:
        return "não identificado"


def fallback_network() -> tuple[str, str, str]:
    route = command(["ip", "-4", "route", "show", "default"])
    interface_match = re.search(r"\bdev\s+(\S+)", route)
    gateway_match = re.search(r"\bvia\s+(\S+)", route)
    interface = interface_match.group(1) if interface_match else "indisponivel"
    gateway = gateway_match.group(1) if gateway_match else "indisponivel"
    address = "indisponivel"
    if interface != "indisponivel":
        output = command(["ip", "-o", "-4", "addr", "show", "dev", interface, "scope", "global"])
        match = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/", output)
        if match:
            address = match.group(1)
    return interface, address, gateway


def management_ip() -> str:
    values = config_values()
    configured = values.get("MOONSHIELD_MGMT_IP", values.get("MOONSHIELD_MANAGEMENT_IP", ""))
    try:
        return str(ipaddress.ip_address(configured)) if configured else fallback_network()[1]
    except ValueError:
        return fallback_network()[1]


def administrative_interface() -> str:
    values = config_values()
    configured = values.get("MOONSHIELD_MGMT_INTERFACE", values.get("MOONSHIELD_MANAGEMENT_INTERFACE", ""))
    return configured if configured else fallback_network()[0]


def administrative_gateway() -> str:
    return fallback_network()[2]


def topology_state() -> str:
    values = config_values()
    return "MGMT oficial" if values.get("MOONSHIELD_MGMT_IP", values.get("MOONSHIELD_MANAGEMENT_IP", "")) else "aguardando onboarding"


def appliance_url() -> str:
    host = management_ip()
    if host == "não identificado":
        return "configuração de rede pendente"
    secure = config_values().get("SECURE_SSL_REDIRECT", "False").lower() == "true"
    return f"{'https' if secure else 'http'}://{host}/"


def ssh_channel() -> str:
    channel = build_values().get("ReleaseChannel", "").lower()
    if channel in {"alpha", "beta", "stable"}:
        return channel
    return "alpha" if Path("/etc/moonshield/alpha-debug").is_file() else "stable"


def ssh_lines() -> list[str]:
    return [
        f"Status: {'ATIVO' if service_active('ssh.service') else 'INATIVO'}",
        f"Interface: {administrative_interface()}",
        f"IP: {management_ip()}",
        "Porta: 22",
        "Autenticacao: chave publica somente",
        f"Canal: {ssh_channel()}",
    ]


def ssh_menu(screen) -> None:
    if ssh_channel() not in {"alpha", "beta"}:
        lines_screen(screen, "SSH / Manutencao", ssh_lines() + ["SSH permanece desabilitado no canal stable."])
        return
    while True:
        start = draw_header(screen, "SSH / MANUTENCAO")
        height, width = screen.getmaxyx()
        for index, line in enumerate(ssh_lines()):
            screen.addnstr(start + index, 2, line, max(0, width - 4))
        row = start + len(ssh_lines()) + 1
        screen.addnstr(row, 2, "[A] Ativar  [D] Desativar  [R] Reiniciar SSH", max(0, width - 4))
        screen.addnstr(height - 1, 2, "Esc: voltar", max(0, width - 4))
        screen.refresh()
        key = screen.getch()
        if key == 27:
            return
        if key in (ord("a"), ord("A")):
            controlled_action(screen, "ativar SSH", ["systemctl", "enable", "--now", "ssh.service"])
        elif key in (ord("d"), ord("D")):
            controlled_action(screen, "desativar SSH", ["systemctl", "disable", "--now", "ssh.service"])
        elif key in (ord("r"), ord("R")):
            controlled_action(screen, "reiniciar SSH", ["systemctl", "restart", "ssh.service"])


def internet_status() -> bool:
    # Connectivity is informational and never required for appliance operation.
    try:
        return subprocess.run(
            ["curl", "--silent", "--show-error", "--location", "--head", "--max-time", "5",
             "https://deb.debian.org/"], check=False, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=6.0,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
        ).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def draw_header(screen, subtitle: str = "Appliance de Seguranca de Rede") -> int:
    height, width = screen.getmaxyx()
    screen.erase()
    try:
        screen.bkgd(" ", 0)
    except curses.error:
        pass
    title = f"{TITLE} // {subtitle}"
    screen.addnstr(0, 2, title, max(0, width - 4), cp(C_ACCENT) | curses.A_BOLD)
    badge = " SECURE CONSOLE "
    if width > len(badge) + len(title) + 8:
        screen.addnstr(0, width - len(badge) - 2, badge, len(badge), selected_attr())
    screen.addnstr(1, 2, f"v{version()} // build {build()}", max(0, width - 4), cp(C_MUTED) | curses.A_DIM)
    screen.addnstr(2, 2, "SYSTEM ONLINE | FIREWALL | IDS | DNS", max(0, width - 4), cp(C_MUTED) | curses.A_DIM)
    screen.addnstr(3, 1, "-" * max(0, width - 2), max(0, width - 2), cp(C_ACCENT) | curses.A_DIM)
    return 5


def lines_screen(screen, title: str, lines: list[str]) -> None:
    start = draw_header(screen, title)
    height, width = screen.getmaxyx()
    for index, line in enumerate(lines[:max(0, height - start - 2)]):
        screen.addnstr(start + index, 2, line, max(0, width - 4))
    screen.addnstr(height - 1, 2, "Esc: voltar  |  Enter: voltar", max(0, width - 4))
    screen.refresh()
    while screen.getch() not in (27, 10, 13, curses.KEY_ENTER):
        pass


def status_lines() -> list[str]:
    active = {name: service_active(unit) for name, unit in SERVICES.items()}
    core_state = (active["Web"], active["Agent"], active["Nginx"], active["PostgreSQL"])
    system = "ONLINE" if all(core_state) else "OFFLINE" if not any(core_state) else "DEGRADADO"
    firewall = active["nftables"]
    ids = active["Suricata"]
    dns = active["AdGuard Home"]
    return [
        f"Sistema: {system}",
        f"Firewall: {'PROTEGIDO' if firewall else 'DEGRADADO'}",
        f"IDS: {'MONITORANDO' if ids else 'OFFLINE'}",
        f"DNS: {'ATIVO' if dns else 'OFFLINE'}",
        "",
        f"Hostname: {socket.gethostname()}",
        f"IP de gerenciamento: {management_ip()}",
        f"URL Web: {appliance_url()}",
        f"Tempo ativo: {uptime_text()}",
        f"Versão MoonShield: {version()}",
    ]


def network_lines() -> list[str]:
    rows = interfaces()
    lines = ["Interfaces (somente leitura):"]
    lines.extend(f"  {name:<16} {address:<20} {state}" for name, address, state in rows)
    if not rows:
        lines.append("  Interfaces indisponíveis")
    lines.extend(["", f"Rota padrão: {default_route()}", f"DNS: {dns_servers()}"])
    lines.extend([f"MGMT: {management_ip()}", f"LAN: {lan_ip()}"])
    return lines


def diagnostic_lines() -> list[str]:
    route = default_route()
    gateway_match = re.search(r"\bvia\s+(\S+)", route)
    gateway_ok = bool(gateway_match and command(["ping", "-c", "1", "-W", "2", gateway_match.group(1)], timeout=3.0))
    dns_ok = bool(command(["getent", "ahostsv4", "deb.debian.org"], timeout=4.0))
    checks = [
        ("Gateway", gateway_ok),
        ("Resolução DNS", dns_ok),
        ("Nginx", service_active("nginx.service")),
        ("PostgreSQL", service_active("postgresql.service")),
        ("Suricata", service_active("suricata.service")),
        ("AdGuard Home", service_active("AdGuardHome.service")),
        ("MoonShield Agent", service_active("moonshield-agent.service")),
    ]
    lines = [f"{'PASS' if okay else 'WARN'}  {label}" for label, okay in checks]
    lines.append(f"{'PASS' if internet_status() else 'OPTIONAL'}  Internet (opcional)")
    return lines


def system_lines() -> list[str]:
    memory = "indisponível"
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                memory = f"{int(line.split()[1]) // 1024} MiB"
                break
    except (OSError, ValueError, IndexError):
        pass
    return [
        f"Hostname: {socket.gethostname()}",
        f"Sistema: {command(['uname', '-sr']) or 'indisponível'}",
        f"Tempo ativo: {uptime_text()}",
        f"Memória total: {memory}",
        f"MoonShield: {version()}",
        f"Python: {command(['/usr/bin/python3', '--version']) or 'indisponível'}",
    ]


def service_lines() -> list[str]:
    return [f"{'ATIVO' if service_active(unit) else 'INATIVO':<8} {name}"
            for name, unit in SERVICES.items()]


def wait_key(screen, prompt: str) -> int:
    height, width = screen.getmaxyx()
    screen.addnstr(height - 1, 2, prompt, max(0, width - 4))
    screen.refresh()
    return screen.getch()


def confirm(screen, action: str) -> bool:
    key = wait_key(screen, f"Confirmar {action}? Digite S para continuar; qualquer outra tecla cancela: ")
    return key in (ord("s"), ord("S"))


def controlled_action(screen, action: str, args: list[str]) -> None:
    if not confirm(screen, action):
        return
    try:
        result = subprocess.run(args, check=False, capture_output=True, timeout=60)
        succeeded = result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        succeeded = False
    message = f"{action}: {'concluído' if succeeded else 'falhou'}"
    lines_screen(screen, "Ação", [message])


def maintenance_identity() -> str:
    try:
        machine_id = Path("/etc/machine-id").read_bytes().strip()
    except OSError:
        machine_id = b"unavailable"
    return hashlib.sha256(machine_id).hexdigest()[:16]


def maintenance_shell(screen) -> None:
    if not PUBLIC_KEY.is_file():
        lines_screen(screen, "Manutenção", ["Modo de manutenção: NÃO PROVISIONADO", "Chave pública ausente."])
        return
    failures = 0
    cooldown_until = 0.0
    while True:
        start = draw_header(screen, "MANUTENÇÃO MOONSHIELD")
        height, width = screen.getmaxyx()
        if time.monotonic() < cooldown_until:
            remaining = int(cooldown_until - time.monotonic()) + 1
            screen.addnstr(start, 2, f"ACESSO NEGADO. Aguarde {remaining}s.", max(0, width - 4))
            wait_key(screen, "Esc: voltar")
            return
        challenge = f"MOONSHIELD-MAINT-V1|{maintenance_identity()}|{secrets.token_hex(32)}"
        screen.addnstr(start, 2, f"Appliance: {maintenance_identity()}", max(0, width - 4))
        screen.addnstr(start + 2, 2, "Desafio:", max(0, width - 4))
        challenge_lines = textwrap.wrap(challenge, max(1, width - 4))
        for offset, line in enumerate(challenge_lines):
            screen.addnstr(start + 3 + offset, 2, line, max(0, width - 4))
        response_row = start + 4 + len(challenge_lines)
        screen.addnstr(response_row, 2, "Resposta (Base64):", max(0, width - 4))
        screen.refresh()
        curses.echo()
        try:
            response = screen.getstr(response_row + 1, 2, 8192).decode("ascii", "ignore").strip()
        finally:
            curses.noecho()
        if response.lower() in {"esc", "q", "quit"}:
            return
        try:
            signature = base64.b64decode(response, validate=True)
            if not signature or len(signature) > 8192:
                raise ValueError("invalid signature size")
            with tempfile.TemporaryDirectory(prefix="maintenance-", dir=MAINTENANCE_DIR) as temp_dir:
                os.chmod(temp_dir, 0o700)
                challenge_path = Path(temp_dir) / "challenge"
                signature_path = Path(temp_dir) / "signature"
                challenge_path.write_bytes(challenge.encode("utf-8"))
                signature_path.write_bytes(signature)
                os.chmod(challenge_path, 0o600)
                os.chmod(signature_path, 0o600)
                verify = subprocess.run(
                    ["openssl", "dgst", "-sha256", "-verify", str(PUBLIC_KEY),
                     "-signature", str(signature_path), str(challenge_path)],
                    check=False, capture_output=True, timeout=10,
                )
            if verify.returncode != 0:
                raise ValueError("signature verification failed")
        except (ValueError, OSError, subprocess.TimeoutExpired):
            failures += 1
            screen.addnstr(start + 8, 2, "ACESSO NEGADO", max(0, width - 4))
            screen.refresh()
            time.sleep(1)
            if failures >= FAILURE_LIMIT:
                cooldown_until = time.monotonic() + COOLDOWN_SECONDS
            continue

        subprocess.run(["logger", "-t", "moonshield-console", "maintenance session opened"],
                       check=False, capture_output=True, timeout=3)
        screen.addnstr(start + 8, 2, "ACESSO AUTORIZADO. Ao encerrar o shell, você retorna ao console.", max(0, width - 4))
        screen.refresh()
        time.sleep(1)
        curses.def_prog_mode()
        curses.endwin()
        env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "TMOUT": "1800",
               "HISTFILE": "/dev/null", "TERM": os.environ.get("TERM", "linux"),
               "LANG": "C.UTF-8", "USER": "root", "LOGNAME": "root"}
        try:
            subprocess.run(["/bin/bash", "--noprofile", "--norc", "-i"], env=env, check=False)
        finally:
            subprocess.run(["logger", "-t", "moonshield-console", "maintenance session closed"],
                           check=False, capture_output=True, timeout=3)
            curses.reset_prog_mode()
            screen.clear()
            screen.refresh()
        return


def main(screen) -> None:
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    screen.keypad(True)
    screen.timeout(-1)
    init_colors(screen)
    menu = [
        ("1", "Status da appliance"),
        ("2", "Informações de rede"),
        ("3", "Diagnóstico"),
        ("4", "Serviços"),
        ("5", "Informações do sistema"),
        ("6", "SSH / Manutenção"),
        ("8", "Reiniciar"),
        ("9", "Desligar"),
    ]
    selected = 0
    while True:
        start = draw_header(screen)
        height, width = screen.getmaxyx()
        for index, (number, label) in enumerate(menu):
            text = f"[{number}]  {label}"
            if index == selected:
                screen.addnstr(start + index, 3, text, max(0, width - 6), selected_attr())
            else:
                screen.addnstr(start + index, 3, text, max(0, width - 6))
        details = [
            f"Hostname : {socket.gethostname()}",
            f"IP       : {management_ip()}",
            f"Interface: {administrative_interface()}",
            f"Gateway  : {administrative_gateway()}",
            f"Web      : {appliance_url()}",
            f"Topologia: {topology_state()}",
        ]
        panel_x = max(40, width // 2)
        for index, detail in enumerate(details):
            screen.addnstr(start + index, panel_x, detail, max(0, width - panel_x - 2))
        screen.addnstr(height - 1, 2, "Setas/Enter | Esc voltar | F12 manutenção", max(0, width - 4))
        screen.refresh()
        key = screen.getch()
        if key == curses.KEY_F12:
            maintenance_shell(screen)
        elif key in (curses.KEY_UP, ord("k")):
            selected = (selected - 1) % len(menu)
        elif key in (curses.KEY_DOWN, ord("j")):
            selected = (selected + 1) % len(menu)
        elif key in (10, 13, curses.KEY_ENTER):
            key = ord(menu[selected][0])
        elif key == 27:
            continue
        if key == ord("1"):
            lines_screen(screen, "Status da appliance", status_lines())
        elif key == ord("2"):
            lines_screen(screen, "Informações de rede", network_lines())
        elif key == ord("3"):
            lines_screen(screen, "Diagnóstico somente leitura", diagnostic_lines())
        elif key == ord("6"):
            ssh_menu(screen)
        elif key == ord("4"):
            draw_header(screen, "Serviços")
            for idx, line in enumerate(service_lines()):
                screen.addnstr(4 + idx, 2, line, max(0, width - 4))
            screen.addnstr(height - 2, 2, "R: reiniciar apenas um serviço MoonShield selecionado", max(0, width - 4))
            screen.addnstr(height - 1, 2, "Esc: voltar", max(0, width - 4))
            screen.refresh()
            choice = screen.getch()
            if choice == ord("r") or choice == ord("R"):
                restartable = sorted(RESTARTABLE)
                selected_service = 0
                while True:
                    service_start = draw_header(screen, "Serviços reiniciáveis")
                    height, width = screen.getmaxyx()
                    for service_index, unit in enumerate(restartable):
                        label = f"{service_index + 1}: {unit}"
                        if service_index == selected_service:
                            screen.addnstr(service_start + service_index, 3, label, max(0, width - 6), selected_attr())
                        else:
                            screen.addnstr(service_start + service_index, 3, label, max(0, width - 6))
                    screen.addnstr(height - 1, 2, "Setas/Enter: selecionar  |  Esc: cancelar", max(0, width - 4))
                    screen.refresh()
                    selection = screen.getch()
                    if selection == 27:
                        break
                    if selection == curses.KEY_UP:
                        selected_service = (selected_service - 1) % len(restartable)
                    elif selection == curses.KEY_DOWN:
                        selected_service = (selected_service + 1) % len(restartable)
                    elif selection in (10, 13, curses.KEY_ENTER):
                        unit = restartable[selected_service]
                        controlled_action(screen, f"reiniciar {unit}", ["systemctl", "restart", unit])
                        break
        elif key == ord("5"):
            lines_screen(screen, "Informações do sistema", system_lines())
        elif key == ord("8") and confirm(screen, "reiniciar a appliance"):
            controlled_action(screen, "reiniciar a appliance", ["systemctl", "reboot"])
        elif key == ord("9") and confirm(screen, "desligar a appliance"):
            controlled_action(screen, "desligar a appliance", ["systemctl", "poweroff"])


if __name__ == "__main__":
    if os.name != "posix":
        raise SystemExit("MoonShield Console requer Linux.")
    MAINTENANCE_DIR.mkdir(mode=0o750, parents=True, exist_ok=True)
    curses.wrapper(main)
