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


def config_values() -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        for line in CONFIG.read_text(encoding="utf-8").splitlines():
            key, sep, value = line.partition("=")
            if sep and key and key not in values:
                values[key] = value.strip()
    except OSError:
        pass
    return values


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
    values = config_values()
    return values.get("MOONSHIELD_VERSION", "indisponivel")


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
    return route or "not identified"


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
        return ", ".join(dict.fromkeys(servers)) or "not identified"
    except (OSError, IndexError):
        return "not identified"


def management_ip() -> str:
    values = config_values()
    configured = values.get("MOONSHIELD_MGMT_IP", values.get("MOONSHIELD_MANAGEMENT_IP", ""))
    try:
        return str(ipaddress.ip_address(configured)) if configured else "not identified"
    except ValueError:
        return "not identified"


def lan_ip() -> str:
    configured = config_values().get("MOONSHIELD_LAN_IP", "")
    try:
        return str(ipaddress.ip_address(configured)) if configured else "not identified"
    except ValueError:
        return "not identified"


def appliance_url() -> str:
    host = management_ip()
    if host == "not identified":
        return "pending network configuration"
    secure = config_values().get("SECURE_SSL_REDIRECT", "False").lower() == "true"
    return f"{'https' if secure else 'http'}://{host}/"


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


def draw_header(screen, subtitle: str = "Network Security Appliance") -> int:
    height, width = screen.getmaxyx()
    screen.erase()
    if curses.has_colors():
        try:
            screen.attron(curses.color_pair(1) | curses.A_BOLD)
        except curses.error:
            pass
    screen.addnstr(0, 2, f"{TITLE}  |  {subtitle}", max(0, width - 4))
    if curses.has_colors():
        try:
            screen.attroff(curses.color_pair(1) | curses.A_BOLD)
        except curses.error:
            pass
    screen.addnstr(1, 2, "System  Firewall  IDS  DNS", max(0, width - 4))
    screen.addnstr(2, 1, "-" * max(0, width - 2), max(0, width - 2))
    return 4


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
    system = "ONLINE" if all(core_state) else "OFFLINE" if not any(core_state) else "DEGRADED"
    firewall = active["nftables"]
    ids = active["Suricata"]
    dns = active["AdGuard Home"]
    return [
        f"System: {system}",
        f"Firewall: {'PROTECTED' if firewall else 'DEGRADED'}",
        f"IDS: {'MONITORING' if ids else 'OFFLINE'}",
        f"DNS: {'ACTIVE' if dns else 'OFFLINE'}",
        "",
        f"Hostname: {socket.gethostname()}",
        f"Management IP: {management_ip()}",
        f"Web URL: {appliance_url()}",
        f"Uptime: {uptime_text()}",
        f"MoonShield version: {version()}",
    ]


def network_lines() -> list[str]:
    rows = interfaces()
    lines = ["Interfaces (read-only):"]
    lines.extend(f"  {name:<16} {address:<20} {state}" for name, address, state in rows)
    if not rows:
        lines.append("  Interfaces unavailable")
    lines.extend(["", f"Default route: {default_route()}", f"DNS: {dns_servers()}"])
    lines.extend([f"MGMT: {management_ip()}", f"LAN: {lan_ip()}"])
    return lines


def diagnostic_lines() -> list[str]:
    route = default_route()
    gateway_match = re.search(r"\bvia\s+(\S+)", route)
    gateway_ok = bool(gateway_match and command(["ping", "-c", "1", "-W", "2", gateway_match.group(1)], timeout=3.0))
    dns_ok = bool(command(["getent", "ahostsv4", "deb.debian.org"], timeout=4.0))
    checks = [
        ("Gateway", gateway_ok),
        ("DNS resolution", dns_ok),
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
    memory = "unavailable"
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                memory = f"{int(line.split()[1]) // 1024} MiB"
                break
    except (OSError, ValueError, IndexError):
        pass
    return [
        f"Hostname: {socket.gethostname()}",
        f"System: {command(['uname', '-sr']) or 'unavailable'}",
        f"Uptime: {uptime_text()}",
        f"Memory total: {memory}",
        f"MoonShield: {version()}",
        f"Python: {command(['/usr/bin/python3', '--version']) or 'unavailable'}",
    ]


def service_lines() -> list[str]:
    return [f"{'ACTIVE' if service_active(unit) else 'INACTIVE':<8} {name}"
            for name, unit in SERVICES.items()]


def wait_key(screen, prompt: str) -> int:
    height, width = screen.getmaxyx()
    screen.addnstr(height - 1, 2, prompt, max(0, width - 4))
    screen.refresh()
    return screen.getch()


def confirm(screen, action: str) -> bool:
    key = wait_key(screen, f"Confirmar {action}? Digite Y para continuar; qualquer outra tecla cancela: ")
    return key in (ord("y"), ord("Y"))


def controlled_action(screen, action: str, args: list[str]) -> None:
    if not confirm(screen, action):
        return
    try:
        result = subprocess.run(args, check=False, capture_output=True, timeout=60)
        succeeded = result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        succeeded = False
    message = f"{action}: {'solicitado' if succeeded else 'falhou'}"
    lines_screen(screen, "Action", [message])


def maintenance_identity() -> str:
    try:
        machine_id = Path("/etc/machine-id").read_bytes().strip()
    except OSError:
        machine_id = b"unavailable"
    return hashlib.sha256(machine_id).hexdigest()[:16]


def maintenance_shell(screen) -> None:
    if not PUBLIC_KEY.is_file():
        lines_screen(screen, "Maintenance", ["Maintenance Mode: NOT PROVISIONED", "Public key missing."])
        return
    failures = 0
    cooldown_until = 0.0
    while True:
        start = draw_header(screen, "MOONSHIELD MAINTENANCE")
        height, width = screen.getmaxyx()
        if time.monotonic() < cooldown_until:
            remaining = int(cooldown_until - time.monotonic()) + 1
            screen.addnstr(start, 2, f"ACCESS DENIED. Aguarde {remaining}s.", max(0, width - 4))
            wait_key(screen, "Esc: voltar")
            return
        challenge = f"MOONSHIELD-MAINT-V1|{maintenance_identity()}|{secrets.token_hex(32)}"
        screen.addnstr(start, 2, f"Appliance: {maintenance_identity()}", max(0, width - 4))
        screen.addnstr(start + 2, 2, "Challenge:", max(0, width - 4))
        challenge_lines = textwrap.wrap(challenge, max(1, width - 4))
        for offset, line in enumerate(challenge_lines):
            screen.addnstr(start + 3 + offset, 2, line, max(0, width - 4))
        response_row = start + 4 + len(challenge_lines)
        screen.addnstr(response_row, 2, "Response (Base64):", max(0, width - 4))
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
            screen.addnstr(start + 8, 2, "ACCESS DENIED", max(0, width - 4))
            screen.refresh()
            time.sleep(1)
            if failures >= FAILURE_LIMIT:
                cooldown_until = time.monotonic() + COOLDOWN_SECONDS
            continue

        subprocess.run(["logger", "-t", "moonshield-console", "maintenance session opened"],
                       check=False, capture_output=True, timeout=3)
        screen.addnstr(start + 8, 2, "ACCESS GRANTED. Encerrando shell retorna ao console.", max(0, width - 4))
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
    if curses.has_colors():
        try:
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_CYAN, -1)
        except curses.error:
            pass
    menu = [
        ("1", "Status da appliance"),
        ("2", "Network information"),
        ("3", "Diagnostics"),
        ("4", "Services"),
        ("5", "System information"),
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
                screen.addnstr(start + index, 3, text, max(0, width - 6), curses.A_REVERSE)
            else:
                screen.addnstr(start + index, 3, text, max(0, width - 6))
        screen.addnstr(height - 2, 2, f"{socket.gethostname()}  |  {management_ip()}  |  {uptime_text()}", max(0, width - 4))
        screen.addnstr(height - 1, 2, "Setas/Enter: selecionar   Esc: permanecer", max(0, width - 4))
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
            lines_screen(screen, "Network information", network_lines())
        elif key == ord("3"):
            lines_screen(screen, "Read-only diagnostics", diagnostic_lines())
        elif key == ord("4"):
            draw_header(screen, "Services")
            for idx, line in enumerate(service_lines()):
                screen.addnstr(4 + idx, 2, line, max(0, width - 4))
            screen.addnstr(height - 2, 2, "R: restart selected MoonShield service only", max(0, width - 4))
            screen.addnstr(height - 1, 2, "Esc: voltar", max(0, width - 4))
            screen.refresh()
            choice = screen.getch()
            if choice == ord("r") or choice == ord("R"):
                restartable = sorted(RESTARTABLE)
                selected_service = 0
                while True:
                    service_start = draw_header(screen, "Restartable services")
                    height, width = screen.getmaxyx()
                    for service_index, unit in enumerate(restartable):
                        label = f"{service_index + 1}: {unit}"
                        if service_index == selected_service:
                            screen.addnstr(service_start + service_index, 3, label, max(0, width - 6), curses.A_REVERSE)
                        else:
                            screen.addnstr(service_start + service_index, 3, label, max(0, width - 6))
                    screen.addnstr(height - 1, 2, "Arrows/Enter: select  |  Esc: cancel", max(0, width - 4))
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
                        controlled_action(screen, f"restart {unit}", ["systemctl", "restart", unit])
                        break
        elif key == ord("5"):
            lines_screen(screen, "System information", system_lines())
        elif key == ord("8") and confirm(screen, "reiniciar a appliance"):
            controlled_action(screen, "reiniciar a appliance", ["systemctl", "reboot"])
        elif key == ord("9") and confirm(screen, "desligar a appliance"):
            controlled_action(screen, "desligar a appliance", ["systemctl", "poweroff"])


if __name__ == "__main__":
    if os.name != "posix":
        raise SystemExit("MoonShield Console requer Linux.")
    MAINTENANCE_DIR.mkdir(mode=0o750, parents=True, exist_ok=True)
    curses.wrapper(main)
