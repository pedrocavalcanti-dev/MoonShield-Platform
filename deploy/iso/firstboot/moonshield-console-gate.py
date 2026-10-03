#!/usr/bin/env python3
"""MoonShield first-boot provisioning console.

Text-only on purpose: works on VGA Linux consoles, serial-like virtual consoles,
VirtualBox, VMware, Hyper-V and physical machines without requiring a GPU stack.
"""

from __future__ import annotations

import base64
import curses
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import textwrap
import time

STATE_FILE = Path("/var/lib/moonshield-iso-bootstrap/state/status.json")
BUILD_INFO = Path("/var/lib/moonshield-iso-bootstrap/BUILD-INFO")
SUCCESS_MARKER = Path("/var/lib/moonshield/.installation-complete")
FAILURE_MARKER = Path("/var/lib/moonshield/.installation-failed")
INSTALL_STAGE = Path("/var/lib/moonshield/install-stage")
LOG_FILE = "/var/log/moonshield/firstboot-install.log"
INSTALL_LOG = "/var/log/moonshield/install.log"
INSTALLED_KEY = Path("/etc/moonshield/support/maintenance_public.pem")
STAGED_KEY = Path("/var/lib/moonshield-iso-bootstrap/release/deploy/console/maintenance_public.pem")
MAINTENANCE_DIR = Path("/run/moonshield")
SPINNER = ("-", "\\", "|", "/")

LABELS = {
    "base": "Sistema base",
    "payload": "Pacote offline",
    "platform": "Plataforma MoonShield",
    "health": "Validacao de seguranca",
    "console": "Console local",
}

# color pairs
C_ACCENT = 1
C_MUTED = 2
C_TEXT = 3
C_OK = 4
C_ERROR = 5
C_WARN = 6
C_BADGE = 7


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
        curses.init_pair(C_TEXT, curses.COLOR_WHITE, bg)
        curses.init_pair(C_OK, curses.COLOR_GREEN, bg)
        curses.init_pair(C_ERROR, curses.COLOR_RED, bg)
        curses.init_pair(C_WARN, curses.COLOR_YELLOW, bg)
        curses.init_pair(C_BADGE, curses.COLOR_BLACK, curses.COLOR_MAGENTA)
        screen.bkgd(" ", cp(C_TEXT))
    except curses.error:
        pass


def public_key() -> Path | None:
    if INSTALLED_KEY.is_file():
        return INSTALLED_KEY
    if STAGED_KEY.is_file():
        return STAGED_KEY
    return None


def state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return {
            "phase": "waiting",
            "message": "Aguardando inicio do provisionamento...",
            "steps": {
                "base": "ok", "payload": "pending", "platform": "pending",
                "health": "pending", "console": "pending",
            },
            "detail": "",
        }


def build_meta() -> tuple[str, str]:
    version, commit = "0.1.0-alpha.2", "unknown"
    try:
        for raw in BUILD_INFO.read_text(encoding="utf-8", errors="replace").splitlines():
            key, sep, value = raw.partition("=")
            if sep and key == "MoonShieldVersion" and value:
                version = value
            elif sep and key == "GitCommit" and value:
                commit = value
    except OSError:
        pass
    return version, commit[:12]


def current_stage() -> str:
    try:
        return INSTALL_STAGE.read_text(encoding="utf-8", errors="replace").strip()[:80]
    except OSError:
        return ""


def alpha_debug_ipv4() -> str:
    if not Path("/etc/moonshield/alpha-debug").is_file():
        return ""
    try:
        result = subprocess.run(
            ["/usr/sbin/ip", "-4", "-o", "addr", "show", "scope", "global"],
            check=False, capture_output=True, text=True, timeout=3,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) > 3 and fields[2] == "inet":
            return fields[3].split("/", 1)[0]
    return ""


def add(screen, row: int, col: int, text: str, attr: int = 0) -> None:
    height, width = screen.getmaxyx()
    if 0 <= row < height and 0 <= col < width:
        try:
            screen.addnstr(row, col, text, max(0, width - col - 1), attr)
        except curses.error:
            pass


def centered(screen, row: int, text: str, attr: int = 0) -> None:
    _, width = screen.getmaxyx()
    add(screen, row, max(0, (width - len(text)) // 2), text, attr)


def rule(screen, row: int, char: str = "-") -> None:
    _, width = screen.getmaxyx()
    add(screen, row, 2, char * max(0, width - 4), cp(C_MUTED) | curses.A_DIM)


def box(screen, top: int, left: int, height: int, width: int, title: str = "", attr: int = 0) -> None:
    max_h, max_w = screen.getmaxyx()
    height = max(3, min(height, max_h - top))
    width = max(10, min(width, max_w - left))
    if height < 3 or width < 4:
        return
    add(screen, top, left, "+" + "-" * (width - 2) + "+", attr)
    for row in range(top + 1, top + height - 1):
        add(screen, row, left, "|", attr)
        add(screen, row, left + width - 1, "|", attr)
    add(screen, top + height - 1, left, "+" + "-" * (width - 2) + "+", attr)
    if title and width > len(title) + 6:
        add(screen, top, left + 3, f" {title} ", attr | curses.A_BOLD)


def header(screen, subtitle: str, badge: str = "ALPHA 2") -> int:
    screen.erase()
    if curses.has_colors():
        try:
            screen.bkgd(" ", cp(C_TEXT))
        except curses.error:
            pass
    _, width = screen.getmaxyx()
    version, commit = build_meta()
    add(screen, 1, 3, "MOONSHIELD", cp(C_ACCENT) | curses.A_BOLD)
    badge_col = max(3, width - len(badge) - 5)
    add(screen, 1, badge_col, f" {badge} ", cp(C_BADGE) | curses.A_BOLD)
    add(screen, 2, 3, "NETWORK SECURITY APPLIANCE", cp(C_TEXT) | curses.A_BOLD)
    add(screen, 3, 3, f"{version}  //  build {commit}", cp(C_MUTED) | curses.A_DIM)
    rule(screen, 5)
    add(screen, 7, 3, subtitle, cp(C_TEXT) | curses.A_BOLD)
    return 9


def maintenance_identity() -> str:
    try:
        machine_id = Path("/etc/machine-id").read_bytes().strip()
    except OSError:
        machine_id = b"unavailable"
    return hashlib.sha256(machine_id).hexdigest()[:16]


def maintenance(screen) -> None:
    key = public_key()
    start = header(screen, "MANUTENCAO PROTEGIDA", "F12")
    if key is None:
        add(screen, start, 3, "Chave publica de manutencao ausente.", cp(C_ERROR) | curses.A_BOLD)
        add(screen, start + 2, 3, "Pressione qualquer tecla para voltar.", cp(C_MUTED))
        screen.refresh()
        screen.nodelay(False); screen.getch(); screen.nodelay(True)
        return

    challenge = f"MOONSHIELD-MAINT-V1|{maintenance_identity()}|{secrets.token_hex(32)}"
    _, width = screen.getmaxyx()
    add(screen, start, 3, f"Appliance ID: {maintenance_identity()}", cp(C_MUTED))
    add(screen, start + 2, 3, "Challenge:", curses.A_BOLD)
    lines = textwrap.wrap(challenge, max(20, width - 8))
    for offset, line in enumerate(lines):
        add(screen, start + 3 + offset, 3, line, cp(C_TEXT))
    row = start + 4 + len(lines)
    add(screen, row, 3, "Resposta Base64 (ou 'voltar'):", cp(C_TEXT) | curses.A_BOLD)
    screen.refresh()
    curses.echo(); screen.nodelay(False)
    try:
        response = screen.getstr(row + 1, 3, 8192).decode("ascii", "ignore").strip()
    finally:
        curses.noecho(); screen.nodelay(True)
    if response.lower() in {"voltar", "esc", "q", "quit"}:
        return

    try:
        signature = base64.b64decode(response, validate=True)
        if not signature or len(signature) > 8192:
            raise ValueError("assinatura invalida")
        MAINTENANCE_DIR.mkdir(mode=0o750, parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="maintenance-", dir=MAINTENANCE_DIR) as temp_dir:
            os.chmod(temp_dir, 0o700)
            challenge_path = Path(temp_dir) / "challenge"
            signature_path = Path(temp_dir) / "signature"
            challenge_path.write_bytes(challenge.encode("utf-8"))
            signature_path.write_bytes(signature)
            os.chmod(challenge_path, 0o600); os.chmod(signature_path, 0o600)
            verify = subprocess.run(
                ["/usr/bin/openssl", "dgst", "-sha256", "-verify", str(key),
                 "-signature", str(signature_path), str(challenge_path)],
                check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10,
            )
        if verify.returncode != 0:
            raise ValueError("assinatura recusada")
    except (ValueError, OSError, subprocess.TimeoutExpired):
        add(screen, row + 3, 3, "ACESSO NEGADO", cp(C_ERROR) | curses.A_BOLD)
        screen.refresh(); time.sleep(2); return

    add(screen, row + 3, 3, "ACESSO AUTORIZADO", cp(C_OK) | curses.A_BOLD)
    add(screen, row + 4, 3, "Ao encerrar o shell, a console protegida sera restaurada.", cp(C_MUTED))
    screen.refresh(); time.sleep(1)
    curses.def_prog_mode(); curses.endwin()
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/root", "TMOUT": "1800", "HISTFILE": "/dev/null",
        "TERM": os.environ.get("TERM", "linux"), "LANG": "C.UTF-8",
        "USER": "root", "LOGNAME": "root",
    }
    try:
        subprocess.run(["/bin/bash", "--noprofile", "--norc", "-i"], env=env, check=False)
    finally:
        curses.reset_prog_mode(); screen.clear(); screen.refresh()


def exec_final_console() -> None:
    python = Path("/opt/moonshield/venv/bin/python")
    console = Path("/opt/moonshield/console/moonshield_console.py")
    if python.is_file() and console.is_file():
        os.execv(str(python), [str(python), str(console)])


def progress_bar(screen, row: int, completed: int, total: int = 5) -> None:
    _, width = screen.getmaxyx()
    bar_width = max(14, min(50, width - 22))
    ratio = max(0.0, min(1.0, completed / max(1, total)))
    fill = int(bar_width * ratio)
    body = "=" * max(0, fill - 1) + (">" if fill else "") + "." * max(0, bar_width - fill)
    pct = int(ratio * 100)
    add(screen, row, 5, f"[{body}] {pct:3d}%", cp(C_ACCENT) | curses.A_BOLD)


def step_marker(status: str, spin: str) -> tuple[str, int]:
    if status == "ok":
        return "[ OK ]", cp(C_OK) | curses.A_BOLD
    if status == "active":
        return f"[ {spin}  ]", cp(C_ACCENT) | curses.A_BOLD
    if status == "error":
        return "[FAIL]", cp(C_ERROR) | curses.A_BOLD
    return "[ .. ]", cp(C_MUTED) | curses.A_DIM


def draw_progress(screen, spin: str) -> None:
    data = state()
    phase = data.get("phase", "waiting")
    height, width = screen.getmaxyx()
    if height < 20 or width < 68:
        screen.erase()
        add(screen, 1, 2, "MOONSHIELD", curses.A_BOLD)
        add(screen, 3, 2, str(data.get("message", "Provisionando...")))
        add(screen, 5, 2, "Aumente o console para 80x25 ou maior para a interface completa.")
        return

    if SUCCESS_MARKER.exists() or phase == "success":
        start = header(screen, "APPLIANCE PRONTA", "READY")
        box(screen, start, 3, 8, width - 6, "PROVISIONAMENTO CONCLUIDO", cp(C_OK))
        add(screen, start + 2, 6, "MoonShield instalada e validada com sucesso.", cp(C_OK) | curses.A_BOLD)
        add(screen, start + 4, 6, "Iniciando console local protegido...", cp(C_TEXT))
        progress_bar(screen, start + 6, 5)
        screen.refresh(); time.sleep(2.0)
        exec_final_console()
        return

    if FAILURE_MARKER.exists() or phase == "failed":
        start = header(screen, "MODO SEGURO", "FAILED")
        box(screen, start, 3, 15, width - 6, "FALHA NO PROVISIONAMENTO", cp(C_ERROR))
        add(screen, start + 2, 6, "A appliance foi bloqueada antes de liberar operacao normal.", cp(C_ERROR) | curses.A_BOLD)
        stage = current_stage()
        if stage:
            add(screen, start + 4, 6, f"Etapa: {stage}", cp(C_WARN) | curses.A_BOLD)
        detail = str(data.get("detail", "")).strip()
        wrapped = textwrap.wrap(detail, max(24, width - 14))[:3] if detail else []
        for idx, line in enumerate(wrapped):
            add(screen, start + 5 + idx, 6, line, cp(C_TEXT))
        row = start + 9
        add(screen, row, 6, f"Log: {LOG_FILE}", cp(C_MUTED))
        add(screen, row + 1, 6, f"Log: {INSTALL_LOG}", cp(C_MUTED))
        if Path("/etc/moonshield/alpha-debug").is_file():
            address = alpha_debug_ipv4()
            add(screen, row + 2, 6, "ALPHA DEBUG SSH: ATIVO  //  Auth: chave de manutencao", cp(C_WARN) | curses.A_BOLD)
            add(screen, row + 3, 6, f"SSH: ssh root@{address}" if address else "SSH: aguardando rede", cp(C_TEXT))
            f12_row = row + 4
        else:
            f12_row = row + 3
        add(screen, f12_row, 6, "F12  manutencao protegida por challenge/response", cp(C_ACCENT) | curses.A_BOLD)
        add(screen, height - 2, 3, "Nenhum login Debian foi liberado.", cp(C_MUTED) | curses.A_DIM)
        return

    start = header(screen, "PREPARANDO SUA APPLIANCE", "PROVISIONING")
    message = str(data.get("message", "Preparando instalacao..."))
    box(screen, start, 3, 13, width - 6, "BOOTSTRAP SEGURO", cp(C_ACCENT))
    add(screen, start + 2, 6, f"{spin}  {message}", cp(C_TEXT) | curses.A_BOLD)
    add(screen, start + 3, 6, "Nao desligue o equipamento durante esta etapa.", cp(C_WARN))

    steps = data.get("steps", {}) if isinstance(data.get("steps", {}), dict) else {}
    order = ("base", "payload", "platform", "health", "console")
    completed = sum(1 for key in order if steps.get(key) == "ok")
    progress_bar(screen, start + 5, completed, len(order))
    row = start + 7
    for key in order:
        marker, attr = step_marker(steps.get(key, "pending"), spin)
        add(screen, row, 7, marker, attr)
        add(screen, row, 16, LABELS[key], cp(C_TEXT) if steps.get(key) != "pending" else cp(C_MUTED))
        row += 1
    debug = "  //  DEBUG SSH: ACTIVE" if Path("/etc/moonshield/alpha-debug").is_file() else ""
    add(screen, height - 2, 3, f"MoonShield Secure Bootstrap{debug}  //  console local protegida", cp(C_MUTED) | curses.A_DIM)


def main(screen) -> None:
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    screen.keypad(True); screen.nodelay(True)
    init_colors(screen)
    index = 0
    while True:
        draw_progress(screen, SPINNER[index % len(SPINNER)])
        screen.refresh()
        key = screen.getch()
        if key == curses.KEY_F12:
            current = state()
            if FAILURE_MARKER.exists() or current.get("phase") == "failed":
                maintenance(screen)
        index += 1
        time.sleep(0.20)


if __name__ == "__main__":
    if os.name != "posix":
        raise SystemExit("MoonShield Console Gate requer Linux.")
    MAINTENANCE_DIR.mkdir(mode=0o750, parents=True, exist_ok=True)
    curses.wrapper(main)
