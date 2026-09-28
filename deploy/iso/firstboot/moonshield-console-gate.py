#!/usr/bin/env python3
"""Tela local segura durante o provisionamento inicial da MoonShield Appliance."""

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
SUCCESS_MARKER = Path("/var/lib/moonshield/.installation-complete")
FAILURE_MARKER = Path("/var/lib/moonshield/.installation-failed")
LOG_FILE = "/var/log/moonshield/firstboot-install.log"
INSTALLED_KEY = Path("/etc/moonshield/support/maintenance_public.pem")
STAGED_KEY = Path("/var/lib/moonshield-iso-bootstrap/release/deploy/console/maintenance_public.pem")
MAINTENANCE_DIR = Path("/run/moonshield")
SPINNER = "|/-\\"

LABELS = {
    "base": "Sistema base",
    "payload": "Pacote de instalação",
    "platform": "Plataforma MoonShield",
    "health": "Validação dos serviços",
    "console": "Console local",
}


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
            "message": "Aguardando início do provisionamento...",
            "steps": {"base": "ok", "payload": "pending", "platform": "pending", "health": "pending", "console": "pending"},
            "detail": "",
        }


def add(screen, row: int, col: int, text: str, attr: int = 0) -> None:
    height, width = screen.getmaxyx()
    if 0 <= row < height and col < width:
        try:
            screen.addnstr(row, col, text, max(0, width - col - 1), attr)
        except curses.error:
            pass


def header(screen, subtitle: str) -> int:
    screen.erase()
    height, width = screen.getmaxyx()
    title_attr = curses.A_BOLD | (curses.color_pair(1) if curses.has_colors() else 0)
    add(screen, 1, 3, "MOONSHIELD", title_attr)
    add(screen, 2, 3, "Appliance de Segurança de Rede", curses.A_BOLD)
    add(screen, 4, 2, "-" * max(0, width - 4))
    add(screen, 6, 3, subtitle, curses.A_BOLD)
    return 8


def maintenance_identity() -> str:
    try:
        machine_id = Path("/etc/machine-id").read_bytes().strip()
    except OSError:
        machine_id = b"unavailable"
    return hashlib.sha256(machine_id).hexdigest()[:16]


def maintenance(screen) -> None:
    key = public_key()
    if key is None:
        start = header(screen, "Manutenção")
        add(screen, start, 3, "Modo de manutenção: NÃO PROVISIONADO")
        add(screen, start + 2, 3, "Chave pública de manutenção ausente.")
        add(screen, start + 4, 3, "Pressione qualquer tecla para voltar.")
        screen.refresh()
        screen.getch()
        return

    challenge = f"MOONSHIELD-MAINT-V1|{maintenance_identity()}|{secrets.token_hex(32)}"
    start = header(screen, "Manutenção protegida")
    height, width = screen.getmaxyx()
    add(screen, start, 3, f"Appliance: {maintenance_identity()}")
    add(screen, start + 2, 3, "Challenge:")
    lines = textwrap.wrap(challenge, max(20, width - 8))
    for offset, line in enumerate(lines):
        add(screen, start + 3 + offset, 3, line)
    row = start + 4 + len(lines)
    add(screen, row, 3, "Resposta Base64 (ou 'voltar'):")
    screen.refresh()
    curses.echo()
    try:
        response = screen.getstr(row + 1, 3, 8192).decode("ascii", "ignore").strip()
    finally:
        curses.noecho()
    if response.lower() in {"voltar", "esc", "q", "quit"}:
        return

    try:
        signature = base64.b64decode(response, validate=True)
        if not signature or len(signature) > 8192:
            raise ValueError("assinatura inválida")
        MAINTENANCE_DIR.mkdir(mode=0o750, parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="maintenance-", dir=MAINTENANCE_DIR) as temp_dir:
            os.chmod(temp_dir, 0o700)
            challenge_path = Path(temp_dir) / "challenge"
            signature_path = Path(temp_dir) / "signature"
            challenge_path.write_bytes(challenge.encode("utf-8"))
            signature_path.write_bytes(signature)
            os.chmod(challenge_path, 0o600)
            os.chmod(signature_path, 0o600)
            verify = subprocess.run(
                ["/usr/bin/openssl", "dgst", "-sha256", "-verify", str(key), "-signature", str(signature_path), str(challenge_path)],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        if verify.returncode != 0:
            raise ValueError("assinatura recusada")
    except (ValueError, OSError, subprocess.TimeoutExpired):
        add(screen, row + 3, 3, "ACESSO NEGADO", curses.A_BOLD)
        screen.refresh()
        time.sleep(2)
        return

    add(screen, row + 3, 3, "ACESSO AUTORIZADO", curses.A_BOLD)
    add(screen, row + 4, 3, "Ao encerrar o shell, esta tela será restaurada.")
    screen.refresh()
    time.sleep(1)
    curses.def_prog_mode()
    curses.endwin()
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/root",
        "TMOUT": "1800",
        "HISTFILE": "/dev/null",
        "TERM": os.environ.get("TERM", "linux"),
        "LANG": "C.UTF-8",
        "USER": "root",
        "LOGNAME": "root",
    }
    try:
        subprocess.run(["/bin/bash", "--noprofile", "--norc", "-i"], env=env, check=False)
    finally:
        curses.reset_prog_mode()
        screen.clear()
        screen.refresh()


def exec_final_console() -> None:
    python = Path("/opt/moonshield/venv/bin/python")
    console = Path("/opt/moonshield/console/moonshield_console.py")
    if python.is_file() and console.is_file():
        os.execv(str(python), [str(python), str(console)])


def draw_progress(screen, spin: str) -> None:
    data = state()
    phase = data.get("phase", "waiting")
    if SUCCESS_MARKER.exists() or phase == "success":
        start = header(screen, "Instalação concluída")
        add(screen, start, 3, "MoonShield foi instalada com sucesso.", curses.A_BOLD)
        add(screen, start + 2, 3, "Iniciando o console local...")
        screen.refresh()
        time.sleep(1)
        exec_final_console()
        return

    if FAILURE_MARKER.exists() or phase == "failed":
        start = header(screen, "FALHA NA INSTALAÇÃO")
        add(screen, start, 3, "O provisionamento da appliance não foi concluído com sucesso.", curses.A_BOLD)
        detail = str(data.get("detail", "")).strip()
        if detail:
            add(screen, start + 2, 3, detail)
        add(screen, start + 4, 3, "Log de diagnóstico:")
        add(screen, start + 5, 5, LOG_FILE)
        add(screen, start + 7, 3, "F12: acesso de manutenção protegido")
        add(screen, start + 9, 3, "A instalação não será repetida automaticamente.")
        return

    start = header(screen, "Preparando sua appliance...")
    message = str(data.get("message", "Preparando instalação..."))
    add(screen, start, 3, f"{spin}  {message}")
    add(screen, start + 2, 3, "Não desligue o equipamento.")

    steps = data.get("steps", {}) if isinstance(data.get("steps", {}), dict) else {}
    row = start + 5
    for key in ("base", "payload", "platform", "health", "console"):
        status = steps.get(key, "pending")
        marker = {"ok": "[ OK ]", "active": f"[ {spin}  ]", "error": "[ERRO]"}.get(status, "[    ]")
        attr = curses.A_BOLD if status in {"active", "error"} else 0
        add(screen, row, 5, f"{marker} {LABELS[key]}", attr)
        row += 1


def main(screen) -> None:
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    screen.keypad(True)
    screen.nodelay(True)
    if curses.has_colors():
        try:
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_MAGENTA, -1)
        except curses.error:
            pass

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
        time.sleep(0.25)


if __name__ == "__main__":
    if os.name != "posix":
        raise SystemExit("MoonShield Console Gate requer Linux.")
    MAINTENANCE_DIR.mkdir(mode=0o750, parents=True, exist_ok=True)
    curses.wrapper(main)
