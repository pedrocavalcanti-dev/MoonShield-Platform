#!/usr/bin/env python3
"""Provisiona a MoonShield Appliance no primeiro boot da ISO."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone


STAGE = Path("/var/lib/moonshield-iso-bootstrap")
STATE_DIR = STAGE / "state"
STATE_FILE = STATE_DIR / "status.json"
RELEASE = STAGE / "release"
BUNDLE = STAGE / "offline-bundle"
INSTALLER = RELEASE / "deploy/install.sh"
LOG_DIR = Path("/var/log/moonshield")
LOG_FILE = LOG_DIR / "firstboot-install.log"
PRODUCT_DIR = Path("/var/lib/moonshield")
SUCCESS_MARKER = PRODUCT_DIR / ".installation-complete"
FAILURE_MARKER = PRODUCT_DIR / ".installation-failed"
IN_PROGRESS_MARKER = PRODUCT_DIR / ".installation-in-progress"
FIRSTBOOT_UNIT = "moonshield-iso-firstboot.service"
GATE_UNIT = "moonshield-iso-console-gate.service"
CONSOLE_UNIT = "moonshield-console.service"


def atomic_write(path: Path, data: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    temp.write_text(data, encoding="utf-8")
    os.chmod(temp, mode)
    os.replace(temp, path)


def write_state(phase: str, message: str, steps: dict[str, str], detail: str = "") -> None:
    payload = {
        "phase": phase,
        "message": message,
        "steps": steps,
        "detail": detail,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    atomic_write(STATE_FILE, json.dumps(payload, ensure_ascii=False), 0o600)


def log_line(handle, message: str) -> None:
    stamp = datetime.now(timezone.utc).isoformat()
    handle.write(f"[{stamp}] {message}\n")
    handle.flush()


def run_logged(handle, args: list[str], label: str) -> int:
    log_line(handle, f"INÍCIO: {label}")
    env = os.environ.copy()
    env.update({"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"})
    try:
        process = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            env=env,
        )
    except OSError as exc:
        log_line(handle, f"FALHA ao iniciar {label}: {exc.__class__.__name__}")
        return 127
    assert process.stdout is not None
    for line in process.stdout:
        handle.write(line)
        handle.flush()
    rc = process.wait()
    log_line(handle, f"FIM: {label}; exit={rc}")
    return rc


def systemctl(handle, *args: str) -> int:
    return run_logged(handle, ["/bin/systemctl", *args], f"systemctl {' '.join(args)}")


def fail(handle, reason: str, steps: dict[str, str]) -> int:
    steps = dict(steps)
    for key, value in list(steps.items()):
        if value == "active":
            steps[key] = "error"
    PRODUCT_DIR.mkdir(parents=True, exist_ok=True)
    atomic_write(
        FAILURE_MARKER,
        f"status=failed\ntime={datetime.now(timezone.utc).isoformat()}\nreason={reason}\n",
        0o600,
    )
    SUCCESS_MARKER.unlink(missing_ok=True)
    IN_PROGRESS_MARKER.unlink(missing_ok=True)
    write_state("failed", "Falha no provisionamento da appliance.", steps, reason)
    log_line(handle, f"FALHA: {reason}")
    subprocess.run(["/bin/systemctl", "disable", FIRSTBOOT_UNIT], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["/bin/systemctl", "disable", "--now", CONSOLE_UNIT], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["/bin/systemctl", "enable", GATE_UNIT], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["/bin/systemctl", "start", GATE_UNIT], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return 1


def clean_bootstrap_payload(handle) -> None:
    for path in (RELEASE, BUNDLE):
        try:
            if path.is_symlink():
                log_line(handle, f"Payload não removido por segurança (symlink): {path}")
                continue
            if path.is_dir() and path.resolve().parent == STAGE.resolve():
                shutil.rmtree(path)
                log_line(handle, f"Payload temporário removido: {path}")
        except OSError as exc:
            log_line(handle, f"AVISO: não foi possível remover {path}: {exc.__class__.__name__}")


def main() -> int:
    if os.geteuid() != 0:
        return 1

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(LOG_DIR, 0o750)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    PRODUCT_DIR.mkdir(parents=True, exist_ok=True)

    if SUCCESS_MARKER.exists() or FAILURE_MARKER.exists():
        return 0

    steps = {
        "base": "ok",
        "payload": "pending",
        "platform": "pending",
        "health": "pending",
        "console": "pending",
    }

    if IN_PROGRESS_MARKER.exists():
        with LOG_FILE.open("a", encoding="utf-8", buffering=1) as interrupted_log:
            os.chmod(LOG_FILE, 0o600)
            return fail(interrupted_log, "A tentativa anterior foi interrompida antes da conclusão.", steps)

    atomic_write(
        IN_PROGRESS_MARKER,
        f"status=in-progress\ntime={datetime.now(timezone.utc).isoformat()}\n",
        0o600,
    )

    steps = {
        "base": "ok",
        "payload": "active",
        "platform": "pending",
        "health": "pending",
        "console": "pending",
    }
    write_state("validating", "Validando mídia e pacote de instalação...", steps)

    with LOG_FILE.open("a", encoding="utf-8", buffering=1) as log:
        os.chmod(LOG_FILE, 0o600)
        log_line(log, "MoonShield Alpha 2 — início do provisionamento de primeiro boot")

        if not INSTALLER.is_file():
            return fail(log, "Installer MoonShield não encontrado no payload.", steps)
        if not (BUNDLE / "SHA256SUMS").is_file():
            return fail(log, "Bundle offline sem SHA256SUMS.", steps)

        # sha256sum executa com cwd no bundle; sem shell para evitar expansão/injeção.
        log_line(log, "INÍCIO: validação do bundle offline")
        try:
            checked = subprocess.run(
                ["/usr/bin/sha256sum", "--check", "--status", "SHA256SUMS"],
                cwd=BUNDLE,
                check=False,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
            )
            rc = checked.returncode
        except OSError as exc:
            log_line(log, f"FALHA ao validar bundle: {exc.__class__.__name__}")
            rc = 127
        log_line(log, f"FIM: validação do bundle offline; exit={rc}")
        if rc != 0:
            return fail(log, "A validação de integridade do bundle offline falhou.", steps)

        steps["payload"] = "ok"
        steps["platform"] = "active"
        write_state("installing", "Instalando e configurando a plataforma MoonShield...", steps)

        rc = run_logged(
            log,
            ["/bin/bash", str(INSTALLER), "--offline", str(BUNDLE), "--final-iso"],
            "installer principal MoonShield",
        )
        if rc != 0:
            return fail(log, f"O installer principal terminou com código {rc}.", steps)

        steps["platform"] = "ok"
        steps["health"] = "active"
        write_state("healthcheck", "Validando serviços e segurança da appliance...", steps)

        healthcheck = Path("/usr/local/sbin/moonshield-install-check")
        if not healthcheck.is_file():
            return fail(log, "Healthcheck gerenciado não foi instalado.", steps)
        rc = run_logged(log, [str(healthcheck)], "healthcheck final MoonShield")
        if rc != 0:
            return fail(log, "O healthcheck final encontrou falha crítica.", steps)

        steps["health"] = "ok"
        steps["console"] = "active"
        write_state("console", "Iniciando o console local MoonShield...", steps)
        time.sleep(1.5)

        # A gate ocupa TTY1. Pare-a antes de iniciar o console final.
        subprocess.run(["/bin/systemctl", "stop", GATE_UNIT], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        rc = systemctl(log, "start", CONSOLE_UNIT)
        active = subprocess.run(["/bin/systemctl", "is-active", "--quiet", CONSOLE_UNIT], check=False).returncode == 0
        if rc != 0 or not active:
            # Reabra a gate para que o operador veja a falha em vez de uma tela vazia.
            steps["console"] = "error"
            subprocess.run(["/bin/systemctl", "start", GATE_UNIT], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return fail(log, "O console MoonShield não iniciou corretamente.", steps)

        steps["console"] = "ok"
        write_state("success", "Instalação concluída com sucesso.", steps)
        FAILURE_MARKER.unlink(missing_ok=True)
        IN_PROGRESS_MARKER.unlink(missing_ok=True)
        atomic_write(
            SUCCESS_MARKER,
            f"status=complete\ntime={datetime.now(timezone.utc).isoformat()}\nversion=0.1.0-alpha.2\n",
            0o644,
        )
        systemctl(log, "disable", FIRSTBOOT_UNIT)
        systemctl(log, "disable", GATE_UNIT)
        systemctl(log, "daemon-reload")
        clean_bootstrap_payload(log)
        log_line(log, "MoonShield Alpha 2 — provisionamento concluído")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
