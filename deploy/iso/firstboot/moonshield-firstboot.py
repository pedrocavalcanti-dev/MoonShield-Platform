#!/usr/bin/env python3
"""Provisiona a MoonShield Appliance no primeiro boot da ISO.

O firstboot e intencionalmente fail-closed: nunca libera um login Debian quando
uma etapa falha. Uma tentativa normal pode ser seguida por uma unica tentativa
de reparo idempotente. Depois disso, a console gate permanece no TTY1 e exige
F12 + challenge/response para manutencao.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
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
INSTALL_LOG = LOG_DIR / "install.log"
INSTALL_STAGE = Path("/var/lib/moonshield/install-stage")
PRODUCT_DIR = Path("/var/lib/moonshield")
SUCCESS_MARKER = PRODUCT_DIR / ".installation-complete"
FAILURE_MARKER = PRODUCT_DIR / ".installation-failed"
IN_PROGRESS_MARKER = PRODUCT_DIR / ".installation-in-progress"
FIRSTBOOT_UNIT = "moonshield-iso-firstboot.service"
GATE_UNIT = "moonshield-iso-console-gate.service"
CONSOLE_UNIT = "moonshield-console.service"
MAX_AUTOMATIC_ATTEMPTS = 2


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
        "updated_at": now(),
    }
    atomic_write(STATE_FILE, json.dumps(payload, ensure_ascii=False), 0o600)


def log_line(handle, message: str) -> None:
    handle.write(f"[{now()}] {message}\n")
    handle.flush()


def safe_text(value: str, limit: int = 900) -> str:
    value = re.sub(r"(?i)(postgres(?:ql)?://[^:\s]+:)[^@\s]+(@)", r"\1***\2", value)
    value = re.sub(r"(?i)(password|passwd|secret|token)=\S+", r"\1=***", value)
    value = " ".join(value.replace("\x00", "").split())
    return value[:limit]


def current_install_stage() -> str:
    try:
        return safe_text(INSTALL_STAGE.read_text(encoding="utf-8", errors="replace"), 140)
    except OSError:
        return ""


def install_error_excerpt() -> str:
    candidates: list[str] = []
    try:
        lines = INSTALL_LOG.read_text(encoding="utf-8", errors="replace").splitlines()[-180:]
    except OSError:
        lines = []
    keywords = ("[ERROR]", "falhou", "ausente", "incompat", "recus", "erro", "failed")
    for line in lines:
        lowered = line.casefold()
        if any(word.casefold() in lowered for word in keywords):
            candidates.append(safe_text(line, 280))
    if not candidates and lines:
        candidates = [safe_text(line, 280) for line in lines[-3:]]
    excerpt = " | ".join(candidates[-3:])
    stage = current_install_stage()
    if stage:
        excerpt = f"Etapa: {stage}. {excerpt}" if excerpt else f"Etapa: {stage}."
    return safe_text(excerpt, 820)


def run_logged(handle, args: list[str], label: str, *, env_extra: dict[str, str] | None = None) -> int:
    log_line(handle, f"INICIO: {label}")
    env = os.environ.copy()
    env.update({
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "DEBIAN_FRONTEND": "noninteractive",
    })
    if env_extra:
        env.update(env_extra)
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
        log_line(handle, f"FALHA ao iniciar {label}: {exc.__class__.__name__}: {safe_text(str(exc), 180)}")
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


def read_attempt_count() -> int:
    try:
        content = IN_PROGRESS_MARKER.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0
    match = re.search(r"^attempts=(\d+)$", content, flags=re.MULTILINE)
    return int(match.group(1)) if match else 1


def mark_attempt(attempt: int) -> None:
    atomic_write(
        IN_PROGRESS_MARKER,
        f"status=in-progress\ntime={now()}\nattempts={attempt}\n",
        0o600,
    )


def keep_gate_available() -> None:
    subprocess.run(["/bin/systemctl", "disable", FIRSTBOOT_UNIT], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["/bin/systemctl", "disable", "--now", CONSOLE_UNIT], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["/bin/systemctl", "enable", GATE_UNIT], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["/bin/systemctl", "restart", GATE_UNIT], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def fail(handle, reason: str, steps: dict[str, str], detail: str = "") -> int:
    steps = dict(steps)
    for key, value in list(steps.items()):
        if value == "active":
            steps[key] = "error"
    detail = safe_text(detail or reason, 900)
    PRODUCT_DIR.mkdir(parents=True, exist_ok=True)
    atomic_write(
        FAILURE_MARKER,
        f"status=failed\ntime={now()}\nreason={safe_text(reason, 400)}\ndetail={detail}\n",
        0o600,
    )
    SUCCESS_MARKER.unlink(missing_ok=True)
    IN_PROGRESS_MARKER.unlink(missing_ok=True)
    write_state("failed", "Falha no provisionamento da appliance.", steps, detail)
    log_line(handle, f"FALHA: {reason}")
    if detail and detail != reason:
        log_line(handle, f"DIAGNOSTICO: {detail}")
    keep_gate_available()
    return 1


def clean_bootstrap_payload(handle) -> None:
    for path in (RELEASE, BUNDLE):
        try:
            if path.is_symlink():
                log_line(handle, f"Payload nao removido por seguranca (symlink): {path}")
                continue
            if path.is_dir() and path.resolve().parent == STAGE.resolve():
                shutil.rmtree(path)
                log_line(handle, f"Payload temporario removido: {path}")
        except OSError as exc:
            log_line(handle, f"AVISO: nao foi possivel remover {path}: {exc.__class__.__name__}")


def recovery_prep(handle) -> None:
    """Reconcilia estado de pacotes sem depender de rede antes do retry."""
    write_state(
        "repairing",
        "Reconciliando pacotes e repetindo o provisionamento...",
        {"base": "ok", "payload": "ok", "platform": "active", "health": "pending", "console": "pending"},
        "Uma tentativa automatica de reparo esta em andamento.",
    )
    run_logged(handle, ["/bin/systemctl", "daemon-reload"], "systemd daemon-reload pre-retry")
    if Path("/usr/bin/dpkg").is_file():
        run_logged(handle, ["/usr/bin/dpkg", "--configure", "-a"], "dpkg --configure -a")
    if Path("/usr/bin/apt-get").is_file():
        # Sem fallback de rede: apenas reconcilia o que ja esta instalado/cacheado.
        run_logged(
            handle,
            ["/usr/bin/apt-get", "--no-download", "--yes", "--fix-broken", "install"],
            "apt-get --no-download --fix-broken install",
        )


def installer_args(repair: bool) -> list[str]:
    args = ["/bin/bash", str(INSTALLER), "--offline", str(BUNDLE), "--final-iso"]
    if repair:
        args.append("--repair")
    return args


def main() -> int:
    if os.geteuid() != 0:
        return 1

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(LOG_DIR, 0o750)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    PRODUCT_DIR.mkdir(parents=True, exist_ok=True)

    if SUCCESS_MARKER.exists():
        return 0
    if FAILURE_MARKER.exists():
        keep_gate_available()
        return 0

    previous_attempts = read_attempt_count()
    if previous_attempts >= MAX_AUTOMATIC_ATTEMPTS:
        with LOG_FILE.open("a", encoding="utf-8", buffering=1) as interrupted_log:
            os.chmod(LOG_FILE, 0o600)
            return fail(
                interrupted_log,
                "O provisionamento foi interrompido repetidamente.",
                {"base": "ok", "payload": "ok", "platform": "error", "health": "pending", "console": "pending"},
                "Limite de tentativas automaticas atingido. Use F12 para manutencao protegida.",
            )

    attempt = previous_attempts + 1
    mark_attempt(attempt)

    steps = {
        "base": "ok",
        "payload": "active",
        "platform": "pending",
        "health": "pending",
        "console": "pending",
    }
    write_state("validating", "Validando pacote offline e preparando a instalacao...", steps)

    with LOG_FILE.open("a", encoding="utf-8", buffering=1) as log:
        os.chmod(LOG_FILE, 0o600)
        log_line(log, f"MoonShield Alpha 2 - firstboot iniciado (tentativa {attempt}/{MAX_AUTOMATIC_ATTEMPTS})")

        if not INSTALLER.is_file():
            return fail(log, "Installer MoonShield nao encontrado no payload.", steps)
        if not (BUNDLE / "SHA256SUMS").is_file():
            return fail(log, "Bundle offline sem SHA256SUMS.", steps)
        if not (BUNDLE / "BUILD-INFO").is_file():
            return fail(log, "Bundle offline sem BUILD-INFO.", steps)
        try:
            bundle_info = (BUNDLE / "BUILD-INFO").read_text(encoding="utf-8", errors="replace")
        except OSError:
            bundle_info = ""
        if "BundleFormat=2" not in bundle_info or "DependencyClosure=full" not in bundle_info:
            return fail(
                log,
                "Bundle offline antigo/incompleto.",
                steps,
                "Regenere o bundle com prepare-offline-bundle.sh desta release antes de gerar a ISO.",
            )

        log_line(log, "INICIO: validacao do bundle offline")
        try:
            checked = subprocess.run(
                ["/usr/bin/sha256sum", "--check", "SHA256SUMS"],
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
        log_line(log, f"FIM: validacao do bundle offline; exit={rc}")
        if rc != 0:
            return fail(log, "A validacao de integridade do bundle offline falhou.", steps)

        steps["payload"] = "ok"
        steps["platform"] = "active"
        write_state("installing", "Instalando e configurando a plataforma MoonShield...", steps)

        repair_first = previous_attempts > 0
        rc = run_logged(
            log,
            installer_args(repair_first),
            "installer principal MoonShield" + (" (resume/repair)" if repair_first else ""),
            env_extra={"MOONSHIELD_FIRSTBOOT": "1"},
        )

        if rc != 0 and not repair_first:
            excerpt = install_error_excerpt()
            log_line(log, f"Primeira tentativa falhou. Diagnostico resumido: {excerpt or 'indisponivel'}")
            recovery_prep(log)
            mark_attempt(2)
            rc = run_logged(
                log,
                installer_args(True),
                "installer MoonShield - tentativa automatica de reparo",
                env_extra={"MOONSHIELD_FIRSTBOOT": "1"},
            )

        if rc != 0:
            excerpt = install_error_excerpt()
            return fail(
                log,
                f"O installer principal terminou com codigo {rc}.",
                steps,
                excerpt or f"Installer terminou com codigo {rc}; consulte {INSTALL_LOG}.",
            )

        steps["platform"] = "ok"
        steps["health"] = "active"
        write_state("healthcheck", "Validando servicos e seguranca da appliance...", steps)

        healthcheck = Path("/usr/local/sbin/moonshield-install-check")
        if not healthcheck.is_file():
            return fail(log, "Healthcheck gerenciado nao foi instalado.", steps)
        rc = run_logged(log, [str(healthcheck)], "healthcheck final MoonShield")
        if rc != 0:
            return fail(log, "O healthcheck final encontrou falha critica.", steps, install_error_excerpt())
        if current_install_stage().strip() != "complete":
            return fail(
                log,
                "Installer retornou sucesso sem finalizar install-stage.",
                steps,
                f"install-stage atual: {current_install_stage() or 'ausente'}",
            )

        steps["health"] = "ok"
        steps["console"] = "active"
        write_state("console", "Preparando transicao para o console MoonShield...", steps)
        time.sleep(0.5)

        # Nao iniciamos moonshield-console.service enquanto a gate ocupa o TTY1:
        # as duas units sao propositalmente conflitantes. Em vez disso, garantimos
        # que o console final esteja habilitado para os proximos boots e marcamos
        # sucesso. A gate observa SUCCESS_MARKER e faz exec() direto para o console,
        # evitando corrida de systemd e tela preta entre os processos.
        rc = systemctl(log, "enable", CONSOLE_UNIT)
        console_python = Path("/opt/moonshield/venv/bin/python")
        console_script = Path("/opt/moonshield/console/moonshield_console.py")
        console_unit = Path("/etc/systemd/system") / CONSOLE_UNIT
        if rc != 0 or not console_python.is_file() or not console_script.is_file() or not console_unit.exists():
            steps["console"] = "error"
            keep_gate_available()
            return fail(log, "O console MoonShield nao foi preparado corretamente.", steps)

        steps["console"] = "ok"
        write_state("success", "Instalacao concluida. Iniciando console protegido...", steps)
        FAILURE_MARKER.unlink(missing_ok=True)
        IN_PROGRESS_MARKER.unlink(missing_ok=True)
        atomic_write(
            SUCCESS_MARKER,
            f"status=complete\ntime={now()}\ninstall_stage=complete\nhealthcheck=pass\nversion=0.1.0-alpha.2\n",
            0o600,
        )
        # disable sem --now: a gate atual permanece viva tempo suficiente para
        # renderizar a tela de sucesso e executar o console final no mesmo TTY.
        systemctl(log, "disable", FIRSTBOOT_UNIT)
        systemctl(log, "disable", GATE_UNIT)
        systemctl(log, "daemon-reload")
        clean_bootstrap_payload(log)
        log_line(log, "MoonShield Alpha 2 - provisionamento concluido; gate fara handoff do TTY1")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
