"""
MoonShield Agent — Suricata / Aplicador
=======================================

Aplicador operacional do Suricata em modo IDS passivo.

Fluxo:
1. recebe topologia/config do Control Plane;
2. valida interfaces no host;
3. gera candidato a partir do suricata.yaml atual;
4. valida candidato com `suricata -T`;
5. cria backup;
6. substitui o YAML;
7. garante override systemd AF_PACKET;
8. reinicia o serviço;
9. se falhar, restaura YAML + override anteriores.

Não instala pacotes e não decide WAN/LAN/HOME_NET.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from suricata.configuracao import (
    BACKUP_DIR,
    normalizar_config,
    renderizar_yaml,
    validar_config_host,
)

VERSAO_APLICADOR = "1.0"
TIMEOUT_TESTE = 120
TIMEOUT_SYSTEMD = 30

OVERRIDE_PATH = Path("/etc/systemd/system/suricata.service.d/override.conf")


def validar(dados: dict[str, Any]) -> dict[str, Any]:
    try:
        cfg = normalizar_config((dados or {}).get("config") or dados)
    except Exception as exc:
        return {"ok": False, "codigo": "config_invalida", "erro": str(exc)}

    host = validar_config_host(cfg)
    if not host["ok"]:
        return {
            "ok": False,
            "codigo": "topologia_invalida",
            "erro": "Configuração de captura inválida.",
            "detalhes": host,
        }

    yaml_path = Path(cfg.yaml_path)
    if not yaml_path.exists():
        return {
            "ok": False,
            "codigo": "yaml_inexistente",
            "erro": f"suricata.yaml não encontrado: {yaml_path}",
        }

    try:
        base = yaml_path.read_text(encoding="utf-8")
        candidato = renderizar_yaml(base, cfg)
    except Exception as exc:
        return {
            "ok": False,
            "codigo": "geracao_config_falhou",
            "erro": str(exc),
        }

    return _validar_candidato(candidato, cfg.yaml_path, cfg.para_dict())


def aplicar(dados: dict[str, Any]) -> dict[str, Any]:
    inicio = time.monotonic()

    try:
        cfg = normalizar_config((dados or {}).get("config") or dados)
    except Exception as exc:
        return _falha("config_invalida", str(exc), inicio)

    host = validar_config_host(cfg)
    if not host["ok"]:
        return _falha(
            "topologia_invalida",
            "Configuração de captura inválida.",
            inicio,
            detalhes=host,
        )

    yaml_path = Path(cfg.yaml_path)
    if not yaml_path.exists():
        return _falha(
            "yaml_inexistente",
            f"suricata.yaml não encontrado: {yaml_path}",
            inicio,
        )

    try:
        base = yaml_path.read_text(encoding="utf-8")
        candidato = renderizar_yaml(base, cfg)
    except Exception as exc:
        return _falha("geracao_config_falhou", str(exc), inicio)

    teste = _validar_candidato(candidato, cfg.yaml_path, cfg.para_dict())
    if not teste.get("ok"):
        teste["duracao_segundos"] = round(time.monotonic() - inicio, 3)
        return teste

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(BACKUP_DIR, 0o750)
    except PermissionError:
        pass

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup_yaml = BACKUP_DIR / f"suricata-{stamp}.yaml"
    backup_override = BACKUP_DIR / f"override-{stamp}.conf"
    meta_path = BACKUP_DIR / f"suricata-{stamp}.json"

    shutil.copy2(yaml_path, backup_yaml)
    override_existia = OVERRIDE_PATH.exists()
    if override_existia:
        shutil.copy2(OVERRIDE_PATH, backup_override)

    try:
        _escrever_atomico(yaml_path, candidato)
        _escrever_override(Path(cfg.yaml_path))
        _daemon_reload()

        reinicio = _restart_e_aguardar()
        if not reinicio["ok"]:
            rb = _restaurar(
                yaml_path=yaml_path,
                backup_yaml=backup_yaml,
                backup_override=backup_override,
                override_existia=override_existia,
            )
            return _falha(
                "restart_falhou",
                reinicio.get("erro") or "Suricata não ficou ativo.",
                inicio,
                detalhes={"restart": reinicio, "rollback": rb},
            )

        meta = {
            "id": stamp,
            "criado_em": datetime.now(timezone.utc).isoformat(),
            "yaml": str(yaml_path),
            "backup_yaml": str(backup_yaml),
            "backup_override": str(backup_override) if override_existia else "",
            "config": cfg.para_dict(),
            "versao_aplicador": VERSAO_APLICADOR,
        }
        meta_path.write_text(
            json.dumps(meta, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        return {
            "ok": True,
            "status": "aplicado",
            "modo": "ids_passivo",
            "backup_id": stamp,
            "mensagem": "Configuração operacional do Suricata aplicada.",
            "config": cfg.para_dict(),
            "validacao": teste,
            "restart": reinicio,
            "duracao_segundos": round(time.monotonic() - inicio, 3),
        }

    except Exception as exc:
        rb = _restaurar(
            yaml_path=yaml_path,
            backup_yaml=backup_yaml,
            backup_override=backup_override,
            override_existia=override_existia,
        )
        return _falha(
            "apply_falhou",
            str(exc),
            inicio,
            detalhes={"rollback": rb},
        )


def _validar_candidato(
    conteudo: str,
    yaml_original: str,
    config: dict[str, Any],
) -> dict[str, Any]:
    suricata = shutil.which("suricata")
    if not suricata:
        return {
            "ok": False,
            "codigo": "suricata_indisponivel",
            "erro": "Binário suricata não encontrado.",
        }

    original = Path(yaml_original)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        prefix=".moonshield-suricata-",
        suffix=".yaml",
        dir=str(original.parent),
        delete=False,
    ) as fp:
        fp.write(conteudo)
        candidato = Path(fp.name)

    try:
        r = subprocess.run(
            [suricata, "-T", "-c", str(candidato)],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_TESTE,
            check=False,
        )
        saida = ((r.stdout or "") + "\n" + (r.stderr or "")).strip()
        return {
            "ok": r.returncode == 0,
            "codigo": "" if r.returncode == 0 else "suricata_t_falhou",
            "erro": "" if r.returncode == 0 else _resumir_erro(saida),
            "returncode": r.returncode,
            "config": config,
            "saida_resumo": _ultimas_linhas(saida, 20),
        }
    finally:
        candidato.unlink(missing_ok=True)


def _escrever_atomico(path: Path, conteudo: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=str(path.parent),
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as fp:
        fp.write(conteudo)
        fp.flush()
        os.fsync(fp.fileno())
        tmp = Path(fp.name)

    os.chmod(tmp, path.stat().st_mode & 0o777)
    os.replace(tmp, path)


def _escrever_override(yaml_path: Path) -> None:
    OVERRIDE_PATH.parent.mkdir(parents=True, exist_ok=True)
    conteudo = (
        "[Service]\n"
        "ExecStart=\n"
        f"ExecStart=/usr/bin/suricata -D --af-packet -c {yaml_path} "
        "--pidfile /run/suricata.pid\n"
    )
    OVERRIDE_PATH.write_text(conteudo, encoding="utf-8")


def _daemon_reload() -> None:
    systemctl = shutil.which("systemctl")
    if not systemctl:
        raise RuntimeError("systemctl não encontrado.")
    r = subprocess.run(
        [systemctl, "daemon-reload"],
        capture_output=True,
        text=True,
        timeout=TIMEOUT_SYSTEMD,
        check=False,
    )
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout or "daemon-reload falhou").strip())


def _restart_e_aguardar() -> dict[str, Any]:
    systemctl = shutil.which("systemctl")
    if not systemctl:
        return {"ok": False, "erro": "systemctl não encontrado."}

    r = subprocess.run(
        [systemctl, "restart", "suricata"],
        capture_output=True,
        text=True,
        timeout=TIMEOUT_SYSTEMD,
        check=False,
    )
    if r.returncode != 0:
        return {
            "ok": False,
            "erro": (r.stderr or r.stdout or "restart falhou").strip(),
        }

    for _ in range(30):
        chk = subprocess.run(
            [systemctl, "is-active", "suricata"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        estado = (chk.stdout or "").strip()
        if chk.returncode == 0 and estado == "active":
            return {"ok": True, "estado": estado}
        if estado == "failed":
            return {"ok": False, "estado": estado, "erro": "serviço entrou em failed"}
        time.sleep(1)

    return {"ok": False, "estado": "timeout", "erro": "Suricata não estabilizou em 30s."}


def _restaurar(
    *,
    yaml_path: Path,
    backup_yaml: Path,
    backup_override: Path,
    override_existia: bool,
) -> dict[str, Any]:
    erros: list[str] = []
    try:
        shutil.copy2(backup_yaml, yaml_path)
    except Exception as exc:
        erros.append(f"yaml: {exc}")

    try:
        if override_existia:
            shutil.copy2(backup_override, OVERRIDE_PATH)
        else:
            OVERRIDE_PATH.unlink(missing_ok=True)
    except Exception as exc:
        erros.append(f"override: {exc}")

    try:
        _daemon_reload()
    except Exception as exc:
        erros.append(f"daemon_reload: {exc}")

    try:
        res = _restart_e_aguardar()
        if not res.get("ok"):
            erros.append(f"restart: {res.get('erro') or res}")
    except Exception as exc:
        erros.append(f"restart: {exc}")

    return {"ok": not erros, "erros": erros}


def _resumir_erro(saida: str) -> str:
    linhas = [
        l.strip()
        for l in saida.splitlines()
        if "error" in l.lower() or "fatal" in l.lower() or l.strip().startswith("E:")
    ]
    return linhas[0][:500] if linhas else (saida[-500:] if saida else "suricata -T falhou")


def _ultimas_linhas(saida: str, n: int) -> list[str]:
    return [x for x in saida.splitlines() if x.strip()][-n:]


def _falha(
    codigo: str,
    erro: str,
    inicio: float,
    *,
    detalhes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "ok": False,
        "status": "erro",
        "codigo": codigo,
        "erro": str(erro),
        "detalhes": detalhes or {},
        "duracao_segundos": round(time.monotonic() - inicio, 3),
    }
