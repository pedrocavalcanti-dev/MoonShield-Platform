"""Handler privilegiado mínimo para reconcile AdGuard após confirmação de Rede."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any


class ErroAdGuardIPC(RuntimeError):
    codigo = "adguard_reconcile_falhou"


def _bootstrap():
    raiz = Path(__file__).resolve().parents[3]
    django_dir = raiz / "MoonShield"
    if str(django_dir) not in sys.path:
        sys.path.insert(0, str(django_dir))
    from dns.services.adguard_bootstrap import provisionar_adguard

    return provisionar_adguard


def _controlar_servico(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(["systemctl", *args], capture_output=True, text=True, timeout=20, check=True)


def _servico_ativo(nome: str) -> bool:
    resultado = subprocess.run(
        ["systemctl", "is-active", "--quiet", nome],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    return resultado.returncode == 0


def executar_acao_adguard(acao: str, dados: dict[str, Any]) -> dict[str, Any]:
    if acao != "adguard.reconcile":
        raise ErroAdGuardIPC("Ação AdGuard não permitida.")
    topologia = dados.get("topologia")
    if not isinstance(topologia, dict):
        raise ErroAdGuardIPC("Topologia oficial ausente para reconcile do AdGuard.")
    return _bootstrap()(
        topologia=topologia,
        controlar_servico=_controlar_servico,
        servico_ativo=_servico_ativo,
    )
