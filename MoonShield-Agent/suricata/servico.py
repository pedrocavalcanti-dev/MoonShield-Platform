"""
MoonShield Agent — Suricata / Controle de Serviço
=================================================

Camada responsável exclusivamente pelo controle do serviço systemd
do Suricata.

Responsabilidades:
- consultar estado do serviço;
- iniciar;
- parar;
- reiniciar;
- confirmar o estado observado após uma operação.

Este módulo NÃO:
- decide WAN/LAN/MGMT;
- calcula HOME_NET;
- altera suricata.yaml;
- altera regras;
- executa shell arbitrário.

Toda chamada a systemctl utiliza argumentos fixos via subprocess,
sem shell=True.
"""

from __future__ import annotations

import subprocess
import time
from datetime import datetime, timezone
from typing import Any


VERSAO_SERVICO = "1.0"

SERVICO_SURICATA = "suricata"

TIMEOUT_SYSTEMCTL = 90
TIMEOUT_ESTADO = 30
INTERVALO_ESTADO = 0.5


class ErroServicoSuricata(RuntimeError):
    """Erro controlado durante operação do serviço Suricata."""

    def __init__(
        self,
        mensagem: str,
        *,
        codigo: str = "erro_servico_suricata",
        detalhes: dict[str, Any] | None = None,
    ):
        super().__init__(mensagem)
        self.codigo = codigo
        self.detalhes = detalhes or {}


def _agora_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _executar(
    argumentos: list[str],
    *,
    timeout: int = TIMEOUT_SYSTEMCTL,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argumentos,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ErroServicoSuricata(
            "A operação systemd excedeu o tempo limite.",
            codigo="suricata_systemctl_timeout",
            detalhes={
                "comando": argumentos,
                "timeout_segundos": timeout,
            },
        ) from exc
    except FileNotFoundError as exc:
        raise ErroServicoSuricata(
            "systemctl não está disponível neste sistema.",
            codigo="systemctl_indisponivel",
        ) from exc
    except OSError as exc:
        raise ErroServicoSuricata(
            f"Falha ao executar systemctl: {exc}",
            codigo="suricata_systemctl_falhou",
            detalhes={"tipo": type(exc).__name__},
        ) from exc


def _parse_int(valor: Any, padrao: int = 0) -> int:
    try:
        return int(str(valor).strip())
    except (TypeError, ValueError):
        return padrao


def _ler_show() -> dict[str, str]:
    propriedades = [
        "LoadState",
        "ActiveState",
        "SubState",
        "UnitFileState",
        "MainPID",
        "ExecMainStatus",
        "NRestarts",
    ]

    comando = [
        "systemctl",
        "show",
        SERVICO_SURICATA,
    ]

    for propriedade in propriedades:
        comando.extend(["-p", propriedade])

    resultado = _executar(comando, timeout=15)

    observado: dict[str, str] = {}

    for linha in (resultado.stdout or "").splitlines():
        if "=" not in linha:
            continue

        chave, valor = linha.split("=", 1)
        observado[chave.strip()] = valor.strip()

    return observado


def obter_status(
    dados: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Retorna estado puro do serviço systemd do Suricata.

    O parâmetro dados é aceito para manter compatibilidade com
    o contrato IPC, mas não é usado para escolher serviço.
    """

    _ = dados

    observado = _ler_show()

    load_state = observado.get("LoadState", "unknown")
    active_state = observado.get("ActiveState", "unknown")
    sub_state = observado.get("SubState", "unknown")
    unit_file_state = observado.get("UnitFileState", "unknown")

    disponivel = load_state not in {
        "",
        "not-found",
        "masked",
    }

    ativo = active_state == "active"

    return {
        "ok": True,
        "versao_servico": VERSAO_SERVICO,
        "servico": SERVICO_SURICATA,
        "disponivel": disponivel,
        "load_state": load_state,
        "active": ativo,
        "estado": active_state,
        "subestado": sub_state,
        "habilitado": unit_file_state in {
            "enabled",
            "enabled-runtime",
            "static",
        },
        "unit_file_state": unit_file_state,
        "main_pid": _parse_int(observado.get("MainPID")),
        "exec_main_status": _parse_int(
            observado.get("ExecMainStatus")
        ),
        "n_restarts": _parse_int(
            observado.get("NRestarts")
        ),
        "atualizado_em": _agora_iso(),
    }


def _aguardar_estado(
    estado_esperado: str,
    *,
    timeout: int = TIMEOUT_ESTADO,
) -> dict[str, Any]:
    inicio = time.monotonic()
    ultimo_status: dict[str, Any] = {}

    while time.monotonic() - inicio < timeout:
        ultimo_status = obter_status()

        if ultimo_status.get("estado") == estado_esperado:
            return ultimo_status

        time.sleep(INTERVALO_ESTADO)

    return ultimo_status or obter_status()


def _operar(
    operacao: str,
    *,
    estado_esperado: str,
) -> dict[str, Any]:
    if operacao not in {
        "start",
        "stop",
        "restart",
    }:
        raise ErroServicoSuricata(
            "Operação de serviço não permitida.",
            codigo="suricata_operacao_servico_invalida",
            detalhes={"operacao": operacao},
        )

    antes = obter_status()

    if not antes.get("disponivel"):
        raise ErroServicoSuricata(
            "O serviço Suricata não está disponível.",
            codigo="suricata_servico_indisponivel",
            detalhes={"status": antes},
        )

    inicio = time.monotonic()

    resultado = _executar(
        [
            "systemctl",
            operacao,
            SERVICO_SURICATA,
        ]
    )

    depois = _aguardar_estado(
        estado_esperado,
        timeout=TIMEOUT_ESTADO,
    )

    duracao = round(
        time.monotonic() - inicio,
        3,
    )

    estado_ok = depois.get("estado") == estado_esperado

    #
    # Há situações em que ExecStop da unit pode retornar não-zero
    # mas o serviço efetivamente terminar em estado inactive.
    #
    # O estado observado final é a fonte de verdade.
    #
    if not estado_ok:
        raise ErroServicoSuricata(
            (
                f"Suricata não atingiu o estado "
                f"esperado '{estado_esperado}'."
            ),
            codigo="suricata_estado_inesperado",
            detalhes={
                "operacao": operacao,
                "returncode": resultado.returncode,
                "stdout": (resultado.stdout or "").strip()[-4096:],
                "stderr": (resultado.stderr or "").strip()[-4096:],
                "antes": antes,
                "depois": depois,
            },
        )

    resposta: dict[str, Any] = {
        "ok": True,
        "servico": SERVICO_SURICATA,
        "operacao": operacao,
        "estado_esperado": estado_esperado,
        "estado": depois.get("estado"),
        "subestado": depois.get("subestado"),
        "main_pid": depois.get("main_pid"),
        "n_restarts": depois.get("n_restarts"),
        "returncode_systemctl": resultado.returncode,
        "duracao_segundos": duracao,
        "status": depois,
        "atualizado_em": _agora_iso(),
    }

    if resultado.returncode != 0:
        resposta["aviso"] = (
            "systemctl retornou código diferente de zero, "
            "mas o estado final observado foi atingido."
        )
        resposta["stderr"] = (
            resultado.stderr or ""
        ).strip()[-4096:]

    return resposta


def iniciar(
    dados: dict[str, Any] | None = None,
) -> dict[str, Any]:
    _ = dados

    status_atual = obter_status()

    if status_atual.get("estado") == "active":
        return {
            "ok": True,
            "servico": SERVICO_SURICATA,
            "operacao": "start",
            "status": "ja_ativo",
            "estado": "active",
            "main_pid": status_atual.get("main_pid"),
            "n_restarts": status_atual.get("n_restarts"),
            "atualizado_em": _agora_iso(),
        }

    return _operar(
        "start",
        estado_esperado="active",
    )


def parar(
    dados: dict[str, Any] | None = None,
) -> dict[str, Any]:
    _ = dados

    status_atual = obter_status()

    if status_atual.get("estado") == "inactive":
        return {
            "ok": True,
            "servico": SERVICO_SURICATA,
            "operacao": "stop",
            "status": "ja_inativo",
            "estado": "inactive",
            "main_pid": 0,
            "n_restarts": status_atual.get("n_restarts"),
            "atualizado_em": _agora_iso(),
        }

    return _operar(
        "stop",
        estado_esperado="inactive",
    )


def reiniciar(
    dados: dict[str, Any] | None = None,
) -> dict[str, Any]:
    _ = dados

    return _operar(
        "restart",
        estado_esperado="active",
    )


# Compatibilidade / nomes explícitos.

status = obter_status
start = iniciar
stop = parar
restart = reiniciar


__all__ = [
    "VERSAO_SERVICO",
    "SERVICO_SURICATA",
    "ErroServicoSuricata",
    "obter_status",
    "iniciar",
    "parar",
    "reiniciar",
    "status",
    "start",
    "stop",
    "restart",
]