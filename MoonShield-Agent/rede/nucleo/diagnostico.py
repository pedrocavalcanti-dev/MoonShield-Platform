"""
MoonShield Agent — Rede / Diagnóstico
=====================================

Diagnóstico somente leitura do módulo de Rede.

Verifica:
- sistema operacional;
- privilégios;
- NetworkManager;
- nmcli;
- iproute2;
- nftables;
- interfaces;
- rota default;
- IPv4 forwarding;
- NAT MoonShield.

Nenhuma configuração é alterada.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .configuracao import comando_existe, eh_linux, eh_root, obter_backend, obter_info_ambiente
from .nat import obter_status_nat
from .roteamento import obter_status_roteamento


def _agora_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _check(
    codigo: str,
    nome: str,
    *,
    status: str,
    mensagem: str,
    detalhes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "codigo": codigo,
        "nome": nome,
        "status": status,
        "ok": status == "ok",
        "mensagem": mensagem,
        "detalhes": detalhes or {},
    }


def _contar(checks: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "total": len(checks),
        "sucesso": sum(1 for item in checks if item["status"] == "ok"),
        "avisos": sum(1 for item in checks if item["status"] == "warning"),
        "erros": sum(1 for item in checks if item["status"] == "error"),
    }


def executar_diagnostico(
    opcoes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    opcoes = opcoes or {}
    checks: list[dict[str, Any]] = []
    ambiente = obter_info_ambiente()

    # -------------------------------------------------------------------------
    # Linux
    # -------------------------------------------------------------------------

    checks.append(
        _check(
            "sistema_linux",
            "Sistema operacional",
            status="ok" if eh_linux() else "error",
            mensagem=(
                "Sistema Linux detectado."
                if eh_linux()
                else "O MoonShield Agent de Rede requer Linux."
            ),
            detalhes={
                "sistema": ambiente.get("sistema"),
                "release": ambiente.get("release"),
                "arquitetura": ambiente.get("arquitetura"),
            },
        )
    )

    # -------------------------------------------------------------------------
    # Root
    # -------------------------------------------------------------------------

    checks.append(
        _check(
            "privilegios_root",
            "Privilégios do Agent",
            status="ok" if eh_root() else "warning",
            mensagem=(
                "Agent executando com privilégios administrativos."
                if eh_root()
                else "Processo atual não está executando como root."
            ),
        )
    )

    # -------------------------------------------------------------------------
    # Binários
    # -------------------------------------------------------------------------

    for codigo, nome, binario in (
        ("nmcli", "NetworkManager CLI", "nmcli"),
        ("iproute2", "iproute2", "ip"),
        ("nftables", "nftables", "nft"),
    ):
        existe = comando_existe(binario)

        checks.append(
            _check(
                codigo,
                nome,
                status="ok" if existe else "error",
                mensagem=(
                    f"Comando '{binario}' disponível."
                    if existe
                    else f"Comando '{binario}' não encontrado."
                ),
            )
        )

    # -------------------------------------------------------------------------
    # Backend
    # -------------------------------------------------------------------------

    backend = None

    try:
        backend = obter_backend()
        status_backend = backend.status()
        disponivel = bool(
            status_backend.get("disponivel")
        )

        checks.append(
            _check(
                "backend_rede",
                "Backend de Rede",
                status="ok" if disponivel else "error",
                mensagem=(
                    f"Backend {backend.nome} disponível."
                    if disponivel
                    else f"Backend {backend.nome} indisponível."
                ),
                detalhes=status_backend,
            )
        )

    except Exception as exc:
        checks.append(
            _check(
                "backend_rede",
                "Backend de Rede",
                status="error",
                mensagem=str(exc),
            )
        )

    # -------------------------------------------------------------------------
    # Interfaces
    # -------------------------------------------------------------------------

    if backend is not None:
        try:
            interfaces = backend.listar_interfaces(
                incluir_loopback=False
            )

            up = [
                item
                for item in interfaces
                if item.get("estado_link") == "up"
            ]

            checks.append(
                _check(
                    "interfaces",
                    "Interfaces de Rede",
                    status="ok" if interfaces else "error",
                    mensagem=(
                        f"{len(interfaces)} interface(s) detectada(s), "
                        f"{len(up)} com link ativo."
                    ),
                    detalhes={
                        "total": len(interfaces),
                        "up": len(up),
                        "interfaces": [
                            {
                                "nome": item.get("nome"),
                                "estado_link": item.get("estado_link"),
                                "ipv4": item.get("ipv4_atual"),
                            }
                            for item in interfaces
                        ],
                    },
                )
            )

        except Exception as exc:
            checks.append(
                _check(
                    "interfaces",
                    "Interfaces de Rede",
                    status="error",
                    mensagem=str(exc),
                )
            )

    # -------------------------------------------------------------------------
    # Roteamento
    # -------------------------------------------------------------------------

    try:
        roteamento = obter_status_roteamento()
        rota_default = roteamento.get(
            "rota_default"
        )

        checks.append(
            _check(
                "rota_default",
                "Rota padrão IPv4",
                status="ok" if rota_default else "warning",
                mensagem=(
                    "Rota padrão IPv4 encontrada."
                    if rota_default
                    else "Nenhuma rota padrão IPv4 encontrada."
                ),
                detalhes={
                    "rota_default": rota_default,
                    "total_rotas": roteamento.get(
                        "total_rotas",
                        0,
                    ),
                },
            )
        )

        forward = bool(
            roteamento.get(
                "ipv4_forward"
            )
        )

        checks.append(
            _check(
                "ipv4_forward",
                "IPv4 Forwarding",
                status="ok" if forward else "warning",
                mensagem=(
                    "Encaminhamento IPv4 está ativo."
                    if forward
                    else "Encaminhamento IPv4 está desativado."
                ),
            )
        )

    except Exception as exc:
        checks.append(
            _check(
                "roteamento",
                "Roteamento IPv4",
                status="error",
                mensagem=str(exc),
            )
        )

    # -------------------------------------------------------------------------
    # NAT
    # -------------------------------------------------------------------------

    try:
        nat = obter_status_nat()

        if not nat.get("disponivel"):
            status_nat = "error"
            mensagem_nat = "nftables indisponível."
        elif nat.get("ativo"):
            status_nat = "ok"
            mensagem_nat = (
                f"NAT MoonShield ativo com "
                f"{nat.get('total_regras', 0)} regra(s)."
            )
        else:
            status_nat = "warning"
            mensagem_nat = "NAT MoonShield ainda não possui regras ativas."

        checks.append(
            _check(
                "nat",
                "NAT MoonShield",
                status=status_nat,
                mensagem=mensagem_nat,
                detalhes={
                    "tabela": nat.get("tabela"),
                    "tabela_existe": nat.get("tabela_existe"),
                    "total_regras": nat.get("total_regras", 0),
                },
            )
        )

    except Exception as exc:
        checks.append(
            _check(
                "nat",
                "NAT MoonShield",
                status="error",
                mensagem=str(exc),
            )
        )

    # -------------------------------------------------------------------------
    # Resultado
    # -------------------------------------------------------------------------

    resumo = _contar(checks)

    if resumo["erros"]:
        resultado = "error"
    elif resumo["avisos"]:
        resultado = "warning"
    else:
        resultado = "ok"

    return {
        "resultado": resultado,
        "saudavel": resumo["erros"] == 0,
        "backend": backend.nome if backend else None,
        "checks": checks,
        "resumo": resumo,
        "ambiente": ambiente,
        "opcoes": opcoes,
        "executado_em": _agora_iso(),
    }


__all__ = [
    "executar_diagnostico",
]