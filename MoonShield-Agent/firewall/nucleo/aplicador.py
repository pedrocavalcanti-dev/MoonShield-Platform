"""
MoonShield Agent — Firewall / Aplicador
======================================

Motor transacional de aplicação do firewall local.

Responsabilidades:
- receber regras normalizadas do Django via IPC;
- validar topologia e regras;
- gerar script nft usando conversor.py;
- proteger ms_system;
- validar textual e sintaticamente;
- criar snapshot;
- aplicar somente table inet moonshield;
- verificar resultado;
- executar rollback automático em falha;
- fornecer block/unblock emergencial local.

Este arquivo NÃO usa HTTP e NÃO conhece Django diretamente.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from firewall.nucleo.rollback import (
    criar_snapshot,
    restaurar,
    tabela_existe,
)
from firewall.nucleo.seguranca import (
    CHAIN_EMERGENCY,
    CHAIN_FORWARD,
    CHAIN_INPUT,
    CHAIN_OUTPUT,
    CHAIN_RULES,
    CHAIN_SYSTEM,
    TABELA_FAMILIA,
    TABELA_NOME,
    ContextoSeguranca,
    detectar_contexto,
    gerar_regras_sistema,
    sanitizar_comentario,
    validar_regras,
    validar_script_nft,
    validar_topologia,
)


VERSAO_APLICADOR = "1.1"

TIMEOUT_NFT = 30
MAX_SCRIPT_BYTES = 4 * 1024 * 1024

_lock = threading.RLock()

_stats = {
    "aplicacoes": 0,
    "sucessos": 0,
    "falhas": 0,
    "rollbacks": 0,
    "ultimo_apply": None,
    "ultimo_erro": "",
    "ultima_duracao_segundos": 0.0,
}


def obter_stats() -> dict[str, Any]:
    return dict(_stats)


def aplicar(dados: dict[str, Any]) -> dict[str, Any]:
    return aplicar_regras(dados)


def aplicar_regras(dados: dict[str, Any]) -> dict[str, Any]:
    """
    Payload esperado:
        {
            "regras": [...],
            "iface_map": {...},          # opcional
            "config": {
                "interface_wan": "...",
                "interface_lan": "...",
                "interface_mgmt": "...",
                "home_net": "..."
            }
        }
    """
    inicio = time.monotonic()

    with _lock:
        _stats["aplicacoes"] += 1

        try:
            regras = dados.get("regras", [])
            if not isinstance(regras, list):
                raise ValueError("dados.regras deve ser uma lista.")

            cfg = dados.get("config") or {}
            if not isinstance(cfg, dict):
                cfg = {}

            contexto = detectar_contexto(cfg)

            # Se o Django enviou iface_map explícito, aproveita apenas os nomes
            # conhecidos sem relaxar a validação do host.
            iface_map = dados.get("iface_map") or {}
            if isinstance(iface_map, dict):
                cfg = dict(cfg)
                cfg.setdefault("interface_wan", iface_map.get("WAN", ""))
                cfg.setdefault("interface_lan", iface_map.get("LAN", ""))
                cfg.setdefault("interface_mgmt", iface_map.get("MGMT", ""))
                contexto = detectar_contexto(cfg)

            topo = validar_topologia(
                contexto,
                exigir_wan=True,
                exigir_lan=True,
                exigir_mgmt=False,
            )
            if not topo.ok:
                return _falha(
                    "topologia_invalida",
                    "Topologia do firewall inválida.",
                    detalhes=topo.para_dict(),
                    inicio=inicio,
                )

            validacao_regras = validar_regras(regras, contexto)
            if not validacao_regras.ok:
                return _falha(
                    "regras_invalidas",
                    "Uma ou mais regras foram rejeitadas.",
                    detalhes=validacao_regras.para_dict(),
                    inicio=inicio,
                )

            script = _gerar_script(
                regras=regras,
                contexto=contexto,
            )

            if len(script.encode("utf-8")) > MAX_SCRIPT_BYTES:
                return _falha(
                    "script_muito_grande",
                    "Script nftables excede o limite permitido.",
                    inicio=inicio,
                )

            seguranca_script = validar_script_nft(
                script,
                permitir_delete_table_moonshield=True,
            )
            if not seguranca_script.ok:
                return _falha(
                    "script_inseguro",
                    "Script nftables rejeitado pela camada de segurança.",
                    detalhes=seguranca_script.para_dict(),
                    inicio=inicio,
                )

            nft = shutil.which("nft")
            if not nft:
                return _falha(
                    "nft_indisponivel",
                    "Comando nft não encontrado.",
                    inicio=inicio,
                )

            snapshot = criar_snapshot(
                "antes_aplicar_regras",
                metadados={
                    "total_regras": len(regras),
                },
            )
            snapshot_id = snapshot["snapshot"]["id"]

            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                suffix=".nft",
                prefix="moonshield-apply-",
                delete=False,
            ) as fp:
                fp.write(script)
                tmp = fp.name

            try:
                check = subprocess.run(
                    [nft, "-c", "-f", tmp],
                    capture_output=True,
                    text=True,
                    timeout=TIMEOUT_NFT,
                    check=False,
                )

                if check.returncode != 0:
                    return _falha(
                        "nft_validacao_falhou",
                        check.stderr.strip()
                        or check.stdout.strip()
                        or "nft -c rejeitou a configuração.",
                        snapshot_id=snapshot_id,
                        inicio=inicio,
                    )

                apply = subprocess.run(
                    [nft, "-f", tmp],
                    capture_output=True,
                    text=True,
                    timeout=TIMEOUT_NFT,
                    check=False,
                )

                if apply.returncode != 0:
                    rb = restaurar(snapshot_id)

                    if rb.get("ok"):
                        _stats["rollbacks"] += 1

                    return _falha(
                        "nft_apply_falhou",
                        apply.stderr.strip()
                        or apply.stdout.strip()
                        or "Falha ao aplicar configuração.",
                        snapshot_id=snapshot_id,
                        rollback=rb,
                        inicio=inicio,
                    )

                verificacao = verificar_estado()

                if not verificacao.get("ok"):
                    rb = restaurar(snapshot_id)

                    if rb.get("ok"):
                        _stats["rollbacks"] += 1

                    return _falha(
                        "healthcheck_pos_apply_falhou",
                        "Configuração aplicada, mas o healthcheck falhou.",
                        snapshot_id=snapshot_id,
                        rollback=rb,
                        detalhes=verificacao,
                        inicio=inicio,
                    )

                duracao = time.monotonic() - inicio

                _stats["sucessos"] += 1
                _stats["ultimo_apply"] = time.time()
                _stats["ultimo_erro"] = ""
                _stats["ultima_duracao_segundos"] = duracao

                return {
                    "ok": True,
                    "status": "sucesso",
                    "mensagem": "Regras aplicadas com sucesso.",
                    "snapshot_id": snapshot_id,
                    "total_regras": len(regras),
                    "duracao_segundos": round(duracao, 3),
                    "verificacao": verificacao,
                }

            finally:
                try:
                    os.unlink(tmp)
                except FileNotFoundError:
                    pass

        except Exception as exc:
            return _falha(
                "erro_interno_aplicacao",
                str(exc),
                inicio=inicio,
            )


def _gerar_script(
    *,
    regras: list[dict[str, Any]],
    contexto: ContextoSeguranca,
) -> str:
    """
    Gera uma tabela completa MoonShield.

    O script é autocontido e NÃO referencia tabelas de terceiros.
    """
    linhas: list[str] = []

    if tabela_existe():
        linhas.append(
            f"delete table {TABELA_FAMILIA} {TABELA_NOME}"
        )

    linhas.extend([
        f"table {TABELA_FAMILIA} {TABELA_NOME} {{",

        f"  chain {CHAIN_SYSTEM} {{",
        "  }",

        f"  chain {CHAIN_EMERGENCY} {{",
        "  }",

        f"  chain {CHAIN_RULES} {{",
        "  }",

        f"  chain {CHAIN_INPUT} {{",
        "    type filter hook input priority 0; policy accept;",
        f"    jump {CHAIN_SYSTEM}",
        f"    jump {CHAIN_EMERGENCY}",
        f"    jump {CHAIN_RULES}",
        "  }",

        f"  chain {CHAIN_FORWARD} {{",
        "    type filter hook forward priority 0; policy accept;",
        f"    jump {CHAIN_SYSTEM}",
        f"    jump {CHAIN_EMERGENCY}",
        f"    jump {CHAIN_RULES}",
        "  }",

        f"  chain {CHAIN_OUTPUT} {{",
        "    type filter hook output priority 0; policy accept;",
        f"    jump {CHAIN_SYSTEM}",
        f"    jump {CHAIN_EMERGENCY}",
        f"    jump {CHAIN_RULES}",
        "  }",

        "}",
    ])

    script = "\n".join(linhas) + "\n"

    # Injeta regras de sistema e usuário com comandos add/insert.
    pos = []

    for expr in gerar_regras_sistema(contexto):
        pos.append(
            f"add rule {TABELA_FAMILIA} {TABELA_NOME} "
            f"{CHAIN_SYSTEM} {expr}"
        )

    regras_ordenadas = sorted(
        [
            r for r in regras
            if isinstance(r, dict)
            and _bool(r.get("enabled", True))
        ],
        key=lambda r: int(r.get("priority", 100)),
    )

    for regra in regras_ordenadas:
        direction = str(regra.get("dir") or "in").lower()

        # BOTH é uma conveniência do painel: a mesma política é materializada
        # em duas regras nft, uma pela interface de entrada e outra pela de
        # saída. O banco continua mantendo uma única regra lógica.
        directions = ("in", "out") if direction == "both" else (direction,)

        for concrete_direction in directions:
            regra_runtime = {
                **regra,
                "dir": concrete_direction,
            }
            expr = _regra_para_expr(regra_runtime, contexto)
            if expr:
                pos.append(
                    f"add rule {TABELA_FAMILIA} {TABELA_NOME} "
                    f"{CHAIN_RULES} {expr}"
                )

    return script + "\n".join(pos) + ("\n" if pos else "")


def _regra_para_expr(
    regra: dict[str, Any],
    contexto: ContextoSeguranca,
) -> str:
    partes: list[str] = []

    iface = str(regra.get("iface") or "any")
    iface_fisica = _resolver_iface(iface, contexto)

    direction = str(regra.get("dir") or "in").lower()

    if iface_fisica != "any":
        if direction in {"in", "forward"}:
            partes.append(f'iifname "{iface_fisica}"')
        elif direction == "out":
            partes.append(f'oifname "{iface_fisica}"')
        elif direction == "both":
            raise ValueError(
                "Direção 'both' deve ser expandida antes da geração da expressão nft."
            )

    src = str(regra.get("src") or "any")
    dst = str(regra.get("dst") or "any")

    if src != "any":
        partes.append(_endereco_expr("saddr", src))

    if dst != "any":
        partes.append(_endereco_expr("daddr", dst))

    proto = str(regra.get("proto") or "any").lower()

    if proto != "any":
        if proto == "icmp":
            partes.append("ip protocol icmp")
        elif proto == "icmpv6":
            partes.append("ip6 nexthdr icmpv6")
        else:
            partes.append(proto)

    port = str(regra.get("port") or "any")

    if port != "any" and proto in {"tcp", "udp"}:
        partes.append(_porta_expr(proto, port))

    if _bool(regra.get("log", True)):
        action = str(regra.get("action") or "deny").lower()
        prefix = (
            "MS-FW-ALLOW: "
            if action in {"allow", "accept"}
            else "MS-FW-DROP: "
        )
        partes.append(
            f'log prefix "{prefix}" flags all counter'
        )

    action = str(regra.get("action") or "deny").lower()

    if action in {"allow", "accept"}:
        partes.append("accept")
    elif action == "reject":
        partes.append("reject")
    else:
        partes.append("drop")

    desc = sanitizar_comentario(regra.get("desc") or "")
    if desc:
        partes.append(f'comment "{desc}"')

    return " ".join(partes)


def _resolver_iface(
    iface: str,
    contexto: ContextoSeguranca,
) -> str:
    mapa = contexto.iface_map()
    return mapa.get(iface, iface)


def _endereco_expr(
    direcao: str,
    valor: str,
) -> str:
    itens = [x.strip() for x in valor.split(",") if x.strip()]

    if len(itens) == 1:
        item = itens[0]
        # ip_network(..., strict=False) aceita host puro e CIDR e
        # escolhe corretamente /32 para IPv4 e /128 para IPv6.
        versao = ipaddress.ip_network(
            item,
            strict=False,
        ).version
        familia = "ip6" if versao == 6 else "ip"
        return f"{familia} {direcao} {item}"

    # múltiplos endereços -> set inline
    # Não anexar /32 manualmente: isso quebraria hosts IPv6.
    versoes = {
        ipaddress.ip_network(
            x,
            strict=False,
        ).version
        for x in itens
    }

    if len(versoes) != 1:
        raise ValueError(
            "Uma mesma regra não pode misturar IPv4 e IPv6."
        )

    familia = "ip6" if 6 in versoes else "ip"

    return f"{familia} {direcao} {{ {', '.join(itens)} }}"


def _porta_expr(
    proto: str,
    valor: str,
) -> str:
    itens = [x.strip() for x in valor.split(",") if x.strip()]

    convertidos: list[str] = []

    for item in itens:
        if "-" in item:
            ini, fim = item.split("-", 1)
            convertidos.append(f"{ini}-{fim}")
        else:
            convertidos.append(item)

    if len(convertidos) == 1:
        return f"{proto} dport {convertidos[0]}"

    return f"{proto} dport {{ {', '.join(convertidos)} }}"


def verificar_estado() -> dict[str, Any]:
    nft = shutil.which("nft")
    if not nft:
        return {
            "ok": False,
            "erro": "nft não encontrado.",
        }

    try:
        r = subprocess.run(
            [nft, "list", "table", TABELA_FAMILIA, TABELA_NOME],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_NFT,
            check=False,
        )
    except Exception as exc:
        return {
            "ok": False,
            "erro": str(exc),
        }

    if r.returncode != 0:
        return {
            "ok": False,
            "erro": r.stderr.strip() or "Tabela MoonShield ausente.",
        }

    saida = r.stdout or ""

    obrigatorias = {
        CHAIN_SYSTEM,
        CHAIN_EMERGENCY,
        CHAIN_RULES,
        CHAIN_INPUT,
        CHAIN_FORWARD,
        CHAIN_OUTPUT,
    }

    faltando = [
        chain for chain in obrigatorias
        if f"chain {chain}" not in saida
    ]

    return {
        "ok": not faltando,
        "tabela": f"{TABELA_FAMILIA} {TABELA_NOME}",
        "chains_faltando": faltando,
        "bytes": len(saida.encode("utf-8")),
    }


def bloquear_ip(dados: dict[str, Any]) -> dict[str, Any]:
    ip = str(dados.get("ip") or "").strip()
    motivo = sanitizar_comentario(
        dados.get("motivo") or "bloqueio emergencial"
    )

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {
            "ok": False,
            "codigo": "ip_invalido",
            "erro": "IP inválido.",
        }

    if addr.is_loopback or addr.is_unspecified:
        return {
            "ok": False,
            "codigo": "ip_protegido",
            "erro": "IP protegido não pode ser bloqueado.",
        }

    if not tabela_existe():
        return {
            "ok": False,
            "codigo": "firewall_nao_instalado",
            "erro": "Tabela MoonShield não existe.",
        }

    nft = shutil.which("nft")
    if not nft:
        return {
            "ok": False,
            "erro": "nft não encontrado.",
        }

    familia = "ip6" if addr.version == 6 else "ip"

    args = [
        nft,
        "add",
        "rule",
        TABELA_FAMILIA,
        TABELA_NOME,
        CHAIN_EMERGENCY,
        familia,
        "saddr",
        str(addr),
        "counter",
        "drop",
        "comment",
        motivo,
    ]

    r = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    if r.returncode != 0:
        return {
            "ok": False,
            "codigo": "bloqueio_falhou",
            "erro": r.stderr.strip() or "Falha ao bloquear IP.",
        }

    return {
        "ok": True,
        "ip": str(addr),
        "motivo": motivo,
        "mensagem": "IP bloqueado na chain de emergência.",
    }


def bloquear(dados: dict[str, Any]) -> dict[str, Any]:
    return bloquear_ip(dados)


def liberar_ip(dados: dict[str, Any]) -> dict[str, Any]:
    ip = str(dados.get("ip") or "").strip()

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {
            "ok": False,
            "codigo": "ip_invalido",
            "erro": "IP inválido.",
        }

    nft = shutil.which("nft")
    if not nft:
        return {
            "ok": False,
            "erro": "nft não encontrado.",
        }

    r = subprocess.run(
        [
            nft,
            "-a",
            "list",
            "chain",
            TABELA_FAMILIA,
            TABELA_NOME,
            CHAIN_EMERGENCY,
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    if r.returncode != 0:
        return {
            "ok": False,
            "erro": r.stderr.strip() or "Falha ao consultar chain.",
        }

    removidos = 0

    for linha in r.stdout.splitlines():
        if str(addr) not in linha or "# handle" not in linha:
            continue

        handle = linha.rsplit("# handle", 1)[-1].strip().split()[0]

        d = subprocess.run(
            [
                nft,
                "delete",
                "rule",
                TABELA_FAMILIA,
                TABELA_NOME,
                CHAIN_EMERGENCY,
                "handle",
                handle,
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        if d.returncode == 0:
            removidos += 1

    return {
        "ok": True,
        "ip": str(addr),
        "removidos": removidos,
        "mensagem": (
            "Bloqueio removido."
            if removidos
            else "Nenhum bloqueio ativo encontrado."
        ),
    }


def desbloquear_ip(dados: dict[str, Any]) -> dict[str, Any]:
    return liberar_ip(dados)


def liberar(dados: dict[str, Any]) -> dict[str, Any]:
    return liberar_ip(dados)


def _falha(
    codigo: str,
    erro: str,
    *,
    inicio: float,
    snapshot_id: str | None = None,
    rollback: dict[str, Any] | None = None,
    detalhes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    duracao = time.monotonic() - inicio

    _stats["falhas"] += 1
    _stats["ultimo_erro"] = str(erro)
    _stats["ultima_duracao_segundos"] = duracao

    return {
        "ok": False,
        "status": "erro",
        "codigo": codigo,
        "erro": str(erro),
        "snapshot_id": snapshot_id,
        "rollback": rollback,
        "detalhes": detalhes or {},
        "duracao_segundos": round(duracao, 3),
    }


def _bool(valor: Any) -> bool:
    if isinstance(valor, bool):
        return valor
    if valor is None:
        return False
    return str(valor).strip().lower() in {
        "1", "true", "sim", "yes", "on", "ativo", "enabled"
    }
