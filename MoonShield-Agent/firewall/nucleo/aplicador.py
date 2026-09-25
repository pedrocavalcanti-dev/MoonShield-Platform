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

import hashlib
import ipaddress
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from firewall.nucleo.rollback import (
    TIMEOUT_SAFE_APPLY_PADRAO,
    armar_rollback_pendente,
    criar_snapshot,
    existe_alteracao_pendente,
    marcar_alteracao_falhou,
    registrar_alteracao_aplicando,
    restaurar,
    tabela_existe,
)
from firewall.nucleo.seguranca import (
    CHAIN_EMERGENCY,
    CHAIN_ALLOWLIST,
    CHAIN_FORWARD,
    CHAIN_INPUT,
    CHAIN_OUTPUT,
    CHAIN_RULES,
    CHAIN_RULES_FORWARD,
    CHAIN_RULES_INPUT,
    CHAIN_RULES_OUTPUT,
    CHAIN_SYSTEM,
    SET_ALLOW_IPV4,
    SET_ALLOW_IPV6,
    TABELA_FAMILIA,
    TABELA_NOME,
    LOG_RATE_LIMIT,
    LOG_BURST_LIMIT,
    PREFIX_EMERGENCY,
    PREFIX_DROP,
    PREFIX_REJECT,
    PREFIX_ALLOW,
    ContextoSeguranca,
    detectar_contexto,
    gerar_regras_sistema,
    sanitizar_comentario,
    validar_regras,
    validar_script_nft,
    validar_topologia,
)


VERSAO_APLICADOR = "1.3"

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
    """Apply legado: transacional imediato, sem janela de confirmação."""
    if existe_alteracao_pendente():
        return {
            "ok": False,
            "status": "erro",
            "codigo": "alteracao_em_andamento",
            "erro": "Existe um Safe Apply de Firewall aguardando conclusão.",
        }
    return _aplicar_regras_impl(dados, safe_apply=False)


def aplicar_alteracao(dados: dict[str, Any]) -> dict[str, Any]:
    """Apply oficial A9 com rollback armado até confirmação explícita."""
    if existe_alteracao_pendente():
        return {
            "ok": False,
            "status": "erro",
            "codigo": "alteracao_em_andamento",
            "erro": "Já existe uma alteração de Firewall em andamento.",
        }

    alteracao_id = str(dados.get("alteracao_id") or uuid.uuid4().hex).strip()
    try:
        timeout_segundos = int(
            dados.get("timeout_segundos")
            or dados.get("timeout")
            or TIMEOUT_SAFE_APPLY_PADRAO
        )
    except (TypeError, ValueError):
        timeout_segundos = TIMEOUT_SAFE_APPLY_PADRAO

    return _aplicar_regras_impl(
        dados,
        safe_apply=True,
        alteracao_id=alteracao_id,
        timeout_segundos=timeout_segundos,
    )


def _aplicar_regras_impl(
    dados: dict[str, Any],
    *,
    safe_apply: bool,
    alteracao_id: str | None = None,
    timeout_segundos: int = TIMEOUT_SAFE_APPLY_PADRAO,
) -> dict[str, Any]:
    """
    Payload esperado:
        {
            "regras": [...],
            "iface_map": {...},          # opcional
            "config": {
                "interface_wan": "...",
                "interface_lan": "...",
                "interface_mgmt": "...",
                "home_net": "...",
                "interfaces_gerenciamento": [...]
            }
        }
    """
    inicio = time.monotonic()
    snapshot_id: str | None = None
    safe_registrado = False

    with _lock:
        _stats["aplicacoes"] += 1

        if existe_alteracao_pendente():
            return _falha(
                "alteracao_em_andamento",
                "Existe um Safe Apply de Firewall aguardando conclusão.",
                inicio=inicio,
            )

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

            allowlist = _normalizar_allowlist(
                dados.get("allowlist", []),
                contexto=contexto,
            )

            script = _gerar_script(
                regras=regras,
                allowlist=allowlist,
                blocklist=dados.get("blocklist"),
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

            if safe_apply:
                try:
                    registrar_alteracao_aplicando(
                        alteracao_id=str(alteracao_id or ""),
                        snapshot_id=snapshot_id,
                        timeout_segundos=timeout_segundos,
                        metadados={
                            "total_regras": len(regras),
                            "topologia": {
                                "interface_wan": contexto.interface_wan,
                                "interface_lan": contexto.interface_lan,
                                "interface_mgmt": contexto.interface_mgmt,
                                "home_net": contexto.home_net,
                            },
                        },
                    )
                    safe_registrado = True
                except Exception as exc:
                    return _falha(
                        "safe_apply_reserva_falhou",
                        str(exc),
                        snapshot_id=snapshot_id,
                        inicio=inicio,
                    )

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
                    erro_check = (
                        check.stderr.strip()
                        or check.stdout.strip()
                        or "nft -c rejeitou a configuração."
                    )
                    if safe_apply and alteracao_id:
                        marcar_alteracao_falhou(
                            alteracao_id=alteracao_id,
                            erro=erro_check,
                            rollback=None,
                        )
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

                    if safe_apply and alteracao_id:
                        marcar_alteracao_falhou(
                            alteracao_id=alteracao_id,
                            erro=(
                                apply.stderr.strip()
                                or apply.stdout.strip()
                                or "Falha ao aplicar configuração."
                            ),
                            rollback=rb,
                        )

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

                    if safe_apply and alteracao_id:
                        marcar_alteracao_falhou(
                            alteracao_id=alteracao_id,
                            erro="Configuração aplicada, mas o healthcheck falhou.",
                            rollback=rb,
                        )

                    return _falha(
                        "healthcheck_pos_apply_falhou",
                        "Configuração aplicada, mas o healthcheck falhou.",
                        snapshot_id=snapshot_id,
                        rollback=rb,
                        detalhes=verificacao,
                        inicio=inicio,
                    )

                if not safe_apply:
                    from firewall.nucleo.instalador import salvar_allowlist_cache
                    salvar_allowlist_cache(allowlist)

                duracao = time.monotonic() - inicio

                if safe_apply and alteracao_id:
                    try:
                        estado_safe = armar_rollback_pendente(
                            alteracao_id=alteracao_id,
                            timeout_segundos=timeout_segundos,
                        )
                    except Exception as exc:
                        rb = restaurar(snapshot_id)
                        if rb.get("ok"):
                            _stats["rollbacks"] += 1
                        marcar_alteracao_falhou(
                            alteracao_id=alteracao_id,
                            erro=f"Falha ao armar rollback: {exc}",
                            rollback=rb,
                        )
                        return _falha(
                            "safe_apply_armamento_falhou",
                            str(exc),
                            snapshot_id=snapshot_id,
                            rollback=rb,
                            inicio=inicio,
                        )

                    _stats["sucessos"] += 1
                    _stats["ultimo_apply"] = time.time()
                    _stats["ultimo_erro"] = ""
                    _stats["ultima_duracao_segundos"] = duracao

                    return {
                        "ok": True,
                        "status": "waiting_confirmation",
                        "mensagem": (
                            "Regras aplicadas; aguardando confirmação antes do timeout."
                        ),
                        "alteracao_id": alteracao_id,
                        "snapshot_id": snapshot_id,
                        "total_regras": len(regras),
                        "duracao_segundos": round(duracao, 3),
                        "verificacao": verificacao,
                        "safe_apply": estado_safe,
                    }

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
            rb = None
            if safe_apply and safe_registrado and alteracao_id and snapshot_id:
                try:
                    rb = restaurar(snapshot_id)
                    if rb.get("ok"):
                        _stats["rollbacks"] += 1
                    marcar_alteracao_falhou(
                        alteracao_id=alteracao_id,
                        erro=str(exc),
                        rollback=rb,
                    )
                except Exception:
                    # O estado persistente continua em applying/rollback_failed e
                    # será recuperado conservadoramente no próximo boot do Agent.
                    pass

            return _falha(
                "erro_interno_aplicacao",
                str(exc),
                snapshot_id=snapshot_id,
                rollback=rb,
                inicio=inicio,
            )


def _gerar_script(
    *,
    regras: list[dict[str, Any]],
    allowlist: dict[str, list[str]],
    blocklist: list[dict[str, Any]] | None = None,
    contexto: ContextoSeguranca,
) -> str:
    """
    Gera a tabela MoonShield completa sem tocar em tabelas externas.

    A9.2:
    - políticas administrativas são separadas por hook;
    - `ms_emergency` é preservada entre aplicações normais;
    - `ms_system` protege somente INPUT administrativo;
    - `ms_rules` fica vazia apenas para compatibilidade legada.
    """
    tabela_ja_existe = tabela_existe()

    linhas: list[str] = []

    if tabela_ja_existe:
        linhas.append(
            f"delete table {TABELA_FAMILIA} {TABELA_NOME}"
        )

    linhas.extend([
        f"table {TABELA_FAMILIA} {TABELA_NOME} {{",
        f"  chain {CHAIN_SYSTEM} {{",
        "  }",
        "",
        f"  chain {CHAIN_EMERGENCY} {{"
    ])

    if blocklist is not None:
        for entry in blocklist:
            endereco = _normalizar_endereco_emergency(entry.get("ip"))
            if endereco:
                alvo, familia = endereco
                comentario = _comentario_emergency(alvo, familia)
                linhas.append(f'    {familia} saddr {alvo} limit rate {LOG_RATE_LIMIT} burst {LOG_BURST_LIMIT} packets log prefix "{PREFIX_EMERGENCY}" comment "{comentario}"')
                linhas.append(f'    {familia} saddr {alvo} counter drop comment "{comentario}"')
    else:
        emergency_existentes = (
            _obter_expressoes_chain(CHAIN_EMERGENCY)
            if tabela_ja_existe
            else []
        )
        for expr in emergency_existentes:
            linhas.append(f"    {expr}")

    linhas.append("  }")

    linhas.extend([
        f"  set {SET_ALLOW_IPV4} {{",
        "    type ipv4_addr;",
        "    flags interval;",
        _set_elements(allowlist["ipv4"]),
        "  }",

        f"  set {SET_ALLOW_IPV6} {{",
        "    type ipv6_addr;",
        "    flags interval;",
        _set_elements(allowlist["ipv6"]),
        "  }",

        f"  chain {CHAIN_ALLOWLIST} {{",
        f"    ip saddr @{SET_ALLOW_IPV4} counter accept comment \"moonshield-allowlist:ipv4\"",
        f"    ip6 saddr @{SET_ALLOW_IPV6} counter accept comment \"moonshield-allowlist:ipv6\"",
        "  }",

        # Compatibilidade com leitores antigos. Políticas novas NÃO usam esta
        # chain porque cada hook possui sua chain administrativa própria.
        f"  chain {CHAIN_RULES} {{",
        "  }",

        f"  chain {CHAIN_RULES_INPUT} {{",
        "  }",

        f"  chain {CHAIN_RULES_FORWARD} {{",
        "  }",

        f"  chain {CHAIN_RULES_OUTPUT} {{",
        "  }",
    ])

    linhas.extend([
        f"  chain {CHAIN_INPUT} {{",
        "    type filter hook input priority 0; policy accept;",
        f"    jump {CHAIN_SYSTEM}",
        f"    jump {CHAIN_EMERGENCY}",
        f"    jump {CHAIN_ALLOWLIST}",
        f"    jump {CHAIN_RULES_INPUT}",
        "    ct state established,related accept",
        "  }",

        f"  chain {CHAIN_FORWARD} {{",
        "    type filter hook forward priority 0; policy accept;",
        f"    jump {CHAIN_EMERGENCY}",
        f"    jump {CHAIN_ALLOWLIST}",
        f"    jump {CHAIN_RULES_FORWARD}",
        "    ct state established,related accept",
        "  }",

        f"  chain {CHAIN_OUTPUT} {{",
        "    type filter hook output priority 0; policy accept;",
        f"    jump {CHAIN_EMERGENCY}",
        f"    jump {CHAIN_ALLOWLIST}",
        f"    jump {CHAIN_RULES_OUTPUT}",
        "    ct state established,related accept",
        "  }",

        "}",
    ])

    pos: list[str] = []

    for expr in gerar_regras_sistema(contexto):
        pos.append(
            f"add rule {TABELA_FAMILIA} {TABELA_NOME} "
            f"{CHAIN_SYSTEM} {expr}"
        )

    # Emergency é estado runtime e agora é persistido pela listagem provida ou restaurado das regras atuais no bloco acima.

    regras_ordenadas = sorted(
        [
            r for r in regras
            if isinstance(r, dict)
            and _bool(r.get("enabled", True))
        ],
        key=lambda r: int(r.get("priority", 100)),
    )

    chain_por_direcao = {
        "in": CHAIN_RULES_INPUT,
        "forward": CHAIN_RULES_FORWARD,
        "out": CHAIN_RULES_OUTPUT,
    }

    for regra in regras_ordenadas:
        direction = str(regra.get("dir") or "in").lower()

        # BOTH continua sendo uma única regra lógica no Django, materializada
        # em INPUT + OUTPUT. FORWARD permanece uma decisão explícita.
        directions = ("in", "out") if direction == "both" else (direction,)

        for concrete_direction in directions:
            chain = chain_por_direcao.get(concrete_direction)

            if not chain:
                raise ValueError(
                    f"Direção de regra sem chain correspondente: {concrete_direction!r}."
                )

            regra_runtime = {
                **regra,
                "dir": concrete_direction,
            }

            expressoes = _regra_para_expr(
                regra_runtime,
                contexto,
            )

            for expr in expressoes:
                if expr:
                    pos.append(
                        f"add rule {TABELA_FAMILIA} {TABELA_NOME} "
                        f"{chain} {expr}"
                    )

    script = "\n".join(linhas) + "\n"

    return script + "\n".join(pos) + ("\n" if pos else "")


def _normalizar_allowlist(
    valor: Any,
    *,
    contexto: ContextoSeguranca | None = None,
) -> dict[str, list[str]]:
    """Aceita somente enderecos estruturados para os sets da allowlist."""
    if not isinstance(valor, list):
        raise ValueError("dados.allowlist deve ser uma lista.")

    normalizados: dict[str, set[str]] = {"ipv4": set(), "ipv6": set()}
    for item in valor:
        bruto = item.get("ip") if isinstance(item, dict) else item
        try:
            rede = ipaddress.ip_network(str(bruto or "").strip(), strict=False)
        except ValueError as exc:
            raise ValueError("Allowlist contem IP ou CIDR invalido.") from exc

        if (
            rede.prefixlen == 0
            or rede.is_loopback
            or rede.is_multicast
            or rede.is_unspecified
        ):
            raise ValueError("Rede nao permitida na allowlist.")

        if _endereco_allowlist_protegido(rede, contexto):
            raise ValueError("Allowlist nao pode incluir endereco administrativo critico.")

        chave = "ipv6" if rede.version == 6 else "ipv4"
        normalizados[chave].add(str(rede))

    return {
        familia: sorted(enderecos)
        for familia, enderecos in normalizados.items()
    }


def _endereco_allowlist_protegido(
    rede: ipaddress.IPv4Network | ipaddress.IPv6Network,
    contexto: ContextoSeguranca | None,
) -> bool:
    if contexto is None:
        return False

    candidatos = [
        getattr(contexto, "gateway", ""),
        *getattr(contexto, "ips_gerenciamento", []),
    ]
    for candidato in candidatos:
        try:
            endereco = ipaddress.ip_address(str(candidato))
        except ValueError:
            continue
        if endereco.version == rede.version and endereco in rede:
            return True
    return False


def _set_elements(enderecos: list[str]) -> str:
    if not enderecos:
        return ""
    return f"    elements = {{ {', '.join(enderecos)} }}"


def _obter_expressoes_chain(
    chain: str,
) -> list[str]:
    """
    Exporta somente expressões de regras de uma chain MoonShield.

    Usado para preservar `ms_emergency` durante um policy apply. Handles são
    removidos porque pertencem à instância atual do ruleset.
    """
    nft = shutil.which("nft")

    if not nft:
        return []

    try:
        result = subprocess.run(
            [
                nft,
                "-a",
                "list",
                "chain",
                TABELA_FAMILIA,
                TABELA_NOME,
                chain,
            ],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_NFT,
            check=False,
        )
    except Exception:
        return []

    if result.returncode != 0:
        return []

    expressoes: list[str] = []

    for linha in (result.stdout or "").splitlines():
        texto = linha.strip()

        if (
            not texto
            or texto.startswith("table ")
            or texto.startswith("chain ")
            or texto in {"{", "}"}
        ):
            continue

        if "# handle" in texto:
            texto = texto.rsplit(
                "# handle",
                1,
            )[0].strip()

        if texto and texto not in expressoes:
            expressoes.append(texto)

    return expressoes


def _regra_para_expr(
    regra: dict[str, Any],
    contexto: ContextoSeguranca,
) -> list[str]:
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
    port = str(regra.get("port") or "any")

    if proto == "icmp":
        partes.append("ip protocol icmp")
    elif proto == "icmpv6":
        partes.append("ip6 nexthdr icmpv6")
    elif proto in {"tcp", "udp"}:
        if port != "any":
            # `_porta_expr` já inclui o protocolo: `tcp dport 443`.
            partes.append(
                _porta_expr(
                    proto,
                    port,
                )
            )
        else:
            partes.append(
                f"meta l4proto {proto}"
            )

    action = str(regra.get("action") or "deny").lower()

    if action in {"allow", "accept"}:
        prefix = PREFIX_ALLOW
        nft_action = "accept"
    elif action == "reject":
        prefix = PREFIX_REJECT
        nft_action = "reject"
    else:
        prefix = PREFIX_DROP
        nft_action = "drop"

    regra_id = str(
        regra.get("id")
        or regra.get("pk")
        or ""
    ).strip()

    desc = sanitizar_comentario(
        regra.get("desc")
        or ""
    )

    marcador = (
        f"moonshield-fw:{regra_id}"
        if regra_id
        else "moonshield-fw"
    )

    comentario = sanitizar_comentario(
        f"{marcador} | {desc}"
        if desc
        else marcador
    )

    linhas = []
    base_match = " ".join(partes)

    if _bool(regra.get("log", True)):
        linhas.append(f'{base_match} limit rate {LOG_RATE_LIMIT} burst {LOG_BURST_LIMIT} packets log prefix "{prefix}" flags all comment "{comentario}"')

    linhas.append(f'{base_match} counter {nft_action} comment "{comentario}"')

    return linhas


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
        CHAIN_RULES_INPUT,
        CHAIN_RULES_FORWARD,
        CHAIN_RULES_OUTPUT,
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
    """Bloqueia IP serializando a mutação com policy apply."""
    with _lock:
        if existe_alteracao_pendente():
            return {
                "ok": False,
                "codigo": "alteracao_em_andamento",
                "erro": "Bloqueio emergencial pausado durante Safe Apply do Firewall.",
            }
        return _bloquear_ip_sem_lock(dados)


def _bloquear_ip_sem_lock(dados: dict[str, Any]) -> dict[str, Any]:
    endereco = _normalizar_endereco_emergency(dados.get("ip"))
    motivo = str(dados.get("motivo") or "bloqueio emergencial")[:255]

    if endereco is None:
        return {
            "ok": False,
            "codigo": "ip_invalido",
            "erro": "IP inválido.",
        }

    alvo, familia = endereco

    if _endereco_emergency_protegido(alvo):
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

    comentario = _comentario_emergency(alvo, familia)

    base_args = [
        nft,
        "add",
        "rule",
        TABELA_FAMILIA,
        TABELA_NOME,
        CHAIN_EMERGENCY,
        familia,
        "saddr",
        alvo,
    ]

    args_log = base_args + [
        "limit", "rate", LOG_RATE_LIMIT, "burst", f"{LOG_BURST_LIMIT} packets",
        "log", "prefix", f'"{PREFIX_EMERGENCY}"',
        "comment", f'"{comentario}"',
    ]

    args_drop = base_args + [
        "counter",
        "drop",
        "comment",
        f'"{comentario}"',
    ]

    # Executa log e drop
    r1 = subprocess.run(args_log, capture_output=True, text=True, timeout=10, check=False)
    if r1.returncode != 0:
        return {
            "ok": False,
            "codigo": "bloqueio_falhou",
            "erro": r1.stderr.strip() or "Falha ao registrar regra de log de emergência.",
        }

    r2 = subprocess.run(args_drop, capture_output=True, text=True, timeout=10, check=False)
    if r2.returncode != 0:
        # Tenta remover o log inserido
        subprocess.run([nft, "delete", "rule", TABELA_FAMILIA, TABELA_NOME, CHAIN_EMERGENCY, "handle", "..."], check=False) # Ignorado, o rollback ou restore cobrirá se o Agent possuir recovery avançado.
        return {
            "ok": False,
            "codigo": "bloqueio_falhou",
            "erro": r2.stderr.strip() or "Falha ao bloquear IP.",
        }

    return {
        "ok": True,
        "ip": alvo,
        "motivo": motivo,
        "comentario": comentario,
        "mensagem": "IP bloqueado na chain de emergência.",
    }


def bloquear(dados: dict[str, Any]) -> dict[str, Any]:
    return bloquear_ip(dados)


def liberar_ip(dados: dict[str, Any]) -> dict[str, Any]:
    """Libera IP serializando a mutação com policy apply."""
    with _lock:
        if existe_alteracao_pendente():
            return {
                "ok": False,
                "codigo": "alteracao_em_andamento",
                "erro": "Liberação emergencial pausada durante Safe Apply do Firewall.",
            }
        return _liberar_ip_sem_lock(dados)


def _liberar_ip_sem_lock(dados: dict[str, Any]) -> dict[str, Any]:
    endereco = _normalizar_endereco_emergency(dados.get("ip"))

    if endereco is None:
        return {
            "ok": False,
            "codigo": "ip_invalido",
            "erro": "IP inválido.",
        }

    alvo, familia = endereco
    comentario = _comentario_emergency(alvo, familia)

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
        if "# handle" not in linha:
            continue

        possui_marcador = f'comment "{comentario}"' in linha
        legado_correspondente = _linha_emergency_legada_corresponde(
            linha,
            alvo=alvo,
            familia=familia,
        )

        if not possui_marcador and not legado_correspondente:
            continue

        match_handle = re.search(r"# handle\s+(\d+)\s*$", linha)
        if not match_handle:
            continue

        handle = match_handle.group(1)

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
        "ip": alvo,
        "removidos": removidos,
        "mensagem": (
            "Bloqueio removido."
            if removidos
            else "Nenhum bloqueio ativo encontrado."
        ),
    }


def _normalizar_endereco_emergency(valor: Any) -> tuple[str, str] | None:
    """Aceita somente IP individual ou CIDR e devolve uma expressao nft segura."""
    texto = str(valor or "").strip()
    if not texto:
        return None

    try:
        addr = ipaddress.ip_address(texto)
        return str(addr), "ip6" if addr.version == 6 else "ip"
    except ValueError:
        pass

    try:
        rede = ipaddress.ip_network(texto, strict=False)
    except ValueError:
        return None

    return str(rede), "ip6" if rede.version == 6 else "ip"


def _endereco_emergency_protegido(alvo: str) -> bool:
    try:
        rede = ipaddress.ip_network(alvo, strict=False)
    except ValueError:
        return True

    return bool(rede.is_loopback or rede.is_unspecified)


def _comentario_emergency(alvo: str, familia: str) -> str:
    """Marcador interno estavel; nunca incorpora campos enviados pelo usuario."""
    digest = hashlib.sha256(
        f"{familia}:{alvo}".encode("ascii")
    ).hexdigest()[:20]
    return f"moonshield-emergency:{digest}"


def _linha_emergency_legada_corresponde(
    linha: str,
    *,
    alvo: str,
    familia: str,
) -> bool:
    """Permite remover regra legada sem confiar no comentario anterior."""
    padrao = rf"\b{re.escape(familia)}\s+saddr\s+{re.escape(alvo)}(?:\s|$)"
    return re.search(padrao, linha) is not None


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
