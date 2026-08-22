"""
MoonShield Agent — Rede / NAT
=============================

Gerenciamento do NAT IPv4 do módulo de Rede.

O MoonShield utiliza uma tabela nftables exclusiva:

    table ip moonshield_nat

Este módulo:
- consulta o estado real do NAT;
- aplica regras MASQUERADE;
- exporta/restaura o estado para Safe Apply;
- nunca executa flush global do nftables;
- nunca altera tabelas pertencentes ao Firewall.

V1 suporta somente MASQUERADE.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from typing import Any


NFT_FAMILY = "ip"
NFT_TABLE = "moonshield_nat"
NFT_CHAIN = "postrouting"
NFT_TIMEOUT = 15
NFT_PRIORITY = 100

INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")


# =============================================================================
# EXCEÇÕES
# =============================================================================

class NatErro(RuntimeError):
    def __init__(self, mensagem: str, *, codigo: str = "nat_erro", detalhes: dict[str, Any] | None = None):
        super().__init__(mensagem)
        self.codigo = codigo
        self.detalhes = detalhes or {}


class NatIndisponivel(NatErro):
    def __init__(self):
        super().__init__(
            "nftables não está disponível no sistema.",
            codigo="nft_indisponivel",
        )


class RegraNatInvalida(NatErro):
    def __init__(self, mensagem: str, *, detalhes: dict[str, Any] | None = None):
        super().__init__(mensagem, codigo="regra_nat_invalida", detalhes=detalhes)


class ComandoNatFalhou(NatErro):
    def __init__(
        self,
        mensagem: str,
        *,
        comando: list[str] | None = None,
        retorno: int | None = None,
        stdout: str = "",
        stderr: str = "",
    ):
        super().__init__(
            mensagem,
            codigo="comando_nat_falhou",
            detalhes={
                "comando": comando or [],
                "retorno": retorno,
                "stdout": stdout,
                "stderr": stderr,
            },
        )


# =============================================================================
# HELPERS
# =============================================================================

def _nft() -> str:
    caminho = shutil.which("nft")

    if not caminho:
        raise NatIndisponivel()

    return caminho


def _executar(
    argumentos: list[str],
    *,
    verificar: bool = True,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    comando = [_nft(), *argumentos]

    try:
        processo = subprocess.run(
            comando,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=NFT_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ComandoNatFalhou(
            "Comando nftables excedeu o tempo limite.",
            comando=comando,
            stdout=exc.stdout or "",
            stderr=exc.stderr or "",
        ) from exc
    except OSError as exc:
        raise ComandoNatFalhou(
            f"Não foi possível executar nftables: {exc}",
            comando=comando,
        ) from exc

    if verificar and processo.returncode != 0:
        raise ComandoNatFalhou(
            processo.stderr.strip()
            or processo.stdout.strip()
            or "Comando nftables falhou.",
            comando=comando,
            retorno=processo.returncode,
            stdout=processo.stdout.strip(),
            stderr=processo.stderr.strip(),
        )

    return processo


def nft_disponivel() -> bool:
    return shutil.which("nft") is not None


def _yes(valor: Any, padrao: bool = True) -> bool:
    if valor is None:
        return padrao

    if isinstance(valor, bool):
        return valor

    if isinstance(valor, (int, float)):
        return valor != 0

    return str(valor).strip().lower() in {
        "1",
        "true",
        "yes",
        "sim",
        "on",
        "enabled",
        "ativo",
    }


def _validar_interface(nome: Any, campo: str) -> str:
    valor = str(nome or "").strip()

    if not valor:
        raise RegraNatInvalida(
            f"Campo '{campo}' é obrigatório."
        )

    if not INTERFACE_RE.fullmatch(valor):
        raise RegraNatInvalida(
            f"Nome de interface inválido em '{campo}'.",
            detalhes={
                "campo": campo,
                "interface": valor,
            },
        )

    return valor


def _normalizar_cidr(valor: Any) -> str | None:
    texto = str(valor or "").strip()

    if not texto:
        return None

    try:
        rede = ipaddress.ip_network(
            texto,
            strict=False,
        )
    except ValueError as exc:
        raise RegraNatInvalida(
            "Rede de origem inválida.",
            detalhes={
                "rede_origem": texto,
            },
        ) from exc

    if rede.version != 4:
        raise RegraNatInvalida(
            "O NAT V1 suporta somente IPv4.",
            detalhes={
                "rede_origem": texto,
            },
        )

    return str(rede)


def normalizar_regra_nat(regra: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(regra, dict):
        raise RegraNatInvalida(
            "Regra NAT precisa ser um objeto."
        )

    tipo = str(
        regra.get("tipo")
        or regra.get("type")
        or "masquerade"
    ).strip().lower()

    if tipo not in {
        "masquerade",
        "masq",
    }:
        raise RegraNatInvalida(
            f"Tipo NAT não suportado: {tipo}",
            detalhes={"tipo": tipo},
        )

    interface_origem = (
        regra.get("interface_origem")
        or regra.get("origem_interface")
        or regra.get("source_interface")
        or regra.get("interface_entrada")
    )

    interface_saida = (
        regra.get("interface_saida")
        or regra.get("saida_interface")
        or regra.get("output_interface")
        or regra.get("wan_interface")
    )

    rede_origem = (
        regra.get("rede_origem")
        or regra.get("origem_cidr")
        or regra.get("source_cidr")
    )

    identificador = (
        regra.get("id")
        or regra.get("uuid")
        or regra.get("nome")
        or "regra"
    )

    prioridade = regra.get(
        "prioridade",
        regra.get(
            "priority",
            100,
        ),
    )

    try:
        prioridade = int(prioridade)
    except (TypeError, ValueError):
        prioridade = 100

    return {
        "id": str(identificador),
        "tipo": "masquerade",
        "interface_origem": _validar_interface(
            interface_origem,
            "interface_origem",
        ),
        "interface_saida": _validar_interface(
            interface_saida,
            "interface_saida",
        ),
        "rede_origem": _normalizar_cidr(
            rede_origem
        ),
        "ativa": _yes(
            regra.get(
                "ativa",
                regra.get(
                    "habilitada",
                    regra.get(
                        "enabled",
                        True,
                    ),
                ),
            ),
            True,
        ),
        "prioridade": prioridade,
    }


# =============================================================================
# ESTADO
# =============================================================================

def tabela_existe() -> bool:
    if not nft_disponivel():
        return False

    processo = _executar(
        [
            "list",
            "table",
            NFT_FAMILY,
            NFT_TABLE,
        ],
        verificar=False,
    )

    return processo.returncode == 0


def _obter_tabela_raw() -> str:
    if not tabela_existe():
        return ""

    processo = _executar(
        [
            "list",
            "table",
            NFT_FAMILY,
            NFT_TABLE,
        ]
    )

    return processo.stdout.strip()


def _extrair_regras(raw: str) -> list[dict[str, Any]]:
    regras = []

    for linha in raw.splitlines():
        linha = linha.strip()

        if "masquerade" not in linha:
            continue

        entrada = re.search(
            r'iifname\s+"([^"]+)"',
            linha,
        )

        saida = re.search(
            r'oifname\s+"([^"]+)"',
            linha,
        )

        origem = re.search(
            r'ip\s+saddr\s+([^\s]+)',
            linha,
        )

        comentario = re.search(
            r'comment\s+"moonshield-nat:([^"]+)"',
            linha,
        )

        regras.append({
            "tipo": "masquerade",
            "interface_origem": entrada.group(1) if entrada else None,
            "interface_saida": saida.group(1) if saida else None,
            "rede_origem": origem.group(1) if origem else None,
            "id": comentario.group(1) if comentario else None,
            "raw": linha,
        })

    return regras


def obter_status_nat() -> dict[str, Any]:
    if not nft_disponivel():
        return {
            "disponivel": False,
            "ativo": False,
            "backend": "nftables",
            "tabela": NFT_TABLE,
            "chain": NFT_CHAIN,
            "regras": [],
            "total_regras": 0,
            "erro": {
                "codigo": "nft_indisponivel",
                "mensagem": "nftables não encontrado.",
            },
        }

    existe = tabela_existe()
    raw = _obter_tabela_raw() if existe else ""
    regras = _extrair_regras(raw)

    return {
        "disponivel": True,
        "ativo": bool(regras),
        "backend": "nftables",
        "familia": NFT_FAMILY,
        "tabela": NFT_TABLE,
        "chain": NFT_CHAIN,
        "tabela_existe": existe,
        "regras": regras,
        "total_regras": len(regras),
        "raw": raw,
    }


# =============================================================================
# GERAÇÃO NFT
# =============================================================================

def _comentario_id(valor: str) -> str:
    return re.sub(
        r"[^A-Za-z0-9_.:-]",
        "-",
        valor,
    )[:64]


def _regra_nft(regra: dict[str, Any]) -> str:
    partes = [
        f'iifname "{regra["interface_origem"]}"',
        f'oifname "{regra["interface_saida"]}"',
    ]

    if regra["rede_origem"]:
        partes.append(
            f'ip saddr {regra["rede_origem"]}'
        )

    partes.append("masquerade")

    identificador = _comentario_id(
        regra["id"]
    )

    partes.append(
        f'comment "moonshield-nat:{identificador}"'
    )

    return " ".join(partes)


def _gerar_ruleset(
    regras: list[dict[str, Any]],
    *,
    remover_existente: bool,
) -> str:
    linhas = []

    if remover_existente:
        linhas.append(
            f"delete table {NFT_FAMILY} {NFT_TABLE}"
        )

    if not regras:
        return "\n".join(linhas) + "\n"

    linhas.extend([
        f"table {NFT_FAMILY} {NFT_TABLE} {{",
        f"    chain {NFT_CHAIN} {{",
        f"        type nat hook postrouting priority {NFT_PRIORITY}; policy accept;",
    ])

    for regra in regras:
        linhas.append(
            f"        {_regra_nft(regra)}"
        )

    linhas.extend([
        "    }",
        "}",
    ])

    return "\n".join(linhas) + "\n"


# =============================================================================
# APLICAÇÃO
# =============================================================================

def aplicar_regras_nat(
    regras: list[dict[str, Any]],
) -> dict[str, Any]:
    if not isinstance(regras, list):
        raise RegraNatInvalida(
            "'regras' precisa ser uma lista."
        )

    normalizadas = [
        normalizar_regra_nat(regra)
        for regra in regras
    ]

    ativas = [
        regra
        for regra in normalizadas
        if regra["ativa"]
    ]

    ativas.sort(
        key=lambda item: (
            item["prioridade"],
            item["id"],
        )
    )

    existente = tabela_existe()

    if not ativas and not existente:
        return {
            "ok": True,
            "alterado": False,
            "tabela": NFT_TABLE,
            "total_regras": 0,
        }

    script = _gerar_ruleset(
        ativas,
        remover_existente=existente,
    )

    if script.strip():
        _executar(
            ["-f", "-"],
            input_text=script,
        )

    status = obter_status_nat()

    return {
        "ok": True,
        "alterado": True,
        "tabela": NFT_TABLE,
        "total_regras": len(ativas),
        "status": status,
    }


def remover_nat() -> dict[str, Any]:
    if not tabela_existe():
        return {
            "ok": True,
            "alterado": False,
        }

    _executar([
        "delete",
        "table",
        NFT_FAMILY,
        NFT_TABLE,
    ])

    return {
        "ok": True,
        "alterado": True,
    }


# =============================================================================
# SNAPSHOT NAT
# =============================================================================

def exportar_estado_nat() -> dict[str, Any]:
    existe = tabela_existe()

    return {
        "familia": NFT_FAMILY,
        "tabela": NFT_TABLE,
        "existe": existe,
        "ruleset": _obter_tabela_raw() if existe else "",
    }


def restaurar_estado_nat(
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(snapshot, dict):
        raise NatErro(
            "Snapshot NAT inválido.",
            codigo="snapshot_nat_invalido",
        )

    existia = bool(
        snapshot.get("existe")
    )

    ruleset = str(
        snapshot.get("ruleset")
        or ""
    ).strip()

    existe_agora = tabela_existe()
    linhas = []

    if existe_agora:
        linhas.append(
            f"delete table {NFT_FAMILY} {NFT_TABLE}"
        )

    if existia:
        if not ruleset:
            raise NatErro(
                "Snapshot indica tabela existente, mas não possui ruleset.",
                codigo="snapshot_nat_invalido",
            )

        linhas.append(ruleset)

    if linhas:
        _executar(
            ["-f", "-"],
            input_text="\n".join(linhas) + "\n",
        )

    return {
        "ok": True,
        "restaurado": True,
        "status": obter_status_nat(),
    }


__all__ = [
    "NFT_FAMILY",
    "NFT_TABLE",
    "NFT_CHAIN",
    "NatErro",
    "NatIndisponivel",
    "RegraNatInvalida",
    "nft_disponivel",
    "normalizar_regra_nat",
    "tabela_existe",
    "obter_status_nat",
    "aplicar_regras_nat",
    "remover_nat",
    "exportar_estado_nat",
    "restaurar_estado_nat",
]