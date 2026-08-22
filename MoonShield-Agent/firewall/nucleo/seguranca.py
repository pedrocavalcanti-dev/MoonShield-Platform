"""
MoonShield Agent — Firewall / Segurança
=======================================

Camada de segurança do firewall local do MoonShield.

Este módulo NÃO aplica regras diretamente.
Ele existe para impedir que uma operação administrativa:

- derrube o acesso de gerenciamento do MoonShield;
- bloqueie loopback;
- remova tráfego ESTABLISHED/RELATED;
- sobrescreva tabelas nftables de terceiros;
- aplique regras em interfaces inexistentes;
- use endereços/portas/protocolos inválidos;
- execute comandos arbitrários;
- faça flush global do ruleset;
- altere objetos fora de "table inet moonshield".

A ideia é que TODO fluxo de aplicação passe por aqui antes do aplicador.py.

Arquitetura esperada:

    Django
      ↓
    IPC local
      ↓
    aplicador.py
      ↓
    seguranca.py   ← valida e protege
      ↓
    rollback.py
      ↓
    nftables

O módulo foi escrito para Linux e usa somente biblioteca padrão.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


# =============================================================================
# CONSTANTES
# =============================================================================

VERSAO_SEGURANCA = "1.0"

TABELA_FAMILIA = "inet"
TABELA_NOME = "moonshield"

CHAIN_SYSTEM = "ms_system"
CHAIN_EMERGENCY = "ms_emergency"
CHAIN_RULES = "ms_rules"
CHAIN_INPUT = "ms_input"
CHAIN_FORWARD = "ms_forward"
CHAIN_OUTPUT = "ms_output"

CHAINS_GERENCIADAS = frozenset({
    CHAIN_SYSTEM,
    CHAIN_EMERGENCY,
    CHAIN_RULES,
    CHAIN_INPUT,
    CHAIN_FORWARD,
    CHAIN_OUTPUT,
})

PROTOCOLOS_SUPORTADOS = frozenset({
    "tcp",
    "udp",
    "icmp",
    "icmpv6",
    "any",
})

ACOES_SUPORTADAS = frozenset({
    "allow",
    "accept",
    "deny",
    "drop",
    "reject",
})

DIRECOES_SUPORTADAS = frozenset({
    "in",
    "out",
    "forward",
    "both",
})

IFACES_LOGICAS = frozenset({
    "WAN",
    "LAN",
    "MGMT",
    "VPN",
    "any",
})

# Operações nft perigosas que jamais devem vir de conteúdo dinâmico.
TOKENS_PROIBIDOS_SCRIPT = (
    "flush ruleset",
    "delete ruleset",
    "destroy table",
)

# Caminhos do próprio MoonShield.
DIRETORIO_CONFIG = Path("/etc/moonshield/firewall")
DIRETORIO_RUNTIME = Path("/run/moonshield")
DIRETORIO_STATE = Path("/var/lib/moonshield/firewall")

# Limite defensivo para regras aplicadas em um lote.
MAX_REGRAS_POR_APLICACAO = 5000

# Limite para uma lista de portas explícita.
MAX_PORTAS_LISTA = 256

# Caracteres aceitos em nomes de interface Linux.
_RE_IFACE = re.compile(r"^[A-Za-z0-9_.:@-]{1,32}$")

# Faixa válida de porta TCP/UDP.
PORTA_MIN = 1
PORTA_MAX = 65535


# =============================================================================
# EXCEÇÕES
# =============================================================================

class ErroSegurancaFirewall(ValueError):
    """Erro base das validações de segurança."""


class OperacaoPerigosa(ErroSegurancaFirewall):
    """Operação rejeitada por poder comprometer o host."""


class RegraInvalida(ErroSegurancaFirewall):
    """Regra administrativa inválida."""


class TopologiaInvalida(ErroSegurancaFirewall):
    """Configuração de interfaces/rede inconsistente."""


# =============================================================================
# MODELOS
# =============================================================================

@dataclass(slots=True)
class ContextoSeguranca:
    interface_wan: str = ""
    interface_lan: str = ""
    interface_mgmt: str = ""
    home_net: str = ""
    ip_local: str = ""
    gateway: str = ""
    rede_mgmt: str = ""
    interfaces_existentes: set[str] = field(default_factory=set)

    def iface_map(self) -> dict[str, str]:
        mapa: dict[str, str] = {}

        if self.interface_wan:
            mapa["WAN"] = self.interface_wan

        if self.interface_lan:
            mapa["LAN"] = self.interface_lan

        if self.interface_mgmt:
            mapa["MGMT"] = self.interface_mgmt

        # Interfaces físicas também podem ser usadas diretamente.
        for iface in self.interfaces_existentes:
            mapa[iface] = iface

        mapa["any"] = "any"

        return mapa

    def para_dict(self) -> dict[str, Any]:
        return {
            "interface_wan": self.interface_wan,
            "interface_lan": self.interface_lan,
            "interface_mgmt": self.interface_mgmt,
            "home_net": self.home_net,
            "ip_local": self.ip_local,
            "gateway": self.gateway,
            "rede_mgmt": self.rede_mgmt,
            "interfaces_existentes": sorted(self.interfaces_existentes),
            "iface_map": self.iface_map(),
        }


@dataclass(slots=True)
class ResultadoValidacao:
    ok: bool
    erros: list[str] = field(default_factory=list)
    avisos: list[str] = field(default_factory=list)
    dados: dict[str, Any] = field(default_factory=dict)

    def para_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "erros": list(self.erros),
            "avisos": list(self.avisos),
            "dados": dict(self.dados),
        }


# =============================================================================
# TOPOLOGIA / SISTEMA
# =============================================================================

def detectar_contexto(cfg: dict[str, Any] | None = None) -> ContextoSeguranca:
    """
    Constrói o contexto real do host Linux.

    cfg esperado, quando disponível:
        {
            "interface_wan": "enp0s3",
            "interface_lan": "enp0s9",
            "interface_mgmt": "enp0s8",
            "home_net": "10.10.0.0/24"
        }

    Campos ausentes são detectados de forma conservadora.
    """
    cfg = cfg or {}

    interfaces = set(listar_interfaces())

    wan = _texto(cfg.get("interface_wan"))
    lan = _texto(cfg.get("interface_lan"))
    mgmt = _texto(cfg.get("interface_mgmt"))
    home_net = _texto(cfg.get("home_net"))

    rota = detectar_rota_padrao()

    if not wan:
        wan = rota.get("interface", "")

    gateway = rota.get("gateway", "")
    ip_local = detectar_ip_interface(mgmt) if mgmt else ""

    # Se não houver IP na MGMT, tenta IP da interface usada pela rota default.
    if not ip_local and wan:
        ip_local = detectar_ip_interface(wan)

    rede_mgmt = ""
    if mgmt:
        rede_mgmt = detectar_rede_interface(mgmt)

    return ContextoSeguranca(
        interface_wan=wan,
        interface_lan=lan,
        interface_mgmt=mgmt,
        home_net=home_net,
        ip_local=ip_local,
        gateway=gateway,
        rede_mgmt=rede_mgmt,
        interfaces_existentes=interfaces,
    )


def listar_interfaces() -> list[str]:
    """
    Lista interfaces Linux sem depender de iproute2.
    """
    base = Path("/sys/class/net")

    try:
        return sorted(
            item.name
            for item in base.iterdir()
            if item.name != "lo"
        )
    except Exception:
        return []


def interface_existe(nome: str) -> bool:
    nome = _texto(nome)

    if not nome or not _RE_IFACE.fullmatch(nome):
        return False

    return Path("/sys/class/net", nome).exists()


def interface_ativa(nome: str) -> bool:
    if not interface_existe(nome):
        return False

    try:
        estado = Path(
            "/sys/class/net",
            nome,
            "operstate",
        ).read_text(encoding="utf-8").strip().lower()

        if estado == "up":
            return True

    except Exception:
        pass

    return bool(detectar_ip_interface(nome))


def detectar_ip_interface(nome: str) -> str:
    if not interface_existe(nome):
        return ""

    ip_bin = shutil.which("ip")
    if not ip_bin:
        return ""

    try:
        result = subprocess.run(
            [ip_bin, "-4", "-o", "addr", "show", "dev", nome],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except Exception:
        return ""

    if result.returncode != 0:
        return ""

    for linha in result.stdout.splitlines():
        partes = linha.split()

        try:
            indice = partes.index("inet")
            cidr = partes[indice + 1]
            return cidr.split("/", 1)[0]
        except (ValueError, IndexError):
            continue

    return ""


def detectar_rede_interface(nome: str) -> str:
    if not interface_existe(nome):
        return ""

    ip_bin = shutil.which("ip")
    if not ip_bin:
        return ""

    try:
        result = subprocess.run(
            [ip_bin, "-4", "-o", "addr", "show", "dev", nome],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except Exception:
        return ""

    if result.returncode != 0:
        return ""

    for linha in result.stdout.splitlines():
        partes = linha.split()

        try:
            indice = partes.index("inet")
            cidr = partes[indice + 1]
            rede = ipaddress.ip_interface(cidr).network
            return str(rede)
        except Exception:
            continue

    return ""


def detectar_rota_padrao() -> dict[str, str]:
    """
    Retorna:
        {
            "gateway": "10.0.2.2",
            "interface": "enp0s3"
        }
    """
    ip_bin = shutil.which("ip")
    if not ip_bin:
        return {
            "gateway": "",
            "interface": "",
        }

    try:
        result = subprocess.run(
            [ip_bin, "-4", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except Exception:
        return {
            "gateway": "",
            "interface": "",
        }

    if result.returncode != 0:
        return {
            "gateway": "",
            "interface": "",
        }

    gateway = ""
    interface = ""

    partes = result.stdout.strip().split()

    for idx, token in enumerate(partes):
        if token == "via" and idx + 1 < len(partes):
            gateway = partes[idx + 1]

        if token == "dev" and idx + 1 < len(partes):
            interface = partes[idx + 1]

    return {
        "gateway": gateway,
        "interface": interface,
    }


# =============================================================================
# VALIDAÇÃO DE TOPOLOGIA
# =============================================================================

def validar_topologia(
    cfg: dict[str, Any] | ContextoSeguranca,
    *,
    exigir_wan: bool = True,
    exigir_lan: bool = True,
    exigir_mgmt: bool = False,
) -> ResultadoValidacao:
    contexto = (
        cfg
        if isinstance(cfg, ContextoSeguranca)
        else detectar_contexto(cfg)
    )

    erros: list[str] = []
    avisos: list[str] = []

    if exigir_wan and not contexto.interface_wan:
        erros.append("Interface WAN não definida.")

    if exigir_lan and not contexto.interface_lan:
        erros.append("Interface LAN não definida.")

    if exigir_mgmt and not contexto.interface_mgmt:
        erros.append("Interface de gerenciamento não definida.")

    for rotulo, iface in (
        ("WAN", contexto.interface_wan),
        ("LAN", contexto.interface_lan),
        ("MGMT", contexto.interface_mgmt),
    ):
        if not iface:
            continue

        if not _RE_IFACE.fullmatch(iface):
            erros.append(f"Interface {rotulo} possui nome inválido: {iface!r}.")
            continue

        if iface not in contexto.interfaces_existentes:
            erros.append(f"Interface {rotulo} não existe no sistema: {iface}.")

    definidas = [
        iface
        for iface in (
            contexto.interface_wan,
            contexto.interface_lan,
            contexto.interface_mgmt,
        )
        if iface
    ]

    if len(definidas) != len(set(definidas)):
        erros.append(
            "WAN, LAN e MGMT não podem apontar para a mesma interface."
        )

    if contexto.home_net:
        try:
            rede = ipaddress.ip_network(
                contexto.home_net,
                strict=False,
            )

            if rede.version != 4:
                avisos.append(
                    "HOME_NET IPv6 ainda não é suportado pelo core inicial."
                )
        except ValueError:
            erros.append(
                f"HOME_NET inválido: {contexto.home_net!r}."
            )
    elif exigir_lan:
        avisos.append(
            "HOME_NET não definido. O firewall poderá operar, "
            "mas validações de origem interna ficarão limitadas."
        )

    if contexto.interface_mgmt and not contexto.rede_mgmt:
        avisos.append(
            "Não foi possível determinar automaticamente a rede da MGMT."
        )

    return ResultadoValidacao(
        ok=not erros,
        erros=erros,
        avisos=avisos,
        dados=contexto.para_dict(),
    )


# =============================================================================
# VALIDAÇÃO DE REGRAS
# =============================================================================

def validar_regras(
    regras: Iterable[dict[str, Any]],
    contexto: ContextoSeguranca | dict[str, Any],
) -> ResultadoValidacao:
    if not isinstance(contexto, ContextoSeguranca):
        contexto = detectar_contexto(contexto)

    regras_lista = list(regras)

    erros: list[str] = []
    avisos: list[str] = []

    if len(regras_lista) > MAX_REGRAS_POR_APLICACAO:
        erros.append(
            f"Quantidade de regras excede o limite de "
            f"{MAX_REGRAS_POR_APLICACAO}."
        )

    ids_vistos: set[str] = set()

    for indice, regra in enumerate(regras_lista):
        if not isinstance(regra, dict):
            erros.append(f"Regra #{indice + 1} não é um objeto.")
            continue

        if not _bool(regra.get("enabled", True)):
            continue

        try:
            _validar_regra_individual(regra, contexto)
        except ErroSegurancaFirewall as exc:
            identificador = (
                regra.get("id")
                or regra.get("pk")
                or indice + 1
            )

            erros.append(
                f"Regra {identificador}: {exc}"
            )

        regra_id = str(
            regra.get("id")
            or regra.get("pk")
            or ""
        ).strip()

        if regra_id:
            if regra_id in ids_vistos:
                avisos.append(
                    f"ID de regra duplicado no lote: {regra_id}."
                )
            ids_vistos.add(regra_id)

    return ResultadoValidacao(
        ok=not erros,
        erros=erros,
        avisos=avisos,
        dados={
            "total": len(regras_lista),
            "ativas": sum(
                1
                for regra in regras_lista
                if isinstance(regra, dict)
                and _bool(regra.get("enabled", True))
            ),
        },
    )


def validar_regra(
    regra: dict[str, Any],
    contexto: ContextoSeguranca | dict[str, Any],
) -> dict[str, Any]:
    """
    Valida uma única regra e retorna a versão normalizada.
    """
    if not isinstance(contexto, ContextoSeguranca):
        contexto = detectar_contexto(contexto)

    return _validar_regra_individual(
        regra,
        contexto,
    )


def _validar_regra_individual(
    regra: dict[str, Any],
    contexto: ContextoSeguranca,
) -> dict[str, Any]:
    if not isinstance(regra, dict):
        raise RegraInvalida("Regra deve ser um objeto.")

    action = _texto(
        regra.get("action"),
        "deny",
    ).lower()

    if action not in ACOES_SUPORTADAS:
        raise RegraInvalida(
            f"Ação não suportada: {action!r}."
        )

    proto = _texto(
        regra.get("proto"),
        "any",
    ).lower()

    if proto not in PROTOCOLOS_SUPORTADOS:
        raise RegraInvalida(
            f"Protocolo não suportado: {proto!r}."
        )

    direction = _texto(
        regra.get("dir"),
        "in",
    ).lower()

    if direction not in DIRECOES_SUPORTADAS:
        raise RegraInvalida(
            f"Direção não suportada: {direction!r}."
        )

    iface = _texto(
        regra.get("iface"),
        "any",
    )

    iface_fisica = resolver_interface(
        iface,
        contexto,
    )

    src = validar_endereco(
        regra.get("src"),
        permitir_any=True,
    )

    dst = validar_endereco(
        regra.get("dst"),
        permitir_any=True,
    )

    porta = validar_porta(
        regra.get("port"),
        proto=proto,
    )

    priority = _inteiro(
        regra.get("priority"),
        100,
    )

    if priority < 0 or priority > 100000:
        raise RegraInvalida(
            "Prioridade deve estar entre 0 e 100000."
        )

    desc = _texto(
        regra.get("desc"),
        "",
    )

    if len(desc) > 255:
        raise RegraInvalida(
            "Descrição excede 255 caracteres."
        )

    normalizada = {
        **regra,
        "action": _normalizar_acao(action),
        "proto": proto,
        "dir": direction,
        "iface": iface,
        "iface_fisica": iface_fisica,
        "src": src,
        "dst": dst,
        "port": porta,
        "priority": priority,
        "enabled": _bool(regra.get("enabled", True)),
        "log": _bool(regra.get("log", True)),
        "desc": desc,
    }

    validar_anti_lockout(
        normalizada,
        contexto,
    )

    return normalizada


# =============================================================================
# ANTI-LOCKOUT
# =============================================================================

def validar_anti_lockout(
    regra: dict[str, Any],
    contexto: ContextoSeguranca,
) -> None:
    """
    Bloqueia regras administrativas claramente perigosas.

    Não tenta substituir a proteção definitiva do ms_system.
    Esta é uma segunda camada defensiva para impedir regras óbvias de lockout.
    """
    action = _texto(
        regra.get("action"),
    ).lower()

    if action not in {
        "drop",
        "deny",
        "reject",
    }:
        return

    iface = _texto(
        regra.get("iface_fisica")
        or regra.get("iface"),
        "any",
    )

    src = _texto(
        regra.get("src"),
        "any",
    )

    dst = _texto(
        regra.get("dst"),
        "any",
    )

    port = _texto(
        regra.get("port"),
        "any",
    )

    # Bloqueio genérico entrando pela interface de gerenciamento.
    if (
        contexto.interface_mgmt
        and iface in {
            contexto.interface_mgmt,
            "MGMT",
            "any",
        }
        and src == "any"
        and dst == "any"
        and port == "any"
    ):
        raise OperacaoPerigosa(
            "Regra genérica de bloqueio pode derrubar o acesso "
            "pela interface de gerenciamento."
        )

    # Nunca permitir regra genérica contra o IP local da administração.
    if contexto.ip_local:
        if _endereco_contem(
            dst,
            contexto.ip_local,
        ):
            if port == "any":
                raise OperacaoPerigosa(
                    "Regra bloqueia genericamente o IP local do MoonShield."
                )

    # Protege a rede de gerenciamento quando detectável.
    if contexto.rede_mgmt:
        if src == "any" and _redes_sobrepoem(
            dst,
            contexto.rede_mgmt,
        ):
            raise OperacaoPerigosa(
                "Regra pode bloquear genericamente a rede de gerenciamento."
            )


def gerar_regras_sistema(
    contexto: ContextoSeguranca | dict[str, Any],
) -> list[str]:
    """
    Gera somente regras ESSENCIAIS da chain ms_system.

    Essas regras não pertencem ao usuário e não devem ser misturadas
    com ms_rules.

    A função retorna expressões nft, não executa comandos.
    """
    if not isinstance(contexto, ContextoSeguranca):
        contexto = detectar_contexto(contexto)

    regras = [
        "ct state established,related accept",
        'iifname "lo" accept',
    ]

    if contexto.interface_mgmt:
        regras.append(
            f'iifname "{contexto.interface_mgmt}" accept'
        )

    if contexto.ip_local:
        regras.append(
            f"ip daddr {contexto.ip_local} accept"
        )

    if contexto.rede_mgmt:
        regras.append(
            f"ip saddr {contexto.rede_mgmt} accept"
        )

    # O gateway não é sempre entrada administrativa, então não liberamos
    # genericamente qualquer tráfego para ele. Apenas mantemos informação
    # no contexto para verificações futuras.

    return _deduplicar(regras)


# =============================================================================
# VALIDAÇÃO DE SCRIPT NFT
# =============================================================================

def validar_script_nft(
    script: str,
    *,
    permitir_delete_table_moonshield: bool = False,
) -> ResultadoValidacao:
    """
    Validação textual defensiva antes de chamar `nft -c -f`.

    Não substitui o parser do nftables.
    O objetivo é rejeitar comandos globais ou objetos de terceiros.
    """
    erros: list[str] = []
    avisos: list[str] = []

    texto = str(script or "")

    if not texto.strip():
        return ResultadoValidacao(
            ok=False,
            erros=["Script nftables vazio."],
        )

    lower = texto.lower()

    for token in TOKENS_PROIBIDOS_SCRIPT:
        if token in lower:
            erros.append(
                f"Operação proibida encontrada no script: {token!r}."
            )

    # Nunca permitir flush global.
    if re.search(
        r"(?im)^\s*flush\s+ruleset\b",
        texto,
    ):
        erros.append(
            "MoonShield nunca pode executar 'flush ruleset'."
        )

    # Tabelas mencionadas explicitamente.
    for familia, tabela in re.findall(
        r"(?im)\b(?:add|delete|flush|list)?\s*table\s+([a-z0-9]+)\s+([A-Za-z0-9_.:-]+)",
        texto,
    ):
        if (
            familia != TABELA_FAMILIA
            or tabela != TABELA_NOME
        ):
            erros.append(
                f"Script tenta manipular tabela externa: "
                f"{familia} {tabela}."
            )

    if (
        not permitir_delete_table_moonshield
        and re.search(
            rf"(?im)^\s*delete\s+table\s+{re.escape(TABELA_FAMILIA)}\s+{re.escape(TABELA_NOME)}\b",
            texto,
        )
    ):
        erros.append(
            "Remoção da tabela MoonShield não é permitida nesta operação."
        )

    # Shell metacharacters são desnecessários em arquivos .nft e podem indicar
    # conteúdo inesperado. Comentários '#' são permitidos.
    if "\x00" in texto:
        erros.append(
            "Script contém byte NUL."
        )

    return ResultadoValidacao(
        ok=not erros,
        erros=erros,
        avisos=avisos,
        dados={
            "bytes": len(
                texto.encode(
                    "utf-8",
                    errors="replace",
                )
            ),
            "tabela": f"{TABELA_FAMILIA} {TABELA_NOME}",
        },
    )


# =============================================================================
# NFTABLES
# =============================================================================

def nft_disponivel() -> bool:
    return shutil.which("nft") is not None


def nft_versao() -> str:
    nft = shutil.which("nft")

    if not nft:
        return ""

    try:
        result = subprocess.run(
            [nft, "--version"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except Exception:
        return ""

    saida = (
        result.stdout
        or result.stderr
        or ""
    ).strip()

    return saida


def validar_com_nft(
    caminho_arquivo: str | os.PathLike[str],
) -> ResultadoValidacao:
    """
    Executa SOMENTE validação (`nft -c -f`).
    Não aplica configuração.
    """
    nft = shutil.which("nft")

    if not nft:
        return ResultadoValidacao(
            ok=False,
            erros=["Comando nft não encontrado."],
        )

    path = Path(caminho_arquivo)

    if not path.exists() or not path.is_file():
        return ResultadoValidacao(
            ok=False,
            erros=[f"Arquivo nft não existe: {path}."],
        )

    try:
        result = subprocess.run(
            [nft, "-c", "-f", str(path)],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ResultadoValidacao(
            ok=False,
            erros=["Validação nft excedeu 15 segundos."],
        )
    except Exception as exc:
        return ResultadoValidacao(
            ok=False,
            erros=[f"Falha ao executar nft -c: {exc}"],
        )

    stdout = (
        result.stdout
        or ""
    ).strip()

    stderr = (
        result.stderr
        or ""
    ).strip()

    return ResultadoValidacao(
        ok=result.returncode == 0,
        erros=(
            []
            if result.returncode == 0
            else [
                stderr
                or stdout
                or f"nft retornou código {result.returncode}."
            ]
        ),
        dados={
            "codigo": result.returncode,
            "stdout": stdout,
            "stderr": stderr,
        },
    )


# =============================================================================
# VALIDADORES DE CAMPOS
# =============================================================================

def resolver_interface(
    valor: Any,
    contexto: ContextoSeguranca,
) -> str:
    iface = _texto(
        valor,
        "any",
    )

    if iface == "any":
        return "any"

    mapa = contexto.iface_map()

    fisica = mapa.get(
        iface,
        iface,
    )

    if not _RE_IFACE.fullmatch(fisica):
        raise RegraInvalida(
            f"Nome de interface inválido: {fisica!r}."
        )

    if (
        contexto.interfaces_existentes
        and fisica not in contexto.interfaces_existentes
    ):
        raise RegraInvalida(
            f"Interface não existe no host: {fisica}."
        )

    return fisica


def validar_endereco(
    valor: Any,
    *,
    permitir_any: bool = True,
) -> str:
    texto = _texto(
        valor,
        "any" if permitir_any else "",
    )

    if permitir_any and texto.lower() == "any":
        return "any"

    if not texto:
        raise RegraInvalida(
            "Endereço IP/rede obrigatório."
        )

    # Suporta lista separada por vírgula para futura conversão em nft set.
    itens = [
        item.strip()
        for item in texto.split(",")
        if item.strip()
    ]

    if not itens:
        raise RegraInvalida(
            "Endereço IP/rede vazio."
        )

    normalizados: list[str] = []

    for item in itens:
        try:
            if "/" in item:
                rede = ipaddress.ip_network(
                    item,
                    strict=False,
                )
                normalizados.append(
                    str(rede)
                )
            else:
                ip = ipaddress.ip_address(
                    item
                )
                normalizados.append(
                    str(ip)
                )
        except ValueError:
            raise RegraInvalida(
                f"IP/rede inválido: {item!r}."
            ) from None

    return ",".join(
        normalizados
    )


def validar_porta(
    valor: Any,
    *,
    proto: str = "tcp",
) -> str:
    proto = _texto(
        proto,
        "any",
    ).lower()

    texto = _texto(
        valor,
        "any",
    ).lower()

    if proto in {
        "any",
        "icmp",
        "icmpv6",
    }:
        if texto not in {
            "",
            "any",
        }:
            raise RegraInvalida(
                f"Porta não é aplicável ao protocolo {proto}."
            )
        return "any"

    if texto in {
        "",
        "any",
    }:
        return "any"

    itens = [
        item.strip()
        for item in texto.split(",")
        if item.strip()
    ]

    if len(itens) > MAX_PORTAS_LISTA:
        raise RegraInvalida(
            f"Lista de portas excede {MAX_PORTAS_LISTA} itens."
        )

    normalizados: list[str] = []

    for item in itens:
        # Aceita "80", "80-90" e "80:90".
        if "-" in item or ":" in item:
            separador = (
                "-"
                if "-" in item
                else ":"
            )

            partes = item.split(
                separador,
                1,
            )

            if len(partes) != 2:
                raise RegraInvalida(
                    f"Range de porta inválido: {item!r}."
                )

            inicio = _porta_int(
                partes[0]
            )

            fim = _porta_int(
                partes[1]
            )

            if inicio > fim:
                raise RegraInvalida(
                    f"Range de porta invertido: {item!r}."
                )

            normalizados.append(
                f"{inicio}-{fim}"
            )

        else:
            normalizados.append(
                str(
                    _porta_int(
                        item
                    )
                )
            )

    return ",".join(
        normalizados
    )


# =============================================================================
# UTILITÁRIOS DE REDE
# =============================================================================

def _endereco_contem(
    regra_endereco: str,
    ip: str,
) -> bool:
    if regra_endereco == "any":
        return True

    try:
        alvo = ipaddress.ip_address(
            ip
        )
    except ValueError:
        return False

    for item in regra_endereco.split(","):
        item = item.strip()

        if not item:
            continue

        try:
            if "/" in item:
                if alvo in ipaddress.ip_network(
                    item,
                    strict=False,
                ):
                    return True
            elif alvo == ipaddress.ip_address(
                item
            ):
                return True
        except ValueError:
            continue

    return False


def _redes_sobrepoem(
    a: str,
    b: str,
) -> bool:
    if a == "any" or b == "any":
        return True

    try:
        rede_b = ipaddress.ip_network(
            b,
            strict=False,
        )
    except ValueError:
        return False

    for item in a.split(","):
        item = item.strip()

        try:
            # ip_network() aceita tanto host puro quanto CIDR:
            #   10.10.0.10 -> 10.10.0.10/32
            #   2001:db8::1 -> 2001:db8::1/128
            # Assim não precisamos montar /32 ou /128 manualmente e evitamos
            # o bug de transformar um IPv4 em algo como 10.10.0.10/128.
            rede_a = ipaddress.ip_network(
                item,
                strict=False,
            )

            if rede_a.overlaps(
                rede_b
            ):
                return True

        except ValueError:
            continue

    return False


# =============================================================================
# SANITIZAÇÃO
# =============================================================================

def sanitizar_comentario(
    valor: Any,
    *,
    limite: int = 160,
) -> str:
    """
    Sanitiza texto usado em `comment` de nftables.

    Não deixa aspas, barras de controle ou quebras de linha escaparem
    para uma expressão nft.
    """
    texto = _texto(
        valor,
        "",
    )

    texto = (
        texto
        .replace("\\", "/")
        .replace('"', "'")
        .replace("\r", " ")
        .replace("\n", " ")
        .replace("\t", " ")
    )

    texto = re.sub(
        r"\s+",
        " ",
        texto,
    ).strip()

    return texto[:limite]


def validar_nome_chain(
    nome: Any,
    *,
    somente_gerenciadas: bool = True,
) -> str:
    nome = _texto(
        nome,
    )

    if not re.fullmatch(
        r"^[A-Za-z0-9_]{1,64}$",
        nome,
    ):
        raise ErroSegurancaFirewall(
            "Nome de chain inválido."
        )

    if (
        somente_gerenciadas
        and nome not in CHAINS_GERENCIADAS
    ):
        raise OperacaoPerigosa(
            f"Chain não gerenciada pelo MoonShield: {nome}."
        )

    return nome


def validar_tabela(
    familia: Any,
    tabela: Any,
) -> tuple[str, str]:
    familia = _texto(
        familia,
    ).lower()

    tabela = _texto(
        tabela,
    )

    if (
        familia != TABELA_FAMILIA
        or tabela != TABELA_NOME
    ):
        raise OperacaoPerigosa(
            "O MoonShield só pode manipular "
            "'table inet moonshield'."
        )

    return familia, tabela


# =============================================================================
# CHECK DE AMBIENTE
# =============================================================================

def healthcheck_seguranca(
    cfg: dict[str, Any] | None = None,
) -> dict[str, Any]:
    contexto = detectar_contexto(
        cfg
    )

    topologia = validar_topologia(
        contexto,
        exigir_wan=False,
        exigir_lan=False,
        exigir_mgmt=False,
    )

    return {
        "ok": bool(
            nft_disponivel()
            and topologia.ok
        ),
        "versao": VERSAO_SEGURANCA,
        "nft_disponivel": nft_disponivel(),
        "nft_versao": nft_versao(),
        "root": (
            os.geteuid() == 0
            if hasattr(os, "geteuid")
            else False
        ),
        "topologia": topologia.para_dict(),
        "contexto": contexto.para_dict(),
        "protecoes_sistema": gerar_regras_sistema(
            contexto
        ),
    }


# =============================================================================
# HELPERS INTERNOS
# =============================================================================

def _texto(
    valor: Any,
    padrao: str = "",
) -> str:
    if valor is None:
        return padrao

    texto = str(
        valor
    ).strip()

    return texto if texto else padrao


def _inteiro(
    valor: Any,
    padrao: int,
) -> int:
    try:
        return int(
            valor
        )
    except (
        TypeError,
        ValueError,
    ):
        return padrao


def _bool(
    valor: Any,
) -> bool:
    if isinstance(
        valor,
        bool,
    ):
        return valor

    if valor is None:
        return False

    return str(
        valor
    ).strip().lower() in {
        "1",
        "true",
        "sim",
        "yes",
        "on",
        "ativo",
        "enabled",
    }


def _porta_int(
    valor: Any,
) -> int:
    try:
        porta = int(
            str(
                valor
            ).strip()
        )
    except (
        TypeError,
        ValueError,
    ):
        raise RegraInvalida(
            f"Porta inválida: {valor!r}."
        ) from None

    if not (
        PORTA_MIN
        <= porta
        <= PORTA_MAX
    ):
        raise RegraInvalida(
            f"Porta fora da faixa válida: {porta}."
        )

    return porta


def _normalizar_acao(
    valor: str,
) -> str:
    valor = valor.lower()

    if valor in {
        "allow",
        "accept",
    }:
        return "accept"

    if valor in {
        "deny",
        "drop",
    }:
        return "drop"

    if valor == "reject":
        return "reject"

    raise RegraInvalida(
        f"Ação desconhecida: {valor}."
    )


def _deduplicar(
    valores: Iterable[str],
) -> list[str]:
    vistos: set[str] = set()
    saida: list[str] = []

    for valor in valores:
        if valor in vistos:
            continue

        vistos.add(
            valor
        )

        saida.append(
            valor
        )

    return saida
