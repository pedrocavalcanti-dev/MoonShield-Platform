"""
MoonShield Agent — Rede / Backend Base
======================================

Contrato comum para backends de configuração de rede.

O backend NÃO decide:
- qual interface é WAN/LAN/MGMT/DMZ;
- regras de negócio;
- permissões de gerenciamento;
- se redes podem se sobrepor;
- política de NAT/firewall.

Essas decisões pertencem ao núcleo de Rede/Django.

O backend é responsável por:
- descobrir interfaces;
- consultar estado real;
- consultar perfis/conexões;
- preparar configuração;
- ativar/desativar interfaces;
- consultar/aplicar rotas;
- produzir/restaurar snapshots técnicos do backend.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


VERSAO_BACKEND_REDE = "1.0"


# =============================================================================
# EXCEÇÕES
# =============================================================================

class BackendRedeErro(RuntimeError):
    """Erro base de backend de rede."""

    def __init__(self, mensagem: str, *, codigo: str = "backend_rede_erro", detalhes: dict[str, Any] | None = None):
        super().__init__(mensagem)
        self.codigo = codigo
        self.detalhes = detalhes or {}


class BackendIndisponivel(BackendRedeErro):
    """Backend/binário necessário não está disponível."""

    def __init__(self, mensagem: str, *, detalhes: dict[str, Any] | None = None):
        super().__init__(mensagem, codigo="backend_indisponivel", detalhes=detalhes)


class ComandoRedeErro(BackendRedeErro):
    """Comando externo terminou com erro."""

    def __init__(
        self,
        mensagem: str,
        *,
        comando: list[str] | None = None,
        retorno: int | None = None,
        stdout: str = "",
        stderr: str = "",
        codigo: str = "comando_rede_falhou",
    ):
        detalhes = {
            "comando": comando or [],
            "retorno": retorno,
            "stdout": stdout,
            "stderr": stderr,
        }
        super().__init__(mensagem, codigo=codigo, detalhes=detalhes)
        self.comando = comando or []
        self.retorno = retorno
        self.stdout = stdout
        self.stderr = stderr


class InterfaceNaoEncontrada(BackendRedeErro):
    def __init__(self, interface: str):
        super().__init__(
            f"Interface de rede não encontrada: {interface}",
            codigo="interface_nao_encontrada",
            detalhes={"interface": interface},
        )


class ConexaoNaoEncontrada(BackendRedeErro):
    def __init__(self, conexao: str):
        super().__init__(
            f"Conexão de rede não encontrada: {conexao}",
            codigo="conexao_nao_encontrada",
            detalhes={"conexao": conexao},
        )


class ConfiguracaoBackendInvalida(BackendRedeErro):
    def __init__(self, mensagem: str, *, detalhes: dict[str, Any] | None = None):
        super().__init__(mensagem, codigo="configuracao_backend_invalida", detalhes=detalhes)


# =============================================================================
# RESULTADO DE COMANDO
# =============================================================================

@dataclass(slots=True, frozen=True)
class ResultadoComando:
    comando: tuple[str, ...]
    retorno: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.retorno == 0

    def para_dict(self) -> dict[str, Any]:
        return {
            "comando": list(self.comando),
            "retorno": self.retorno,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "ok": self.ok,
        }


# =============================================================================
# SNAPSHOT
# =============================================================================

@dataclass(slots=True)
class SnapshotBackend:
    backend: str
    interfaces: list[dict[str, Any]] = field(default_factory=list)
    metadados: dict[str, Any] = field(default_factory=dict)

    def para_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "interfaces": self.interfaces,
            "metadados": self.metadados,
        }


# =============================================================================
# NORMALIZAÇÃO
# =============================================================================

def normalizar_bool(valor: Any, padrao: bool = False) -> bool:
    if isinstance(valor, bool):
        return valor

    if isinstance(valor, (int, float)):
        return valor != 0

    if valor is None:
        return padrao

    texto = str(valor).strip().lower()

    if texto in {"1", "true", "yes", "sim", "on", "enabled", "ativo"}:
        return True

    if texto in {"0", "false", "no", "nao", "não", "off", "disabled", "inativo"}:
        return False

    return padrao


def normalizar_inteiro(valor: Any, padrao: int | None = None) -> int | None:
    if valor is None or valor == "":
        return padrao

    try:
        return int(valor)
    except (TypeError, ValueError):
        return padrao


def normalizar_configuracao_interface(configuracao: dict[str, Any] | None) -> dict[str, Any]:
    config = dict(configuracao or {})

    modo = str(config.get("ipv4_modo") or config.get("modo_ipv4") or "dhcp").strip().lower()

    aliases = {
        "auto": "dhcp",
        "automatic": "dhcp",
        "manual": "static",
        "estatico": "static",
        "estático": "static",
        "off": "disabled",
        "none": "disabled",
    }
    modo = aliases.get(modo, modo)

    if modo not in {"dhcp", "static", "disabled"}:
        raise ConfiguracaoBackendInvalida(
            f"Modo IPv4 não suportado: {modo}",
            detalhes={"ipv4_modo": modo},
        )

    endereco = config.get("ipv4_endereco")
    prefixo = normalizar_inteiro(config.get("ipv4_prefixo"))
    gateway = config.get("gateway")

    if modo == "static":
        if not endereco:
            raise ConfiguracaoBackendInvalida("Configuração IPv4 estática exige endereço.")

        if prefixo is None or not 0 <= prefixo <= 32:
            raise ConfiguracaoBackendInvalida(
                "Prefixo IPv4 inválido.",
                detalhes={"ipv4_prefixo": config.get("ipv4_prefixo")},
            )

    metrica = normalizar_inteiro(config.get("metrica"), 100)
    mtu = normalizar_inteiro(config.get("mtu"), 1500)

    if metrica is not None and metrica < 0:
        raise ConfiguracaoBackendInvalida("Métrica de rota inválida.", detalhes={"metrica": metrica})

    if mtu is not None and mtu < 576:
        raise ConfiguracaoBackendInvalida("MTU inválido.", detalhes={"mtu": mtu})

    return {
        "habilitada": normalizar_bool(config.get("habilitada"), True),
        "ipv4_modo": modo,
        "ipv4_endereco": str(endereco).strip() if endereco else None,
        "ipv4_prefixo": prefixo,
        "gateway": str(gateway).strip() if gateway else None,
        "rota_padrao": normalizar_bool(config.get("rota_padrao"), False),
        "metrica": metrica,
        "mtu": mtu,
    }


def normalizar_rota(rota: dict[str, Any]) -> dict[str, Any]:
    destino = str(rota.get("destino") or "").strip()

    if not destino:
        raise ConfiguracaoBackendInvalida("Rota estática sem destino.", detalhes={"rota": rota})

    interface = (
        rota.get("interface_nome")
        or rota.get("nome_interface")
        or rota.get("interface")
        or ""
    )

    if isinstance(interface, dict):
        interface = interface.get("nome") or interface.get("name") or ""

    gateway = rota.get("gateway")
    metrica = normalizar_inteiro(rota.get("metrica"), 100)

    return {
        "id": rota.get("id"),
        "nome": str(rota.get("nome") or "").strip(),
        "destino": destino,
        "gateway": str(gateway).strip() if gateway else None,
        "interface_nome": str(interface).strip(),
        "metrica": metrica,
        "ativa": normalizar_bool(rota.get("ativa"), True),
    }


# =============================================================================
# BACKEND BASE
# =============================================================================

class BackendRede(ABC):
    nome = "base"
    versao = VERSAO_BACKEND_REDE

    @abstractmethod
    def disponivel(self) -> bool:
        """Retorna True quando o backend pode ser utilizado."""

    @abstractmethod
    def status(self) -> dict[str, Any]:
        """Estado geral do backend."""

    @abstractmethod
    def listar_interfaces(self, *, incluir_loopback: bool = False) -> list[dict[str, Any]]:
        """Inventário das interfaces conhecidas pelo sistema."""

    def obter_interface(self, nome: str) -> dict[str, Any]:
        for interface in self.listar_interfaces(incluir_loopback=True):
            if interface.get("nome") == nome:
                return interface

        raise InterfaceNaoEncontrada(nome)

    @abstractmethod
    def listar_conexoes(self) -> list[dict[str, Any]]:
        """Lista perfis/conexões persistentes do backend."""

    @abstractmethod
    def obter_conexao(self, nome: str) -> dict[str, Any]:
        """Retorna detalhes técnicos de uma conexão."""

    @abstractmethod
    def conexao_para_interface(self, interface: str) -> str | None:
        """Retorna a conexão utilizada atualmente pela interface."""

    @abstractmethod
    def configurar_interface(
        self,
        interface: str,
        configuracao: dict[str, Any],
        *,
        conexao: str | None = None,
    ) -> dict[str, Any]:
        """Modifica o perfil persistente, sem obrigatoriamente ativá-lo."""

    @abstractmethod
    def ativar_interface(self, interface: str, *, conexao: str | None = None) -> dict[str, Any]:
        """Ativa uma conexão/interface."""

    @abstractmethod
    def desativar_interface(self, interface: str, *, conexao: str | None = None) -> dict[str, Any]:
        """Desativa uma conexão/interface."""

    def aplicar_interface(
        self,
        interface: str,
        configuracao: dict[str, Any],
        *,
        conexao: str | None = None,
    ) -> dict[str, Any]:
        config = normalizar_configuracao_interface(configuracao)
        resultado = self.configurar_interface(interface, config, conexao=conexao)

        conexao_final = resultado.get("conexao") or conexao

        if config["habilitada"]:
            ativacao = self.ativar_interface(interface, conexao=conexao_final)
        else:
            ativacao = self.desativar_interface(interface, conexao=conexao_final)

        return {
            "ok": True,
            "backend": self.nome,
            "interface": interface,
            "conexao": conexao_final,
            "configuracao": config,
            "perfil": resultado,
            "ativacao": ativacao,
        }

    @abstractmethod
    def obter_rotas(self) -> list[dict[str, Any]]:
        """Retorna as rotas IPv4 efetivamente instaladas."""

    @abstractmethod
    def configurar_rotas(
        self,
        rotas: list[dict[str, Any]],
        *,
        interfaces_alvo: list[str] | None = None,
    ) -> dict[str, Any]:
        """Grava rotas persistentes nos perfis do backend."""

    @abstractmethod
    def criar_snapshot_interface(self, interface: str, *, conexao: str | None = None) -> dict[str, Any]:
        """Snapshot suficiente para restaurar uma interface alterada."""

    @abstractmethod
    def restaurar_snapshot_interface(self, snapshot: dict[str, Any]) -> dict[str, Any]:
        """Restaura snapshot anteriormente criado."""

    def criar_snapshot(
        self,
        interfaces: list[str],
        *,
        conexoes: dict[str, str] | None = None,
    ) -> SnapshotBackend:
        conexoes = conexoes or {}
        snapshots = []

        for interface in interfaces:
            snapshots.append(
                self.criar_snapshot_interface(
                    interface,
                    conexao=conexoes.get(interface),
                )
            )

        return SnapshotBackend(
            backend=self.nome,
            interfaces=snapshots,
            metadados={"versao_backend": self.versao},
        )

    def restaurar_snapshot(self, snapshot: SnapshotBackend | dict[str, Any]) -> dict[str, Any]:
        dados = snapshot.para_dict() if isinstance(snapshot, SnapshotBackend) else snapshot

        if dados.get("backend") != self.nome:
            raise ConfiguracaoBackendInvalida(
                "Snapshot pertence a outro backend.",
                detalhes={
                    "backend_snapshot": dados.get("backend"),
                    "backend_atual": self.nome,
                },
            )

        resultados = []

        for item in dados.get("interfaces", []):
            resultados.append(self.restaurar_snapshot_interface(item))

        return {
            "ok": all(item.get("ok", False) for item in resultados),
            "backend": self.nome,
            "resultados": resultados,
        }