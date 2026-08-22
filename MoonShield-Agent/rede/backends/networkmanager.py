"""
MoonShield Agent — Rede / NetworkManager
========================================

Backend de Rede V1 para Debian 13 utilizando NetworkManager/nmcli.

Princípios:
- não decide WAN/LAN/MGMT;
- não executa comandos através de shell;
- não manipula nftables;
- não altera DNS;
- não modifica IPv6;
- não executa flush global;
- preserva perfis existentes sempre que possível;
- cria perfil MoonShield somente quando a interface não possui perfil;
- permite snapshot/restauração antes do Safe Apply.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from typing import Any

from .base import (
    BackendIndisponivel,
    BackendRede,
    ComandoRedeErro,
    ConexaoNaoEncontrada,
    ConfiguracaoBackendInvalida,
    InterfaceNaoEncontrada,
    ResultadoComando,
    normalizar_configuracao_interface,
    normalizar_rota,
)


VERSAO_NETWORKMANAGER_BACKEND = "1.0"

NMCLI_TIMEOUT = 20
IP_TIMEOUT = 10

CAMPOS_CONEXAO_SNAPSHOT = (
    "connection.id",
    "connection.uuid",
    "connection.type",
    "connection.interface-name",
    "connection.autoconnect",
    "ipv4.method",
    "ipv4.addresses",
    "ipv4.gateway",
    "ipv4.routes",
    "ipv4.route-metric",
    "ipv4.never-default",
    "802-3-ethernet.mtu",
)

PROPRIEDADES_RESTAURAVEIS = (
    "connection.interface-name",
    "connection.autoconnect",
    "ipv4.method",
    "ipv4.addresses",
    "ipv4.gateway",
    "ipv4.routes",
    "ipv4.route-metric",
    "ipv4.never-default",
    "802-3-ethernet.mtu",
)


class NetworkManagerBackend(BackendRede):
    nome = "networkmanager"
    versao = VERSAO_NETWORKMANAGER_BACKEND

    def __init__(self, *, nmcli: str | None = None, ip: str | None = None):
        self.nmcli = nmcli or shutil.which("nmcli")
        self.ip = ip or shutil.which("ip")

    # =========================================================================
    # COMANDOS
    # =========================================================================

    def _executar(
        self,
        comando: list[str],
        *,
        timeout: int = NMCLI_TIMEOUT,
        verificar: bool = True,
        input_text: str | None = None,
    ) -> ResultadoComando:
        try:
            processo = subprocess.run(
                comando,
                input=input_text,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            raise BackendIndisponivel(
                f"Comando não encontrado: {comando[0]}",
                detalhes={"comando": comando},
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise ComandoRedeErro(
                "Comando de rede excedeu o tempo limite.",
                comando=comando,
                retorno=None,
                stdout=exc.stdout or "",
                stderr=exc.stderr or "",
                codigo="comando_timeout",
            ) from exc
        except OSError as exc:
            raise ComandoRedeErro(
                f"Não foi possível executar comando de rede: {exc}",
                comando=comando,
                codigo="comando_execucao_falhou",
            ) from exc

        resultado = ResultadoComando(
            comando=tuple(comando),
            retorno=processo.returncode,
            stdout=(processo.stdout or "").strip(),
            stderr=(processo.stderr or "").strip(),
        )

        if verificar and not resultado.ok:
            raise ComandoRedeErro(
                resultado.stderr or resultado.stdout or "Comando de rede falhou.",
                comando=comando,
                retorno=resultado.retorno,
                stdout=resultado.stdout,
                stderr=resultado.stderr,
            )

        return resultado

    def _nmcli(self, *args: str, verificar: bool = True, timeout: int = NMCLI_TIMEOUT) -> ResultadoComando:
        if not self.nmcli:
            raise BackendIndisponivel("nmcli não está disponível no sistema.")

        return self._executar([self.nmcli, *args], verificar=verificar, timeout=timeout)

    def _ip(self, *args: str, verificar: bool = True) -> ResultadoComando:
        if not self.ip:
            raise BackendIndisponivel("Comando ip não está disponível no sistema.")

        return self._executar([self.ip, *args], verificar=verificar, timeout=IP_TIMEOUT)

    # =========================================================================
    # BACKEND
    # =========================================================================

    def disponivel(self) -> bool:
        if not self.nmcli:
            return False

        try:
            resultado = self._nmcli("-t", "-f", "STATE", "general", "status", verificar=False)
            return resultado.ok
        except Exception:
            return False

    def status(self) -> dict[str, Any]:
        if not self.nmcli:
            return {
                "backend": self.nome,
                "disponivel": False,
                "ativo": False,
                "erro": "nmcli não encontrado.",
            }

        estado = None
        conectividade = None
        versao = None

        geral = self._nmcli("-t", "--escape", "yes", "-f", "STATE,CONNECTIVITY", "general", "status", verificar=False)

        if geral.ok and geral.stdout:
            campos = self._split_terse(geral.stdout.splitlines()[0])

            if campos:
                estado = campos[0] or None

            if len(campos) > 1:
                conectividade = campos[1] or None

        versao_resultado = self._nmcli("--version", verificar=False)

        if versao_resultado.ok:
            match = re.search(r"(\d+(?:\.\d+)+)", versao_resultado.stdout)

            if match:
                versao = match.group(1)

        return {
            "backend": self.nome,
            "versao_backend": self.versao,
            "disponivel": geral.ok,
            "ativo": estado not in {None, "asleep", "disconnected", "unknown"},
            "estado": estado,
            "conectividade": conectividade,
            "networkmanager_versao": versao,
            "nmcli": self.nmcli,
            "ip": self.ip,
        }

    # =========================================================================
    # TERSE PARSER
    # =========================================================================

    @staticmethod
    def _split_terse(linha: str) -> list[str]:
        partes = []
        atual = []
        escapado = False

        for caractere in linha:
            if escapado:
                atual.append(caractere)
                escapado = False
                continue

            if caractere == "\\":
                escapado = True
                continue

            if caractere == ":":
                partes.append("".join(atual))
                atual = []
                continue

            atual.append(caractere)

        if escapado:
            atual.append("\\")

        partes.append("".join(atual))
        return partes

    @staticmethod
    def _split_primeiro_terse(linha: str) -> tuple[str, str]:
        atual = []
        escapado = False

        for indice, caractere in enumerate(linha):
            if escapado:
                atual.append(caractere)
                escapado = False
                continue

            if caractere == "\\":
                escapado = True
                continue

            if caractere == ":":
                return "".join(atual), NetworkManagerBackend._unescape_terse(linha[indice + 1:])

            atual.append(caractere)

        return NetworkManagerBackend._unescape_terse(linha), ""

    @staticmethod
    def _unescape_terse(valor: str) -> str:
        resultado = []
        escapado = False

        for caractere in valor:
            if escapado:
                resultado.append(caractere)
                escapado = False
            elif caractere == "\\":
                escapado = True
            else:
                resultado.append(caractere)

        if escapado:
            resultado.append("\\")

        return "".join(resultado)

    # =========================================================================
    # IP JSON
    # =========================================================================

    def _ip_json(self, *args: str) -> list[dict[str, Any]]:
        resultado = self._ip("-j", *args)

        if not resultado.stdout:
            return []

        try:
            dados = json.loads(resultado.stdout)
        except json.JSONDecodeError as exc:
            raise ComandoRedeErro(
                "O comando ip retornou JSON inválido.",
                comando=list(resultado.comando),
                retorno=resultado.retorno,
                stdout=resultado.stdout,
                stderr=resultado.stderr,
                codigo="ip_json_invalido",
            ) from exc

        return dados if isinstance(dados, list) else []

    # =========================================================================
    # CONEXÕES
    # =========================================================================

    def listar_conexoes(self) -> list[dict[str, Any]]:
        resultado = self._nmcli(
            "-t",
            "--escape",
            "yes",
            "-f",
            "NAME,UUID,TYPE,DEVICE,AUTOCONNECT",
            "connection",
            "show",
        )

        conexoes = []

        for linha in resultado.stdout.splitlines():
            if not linha.strip():
                continue

            campos = self._split_terse(linha)

            while len(campos) < 5:
                campos.append("")

            conexoes.append({
                "nome": campos[0],
                "uuid": campos[1],
                "tipo": campos[2],
                "interface": campos[3] or None,
                "autoconnect": campos[4].lower() == "yes",
                "ativa": bool(campos[3]),
            })

        return conexoes

    def _conexao_existe(self, conexao: str) -> bool:
        return any(item["nome"] == conexao for item in self.listar_conexoes())

    def conexao_para_interface(self, interface: str) -> str | None:
        resultado = self._nmcli(
            "-t",
            "--escape",
            "yes",
            "-f",
            "DEVICE,STATE,CONNECTION",
            "device",
            "status",
        )

        fallback = None

        for linha in resultado.stdout.splitlines():
            campos = self._split_terse(linha)

            while len(campos) < 3:
                campos.append("")

            if campos[0] != interface:
                continue

            conexao = campos[2]

            if conexao and conexao != "--":
                return conexao

        for conexao in self.listar_conexoes():
            if conexao.get("interface") == interface:
                fallback = conexao["nome"]

                if conexao.get("ativa"):
                    return fallback

        return fallback

    def obter_conexao(self, nome: str) -> dict[str, Any]:
        if not self._conexao_existe(nome):
            raise ConexaoNaoEncontrada(nome)

        campos = ",".join(CAMPOS_CONEXAO_SNAPSHOT)

        resultado = self._nmcli(
            "-t",
            "--escape",
            "yes",
            "-f",
            campos,
            "connection",
            "show",
            nome,
        )

        dados: dict[str, Any] = {}

        for linha in resultado.stdout.splitlines():
            if not linha:
                continue

            chave, valor = self._split_primeiro_terse(linha)
            dados[chave] = valor

        return {
            "nome": dados.get("connection.id") or nome,
            "uuid": dados.get("connection.uuid") or None,
            "tipo": dados.get("connection.type") or None,
            "interface": dados.get("connection.interface-name") or None,
            "autoconnect": dados.get("connection.autoconnect", "").lower() == "yes",
            "ipv4": {
                "method": dados.get("ipv4.method") or None,
                "addresses": dados.get("ipv4.addresses") or "",
                "gateway": dados.get("ipv4.gateway") or "",
                "routes": dados.get("ipv4.routes") or "",
                "route_metric": self._parse_int(dados.get("ipv4.route-metric")),
                "never_default": dados.get("ipv4.never-default", "").lower() == "yes",
            },
            "mtu": self._parse_int(dados.get("802-3-ethernet.mtu")),
            "raw": dados,
        }

    # =========================================================================
    # INVENTÁRIO
    # =========================================================================

    def listar_interfaces(self, *, incluir_loopback: bool = False) -> list[dict[str, Any]]:
        if not self.disponivel():
            raise BackendIndisponivel("NetworkManager não está disponível.")

        links = {item.get("ifname"): item for item in self._ip_json("address", "show") if item.get("ifname")}
        rotas = self.obter_rotas()

        nm_resultado = self._nmcli(
            "-t",
            "--escape",
            "yes",
            "-f",
            "DEVICE,TYPE,STATE,CONNECTION",
            "device",
            "status",
        )

        nm_devices: dict[str, dict[str, Any]] = {}

        for linha in nm_resultado.stdout.splitlines():
            campos = self._split_terse(linha)

            while len(campos) < 4:
                campos.append("")

            nm_devices[campos[0]] = {
                "tipo": campos[1],
                "estado_nm": campos[2],
                "conexao": campos[3] if campos[3] and campos[3] != "--" else None,
            }

        nomes = set(links) | set(nm_devices)
        interfaces = []

        for nome in sorted(nomes):
            if not incluir_loopback and nome == "lo":
                continue

            link = links.get(nome, {})
            nm = nm_devices.get(nome, {})

            enderecos_ipv4 = []
            enderecos_ipv6 = []

            for endereco in link.get("addr_info", []):
                familia = endereco.get("family")
                item = {
                    "endereco": endereco.get("local"),
                    "prefixo": endereco.get("prefixlen"),
                    "escopo": endereco.get("scope"),
                    "dinamico": "dynamic" in endereco.get("flags", []),
                }

                if familia == "inet":
                    enderecos_ipv4.append(item)
                elif familia == "inet6":
                    enderecos_ipv6.append(item)

            ipv4_principal = self._selecionar_ipv4(enderecos_ipv4)
            rota_default = next((rota for rota in rotas if rota.get("interface") == nome and rota.get("default")), None)

            flags = set(link.get("flags") or [])
            operstate = str(link.get("operstate") or "").upper()
            carrier = "LOWER_UP" in flags or operstate == "UP"

            interfaces.append({
                "nome": nome,
                "indice": link.get("ifindex"),
                "tipo": nm.get("tipo") or link.get("link_type") or "unknown",
                "backend": self.nome,
                "estado": nm.get("estado_nm") or operstate.lower(),
                "estado_link": "up" if carrier else "down",
                "carrier": carrier,
                "administrativamente_up": "UP" in flags,
                "mac_address": link.get("address"),
                "broadcast": link.get("broadcast"),
                "mtu_atual": link.get("mtu"),
                "conexao": nm.get("conexao"),
                "ipv4": enderecos_ipv4,
                "ipv6": enderecos_ipv6,
                "ipv4_atual": ipv4_principal.get("endereco") if ipv4_principal else None,
                "prefixo_atual": ipv4_principal.get("prefixo") if ipv4_principal else None,
                "gateway_atual": rota_default.get("gateway") if rota_default else None,
                "rota_default": bool(rota_default),
                "metrica_atual": rota_default.get("metrica") if rota_default else None,
                "gerenciavel": nome != "lo" and nm.get("tipo") not in {"loopback"},
            })

        return interfaces

    def obter_interface(self, nome: str) -> dict[str, Any]:
        for interface in self.listar_interfaces(incluir_loopback=True):
            if interface["nome"] == nome:
                return interface

        raise InterfaceNaoEncontrada(nome)

    @staticmethod
    def _selecionar_ipv4(enderecos: list[dict[str, Any]]) -> dict[str, Any] | None:
        if not enderecos:
            return None

        global_scope = next((item for item in enderecos if item.get("escopo") == "global"), None)
        return global_scope or enderecos[0]

    # =========================================================================
    # PERFIL
    # =========================================================================

    @staticmethod
    def gerar_nome_conexao(interface: str) -> str:
        seguro = re.sub(r"[^A-Za-z0-9_.-]", "-", interface).strip("-")
        return f"moonshield-{seguro or 'interface'}"

    def _garantir_conexao(self, interface: str, conexao: str | None = None) -> tuple[str, bool]:
        self.obter_interface(interface)

        if conexao:
            if not self._conexao_existe(conexao):
                raise ConexaoNaoEncontrada(conexao)

            return conexao, False

        encontrada = self.conexao_para_interface(interface)

        if encontrada:
            return encontrada, False

        interface_info = self.obter_interface(interface)
        tipo = str(interface_info.get("tipo") or "").lower()

        if tipo not in {"ethernet", "802-3-ethernet"}:
            raise ConfiguracaoBackendInvalida(
                "A interface não possui conexão existente e seu tipo ainda não pode ser criado automaticamente.",
                detalhes={"interface": interface, "tipo": tipo},
            )

        nome = self.gerar_nome_conexao(interface)

        if self._conexao_existe(nome):
            self._nmcli("connection", "modify", nome, "connection.interface-name", interface)
            return nome, False

        self._nmcli(
            "connection",
            "add",
            "type",
            "ethernet",
            "ifname",
            interface,
            "con-name",
            nome,
        )

        return nome, True

    # =========================================================================
    # CONFIGURAÇÃO DE INTERFACE
    # =========================================================================

    def configurar_interface(
        self,
        interface: str,
        configuracao: dict[str, Any],
        *,
        conexao: str | None = None,
    ) -> dict[str, Any]:
        config = normalizar_configuracao_interface(configuracao)
        interface_info = self.obter_interface(interface)
        conexao_final, criada = self._garantir_conexao(interface, conexao)

        argumentos = [
            "connection",
            "modify",
            conexao_final,
            "connection.interface-name",
            interface,
            "connection.autoconnect",
            self._yes_no(config["habilitada"]),
        ]

        modo = config["ipv4_modo"]

        if modo == "dhcp":
            argumentos.extend([
                "ipv4.method", "auto",
                "ipv4.addresses", "",
                "ipv4.gateway", "",
                "ipv4.never-default", self._yes_no(not config["rota_padrao"]),
            ])

        elif modo == "static":
            endereco = f"{config['ipv4_endereco']}/{config['ipv4_prefixo']}"

            argumentos.extend([
                "ipv4.method", "manual",
                "ipv4.addresses", endereco,
                "ipv4.gateway", config["gateway"] or "",
                "ipv4.never-default", self._yes_no(not config["rota_padrao"]),
            ])

        elif modo == "disabled":
            argumentos.extend([
                "ipv4.method", "disabled",
                "ipv4.addresses", "",
                "ipv4.gateway", "",
                "ipv4.never-default", "yes",
            ])

        if config["metrica"] is not None and modo != "disabled":
            argumentos.extend(["ipv4.route-metric", str(config["metrica"])])

        tipo = str(interface_info.get("tipo") or "").lower()

        if config["mtu"] is not None and tipo in {"ethernet", "802-3-ethernet"}:
            argumentos.extend(["802-3-ethernet.mtu", str(config["mtu"])])

        self._nmcli(*argumentos)

        return {
            "ok": True,
            "backend": self.nome,
            "interface": interface,
            "conexao": conexao_final,
            "conexao_criada": criada,
            "configuracao": config,
            "conexao_atual": self.obter_conexao(conexao_final),
        }

    # =========================================================================
    # ATIVAÇÃO
    # =========================================================================

    def ativar_interface(self, interface: str, *, conexao: str | None = None) -> dict[str, Any]:
        self.obter_interface(interface)

        conexao_final = conexao or self.conexao_para_interface(interface)

        if not conexao_final:
            raise ConexaoNaoEncontrada(f"interface:{interface}")

        resultado = self._nmcli(
            "connection",
            "up",
            "id",
            conexao_final,
            "ifname",
            interface,
            timeout=45,
        )

        return {
            "ok": True,
            "backend": self.nome,
            "interface": interface,
            "conexao": conexao_final,
            "stdout": resultado.stdout,
        }

    def desativar_interface(self, interface: str, *, conexao: str | None = None) -> dict[str, Any]:
        self.obter_interface(interface)

        resultado = self._nmcli("device", "disconnect", interface, verificar=False, timeout=30)

        if not resultado.ok:
            texto = f"{resultado.stdout}\n{resultado.stderr}".lower()

            if "not active" not in texto and "not connected" not in texto and "disconnected" not in texto:
                raise ComandoRedeErro(
                    resultado.stderr or resultado.stdout or "Falha ao desativar interface.",
                    comando=list(resultado.comando),
                    retorno=resultado.retorno,
                    stdout=resultado.stdout,
                    stderr=resultado.stderr,
                )

        return {
            "ok": True,
            "backend": self.nome,
            "interface": interface,
            "conexao": conexao or self.conexao_para_interface(interface),
        }

    # =========================================================================
    # ROTAS REAIS
    # =========================================================================

    def obter_rotas(self) -> list[dict[str, Any]]:
        rotas_raw = self._ip_json("-4", "route", "show", "table", "main")
        rotas = []

        for rota in rotas_raw:
            destino = rota.get("dst") or "default"
            interface = rota.get("dev")
            gateway = rota.get("gateway")
            metrica = rota.get("metric")

            rotas.append({
                "destino": destino,
                "gateway": gateway,
                "interface": interface,
                "metrica": metrica,
                "protocolo": rota.get("protocol"),
                "escopo": rota.get("scope"),
                "origem_preferida": rota.get("prefsrc"),
                "default": destino == "default" or destino == "0.0.0.0/0",
                "raw": rota,
            })

        return rotas

    # =========================================================================
    # ROTAS PERSISTENTES
    # =========================================================================

    def configurar_rotas(
        self,
        rotas: list[dict[str, Any]],
        *,
        interfaces_alvo: list[str] | None = None,
    ) -> dict[str, Any]:
        normalizadas = [normalizar_rota(rota) for rota in rotas]
        normalizadas = [rota for rota in normalizadas if rota["ativa"]]

        agrupadas: dict[str, list[dict[str, Any]]] = {}

        for rota in normalizadas:
            interface = rota["interface_nome"]

            if not interface:
                raise ConfiguracaoBackendInvalida(
                    "Rota estática precisa informar a interface.",
                    detalhes={"rota": rota},
                )

            self.obter_interface(interface)
            agrupadas.setdefault(interface, []).append(rota)

        alvos = set(interfaces_alvo or []) | set(agrupadas)
        resultados = []

        for interface in sorted(alvos):
            self.obter_interface(interface)

            conexao = self.conexao_para_interface(interface)

            if not conexao:
                conexao, _ = self._garantir_conexao(interface)

            rotas_interface = agrupadas.get(interface, [])
            valor = ",".join(self._formatar_rota_nmcli(rota) for rota in rotas_interface)

            self._nmcli("connection", "modify", conexao, "ipv4.routes", valor)

            resultados.append({
                "interface": interface,
                "conexao": conexao,
                "rotas": rotas_interface,
            })

        return {
            "ok": True,
            "backend": self.nome,
            "total": len(normalizadas),
            "interfaces": resultados,
        }

    @staticmethod
    def _formatar_rota_nmcli(rota: dict[str, Any]) -> str:
        destino = rota["destino"]
        gateway = rota.get("gateway")
        metrica = rota.get("metrica")

        if gateway and metrica is not None:
            return f"{destino} {gateway} {metrica}"

        if gateway:
            return f"{destino} {gateway}"

        return destino

    # =========================================================================
    # SNAPSHOT
    # =========================================================================

    def criar_snapshot_interface(self, interface: str, *, conexao: str | None = None) -> dict[str, Any]:
        interface_estado = self.obter_interface(interface)
        conexao_ativa = self._conexao_ativa_interface(interface)
        conexao_final = conexao or self.conexao_para_interface(interface)

        conexao_existe = bool(conexao_final and self._conexao_existe(conexao_final))
        conexao_dados = self.obter_conexao(conexao_final) if conexao_existe else None

        return {
            "backend": self.nome,
            "interface": interface,
            "interface_estado": interface_estado,
            "conexao": conexao_final,
            "conexao_existia": conexao_existe,
            "conexao_ativa": conexao_ativa,
            "conexao_dados": conexao_dados,
        }

    def restaurar_snapshot_interface(self, snapshot: dict[str, Any]) -> dict[str, Any]:
        if snapshot.get("backend") != self.nome:
            raise ConfiguracaoBackendInvalida(
                "Snapshot não pertence ao backend NetworkManager.",
                detalhes={"backend": snapshot.get("backend")},
            )

        interface = str(snapshot.get("interface") or "").strip()

        if not interface:
            raise ConfiguracaoBackendInvalida("Snapshot sem interface.")

        conexao = snapshot.get("conexao")
        existia = bool(snapshot.get("conexao_existia"))
        dados = snapshot.get("conexao_dados") or {}
        ativa_antes = snapshot.get("conexao_ativa")

        if not existia:
            atual = self.conexao_para_interface(interface)

            if atual and atual.startswith("moonshield-"):
                self._nmcli("connection", "delete", atual, verificar=False)

            return {
                "ok": True,
                "backend": self.nome,
                "interface": interface,
                "acao": "perfil_criado_removido",
            }

        if not conexao:
            raise ConfiguracaoBackendInvalida("Snapshot indica conexão existente, mas não informa seu nome.")

        if not self._conexao_existe(conexao):
            raise ConexaoNaoEncontrada(conexao)

        raw = dados.get("raw") or {}
        argumentos = ["connection", "modify", conexao]

        for propriedade in PROPRIEDADES_RESTAURAVEIS:
            if propriedade not in raw:
                continue

            argumentos.extend([propriedade, raw.get(propriedade) or ""])

        if len(argumentos) > 3:
            self._nmcli(*argumentos)

        if ativa_antes:
            self._nmcli(
                "connection",
                "up",
                "id",
                ativa_antes,
                "ifname",
                interface,
                timeout=45,
            )
        else:
            self._nmcli("device", "disconnect", interface, verificar=False, timeout=30)

        return {
            "ok": True,
            "backend": self.nome,
            "interface": interface,
            "conexao": conexao,
            "acao": "snapshot_restaurado",
        }

    # =========================================================================
    # CONEXÃO ATIVA
    # =========================================================================

    def _conexao_ativa_interface(self, interface: str) -> str | None:
        resultado = self._nmcli(
            "-t",
            "--escape",
            "yes",
            "-f",
            "NAME,DEVICE",
            "connection",
            "show",
            "--active",
            verificar=False,
        )

        if not resultado.ok:
            return None

        for linha in resultado.stdout.splitlines():
            campos = self._split_terse(linha)

            while len(campos) < 2:
                campos.append("")

            if campos[1] == interface:
                return campos[0]

        return None

    # =========================================================================
    # DIAGNÓSTICO BÁSICO
    # =========================================================================

    def diagnostico(self) -> dict[str, Any]:
        checks = []

        checks.append({
            "codigo": "networkmanager_disponivel",
            "nome": "NetworkManager disponível",
            "ok": self.disponivel(),
            "mensagem": "NetworkManager respondeu ao nmcli." if self.disponivel() else "NetworkManager não respondeu ao nmcli.",
        })

        checks.append({
            "codigo": "nmcli_binario",
            "nome": "nmcli",
            "ok": bool(self.nmcli),
            "mensagem": self.nmcli or "Binário nmcli não encontrado.",
        })

        checks.append({
            "codigo": "iproute2_binario",
            "nome": "iproute2",
            "ok": bool(self.ip),
            "mensagem": self.ip or "Comando ip não encontrado.",
        })

        try:
            interfaces = self.listar_interfaces()
            checks.append({
                "codigo": "interfaces",
                "nome": "Inventário de interfaces",
                "ok": True,
                "mensagem": f"{len(interfaces)} interface(s) detectada(s).",
                "detalhes": {"interfaces": [item["nome"] for item in interfaces]},
            })
        except Exception as exc:
            checks.append({
                "codigo": "interfaces",
                "nome": "Inventário de interfaces",
                "ok": False,
                "mensagem": str(exc),
            })

        try:
            rotas = self.obter_rotas()
            defaults = [rota for rota in rotas if rota["default"]]

            checks.append({
                "codigo": "rota_default",
                "nome": "Rota padrão IPv4",
                "ok": bool(defaults),
                "mensagem": f"{len(defaults)} rota(s) padrão encontrada(s)." if defaults else "Nenhuma rota padrão IPv4 encontrada.",
                "detalhes": {"rotas": defaults},
            })
        except Exception as exc:
            checks.append({
                "codigo": "rota_default",
                "nome": "Rota padrão IPv4",
                "ok": False,
                "mensagem": str(exc),
            })

        return {
            "backend": self.nome,
            "saudavel": all(check["ok"] for check in checks),
            "checks": checks,
        }

    # =========================================================================
    # HELPERS
    # =========================================================================

    @staticmethod
    def _yes_no(valor: bool) -> str:
        return "yes" if valor else "no"

    @staticmethod
    def _parse_int(valor: Any) -> int | None:
        if valor is None or valor == "":
            return None

        try:
            return int(valor)
        except (TypeError, ValueError):
            return None


# =============================================================================
# FACTORY
# =============================================================================

def criar_backend_networkmanager() -> NetworkManagerBackend:
    backend = NetworkManagerBackend()

    if not backend.disponivel():
        raise BackendIndisponivel(
            "NetworkManager/nmcli não está disponível ou não está ativo.",
            detalhes={
                "nmcli": backend.nmcli,
                "ip": backend.ip,
            },
        )

    return backend