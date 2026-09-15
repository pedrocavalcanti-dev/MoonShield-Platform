"""Bootstrap local e idempotente do AdGuard Home da appliance MoonShield."""

from __future__ import annotations

import errno
import grp
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from .adguard_client import AdGuardClient, AdGuardError, AdGuardHTTPError


SECRET_DIR_PADRAO = Path("/etc/moonshield/secrets")
SECRET_ADGUARD_PADRAO = SECRET_DIR_PADRAO / "adguard"
USUARIO_INTEGRACAO = "moonshield"
ENDERECO_ADMIN_PADRAO = "127.0.0.1:3000"
PORTA_DNS_PADRAO = 53
SERVICO_ADGUARD_PADRAO = "AdGuardHome.service"

_LAYOUTS_CONHECIDOS = (
    Path("/opt/AdGuardHome/AdGuardHome"),
    Path("/opt/moonshield-system/services/adguard/AdGuardHome/AdGuardHome"),
)
_CONFIGS_ALTERNATIVOS = (Path("/etc/AdGuardHome.yaml"),)
_PAPEIS_REDE = ("wan", "lan", "mgmt", "dmz", "custom", "unassigned")


class AdGuardBootstrapError(RuntimeError):
    """Falha de bootstrap que pode ser exibida sem revelar o secret."""


@dataclass(frozen=True)
class CaminhosAdGuard:
    binario: Path
    diretorio_trabalho: Path
    configuracao: Path
    diretorio_dados: Path
    servico: str = SERVICO_ADGUARD_PADRAO


def descobrir_adguard(*, obrigatorio: bool = True) -> CaminhosAdGuard | None:
    """Descobre o layout instalado sem assumir um único caminho de ISO."""
    for binario in _LAYOUTS_CONHECIDOS:
        if not binario.is_file():
            continue

        diretorio = binario.parent
        candidatos_config = (
            diretorio / "AdGuardHome.yaml",
            * _CONFIGS_ALTERNATIVOS,
        )
        configuracao = next(
            (caminho for caminho in candidatos_config if caminho.is_file()),
            candidatos_config[0],
        )
        return CaminhosAdGuard(
            binario=binario,
            diretorio_trabalho=diretorio,
            configuracao=configuracao,
            diretorio_dados=diretorio / "data",
        )

    if obrigatorio:
        raise AdGuardBootstrapError(
            "Binário do AdGuard Home não encontrado nos layouts oficiais da appliance."
        )
    return None


def _valor_yaml(valor: str) -> str:
    return valor.strip().strip("'\"")


def obter_url_admin(paths: CaminhosAdGuard) -> str:
    """Lê apenas o endereço HTTP do YAML, com suporte ao layout 0.107.x."""
    if not paths.configuracao.is_file():
        return f"http://{ENDERECO_ADMIN_PADRAO}"

    try:
        linhas = paths.configuracao.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise AdGuardBootstrapError("Não foi possível ler a configuração do AdGuard Home.") from exc

    http_indent: int | None = None
    bind_host = ""
    bind_port = ""
    for linha in linhas:
        sem_comentario = linha.split("#", 1)[0].rstrip()
        if not sem_comentario:
            continue

        indentacao = len(sem_comentario) - len(sem_comentario.lstrip())
        texto = sem_comentario.strip()
        if texto == "http:":
            http_indent = indentacao
            continue
        if http_indent is not None and indentacao <= http_indent:
            http_indent = None
        if http_indent is not None:
            match = re.match(r"address:\s*(.+)$", texto)
            if match:
                endereco = _valor_yaml(match.group(1))
                if endereco:
                    return f"http://{endereco}"
        if texto.startswith("bind_host:"):
            bind_host = _valor_yaml(texto.split(":", 1)[1])
        elif texto.startswith("bind_port:"):
            bind_port = _valor_yaml(texto.split(":", 1)[1])

    if bind_host and bind_port:
        return f"http://{bind_host}:{bind_port}"
    return f"http://{ENDERECO_ADMIN_PADRAO}"


def obter_porta_admin(paths: CaminhosAdGuard) -> int:
    """Preserva a porta administrativa instalada, mantendo o bind local."""
    try:
        porta = urlparse(obter_url_admin(paths)).port
    except ValueError:
        porta = None
    return porta or 3000


def obter_url_admin_local(paths: CaminhosAdGuard) -> str:
    return f"http://127.0.0.1:{obter_porta_admin(paths)}"


def carregar_secret(caminho: Path = SECRET_ADGUARD_PADRAO) -> dict[str, str]:
    """Carrega a credencial local e valida permissões antes de utilizá-la."""
    try:
        modo = stat.S_IMODE(caminho.stat().st_mode)
        if modo & 0o007:
            raise AdGuardBootstrapError("Secret do AdGuard possui permissões públicas.")
        dados = json.loads(caminho.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AdGuardBootstrapError("Secret interno do AdGuard não foi encontrado.") from exc
    except (OSError, ValueError, TypeError) as exc:
        raise AdGuardBootstrapError("Secret interno do AdGuard é inválido.") from exc

    usuario = dados.get("username") if isinstance(dados, dict) else None
    senha = dados.get("password") if isinstance(dados, dict) else None
    if usuario != USUARIO_INTEGRACAO or not isinstance(senha, str) or len(senha) < 32:
        raise AdGuardBootstrapError("Secret interno do AdGuard é inválido.")
    return {"username": usuario, "password": senha}


def garantir_secret(
    caminho: Path = SECRET_ADGUARD_PADRAO,
    *,
    grupo: str | None = "moonshield",
) -> dict[str, str]:
    """Cria uma credencial por appliance uma única vez, sem regenerá-la."""
    if caminho.exists():
        return carregar_secret(caminho)

    caminho.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    if grupo:
        try:
            os.chown(caminho.parent, 0, grp.getgrnam(grupo).gr_gid)
        except (KeyError, PermissionError, OSError) as exc:
            raise AdGuardBootstrapError("Não foi possível proteger o diretório de secrets.") from exc

    segredo = {
        "username": USUARIO_INTEGRACAO,
        "password": secrets.token_urlsafe(48),
    }
    conteudo = json.dumps(segredo, separators=(",", ":"))
    try:
        descritor = os.open(caminho, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
        with os.fdopen(descritor, "w", encoding="utf-8") as arquivo:
            arquivo.write(conteudo)
        if grupo:
            os.chown(caminho, 0, grp.getgrnam(grupo).gr_gid)
        os.chmod(caminho, 0o640)
    except FileExistsError:
        return carregar_secret(caminho)
    except (KeyError, PermissionError, OSError) as exc:
        raise AdGuardBootstrapError("Não foi possível persistir o secret interno do AdGuard.") from exc

    return segredo


def criar_cliente_adguard_local(
    *,
    paths: CaminhosAdGuard | None = None,
    secret_path: Path = SECRET_ADGUARD_PADRAO,
) -> AdGuardClient:
    paths = paths or descobrir_adguard()
    secret = carregar_secret(secret_path)
    return AdGuardClient(
        url=obter_url_admin_local(paths),
        user=secret["username"],
        password=secret["password"],
    )


def _garantir_permissoes_configuracao(
    paths: CaminhosAdGuard,
    *,
    grupo: str = "moonshield",
) -> None:
    """Mantém o YAML acessível apenas ao runtime web da appliance."""
    try:
        gid = grp.getgrnam(grupo).gr_gid
    except KeyError as exc:
        raise AdGuardBootstrapError(
            f"Grupo de integração {grupo} não foi encontrado."
        ) from exc

    try:
        os.chown(paths.configuracao, 0, gid)
        os.chmod(paths.configuracao, 0o640)
    except (PermissionError, OSError) as exc:
        raise AdGuardBootstrapError(
            "Não foi possível proteger a configuração local do AdGuard Home."
        ) from exc


def _enderecos_ipv4(interface: dict) -> list[str]:
    real = interface.get("real") if isinstance(interface.get("real"), dict) else {}
    candidatos = list(real.get("enderecos_ipv4") or [])
    if real.get("ipv4"):
        candidatos.append(real["ipv4"])

    enderecos: list[str] = []
    for item in candidatos:
        valor = (
            item.get("endereco", item.get("address", item.get("ip")))
            if isinstance(item, dict)
            else item
        )
        if not isinstance(valor, str):
            continue
        try:
            endereco = str(ipaddress.ip_address(valor.split("/", 1)[0]))
        except ValueError:
            continue
        if endereco not in enderecos:
            enderecos.append(endereco)
    return enderecos


def inventariar_interfaces_dns(topologia: dict) -> dict[str, list[dict]]:
    """Expõe todos os papéis e ativa por padrão toda interface habilitada com IPv4."""
    disponiveis: list[dict] = []
    ativas: list[dict] = []
    for papel in _PAPEIS_REDE:
        grupo = topologia.get(papel, {})
        interfaces = grupo.get("interfaces", []) if isinstance(grupo, dict) else grupo
        for interface in interfaces or []:
            if not isinstance(interface, dict):
                continue
            desejado = interface.get("desejado") if isinstance(interface.get("desejado"), dict) else {}
            registro = {
                "nome": interface.get("nome"),
                "papel": papel,
                "habilitada": bool(desejado.get("habilitada", True)),
                "enderecos_ipv4": _enderecos_ipv4(interface),
            }
            disponiveis.append(registro)
            if registro["habilitada"] and registro["enderecos_ipv4"]:
                ativas.append(registro)
    return {
        "interfaces_disponiveis": disponiveis,
        "interfaces_dns_ativas": ativas,
    }


def obter_inventario_dns_oficial() -> dict[str, list[dict]]:
    """Ponto de consumo para a futura Central DNS, sem segunda topologia."""
    from rede.services.topologia import obter_topologia

    return inventariar_interfaces_dns(obter_topologia())


def _listeners_porta_53() -> tuple[bool, list[str]]:
    try:
        resultado = subprocess.run(
            ["ss", "-H", "-ltnup", "sport", "=", ":53"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False, []
    if resultado.returncode not in (0, 1):
        return False, []
    return True, [linha for linha in resultado.stdout.splitlines() if linha.strip()]


def detectar_conflitos_porta_dns(*, porta: int = PORTA_DNS_PADRAO) -> list[str]:
    """Detecta listeners em 53, aceitando apenas o processo AdGuard já ativo."""
    if porta != PORTA_DNS_PADRAO:
        raise AdGuardBootstrapError("A appliance requer validação explícita para porta DNS não padrão.")

    disponivel, listeners = _listeners_porta_53()
    if disponivel:
        return [linha for linha in listeners if "AdGuardHome" not in linha]

    conflitos: list[str] = []
    for tipo in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        teste = socket.socket(socket.AF_INET, tipo)
        try:
            teste.bind(("0.0.0.0", porta))
        except OSError as exc:
            if exc.errno == errno.EADDRINUSE:
                conflitos.append("listener não identificado em porta 53")
        finally:
            teste.close()
    return conflitos


def _validar_preflight_dns(inventario: dict[str, list[dict]]) -> str:
    ativas = inventario["interfaces_dns_ativas"]
    conflitos = detectar_conflitos_porta_dns()
    if conflitos:
        raise AdGuardBootstrapError(
            "Conflito na porta 53 detectado: " + "; ".join(conflitos)
        )
    # Sem nenhuma interface ativa observada pela topologia, somente localhost
    # é seguro. Com interfaces ativas, o bootstrap usa a primeira apenas para
    # o check_config inicial; o reconcile final aplica todas em bind_hosts.
    return ativas[0]["enderecos_ipv4"][0] if ativas else "127.0.0.1"


def _bloco_yaml(linhas: list[str], chave: str) -> tuple[int | None, int]:
    inicio = next((i for i, linha in enumerate(linhas) if linha.strip() == f"{chave}:"), None)
    if inicio is None:
        return None, len(linhas)
    fim = next(
        (i for i in range(inicio + 1, len(linhas)) if linhas[i] and not linhas[i][0].isspace()),
        len(linhas),
    )
    return inicio, fim


def _substituir_campo(linhas: list[str], inicio: int, fim: int, campo: str, valor: str) -> list[str]:
    padrao = re.compile(rf"^(\s*){re.escape(campo)}:\s*.*$")
    for indice in range(inicio + 1, fim):
        match = padrao.match(linhas[indice])
        if match:
            linhas[indice] = f"{match.group(1)}{campo}: {valor}"
            return linhas
    linhas.insert(inicio + 1, f"  {campo}: {valor}")
    return linhas


def _atualizar_bind_hosts(linhas: list[str], hosts: list[str]) -> list[str]:
    inicio, fim = _bloco_yaml(linhas, "dns")
    if inicio is None:
        linhas.extend(["dns:", "  bind_hosts:", *[f"    - {host}" for host in hosts]])
        return linhas

    campo = next((i for i in range(inicio + 1, fim) if linhas[i].strip() == "bind_hosts:"), None)
    bloco = ["  bind_hosts:", *[f"    - {host}" for host in hosts]]
    if campo is None:
        linhas[inicio + 1:inicio + 1] = bloco
        return linhas

    fim_lista = next(
        (i for i in range(campo + 1, fim) if linhas[i].strip() and len(linhas[i]) - len(linhas[i].lstrip()) <= 2),
        fim,
    )
    linhas[campo:fim_lista] = bloco
    return linhas


def _atualizar_usuario_moonshield(linhas: list[str], senha_hash: str) -> list[str]:
    inicio, fim = _bloco_yaml(linhas, "users")
    if inicio is None:
        linhas.extend(["users:", "  - name: moonshield", f"    password: {senha_hash}"])
        return linhas

    usuario = next(
        (i for i in range(inicio + 1, fim) if re.match(r"^\s*-\s*name:\s*moonshield\s*$", linhas[i])),
        None,
    )
    if usuario is None:
        linhas[fim:fim] = ["  - name: moonshield", f"    password: {senha_hash}"]
        return linhas

    proximo = next(
        (i for i in range(usuario + 1, fim) if re.match(r"^\s*-\s*name:\s*", linhas[i])),
        fim,
    )
    for indice in range(usuario + 1, proximo):
        if re.match(r"^\s*password:\s*", linhas[indice]):
            linhas[indice] = f"    password: {senha_hash}"
            return linhas
    linhas.insert(usuario + 1, f"    password: {senha_hash}")
    return linhas


def _bcrypt(senha: str) -> str:
    try:
        import bcrypt
        return bcrypt.hashpw(senha.encode("utf-8"), bcrypt.gensalt(rounds=10)).decode("utf-8")
    except ImportError:
        pass

    try:
        resultado = subprocess.run(
            ["htpasswd", "-bnBC", "10", "", senha],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        raise AdGuardBootstrapError("Gerador BCrypt não está disponível na appliance.") from exc
    if resultado.returncode != 0 or ":" not in resultado.stdout:
        raise AdGuardBootstrapError("Não foi possível gerar o hash BCrypt do AdGuard.")
    return resultado.stdout.strip().split(":", 1)[1]


def _hash_usuario_moonshield(linhas: list[str]) -> str | None:
    inicio, fim = _bloco_yaml(linhas, "users")
    if inicio is None:
        return None
    usuario = next(
        (i for i in range(inicio + 1, fim) if re.match(r"^\s*-\s*name:\s*moonshield\s*$", linhas[i])),
        None,
    )
    if usuario is None:
        return None
    proximo = next(
        (i for i in range(usuario + 1, fim) if re.match(r"^\s*-\s*name:\s*", linhas[i])),
        fim,
    )
    campo = next((linha for linha in linhas[usuario + 1:proximo] if re.match(r"^\s*password:\s*", linha)), None)
    return campo.split(":", 1)[1].strip() if campo else None


def _senha_confere(senha_hash: str, senha: str) -> bool:
    try:
        import bcrypt
        return bool(bcrypt.checkpw(senha.encode("utf-8"), senha_hash.encode("utf-8")))
    except (ImportError, ValueError):
        pass

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as arquivo:
        arquivo.write(f"moonshield:{senha_hash}\n")
        arquivo.flush()
        caminho = arquivo.name
    os.chmod(caminho, 0o600)
    try:
        resultado = subprocess.run(
            ["htpasswd", "-vb", caminho, "moonshield", senha],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        return resultado.returncode == 0
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False
    finally:
        Path(caminho).unlink(missing_ok=True)


def _configuracao_desejada(paths: CaminhosAdGuard, senha: str, hosts_dns: list[str]) -> tuple[str, str]:
    try:
        original = paths.configuracao.read_text(encoding="utf-8")
    except OSError as exc:
        raise AdGuardBootstrapError("Configuração legada do AdGuard não está disponível.") from exc
    linhas = original.splitlines()
    hash_atual = _hash_usuario_moonshield(linhas)
    senha_hash = hash_atual if hash_atual and _senha_confere(hash_atual, senha) else _bcrypt(senha)
    http_inicio, http_fim = _bloco_yaml(linhas, "http")
    endereco_admin = f"127.0.0.1:{obter_porta_admin(paths)}"
    if http_inicio is None:
        linhas.extend(["http:", f"  address: {endereco_admin}"])
    else:
        linhas = _substituir_campo(linhas, http_inicio, http_fim, "address", endereco_admin)
    linhas = _atualizar_bind_hosts(linhas, hosts_dns)
    linhas = _atualizar_usuario_moonshield(linhas, senha_hash)
    return original, "\n".join(linhas) + "\n"


def _escrever_configuracao_atomica(paths: CaminhosAdGuard, conteudo: str) -> Path:
    original = paths.configuracao
    backup = original.with_name(f"{original.name}.moonshield.bak")
    shutil.copy2(original, backup)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=original.parent, delete=False) as temporario:
        temporario.write(conteudo)
        nome_temporario = temporario.name
    os.replace(nome_temporario, original)
    _garantir_permissoes_configuracao(paths)
    return backup


def _restaurar_backup(paths: CaminhosAdGuard, backup: Path) -> None:
    if backup.is_file():
        shutil.copy2(backup, paths.configuracao)
        _garantir_permissoes_configuracao(paths)


def validar_resolucao_dns(*, host: str = "127.0.0.1", porta: int = 53, timeout: float = 1.5) -> dict[str, bool]:
    """Consulta controlada via UDP; API saudável não substitui DNS funcional."""
    identificador = secrets.randbits(16)
    rotulos = ["example", "com"]
    pergunta = b"".join(bytes([len(rotulo)]) + rotulo.encode("ascii") for rotulo in rotulos) + b"\x00"
    pacote = identificador.to_bytes(2, "big") + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + pergunta + b"\x00\x01\x00\x01"
    cliente = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cliente.settimeout(timeout)
    try:
        cliente.sendto(pacote, (host, porta))
        resposta, _ = cliente.recvfrom(4096)
    except OSError:
        return {"resolver_ok": False, "upstream_ok": False}
    finally:
        cliente.close()
    if len(resposta) < 12 or int.from_bytes(resposta[:2], "big") != identificador:
        return {"resolver_ok": False, "upstream_ok": False}
    rcode = resposta[3] & 0x0F
    respostas = int.from_bytes(resposta[6:8], "big")
    return {"resolver_ok": rcode == 0 and respostas > 0}


def _normalizar_endpoint_upstream(valor: object) -> str:
    """Normaliza endpoints para comparar a forma configurada com a forma canônica do AdGuard."""
    texto = str(valor or "").strip()
    if not texto:
        return ""

    try:
        parsed = urlparse(texto)
    except ValueError:
        return texto

    if not parsed.scheme or not parsed.hostname:
        return texto

    esquema = parsed.scheme.lower()
    host = parsed.hostname.lower()

    try:
        porta = parsed.port
    except ValueError:
        return texto

    portas_padrao = {
        "http": 80,
        "https": 443,
        "tls": 853,
        "quic": 853,
    }
    porta = porta or portas_padrao.get(esquema)

    if ":" in host and not host.startswith("["):
        host = f"[{host}]"

    autoridade = host if porta is None else f"{host}:{porta}"
    caminho = parsed.path or ""
    consulta = f"?{parsed.query}" if parsed.query else ""

    return f"{esquema}://{autoridade}{caminho}{consulta}"


def upstreams_aprovados(dns_info: dict, resultado: dict) -> bool:
    """Exige OK para cada upstream DNS configurado, sem exigir bootstrap DNS."""
    esperados = list(dns_info.get("upstream_dns") or [])
    if not esperados:
        return False

    respostas = resultado.get("upstream_dns", resultado)
    if not isinstance(respostas, dict) or not respostas:
        return False

    respostas_normalizadas = {
        _normalizar_endpoint_upstream(upstream): str(estado).strip().upper()
        for upstream, estado in respostas.items()
    }

    for upstream in esperados:
        chave = _normalizar_endpoint_upstream(upstream)
        if not chave or respostas_normalizadas.get(chave) != "OK":
            return False

    return True


def _hosts_dns_iniciais(inventario: dict[str, list[dict]]) -> list[str]:
    hosts = ["127.0.0.1"]
    for interface in inventario["interfaces_dns_ativas"]:
        for endereco in interface["enderecos_ipv4"]:
            if endereco not in hosts:
                hosts.append(endereco)
    return hosts


def _reconciliar_yaml(
    *,
    paths: CaminhosAdGuard,
    senha: str,
    hosts_dns: list[str],
    controlar_servico: Callable[[list[str]], None],
    validar_apos_inicio: Callable[[], None] | None = None,
) -> bool:
    original, desejado = _configuracao_desejada(paths, senha, hosts_dns)
    if original == desejado:
        return False

    backup: Path | None = None
    controlar_servico(["stop", paths.servico])
    try:
        # Releitura após stop elimina a corrida com escrita do AdGuard.
        _, desejado = _configuracao_desejada(paths, senha, hosts_dns)
        backup = _escrever_configuracao_atomica(paths, desejado)
        controlar_servico(["start", paths.servico])
        if validar_apos_inicio is not None:
            validar_apos_inicio()
        return True
    except Exception:
        if backup is not None:
            try:
                controlar_servico(["stop", paths.servico])
            except Exception:
                pass
            _restaurar_backup(paths, backup)
        try:
            controlar_servico(["start", paths.servico])
        except Exception:
            pass
        raise


def provisionar_adguard(
    *,
    topologia: dict,
    controlar_servico: Callable[[list[str]], None],
    servico_ativo: Callable[[str], bool],
    secret_path: Path = SECRET_ADGUARD_PADRAO,
) -> dict[str, object]:
    """Provisiona setup nativo sem HTML e preserva instâncias já válidas."""
    paths = descobrir_adguard()
    secret = garantir_secret(secret_path)
    _garantir_permissoes_configuracao(paths)
    inventario = inventariar_interfaces_dns(topologia)
    if not inventario["interfaces_dns_ativas"]:
        return {
            "ok": True,
            "estado": "aguardando_topologia",
            "setup_realizado": False,
            "reconciliado": False,
            "servico": paths.servico,
            **inventario,
        }

    dns_ip = _validar_preflight_dns(inventario)
    controlar_servico(["enable", paths.servico])
    if not servico_ativo(paths.servico):
        controlar_servico(["start", paths.servico])

    porta_admin = obter_porta_admin(paths)
    client = AdGuardClient(obter_url_admin_local(paths), secret["username"], secret["password"])
    setup_realizado = False
    try:
        client.get_status()
    except AdGuardHTTPError as exc:
        if exc.status_code == 404:
            payload = {
                "web": {"ip": "127.0.0.1", "port": porta_admin},
                "dns": {"ip": dns_ip, "port": PORTA_DNS_PADRAO, "autofix": False},
                "username": USUARIO_INTEGRACAO,
                "password": secret["password"],
            }
            checagem = client.verificar_configuracao_inicial(payload)
            problemas = [str(valor) for valor in (checagem.get("web", {}), checagem.get("dns", {})) if isinstance(valor, dict) and valor.get("status")]
            if problemas:
                raise AdGuardBootstrapError("Configuração inicial do AdGuard recusada: " + "; ".join(problemas))
            client.configurar_instalacao(payload)
            _garantir_permissoes_configuracao(paths)
            setup_realizado = True
        elif exc.status_code != 401:
            raise AdGuardBootstrapError("API local do AdGuard não respondeu ao contrato esperado.") from exc

    def validar_api_reconciliada() -> None:
        client_validacao = AdGuardClient(
            obter_url_admin_local(paths),
            secret["username"],
            secret["password"],
        )
        ultimo_erro: AdGuardError | None = None
        for tentativa in range(20):
            try:
                client_validacao.get_status()
                return
            except AdGuardError as exc:
                ultimo_erro = exc
                if tentativa == 19:
                    break
                time.sleep(0.25)
        raise AdGuardBootstrapError(
            "API do AdGuard não ficou disponível após o restart."
        ) from ultimo_erro

    reconciliado = _reconciliar_yaml(
        paths=paths,
        senha=secret["password"],
        hosts_dns=_hosts_dns_iniciais(inventario),
        controlar_servico=controlar_servico,
        validar_apos_inicio=validar_api_reconciliada,
    )
    _garantir_permissoes_configuracao(paths)
    client = AdGuardClient(obter_url_admin_local(paths), secret["username"], secret["password"])
    try:
        for tentativa in range(20):
            try:
                status = client.get_status()
                break
            except AdGuardError:
                if tentativa == 19:
                    raise
                time.sleep(0.25)
        client.ativar_protecao()
        status = client.get_status()
        dns = client.get_dns_info()
    except AdGuardError as exc:
        raise AdGuardBootstrapError("Validação autenticada da API do AdGuard falhou.") from exc

    hosts_esperados = set(_hosts_dns_iniciais(inventario))
    hosts_reais = set(status.get("dns_addresses") or [])
    listener_ok = hosts_reais == hosts_esperados and not ({"0.0.0.0", "::"} & hosts_reais)
    protecao = bool(dns.get("protection_enabled", status.get("protection_enabled", False)))
    porta_dns = int(dns.get("port", status.get("dns_port", PORTA_DNS_PADRAO)) or 0)
    dns_real = validar_resolucao_dns()
    try:
        teste_upstreams = client.testar_upstreams_dns(dns)
        upstream_ok = upstreams_aprovados(dns, teste_upstreams)
    except AdGuardError:
        upstream_ok = False
    if not (protecao and porta_dns == PORTA_DNS_PADRAO and listener_ok):
        raise AdGuardBootstrapError("Validação final do DNS AdGuard não foi aprovada.")

    return {
        "ok": True,
        "estado": "operacional" if dns_real.get("resolver_ok") and upstream_ok else "atencao",
        "saudavel": bool(dns_real.get("resolver_ok") and upstream_ok),
        "setup_realizado": setup_realizado,
        "reconciliado": reconciliado,
        "api_url": client.base_url,
        "binario": str(paths.binario),
        "configuracao": str(paths.configuracao),
        "diretorio_dados": str(paths.diretorio_dados),
        "servico": paths.servico,
        "dns": dns,
        "engine_ok": bool(status.get("running")),
        "api_ok": True,
        "listener_ok": listener_ok,
        **dns_real,
        "upstream_ok": upstream_ok,
        **inventario,
    }
