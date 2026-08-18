"""
Módulo para detecção segura e passiva de ambiente do sistema e infraestrutura Suricata.
Não instala, altera ou modifica permissões do sistema operacional.
"""

import os
import platform
import getpass
import logging
import re
from pathlib import Path

from .tipos import (
    ResultadoEtapa,
    StatusEtapa,
    DiagnosticoItem,
)
from .comandos import comando_existe, localizar_comando, executar_comando

logger = logging.getLogger(__name__)

# ==============================================================================
# CONSTANTES OBRIGATÓRIAS
# ==============================================================================

YAML_CANDIDATOS = (
    Path("/etc/suricata/suricata.yaml"),
    Path("/usr/local/etc/suricata/suricata.yaml"),
)

EVE_JSON_PADRAO = Path("/var/log/suricata/eve.json")

REGRAS_MOONSHIELD_PADRAO = Path(
    "/var/lib/suricata/rules/moonshield/ms.rules"
)

REGRAS_ET_OPEN_PADRAO = Path(
    "/var/lib/suricata/rules/suricata.rules"
)

CURSOR_PADRAO_RELATIVO = Path(
    "var/cursors/suricata_eve.cursor"
)

GERENCIADORES_SUPORTADOS = (
    "apt-get",
    "apt",
    "dnf",
    "yum",
    "pacman",
)

DISTRIBUICOES_DEBIAN = {
    "debian",
    "ubuntu",
    "linuxmint",
    "pop",
    "raspbian",
}


# ==============================================================================
# DETECÇÃO BÁSICA DO SISTEMA OPERACIONAL E USUÁRIO
# ==============================================================================

def sistema_operacional() -> str:
    """Retorna o sistema operacional em lowercase padronizado."""
    sys_nome = platform.system().lower()
    if "linux" in sys_nome:
        return "linux"
    if "windows" in sys_nome:
        return "windows"
    if "darwin" in sys_nome or "mac" in sys_nome:
        return "darwin"
    return "desconhecido"


def eh_linux() -> bool:
    """Avalia booleanamente se o backend está executando no Linux."""
    return sistema_operacional() == "linux"


def eh_windows() -> bool:
    """Avalia booleanamente se o backend está executando no Windows."""
    return sistema_operacional() == "windows"


def obter_uid() -> int | None:
    """Obtém o User ID do processo atual em sistemas POSIX. Retorna None no Windows."""
    try:
        if hasattr(os, "getuid"):
            return os.getuid()
    except Exception as e:
        logger.debug(f"Falha amena ao obter UID via os.getuid(): {e}")
    return None


def usuario_e_root() -> dict[str, object]:
    """Retorna um mapeamento da identidade do processo e privilégios base."""
    uid = obter_uid()
    
    # Tentativa hierárquica de determinar o nome do usuário logado
    usuario = "desconhecido"
    try:
        usuario = getpass.getuser()
    except Exception:
        usuario = os.environ.get("USER") or os.environ.get("USERNAME") or "desconhecido"

    # Define privilégio
    is_root = False
    if eh_linux() and uid == 0:
        is_root = True
    elif eh_windows():
        is_root = False

    return {
        "usuario": usuario,
        "uid": uid,
        "root": is_root,
        "sistema": sistema_operacional(),
    }


def verificar_linux() -> ResultadoEtapa:
    """ResultWrapper para garantir que as ferramentas que requerem POSIX não executem cegamente."""
    etapa_id = "verificar_linux"
    sistema_atual = sistema_operacional()
    
    if eh_linux():
        res = ResultadoEtapa(
            etapa=etapa_id,
            status=StatusEtapa.SUCESSO,
            sucesso=True,
            mensagem="Sistema compatível detectado (Linux).",
            dados={"sistema": sistema_atual}
        )
        return res
    
    res = ResultadoEtapa(
        etapa=etapa_id,
        status=StatusEtapa.ERRO,
        sucesso=False,
        mensagem=f"Sistema Incompatível: {sistema_atual}",
        erro="A instalação e orquestração do Suricata IDS só são suportadas no Linux. Use apenas para desenvolvimento em outras plataformas.",
        dados={"sistema": sistema_atual}
    )
    return res


def verificar_privilegios() -> ResultadoEtapa:
    """ResultWrapper para avaliar e reportar falta de privilégios necessários (root) em Linux."""
    identidade = usuario_e_root()
    res = ResultadoEtapa(
        etapa="verificar_privilegios",
        status=StatusEtapa.ERRO,
        sucesso=False,
        mensagem="Privilégios administrativos insuficientes.",
        dados=identidade
    )

    if eh_windows():
        res.erro = "No Windows as operações não devem tentar elevação UAC. Use o servidor Linux principal."
        return res
    
    if identidade.get("root"):
        res.status = StatusEtapa.SUCESSO
        res.sucesso = True
        res.mensagem = "Processo executando com privilégios de root (UID 0)."
    else:
        res.erro = f"O processo precisa estar rodando como root, mas iniciou com o usuário '{identidade.get('usuario')} (UID: {identidade.get('uid')})'."
        
    return res


# ==============================================================================
# LEITURA PASSIVA DE ARQUIVOS DE SISTEMA (OS-RELEASE E CAMINHOS)
# ==============================================================================

def ler_os_release(caminho: str | Path = "/etc/os-release") -> dict[str, str]:
    """Parseia as chaves chave=valor contidas no arquivo de metadados da distribuição Linux."""
    resultado = {}
    path_obj = Path(caminho)
    
    if not path_obj.is_file():
        return resultado
        
    try:
        # Lê de forma segura limitando a bufferização
        with open(path_obj, "r", encoding="utf-8", errors="replace") as f:
            for linha in f:
                linha = linha.strip()
                if not linha or linha.startswith("#"):
                    continue
                if "=" in linha:
                    chave, _, valor = linha.partition("=")
                    chave = chave.strip()
                    # Remove aspas
                    valor = valor.strip().strip("'").strip('"')
                    resultado[chave] = valor
    except Exception as e:
        logger.debug(f"Falha tolerada ao ler {caminho}: {e}")
        
    return resultado


def detectar_distribuicao_linux() -> dict[str, str]:
    """Interpreta os metadados de distribuição em um dicionário padronizado."""
    if not eh_linux():
        return {}
        
    dados_release = ler_os_release()
    if not dados_release:
        return {}
        
    return {
        "id": dados_release.get("ID", ""),
        "nome": dados_release.get("NAME", ""),
        "versao": dados_release.get("VERSION_ID", ""),
        "versao_completa": dados_release.get("VERSION", ""),
        "id_like": dados_release.get("ID_LIKE", ""),
        "codinome": dados_release.get("VERSION_CODENAME", ""),
    }


def detectar_gerenciador_pacotes() -> str | None:
    """Procura pelo primeiro comando de package manager existente no sistema base."""
    if not eh_linux():
        return None
        
    for mgr in GERENCIADORES_SUPORTADOS:
        if comando_existe(mgr):
            return mgr
    return None


def obter_comando_instalacao(pacote: str, gerenciador: str | None = None) -> list[str] | None:
    """Prepara argumentos seguros baseados na semântica de cada gerenciador."""
    if not isinstance(pacote, str):
        raise ValueError("Pacote deve ser uma string simples.")
        
    pacote_limpo = pacote.strip()
    if not pacote_limpo:
        raise ValueError("O nome do pacote não pode estar vazio.")

    # Restringir o nome de pacote para mitigar injeções
    caracteres_invalidos = set(pacote_limpo) - set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_+")
    if caracteres_invalidos:
        raise ValueError("O nome do pacote contém caracteres inválidos/espaços.")

    if gerenciador is None:
        gerenciador = detectar_gerenciador_pacotes()
        
    if not gerenciador:
        return None

    if gerenciador == "apt-get":
        return ["apt-get", "install", "-y", pacote_limpo]
    if gerenciador == "apt":
        return ["apt", "install", "-y", pacote_limpo]
    if gerenciador == "dnf":
        return ["dnf", "install", "-y", pacote_limpo]
    if gerenciador == "yum":
        return ["yum", "install", "-y", pacote_limpo]
    if gerenciador == "pacman":
        return ["pacman", "-S", "--noconfirm", pacote_limpo]

    return None


def localizar_suricata_yaml(caminho_preferido: str | Path | None = None) -> Path | None:
    """Busca o arquivo mestre do Suricata usando a ordem de precedência estabelecida."""
    if caminho_preferido:
        p_pref = Path(caminho_preferido)
        if p_pref.is_file():
            return p_pref

    for cand in YAML_CANDIDATOS:
        if cand.is_file():
            return cand

    return None


def localizar_eve_json(caminho_preferido: str | Path | None = None) -> Path | None:
    """Busca o log canônico eve.json do Suricata."""
    if caminho_preferido:
        p_pref = Path(caminho_preferido)
        if p_pref.is_file():
            return p_pref

    if EVE_JSON_PADRAO.is_file():
        return EVE_JSON_PADRAO

    return None


# ==============================================================================
# STATUS DIRETO DO SERVIÇO EXTERNO (SURICATA BINARY)
# ==============================================================================

def suricata_instalado() -> bool:
    """Confere com segurança se o binário já se encontra no PATH local."""
    return comando_existe("suricata")


def _extrair_versao_suricata(texto: str) -> str:
    """
    Extrai somente a versão semântica da saída do Suricata.

    Compatível com formatos comuns como:
    - "Suricata 7.0.10"
    - "This is Suricata version 7.0.10 RELEASE"
    - "Suricata version 7.0.10"

    Nunca retorna o objeto ResultadoEtapa nem texto de usage/help para o frontend.
    """
    conteudo = str(texto or "").strip()
    if not conteudo:
        return ""

    padroes = (
        r"\bThis\s+is\s+Suricata\s+version\s+v?([0-9]+(?:\.[0-9]+){1,3}(?:[-+~._A-Za-z0-9]*)?)",
        r"\bSuricata\s+version\s+v?([0-9]+(?:\.[0-9]+){1,3}(?:[-+~._A-Za-z0-9]*)?)",
        r"\bSuricata\s+v?([0-9]+(?:\.[0-9]+){1,3}(?:[-+~._A-Za-z0-9]*)?)",
    )

    for padrao in padroes:
        match = re.search(padrao, conteudo, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip()

    # Fallback conservador: aceita apenas uma versão numérica que esteja
    # presente em uma linha que mencione Suricata.
    for linha in conteudo.splitlines():
        if "suricata" not in linha.lower():
            continue
        match = re.search(
            r"\bv?([0-9]+(?:\.[0-9]+){1,3}(?:[-+~._A-Za-z0-9]*)?)\b",
            linha,
            flags=re.IGNORECASE,
        )
        if match:
            return match.group(1).strip()

    return ""


def obter_versao_suricata() -> ResultadoEtapa:
    """
    Consulta a versão do binário Suricata de forma passiva.

    Importante:
    o Suricata 7 utiliza `-V` para exibir a versão. `--version` não é uma
    opção válida nessa instalação e pode imprimir VERSION + USAGE enquanto
    retorna erro, o que fazia o MoonShield serializar um ResultadoEtapa
    inteiro no painel.
    """
    etapa_id = "versao_suricata"

    if not suricata_instalado():
        return ResultadoEtapa(
            etapa=etapa_id,
            status=StatusEtapa.ERRO,
            sucesso=False,
            mensagem="Suricata não está instalado.",
            erro="Comando 'suricata' não foi encontrado no PATH.",
            dados={
                "instalado": False,
                "versao": "",
                "caminho_binario": "",
            },
        )

    caminho_binario = localizar_comando("suricata") or ""

    # Forma correta suportada pelo Suricata atual.
    resultado_cmd = executar_comando(
        ["suricata", "-V"],
        timeout=15.0,
    )

    stdout = str(getattr(resultado_cmd, "saida", "") or "").strip()
    stderr = str(getattr(resultado_cmd, "erro", "") or "").strip()

    # Algumas versões/distribuições podem escrever a versão em stderr.
    texto_completo = "\n".join(
        parte for parte in (stdout, stderr) if parte
    ).strip()

    versao = _extrair_versao_suricata(texto_completo)

    # A versão é a evidência principal. Mesmo que um wrapper de comando tenha
    # classificado o retorno de forma inesperada, se `-V` devolveu uma versão
    # válida não há motivo para contaminar o painel com o objeto de erro.
    if versao:
        return ResultadoEtapa(
            etapa=etapa_id,
            status=StatusEtapa.SUCESSO,
            sucesso=True,
            mensagem="Versão do Suricata extraída com sucesso.",
            dados={
                "instalado": True,
                "caminho_binario": caminho_binario,
                "versao": versao,
                "stdout": stdout,
            },
        )

    detalhe_erro = stderr or stdout or "O comando não retornou uma versão reconhecível."

    return ResultadoEtapa(
        etapa=etapa_id,
        status=StatusEtapa.ERRO,
        sucesso=False,
        mensagem="Falha ao extrair versão do binário Suricata.",
        erro=detalhe_erro,
        dados={
            "instalado": True,
            "caminho_binario": caminho_binario,
            "versao": "",
        },
    )


def obter_versao_suricata_texto() -> str:
    """
    Retorna somente a string de versão para status/API/UI.

    Exemplo:
        "7.0.10"

    Esta função nunca retorna ResultadoEtapa, repr() de DTO, USAGE ou traceback.
    """
    resultado = obter_versao_suricata()

    if not resultado.sucesso:
        return ""

    dados = resultado.dados if isinstance(resultado.dados, dict) else {}
    versao = dados.get("versao", "")

    return str(versao or "").strip()


# ==============================================================================
# AUDITORIA PASSIVA COMPLETA (SEM SIDE EFFECTS)
# ==============================================================================

def verificar_caminhos_suricata(
    yaml_path: str | Path | None = None,
    eve_path: str | Path | None = None,
) -> dict[str, object]:
    """Retorna as propriedades estáticas de cada arquivo chaves do stack do Suricata."""
    def _stat_passivo(alvo: Path | None) -> dict:
        info = {
            "caminho": str(alvo) if alvo else "",
            "existe": False,
            "arquivo": False,
            "legivel": False,
            "tamanho": 0,
        }
        if not alvo:
            return info
            
        if alvo.exists():
            info["existe"] = True
            info["arquivo"] = alvo.is_file()
            info["legivel"] = os.access(alvo, os.R_OK)
            try:
                info["tamanho"] = alvo.stat().st_size
            except OSError:
                pass
        return info

    yaml_real = localizar_suricata_yaml(yaml_path)
    eve_real = localizar_eve_json(eve_path)

    stats = {
        "yaml": _stat_passivo(yaml_real),
        "eve": _stat_passivo(eve_real),
        "regras_moonshield": _stat_passivo(REGRAS_MOONSHIELD_PADRAO),
        "regras_et_open": _stat_passivo(REGRAS_ET_OPEN_PADRAO),
    }

    # Adiciona a verificação extra para escrita no EVE caso de monitor re-roteando ou logrotate custom
    if eve_real and eve_real.exists():
        stats["eve"]["gravavel"] = os.access(eve_real, os.W_OK)
    else:
        stats["eve"]["gravavel"] = False

    return stats


def detectar_ambiente_completo(
    yaml_path: str | Path | None = None,
    eve_path: str | Path | None = None,
) -> dict[str, object]:
    """Compila e avalia todas as propriedades passivas do sistema gerando o 'cenário atual' da máquina hospedeira."""
    identidade = usuario_e_root()
    distro = detectar_distribuicao_linux()
    gerenciador = detectar_gerenciador_pacotes()
    suricata_ok = suricata_instalado()
    versao_suricata = obter_versao_suricata_texto() if suricata_ok else ""
    caminhos = verificar_caminhos_suricata(yaml_path, eve_path)
    
    # Compilando capacidades lógicas do MoonShield
    pode_instalar = bool(identidade.get("sistema") == "linux" and identidade.get("root") and gerenciador)
    pode_configurar = bool(identidade.get("sistema") == "linux" and identidade.get("root"))
    pode_controlar = bool(pode_configurar and comando_existe("systemctl"))
    is_win_dev = bool(identidade.get("sistema") == "windows")

    avisos = []
    if not eh_linux():
        avisos.append("Servidor não é Linux.")
    if not identidade.get("root"):
        avisos.append("Usuário sem permissão de root (UID 0).")
    if eh_linux() and not gerenciador:
        avisos.append("Gerenciador de pacotes compatível não foi detectado no PATH.")
    if not suricata_ok:
        avisos.append("Binário do Suricata não está instalado.")
    if not caminhos["yaml"]["existe"]:
        avisos.append("Arquivo de configuração mestre (suricata.yaml) não foi encontrado.")
    if not caminhos["eve"]["existe"]:
        avisos.append("Arquivo de telemetria/logs (eve.json) não foi encontrado.")

    return {
        "sistema": {
            "nome": identidade.get("sistema"),
            "linux": eh_linux(),
            "windows": eh_windows(),
            "usuario": identidade.get("usuario"),
            "uid": identidade.get("uid"),
            "root": identidade.get("root"),
        },
        "distribuicao": distro,
        "gerenciador_pacotes": gerenciador,
        "suricata": {
            "instalado": suricata_ok,
            "binario": localizar_comando("suricata") if suricata_ok else "",
            "versao": versao_suricata,
        },
        "caminhos": caminhos,
        "capacidades": {
            "pode_instalar": pode_instalar,
            "pode_configurar": pode_configurar,
            "pode_controlar_servicos": pode_controlar,
            "modo_desenvolvimento_windows": is_win_dev,
        },
        "avisos": avisos,
    }


def gerar_checks_ambiente() -> list[DiagnosticoItem]:
    """Traduz o ambiente detectado em itens de diagnóstico prontos para o assistente web."""
    ambiente = detectar_ambiente_completo()
    itens = []

    # 1. Sistema e SO
    is_linux = ambiente["sistema"]["linux"]
    itens.append(DiagnosticoItem(
        id="sistema_linux",
        grupo="Sistema",
        titulo="Sistema Operacional Linux",
        ok=is_linux,
        detalhe=f"Detectado: {ambiente['sistema']['nome']}" if not is_linux else "",
        acao="Execute a implantação em ambiente Linux." if not is_linux else "",
        critico=True,
        dados={"is_linux": is_linux}
    ))

    # 2. Usuário Administrador (Root UID 0)
    is_root = ambiente["sistema"]["root"]
    usuario_nome = ambiente["sistema"]["usuario"]
    itens.append(DiagnosticoItem(
        id="usuario_root",
        grupo="Sistema",
        titulo="Privilégios de Administrador (Root)",
        ok=is_root,
        detalhe=f"Executando como usuário {usuario_nome}",
        acao="Para instalar e modificar arquivos do IDS é necessário processo com privilégios totais de root." if not is_root else "",
        critico=True, # Critico para a fase de instalação/configuração. O Helper deverá suprir isto.
        dados={"is_root": is_root, "usuario": usuario_nome}
    ))

    # 3. Gerenciador de Pacotes
    tem_gerenciador = bool(ambiente["gerenciador_pacotes"])
    is_instalado = ambiente["suricata"]["instalado"]
    itens.append(DiagnosticoItem(
        id="gerenciador_pacotes",
        grupo="Sistema",
        titulo="Gerenciador de Pacotes",
        ok=tem_gerenciador,
        detalhe=f"Detectado: {ambiente['gerenciador_pacotes']}" if tem_gerenciador else "Ausente/Desconhecido",
        acao="Requer apt, dnf, yum ou pacman caso precise instalar novas dependências." if not tem_gerenciador else "",
        critico=not is_instalado, # Critico só se o Suricata ainda precisar ser baixado
        dados={"gerenciador": ambiente["gerenciador_pacotes"]}
    ))

    # 4. Binário do Suricata
    versao_suricata = str(ambiente["suricata"].get("versao") or "").strip()
    itens.append(DiagnosticoItem(
        id="suricata_instalado",
        grupo="Suricata",
        titulo="Binário do Suricata Instalado",
        ok=is_instalado,
        detalhe=(
            f"Versão {versao_suricata}"
            if is_instalado and versao_suricata
            else "Binário localizado; versão não identificada."
            if is_instalado
            else "Não detectado no PATH."
        ),
        acao="Execute o onboarding de instalação automatizado." if not is_instalado else "",
        critico=True,  # Operacionalmente crítico
        dados={"instalado": is_instalado, "versao": versao_suricata},
    ))

    # 5. Arquivo Principal de Configuração (suricata.yaml)
    yaml_info = ambiente["caminhos"]["yaml"]
    tem_yaml = yaml_info["existe"]
    itens.append(DiagnosticoItem(
        id="suricata_yaml",
        grupo="Suricata",
        titulo="Arquivo de Configuração mestre (suricata.yaml)",
        ok=tem_yaml,
        detalhe=yaml_info["caminho"] if tem_yaml else "Nenhum arquivo detectado nos caminhos default (/etc/suricata ou /usr/local/etc/suricata).",
        acao="Reinstale o Suricata ou aponte o arquivo de configuração correto." if not tem_yaml else "",
        critico=is_instalado, # Se não tá instalado ainda, óbvio que não tem o arquivo
        dados=yaml_info
    ))

    # 6. Log EVE
    eve_info = ambiente["caminhos"]["eve"]
    tem_eve = eve_info["existe"]
    itens.append(DiagnosticoItem(
        id="eve_json",
        grupo="Suricata",
        titulo="Arquivo de Metadados/Eventos (eve.json)",
        ok=tem_eve,
        detalhe=f"{eve_info['tamanho']} bytes encontrados em {eve_info['caminho']}" if tem_eve else "Ainda não detectado ou Suricata não iniciou a gravação.",
        acao="Certifique-se de que a configuração eve-log esteja ativada no YAML." if not tem_eve else "",
        critico=False, # Não é crítico pois pode ainda não ter bootado pela primeira vez.
        dados=eve_info
    ))

    return itens