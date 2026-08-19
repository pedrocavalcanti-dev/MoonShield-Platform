"""
Orquestrador central de instalação, configuração e manutenção do ciclo de vida do Suricata.
Não contém lógicas de SO diretas, atua como coordenador de etapas dos módulos especialistas.
"""

import json
import logging
import os
from pathlib import Path
from django.utils import timezone as django_timezone

from .tipos import (
    ResultadoEtapa,
    StatusEtapa,
    NivelLog,
    ConfiguracaoSuricataDados,
    ProgressoTarefa,
    TipoTarefaSuricata,
)
from .ambiente import (
    verificar_linux,
    verificar_privilegios,
    suricata_instalado,
    obter_versao_suricata,
    localizar_suricata_yaml,
    localizar_eve_json,
    detectar_gerenciador_pacotes,
    obter_comando_instalacao,
)
from .regras import (
    instalar_suricata_update,
    atualizar_et_open,
    copiar_regras_moonshield,
    obter_status_regras_completo,
)
from .configurador import (
    aplicar_configuracao_dados,
    validar_configuracao,
    obter_status_configuracao,
)
from .interfaces import (
    validar_topologia,
    obter_topologia_detectada,
    montar_configuracao_sugerida,
)
from .servicos import (
    daemon_reload,
    reiniciar_servico,
    reiniciar_stack_suricata,
    iniciar_stack_suricata,
    obter_status_stack,
    SERVICO_SURICATA,
    SERVICO_MONITOR,
)
from .diagnostico import executar_diagnostico
from .status import obter_status_stack_completo
from .comandos import executar_comando

logger = logging.getLogger(__name__)

# ==============================================================================
# CONSTANTES OBRIGATÓRIAS
# ==============================================================================

PACOTE_SURICATA = "suricata"

ETAPAS_INSTALACAO = (
    "verificar_ambiente",
    "instalar_suricata",
    "instalar_suricata_update",
    "atualizar_et_open",
    "validar_topologia",
    "copiar_regras_moonshield",
    "configurar_suricata",
    "validar_suricata",
    "reiniciar_servicos",
    "validar_instalacao",
)

TIMEOUT_INSTALACAO_SURICATA = 900.0
TIMEOUT_VALIDACAO_FINAL = 300.0
TIMEOUT_ATUALIZAR_INDICES = 300.0
MODO_DIRETORIO_RUNTIME = 0o755
MODO_ARQUIVO_EVE = 0o644


# ==============================================================================
# HELPERS PRIVADOS DE EXECUÇÃO E CONTROLE
# ==============================================================================

def _criar_resultado_etapa(etapa: str, mensagem: str) -> ResultadoEtapa:
    """Prepara um container básico em andamento."""
    return ResultadoEtapa(
        etapa=etapa,
        status=StatusEtapa.EXECUTANDO,
        sucesso=False,
        mensagem=mensagem,
        iniciado_em=django_timezone.now()
    )


def _atualizar_progresso(
    progresso: ProgressoTarefa | None,
    percentual: int,
    etapa: str,
    mensagem: str,
    nivel: NivelLog = NivelLog.INFO,
) -> None:
    """Atualiza o tracker sem permitir regressão do percentual."""
    if progresso is None:
        return
    try:
        atual = int(getattr(progresso, "progresso", 0) or 0)
        novo = max(atual, max(0, min(100, int(percentual))))
        progresso.atualizar(novo, etapa, mensagem, nivel)
    except Exception as exc:
        logger.debug("Falha não crítica ao atualizar progresso: %s", exc)


def _executar_etapa_segura(nome_etapa: str, funcao, *args, **kwargs) -> ResultadoEtapa:
    """Evita o colapso do orquestrador caso um módulo especialista falhe drasticamente (Ex: ImportError)."""
    try:
        res = funcao(*args, **kwargs)
        if not isinstance(res, ResultadoEtapa):
            logger.error(f"A etapa {nome_etapa} não retornou o contrato ResultadoEtapa.")
            fallback = _criar_resultado_etapa(nome_etapa, "Erro de contrato interno.")
            fallback.finalizar_erro("A função acionada retornou um tipo incompatível de objeto.")
            return fallback
        return res
    except Exception as e:
        logger.exception(f"Exceção catastrófica não tratada na execução da etapa: {nome_etapa}")
        fallback = _criar_resultado_etapa(nome_etapa, "Exceção Interna")
        fallback.finalizar_erro(
            mensagem="Um erro não previsto quebrou o processamento lógico da etapa.",
            erro=str(e)
        )
        return fallback


def _consolidar_resultados(
    etapa_principal: str,
    resultados: dict[str, ResultadoEtapa],
    mensagem_sucesso: str,
    mensagem_erro: str,
    avisos: list[str] | None = None,
) -> ResultadoEtapa:
    """Une os vereditos de várias etapas num DTO pai para a View/API."""
    res_final = _criar_resultado_etapa(etapa_principal, "Consolidando...")
    
    houve_erro = False
    falhas_nomes = []
    
    dados_compilados = {}
    for sub_etapa, sub_res in resultados.items():
        dados_compilados[sub_etapa] = sub_res.to_dict()
        if not sub_res.sucesso:
            houve_erro = True
            falhas_nomes.append(sub_etapa)
            
    res_final.dados["etapas"] = dados_compilados
    if avisos:
        res_final.dados["avisos"] = avisos

    if houve_erro:
        res_final.finalizar_erro(
            mensagem=mensagem_erro,
            erro=f"Falha em etapas críticas: {', '.join(falhas_nomes)}"
        )
    else:
        res_final.finalizar_sucesso(mensagem=mensagem_sucesso)

    return res_final



def _preparar_runtime_suricata(
    configuracao: ConfiguracaoSuricataDados,
) -> ResultadoEtapa:
    """Prepara EVE, cursor e diretórios para instalação nova ou reexecução."""
    res = _criar_resultado_etapa(
        "preparar_runtime",
        "Preparando arquivos de execução.",
    )

    try:
        eve_path = Path(configuracao.eve_path).expanduser()
        eve_path.parent.mkdir(parents=True, exist_ok=True)
        if not eve_path.exists():
            eve_path.touch()
        os.chmod(eve_path.parent, MODO_DIRETORIO_RUNTIME)
        os.chmod(eve_path, MODO_ARQUIVO_EVE)

        cursor_raw = getattr(configuracao, "cursor_path", "") or (
            "var/cursors/suricata_eve.cursor"
        )
        cursor_path = Path(cursor_raw).expanduser()
        if not cursor_path.is_absolute():
            cursor_path = Path.cwd() / cursor_path

        cursor_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(cursor_path.parent, MODO_DIRETORIO_RUNTIME)

        removidos = []
        for temp in cursor_path.parent.glob(f"{cursor_path.name}.tmp.*"):
            try:
                temp.unlink()
                removidos.append(str(temp))
            except OSError:
                logger.warning("Não foi possível remover %s", temp)

        cursor_resetado = False
        if cursor_path.exists():
            valido = False
            try:
                dados = json.loads(cursor_path.read_text(encoding="utf-8"))
                valido = (
                    isinstance(dados, dict)
                    and isinstance(dados.get("offset"), int)
                    and dados["offset"] >= 0
                )
            except Exception:
                valido = False

            if not valido:
                cursor_path.unlink(missing_ok=True)
                cursor_resetado = True

        res.dados = {
            "eve_path": str(eve_path),
            "cursor_path": str(cursor_path),
            "cursor_resetado": cursor_resetado,
            "temporarios_removidos": removidos,
        }
        res.finalizar_sucesso("Runtime preparado com sucesso.")
    except Exception as exc:
        logger.exception("Falha ao preparar runtime do Suricata.")
        res.finalizar_erro(
            "Não foi possível preparar EVE e cursor.",
            erro=str(exc),
        )

    return res


def _atualizar_indices_apt() -> ResultadoEtapa:
    """Atualiza os índices APT em uma instalação Debian nova."""
    res = _criar_resultado_etapa(
        "atualizar_indices_pacotes",
        "Atualizando catálogo APT.",
    )
    cmd = executar_comando(
        ["apt-get", "update"],
        timeout=TIMEOUT_ATUALIZAR_INDICES,
        env={
            "DEBIAN_FRONTEND": "noninteractive",
            "LC_ALL": "C",
        },
    )
    res.dados["comando"] = cmd.to_dict()

    if cmd.sucesso:
        res.finalizar_sucesso("Catálogo APT atualizado.")
    else:
        res.finalizar_erro(
            "Falha ao atualizar catálogo APT.",
            erro=cmd.erro or cmd.saida,
        )

    return res





def _ler_os_release() -> dict[str, str]:
    """Lê /etc/os-release sem depender de bibliotecas externas."""
    dados: dict[str, str] = {}
    caminho = Path("/etc/os-release")
    if not caminho.is_file():
        return dados
    try:
        for linha in caminho.read_text(encoding="utf-8", errors="replace").splitlines():
            linha = linha.strip()
            if not linha or linha.startswith("#") or "=" not in linha:
                continue
            chave, valor = linha.split("=", 1)
            dados[chave.strip()] = valor.strip().strip('"').strip("'")
    except OSError:
        logger.exception("Não foi possível ler /etc/os-release.")
    return dados


def _detectar_codename_debian() -> tuple[str, dict[str, str]]:
    """
    Descobre o codename Debian com múltiplos fallbacks.
    Debian 12 => bookworm; Debian 13 => trixie.
    """
    os_release = _ler_os_release()
    distro = os_release.get("ID", "").strip().lower()

    detalhes = {
        "distro": distro,
        "version_id": os_release.get("VERSION_ID", "").strip(),
        "version_codename": os_release.get("VERSION_CODENAME", "").strip(),
        "debian_codename": os_release.get("DEBIAN_CODENAME", "").strip(),
        "debian_version": "",
    }

    if distro and distro != "debian":
        return "", detalhes

    codename = detalhes["version_codename"] or detalhes["debian_codename"]
    if codename:
        return codename, detalhes

    mapa_major = {"12": "bookworm", "13": "trixie"}

    version_id = detalhes["version_id"].split(".", 1)[0].strip()
    if version_id in mapa_major:
        return mapa_major[version_id], detalhes

    debian_version_path = Path("/etc/debian_version")
    if debian_version_path.is_file():
        try:
            debian_version = debian_version_path.read_text(
                encoding="utf-8", errors="replace"
            ).strip()
            detalhes["debian_version"] = debian_version

            major = debian_version.split(".", 1)[0].strip()
            if major in mapa_major:
                return mapa_major[major], detalhes

            lower = debian_version.lower()
            for nome in ("bookworm", "trixie"):
                if nome in lower:
                    return nome, detalhes
        except OSError:
            logger.exception("Não foi possível ler /etc/debian_version.")

    return "", detalhes


def _habilitar_backports_suricata_debian(
    progresso: ProgressoTarefa | None = None,
) -> ResultadoEtapa:
    """
    Habilita o Backports oficial do Debian sem substituir os sources existentes.
    """
    res = _criar_resultado_etapa(
        "habilitar_backports_suricata",
        "Preparando Debian Backports para o Suricata.",
    )

    codename, detalhes = _detectar_codename_debian()
    res.dados["deteccao_debian"] = detalhes
    res.dados["codename"] = codename

    if detalhes.get("distro") not in {"", "debian"}:
        res.finalizar_erro(
            "Fallback por Backports é suportado apenas em Debian.",
            erro=f"Distribuição detectada: {detalhes.get('distro') or 'desconhecida'}",
        )
        return res

    if not codename:
        res.finalizar_erro(
            "Não foi possível identificar a versão Debian para montar o Backports.",
            erro=str(detalhes),
        )
        return res

    suite_backports = f"{codename}-backports"
    destino = Path("/etc/apt/sources.list.d/moonshield-suricata-backports.list")
    conteudo = f"deb http://deb.debian.org/debian {suite_backports} main\n"

    _atualizar_progresso(
        progresso,
        18,
        "habilitar_backports_suricata",
        f"Habilitando repositório oficial Debian {suite_backports}...",
        NivelLog.AVISO,
    )

    try:
        destino.parent.mkdir(parents=True, exist_ok=True)
        atual = (
            destino.read_text(encoding="utf-8", errors="replace")
            if destino.exists()
            else ""
        )
        if atual != conteudo:
            temporario = destino.with_name(
                f".{destino.name}.moonshield.{os.getpid()}.tmp"
            )
            temporario.write_text(conteudo, encoding="utf-8")
            os.chmod(temporario, 0o644)
            os.replace(temporario, destino)

        res.dados["arquivo"] = str(destino)
        res.dados["suite_backports"] = suite_backports
        res.dados["repositorio"] = conteudo.strip()
    except OSError as exc:
        logger.exception("Não foi possível criar a fonte Debian Backports.")
        res.finalizar_erro(
            "Falha ao criar a fonte Debian Backports.",
            erro=str(exc),
        )
        return res

    _atualizar_progresso(
        progresso,
        18,
        "atualizar_indices_backports",
        "Atualizando catálogo APT após habilitar Backports...",
    )

    atualizacao = _atualizar_indices_apt()
    res.dados["atualizacao_apt"] = atualizacao.to_dict()

    if not atualizacao.sucesso:
        res.finalizar_erro(
            "Backports foi configurado, mas o APT não conseguiu atualizar os índices.",
            erro=atualizacao.erro or atualizacao.mensagem,
        )
        return res

    res.finalizar_sucesso(
        f"Debian Backports pronto: {suite_backports}."
    )
    return res


def _instalar_suricata_via_backports(
    suite_backports: str,
) -> ResultadoEtapa:
    """Instala Suricata e suricata-update pelo Debian Backports."""
    res = _criar_resultado_etapa(
        "instalar_suricata_backports",
        f"Instalando Suricata por {suite_backports}.",
    )

    comando = [
        "apt-get",
        "-o", "Acquire::Retries=3",
        "-o", "Acquire::http::Timeout=30",
        "-o", "Acquire::https::Timeout=30",
        "-o", "Acquire::ForceIPv4=true",
        "-t", suite_backports,
        "install",
        "-y",
        "suricata",
        "suricata-update",
    ]

    cmd = executar_comando(
        comando,
        timeout=TIMEOUT_INSTALACAO_SURICATA,
        env={"DEBIAN_FRONTEND": "noninteractive", "LC_ALL": "C"},
    )
    res.dados["comando"] = cmd.to_dict()

    if cmd.sucesso:
        res.finalizar_sucesso(
            f"Suricata instalado via {suite_backports}."
        )
    else:
        motivo = (
            cmd.erro
            or cmd.stderr
            or cmd.stdout
            or cmd.saida
            or "APT retornou falha sem mensagem adicional."
        )
        res.finalizar_erro(
            "Falha ao instalar Suricata pelo Debian Backports.",
            erro=motivo,
        )
    return res


# ==============================================================================
# ORQUESTRAÇÕES DE INFRAESTRUTURA
# ==============================================================================


def garantir_suricata_instalado(
    progresso: ProgressoTarefa | None = None,
) -> ResultadoEtapa:
    """
    Instala o Suricata de forma idempotente.

    Debian/APT:
    1. tenta instalação normal;
    2. atualiza o APT e tenta novamente;
    3. se ainda falhar, habilita o Debian Backports oficial;
    4. instala suricata + suricata-update com -t <codename>-backports;
    5. valida o binário.
    """
    etapa_nome = "instalar_suricata"

    _atualizar_progresso(
        progresso, 15, etapa_nome,
        "Verificando instalação base do Suricata.",
    )

    res = _criar_resultado_etapa(
        etapa_nome,
        "Gerenciando pacote core do Suricata.",
    )

    if suricata_instalado():
        res_versao = obter_versao_suricata()
        res.dados["versao"] = res_versao.dados.get("versao", "")
        res.adicionar_log(
            "Suricata já está instalado. Reutilizando instalação existente.",
            NivelLog.SUCESSO,
        )
        res.finalizar_sucesso(
            "Binário do Suricata já está presente no sistema."
        )
        return res

    res_linux = verificar_linux()
    if not res_linux.sucesso:
        res.finalizar_erro(
            "A instalação automática só atua em servidores Linux.",
            erro=res_linux.erro or res_linux.mensagem,
        )
        return res

    res_root = verificar_privilegios()
    if not res_root.sucesso:
        res.finalizar_erro(
            "Instalação do pacote requer privilégio administrativo.",
            erro=res_root.erro or res_root.mensagem,
        )
        return res

    gerenciador = detectar_gerenciador_pacotes()
    if not gerenciador:
        res.finalizar_erro(
            "Não localizamos utilitários de pacotes (apt, dnf, yum, pacman)."
        )
        return res

    comando_base = obter_comando_instalacao(
        PACOTE_SURICATA,
        gerenciador,
    )
    if not comando_base:
        res.finalizar_erro(
            "Impossível montar instrução segura para instalar o Suricata."
        )
        return res

    ambiente_pacotes = {
        "DEBIAN_FRONTEND": "noninteractive",
        "LC_ALL": "C",
    }

    _atualizar_progresso(
        progresso,
        18,
        etapa_nome,
        f"Instalando Suricata via {gerenciador}...",
    )

    res.adicionar_log(
        f"Executando instalação padrão via {gerenciador}: "
        f"{' '.join(comando_base)}",
        NivelLog.INFO,
    )

    resultado_cmd = executar_comando(
        comando_base,
        timeout=TIMEOUT_INSTALACAO_SURICATA,
        env=ambiente_pacotes,
    )
    res.dados["primeira_tentativa"] = resultado_cmd.to_dict()

    if (
        not resultado_cmd.sucesso
        and gerenciador in {"apt", "apt-get"}
    ):
        _atualizar_progresso(
            progresso,
            18,
            "atualizar_indices_pacotes",
            "Instalação padrão falhou. Atualizando catálogo APT...",
            NivelLog.AVISO,
        )

        res_indices = _atualizar_indices_apt()
        res.dados["atualizar_indices"] = res_indices.to_dict()

        if res_indices.sucesso:
            _atualizar_progresso(
                progresso,
                18,
                etapa_nome,
                "Tentando instalação padrão novamente após apt-get update...",
            )

            resultado_cmd = executar_comando(
                comando_base,
                timeout=TIMEOUT_INSTALACAO_SURICATA,
                env=ambiente_pacotes,
            )
            res.dados["segunda_tentativa"] = resultado_cmd.to_dict()

    if (
        not resultado_cmd.sucesso
        and gerenciador in {"apt", "apt-get"}
    ):
        res.adicionar_log(
            "O repositório padrão não forneceu o Suricata. "
            "Ativando fallback oficial Debian Backports.",
            NivelLog.AVISO,
        )

        res_backports = _habilitar_backports_suricata_debian(
            progresso=progresso,
        )
        res.dados["backports"] = res_backports.to_dict()

        if not res_backports.sucesso:
            motivo = (
                res_backports.erro
                or res_backports.mensagem
                or "Falha ao preparar Debian Backports."
            )
            res.finalizar_erro(
                "Não foi possível preparar Debian Backports para o Suricata.",
                erro=motivo,
            )
            return res

        suite_backports = str(
            res_backports.dados.get("suite_backports", "")
        ).strip()

        if not suite_backports:
            res.finalizar_erro(
                "Backports foi preparado, mas a suíte não foi identificada."
            )
            return res

        _atualizar_progresso(
            progresso,
            19,
            "instalar_suricata_backports",
            f"Instalando Suricata via {suite_backports}...",
            NivelLog.AVISO,
        )

        res_inst_backports = _instalar_suricata_via_backports(
            suite_backports,
        )
        res.dados["instalacao_backports"] = (
            res_inst_backports.to_dict()
        )

        if not res_inst_backports.sucesso:
            motivo = (
                res_inst_backports.erro
                or res_inst_backports.mensagem
                or "Falha ao instalar via Backports."
            )
            res.finalizar_erro(
                "Falha ao instalar o Suricata pelo Debian Backports.",
                erro=motivo,
            )
            return res

        resultado_cmd = None
        res.dados["metodo_instalacao"] = suite_backports

    elif resultado_cmd.sucesso:
        res.dados["metodo_instalacao"] = gerenciador

    if resultado_cmd is not None and not resultado_cmd.sucesso:
        motivo = (
            resultado_cmd.erro
            or resultado_cmd.stderr
            or resultado_cmd.stdout
            or resultado_cmd.saida
            or "O gerenciador de pacotes retornou falha sem mensagem adicional."
        )
        res.finalizar_erro(
            "Falha ao instalar o Suricata pelo gerenciador de pacotes do sistema.",
            erro=motivo,
        )
        return res

    if not suricata_instalado():
        res.finalizar_erro(
            "Binário do Suricata não foi encontrado após a instalação."
        )
        return res

    res_versao = obter_versao_suricata()
    res.dados["versao"] = res_versao.dados.get(
        "versao",
        "Desconhecido",
    )

    res.adicionar_log(
        f"Suricata instalado com sucesso: {res.dados['versao']}.",
        NivelLog.SUCESSO,
    )
    res.finalizar_sucesso(
        "Suricata instalado e validado com sucesso."
    )
    return res


# ==============================================================================
# ORQUESTRAÇÕES DE CONFIGURAÇÃO E DADOS LÓGICOS
# ==============================================================================

def preparar_configuracao_instalacao(configuracao: ConfiguracaoSuricataDados | None = None) -> tuple[ConfiguracaoSuricataDados | None, list[str]]:
    """Resolve os preenchimentos em falta gerando uma recomendação inteligente."""
    erros = []
    
    if configuracao is not None:
        erros = configuracao.validar()
        return configuracao, erros
        
    try:
        topo = obter_topologia_detectada(incluir_virtuais=True)
        config_sugerida = montar_configuracao_sugerida(topo)
        erros = config_sugerida.validar()
        return config_sugerida, erros
    except Exception as e:
        logger.exception("Falha na previsão de topologia base.")
        erros.append(f"Erro ao inferir topologia inicial: {e}")
        return None, erros


def validar_pre_requisitos(configuracao: ConfiguracaoSuricataDados) -> ResultadoEtapa:
    """Bloqueio primário. Não permite que instalação inicie se o design lógico for incompatível com o físico."""
    res = _criar_resultado_etapa("validar_pre_requisitos", "Analisando consistência dos parâmetros antes de aplicar.")
    erros = []

    res_lin = verificar_linux()
    if not res_lin.sucesso:
        erros.append(res_lin.mensagem)
        
    res_root = verificar_privilegios()
    if not res_root.sucesso:
        erros.append(res_root.mensagem)

    try:
        erros_topo = validar_topologia(configuracao)
        erros.extend(erros_topo)
    except Exception as e:
        erros.append(f"Erro em rotina de validação topológica: {e}")

    if not configuracao.yaml_path:
        erros.append("O caminho de configuração yaml_path é mandatório.")
    if not configuracao.eve_path:
        erros.append("O caminho de telemetria eve_path é mandatório.")

    if not configuracao.interfaces_monitoradas:
        erros.append("Ao menos uma interface precisa ser definida na matriz de af-packet.")
    if not configuracao.home_net:
        erros.append("Não se define proteção sem pelo menos um range declarado em HOME_NET.")

    if erros:
        res.dados["erros_detalhados"] = erros
        res.finalizar_erro("Validação inicial não aprovou o design técnico submetido.", erro="; ".join(erros[:2]))
    else:
        res.finalizar_sucesso("Ambiente de sistema e variáveis aprovados para deploy.")
        
    return res


# ==============================================================================
# ENTRYPOINTS MESTRES / FLUXOS DE ORQUESTRAÇÃO
# ==============================================================================

def executar_instalacao(
    configuracao: ConfiguracaoSuricataDados | None = None,
    progresso: ProgressoTarefa | None = None,
    instalar_et_open: bool | None = None,
    reiniciar_servicos: bool | None = None,
    executar_diagnostico_final: bool = True,
) -> ResultadoEtapa:
    """
    Roteiro Full-Cycle.
    Preenche de cabo a rabo a stack transformando Linux comum num Probe MoonShield.
    Abortivo rápido em checkpoints críticos, permissivo em blocos como Update ET-Open.
    """
    _atualizar_progresso(progresso, 0, "iniciando", "Start do Roteiro Orquestrador de Instalação")
    
    etapas_rodadas: dict[str, ResultadoEtapa] = {}
    avisos_globais: list[str] = []

    # 1. Base Setup
    cfg_pronta, erros_cfg = preparar_configuracao_instalacao(configuracao)
    if not cfg_pronta or erros_cfg:
        _atualizar_progresso(progresso, 5, "ambiente", "Falha de validação primária.", NivelLog.ERRO)
        fallback = _criar_resultado_etapa("verificar_ambiente", "Pre-flight abortado.")
        fallback.dados["erros_detalhados"] = erros_cfg
        fallback.finalizar_erro("Estrutura não corresponde as validações da topologia.", erro="; ".join(erros_cfg))
        return fallback

    _atualizar_progresso(progresso, 5, "ambiente", "Validando capacidades operacionais...")
    res_pre = _executar_etapa_segura("validar_pre_requisitos", validar_pre_requisitos, cfg_pronta)
    etapas_rodadas["verificar_ambiente"] = res_pre
    if not res_pre.sucesso:
        return _consolidar_resultados("executar_instalacao", etapas_rodadas, "", "Deploy rejeitado nos Pré-requisitos", avisos_globais)

    # 2. Preparação de EVE e cursor.
    _atualizar_progresso(
        progresso,
        10,
        "preparar_runtime",
        "Preparando EVE, cursor e diretórios...",
    )
    res_runtime = _executar_etapa_segura(
        "preparar_runtime",
        _preparar_runtime_suricata,
        cfg_pronta,
    )
    etapas_rodadas["preparar_runtime"] = res_runtime
    if not res_runtime.sucesso:
        return _consolidar_resultados(
            "executar_instalacao",
            etapas_rodadas,
            "",
            "Falha ao preparar arquivos de execução.",
            avisos_globais,
        )

    # 3. Infra Base IDS
    _atualizar_progresso(progresso, 15, "instalar_suricata", "Garantindo deploy do Suricata...")
    res_bin = _executar_etapa_segura("garantir_suricata_instalado", garantir_suricata_instalado, progresso)
    etapas_rodadas["instalar_suricata"] = res_bin
    if not res_bin.sucesso:
        return _consolidar_resultados("executar_instalacao", etapas_rodadas, "", "Cancelado pois a base do Suricata não pôde ser injetada no Sistema.", avisos_globais)

    # 3. Módulo ET Open (Opcional permissivo)
    usar_et = instalar_et_open if instalar_et_open is not None else cfg_pronta.instalar_et_open
    if usar_et:
        _atualizar_progresso(progresso, 25, "instalar_suricata_update", "Acoplando gestor de regras comunitário...")
        res_suri_up = _executar_etapa_segura("instalar_suricata_update", instalar_suricata_update)
        etapas_rodadas["instalar_suricata_update"] = res_suri_up
        
        if res_suri_up.sucesso:
            _atualizar_progresso(progresso, 35, "atualizar_et_open", "Fazendo download massivo da rede ET...")
            res_et = _executar_etapa_segura("atualizar_et_open", atualizar_et_open, habilitar_fonte=True)
            etapas_rodadas["atualizar_et_open"] = res_et
            if not res_et.sucesso:
                avisos_globais.append("O download das regras gratuitas ET Open falhou, porém a instalação primária irá continuar.")
        else:
            avisos_globais.append("O utilitário suricata-update não ingressou, ignorando puxada do dataset ET.")

    # 4. Topologia Extra / Dummy checkpoint
    _atualizar_progresso(progresso, 45, "validar_topologia", "Inspecionando compatibilidade da topologia do cfg no hardware...")
    
    # 5. Assinaturas Proprietary (MoonShield Rules)
    _atualizar_progresso(progresso, 55, "copiar_regras_moonshield", "Deployando assinaturas locais Drop-False-Positives...")
    res_rules = _executar_etapa_segura("copiar_regras_moonshield", copiar_regras_moonshield, copiar_para_etc=True)
    etapas_rodadas["copiar_regras_moonshield"] = res_rules
    if not res_rules.sucesso:
        return _consolidar_resultados("executar_instalacao", etapas_rodadas, "", "Parada total: Falha ao exportar Dataset MoonShield.", avisos_globais)

    # 6. Application Patching
    _atualizar_progresso(progresso, 70, "configurar_suricata", "Mesclando patch de parametrização atômica no .yaml...")
    res_cfg = _executar_etapa_segura("aplicar_configuracao_dados", aplicar_configuracao_dados, cfg_pronta)
    etapas_rodadas["configurar_suricata"] = res_cfg
    if not res_cfg.sucesso:
        return _consolidar_resultados("executar_instalacao", etapas_rodadas, "", "Configuração não foi absorvida pelo disco.", avisos_globais)

    # 7. Segurança de Engine (Dry Run)
    _atualizar_progresso(progresso, 80, "validar_suricata", "Acionando a engine na simulação profunda (Dry-Run YAML)...")
    res_val = _executar_etapa_segura("validar_configuracao", validar_configuracao, cfg_pronta.yaml_path, TIMEOUT_VALIDACAO_FINAL)
    etapas_rodadas["validar_suricata"] = res_val
    if not res_val.sucesso:
        return _consolidar_resultados("executar_instalacao", etapas_rodadas, "", "Arquivo rejeitado internamente pelo Suricata. Rollback atuando se existir.", avisos_globais)

    # 8. Service Control e Matriz Bounce
    usar_bounce = reiniciar_servicos if reiniciar_servicos is not None else cfg_pronta.reiniciar_servicos
    if usar_bounce:
        _atualizar_progresso(progresso, 90, "reiniciar_servicos", "Iniciando processo de Restart/Deploy em RAM...")
        # O Helper fará o bounce do cluster completo
        res_bounce = _executar_etapa_segura("iniciar_stack_suricata", iniciar_stack_suricata)
        etapas_rodadas["reiniciar_servicos"] = res_bounce
        if not res_bounce.sucesso:
            avisos_globais.append("A aplicação de base foi bem-sucedida, porém os serviços demoraram/falharam ao estabilizar seu bounce.")

    # 9. Consolidação Pós-Deploy e Inspeção (Health Check Full)
    _atualizar_progresso(progresso, 95, "validar_instalacao", "Acionando Doctor pra auditar deploy completo.")
    
    st_final = {}
    res_diag = None

    try:
        st_final = obter_status_stack_completo(cfg_pronta)
    except Exception as exc:
        logger.exception("Falha ao coletar status final.")
        avisos_globais.append(f"Status final indisponível: {exc}")

    if executar_diagnostico_final:
        try:
            diag = executar_diagnostico(cfg_pronta)
            res_diag = diag.to_dict()
        except Exception as exc:
            logger.exception("Falha no diagnóstico final.")
            avisos_globais.append(f"Diagnóstico final indisponível: {exc}")

    _atualizar_progresso(
        progresso,
        100,
        "concluido",
        "Processo transacional finalizado.",
        NivelLog.SUCESSO,
    )

    res_final = _consolidar_resultados(
        "executar_instalacao",
        etapas_rodadas,
        "Ambiente implantado de ponta a ponta.",
        "Falha macro no processo orquestrado.",
        avisos_globais,
    )

    # Pendura os relatórios estáticos na ponta do wrapper
    res_final.dados["configuracao"] = cfg_pronta.to_dict()
    res_final.dados["status_final"] = st_final
    res_final.dados["diagnostico"] = res_diag

    return res_final


def executar_configuracao(
    configuracao: ConfiguracaoSuricataDados,
    progresso: ProgressoTarefa | None = None,
    reiniciar_servicos: bool | None = None,
) -> ResultadoEtapa:
    """Manutenção de Topologia - Altera apenas o suricata.yaml baseando na interface/redes alteradas."""
    _atualizar_progresso(progresso, 0, "iniciando", "Start de Atualização de Topologia")
    
    etapas_rodadas: dict[str, ResultadoEtapa] = {}
    avisos_globais: list[str] = []

    res_pre = _executar_etapa_segura("validar_pre_requisitos", validar_pre_requisitos, configuracao)
    etapas_rodadas["verificar_ambiente"] = res_pre
    if not res_pre.sucesso:
        return _consolidar_resultados("executar_configuracao", etapas_rodadas, "", "Falha em validacao previa.", avisos_globais)
        
    if not suricata_instalado():
        return _consolidar_resultados("executar_configuracao", etapas_rodadas, "", "Configuração não atua em máquina sem o binario primário.", avisos_globais)

    _atualizar_progresso(progresso, 30, "copiar_regras_moonshield", "Refazendo base de regras...")
    res_rules = _executar_etapa_segura("copiar_regras_moonshield", copiar_regras_moonshield, copiar_para_etc=True)
    etapas_rodadas["copiar_regras_moonshield"] = res_rules
    if not res_rules.sucesso:
         return _consolidar_resultados("executar_configuracao", etapas_rodadas, "", "Crash de regras.", avisos_globais)

    _atualizar_progresso(progresso, 60, "configurar_suricata", "Patching yaml...")
    res_cfg = _executar_etapa_segura("aplicar_configuracao_dados", aplicar_configuracao_dados, configuracao)
    etapas_rodadas["configurar_suricata"] = res_cfg
    if not res_cfg.sucesso:
        return _consolidar_resultados("executar_configuracao", etapas_rodadas, "", "Yaml patch failed.", avisos_globais)

    _atualizar_progresso(progresso, 80, "validar_suricata", "Validando a sintaxe nova...")
    res_val = _executar_etapa_segura("validar_configuracao", validar_configuracao, configuracao.yaml_path, TIMEOUT_VALIDACAO_FINAL)
    etapas_rodadas["validar_suricata"] = res_val
    if not res_val.sucesso:
        return _consolidar_resultados("executar_configuracao", etapas_rodadas, "", "Rejeição engine C.", avisos_globais)

    usar_reinicio = reiniciar_servicos if reiniciar_servicos is not None else configuracao.reiniciar_servicos
    if usar_reinicio:
        _atualizar_progresso(progresso, 90, "reiniciar_servicos", "Reiniciando stack Suricata...")
        res_b = _executar_etapa_segura("reiniciar_stack_suricata", reiniciar_stack_suricata)
        etapas_rodadas["reiniciar_servicos"] = res_b

    _atualizar_progresso(progresso, 100, "concluido", "Pronto.")
    
    return _consolidar_resultados("executar_configuracao", etapas_rodadas, "Topologia Re-aplicada", "Falha orquestral", avisos_globais)


def executar_atualizacao_regras(
    atualizar_et: bool = True,
    atualizar_moonshield: bool = True,
    origem_moonshield: str | Path | None = None,
    validar_depois: bool = True,
    yaml_path: str | Path | None = None,
    reiniciar_depois: bool = False,
    progresso: ProgressoTarefa | None = None,
) -> ResultadoEtapa:
    """Funil dedicado a manter o Intelligence Pipeline alimentado e não corrompido."""
    etapas_rodadas: dict[str, ResultadoEtapa] = {}
    avisos_globais: list[str] = []
    _atualizar_progresso(progresso, 0, "iniciando", "Syncronizando Assinaturas")

    if atualizar_et:
        _atualizar_progresso(progresso, 30, "atualizar_et_open", "Processando fetch do registry ET-Open")
        res_et = _executar_etapa_segura("atualizar_et_open", atualizar_et_open)
        etapas_rodadas["atualizar_et_open"] = res_et
        if not res_et.sucesso:
            avisos_globais.append("Repositório Open-Source ET-Open retornou falha temporária ou timeout.")
            
    if atualizar_moonshield:
        _atualizar_progresso(progresso, 60, "copiar_regras_moonshield", "Extraindo e aplicando regras MS locais")
        res_ms = _executar_etapa_segura("copiar_regras_moonshield", copiar_regras_moonshield, origem_moonshield, True)
        etapas_rodadas["copiar_regras_moonshield"] = res_ms
        if not res_ms.sucesso:
            return _consolidar_resultados("executar_atualizacao_regras", etapas_rodadas, "", "Crítico: Não foi possível assegurar as definições customizadas do Moonshield.", avisos_globais)

    if validar_depois:
        yaml_ativo = yaml_path or localizar_suricata_yaml()
        if yaml_ativo:
             _atualizar_progresso(progresso, 80, "validar_suricata", "Análise de integridade estrutural (Teste das regras)...")
             res_val = _executar_etapa_segura("validar_configuracao", validar_configuracao, yaml_ativo)
             etapas_rodadas["validar_suricata"] = res_val
             if not res_val.sucesso:
                 return _consolidar_resultados("executar_atualizacao_regras", etapas_rodadas, "", "Falha Crítica: Algum pacote de regras corrompeu o runtime do IDS.", avisos_globais)
        else:
             avisos_globais.append("Pulo de validação. Yaml Inexistente.")

    if reiniciar_depois:
        _atualizar_progresso(progresso, 90, "reiniciar_servicos", "Recarregando daemon central...")
        # Nota: Bounce apenas do Suricata, não precisa derrubar o monitor no drop de regras.
        res_suri = _executar_etapa_segura("reiniciar_servico", reiniciar_servico, SERVICO_SURICATA)
        etapas_rodadas["reiniciar_suricata"] = res_suri

    _atualizar_progresso(progresso, 100, "concluido", "Pronto.")
    return _consolidar_resultados("executar_atualizacao_regras", etapas_rodadas, "Assinaturas ativas atualizadas com as ultimas defs.", "Um problema nas branches de repositório impediu atualização fluida.", avisos_globais)


def executar_validacao(
    configuracao: ConfiguracaoSuricataDados | None = None,
    progresso: ProgressoTarefa | None = None,
) -> ResultadoEtapa:
    """
    Valida formalmente a configuração ativa do Suricata.

    Fluxo:
    1. Localiza o YAML ativo.
    2. Executa `suricata -T`.
    3. Executa o diagnóstico profundo sem repetir o `suricata -T`.
    4. Converte o ResultadoDiagnostico para ResultadoEtapa.
    5. Consolida o resultado para o worker/tarefa.
    """
    _atualizar_progresso(
        progresso,
        10,
        "validar",
        "Executando inspeções operacionais.",
    )

    etapas_rodadas: dict[str, ResultadoEtapa] = {}

    # ------------------------------------------------------------------
    # 1. Localizar YAML
    # ------------------------------------------------------------------
    yaml_ativo = (
        configuracao.yaml_path
        if configuracao
        else localizar_suricata_yaml()
    )

    if not yaml_ativo:
        return _consolidar_resultados(
            "executar_validacao",
            etapas_rodadas,
            "",
            "YAML de configuração do Suricata não encontrado.",
        )

    # ------------------------------------------------------------------
    # 2. Validação nativa: suricata -T
    # ------------------------------------------------------------------
    res_val = _executar_etapa_segura(
        "validar_configuracao",
        validar_configuracao,
        yaml_ativo,
    )

    etapas_rodadas["validar_suricata"] = res_val

    if not res_val.sucesso:
        return _consolidar_resultados(
            "executar_validacao",
            etapas_rodadas,
            "",
            "A configuração foi rejeitada pelo suricata -T.",
        )

    # ------------------------------------------------------------------
    # 3. Diagnóstico profundo
    #
    # executar_diagnostico() retorna ResultadoDiagnostico, e não
    # ResultadoEtapa. Portanto NÃO deve passar por
    # _executar_etapa_segura().
    #
    # Como o suricata -T já foi executado acima, desativamos a validação
    # duplicada dentro do diagnóstico para não gastar mais ~40 segundos.
    # ------------------------------------------------------------------
    _atualizar_progresso(
        progresso,
        55,
        "diagnostico",
        "Recolhendo telemetria do sistema para relatório final.",
    )

    try:
        diagnostico = executar_diagnostico(
            configuracao=configuracao,
            incluir_validacao_suricata=False,
        )
    except Exception as exc:
        logger.exception(
            "Falha durante diagnóstico profundo da validação."
        )

        res_diag = _criar_resultado_etapa(
            "diagnostico",
            "Falha durante diagnóstico profundo.",
        )
        res_diag.finalizar_erro(
            mensagem=(
                "Não foi possível concluir o healthcheck interno "
                "do Suricata."
            ),
            erro=str(exc),
        )

        etapas_rodadas["diagnostico"] = res_diag

        return _consolidar_resultados(
            "executar_validacao",
            etapas_rodadas,
            "",
            "Configuração falhou em auditoria profunda.",
        )

    # ------------------------------------------------------------------
    # 4. Adaptar ResultadoDiagnostico -> ResultadoEtapa
    # ------------------------------------------------------------------
    diagnostico_pronto = bool(
        getattr(diagnostico, "pronto", False)
    )

    res_diag = _criar_resultado_etapa(
        "diagnostico",
        "Consolidando healthcheck interno.",
    )

    try:
        diagnostico_serializado = diagnostico.to_dict()
    except Exception:
        diagnostico_serializado = {}

    res_diag.dados = {
        "pronto": diagnostico_pronto,
        "total_checks": int(
            getattr(diagnostico, "total_checks", 0) or 0
        ),
        "total_ok": int(
            getattr(diagnostico, "total_ok", 0) or 0
        ),
        "total_falhas": int(
            getattr(diagnostico, "total_falhas", 0) or 0
        ),
        "total_criticos": int(
            getattr(diagnostico, "total_criticos", 0) or 0
        ),
        "resultado": diagnostico_serializado,
    }

    if diagnostico_pronto:
        res_diag.finalizar_sucesso(
            "Healthcheck interno aprovado."
        )
    else:
        total_criticos = int(
            getattr(diagnostico, "total_criticos", 0) or 0
        )

        res_diag.finalizar_erro(
            mensagem=(
                "Healthcheck interno identificou falhas críticas."
            ),
            erro=(
                f"{total_criticos} falha(s) crítica(s) identificada(s)."
            ),
        )

    etapas_rodadas["diagnostico"] = res_diag

    if not diagnostico_pronto:
        return _consolidar_resultados(
            "executar_validacao",
            etapas_rodadas,
            "",
            "Configuração falhou em auditoria profunda.",
        )

    # ------------------------------------------------------------------
    # 5. Conclusão
    # ------------------------------------------------------------------
    _atualizar_progresso(
        progresso,
        100,
        "concluido",
        "Validação concluída com sucesso.",
        NivelLog.SUCESSO,
    )

    return _consolidar_resultados(
        "executar_validacao",
        etapas_rodadas,
        "Ambiente íntegro e validado.",
        "",
    )

def executar_reparo(configuracao: ConfiguracaoSuricataDados, progresso: ProgressoTarefa | None = None) -> ResultadoEtapa:
    """Hard-Override: Regera todas as dependências nativas Moonshield sem tocar nos pacotes instalados por Package Managers."""
    _atualizar_progresso(progresso, 0, "iniciando", "Runbook de Self-Healing...")
    etapas_rodadas: dict[str, ResultadoEtapa] = {}
    avisos_globais: list[str] = []

    res_pre = _executar_etapa_segura("validar_pre_requisitos", validar_pre_requisitos, configuracao)
    if not res_pre.sucesso:
        return _consolidar_resultados("executar_reparo", etapas_rodadas, "", "Self-Healing abortado. Ambiente não sustenta o modelo baseline.", avisos_globais)
        
    _atualizar_progresso(progresso, 20, "copiar_regras_moonshield", "Redeploy dos conjuntos de proteção estáticos.")
    res_rules = _executar_etapa_segura("copiar_regras_moonshield", copiar_regras_moonshield, copiar_para_etc=True)
    etapas_rodadas["copiar_regras_moonshield"] = res_rules
    if not res_rules.sucesso:
        return _consolidar_resultados("executar_reparo", etapas_rodadas, "", "Falha no expurgo/copia de rules.", avisos_globais)

    _atualizar_progresso(progresso, 40, "configurar_suricata", "Forçando regravação do Yaml com blocos default corretos.")
    res_cfg = _executar_etapa_segura("aplicar_configuracao_dados", aplicar_configuracao_dados, configuracao)
    etapas_rodadas["configurar_suricata"] = res_cfg
    if not res_cfg.sucesso:
        return _consolidar_resultados("executar_reparo", etapas_rodadas, "", "Escrita rejeitada no config-file.", avisos_globais)

    _atualizar_progresso(progresso, 60, "validar_suricata", "Submetendo infra para checagem.")
    res_val = _executar_etapa_segura("validar_configuracao", validar_configuracao, configuracao.yaml_path, TIMEOUT_VALIDACAO_FINAL)
    etapas_rodadas["validar_suricata"] = res_val
    if not res_val.sucesso:
        return _consolidar_resultados("executar_reparo", etapas_rodadas, "", "Config gerada foi rejeitada internamente. Ação corrompida.", avisos_globais)

    _atualizar_progresso(progresso, 80, "reiniciar_servicos", "Bouncing the system.")
    _executar_etapa_segura("daemon_reload", daemon_reload)
    res_bounce = _executar_etapa_segura("reiniciar_stack_suricata", reiniciar_stack_suricata)
    etapas_rodadas["reiniciar_servicos"] = res_bounce
    
    _atualizar_progresso(progresso, 100, "concluido", "Self-Healing concluído com veredito final.")
    return _consolidar_resultados("executar_reparo", etapas_rodadas, "Subsistema estabilizado através de reparo dinâmico.", "Ocorreram distúrbios na re-estabilização de serviços.", avisos_globais)


# ==============================================================================
# TRANSPARÊNCIA FRONTEND (PLANO DE EXECUÇÃO / DRY-RUN LÓGICO)
# ==============================================================================

def obter_plano_instalacao(configuracao: ConfiguracaoSuricataDados | None = None) -> dict[str, object]:
    """Exibe em preview os metadados brutos das ações que serão orquestradas para que o usuário aprove o escopo."""
    cfg_pronta, erros = preparar_configuracao_instalacao(configuracao)
    
    plano = {
        "configuracao": cfg_pronta.to_dict() if cfg_pronta else {},
        "etapas": [],
        "comandos_previstos": [],
        "arquivos_alterados": [],
        "servicos_afetados": [],
        "avisos": [],
        "bloqueios": erros,
    }

    if not verificar_linux().sucesso or not verificar_privilegios().sucesso:
        plano["bloqueios"].append("A máquina requer privilégios totais (Root) de sistema operacional Linux (Debian) para ser transformada num IDS node.")
        
    gerenciador = detectar_gerenciador_pacotes()

    plano["etapas"].extend([
        {"id": "verificar_ambiente", "titulo": "Verificar Ambiente", "descricao": "Verificação SO e privilégios", "obrigatoria": True, "estimativa_segundos": 2},
        {"id": "instalar_suricata", "titulo": "Obter IDS nativo", "descricao": "Download/Aptidão de Suricata Engine", "obrigatoria": True, "estimativa_segundos": 180},
    ])
    
    usar_et = True
    if cfg_pronta and not cfg_pronta.instalar_et_open:
        usar_et = False
        
    if usar_et:
        plano["etapas"].append({"id": "atualizar_et_open", "titulo": "Regras ET-Open", "descricao": "Ingresso do ET-Open Signatures", "obrigatoria": False, "estimativa_segundos": 150})
        
    plano["etapas"].extend([
        {"id": "copiar_regras_moonshield", "titulo": "Aplica MS-Rules", "descricao": "Filtros custom MoonShield", "obrigatoria": True, "estimativa_segundos": 2},
        {"id": "configurar_suricata", "titulo": "Injetar Configuração", "descricao": "Manipulação atômica via PATCH yaml.", "obrigatoria": True, "estimativa_segundos": 5},
        {"id": "validar_suricata", "titulo": "Dry-Run Suricata", "descricao": "Validação cruzada de conformidade (Engine).", "obrigatoria": True, "estimativa_segundos": 20},
        {"id": "reiniciar_servicos", "titulo": "Deploy Memory-State", "descricao": "Daemon reload e Restart Service (Bounce)", "obrigatoria": True, "estimativa_segundos": 30},
    ])

    if gerenciador:
        cmd_i = obter_comando_instalacao(PACOTE_SURICATA, gerenciador)
        if cmd_i:
            plano["comandos_previstos"].append(cmd_i)

    # Previsões Lógicas
    path_yaml = cfg_pronta.yaml_path if cfg_pronta else "/etc/suricata/suricata.yaml"
    plano["arquivos_alterados"].extend([
        path_yaml,
        f"{path_yaml}.moonshield.bak",
        "/var/lib/suricata/rules/moonshield/ms.rules",
        "/etc/suricata/rules/moonshield/ms.rules",
    ])
    
    plano["servicos_afetados"].extend([SERVICO_SURICATA, SERVICO_MONITOR])

    return plano


def validar_plano_instalacao(plano: dict[str, object]) -> list[str]:
    """Inspeção de sanity check do array JSON do plano para blindar eventuais frontends mal comportados."""
    erros = []
    
    etapas_ids = [e.get("id") for e in plano.get("etapas", []) if isinstance(e, dict)]
    for eid in etapas_ids:
        if eid not in ETAPAS_INSTALACAO:
            erros.append(f"A etapa de provisionamento fornecida no manifesto não é oficial ({eid}).")

    for cmd in plano.get("comandos_previstos", []):
        if not isinstance(cmd, list):
            erros.append("Sintaxe shell subvertida no mapeamento de comandos previstos.")
        elif any(c in {"|", ">", "&&", ";"} for c in cmd):
            erros.append("Assinatura maliciosa encontrada em manifest list_str command.")
            
    for srv in plano.get("servicos_afetados", []):
        if srv not in {SERVICO_SURICATA, SERVICO_MONITOR}:
            erros.append(f"Alvo logico inválido detectado na instrução ({srv}).")

    return erros


def cancelar_instalacao(progresso: ProgressoTarefa, mensagem: str = "Instalação cancelada pelo usuário.") -> ResultadoEtapa:
    """Intervenção stateful de kill da thread orquestradora."""
    progresso.cancelar(mensagem)
    res = _criar_resultado_etapa("cancelar_instalacao", mensagem)
    res.status = StatusEtapa.CANCELADO
    res.sucesso = False
    return res


def obter_resumo_instalacao(resultado: ResultadoEtapa) -> dict[str, object]:
    """Parseador da view/interface que consolida a matrix pesada do ResultadoEtapa global num dashboard UI clean."""
    etapas = resultado.dados.get("etapas", {})
    t_suc = sum(1 for v in etapas.values() if v.get("sucesso", False))
    
    resumo = {
        "sucesso": resultado.sucesso,
        "mensagem": resultado.mensagem,
        "etapas_total": len(etapas),
        "etapas_sucesso": t_suc,
        "etapas_erro": len(etapas) - t_suc,
        "avisos": resultado.dados.get("avisos", []),
        "configuracao": resultado.dados.get("configuracao", {}),
        "status_final": resultado.dados.get("status_final", {}),
        "diagnostico_pronto": resultado.dados.get("diagnostico", {}).get("pronto", False),
        "erro": resultado.erro
    }
    return resumo