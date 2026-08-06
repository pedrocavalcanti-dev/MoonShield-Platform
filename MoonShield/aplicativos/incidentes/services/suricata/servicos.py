"""
Módulo de controle estrito para serviços do sistema (Systemd) relacionados ao Suricata IDS.
Prove isolamento seguro validando nomes e ações via whitelist e garantindo sequenciamento de dependências.
"""

import os
import time
import logging
from pathlib import Path
from datetime import datetime

from .tipos import (
    ResultadoEtapa,
    StatusEtapa,
    NivelLog,
    DiagnosticoItem,
    StatusServicoDados,
    EstadoServico,
)
from .comandos import executar_comando, comando_existe
from .ambiente import eh_linux, verificar_privilegios

logger = logging.getLogger(__name__)

# ==============================================================================
# CONSTANTES OBRIGATÓRIAS
# ==============================================================================

SERVICO_SURICATA = "suricata"
SERVICO_MONITOR = "moonshield-suricata-monitor"
SERVICO_WORKER = "moonshield-suricata-worker"

SERVICOS_PERMITIDOS = {
    SERVICO_SURICATA,
    SERVICO_MONITOR,
    SERVICO_WORKER,
}

TIMEOUT_PADRAO_SYSTEMCTL = 60.0
TIMEOUT_REINICIO = 120.0
INTERVALO_VERIFICACAO = 1.0

MAX_LINHAS_LOG = 500
DIRETORIO_UNITS_SYSTEMD = Path("/etc/systemd/system")
MODO_UNIT_SYSTEMD = 0o644

ESTADOS_ATIVOS_SYSTEMD = {
    "active",
    "activating",
}

ESTADOS_FALHA_SYSTEMD = {
    "failed",
}


# ==============================================================================
# VALIDAÇÕES DE SEGURANÇA (WHITELISTS)
# ==============================================================================

def validar_nome_servico(nome: str) -> str:
    """Higieniza e assegura que apenas serviços conhecidos pelo sistema de IDS sejam operados."""
    if not isinstance(nome, str):
        raise ValueError("O nome do serviço deve ser uma string.")
        
    nome_limpo = nome.strip()
    if not nome_limpo:
        raise ValueError("O nome do serviço não pode estar vazio.")
        
    # Previne concatenações e subshells em nomes maliciosos
    caracteres_invalidos = set("|<>;$&`()[]{}\\ \x00")
    if any(c in caracteres_invalidos for c in nome_limpo):
        raise ValueError("Caracteres proibidos detectados no nome do serviço.")
        
    if nome_limpo not in SERVICOS_PERMITIDOS:
        raise ValueError(f"Operação negada. O serviço '{nome_limpo}' não está na whitelist do módulo de Segurança.")
        
    return nome_limpo


def systemd_disponivel() -> bool:
    """Checa se o daemon nativo do Linux suportado está presente na máquina local."""
    return eh_linux() and comando_existe("systemctl")


# ==============================================================================
# LEITURAS DE ESTADO (SOMENTE LEITURA)
# ==============================================================================

def obter_estado_bruto(nome: str) -> str:
    """Interroga o init local para obter o status de atividade nominal da unidade."""
    nome_seguro = validar_nome_servico(nome)
    
    if not systemd_disponivel():
        return "desconhecido"
        
    cmd = executar_comando(["systemctl", "is-active", nome_seguro], timeout=15.0)
    
    if cmd.timeout:
        return "desconhecido"
        
    # 'is-active' joga pra stderr em caso de erro as vezes, ou stdout limpo se ativou
    saida = cmd.stdout.strip()
    if not saida:
        saida = cmd.stderr.strip()
        
    # 'is-active' pode printar 'inactive', 'failed', 'unknown', etc.
    if saida:
        return saida.lower()
        
    return "desconhecido"


def mapear_estado_servico(estado_bruto: str, instalado: bool = True) -> EstadoServico:
    """Normaliza o texto variável do systemd em uma Enum tipada previsível."""
    if not instalado:
        return EstadoServico.NAO_INSTALADO
        
    bruto_limpo = estado_bruto.strip().lower()
    
    if bruto_limpo in ESTADOS_ATIVOS_SYSTEMD:
        return EstadoServico.ATIVO
    if bruto_limpo in ("inactive", "deactivating"):
        return EstadoServico.INATIVO
    if bruto_limpo in ESTADOS_FALHA_SYSTEMD:
        return EstadoServico.FALHOU
        
    return EstadoServico.DESCONHECIDO


def servico_instalado(nome: str) -> bool:
    """Verifica se os arquivos da Unit constam no FS do Systemd."""
    nome_seguro = validar_nome_servico(nome)
    
    if not systemd_disponivel():
        return False
        
    cmd = executar_comando(
        ["systemctl", "show", nome_seguro, "--property=LoadState", "--value"],
        timeout=15.0
    )
    
    if cmd.falhou or not cmd.stdout:
        return False
        
    saida = cmd.stdout.strip().lower()
    # 'loaded' significa que o arquivo service foi lido
    return saida == "loaded"


def servico_habilitado(nome: str) -> bool:
    """Verifica se a Unit foi pinada nos targets de boot automáticos."""
    nome_seguro = validar_nome_servico(nome)
    
    if not systemd_disponivel():
        return False
        
    cmd = executar_comando(["systemctl", "is-enabled", nome_seguro], timeout=15.0)
    saida = cmd.stdout.strip().lower()
    
    estados_ativos = {"enabled", "enabled-runtime", "static", "indirect", "generated"}
    return saida in estados_ativos


def obter_pid_servico(nome: str) -> int | None:
    """Localiza o processo principal (MainPID) amarrado ao controle do serviço."""
    nome_seguro = validar_nome_servico(nome)
    
    if not systemd_disponivel():
        return None
        
    cmd = executar_comando(
        ["systemctl", "show", nome_seguro, "--property=MainPID", "--value"],
        timeout=15.0
    )
    
    if cmd.falhou or not cmd.stdout:
        return None
        
    try:
        pid = int(cmd.stdout.strip())
        return pid if pid > 0 else None
    except ValueError:
        return None


def obter_propriedades_servico(nome: str) -> dict[str, str]:
    """Coleta num só passe todos os metadados gerenciais da Unit informada."""
    nome_seguro = validar_nome_servico(nome)
    resultado = {}
    
    if not systemd_disponivel():
        return resultado
        
    props = "Id,LoadState,ActiveState,SubState,UnitFileState,MainPID,ExecMainStatus,ExecMainStartTimestamp"
    cmd = executar_comando(
        ["systemctl", "show", nome_seguro, f"--property={props}"],
        timeout=20.0
    )
    
    if cmd.sucesso and cmd.stdout:
        for linha in cmd.stdout.splitlines():
            if "=" in linha:
                chave, valor = linha.split("=", 1)
                resultado[chave.strip()] = valor.strip()
                
    return resultado


def obter_status_servico(nome: str) -> StatusServicoDados:
    """Fábrica de dados estruturada que reflete instantaneamente um endpoint systemd local."""
    # Preserva o nome se for para logging mesmo que a checagem quebre
    nome_final = nome.strip()
    try:
        nome_seguro = validar_nome_servico(nome)
        nome_final = nome_seguro
    except ValueError:
        return StatusServicoDados(nome=nome_final, estado=EstadoServico.DESCONHECIDO, detalhes="Nome de serviço não permitido.")

    dados = StatusServicoDados(nome=nome_final)
    
    if not systemd_disponivel():
        dados.detalhes = "Systemd indisponível (Linux nativo requerido)."
        return dados

    instalado = servico_instalado(nome_final)
    dados.instalado = instalado
    
    if not instalado:
        dados.estado = EstadoServico.NAO_INSTALADO
        dados.detalhes = "A unidade de serviço (.service) não foi encontrada."
        return dados
        
    estado_bruto = obter_estado_bruto(nome_final)
    dados.estado = mapear_estado_servico(estado_bruto, instalado)
    dados.ativo = (dados.estado == EstadoServico.ATIVO)
    dados.habilitado = servico_habilitado(nome_final)
    dados.pid = obter_pid_servico(nome_final)
    dados.detalhes = f"Estado nativo systemd: {estado_bruto}"
    
    return dados


def obter_status_servicos() -> dict[str, StatusServicoDados]:
    """Visão panorâmica em tempo real da matriz de serviços do MoonShield."""
    return {
        SERVICO_SURICATA: obter_status_servico(SERVICO_SURICATA),
        SERVICO_MONITOR: obter_status_servico(SERVICO_MONITOR),
        SERVICO_WORKER: obter_status_servico(SERVICO_WORKER),
    }


def obter_logs_servico(nome: str, linhas: int = 50, desde: str | None = None) -> ResultadoEtapa:
    """Extrai passivamente buffers do systemd journal, protegendo contra tail shell injections."""
    nome_seguro = validar_nome_servico(nome)
    
    # Limitação sanitária
    linhas_safe = max(1, min(linhas, MAX_LINHAS_LOG))
    
    etapa_id = "logs_servico"
    res = ResultadoEtapa(
        etapa=etapa_id,
        status=StatusEtapa.EXECUTANDO,
        sucesso=False,
        mensagem=f"Puxando últimas {linhas_safe} linhas do journal para '{nome_seguro}'...",
        iniciado_em=datetime.now()
    )

    if not systemd_disponivel():
        res.finalizar_erro("Gerenciador de logs Systemd não está disponível no SO base.")
        return res

    cmd_args = [
        "journalctl",
        "-u", nome_seguro,
        "--no-pager",
        "-n", str(linhas_safe),
        "--output=short-iso"
    ]
    
    if desde:
        cmd_args.extend(["--since", str(desde)])

    cmd = executar_comando(cmd_args, timeout=30.0)
    
    if cmd.timeout:
        res.finalizar_erro("O leitor de journalctl travou ou excedeu o limite de tempo.")
        return res
        
    # 'journalctl' sem logs pra unidade retorna código 0 e output "No journal files were found" ou vazio
    texto = cmd.stdout.strip()
    lista_linhas = [l for l in texto.splitlines() if l.strip()]

    res.dados = {
        "linhas": lista_linhas,
        "texto_completo": texto,
        "quantidade": len(lista_linhas),
        "comando": cmd.to_dict()
    }
    
    res.adicionar_log(f"Journal leu {len(lista_linhas)} linhas para {nome_seguro}.", NivelLog.INFO)
    res.finalizar_sucesso("Leitura de logs realizada com sucesso.")
    return res


def obter_erros_recentes_servico(nome: str, linhas: int = 100) -> list[str]:
    """Auxiliar de diagnóstico focado em achar exceções no log bruto de um daemon."""
    res_logs = obter_logs_servico(nome, linhas=linhas)
    erros = []
    
    if not res_logs.sucesso:
        return erros
        
    lista_linhas = res_logs.dados.get("linhas", [])
    
    termos_falha = {
        "error", "failed", "fatal", "exception", "permission denied", "denied"
    }

    for linha in lista_linhas:
        linha_lower = linha.lower()
        if any(termo in linha_lower for termo in termos_falha):
            erros.append(linha.strip())
            
    # Trava em 20 para não explodir payload HTTP
    return erros[-20:]


def aguardar_estado(
    nome: str,
    estados_esperados: set[str],
    timeout: float = 30.0,
    intervalo: float = INTERVALO_VERIFICACAO,
) -> tuple[bool, str]:
    """Loop temporal contínuo sem uso de CPU (sleeps esparsos) até a transição da Unit."""
    if not isinstance(estados_esperados, set):
        estados_esperados = set(estados_esperados)
        
    t_max = max(1.0, timeout)
    i_val = max(0.1, intervalo)
    
    inicio = time.monotonic()
    ultimo = "desconhecido"
    
    while (time.monotonic() - inicio) < t_max:
        ultimo = obter_estado_bruto(nome)
        if ultimo in estados_esperados:
            return True, ultimo
        time.sleep(i_val)
        
    return False, ultimo


# ==============================================================================
# MANIPULAÇÃO DO ESTADO DE SISTEMA (MUTAÇÕES)
# ==============================================================================

def _executar_acao_systemctl(
    nome: str,
    acao: str,
    timeout: float = TIMEOUT_PADRAO_SYSTEMCTL,
) -> ResultadoEtapa:
    """Motor restrito. Só roda se todos os checkpoints passarem rigorosamente."""
    nome_seguro = validar_nome_servico(nome)
    
    acoes_permitidas = {"start", "stop", "restart", "reload", "enable", "disable"}
    acao_limpa = acao.strip().lower()
    
    if acao_limpa not in acoes_permitidas:
        raise ValueError(f"Ação do systemd não autorizada (Tentativa: {acao_limpa})")
        
    etapa_id = f"{acao_limpa}_servico"
    res = ResultadoEtapa(
        etapa=etapa_id,
        status=StatusEtapa.EXECUTANDO,
        sucesso=False,
        mensagem=f"Preparando controle systemd [{acao_limpa}] para {nome_seguro}",
        iniciado_em=datetime.now()
    )

    if not systemd_disponivel():
        res.finalizar_erro("Recurso exclusivo a distribuições com o gestor systemd.")
        return res
        
    if not verificar_privilegios().sucesso:
        res.finalizar_erro("Faltam privilégios de administrador (root).")
        return res

    if not servico_instalado(nome_seguro):
        res.finalizar_erro(f"Ação bloqueada. Unit {nome_seguro} não está instalada no FS.")
        return res

    res.adicionar_log(f"Comando autorizado. Solicitando {acao_limpa}...", NivelLog.INFO)
    
    cmd = executar_comando(
        ["systemctl", acao_limpa, nome_seguro],
        timeout=timeout
    )
    
    res.dados["comando"] = cmd.to_dict()

    if cmd.sucesso:
        res.adicionar_log("Comando enviado e acatado pelo Systemd.", NivelLog.SUCESSO)
        res.finalizar_sucesso("Transação concluída.")
    else:
        res.adicionar_log(f"Systemd rejeitou comando: {cmd.erro or cmd.saida}", NivelLog.ERRO)
        res.finalizar_erro("Falha durante instrução do serviço.", erro=cmd.erro or cmd.saida)
        
    return res


def iniciar_servico(nome: str, aguardar: bool = True, timeout_estabilizacao: float = 30.0) -> ResultadoEtapa:
    """Requisita start de serviço e rastreia o alcance real da meta 'active'."""
    estado_atual = obter_estado_bruto(nome)
    if estado_atual == "active":
        res = ResultadoEtapa("start_servico", StatusEtapa.SUCESSO, True, "Idempotente: O serviço já estava ativo.", iniciado_em=datetime.now())
        res.finalizar_sucesso()
        return res
        
    res = _executar_acao_systemctl(nome, "start", timeout=TIMEOUT_PADRAO_SYSTEMCTL)
    
    if res.sucesso and aguardar:
        atingiu, st_final = aguardar_estado(nome, ESTADOS_ATIVOS_SYSTEMD, timeout=timeout_estabilizacao)
        res.dados["estado_final"] = st_final
        if not atingiu:
            res.adicionar_log("Timeout enquanto o processo inicializava.", NivelLog.AVISO)
            res.finalizar_erro(
                mensagem="Processo não transicionou para ATIVO a tempo.",
                erro=f"Estabilizou no estado: {st_final}"
            )
            
    return res


def parar_servico(nome: str, aguardar: bool = True, timeout_estabilizacao: float = 30.0) -> ResultadoEtapa:
    """Força sinal de stop e garante inatividade (SIGTERM fallback implicito systemd)."""
    estado_atual = obter_estado_bruto(nome)
    if estado_atual in ("inactive", "failed", "desconhecido"):
        res = ResultadoEtapa("stop_servico", StatusEtapa.SUCESSO, True, "Idempotente: O serviço já se encontrava offline.", iniciado_em=datetime.now())
        res.finalizar_sucesso()
        return res
        
    res = _executar_acao_systemctl(nome, "stop", timeout=TIMEOUT_PADRAO_SYSTEMCTL)
    
    if res.sucesso and aguardar:
        estados_fim = {"inactive", "failed"}
        atingiu, st_final = aguardar_estado(nome, estados_fim, timeout=timeout_estabilizacao)
        res.dados["estado_final"] = st_final
        if not atingiu:
            res.adicionar_log("Processo estagnou no desligamento (Zumbi?).", NivelLog.ERRO)
            res.finalizar_erro(
                mensagem="Serviço não encerrou no tempo hábil.",
                erro=f"Estabilizou no estado: {st_final}"
            )
            
    return res


def reiniciar_servico(nome: str, aguardar: bool = True, timeout_estabilizacao: float = 60.0) -> ResultadoEtapa:
    """Bounce robusto. Extrai logs automaticamente em caso de crash (Ex: regra ET Open quebrou o YAML)."""
    res = _executar_acao_systemctl(nome, "restart", timeout=TIMEOUT_REINICIO)
    
    if res.sucesso and aguardar:
        atingiu, st_final = aguardar_estado(nome, ESTADOS_ATIVOS_SYSTEMD, timeout=timeout_estabilizacao)
        res.dados["estado_final"] = st_final
        
        if not atingiu:
            res.adicionar_log("Systemctl enviou RESTART ok, porém o daemon falhou/crashou em seguida.", NivelLog.ERRO)
            
            # Análise post-mortem instantânea
            erros_journal = obter_erros_recentes_servico(nome, linhas=50)
            if erros_journal:
                res.dados["erros_recentes"] = erros_journal
                err_concat = " | ".join(erros_journal[:2])
            else:
                err_concat = "Nenhum erro reportado nos ultimos 50 logs da unidade."
                
            res.finalizar_erro(
                mensagem="O serviço iniciou o reload mas crashou (Failed/Inactive).",
                erro=f"Diagnóstico do Journal: {err_concat}"
            )
            
    return res


def recarregar_servico(nome: str, aguardar: bool = True) -> ResultadoEtapa:
    """Solicita recarga de conf 'Live' ao processo (SIGHUP) sem downtime de conexão."""
    # Nota: Alguns units podem não possuir diretiva de reload gerando falha nativa.
    # Nestes casos, delegamos o erro para a view web e não escalamos restart sem autorização.
    return _executar_acao_systemctl(nome, "reload", timeout=TIMEOUT_PADRAO_SYSTEMCTL)


def habilitar_servico(nome: str, iniciar_agora: bool = False) -> ResultadoEtapa:
    """Registra as dependências symlinks no sistema e opcionalmente garante processo ativo."""
    res = _executar_acao_systemctl(nome, "enable", timeout=TIMEOUT_PADRAO_SYSTEMCTL)
    
    if res.sucesso and iniciar_agora:
        res.adicionar_log("Habilitado via config de boot. Invocando inicio imediato...", NivelLog.INFO)
        res_inicio = iniciar_servico(nome)
        if not res_inicio.sucesso:
            res.adicionar_log("Start pós-habilitação falhou.", NivelLog.ERRO)
            res.finalizar_erro("Unidade symlinkada para inicializar depois, mas start instantâneo falhou.", erro=res_inicio.erro)
            
    return res


def desabilitar_servico(nome: str, parar_agora: bool = False) -> ResultadoEtapa:
    """Remove presença do target de boot para o próximo startup."""
    res = _executar_acao_systemctl(nome, "disable", timeout=TIMEOUT_PADRAO_SYSTEMCTL)
    
    if res.sucesso and parar_agora:
        res.adicionar_log("Boot config desativado. Matando processos em memória...", NivelLog.INFO)
        res_parada = parar_servico(nome)
        if not res_parada.sucesso:
            res.adicionar_log("Disable efetuado, mas o stop runtime falhou.", NivelLog.ERRO)
            res.finalizar_erro("Start removido, porém o Stop do processo runtime retornou erro.", erro=res_parada.erro)
            
    return res


def daemon_reload() -> ResultadoEtapa:
    """Recarrega os metadados de FS do Systemd para adotar drop-ins novos (ex: override.conf)."""
    etapa_id = "systemd_daemon_reload"
    res = ResultadoEtapa(
        etapa=etapa_id,
        status=StatusEtapa.EXECUTANDO,
        sucesso=False,
        mensagem="Forçando reconstrução do registry global systemd.",
        iniciado_em=datetime.now()
    )

    if not systemd_disponivel():
        res.finalizar_erro("Gerenciador ausente.")
        return res
        
    if not verificar_privilegios().sucesso:
        res.finalizar_erro("Permissão System/Root necessária.")
        return res

    cmd = executar_comando(["systemctl", "daemon-reload"], timeout=60.0)
    res.dados["comando"] = cmd.to_dict()

    if cmd.sucesso:
        res.adicionar_log("Registry regerado.", NivelLog.SUCESSO)
        res.finalizar_sucesso("Os arquivos unitários modificados foram reconhecidos pelo sistema.")
    else:
        res.adicionar_log("Erro durante reload geral.", NivelLog.ERRO)
        res.finalizar_erro("O systemctl rejeitou a carga de arquivos das units.", erro=cmd.erro or cmd.saida)
        
    return res



# ==============================================================================
# INSTALAÇÃO E ATUALIZAÇÃO DAS UNITS MOONSHIELD
# ==============================================================================

def _escapar_valor_systemd(valor: str | Path) -> str:
    texto = str(valor).strip()
    if not texto:
        raise ValueError("Valor vazio não pode ser usado em uma unit systemd.")
    if "\n" in texto or "\r" in texto or "\x00" in texto:
        raise ValueError("Valor inválido para manifesto systemd.")
    return texto


def _escrever_unit_atomica(
    nome_servico: str,
    conteudo: str,
    diretorio_units: str | Path = DIRETORIO_UNITS_SYSTEMD,
) -> ResultadoEtapa:
    """Grava uma unit systemd de forma atômica e idempotente."""
    nome_seguro = validar_nome_servico(nome_servico)
    res = ResultadoEtapa(
        etapa="instalar_unit_systemd",
        status=StatusEtapa.EXECUTANDO,
        sucesso=False,
        mensagem=f"Instalando unit {nome_seguro}.",
        iniciado_em=datetime.now(),
    )

    if not systemd_disponivel():
        res.finalizar_erro("Systemd indisponível.")
        return res

    if not verificar_privilegios().sucesso:
        res.finalizar_erro("Privilégios root são obrigatórios.")
        return res

    destino_dir = Path(diretorio_units)
    destino = destino_dir / f"{nome_seguro}.service"
    temporario = destino_dir / (
        f".{nome_seguro}.service.moonshield.{os.getpid()}.tmp"
    )

    try:
        destino_dir.mkdir(parents=True, exist_ok=True)
        conteudo_final = conteudo.strip() + "\n"

        if destino.exists():
            atual = destino.read_text(encoding="utf-8", errors="replace")
            if atual == conteudo_final:
                res.dados = {"caminho": str(destino), "alterado": False}
                res.finalizar_sucesso(
                    f"Unit {nome_seguro} já estava atualizada."
                )
                return res

        with temporario.open("w", encoding="utf-8", newline="\n") as arquivo:
            arquivo.write(conteudo_final)
            arquivo.flush()
            os.fsync(arquivo.fileno())

        os.chmod(temporario, MODO_UNIT_SYSTEMD)
        os.replace(temporario, destino)

        res.dados = {"caminho": str(destino), "alterado": True}
        res.finalizar_sucesso(f"Unit {nome_seguro} instalada.")
    except Exception as exc:
        logger.exception("Falha ao instalar unit %s.", nome_seguro)
        res.finalizar_erro(
            f"Não foi possível instalar a unit {nome_seguro}.",
            erro=str(exc),
        )
    finally:
        try:
            temporario.unlink(missing_ok=True)
        except OSError:
            pass

    return res


def gerar_unit_monitor_suricata(
    *,
    base_dir: str | Path,
    python_executavel: str | Path,
    gerenciar_path: str | Path,
    eve_path: str | Path,
    cursor_path: str | Path,
) -> str:
    base = _escapar_valor_systemd(base_dir)
    python = _escapar_valor_systemd(python_executavel)
    gerenciar = _escapar_valor_systemd(gerenciar_path)
    eve = _escapar_valor_systemd(eve_path)
    cursor = _escapar_valor_systemd(cursor_path)

    return f"""[Unit]
Description=MoonShield Suricata Local Monitor
After=network-online.target suricata.service
Wants=network-online.target
Requires=suricata.service

[Service]
Type=simple
User=root
WorkingDirectory={base}
Environment=PYTHONUNBUFFERED=1
ExecStart={python} {gerenciar} monitorar_suricata --arquivo {eve} --cursor {cursor}
Restart=always
RestartSec=3
TimeoutStopSec=30
KillSignal=SIGTERM

[Install]
WantedBy=multi-user.target
"""


def gerar_unit_worker_tarefas(
    *,
    base_dir: str | Path,
    python_executavel: str | Path,
    gerenciar_path: str | Path,
) -> str:
    base = _escapar_valor_systemd(base_dir)
    python = _escapar_valor_systemd(python_executavel)
    gerenciar = _escapar_valor_systemd(gerenciar_path)

    return f"""[Unit]
Description=MoonShield Suricata Task Worker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory={base}
Environment=PYTHONUNBUFFERED=1
ExecStart={python} {gerenciar} processar_tarefas_suricata
Restart=always
RestartSec=3
TimeoutStopSec=60
KillSignal=SIGTERM

[Install]
WantedBy=multi-user.target
"""


def instalar_units_moonshield(
    *,
    base_dir: str | Path,
    python_executavel: str | Path,
    gerenciar_path: str | Path,
    eve_path: str | Path,
    cursor_path: str | Path,
    habilitar: bool = True,
    iniciar_monitor: bool = False,
    iniciar_worker: bool = False,
) -> ResultadoEtapa:
    """
    Instala/atualiza monitor e worker, recarrega o systemd e habilita autostart.

    O worker não é reiniciado por padrão porque esta função pode estar rodando
    dentro do próprio worker durante uma instalação.
    """
    res = ResultadoEtapa(
        etapa="instalar_units_moonshield",
        status=StatusEtapa.EXECUTANDO,
        sucesso=False,
        mensagem="Instalando serviços auxiliares MoonShield.",
        iniciado_em=datetime.now(),
    )
    resultados = {}

    r_monitor = _escrever_unit_atomica(
        SERVICO_MONITOR,
        gerar_unit_monitor_suricata(
            base_dir=base_dir,
            python_executavel=python_executavel,
            gerenciar_path=gerenciar_path,
            eve_path=eve_path,
            cursor_path=cursor_path,
        ),
    )
    resultados["unit_monitor"] = r_monitor.to_dict()
    if not r_monitor.sucesso:
        res.dados = resultados
        res.finalizar_erro("Falha ao instalar unit do monitor.", erro=r_monitor.erro)
        return res

    r_worker = _escrever_unit_atomica(
        SERVICO_WORKER,
        gerar_unit_worker_tarefas(
            base_dir=base_dir,
            python_executavel=python_executavel,
            gerenciar_path=gerenciar_path,
        ),
    )
    resultados["unit_worker"] = r_worker.to_dict()
    if not r_worker.sucesso:
        res.dados = resultados
        res.finalizar_erro("Falha ao instalar unit do worker.", erro=r_worker.erro)
        return res

    r_reload = daemon_reload()
    resultados["daemon_reload"] = r_reload.to_dict()
    if not r_reload.sucesso:
        res.dados = resultados
        res.finalizar_erro("Daemon-reload falhou.", erro=r_reload.erro)
        return res

    if habilitar:
        for nome in (SERVICO_MONITOR, SERVICO_WORKER):
            r_enable = habilitar_servico(nome)
            resultados[f"enable_{nome}"] = r_enable.to_dict()
            if not r_enable.sucesso:
                res.dados = resultados
                res.finalizar_erro(
                    f"Não foi possível habilitar {nome}.",
                    erro=r_enable.erro,
                )
                return res

    if iniciar_monitor:
        r_start = iniciar_servico(SERVICO_MONITOR)
        resultados["start_monitor"] = r_start.to_dict()
        if not r_start.sucesso:
            res.dados = resultados
            res.finalizar_erro(
                "Monitor não iniciou.",
                erro=r_start.erro,
            )
            return res

    if iniciar_worker:
        r_start = iniciar_servico(SERVICO_WORKER)
        resultados["start_worker"] = r_start.to_dict()
        if not r_start.sucesso:
            res.dados = resultados
            res.finalizar_erro(
                "Worker não iniciou.",
                erro=r_start.erro,
            )
            return res

    res.dados = resultados
    res.finalizar_sucesso(
        "Units do monitor e worker instaladas e habilitadas."
    )
    return res


# ==============================================================================
# ORQUESTRAÇÃO DE START/STOP DO STACK CONJUGADO
# ==============================================================================

def reiniciar_stack_suricata(reiniciar_suricata_primeiro: bool = True) -> ResultadoEtapa:
    """Processo mestre em cascata para cold/warm bounce da matriz do MoonShield."""
    etapa_id = "reiniciar_stack_suricata"
    res = ResultadoEtapa(etapa=etapa_id, status=StatusEtapa.EXECUTANDO, sucesso=False, mensagem="Inicializando sequenciador de restart.", iniciado_em=datetime.now())

    # Drop-ins requerem recarga
    res_daemon = daemon_reload()
    res.dados["daemon_reload"] = res_daemon.to_dict()
    if not res_daemon.sucesso:
        res.finalizar_erro("Abordando bounce por falha base de daemon_reload.", erro=res_daemon.erro)
        return res

    def _bounce_suricata() -> bool:
        res.adicionar_log("Bouncing Engine IDS (Suricata)...", NivelLog.INFO)
        r_s = reiniciar_servico(SERVICO_SURICATA)
        res.dados["suricata"] = r_s.to_dict()
        if not r_s.sucesso:
            res.finalizar_erro("Falha crassa. Suricata engine não estabilizou.", erro=r_s.erro)
            return False
        return True

    def _bounce_monitor() -> bool:
        res.adicionar_log("Bouncing Worker Django...", NivelLog.INFO)
        r_m = reiniciar_servico(SERVICO_MONITOR)
        res.dados["monitor"] = r_m.to_dict()
        if not r_m.sucesso:
            res.finalizar_erro("O monitor ingress não iniciou (Possivelmente log rotacionou no bounce).", erro=r_m.erro)
            return False
        return True

    if reiniciar_suricata_primeiro:
        if not _bounce_suricata(): return res
        if not _bounce_monitor(): return res
    else:
        if not _bounce_monitor(): return res
        if not _bounce_suricata(): return res

    res.finalizar_sucesso("Todo o cluster Suricata Moonshield subiu para ATIVO com sucesso.")
    return res


def parar_stack_suricata() -> ResultadoEtapa:
    """Realiza o un-deploy reverso da stack. Desliga receptor para depois derrubar gerador EVE."""
    etapa_id = "parar_stack_suricata"
    res = ResultadoEtapa(etapa=etapa_id, status=StatusEtapa.EXECUTANDO, sucesso=False, mensagem="Solicitando interrupção do cluster.", iniciado_em=datetime.now())

    # Derruba consumidor primeiro
    r_mon = parar_servico(SERVICO_MONITOR)
    res.dados["monitor"] = r_mon.to_dict()
    
    # Independente se o worker demorar para morrer (ainda drenando fila p banco), 
    # forçamos a engine C (Suricata) a dar stop da interface nativa
    r_suri = parar_servico(SERVICO_SURICATA)
    res.dados["suricata"] = r_suri.to_dict()

    if r_mon.sucesso and r_suri.sucesso:
        res.finalizar_sucesso("Unidades MoonShield + Suricata pausadas corretamente.")
    else:
        res.finalizar_erro("Ao menos um daemon falhou no graceful exit ou travou em desativação.")
        
    return res


def iniciar_stack_suricata() -> ResultadoEtapa:
    """Deployment runtime inicial - Garante geração para em seguida iniciar leitura."""
    etapa_id = "iniciar_stack_suricata"
    res = ResultadoEtapa(etapa=etapa_id, status=StatusEtapa.EXECUTANDO, sucesso=False, mensagem="Requisitando inicialização core do IDS.", iniciado_em=datetime.now())

    r_s = iniciar_servico(SERVICO_SURICATA)
    res.dados["suricata"] = r_s.to_dict()
    if not r_s.sucesso:
        res.finalizar_erro("Impeditivo: Motor C do Suricata recusou inicialização (YAML incorreto?).", erro=r_s.erro)
        return res

    res.adicionar_log("Motor primário UP. Startando coletor secundário (Worker Django)...", NivelLog.INFO)
    
    r_m = iniciar_servico(SERVICO_MONITOR)
    res.dados["monitor"] = r_m.to_dict()
    if not r_m.sucesso:
        res.finalizar_erro("O Suricata está funcionando, mas o leitor de EVE parou na subida.", erro=r_m.erro)
        return res

    res.finalizar_sucesso("Cluster 100% UP.")
    return res


# ==============================================================================
# AUDITORIAS PASSIVAS EM MASSA
# ==============================================================================

def verificar_dependencia_servicos() -> DiagnosticoItem:
    """Verifica se não houve inversão física ou quebra do modelo produtor-consumidor (IDS -> Worker)."""
    suri_up = obter_estado_bruto(SERVICO_SURICATA) in ESTADOS_ATIVOS_SYSTEMD
    mon_up = obter_estado_bruto(SERVICO_MONITOR) in ESTADOS_ATIVOS_SYSTEMD

    ok = True
    crit = False
    detalhe = "Integridade produtor/consumidor intacta."
    acao = ""

    if not suri_up:
        ok = False
        crit = True
        detalhe = "Motor Suricata desligado. Nenhuma ameaça será observada."
        acao = "Ative a base para retomada da visibilidade."
    elif not mon_up:
        ok = False
        crit = True
        detalhe = "O Suricata está gerando dados, mas o Worker que salva no banco parou."
        acao = "Reinicie a unidade moonshield-suricata-monitor."
    return DiagnosticoItem(
        id="dependencia_servicos",
        grupo="Serviços",
        titulo="Integridade de Fluxo (IDS → Database)",
        ok=ok,
        detalhe=detalhe,
        acao=acao,
        critico=crit,
    )


def gerar_checks_servicos() -> list[DiagnosticoItem]:
    """Expõe cada métrica isolada dos servicos vitais."""
    itens = []
    
    has_systemd = systemd_disponivel()
    itens.append(DiagnosticoItem(
        id="systemd_disponivel", grupo="Serviços", titulo="Gerenciador de Sistema Nativo",
        ok=has_systemd, detalhe="Obrigatório em Linux Server." if not has_systemd else "Systemd/systemctl pronto.",
        acao="O Moonshield foi desenvolvido especificamente com base no Ubuntu/Debian." if not has_systemd else "",
        critico=eh_linux(),
    ))

    # NÚCLEO
    s_suri = obter_status_servico(SERVICO_SURICATA)
    itens.append(DiagnosticoItem(
        id="servico_suricata_instalado", grupo="Serviços", titulo="Arquivo de Inicialização (.service)",
        ok=s_suri.instalado, detalhe="Presente." if s_suri.instalado else "Ausente do sistema base.",
        acao="Execute o onboarding de instalação para o Moonshield aplicar a base suricata no SO." if not s_suri.instalado else "",
        critico=True,
    ))

    itens.append(DiagnosticoItem(
        id="servico_suricata_habilitado", grupo="Serviços", titulo="Startup no Boot Nativo",
        ok=s_suri.habilitado, detalhe="Autostart ON." if s_suri.habilitado else "Se o servidor reiniciar o IDS permanecerá inativo.",
        acao="Execute: systemctl enable suricata" if not s_suri.habilitado else "",
        critico=False, # Somente Warning, é uma boa prática não regra técnica.
    ))

    itens.append(DiagnosticoItem(
        id="servico_suricata_ativo", grupo="Serviços", titulo="Memória Runtime (Executando)",
        ok=s_suri.ativo, detalhe=f"Processo PID: {s_suri.pid}" if s_suri.ativo else f"Status atual: {s_suri.estado.value}",
        acao="A rede está desprotegida, ligue o IDS." if not s_suri.ativo else "",
        critico=True,
    ))

    # WORKER DJANGO
    s_mon = obter_status_servico(SERVICO_MONITOR)
    itens.append(DiagnosticoItem(
        id="servico_monitor_instalado", grupo="Monitor MoonShield", titulo="Daemon de Ingestão de Dados (Unit)",
        ok=s_mon.instalado, detalhe="Presente." if s_mon.instalado else "Ausente. O arquivo de auto-consumo nunca foi deployado.",
        acao="Crie o manifesto moonshield-suricata-monitor.service" if not s_mon.instalado else "",
        critico=True,
    ))

    itens.append(DiagnosticoItem(
        id="servico_monitor_habilitado", grupo="Monitor MoonShield", titulo="Startup Automático do Ingress",
        ok=s_mon.habilitado, detalhe="Autostart ON." if s_mon.habilitado else "Após boot é preciso puxar script na mão.",
        acao="Systemctl enable moonshield-suricata-monitor." if not s_mon.habilitado else "",
        critico=False,
    ))

    itens.append(DiagnosticoItem(
        id="servico_monitor_ativo", grupo="Monitor MoonShield", titulo="Alimentação Contínua de Logs para o BD",
        ok=s_mon.ativo, detalhe="O Python Worker está processando o tail." if s_mon.ativo else f"Worker paralisado ou com erros: {s_mon.estado.value}",
        acao="Ligue o componente para o painel de alertas não estagnar." if not s_mon.ativo else "",
        critico=True,
    ))

    # WORKER DE TAREFAS
    s_worker = obter_status_servico(SERVICO_WORKER)

    itens.append(DiagnosticoItem(
        id="servico_worker_instalado",
        grupo="Worker de Tarefas",
        titulo="Executor Automático de Tarefas",
        ok=s_worker.instalado,
        detalhe="Unit presente." if s_worker.instalado else "Unit ausente.",
        acao="Instale moonshield-suricata-worker.service" if not s_worker.instalado else "",
        critico=True,
    ))

    itens.append(DiagnosticoItem(
        id="servico_worker_habilitado",
        grupo="Worker de Tarefas",
        titulo="Inicialização Automática",
        ok=s_worker.habilitado,
        detalhe="Autostart ON." if s_worker.habilitado else "Autostart OFF.",
        acao="Habilite moonshield-suricata-worker." if not s_worker.habilitado else "",
        critico=False,
    ))

    itens.append(DiagnosticoItem(
        id="servico_worker_ativo",
        grupo="Worker de Tarefas",
        titulo="Processamento Automático",
        ok=s_worker.ativo,
        detalhe=f"PID: {s_worker.pid}" if s_worker.ativo else f"Estado: {s_worker.estado.value}",
        acao="Inicie o worker para processar tarefas pendentes." if not s_worker.ativo else "",
        critico=True,
    ))

    # Relação Produtor/Consumidor
    if s_suri.instalado and s_mon.instalado:
        itens.append(verificar_dependencia_servicos())

    return itens


def obter_status_stack() -> dict[str, object]:
    """Sumário panorâmico da stack Suricata e dos workers MoonShield."""
    has_systemd = systemd_disponivel()

    st_suri = obter_status_servico(SERVICO_SURICATA)
    st_mon = obter_status_servico(SERVICO_MONITOR)
    st_worker = obter_status_servico(SERVICO_WORKER)

    ativa = st_suri.ativo and st_mon.ativo
    pronta = st_suri.instalado and st_mon.instalado and ativa

    avisos = []
    if not has_systemd and eh_linux():
        avisos.append(
            "Controles negados pois não há systemd/systemctl no hospedeiro."
        )
    if st_suri.instalado and not st_suri.ativo:
        avisos.append("A engine Suricata está parada.")
    if st_mon.instalado and not st_mon.ativo:
        avisos.append("O monitor de ingestão está parado.")
    if not st_worker.instalado:
        avisos.append("Worker automático de tarefas não está instalado.")
    elif not st_worker.ativo:
        avisos.append(
            "Worker automático está parado; tarefas novas ficarão pendentes."
        )

    return {
        "systemd_disponivel": has_systemd,
        "suricata": st_suri.to_dict(),
        "monitor": st_mon.to_dict(),
        "worker_tarefas": st_worker.to_dict(),
        "stack_ativa": ativa,
        "stack_pronta": pronta,
        "dependencia_ok": verificar_dependencia_servicos().ok,
        "avisos": avisos,
        "verificado_em": datetime.now().isoformat(),
    }
