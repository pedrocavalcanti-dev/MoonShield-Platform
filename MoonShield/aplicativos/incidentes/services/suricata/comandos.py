"""
Módulo de execução central e segura de comandos no sistema operacional.

Este módulo elimina o uso de shell=True da arquitetura antiga, garantindo a
validação e sanitização de argumentos, controle de timeout, logging estruturado
e rastreabilidade para o assistente de instalação/configuração do Suricata.
"""

import os
import shutil
import logging
import subprocess
import time
from pathlib import Path
from datetime import datetime

from .tipos import (
    ResultadoComando,
    ResultadoEtapa,
    StatusEtapa,
    NivelLog,
)

logger = logging.getLogger(__name__)

# Operadores que poderiam caracterizar injeção de shell se interpretados
OPERADORES_SHELL_PROIBIDOS = {
    "|", ">", ">>", "<", "<<", "&&", "||", ";", "$(", "`",
}

# Chaves comuns cujos valores devem ser sanitizados nos logs
CHAVES_SENSIVEIS = {
    "password", "senha", "token", "secret", "api_key", "authorization",
}


# ==============================================================================
# SEGURANÇA E SANITIZAÇÃO
# ==============================================================================

def validar_sem_operadores_shell(argumentos: list[str]) -> None:
    """Verifica individualmente se há tentativa de injeção direta de operadores shell."""
    for arg in argumentos:
        if arg in OPERADORES_SHELL_PROIBIDOS:
            raise ValueError(f"Argumento proibido (operador de shell detectado): {arg}")
        if "$(" in arg:
            raise ValueError(f"Argumento proibido (subshell detectada): {arg}")
        if "`" in arg:
            raise ValueError(f"Argumento proibido (backticks detectados): {arg}")


def sanitizar_argumentos_para_log(argumentos: list[str]) -> list[str]:
    """Cria uma cópia dos argumentos ocultando valores sensíveis para o logger."""
    arg_log = list(argumentos)
    ocultar_proximo = False

    for i, arg in enumerate(arg_log):
        if ocultar_proximo:
            arg_log[i] = "***"
            ocultar_proximo = False
            continue

        arg_lower = arg.lower()
        
        # Tratamento de formato "--chave=valor" ou "chave=valor"
        if "=" in arg:
            chave, _, valor = arg.partition("=")
            chave_limpa = chave.strip("-").lower()
            if chave_limpa in CHAVES_SENSIVEIS:
                arg_log[i] = f"{chave}=***"
        
        # Tratamento de formato "--chave valor"
        else:
            chave_limpa = arg_lower.strip("-")
            if chave_limpa in CHAVES_SENSIVEIS:
                ocultar_proximo = True

    return arg_log


def normalizar_argumentos(argumentos: list[str] | tuple[str, ...]) -> list[str]:
    """Assegura formato rigoroso de argumentos (list[str]) e ausência de injetores shell."""
    if not isinstance(argumentos, (list, tuple)):
        raise ValueError("Argumentos devem ser uma lista ou tupla.")
    
    if not argumentos:
        raise ValueError("Lista de argumentos não pode estar vazia.")

    args_normalizados = []
    for i, arg in enumerate(argumentos):
        if not isinstance(arg, str):
            raise ValueError(f"Argumento não é uma string na posição {i}.")
        if "\x00" in arg:
            raise ValueError(f"Caractere nulo detectado no argumento na posição {i}.")
        
        if i == 0:
            arg_processado = arg.strip()
            if not arg_processado:
                raise ValueError("O executável (primeiro argumento) não pode estar vazio.")
            args_normalizados.append(arg_processado)
        else:
            args_normalizados.append(arg)

    validar_sem_operadores_shell(args_normalizados)
    return args_normalizados


# ==============================================================================
# HELPERS DE INFORMAÇÃO (LOCALIZAÇÃO)
# ==============================================================================

def localizar_comando(nome: str) -> str | None:
    """Busca o caminho completo do executável no PATH (Seguro - não executa)."""
    nome_limpo = nome.strip() if isinstance(nome, str) else ""
    if not nome_limpo:
        return None
    return shutil.which(nome_limpo)


def comando_existe(nome: str) -> bool:
    """Retorna verdadeiro caso o binário seja localizado no PATH."""
    return localizar_comando(nome) is not None


def _resultado_erro(argumentos: list[str], codigo: int, erro: str, comando_encontrado: bool = True) -> ResultadoComando:
    """Factory builder privado para gerar falhas padronizadas do ResultadoComando."""
    return ResultadoComando(
        argumentos=argumentos,
        codigo=codigo,
        sucesso=False,
        erro=erro,
        comando_encontrado=comando_encontrado,
    )


# ==============================================================================
# NÚCLEO DE EXECUÇÃO
# ==============================================================================

def executar_comando(
    argumentos: list[str] | tuple[str, ...],
    timeout: float = 120.0,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
    input_texto: str | None = None,
    verificar_executavel: bool = True,
) -> ResultadoComando:
    """
    Executa comandos arbitrarios via lista protegida de injeção (shell=False).
    Fornece métricas de tempo, sanitiza output e trata falhas não críticas.
    """
    iniciado = datetime.now()
    inicio_mono = time.monotonic()
    
    # 1. Normalização e Validação
    try:
        args_limpos = normalizar_argumentos(argumentos)
    except ValueError as e:
        return _resultado_erro(
            argumentos=list(argumentos) if isinstance(argumentos, (list, tuple)) else [],
            codigo=-1,
            erro=f"Argumentos inválidos: {str(e)}",
            comando_encontrado=False
        )

    cmd_display = " ".join(sanitizar_argumentos_para_log(args_limpos))
    logger.debug(f"Preparando execução: {cmd_display}")

    # 2. Verificação prévia do executável
    if verificar_executavel and not localizar_comando(args_limpos[0]):
        return _resultado_erro(
            argumentos=args_limpos,
            codigo=127,
            erro=f"Executável não encontrado: {args_limpos[0]}",
            comando_encontrado=False
        )

    # 3. Processamento de Diretório
    cwd_str = None
    if cwd is not None:
        cwd_str = str(cwd)
        if not os.path.exists(cwd_str):
            return _resultado_erro(args_limpos, -1, f"Diretório cwd não encontrado: {cwd_str}")
        if not os.path.isdir(cwd_str):
            return _resultado_erro(args_limpos, -1, f"Caminho cwd não é diretório: {cwd_str}")

    # 4. Cópia Segura de Ambiente
    env_seguro = None
    if env is not None:
        env_seguro = os.environ.copy()
        for k, v in env.items():
            str_k, str_v = str(k), str(v)
            if "\x00" in str_k or "\x00" in str_v:
                return _resultado_erro(args_limpos, -1, "Byte nulo detectado no dicionário env.")
            env_seguro[str_k] = str_v

    # 5. Execução do Subprocesso
    try:
        resultado_sub = subprocess.run(
            args_limpos,
            shell=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            cwd=cwd_str,
            env=env_seguro,
            input=input_texto
        )
        
        duracao = time.monotonic() - inicio_mono
        logger.debug(f"Comando concluído [{resultado_sub.returncode}] em {duracao:.2f}s: {cmd_display}")
        
        return ResultadoComando(
            argumentos=args_limpos,
            codigo=resultado_sub.returncode,
            stdout=resultado_sub.stdout.rstrip("\n") if resultado_sub.stdout else "",
            stderr=resultado_sub.stderr.rstrip("\n") if resultado_sub.stderr else "",
            sucesso=(resultado_sub.returncode == 0),
            duracao_segundos=duracao,
            timeout=False,
            comando_encontrado=True,
            iniciado_em=iniciado,
            finalizado_em=datetime.now(),
            erro=""
        )

    except subprocess.TimeoutExpired as e:
        logger.warning(f"Timeout ({timeout}s) excedido para: {cmd_display}")
        return ResultadoComando(
            argumentos=args_limpos,
            codigo=124,
            stdout=e.stdout.decode('utf-8', errors='replace').rstrip("\n") if isinstance(e.stdout, bytes) else (e.stdout.rstrip("\n") if e.stdout else ""),
            stderr=e.stderr.decode('utf-8', errors='replace').rstrip("\n") if isinstance(e.stderr, bytes) else (e.stderr.rstrip("\n") if e.stderr else ""),
            sucesso=False,
            duracao_segundos=time.monotonic() - inicio_mono,
            timeout=True,
            comando_encontrado=True,
            iniciado_em=iniciado,
            finalizado_em=datetime.now(),
            erro=f"Timeout de {timeout} segundos atingido."
        )

    except PermissionError as e:
        logger.error(f"Permissão negada ao executar: {cmd_display}")
        return _resultado_erro(args_limpos, 126, f"Sem permissão de execução: {str(e)}")

    except FileNotFoundError:
        return _resultado_erro(args_limpos, 127, f"Executável inexistente: {args_limpos[0]}", comando_encontrado=False)

    except OSError as e:
        logger.error(f"Erro de SO ao executar {cmd_display}: {e}")
        return _resultado_erro(args_limpos, -1, f"Erro operacional: {str(e)}")

    except Exception as e:
        logger.exception(f"Erro inesperado durante a execução de {cmd_display}")
        return _resultado_erro(args_limpos, -1, f"Falha interna do Python: {str(e)}")


def executar_pipeline(comandos: list[list[str]], timeout: float = 120.0) -> ResultadoComando:
    """
    Roteia múltiplos comandos sequenciais (Pipe | virtual) conectando o stdout do
    anterior ao stdin do subsequente, sem necessidade de shell=True.
    """
    iniciado = datetime.now()
    inicio_mono = time.monotonic()
    
    if not comandos:
        return _resultado_erro([], -1, "Lista de comandos do pipeline está vazia.", comando_encontrado=False)
        
    processos_abertos = []
    stderr_historico = []
    stdin_atual = None
    args_normalizados_list = []
    
    try:
        # Cria a cadeia de subprocessos
        for idx, cmd in enumerate(comandos):
            args_normalizados = normalizar_argumentos(cmd)
            args_normalizados_list.append(args_normalizados)
            
            if not localizar_comando(args_normalizados[0]):
                raise FileNotFoundError(args_normalizados[0])

            # Último processo do pipeline deve capturar output
            is_last = (idx == len(comandos) - 1)
            stdout_target = subprocess.PIPE
            stderr_target = subprocess.PIPE
            
            proc = subprocess.Popen(
                args_normalizados,
                stdin=stdin_atual,
                stdout=stdout_target,
                stderr=stderr_target,
                shell=False,
                text=True,
                encoding="utf-8",
                errors="replace"
            )
            
            # Fecha a ponta do processo anterior que foi acoplada ao atual (evita lock de buffer)
            if stdin_atual:
                stdin_atual.close()
                
            stdin_atual = proc.stdout
            processos_abertos.append(proc)

        # Aguarda a cadeia concluir monitorando timeout
        proc_final = processos_abertos[-1]
        try:
            stdout_final, stderr_final = proc_final.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            for p in processos_abertos:
                p.kill()
            proc_final.communicate()
            return ResultadoComando(
                argumentos=args_normalizados_list[-1],
                codigo=124,
                sucesso=False,
                duracao_segundos=time.monotonic() - inicio_mono,
                timeout=True,
                iniciado_em=iniciado,
                finalizado_em=datetime.now(),
                erro=f"Timeout de {timeout}s excedido durante execução do pipeline."
            )

        # Recolhe stderrs e garante que nenhum quebrou
        sucesso_geral = True
        codigo_final = proc_final.returncode
        for p in processos_abertos:
            p.wait()
            if p.returncode != 0:
                sucesso_geral = False
            
            if p.stderr:
                err_text = p.stderr.read()
                if err_text:
                    stderr_historico.append(err_text)
                    
        stderr_consolidado = "\n".join(stderr_historico) + (stderr_final or "")

        return ResultadoComando(
            argumentos=args_normalizados_list[-1],
            codigo=codigo_final,
            stdout=stdout_final.rstrip("\n") if stdout_final else "",
            stderr=stderr_consolidado.rstrip("\n"),
            sucesso=sucesso_geral,
            duracao_segundos=time.monotonic() - inicio_mono,
            comando_encontrado=True,
            iniciado_em=iniciado,
            finalizado_em=datetime.now(),
            erro="Falha intermediária em estágio do pipeline." if not sucesso_geral else ""
        )

    except FileNotFoundError as e:
        for p in processos_abertos:
            p.kill()
        return _resultado_erro(args_normalizados_list[-1] if args_normalizados_list else [], 127, f"Comando do pipeline não existe: {e}", comando_encontrado=False)

    except Exception as e:
        logger.exception("Falha na construção/execução do pipeline.")
        for p in processos_abertos:
            p.kill()
        return _resultado_erro(comandos[-1] if comandos else [], -1, f"Falha interna do pipeline: {str(e)}")


# ==============================================================================
# INTEGRAÇÃO DE ASSISTENTE (ETAPAS)
# ==============================================================================

def executar_comando_com_resultado_etapa(
    etapa: str,
    argumentos: list[str] | tuple[str, ...],
    mensagem_sucesso: str,
    mensagem_erro: str,
    timeout: float = 120.0,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
) -> ResultadoEtapa:
    """Invólucro para vincular as validações seguras a uma macro-etapa do Onboarding MoonShield."""
    resultado_etapa = ResultadoEtapa(
        etapa=etapa,
        status=StatusEtapa.EXECUTANDO,
        sucesso=False,
        mensagem="Iniciando execução de comando vinculado.",
        iniciado_em=datetime.now()
    )

    args_display = sanitizar_argumentos_para_log(
        list(argumentos) if isinstance(argumentos, (tuple, list)) else []
    )
    cmd_str = " ".join(args_display)
    
    resultado_etapa.adicionar_log(f"Comando agendado: {cmd_str}", NivelLog.INFO)

    res_comando = executar_comando(
        argumentos=argumentos,
        timeout=timeout,
        cwd=cwd,
        env=env,
        verificar_executavel=True
    )
    
    resultado_etapa.dados["comando"] = res_comando.to_dict()

    if res_comando.sucesso:
        resultado_etapa.adicionar_log(f"Sucesso: {cmd_str}", NivelLog.SUCESSO)
        resultado_etapa.finalizar_sucesso(mensagem=mensagem_sucesso)
    else:
        # Usa o erro estruturado gerado pelos tratamentos internos ou a saída de stderr
        motivo = res_comando.erro if res_comando.erro else res_comando.saida
        resultado_etapa.adicionar_log(f"Falha de execução [{res_comando.codigo}]: {motivo}", NivelLog.ERRO)
        resultado_etapa.finalizar_erro(
            mensagem=mensagem_erro,
            erro=motivo
        )

    return resultado_etapa


def exigir_comando(nome: str) -> ResultadoEtapa:
    """Verifica e reporta formalmente a disponibilidade de dependência binária."""
    resultado = ResultadoEtapa(
        etapa="verificar_comando",
        status=StatusEtapa.EXECUTANDO,
        sucesso=False,
        mensagem=f"Checando disponibilidade do utilitário: {nome}",
        iniciado_em=datetime.now()
    )

    caminho = localizar_comando(nome)
    if caminho:
        resultado.dados = {"nome": nome, "caminho": caminho}
        resultado.finalizar_sucesso(mensagem=f"Dependência localizada: {nome}")
    else:
        resultado.dados = {"nome": nome}
        resultado.finalizar_erro(
            mensagem=f"Dependência crítica ausente: {nome}",
            erro=f"O comando '{nome}' não foi localizado no PATH do sistema. Instale as dependências para continuar."
        )

    return resultado