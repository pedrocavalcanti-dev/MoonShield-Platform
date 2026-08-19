"""
Módulo centralizado para a orquestração padronizada de tarefas longas do Suricata.
Atua como um dispatcher seguro, encapsulando validações, cancelamentos cooperativos,
tracking de logs em memória e sanitização de dados, independente do transport layer
(background worker, HTTP API ou Management Command).
"""

import uuid
import logging
import threading
import time
from datetime import datetime
from pathlib import Path
from enum import Enum
from typing import Any, Callable

from django.utils import timezone as django_timezone

from .tipos import (
    ProgressoTarefa,
    TipoTarefaSuricata,
    StatusEtapa,
    NivelLog,
    ResultadoEtapa,
    ConfiguracaoSuricataDados,
    ModoCaptura,
)

from .instalador import (
    executar_instalacao,
    executar_configuracao,
    executar_atualizacao_regras,
    executar_validacao,
)

from .diagnostico import (
    executar_diagnostico,
)

from .servicos import (
    reiniciar_servico,
    SERVICO_SURICATA,
    SERVICO_MONITOR,
)

logger = logging.getLogger(__name__)


# ==============================================================================
# CONSTANTES OBRIGATÓRIAS
# ==============================================================================

TIPOS_TAREFA_SUPORTADOS = {
    TipoTarefaSuricata.DIAGNOSTICO,
    TipoTarefaSuricata.INSTALACAO,
    TipoTarefaSuricata.CONFIGURACAO,
    TipoTarefaSuricata.ATUALIZACAO_REGRAS,
    TipoTarefaSuricata.VALIDACAO,
    TipoTarefaSuricata.REINICIO_SURICATA,
    TipoTarefaSuricata.REINICIO_MONITOR,
}

STATUS_FINAIS = {
    StatusEtapa.SUCESSO,
    StatusEtapa.ERRO,
    StatusEtapa.CANCELADO,
    StatusEtapa.IGNORADO,
}

PARAMETROS_PERMITIDOS = {
    TipoTarefaSuricata.DIAGNOSTICO: {
        "configuracao",
        "incluir_validacao_suricata",
        "incluir_checks_eve",
        "incluir_checks_servicos",
    },
    TipoTarefaSuricata.INSTALACAO: {
        "configuracao",
        "instalar_et_open",
        "reiniciar_servicos",
        "executar_diagnostico_final",
    },
    TipoTarefaSuricata.CONFIGURACAO: {
        "configuracao",
        "reiniciar_servicos",
    },
    TipoTarefaSuricata.ATUALIZACAO_REGRAS: {
        "atualizar_et",
        "atualizar_moonshield",
        "origem_moonshield",
        "validar_depois",
        "yaml_path",
        "reiniciar_depois",
    },
    TipoTarefaSuricata.VALIDACAO: {
        "configuracao",
    },
    TipoTarefaSuricata.REINICIO_SURICATA: set(),
    TipoTarefaSuricata.REINICIO_MONITOR: set(),
}

MAX_LOGS_MEMORIA = 2000
MAX_TAMANHO_PARAMETRO_TEXTO = 4096


# ==============================================================================
# HELPERS DE DATA/HORA
# ==============================================================================

def _agora() -> datetime:
    """Retorna datetime timezone-aware compatível com USE_TZ do Django."""
    return django_timezone.now()


def _normalizar_datetime(valor: datetime | None) -> datetime | None:
    """
    Normaliza datetimes legados/naive para o timezone atual do Django.

    O projeto possuía DTOs antigos que ainda podiam produzir _agora()
    sem timezone. Essa normalização impede mistura entre naive/aware no worker.
    """
    if valor is None:
        return None

    if django_timezone.is_naive(valor):
        try:
            return django_timezone.make_aware(
                valor,
                django_timezone.get_current_timezone(),
            )
        except Exception:
            return django_timezone.make_aware(valor)

    return valor


def _normalizar_tempos_progresso(progresso: ProgressoTarefa) -> None:
    """Normaliza os relógios do tracker antes de persistir/serializar/calcular."""
    progresso.iniciado_em = _normalizar_datetime(
        getattr(progresso, "iniciado_em", None)
    )
    progresso.finalizado_em = _normalizar_datetime(
        getattr(progresso, "finalizado_em", None)
    )


# ==============================================================================
# HELPERS DE HIGIENIZAÇÃO E SERIALIZAÇÃO PRIVADOS
# ==============================================================================

def _limpar_dados_sensiveis(valor: object) -> object:
    """Higieniza dados operacionais garantindo que credenciais acidentais nunca apareçam nos logs."""
    chaves_sensitivas = {"password", "senha", "token", "secret", "authorization", "api_key"}

    if isinstance(valor, dict):
        limpo = {}
        for k, v in valor.items():
            if str(k).lower() in chaves_sensitivas:
                limpo[k] = "***"
            else:
                limpo[k] = _limpar_dados_sensiveis(v)
        return limpo
    elif isinstance(valor, list):
        return [_limpar_dados_sensiveis(item) for item in valor]
    elif isinstance(valor, tuple):
        return tuple(_limpar_dados_sensiveis(item) for item in valor)
    return valor


def _serializar_resultado(valor: object) -> object:
    """Constrói iterativamente representações JSON-Safe da malha de objetos."""
    if isinstance(valor, Enum):
        return valor.value
    if isinstance(valor, Path):
        return str(valor)
    if isinstance(valor, datetime):
        return valor.isoformat()
    if hasattr(valor, "to_dict") and callable(getattr(valor, "to_dict")):
        return _serializar_resultado(valor.to_dict())
    if hasattr(valor, "__dataclass_fields__"):
        import dataclasses
        return _serializar_resultado(dataclasses.asdict(valor))
    if isinstance(valor, set):
        return sorted(list(valor))
    if isinstance(valor, bytes):
        return valor.decode("utf-8", errors="replace")
    if isinstance(valor, dict):
        return {k: _serializar_resultado(v) for k, v in valor.items()}
    if isinstance(valor, list):
        return [_serializar_resultado(v) for v in valor]
    if isinstance(valor, tuple):
        return tuple(_serializar_resultado(v) for v in valor)
    return valor



def _resumir_diagnostico_existente(resultado: object) -> dict[str, object]:
    """
    Gera o resumo do diagnóstico a partir do MESMO ResultadoDiagnostico já
    produzido pelo worker.

    Importante:
    - não chama executar_diagnostico() novamente;
    - não chama executar_diagnostico_resumido();
    - mantém total = saudáveis + avisos + críticos;
    - produz um snapshot JSON-safe adequado para persistência no banco.
    """
    itens = list(getattr(resultado, "itens", None) or [])

    total_checks = len(itens)
    total_saudaveis = sum(
        1
        for item in itens
        if bool(getattr(item, "ok", False))
    )
    total_criticos = sum(
        1
        for item in itens
        if (
            not bool(getattr(item, "ok", False))
            and bool(getattr(item, "critico", False))
        )
    )
    total_avisos = sum(
        1
        for item in itens
        if (
            not bool(getattr(item, "ok", False))
            and not bool(getattr(item, "critico", False))
        )
    )
    total_falhas = total_criticos + total_avisos

    score = (
        round((total_saudaveis / total_checks) * 100)
        if total_checks > 0
        else 0
    )

    grupos_resumo: dict[str, dict[str, object]] = {}
    grupos = getattr(resultado, "grupos", {}) or {}

    if isinstance(grupos, dict):
        for nome_grupo, checks in grupos.items():
            checks_lista = list(checks or [])

            grupo_total = len(checks_lista)
            grupo_saudaveis = sum(
                1
                for item in checks_lista
                if bool(getattr(item, "ok", False))
            )
            grupo_criticos = sum(
                1
                for item in checks_lista
                if (
                    not bool(getattr(item, "ok", False))
                    and bool(getattr(item, "critico", False))
                )
            )
            grupo_avisos = sum(
                1
                for item in checks_lista
                if (
                    not bool(getattr(item, "ok", False))
                    and not bool(getattr(item, "critico", False))
                )
            )

            grupo_score = (
                round((grupo_saudaveis / grupo_total) * 100)
                if grupo_total > 0
                else 0
            )

            grupos_resumo[str(nome_grupo)] = {
                "total": grupo_total,
                "ok": grupo_saudaveis,
                "saudaveis": grupo_saudaveis,
                "avisos": grupo_avisos,
                "criticos": grupo_criticos,
                "falhas": grupo_avisos + grupo_criticos,
                "score": grupo_score,
            }

    executado_em = getattr(resultado, "executado_em", None)
    executado_em_serializado = (
        executado_em.isoformat()
        if hasattr(executado_em, "isoformat")
        else ""
    )

    duracao = float(
        getattr(resultado, "duracao_segundos", 0.0) or 0.0
    )

    pronto = bool(
        getattr(resultado, "pronto", False)
    )

    if pronto and total_avisos:
        mensagem = (
            "Infraestrutura pronta; existem apenas avisos operacionais."
        )
    elif pronto:
        mensagem = (
            "Infraestrutura pronta e sem falhas críticas."
        )
    else:
        mensagem = (
            "Existem falhas críticas que exigem correção."
        )

    return {
        "pronto": pronto,
        "total_checks": total_checks,
        "total_ok": total_saudaveis,
        "total_saudaveis": total_saudaveis,
        "total_avisos": total_avisos,
        "total_falhas": total_falhas,
        "total_criticos": total_criticos,
        "score_integridade": score,
        "score": score,
        "grupos": grupos_resumo,
        "duracao_segundos": round(duracao, 3),
        "executado_em": executado_em_serializado,
        "mensagem": mensagem,
    }


# ==============================================================================
# ENCAPSULAMENTO DE DADOS E VALIDAÇÕES (DTOs)
# ==============================================================================

def converter_tipo_tarefa(valor: TipoTarefaSuricata | str) -> TipoTarefaSuricata:
    """Assegura conversão estrita do enum e proíbe metaprogramação de payloads REST."""
    if not valor:
        raise ValueError("O tipo de tarefa não pode estar vazio.")
        
    if isinstance(valor, TipoTarefaSuricata):
        return valor
        
    if isinstance(valor, str):
        valor_limpo = valor.strip().lower()
        for t in TipoTarefaSuricata:
            if t.value.lower() == valor_limpo:
                return t
                
    raise ValueError(f"O tipo '{valor}' não corresponde a uma tarefa válida suportada.")


def gerar_id_tarefa() -> str:
    """Gerador UUIDv4 autônomo (Evita PKs relacionais p/ logs efêmeros)."""
    return str(uuid.uuid4())


def criar_progresso_tarefa(tipo: TipoTarefaSuricata | str, tarefa_id: str | None = None) -> ProgressoTarefa:
    """Instancia um tracker limpo com UUID higienizado."""
    tipo_enum = converter_tipo_tarefa(tipo)
    
    if tarefa_id:
        t_id_limpo = str(tarefa_id).strip()
        import re
        if not re.match(r"^[a-zA-Z0-9\-_]+$", t_id_limpo) or len(t_id_limpo) > 100:
             raise ValueError("O ID fornecido possui caracteres proibidos ou excedeu o limite.")
    else:
        t_id_limpo = gerar_id_tarefa()

    return ProgressoTarefa(
        tarefa_id=t_id_limpo,
        tipo=tipo_enum,
        status=StatusEtapa.PENDENTE,
        progresso=0,
        mensagem=f"Tracker orquestrado inicializado ({tipo_enum.value}).",
    )


def configuracao_de_dict(dados: dict[str, object] | ConfiguracaoSuricataDados | None) -> ConfiguracaoSuricataDados | None:
    """Converte e tipa uma estrutura bruta via construtor literal da dataclass."""
    if dados is None:
        return None
    if isinstance(dados, ConfiguracaoSuricataDados):
        return dados
        
    if not isinstance(dados, dict):
        raise ValueError("Payload de configuração exige dicionário base.")

    cfg = ConfiguracaoSuricataDados()
    
    # Mapeamentos estritos para evitar setattr livre e fields alienígenas
    if "interface_wan" in dados:
        cfg.interface_wan = str(dados["interface_wan"]).strip()
    if "interface_lan" in dados:
        cfg.interface_lan = str(dados["interface_lan"]).strip()
    if "interface_mgmt" in dados:
        cfg.interface_mgmt = str(dados["interface_mgmt"]).strip()
        
    if "modo_captura" in dados:
        v_modo = str(dados["modo_captura"]).strip().lower()
        modo_resolvido = None
        for m in ModoCaptura:
            if m.value.lower() == v_modo:
                modo_resolvido = m
                break
        if not modo_resolvido:
            raise ValueError(f"Modo de captura inválido: {v_modo}")
        cfg.modo_captura = modo_resolvido

    if "interfaces_monitoradas" in dados:
        ifs = dados["interfaces_monitoradas"]
        if not isinstance(ifs, list):
             raise ValueError("interfaces_monitoradas exige array base de strings.")
        cfg.interfaces_monitoradas = [str(i).strip() for i in ifs]

    if "home_net" in dados:
        hn = dados["home_net"]
        if not isinstance(hn, list):
             raise ValueError("home_net exige array base de strings.")
        cfg.home_net = [str(r).strip() for r in hn]

    if "dns_interno" in dados:
        cfg.dns_interno = str(dados["dns_interno"]).strip()
    if "yaml_path" in dados:
        cfg.yaml_path = str(dados["yaml_path"]).strip()
    if "eve_path" in dados:
        cfg.eve_path = str(dados["eve_path"]).strip()

    if "instalar_et_open" in dados:
        cfg.instalar_et_open = bool(dados["instalar_et_open"])
    if "instalar_regras_moonshield" in dados:
        cfg.instalar_regras_moonshield = bool(dados["instalar_regras_moonshield"])
    if "reiniciar_servicos" in dados:
        cfg.reiniciar_servicos = bool(dados["reiniciar_servicos"])

    return cfg


def validar_parametros_tarefa(tipo: TipoTarefaSuricata | str, parametros: dict[str, object] | None) -> dict[str, object]:
    """Clona parâmetros do Request, filtra chaves não documentadas e impede payloads massivos."""
    tipo_enum = converter_tipo_tarefa(tipo)
    p_in = parametros or {}
    p_out = {}
    
    permitidos = PARAMETROS_PERMITIDOS.get(tipo_enum, set())
    
    for k, v in p_in.items():
        if k not in permitidos:
            continue
            
        if k == "configuracao":
            p_out[k] = configuracao_de_dict(v)
            continue
            
        if isinstance(v, str):
            if len(v) > MAX_TAMANHO_PARAMETRO_TEXTO:
                 raise ValueError(f"Parâmetro '{k}' excede o comprimento textual permitido.")
            if "\x00" in v:
                 raise ValueError(f"Bytes nulos detectados no parâmetro '{k}'.")
            p_out[k] = v
        elif isinstance(v, bool):
            # Preserva veracidade estrita (não inteiros atuando como bool)
            p_out[k] = v is True
        elif isinstance(v, (int, float)):
            p_out[k] = v
        else:
            raise ValueError(f"O parâmetro {k} usa estrutura não serializável estritamente suportada.")
            
    return p_out


def validar_estado_progresso(progresso: ProgressoTarefa) -> list[str]:
    """Auditoria sanitária na consistência temporal e relacional do DTO do tracker."""
    erros = []
    if not progresso.tarefa_id:
        erros.append("Tarefa orfã (ausência de UUID).")
    if progresso.tipo not in TIPOS_TAREFA_SUPORTADOS:
        erros.append("Assinatura de tipo não homologada.")
    if not (0 <= progresso.progresso <= 100):
        erros.append("Escala progressiva violada.")
        
    if progresso.status == StatusEtapa.SUCESSO and progresso.progresso != 100:
        erros.append("Contrato falho: A tarefa obteve SUCESSO, mas progresso não cravou 100%.")
    if progresso.status == StatusEtapa.ERRO and not progresso.erro and not progresso.mensagem:
        erros.append("Contrato falho: O status aponta ERRO crítico sem traço de diagnóstico.")
    if progresso.status == StatusEtapa.CANCELADO and not progresso.finalizado_em:
        erros.append("Cancelamento sem encerramento de relógio marcado.")
    if progresso.status == StatusEtapa.EXECUTANDO and not progresso.iniciado_em:
        erros.append("Estado em execução apontado antes da marcação de boot inicial (iniciado_em nulo).")
        
    return erros


# ==============================================================================
# HELPERS DE CONTROLE E LIFECYCLE (WORKER COOP)
# ==============================================================================

def _adicionar_log_progresso(progresso: ProgressoTarefa, mensagem: str, nivel: NivelLog = NivelLog.INFO, etapa: str = "") -> None:
    """Abstração da limitação do buffer para não inviabilizar RAM ou POST body com mil loglines."""
    msg_curta = mensagem[:MAX_TAMANHO_PARAMETRO_TEXTO]
    try:
        progresso.atualizar(progresso.progresso, etapa, msg_curta, nivel)
        if len(progresso.logs) > MAX_LOGS_MEMORIA:
            # Preserva os ~10% primeiros para ter contexto de start e clipa o meio
            topo = int(MAX_LOGS_MEMORIA * 0.1)
            cauda = MAX_LOGS_MEMORIA - topo - 1
            preservados = progresso.logs[:topo] + progresso.logs[-cauda:]
            progresso.logs = preservados
    except Exception as e:
        logger.debug(f"Sobrecarga mitigada no add_log do tracker: {e}")


def tarefa_cancelada(progresso: ProgressoTarefa) -> bool:
    """Sinalização booleana para interrupções inter-etapas."""
    return progresso.status == StatusEtapa.CANCELADO


def solicitar_cancelamento(progresso: ProgressoTarefa, mensagem: str = "Cancelamento solicitado.") -> None:
    """Emite intenção de parada amigável. Orquestradores irão checar e interceder."""
    if progresso.status in STATUS_FINAIS:
        return
        
    progresso.status = StatusEtapa.CANCELADO
    progresso.mensagem = mensagem[:MAX_TAMANHO_PARAMETRO_TEXTO]
    progresso.finalizado_em = _agora()
    _adicionar_log_progresso(progresso, f"Sinal de interrupção: {mensagem}", NivelLog.AVISO, progresso.etapa_atual)


def _verificar_cancelamento(progresso: ProgressoTarefa, etapa: str) -> ResultadoEtapa | None:
    """Alicerçe dry-run/break pros delegates evitarem de realizar lógicas complexas."""
    if not tarefa_cancelada(progresso):
        return None
        
    res = ResultadoEtapa(
        etapa=etapa,
        status=StatusEtapa.CANCELADO,
        sucesso=False,
        mensagem=progresso.mensagem or "Fluxo abortado cooperativamente."
    )
    return res


# ==============================================================================
# DELEGATES E EXECUTORES ESPECIALISTAS (WORKFLOWS)
# ==============================================================================

def executar_tarefa_diagnostico(
    progresso: ProgressoTarefa,
    parametros: dict[str, object],
) -> ResultadoEtapa:
    """
    Executa o diagnóstico profundo do Suricata UMA ÚNICA VEZ.

    O resultado completo e o resumo são derivados do mesmo snapshot para:
    - evitar repetir `suricata -T`;
    - reduzir significativamente o tempo da tarefa;
    - impedir divergência entre cards, grupos e resultado completo;
    - permitir persistência confiável em TarefaSuricata.resultado.
    """
    etapa_id = "tarefa_diagnostico_full"
    iniciado_em = _agora()

    chk_cancel = _verificar_cancelamento(
        progresso,
        etapa_id,
    )
    if chk_cancel:
        return chk_cancel

    progresso.progresso = 5
    _adicionar_log_progresso(
        progresso,
        "Preparando diagnóstico profundo do Suricata.",
        NivelLog.INFO,
        "preparando_diagnostico",
    )

    cfg = parametros.get("configuracao")

    inc_val_suri = bool(
        parametros.get(
            "incluir_validacao_suricata",
            True,
        )
    )
    inc_chk_eve = bool(
        parametros.get(
            "incluir_checks_eve",
            True,
        )
    )
    inc_chk_svc = bool(
        parametros.get(
            "incluir_checks_servicos",
            True,
        )
    )

    progresso.progresso = 15
    _adicionar_log_progresso(
        progresso,
        (
            "Executando verificações de saúde. "
            "A validação das regras pode levar alguns segundos."
        ),
        NivelLog.INFO,
        "executando_diagnostico",
    )

    try:
        diag_bruto = executar_diagnostico(
            configuracao=cfg,
            incluir_validacao_suricata=inc_val_suri,
            incluir_checks_eve=inc_chk_eve,
            incluir_checks_servicos=inc_chk_svc,
        )
    except Exception as exc:
        logger.exception(
            "Crash interno do pacote diagnóstico."
        )

        progresso.progresso = max(
            int(getattr(progresso, "progresso", 0) or 0),
            15,
        )

        _adicionar_log_progresso(
            progresso,
            "O diagnóstico não pôde ser concluído.",
            NivelLog.ERRO,
            "diagnostico",
        )

        res_fail = ResultadoEtapa(
            etapa=etapa_id,
            status=StatusEtapa.ERRO,
            sucesso=False,
            mensagem="Falha ao executar diagnóstico profundo.",
            erro=str(exc),
            iniciado_em=iniciado_em,
        )

        res_fail.finalizar_erro(
            "Falha ao executar diagnóstico profundo.",
            erro=str(exc),
        )

        return res_fail

    chk_cancel = _verificar_cancelamento(
        progresso,
        etapa_id,
    )
    if chk_cancel:
        return chk_cancel

    progresso.progresso = 90
    _adicionar_log_progresso(
        progresso,
        "Consolidando o relatório do diagnóstico.",
        NivelLog.INFO,
        "consolidando_diagnostico",
    )

    diagnostico_completo = _serializar_resultado(
        diag_bruto
    )

    resumo_rapido = _resumir_diagnostico_existente(
        diag_bruto
    )

    diagnostico_pronto = bool(
        getattr(
            diag_bruto,
            "pronto",
            False,
        )
    )

    res = ResultadoEtapa(
        etapa=etapa_id,
        status=(
            StatusEtapa.SUCESSO
            if diagnostico_pronto
            else StatusEtapa.ERRO
        ),
        sucesso=diagnostico_pronto,
        mensagem="Checkup operacional completo.",
        iniciado_em=iniciado_em,
    )

    # Mantém o contrato atual consumido pela API/frontend.
    # Tanto o relatório quanto o resumo pertencem à MESMA execução.
    res.dados = {
        "diagnostico_completo": diagnostico_completo,
        "resumo_rapido": resumo_rapido,
        "meta": {
            "execucoes_diagnostico": 1,
            "resultado_persistivel": True,
            "incluiu_validacao_suricata": inc_val_suri,
            "incluiu_checks_eve": inc_chk_eve,
            "incluiu_checks_servicos": inc_chk_svc,
        },
    }

    if diagnostico_pronto:
        res.finalizar_sucesso(
            "Diagnóstico concluído sem falhas críticas."
        )

        _adicionar_log_progresso(
            progresso,
            (
                f"Diagnóstico aprovado: "
                f"{resumo_rapido['total_saudaveis']}/"
                f"{resumo_rapido['total_checks']} verificações saudáveis."
            ),
            NivelLog.SUCESSO,
            "diagnostico_concluido",
        )
    else:
        total_criticos = int(
            resumo_rapido.get(
                "total_criticos",
                0,
            )
            or 0
        )

        res.finalizar_erro(
            (
                "O diagnóstico identificou falhas críticas "
                "que exigem correção."
            ),
            erro=(
                f"{total_criticos} falha(s) crítica(s) identificada(s)."
            ),
        )

        _adicionar_log_progresso(
            progresso,
            (
                f"Diagnóstico finalizado com "
                f"{total_criticos} falha(s) crítica(s)."
            ),
            NivelLog.ERRO,
            "diagnostico_concluido",
        )

    progresso.progresso = 100

    return res


def executar_tarefa_instalacao(progresso: ProgressoTarefa, parametros: dict[str, object]) -> ResultadoEtapa:
    """Aciona a master-routine transacional (A a Z) provisionando do APT até as Regras MS."""
    cfg = parametros.get("configuracao")
    # Usa triplo get default para garantir compatibilidade pass-thru e permitir bools nativos de cfg
    inst_et = parametros.get("instalar_et_open")
    bounce = parametros.get("reiniciar_servicos")
    diag_fin = parametros.get("executar_diagnostico_final", True)

    chk_cancel = _verificar_cancelamento(progresso, "tarefa_instalacao")
    if chk_cancel: return chk_cancel

    # Delega pro serviço do módulo "instalador.py" o pass-through, honrando o progresso
    res_raw = executar_instalacao(
        configuracao=cfg,
        progresso=progresso,
        instalar_et_open=inst_et,
        reiniciar_servicos=bounce,
        executar_diagnostico_final=diag_fin
    )
    
    if tarefa_cancelada(progresso):
        return _verificar_cancelamento(progresso, "tarefa_instalacao")

    return res_raw


def executar_tarefa_configuracao(progresso: ProgressoTarefa, parametros: dict[str, object]) -> ResultadoEtapa:
    """Dispara alteração topológica sem interferir nos scripts e binários debian instalados."""
    etapa_id = "tarefa_configuracao_topologia"
    cfg = parametros.get("configuracao")
    
    if not cfg:
        res = ResultadoEtapa(etapa_id, StatusEtapa.ERRO, False, "Configuração nula", iniciado_em=_agora())
        res.finalizar_erro("A configuração da topologia IDS foi submetida em branco.")
        return res
        
    chk_cancel = _verificar_cancelamento(progresso, etapa_id)
    if chk_cancel: return chk_cancel

    bounce = parametros.get("reiniciar_servicos")
    
    res_raw = executar_configuracao(
        configuracao=cfg,
        progresso=progresso,
        reiniciar_servicos=bounce
    )
    
    if tarefa_cancelada(progresso):
        return _verificar_cancelamento(progresso, etapa_id)
        
    return res_raw


def executar_tarefa_atualizacao_regras(progresso: ProgressoTarefa, parametros: dict[str, object]) -> ResultadoEtapa:
    """Garante sincronia e flush unificado do Intelligence Pack (ET + MS)."""
    chk_cancel = _verificar_cancelamento(progresso, "tarefa_atualizar_regras")
    if chk_cancel: return chk_cancel

    res_raw = executar_atualizacao_regras(
        atualizar_et=bool(parametros.get("atualizar_et", True)),
        atualizar_moonshield=bool(parametros.get("atualizar_moonshield", True)),
        origem_moonshield=parametros.get("origem_moonshield"),
        validar_depois=bool(parametros.get("validar_depois", True)),
        yaml_path=parametros.get("yaml_path"),
        reiniciar_depois=bool(parametros.get("reiniciar_depois", False)),
        progresso=progresso
    )
    
    if tarefa_cancelada(progresso):
        return _verificar_cancelamento(progresso, "tarefa_atualizar_regras")
        
    return res_raw


def executar_tarefa_validacao(progresso: ProgressoTarefa, parametros: dict[str, object]) -> ResultadoEtapa:
    """Dispara Healthcheck + YAML syntax verifier para certificar o estado atual."""
    chk_cancel = _verificar_cancelamento(progresso, "tarefa_validar")
    if chk_cancel: return chk_cancel

    cfg = parametros.get("configuracao")
    res_raw = executar_validacao(configuracao=cfg, progresso=progresso)
    
    if tarefa_cancelada(progresso):
        return _verificar_cancelamento(progresso, "tarefa_validar")
        
    return res_raw


def executar_tarefa_reinicio_suricata(progresso: ProgressoTarefa, parametros: dict[str, object]) -> ResultadoEtapa:
    """Bounce do Motor."""
    etapa_id = "bounce_suricata"
    chk_cancel = _verificar_cancelamento(progresso, etapa_id)
    if chk_cancel: return chk_cancel
    
    _adicionar_log_progresso(progresso, "Bounce motor ativo C.", NivelLog.INFO, etapa_id)
    progresso.progresso = 20
    
    res_raw = reiniciar_servico(SERVICO_SURICATA)
    
    if tarefa_cancelada(progresso):
        return _verificar_cancelamento(progresso, etapa_id)
        
    progresso.progresso = 100
    return res_raw


def executar_tarefa_reinicio_monitor(progresso: ProgressoTarefa, parametros: dict[str, object]) -> ResultadoEtapa:
    """Bounce do Ingress Worker."""
    etapa_id = "bounce_monitor"
    chk_cancel = _verificar_cancelamento(progresso, etapa_id)
    if chk_cancel: return chk_cancel
    
    _adicionar_log_progresso(progresso, "Bounce pipeline ingress Python.", NivelLog.INFO, etapa_id)
    progresso.progresso = 20
    
    res_raw = reiniciar_servico(SERVICO_MONITOR)
    
    if tarefa_cancelada(progresso):
        return _verificar_cancelamento(progresso, etapa_id)
        
    progresso.progresso = 100
    return res_raw



# ==============================================================================
# OBSERVADOR DE PROGRESSO PARA WORKERS / BANCO
# ==============================================================================

CallbackProgresso = Callable[[ProgressoTarefa], None]
CallbackCancelamento = Callable[[], bool]


def _snapshot_progresso(progresso: ProgressoTarefa) -> tuple[object, ...]:
    """
    Cria uma assinatura leve do estado atual.

    O instalador altera o mesmo objeto ProgressoTarefa durante as etapas. O
    observador compara esta assinatura e chama o callback apenas quando alguma
    informação relevante muda, evitando gravações desnecessárias no banco.
    """
    return (
        getattr(getattr(progresso, "status", None), "value", getattr(progresso, "status", None)),
        int(getattr(progresso, "progresso", 0) or 0),
        str(getattr(progresso, "etapa_atual", "") or ""),
        str(getattr(progresso, "mensagem", "") or ""),
        str(getattr(progresso, "erro", "") or ""),
        len(getattr(progresso, "logs", []) or []),
        getattr(progresso, "iniciado_em", None),
        getattr(progresso, "finalizado_em", None),
    )


def _notificar_progresso(
    progresso: ProgressoTarefa,
    callback: CallbackProgresso | None,
) -> None:
    """Executa o callback sem permitir que uma falha de persistência derrube a instalação."""
    if callback is None:
        return

    try:
        _normalizar_tempos_progresso(progresso)
        callback(progresso)
    except Exception:
        logger.exception(
            "Falha ao persistir/notificar progresso da tarefa %s.",
            getattr(progresso, "tarefa_id", "?"),
        )


class _ObservadorProgresso:
    """
    Observa alterações no tracker enquanto uma etapa longa está executando.

    Isso resolve o problema em que a instalação trabalha por vários segundos,
    porém a tarefa permanece visualmente em PENDENTE/0% até o comando terminar.
    """

    def __init__(
        self,
        progresso: ProgressoTarefa,
        callback_progresso: CallbackProgresso | None,
        callback_cancelamento: CallbackCancelamento | None,
        intervalo: float,
    ) -> None:
        self.progresso = progresso
        self.callback_progresso = callback_progresso
        self.callback_cancelamento = callback_cancelamento
        self.intervalo = max(float(intervalo), 0.20)
        self._parar = threading.Event()
        self._thread: threading.Thread | None = None
        self._ultimo_snapshot: tuple[object, ...] | None = None

    def iniciar(self) -> None:
        self._ultimo_snapshot = None
        self._publicar_se_alterado(forcar=True)

        if self.callback_progresso is None and self.callback_cancelamento is None:
            return

        self._thread = threading.Thread(
            target=self._executar,
            name=f"suricata-progress-{getattr(self.progresso, 'tarefa_id', 'task')}",
            daemon=True,
        )
        self._thread.start()

    def finalizar(self) -> None:
        self._parar.set()

        if self._thread is not None:
            self._thread.join(timeout=max(self.intervalo * 3, 1.0))

        self._publicar_se_alterado(forcar=True)

    def _executar(self) -> None:
        while not self._parar.wait(self.intervalo):
            self._consultar_cancelamento()
            self._publicar_se_alterado()

    def _consultar_cancelamento(self) -> None:
        if self.callback_cancelamento is None:
            return

        if self.progresso.status in STATUS_FINAIS:
            return

        try:
            if self.callback_cancelamento():
                solicitar_cancelamento(
                    self.progresso,
                    "Cancelamento solicitado pelo operador.",
                )
        except Exception:
            logger.exception(
                "Falha ao consultar cancelamento da tarefa %s.",
                getattr(self.progresso, "tarefa_id", "?"),
            )

    def _publicar_se_alterado(self, forcar: bool = False) -> None:
        atual = _snapshot_progresso(self.progresso)

        if forcar or atual != self._ultimo_snapshot:
            self._ultimo_snapshot = atual
            _notificar_progresso(self.progresso, self.callback_progresso)


# ==============================================================================
# DISPATCHER CENTRAL E INTERFACES DE API
# ==============================================================================

def obter_executor_tarefa(tipo: TipoTarefaSuricata) -> Callable:
    """Delega a rotina conforme a Intenção da Enumeração."""
    mapa = {
        TipoTarefaSuricata.DIAGNOSTICO: executar_tarefa_diagnostico,
        TipoTarefaSuricata.INSTALACAO: executar_tarefa_instalacao,
        TipoTarefaSuricata.CONFIGURACAO: executar_tarefa_configuracao,
        TipoTarefaSuricata.ATUALIZACAO_REGRAS: executar_tarefa_atualizacao_regras,
        TipoTarefaSuricata.VALIDACAO: executar_tarefa_validacao,
        TipoTarefaSuricata.REINICIO_SURICATA: executar_tarefa_reinicio_suricata,
        TipoTarefaSuricata.REINICIO_MONITOR: executar_tarefa_reinicio_monitor,
    }
    
    fn = mapa.get(tipo)
    if not fn:
        raise ValueError(f"Não há função orquestradora mapeada para a Intenção do Tipo {tipo.value}.")
    return fn


def executar_tarefa(
    tipo: TipoTarefaSuricata | str,
    parametros: dict[str, object] | None = None,
    tarefa_id: str | None = None,
    progresso: ProgressoTarefa | None = None,
    callback_progresso: CallbackProgresso | None = None,
    callback_cancelamento: CallbackCancelamento | None = None,
    intervalo_callback: float = 0.5,
) -> tuple[ProgressoTarefa, ResultadoEtapa]:
    """
    Executa uma tarefa do Suricata e acompanha seu ciclo de vida completo.

    `callback_progresso` pode persistir o tracker no banco enquanto a rotina
    ainda está executando. `callback_cancelamento` pode consultar a flag de
    cancelamento no banco sem acoplar este módulo ao ORM do Django.
    """
    try:
        t_tipo = converter_tipo_tarefa(tipo)
        if t_tipo not in TIPOS_TAREFA_SUPORTADOS:
            raise ValueError(
                "Tipo solicitado excluído da whitelist global de segurança."
            )

        p_ok = validar_parametros_tarefa(t_tipo, parametros)
    except Exception as exc:
        logger.warning("Rejeição de requisição inválida de tarefa: %s", exc)

        tipo_fallback = (
            tipo
            if isinstance(tipo, TipoTarefaSuricata)
            else TipoTarefaSuricata.VALIDACAO
        )
        prg = progresso or criar_progresso_tarefa(tipo_fallback, tarefa_id)
        prg.falhar("Requisição corrompida.", str(exc))

        res = ResultadoEtapa(
            "start",
            StatusEtapa.ERRO,
            False,
            "Erro de formato.",
            erro=str(exc),
            iniciado_em=_agora(),
        )
        _notificar_progresso(prg, callback_progresso)
        return prg, res

    prg = progresso or criar_progresso_tarefa(t_tipo, tarefa_id)

    if prg.tipo != t_tipo:
        logger.warning(
            "Descompasso de tipo detectado. Adequando tracker para %s.",
            t_tipo.value,
        )
        prg.tipo = t_tipo

    if tarefa_cancelada(prg):
        res = ResultadoEtapa(
            "start",
            StatusEtapa.CANCELADO,
            False,
            "Tarefa cancelada antes da execução.",
            iniciado_em=_agora(),
        )
        if not prg.finalizado_em:
            prg.finalizado_em = _agora()
        _notificar_progresso(prg, callback_progresso)
        return prg, res

    prg.status = StatusEtapa.EXECUTANDO
    prg.progresso = max(1, int(prg.progresso or 0))
    prg.etapa_atual = prg.etapa_atual or "iniciando"
    prg.mensagem = "Tarefa capturada pelo worker e execução iniciada."

    if not prg.iniciado_em:
        prg.iniciado_em = _agora()

    _adicionar_log_progresso(
        prg,
        f"Iniciando tarefa '{t_tipo.value}'.",
        NivelLog.INFO,
        prg.etapa_atual,
    )

    observador = _ObservadorProgresso(
        progresso=prg,
        callback_progresso=callback_progresso,
        callback_cancelamento=callback_cancelamento,
        intervalo=intervalo_callback,
    )
    observador.iniciar()

    fn_exec = obter_executor_tarefa(t_tipo)
    res_final: ResultadoEtapa | None = None

    try:
        res_final = fn_exec(prg, p_ok)

        if res_final is None:
            raise RuntimeError(
                f"O executor '{t_tipo.value}' encerrou sem retornar ResultadoEtapa."
            )

        prg.resultado = _serializar_resultado(res_final)

        if res_final.status == StatusEtapa.CANCELADO:
            prg.status = StatusEtapa.CANCELADO
            prg.mensagem = (
                res_final.mensagem or "Processo interrompido durante a execução."
            )
        elif res_final.sucesso:
            prg.concluir()
        else:
            prg.falhar(
                res_final.mensagem or "A tarefa terminou com erro.",
                res_final.erro or "",
            )

    except Exception as exc:
        logger.exception(
            "Falha crítica no dispatcher da tarefa %s.",
            t_tipo.value,
        )
        prg.falhar(
            "O serviço backend sofreu uma falha durante a execução.",
            str(exc),
        )
        res_final = ResultadoEtapa(
            "dispatcher",
            StatusEtapa.ERRO,
            False,
            "O serviço backend sofreu uma falha.",
            erro=str(exc),
            iniciado_em=prg.iniciado_em,
        )

    finally:
        _normalizar_tempos_progresso(prg)

        if not prg.finalizado_em:
            prg.finalizado_em = _agora()

        _normalizar_tempos_progresso(prg)

        if prg.status == StatusEtapa.SUCESSO:
            prg.progresso = 100

        observador.finalizar()

    erros_estado = validar_estado_progresso(prg)
    if erros_estado:
        logger.warning(
            "Tracker %s finalizado com inconsistências: %s",
            prg.tarefa_id,
            "; ".join(erros_estado),
        )

    return prg, res_final


def executar_tarefa_para_api(
    tipo: TipoTarefaSuricata | str,
    parametros: dict[str, object] | None = None,
    tarefa_id: str | None = None,
) -> dict[str, object]:
    """Alicerça os retornos brutos num frame que o REST API possa transportar via Django."""
    try:
        prg, res = executar_tarefa(tipo=tipo, parametros=parametros, tarefa_id=tarefa_id)
        
        payload = {
            "ok": res.sucesso,
            "tarefa": _serializar_resultado(prg),
            "resultado": _serializar_resultado(res),
        }
        
        if not res.sucesso:
            payload["mensagem"] = res.erro or res.mensagem
            
        return payload
    except Exception as e:
        logger.exception("Injeção quebrou o frame da API Task.")
        return {
            "ok": False,
            "tarefa": {},
            "resultado": {},
            "mensagem": str(e)
        }


# ==============================================================================
# LEITURAS LÓGICAS E METADADOS DO ASSISTENTE
# ==============================================================================

def executar_tarefa_seca(tipo: TipoTarefaSuricata | str, parametros: dict[str, object] | None = None) -> dict[str, object]:
    """Valida o frame completo (Parâmetros, Configs e Estrutura) simulando um DRY RUN para UI's exibirem botoes 'Ready'."""
    try:
        t_tipo = converter_tipo_tarefa(tipo)
        p_ok = validar_parametros_tarefa(t_tipo, parametros)
        
        return {
            "valida": True,
            "tipo": t_tipo.value,
            "parametros": _serializar_resultado(_limpar_dados_sensiveis(p_ok)),
            "erros": [],
            "aviso": "Nenhuma operação foi executada.",
        }
    except Exception as e:
        return {
            "valida": False,
            "tipo": str(tipo),
            "parametros": {},
            "erros": [str(e)],
            "aviso": "Estrutura inválida.",
        }


def obter_tipos_tarefa_disponiveis() -> list[dict[str, object]]:
    """Define quais blocos da UI podem ser abertos pra usuário (Capability Matrix)."""
    return [
        {
            "value": TipoTarefaSuricata.DIAGNOSTICO.value,
            "titulo": "Diagnóstico do Sistema",
            "descricao": "Varedura completa nas layers do Suricata sem efetuar alterações.",
            "requer_configuracao": False,
            "operacao_privilegiada": False,
            "pode_cancelar_entre_etapas": True,
        },
        {
            "value": TipoTarefaSuricata.INSTALACAO.value,
            "titulo": "Deploy & Instalação IDS",
            "descricao": "Instala os binaries nativos, regras comunitárias e estabelece o sistema principal.",
            "requer_configuracao": False,
            "operacao_privilegiada": True,
            "pode_cancelar_entre_etapas": True,
        },
        {
            "value": TipoTarefaSuricata.CONFIGURACAO.value,
            "titulo": "Patching YAML / Interfaces",
            "descricao": "Edição cirúrgica das bridges de rede em uso e diretivas internas no yaml.",
            "requer_configuracao": True,
            "operacao_privilegiada": True,
            "pode_cancelar_entre_etapas": False,
        },
        {
            "value": TipoTarefaSuricata.ATUALIZACAO_REGRAS.value,
            "titulo": "Atualização Constante de Regras",
            "descricao": "Puxada forçada do Intelligence Pack (ET/Open e regras Locais).",
            "requer_configuracao": False,
            "operacao_privilegiada": True,
            "pode_cancelar_entre_etapas": False,
        },
        {
            "value": TipoTarefaSuricata.VALIDACAO.value,
            "titulo": "Auditoria YAML Dry-Run",
            "descricao": "Bate o suricata -T para averiguar a sanidade das configs.",
            "requer_configuracao": False,
            "operacao_privilegiada": False,
            "pode_cancelar_entre_etapas": False,
        },
        {
            "value": TipoTarefaSuricata.REINICIO_SURICATA.value,
            "titulo": "Bounce do Motor C",
            "descricao": "Reinicia isoladamente a engine principal.",
            "requer_configuracao": False,
            "operacao_privilegiada": True,
            "pode_cancelar_entre_etapas": False,
        },
        {
            "value": TipoTarefaSuricata.REINICIO_MONITOR.value,
            "titulo": "Bounce do Worker Python",
            "descricao": "Reinicia isoladamente o Ingress Consumer no log e BD.",
            "requer_configuracao": False,
            "operacao_privilegiada": True,
            "pode_cancelar_entre_etapas": False,
        },
    ]


def resumir_tarefa(progresso: ProgressoTarefa, resultado: ResultadoEtapa | None = None) -> dict[str, object]:
    """Exibe um card de relatório (Visão alta) de qualquer tarefa em andamento/finalizada."""
    _normalizar_tempos_progresso(progresso)

    dur = 0.0
    if progresso.iniciado_em:
        inicio = _normalizar_datetime(progresso.iniciado_em)
        fim = _normalizar_datetime(progresso.finalizado_em) or _agora()

        if inicio is not None:
            dur = max(0.0, (fim - inicio).total_seconds())

    return {
        "id": progresso.tarefa_id,
        "tipo": progresso.tipo.value,
        "status": progresso.status.value,
        "progresso": progresso.progresso,
        "etapa_atual": progresso.etapa_atual,
        "mensagem": progresso.mensagem,
        "sucesso": (progresso.status == StatusEtapa.SUCESSO),
        "erro": progresso.erro,
        "iniciado_em": progresso.iniciado_em.isoformat() if progresso.iniciado_em else "-",
        "finalizado_em": progresso.finalizado_em.isoformat() if progresso.finalizado_em else "-",
        "duracao_segundos": round(dur, 2),
        "logs_total": len(progresso.logs),
        "resultado_resumo": _serializar_resultado(resultado) if resultado else {},
    }


def obter_logs_tarefa(progresso: ProgressoTarefa, offset: int = 0, limite: int = 200) -> dict[str, object]:
    """Paginação via Slice de memória (Garante que UI não engula os MAX_LOGS de uma só vez)."""
    off_safe = max(0, offset)
    lim_safe = max(1, min(500, limite))
    total = len(progresso.logs)
    
    end_idx = off_safe + lim_safe
    l_cut = progresso.logs[off_safe:end_idx]
    
    return {
        "offset": off_safe,
        "limite": lim_safe,
        "total": total,
        "proximo_offset": end_idx if end_idx < total else total,
        "tem_mais": end_idx < total,
        "logs": _serializar_resultado(_limpar_dados_sensiveis(l_cut)),
    }