"""
Views e APIs focadas no onboarding e gerenciamento do Suricata Local.

Operações de sistema são persistidas como tarefas no banco e processadas pelo
worker automático `moonshield-suricata-worker`, mantendo a thread HTTP livre e
sem exigir execução manual de comandos.
"""

import json
import logging
import uuid
from typing import Any

from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.http import JsonResponse, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_GET, require_POST
from django.views.decorators.csrf import csrf_protect

from .models import (
    ConfiguracaoSuricata,
    TarefaSuricata,
    LogTarefaSuricata,
    StatusTarefaSuricata,
    TipoTarefaSuricataModel,
    NivelLogSuricata,
)

from .services.suricata.tipos import (
    ConfiguracaoSuricataDados,
    StatusEtapa,
    NivelLog,
)
from .services.suricata.tarefas import (
    executar_tarefa,
    executar_tarefa_seca,
    obter_tipos_tarefa_disponiveis,
    validar_parametros_tarefa,
    converter_tipo_tarefa,
    configuracao_de_dict,
    resumir_tarefa,
    solicitar_cancelamento,
    obter_logs_tarefa,
)
from .services.suricata.status import (
    obter_status_onboarding,
    obter_status_para_api,
    obter_resumo_cards,
    obter_status_stack_completo,
)
from .services.suricata.instalador import (
    obter_plano_instalacao,
)
from .services.suricata.interfaces import (
    obter_topologia_detectada,
    montar_configuracao_sugerida,
    validar_topologia,
)

logger = logging.getLogger(__name__)

# ==============================================================================
# CONSTANTES E CONFIGURAÇÕES
# ==============================================================================

MAX_BODY_JSON = 1024 * 1024  # 1 MB
MAX_LOGS_RETORNO = 500

TIPOS_TAREFA_PERMITIDOS = {
    "diagnostico",
    "instalacao",
    "configuracao",
    "atualizacao_regras",
    "validacao",
    "reinicio_suricata",
    "reinicio_monitor",
}


# ==============================================================================
# HELPERS PRIVADOS DE API E BANCO
# ==============================================================================

def _json_erro(
    mensagem: str,
    status_http: int = 400,
    erros: list[str] | None = None,
    dados: dict | None = None,
) -> JsonResponse:
    """Padroniza payload de falha no contrato da API HTTP."""
    return JsonResponse({
        "ok": False,
        "mensagem": mensagem,
        "erros": erros or [],
        "dados": dados or {}
    }, status=status_http)


def _json_sucesso(
    mensagem: str,
    dados: dict | None = None,
    status_http: int = 200,
) -> JsonResponse:
    """Padroniza payload positivo no contrato da API HTTP."""
    return JsonResponse({
        "ok": True,
        "mensagem": mensagem,
        "dados": dados or {}
    }, status=status_http)


def _ler_json_request(request: HttpRequest) -> dict:
    """Parseia e defende a view contra bodies JSON corrompidos ou maliciosos."""
    if request.content_type != "application/json":
        raise ValueError("O Content-Type da requisição deve ser application/json.")
        
    try:
        body = request.body
    except Exception:
        raise ValueError("Falha ao ler o corpo da requisição.")

    if len(body) > MAX_BODY_JSON:
        raise ValueError(f"Payload excede o limite permitido de {MAX_BODY_JSON} bytes.")

    try:
        texto = body.decode("utf-8")
        dados = json.loads(texto)
    except UnicodeDecodeError:
        raise ValueError("O payload JSON deve possuir codificação UTF-8.")
    except json.JSONDecodeError:
        raise ValueError("JSON estruturalmente inválido.")

    if not isinstance(dados, dict):
        raise ValueError("A raiz do payload JSON deve ser um objeto (Dicionário).")

    return dados


def _tornar_json_serializavel(valor: Any) -> Any:
    """Converte DTOs e estruturas aninhadas em tipos aceitos por JSONField."""
    if isinstance(valor, ConfiguracaoSuricataDados):
        return _tornar_json_serializavel(valor.to_dict())

    if hasattr(valor, "value") and not isinstance(valor, (str, int, float, bool)):
        return _tornar_json_serializavel(valor.value)

    if isinstance(valor, dict):
        return {
            str(chave): _tornar_json_serializavel(conteudo)
            for chave, conteudo in valor.items()
        }

    if isinstance(valor, (list, tuple, set)):
        return [_tornar_json_serializavel(item) for item in valor]

    return valor


def _obter_configuracao_ativa(criar: bool = False) -> ConfiguracaoSuricata | None:
    """Retorna o modelo de config da base Django (Singleton Mode Virtual)."""
    cfg = ConfiguracaoSuricata.objects.filter(ativo=True).order_by("-atualizado_em").first()
    
    if not cfg and criar:
        cfg = ConfiguracaoSuricata.objects.create(
            nome="Suricata Local",
            ativo=True
        )
        
    return cfg


def _configuracao_service(configuracao: ConfiguracaoSuricata | None) -> ConfiguracaoSuricataDados | None:
    """Faz a ponte entre a ORM do Django e o DTO read-only exigido pela camada Service (Suricata)."""
    if not configuracao:
        return None
        
    dic_cfg = configuracao.to_service_dict()
    return configuracao_de_dict(dic_cfg)


def _salvar_logs_progresso(tarefa: TarefaSuricata, progresso) -> None:
    """Descarrega assincronamente (em db) a trilha de logs instanciada em RAM durante a task."""
    logs_memoria = progresso.logs
    if not logs_memoria:
        return

    # Acha onde parou pra não dar dupe de UniqueConstraint (tarefa+sequencia)
    seq_atual = tarefa.logs.count()
    
    logs_para_inserir = []
    
    # Adiciona só o que veio depois do que ja ta no BD
    for i, mem_log in enumerate(logs_memoria):
        if i < seq_atual:
            continue
            
        # O serializer interno proibe chaves perigosas
        detalhes_seguros = {}
        if hasattr(mem_log, "to_dict"):
            detalhes_seguros = mem_log.to_dict().get("detalhes", {})
            
        # Transpõe o Enum do Core p/ o Enum do Model
        nivel_core = getattr(mem_log, "nivel", NivelLog.INFO)
        nivel_model = NivelLogSuricata.INFO
        for n in NivelLogSuricata:
            if n.value == nivel_core.value:
                nivel_model = n
                break

        logs_para_inserir.append(LogTarefaSuricata(
            tarefa=tarefa,
            sequencia=i,
            nivel=nivel_model,
            etapa=getattr(mem_log, "etapa", "")[:100],
            mensagem=getattr(mem_log, "mensagem", "")[:1000], # Trava len do bd
            detalhes=detalhes_seguros,
            criado_em=getattr(mem_log, "criado_em", timezone.now())
        ))

    if logs_para_inserir:
        LogTarefaSuricata.objects.bulk_create(logs_para_inserir, batch_size=200)


def _sincronizar_tarefa(tarefa: TarefaSuricata, progresso, resultado=None) -> None:
    """Equipara o estado local do Objeto RAM Python persistindo seus avanços num DB Hit."""
    tarefa.progresso = progresso.progresso
    tarefa.etapa_atual = progresso.etapa_atual
    tarefa.mensagem = progresso.mensagem
    tarefa.erro = progresso.erro
    
    if progresso.iniciado_em:
        tarefa.iniciado_em = progresso.iniciado_em
    if progresso.finalizado_em:
        tarefa.finalizado_em = progresso.finalizado_em

    if resultado is not None:
        if hasattr(resultado, "to_dict"):
            tarefa.resultado = resultado.to_dict()
        else:
            tarefa.resultado = resultado

    # Map do Enum do Core (StatusEtapa) p/ Model Django
    novo_status = StatusTarefaSuricata.PENDENTE
    for s in StatusTarefaSuricata:
        if s.value == progresso.status.value:
            novo_status = s
            break
            
    tarefa.status = novo_status
    tarefa.save()



def _resumir_diagnostico_serializado(
    diagnostico: dict | None,
) -> dict:
    """
    Reconstrói os contadores do Doctor a partir de um snapshot já persistido.

    Não executa checks, subprocessos ou `suricata -T`.
    """
    diagnostico = (
        diagnostico
        if isinstance(diagnostico, dict)
        else {}
    )

    itens = diagnostico.get("itens")
    itens = itens if isinstance(itens, list) else []

    if itens:
        total_checks = len(itens)
        total_ok = sum(
            1
            for item in itens
            if isinstance(item, dict)
            and bool(item.get("ok"))
        )
        total_criticos = sum(
            1
            for item in itens
            if isinstance(item, dict)
            and not bool(item.get("ok"))
            and bool(item.get("critico"))
        )
        total_avisos = sum(
            1
            for item in itens
            if isinstance(item, dict)
            and not bool(item.get("ok"))
            and not bool(item.get("critico"))
        )
    else:
        total_checks = int(
            diagnostico.get("total_checks")
            or 0
        )
        total_ok = int(
            diagnostico.get("total_ok")
            or diagnostico.get("total_saudaveis")
            or 0
        )
        total_criticos = int(
            diagnostico.get("total_criticos")
            or 0
        )
        total_falhas_informado = int(
            diagnostico.get("total_falhas")
            or 0
        )
        total_avisos = int(
            diagnostico.get("total_avisos")
            or max(
                0,
                total_falhas_informado - total_criticos,
            )
        )

    total_falhas = (
        total_avisos
        + total_criticos
    )

    score_integridade = (
        round(
            (total_ok / total_checks) * 100
        )
        if total_checks > 0
        else 0
    )

    grupos_resumo: dict[str, dict[str, object]] = {}

    if itens:
        for item in itens:
            if not isinstance(item, dict):
                continue

            grupo = str(
                item.get("grupo")
                or "Outros"
            )

            bucket = grupos_resumo.setdefault(
                grupo,
                {
                    "total": 0,
                    "ok": 0,
                    "saudaveis": 0,
                    "avisos": 0,
                    "criticos": 0,
                    "falhas": 0,
                    "score": 0,
                },
            )

            bucket["total"] += 1

            if bool(item.get("ok")):
                bucket["ok"] += 1
                bucket["saudaveis"] += 1
            elif bool(item.get("critico")):
                bucket["criticos"] += 1
                bucket["falhas"] += 1
            else:
                bucket["avisos"] += 1
                bucket["falhas"] += 1

        for bucket in grupos_resumo.values():
            total_grupo = int(
                bucket.get("total")
                or 0
            )
            ok_grupo = int(
                bucket.get("ok")
                or 0
            )
            bucket["score"] = (
                round(
                    (ok_grupo / total_grupo) * 100
                )
                if total_grupo > 0
                else 0
            )

    elif isinstance(
        diagnostico.get("grupos"),
        dict,
    ):
        grupos_resumo = (
            diagnostico.get("grupos")
            or {}
        )

    falhas_criticas = [
        item
        for item in itens
        if isinstance(item, dict)
        and not bool(item.get("ok"))
        and bool(item.get("critico"))
    ]

    avisos = [
        item
        for item in itens
        if isinstance(item, dict)
        and not bool(item.get("ok"))
        and not bool(item.get("critico"))
    ]

    pronto = bool(
        diagnostico.get("pronto")
        if "pronto" in diagnostico
        else (
            total_checks > 0
            and total_criticos == 0
        )
    )

    return {
        "pronto": pronto,
        "total_checks": total_checks,
        "total_ok": total_ok,
        "total_saudaveis": total_ok,
        "total_avisos": total_avisos,
        "total_falhas": total_falhas,
        "total_criticos": total_criticos,
        "score_integridade": score_integridade,
        "score": score_integridade,
        "falhas_criticas": falhas_criticas,
        "avisos": avisos,
        "grupos": grupos_resumo,
        "duracao_segundos": float(
            diagnostico.get("duracao_segundos")
            or 0.0
        ),
        "executado_em": str(
            diagnostico.get("executado_em")
            or ""
        ),
        "mensagem": (
            "Infraestrutura pronta; existem apenas avisos operacionais."
            if pronto and total_avisos > 0
            else "Infraestrutura pronta e sem falhas críticas."
            if pronto
            else "Existem falhas críticas que exigem correção."
        ),
    }


def _extrair_diagnostico_de_resultado_tarefa(
    resultado: Any,
) -> tuple[dict, dict, list]:
    """
    Normaliza formatos antigos e novos de resultados de diagnóstico.

    Contrato atual do worker:
        resultado
          -> dados
             -> diagnostico_completo
             -> resumo_rapido

    Também aceita aliases futuros:
        diagnostico / resumo / acoes_recomendadas
    """
    if not isinstance(resultado, dict):
        return {}, {}, []

    dados = resultado.get("dados")
    dados = (
        dados
        if isinstance(dados, dict)
        else {}
    )

    diagnostico = (
        dados.get("diagnostico_completo")
        or dados.get("diagnostico")
        or resultado.get("diagnostico")
        or {}
    )
    diagnostico = (
        diagnostico
        if isinstance(diagnostico, dict)
        else {}
    )

    resumo_informado = (
        dados.get("resumo_rapido")
        or dados.get("resumo")
        or resultado.get("resumo")
        or {}
    )
    resumo_informado = (
        resumo_informado
        if isinstance(resumo_informado, dict)
        else {}
    )

    resumo = (
        _resumir_diagnostico_serializado(
            diagnostico
        )
        if diagnostico
        else {}
    )

    if resumo_informado:
        # Os contadores derivados do mesmo laudo têm precedência.
        resumo = {
            **resumo_informado,
            **resumo,
        }

    acoes = (
        dados.get("acoes_recomendadas")
        or dados.get("acoes")
        or resultado.get("acoes_recomendadas")
        or resultado.get("acoes")
        or []
    )
    acoes = (
        acoes
        if isinstance(acoes, list)
        else []
    )

    return (
        diagnostico,
        resumo,
        acoes,
    )


def _meta_tarefa(
    tarefa: TarefaSuricata | None,
) -> dict | None:
    """Serializa metadados leves para polling da interface."""
    if not tarefa:
        return None

    return {
        "id": str(tarefa.pk),
        "tipo": tarefa.tipo,
        "status": tarefa.status,
        "progresso": tarefa.progresso,
        "etapa_atual": tarefa.etapa_atual,
        "mensagem": tarefa.mensagem,
        "erro": tarefa.erro,
        "duracao_segundos": tarefa.duracao_segundos,
        "criado_em": (
            tarefa.criado_em.isoformat()
            if tarefa.criado_em
            else None
        ),
        "iniciado_em": (
            tarefa.iniciado_em.isoformat()
            if tarefa.iniciado_em
            else None
        ),
        "finalizado_em": (
            tarefa.finalizado_em.isoformat()
            if tarefa.finalizado_em
            else None
        ),
        "atualizado_em": (
            tarefa.atualizado_em.isoformat()
            if tarefa.atualizado_em
            else None
        ),
    }


def _obter_estado_diagnostico_persistido(
    configuracao: ConfiguracaoSuricata | None,
) -> dict:
    """
    Carrega o último diagnóstico SEM executar o Doctor.

    Prioridade:
    1. última TarefaSuricata de diagnóstico com resultado válido;
    2. ConfiguracaoSuricata.ultimo_diagnostico como fallback.

    Também retorna eventual tarefa pendente/em execução para que o frontend
    consiga retomar o polling após F5 ou troca de seção.
    """
    qs = TarefaSuricata.objects.filter(
        tipo=TipoTarefaSuricataModel.DIAGNOSTICO,
    )

    if configuracao is not None:
        qs = qs.filter(
            configuracao=configuracao,
        )

    em_andamento = (
        qs.filter(
            status__in=[
                StatusTarefaSuricata.PENDENTE,
                StatusTarefaSuricata.EXECUTANDO,
            ]
        )
        .order_by("-criado_em")
        .first()
    )

    ultima_tentativa = (
        qs.order_by("-criado_em").first()
    )

    diagnostico: dict = {}
    resumo: dict = {}
    acoes: list = []
    fonte = "nenhuma"
    tarefa_fonte: TarefaSuricata | None = None

    sucessos_recentes = (
        qs.filter(
            status=StatusTarefaSuricata.SUCESSO,
        )
        .order_by(
            "-finalizado_em",
            "-criado_em",
        )[:10]
    )

    for tarefa in sucessos_recentes:
        (
            diag_tarefa,
            resumo_tarefa,
            acoes_tarefa,
        ) = _extrair_diagnostico_de_resultado_tarefa(
            tarefa.resultado,
        )

        if diag_tarefa or resumo_tarefa:
            diagnostico = diag_tarefa
            resumo = resumo_tarefa
            acoes = acoes_tarefa
            fonte = "tarefa"
            tarefa_fonte = tarefa
            break

    if (
        not diagnostico
        and configuracao
        and isinstance(
            configuracao.ultimo_diagnostico,
            dict,
        )
        and configuracao.ultimo_diagnostico
    ):
        snapshot = (
            configuracao.ultimo_diagnostico
        )

        (
            diagnostico,
            resumo,
            acoes,
        ) = _extrair_diagnostico_de_resultado_tarefa(
            snapshot
        )

        if not diagnostico:
            # Compatibilidade com snapshot salvo diretamente como laudo.
            diagnostico = snapshot
            resumo = _resumir_diagnostico_serializado(
                diagnostico
            )

        if diagnostico or resumo:
            fonte = "configuracao"

    executado_em = ""
    duracao_segundos = 0.0

    if resumo:
        executado_em = str(
            resumo.get("executado_em")
            or ""
        )
        duracao_segundos = float(
            resumo.get("duracao_segundos")
            or 0.0
        )

    if tarefa_fonte:
        if tarefa_fonte.finalizado_em:
            executado_em = (
                tarefa_fonte.finalizado_em.isoformat()
            )

        if (
            tarefa_fonte.duracao_segundos
            is not None
        ):
            duracao_segundos = float(
                tarefa_fonte.duracao_segundos
            )

    if resumo:
        resumo = dict(resumo)
        resumo["executado_em"] = executado_em
        resumo["duracao_segundos"] = (
            duracao_segundos
        )

    return {
        "executado": bool(
            diagnostico
            or resumo
        ),
        "fonte": fonte,
        "diagnostico": diagnostico,
        "resumo": resumo,
        "acoes_recomendadas": acoes,
        "executado_em": (
            executado_em
            or None
        ),
        "duracao_segundos": duracao_segundos,
        "tarefa_id": (
            str(tarefa_fonte.pk)
            if tarefa_fonte
            else None
        ),
        "em_andamento": (
            em_andamento is not None
        ),
        "tarefa_em_andamento": (
            _meta_tarefa(
                em_andamento
            )
        ),
        "ultima_tentativa": (
            _meta_tarefa(
                ultima_tentativa
            )
        ),
    }


def _serializar_configuracao(configuracao: ConfiguracaoSuricata | None) -> dict | None:
    """Expõe a matriz da configuração do Suricata pro View context."""
    if not configuracao:
        return None
        
    return {
        "id": configuracao.id,
        "nome": configuracao.nome,
        "ativo": configuracao.ativo,
        "interface_wan": configuracao.interface_wan,
        "interface_lan": configuracao.interface_lan,
        "interface_mgmt": configuracao.interface_mgmt,
        "interfaces_monitoradas": configuracao.interfaces_monitoradas,
        "home_net": configuracao.home_net,
        "dns_interno": configuracao.dns_interno,
        "yaml_path": configuracao.yaml_path,
        "eve_path": configuracao.eve_path,
        "cursor_path": configuracao.cursor_path,
        "modo_captura": configuracao.modo_captura,
        "instalar_et_open": configuracao.instalar_et_open,
        "instalar_regras_moonshield": configuracao.instalar_regras_moonshield,
        "reiniciar_servicos": configuracao.reiniciar_servicos,
        "suricata_instalado": configuracao.suricata_instalado,
        "suricata_configurado": configuracao.suricata_configurado,
        "instalacao_concluida": configuracao.instalacao_concluida,
        "onboarding_concluido": configuracao.onboarding_concluido,
        "versao_suricata": configuracao.versao_suricata,
        "pronto": configuracao.pronto,
        "criado_em": configuracao.criado_em.isoformat() if configuracao.criado_em else None,
        "atualizado_em": configuracao.atualizado_em.isoformat() if configuracao.atualizado_em else None,
    }


def _configuracao_pode_abrir_painel(configuracao: ConfiguracaoSuricata | None) -> bool:
    """
    Regra única de navegação entre onboarding e painel.

    Saúde operacional não participa desta decisão: se um serviço cair depois
    da instalação, o operador continua entrando no painel para diagnosticar e
    recuperar a stack, em vez de ser enviado novamente ao instalador.
    """
    if not configuracao:
        return False

    return bool(
        configuracao.onboarding_concluido
        and configuracao.instalacao_concluida
        and configuracao.suricata_instalado
        and configuracao.suricata_configurado
    )


def _motivos_configuracao_incompleta(configuracao: ConfiguracaoSuricata | None) -> list[str]:
    """Explica por que o painel ainda deve encaminhar ao onboarding."""
    if not configuracao:
        return ["Nenhuma configuração ativa do Suricata foi encontrada."]

    motivos = []
    if not configuracao.suricata_instalado:
        motivos.append("Suricata ainda não marcado como instalado.")
    if not configuracao.suricata_configurado:
        motivos.append("Configuração do Suricata ainda não concluída.")
    if not configuracao.instalacao_concluida:
        motivos.append("Instalação ainda não concluída.")
    if not configuracao.onboarding_concluido:
        motivos.append("Onboarding ainda não concluído.")
    return motivos


def _urls_navegacao_suricata() -> dict:
    """URLs oficiais de navegação do módulo Suricata."""
    return {
        "painel": reverse("incidentes:suricata_painel"),
        "onboarding": reverse("incidentes:suricata_onboarding"),
    }


# ==============================================================================
# VIEWS (RENDERIZAÇÃO HTML)
# ==============================================================================

@login_required(login_url="autenticacao:login")
@require_GET
def onboarding_suricata(request):
    """
    Assistente de instalação e reconfiguração do Suricata.

    A URL do onboarding continua acessível quando chamada explicitamente mesmo
    depois da instalação. Isso permite que "Configurar Suricata" abra o wizard
    para revisão/reconfiguração sem apagar flags e sem fingir desinstalação.
    """
    cfg = _obter_configuracao_ativa(criar=True)
    dto_cfg = _configuracao_service(cfg)
    urls_nav = _urls_navegacao_suricata()
    painel_disponivel = _configuracao_pode_abrir_painel(cfg)

    try:
        st_onb = obter_status_onboarding(dto_cfg)
    except Exception as exc:
        logger.exception("Falha ao determinar a etapa inicial do onboarding.")
        st_onb = {
            "erro": "Falha na análise do ambiente.",
            "mensagem": str(exc),
        }

    try:
        plano = obter_plano_instalacao(dto_cfg)
    except Exception as exc:
        logger.exception("Falha na formatação preditiva do plano de implantação.")
        plano = {
            "erro": "Falha na construção do plano de ação.",
            "bloqueios": [str(exc)],
        }

    context = {
        "configuracao_suricata": _serializar_configuracao(cfg),
        "status_onboarding": st_onb,
        "plano_instalacao": plano,
        "painel_disponivel": painel_disponivel,
        "modo_reconfiguracao": painel_disponivel,
        "url_painel_suricata": urls_nav["painel"],
        "url_onboarding_suricata": urls_nav["onboarding"],
        "pagina_suricata": True,
        "titulo_pagina": (
            "Configuração do Suricata"
            if painel_disponivel
            else "Instalação do Suricata"
        ),
    }

    return render(request, "incidentes/suricata/onboarding.html", context)


@login_required(login_url="autenticacao:login")
@require_GET
def painel_suricata(request):
    """
    Cockpit operacional do Suricata.

    Só redireciona ao onboarding quando a instalação/configuração inicial ainda
    não terminou. Uma stack degradada NÃO bloqueia o painel, pois é justamente
    nele que o operador precisa enxergar, diagnosticar e recuperar o serviço.
    """
    cfg = _obter_configuracao_ativa(criar=False)

    if not _configuracao_pode_abrir_painel(cfg):
        logger.info(
            "Painel Suricata indisponível; encaminhando ao onboarding: %s",
            "; ".join(_motivos_configuracao_incompleta(cfg)),
        )
        return redirect("incidentes:suricata_onboarding")

    dto_cfg = _configuracao_service(cfg)
    urls_nav = _urls_navegacao_suricata()

    try:
        st_stack = obter_status_stack_completo(
            dto_cfg,
            incluir_diagnostico=False,
        )
    except Exception as exc:
        logger.exception("Falha ao ler status rápido da stack Suricata.")
        st_stack = {
            "status": "erro",
            "saudavel": False,
            "mensagem": "Não foi possível consultar o estado atual da stack.",
            "erros": [str(exc)],
        }

    try:
        cards = obter_resumo_cards(dto_cfg)
    except Exception as exc:
        logger.exception("Falha ao gerar cards iniciais do painel Suricata.")
        cards = {
            "erro": True,
            "mensagem": "Não foi possível montar o resumo dos componentes.",
            "detalhes": str(exc),
        }

    try:
        estado_diagnostico = _obter_estado_diagnostico_persistido(cfg)
    except Exception as exc:
        logger.exception(
            "Falha ao carregar último diagnóstico persistido."
        )
        estado_diagnostico = {
            "executado": False,
            "em_andamento": False,
            "mensagem": str(exc),
        }

    context = {
        "configuracao_suricata": _serializar_configuracao(cfg),
        "status_stack": st_stack,
        "cards_suricata": cards,
        "ultimo_diagnostico_suricata": estado_diagnostico,
        "painel_disponivel": True,
        "modo_reconfiguracao": False,
        "url_painel_suricata": urls_nav["painel"],
        "url_onboarding_suricata": urls_nav["onboarding"],
        "pagina_suricata": True,
        "titulo_pagina": "Suricata",
    }

    return render(request, "incidentes/suricata/painel.html", context)


# ==============================================================================
# API (LEITURA / DIAGNÓSTICOS)
# ==============================================================================

@login_required(login_url="autenticacao:login")
@require_GET
def api_status_suricata(request):
    """Consulta consolidada leve usada pelo polling do painel."""
    cfg = _obter_configuracao_ativa(criar=False)
    urls_nav = _urls_navegacao_suricata()

    if not cfg:
        return _json_erro(
            "Suricata ainda não possui configuração ativa.",
            status_http=409,
            dados={
                "requer_onboarding": True,
                "painel_disponivel": False,
                "url_onboarding": urls_nav["onboarding"],
            },
        )

    dto_cfg = _configuracao_service(cfg)
    incluir_diagnostico = request.GET.get("diagnostico") == "1"

    try:
        payload = obter_status_para_api(
            dto_cfg,
            incluir_diagnostico=incluir_diagnostico,
        )
    except Exception as exc:
        logger.exception("Falha ao consultar status do Suricata pela API.")
        return _json_erro(
            "Não foi possível consultar o estado atual do Suricata.",
            status_http=500,
            erros=[str(exc)],
            dados={
                "requer_onboarding": not _configuracao_pode_abrir_painel(cfg),
                "painel_disponivel": _configuracao_pode_abrir_painel(cfg),
                "url_painel": urls_nav["painel"],
                "url_onboarding": urls_nav["onboarding"],
            },
        )

    if payload.get("ok"):
        dados = payload.get("dados") or {}
        if not isinstance(dados, dict):
            dados = {"status": dados}

        dados["navegacao"] = {
            "requer_onboarding": not _configuracao_pode_abrir_painel(cfg),
            "painel_disponivel": _configuracao_pode_abrir_painel(cfg),
            "url_painel": urls_nav["painel"],
            "url_onboarding": urls_nav["onboarding"],
        }
        return _json_sucesso("Status obtido.", dados)

    return _json_erro(
        payload.get("mensagem", "Erro ao consultar status."),
        status_http=500,
        dados={
            "payload": payload,
            "navegacao": {
                "requer_onboarding": not _configuracao_pode_abrir_painel(cfg),
                "painel_disponivel": _configuracao_pode_abrir_painel(cfg),
                "url_painel": urls_nav["painel"],
                "url_onboarding": urls_nav["onboarding"],
            },
        },
    )


@login_required(login_url="autenticacao:login")
@require_GET
def api_onboarding_status(request):
    """Fornece state-machine realtime sobre que fase do assistente o cliente está."""
    cfg = _obter_configuracao_ativa(criar=False)
    dto_cfg = _configuracao_service(cfg)
    
    try:
        onb = obter_status_onboarding(dto_cfg)
        plano = obter_plano_instalacao(dto_cfg)
        tipos_disp = obter_tipos_tarefa_disponiveis()
        
        urls_nav = _urls_navegacao_suricata()
        painel_disponivel = _configuracao_pode_abrir_painel(cfg)

        return _json_sucesso("Status Onboarding lido.", {
            "configuracao": _serializar_configuracao(cfg),
            "status_onboarding": onb,
            "plano_instalacao": plano,
            "tarefas_disponiveis": tipos_disp,
            "painel_disponivel": painel_disponivel,
            "modo_reconfiguracao": painel_disponivel,
            "url_painel": urls_nav["painel"],
            "url_onboarding": urls_nav["onboarding"],
        })
    except Exception as e:
        logger.exception("Erro em api_onboarding_status")
        return _json_erro("Erro interno.", 500, [str(e)])


@login_required(login_url="autenticacao:login")
@require_GET
def api_detectar_interfaces(request):
    """Varredura de baixo nivel p/ inferir placas e topologia lógicas do SO (Sem touch no disco)."""
    try:
        topo = obter_topologia_detectada(incluir_virtuais=False)
        cfg_sug = montar_configuracao_sugerida(topo)
        
        return _json_sucesso("Topologia inspecionada.", {
            "topologia": topo.to_dict(),
            "configuracao_sugerida": cfg_sug.to_dict()
        })
    except Exception as e:
        logger.exception("Erro ao prospectar a topologia local.")
        return _json_erro("Falha ao inferir as placas de rede do sistema.", 500, [str(e)])


@login_required(login_url="autenticacao:login")
@require_GET
def api_diagnostico_suricata(request):
    """
    Retorna o último diagnóstico persistido.

    Esta rota é read-only:
    - não executa `suricata -T`;
    - não chama o Doctor;
    - não abre subprocessos;
    - não bloqueia a thread HTTP.

    Um novo diagnóstico deve ser criado como TarefaSuricata do tipo
    `diagnostico` e executado pelo worker automático.
    """
    cfg = _obter_configuracao_ativa(
        criar=False
    )

    if not cfg:
        return _json_sucesso(
            "Diagnóstico ainda não executado.",
            {
                "executado": False,
                "fonte": "nenhuma",
                "diagnostico": {},
                "resumo": {},
                "acoes_recomendadas": [],
                "executado_em": None,
                "duracao_segundos": 0.0,
                "tarefa_id": None,
                "em_andamento": False,
                "tarefa_em_andamento": None,
                "ultima_tentativa": None,
            },
        )

    try:
        estado = (
            _obter_estado_diagnostico_persistido(
                cfg
            )
        )
    except Exception as exc:
        logger.exception(
            "Falha ao carregar diagnóstico persistido."
        )
        return _json_erro(
            "Não foi possível consultar o último diagnóstico salvo.",
            status_http=500,
            erros=[str(exc)],
        )

    if estado.get("em_andamento"):
        mensagem = (
            "Existe um diagnóstico em processamento pelo worker."
        )
    elif estado.get("executado"):
        mensagem = (
            "Último diagnóstico persistido carregado."
        )
    else:
        mensagem = (
            "Diagnóstico ainda não executado."
        )

    return _json_sucesso(
        mensagem,
        estado,
    )


@login_required(login_url="autenticacao:login")
@require_GET
def api_listar_tarefas(request):
    """Extrator de histórico de orquestrações do Model."""
    status_f = request.GET.get("status")
    tipo_f = request.GET.get("tipo")
    
    try:
        limite = int(request.GET.get("limite", 50))
        offset = int(request.GET.get("offset", 0))
    except ValueError:
        return _json_erro("Paginação requer inteiros.", 400)
        
    limite = max(1, min(limite, 100))
    offset = max(0, offset)

    qs = TarefaSuricata.objects.all().order_by("-criado_em")
    
    if status_f and status_f in StatusTarefaSuricata.values:
        qs = qs.filter(status=status_f)
        
    if tipo_f and tipo_f in TipoTarefaSuricataModel.values:
        qs = qs.filter(tipo=tipo_f)

    total = qs.count()
    tarefas = qs[offset:offset + limite]
    
    return _json_sucesso("Extrato lido.", {
        "total": total,
        "offset": offset,
        "limite": limite,
        "tarefas": [t.to_dict(incluir_logs=False) for t in tarefas]
    })


@login_required(login_url="autenticacao:login")
@require_GET
def api_detalhe_tarefa(request, tarefa_id: str):
    """Lupa isolada sobre task que roda no backend."""
    tarefa = get_object_or_404(TarefaSuricata, pk=tarefa_id)
    return _json_sucesso("Tarefa carregada.", tarefa.to_dict(incluir_logs=True))


@login_required(login_url="autenticacao:login")
@require_GET
def api_logs_tarefa(request, tarefa_id: str):
    """Paging para logs verbosos do Suricata Helper."""
    tarefa = get_object_or_404(TarefaSuricata, pk=tarefa_id)
    
    try:
        limite = int(request.GET.get("limite", 200))
        offset = int(request.GET.get("offset", 0))
    except ValueError:
        return _json_erro("Limites mal formatados.", 400)
        
    limite = max(1, min(limite, 500))
    offset = max(0, offset)

    logs_qs = tarefa.logs.order_by("sequencia", "id")
    total = logs_qs.count()
    
    pedaco = logs_qs[offset:offset + limite]
    prox_off = offset + len(pedaco)
    
    return _json_sucesso("Logs descarregados.", {
        "total": total,
        "offset": offset,
        "limite": limite,
        "proximo_offset": prox_off,
        "tem_mais": prox_off < total,
        "logs": [l.to_dict() for l in pedaco]
    })


# ==============================================================================
# API (ESCRITAS / POST)
# ==============================================================================

@login_required(login_url="autenticacao:login")
@require_POST
@csrf_protect
def api_salvar_configuracao(request):
    """Persiste parâmetros arquiteturais da rede pro DB antes que vire Task do Host."""
    try:
        payload = _ler_json_request(request)
    except ValueError as e:
        return _json_erro(str(e))

    chaves_aceitas = {
        "nome", "interface_wan", "interface_lan", "interface_mgmt",
        "interfaces_monitoradas", "home_net", "dns_interno",
        "yaml_path", "eve_path", "cursor_path", "modo_captura",
        "instalar_et_open", "instalar_regras_moonshield", "reiniciar_servicos"
    }

    dados_limpos = {k: v for k, v in payload.items() if k in chaves_aceitas}
    
    # 1. Validação de Topologia Strict Local
    try:
        cfg_dto = configuracao_de_dict(dados_limpos)
    except ValueError as e:
         return _json_erro("Formatação dos parâmetros inválida.", erros=[str(e)])
         
    if not cfg_dto:
        return _json_erro("Payload sem os dados mínimos da arquitetura.")
        
    erros_topo = validar_topologia(cfg_dto)
    if erros_topo:
        return _json_erro("A topologia de rede foi rejeitada nas validações primárias.", erros=erros_topo)

    # 2. Persistência
    try:
        with transaction.atomic():
            cfg_model = _obter_configuracao_ativa(criar=True)
            
            if "nome" in dados_limpos: cfg_model.nome = str(dados_limpos["nome"])
            if "interface_wan" in dados_limpos: cfg_model.interface_wan = cfg_dto.interface_wan
            if "interface_lan" in dados_limpos: cfg_model.interface_lan = cfg_dto.interface_lan
            if "interface_mgmt" in dados_limpos: cfg_model.interface_mgmt = cfg_dto.interface_mgmt
            if "interfaces_monitoradas" in dados_limpos: cfg_model.interfaces_monitoradas = cfg_dto.interfaces_monitoradas
            if "home_net" in dados_limpos: cfg_model.home_net = cfg_dto.home_net
            if "dns_interno" in dados_limpos: cfg_model.dns_interno = cfg_dto.dns_interno
            
            if "yaml_path" in dados_limpos: cfg_model.yaml_path = cfg_dto.yaml_path
            if "eve_path" in dados_limpos: cfg_model.eve_path = cfg_dto.eve_path
            if "cursor_path" in dados_limpos: cfg_model.cursor_path = str(dados_limpos["cursor_path"]).strip()
            
            if "modo_captura" in dados_limpos: cfg_model.modo_captura = cfg_dto.modo_captura.value
            
            if "instalar_et_open" in dados_limpos: cfg_model.instalar_et_open = cfg_dto.instalar_et_open
            if "instalar_regras_moonshield" in dados_limpos: cfg_model.instalar_regras_moonshield = cfg_dto.instalar_regras_moonshield
            if "reiniciar_servicos" in dados_limpos: cfg_model.reiniciar_servicos = cfg_dto.reiniciar_servicos
            
            cfg_model.save()
            
        return _json_sucesso("Topologia arquivada com sucesso.", _serializar_configuracao(cfg_model))
    except Exception as e:
        logger.exception("Crash no banco ao salvar configuracao do Suricata.")
        return _json_erro("Dificuldade técnica na gravação do modelo.", 500, [str(e)])


@login_required(login_url="autenticacao:login")
@require_POST
@csrf_protect
def api_criar_tarefa(request):
    """
    Registra uma tarefa para processamento automático pelo worker local.

    A view apenas valida e persiste a intenção. Nenhuma operação privilegiada
    é executada dentro da requisição HTTP.
    """
    try:
        payload = _ler_json_request(request)
    except ValueError as exc:
        return _json_erro(str(exc))

    tipo_str = str(payload.get("tipo", "")).strip()
    parametros = payload.get("parametros", {})

    if tipo_str not in TIPOS_TAREFA_PERMITIDOS:
        return _json_erro(
            f"Operação '{tipo_str}' não consta no diretório de tarefas "
            "habilitadas."
        )

    if parametros is None:
        parametros = {}

    if not isinstance(parametros, dict):
        return _json_erro(
            "O campo 'parametros' precisa ser um objeto JSON."
        )

    parametros = dict(parametros)

    # Diagnóstico profundo é uma operação longa. Reutiliza uma tarefa já
    # pendente/em execução para impedir duplo clique, reload ou duas abas
    # disparando `suricata -T` concorrentemente.
    if tipo_str == TipoTarefaSuricataModel.DIAGNOSTICO.value:
        tarefa_existente = (
            TarefaSuricata.objects.filter(
                tipo=TipoTarefaSuricataModel.DIAGNOSTICO,
                status__in=[
                    StatusTarefaSuricata.PENDENTE,
                    StatusTarefaSuricata.EXECUTANDO,
                ],
            )
            .order_by("-criado_em")
            .first()
        )

        if tarefa_existente:
            return _json_sucesso(
                (
                    "Já existe um diagnóstico em processamento; "
                    "acompanhando a tarefa atual."
                ),
                {
                    "tarefa_id": str(tarefa_existente.pk),
                    "tarefa": tarefa_existente.to_dict(
                        incluir_logs=False
                    ),
                    "reutilizada": True,
                    "processamento": {
                        "modo": "worker_automatico",
                        "servico": "moonshield-suricata-worker",
                        "requer_comando_manual": False,
                        "status_inicial": tarefa_existente.status,
                    },
                },
            )

    # Doctor e validação usam a configuração canônica já salva no banco quando
    # o cliente não fornecer explicitamente um snapshot.
    if (
        tipo_str
        in {
            TipoTarefaSuricataModel.DIAGNOSTICO.value,
            TipoTarefaSuricataModel.VALIDACAO.value,
        }
        and "configuracao" not in parametros
    ):
        cfg_ativa = _obter_configuracao_ativa(
            criar=False
        )

        if cfg_ativa:
            parametros["configuracao"] = (
                cfg_ativa.to_service_dict()
            )

    try:
        tipo_tarefa = converter_tipo_tarefa(tipo_str)
        parametros_validados = validar_parametros_tarefa(
            tipo_tarefa,
            parametros,
        )
    except ValueError as exc:
        return _json_erro(
            "Configuração atrelada incorreta ou malformada.",
            erros=[str(exc)],
        )

    try:
        with transaction.atomic():
            configuracao = _obter_configuracao_ativa(criar=False)
            parametros_json = _tornar_json_serializavel(
                parametros_validados
            )

            tarefa = TarefaSuricata.objects.create(
                id=str(uuid.uuid4()),
                tipo=tipo_tarefa.value,
                status=StatusTarefaSuricata.PENDENTE,
                progresso=0,
                etapa_atual="aguardando_worker",
                mensagem=(
                    "Tarefa registrada e aguardando processamento "
                    "automático."
                ),
                parametros=parametros_json,
                configuracao=configuracao,
            )

        logger.info(
            "Tarefa Suricata %s criada para processamento automático (%s).",
            tarefa.pk,
            tarefa.tipo,
        )

        return _json_sucesso(
            "Tarefa criada e enviada ao processamento automático.",
            {
                "tarefa_id": str(tarefa.pk),
                "tarefa": tarefa.to_dict(incluir_logs=False),
                "processamento": {
                    "modo": "worker_automatico",
                    "servico": "moonshield-suricata-worker",
                    "requer_comando_manual": False,
                    "status_inicial": StatusTarefaSuricata.PENDENTE,
                },
            },
            status_http=201,
        )

    except Exception as exc:
        logger.exception(
            "Falha ao registrar tarefa Suricata do tipo %s.",
            tipo_str,
        )
        return _json_erro(
            "Não foi possível registrar a tarefa para processamento.",
            500,
            [str(exc)],
        )


@login_required(login_url="autenticacao:login")
@require_POST
@csrf_protect
def api_executar_tarefa_sincrona(request, tarefa_id: str):
    """Executa somente tarefas de leitura consideradas seguras na própria requisição HTTP."""
    tarefa = get_object_or_404(TarefaSuricata, pk=tarefa_id)

    if tarefa.finalizada or tarefa.executando:
        return _json_erro("O ciclo de vida desta Task expirou ou ela já se encontra sob judice do processador.", 409)

    tipos_inofensivos = {
        TipoTarefaSuricataModel.DIAGNOSTICO,
        TipoTarefaSuricataModel.VALIDACAO,
    }
    
    if tarefa.tipo not in tipos_inofensivos:
        return _json_erro("Negado. Requisição HTTP é restrita a auditorias (read-only) como Validação e Checkup. Mutações como INSTALL são executadas exclusivamente pelo worker automático.", 403)

    try:
        # Apenas operações read-only leves podem usar esta rota síncrona.
        from .services.suricata.tarefas import criar_progresso_tarefa
        
        prg = criar_progresso_tarefa(tarefa.tipo, str(tarefa.pk))
        _sincronizar_tarefa(tarefa, prg)
        
        # Execução síncrona restrita a diagnóstico e validação.
        prg_fim, res_fim = executar_tarefa(
            tipo=tarefa.tipo,
            parametros=tarefa.parametros,
            tarefa_id=tarefa.id,
            progresso=prg
        )
        
        # Atualiza a espinha dorsal ORM
        _sincronizar_tarefa(tarefa, prg_fim, res_fim)
        _salvar_logs_progresso(tarefa, prg_fim)

        return _json_sucesso("Tarefa de leitura processada.", tarefa.to_dict(incluir_logs=False))
        
    except Exception as e:
        logger.exception("Falha na execução síncrona da tarefa %s.", tarefa_id)
        return _json_erro("Crash interno.", 500, [str(e)])


@login_required(login_url="autenticacao:login")
@require_POST
@csrf_protect
def api_solicitar_cancelamento(request, tarefa_id: str):
    """Pede ao executor via Flag booleana na table TarefaSuricata que engatilhe um Soft-Kill."""
    tarefa = get_object_or_404(TarefaSuricata, pk=tarefa_id)
    
    if tarefa.finalizada:
        return _json_erro("A tarefa já esgotou a sua execução natural.", 409)

    try:
        with transaction.atomic():
            tarefa.solicitar_cancelamento("O operador Web acionou Abort.")
        return _json_sucesso("Protocolo de parada alocado para intercepção do worker.", tarefa.to_dict())
    except Exception as e:
        logger.exception("Não foi possível enviar Flag de Halt pro DB.")
        return _json_erro("Anomalia comunicacional com o Banco de Dados.", 500, [str(e)])


@login_required(login_url="autenticacao:login")
@require_POST
@csrf_protect
def api_marcar_onboarding_concluido(request):
    """
    Finaliza o onboarding sem executar novamente o Doctor profundo.

    O diagnóstico completo já pertence à tarefa de instalação. Neste endpoint
    fazemos apenas uma leitura rápida do estado atual dos serviços essenciais,
    persistimos as flags de conclusão e deixamos o frontend redirecionar para
    o painel do Suricata.
    """
    cfg = _obter_configuracao_ativa(criar=False)
    if not cfg:
        return _json_erro("Mestre em branco. Onboarding não executado.")

    dto_cfg = _configuracao_service(cfg)

    try:
        # IMPORTANTE:
        # Não usar incluir_diagnostico=True aqui. O Doctor chama `suricata -T`
        # e pode levar dezenas de segundos, enquanto o frontend possui timeout.
        st = obter_status_stack_completo(
            dto_cfg,
            incluir_diagnostico=False,
        )
    except Exception as exc:
        logger.exception("Falha ao consultar a stack antes de concluir onboarding.")
        return _json_erro(
            "Não foi possível consultar o estado final do sensor.",
            status_http=500,
            erros=[str(exc)],
        )

    servicos = st.get("servicos") or {}

    st_suricata = servicos.get("suricata") or {}
    st_monitor = servicos.get("monitor") or {}
    st_worker = servicos.get("worker_tarefas") or {}

    # Compatibilidade defensiva com contratos anteriores.
    if not st_suricata:
        suri_top = st.get("suricata") or {}
        st_suricata = suri_top.get("servico") or suri_top

    if not st_monitor:
        mon_top = st.get("monitor") or {}
        st_monitor = mon_top.get("servico") or mon_top

    if not st_worker:
        worker_top = st.get("worker_tarefas") or {}
        st_worker = worker_top.get("servico") or worker_top

    def _servico_ok(dados: dict) -> bool:
        return bool(
            isinstance(dados, dict)
            and dados.get("instalado")
            and dados.get("ativo")
        )

    suricata_ok = _servico_ok(st_suricata)
    monitor_ok = _servico_ok(st_monitor)
    worker_ok = _servico_ok(st_worker)

    # O clique em "Abrir painel" não deve repetir a instalação nem o Doctor.
    # Apenas impede a conclusão quando um daemon essencial realmente caiu.
    if not (suricata_ok and monitor_ok and worker_ok):
        erros = []
        if not suricata_ok:
            erros.append("Suricata não está instalado e ativo.")
        if not monitor_ok:
            erros.append("Monitor MoonShield não está instalado e ativo.")
        if not worker_ok:
            erros.append("Worker automático de tarefas não está instalado e ativo.")

        return _json_erro(
            "Finalização vetada: existem serviços essenciais indisponíveis.",
            status_http=409,
            erros=erros,
            dados={
                "suricata_ok": suricata_ok,
                "monitor_ok": monitor_ok,
                "worker_ok": worker_ok,
            },
        )

    try:
        with transaction.atomic():
            # Primeiro atualiza o snapshot operacional. Esse método pode recalcular
            # campos de estado; por isso ele deve rodar ANTES das flags finais.
            cfg.atualizar_status(status=st, salvar=True)

            suri_top = st.get("suricata") or {}

            versao = (
                suri_top.get("versao")
                or (st.get("ambiente") or {}).get("suricata", {}).get("versao")
                or cfg.versao_suricata
                or ""
            )

            # As flags de conclusão são persistidas por último para não serem
            # sobrescritas pelo atualizar_status().
            cfg.onboarding_concluido = True
            cfg.instalacao_concluida = True
            cfg.suricata_instalado = True
            cfg.suricata_configurado = True
            cfg.versao_suricata = str(versao)

            cfg.save(update_fields=[
                "onboarding_concluido",
                "instalacao_concluida",
                "suricata_instalado",
                "suricata_configurado",
                "versao_suricata",
            ])

        return _json_sucesso(
            "Onboarding concluído. Abrindo painel do Suricata.",
            {
                "configuracao": _serializar_configuracao(cfg),
                "validacao_final": {
                    "suricata_ok": suricata_ok,
                    "monitor_ok": monitor_ok,
                    "worker_ok": worker_ok,
                },
                "painel_disponivel": True,
                "redirecionar_para": reverse("incidentes:suricata_painel"),
            },
        )
    except Exception as exc:
        logger.exception("Falha ao concluir o onboarding do Suricata.")
        return _json_erro(
            "Falha inesperada ao concluir o onboarding.",
            status_http=500,
            erros=[str(exc)],
        )


@login_required(login_url="autenticacao:login")
@require_POST
@csrf_protect
def api_reabrir_onboarding(request):
    """
    Reabre formalmente o onboarding sem desinstalar o Suricata.

    Para apenas abrir o assistente e revisar configurações, o frontend deve
    navegar diretamente para `incidentes:suricata_onboarding`. Esta API só é
    necessária quando queremos marcar o onboarding como pendente novamente.
    """
    cfg = _obter_configuracao_ativa(criar=False)
    if not cfg:
        return _json_erro("Nenhuma configuração local ativa presente no ambiente.")

    try:
        with transaction.atomic():
            cfg.onboarding_concluido = False
            cfg.save(update_fields=["onboarding_concluido", "atualizado_em"])

        return _json_sucesso(
            "Onboarding reaberto sem remover a instalação existente.",
            {
                "configuracao": _serializar_configuracao(cfg),
                "painel_disponivel": False,
                "redirecionar_para": reverse("incidentes:suricata_onboarding"),
            },
        )
    except Exception as exc:
        logger.exception("Falha ao reabrir onboarding do Suricata.")
        return _json_erro(
            "Não foi possível reabrir o onboarding.",
            500,
            [str(exc)],
        )