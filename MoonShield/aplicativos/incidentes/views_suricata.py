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
from .services.suricata.diagnostico import (
    executar_diagnostico,
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

    if resultado:
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


# ==============================================================================
# VIEWS (RENDERIZAÇÃO HTML)
# ==============================================================================

@login_required(login_url="autenticacao:login")
@require_GET
def onboarding_suricata(request):
    """View do assistente/wizard de instalação do núcleo de Segurança do IDS."""
    cfg = _obter_configuracao_ativa(criar=True)
    dto_cfg = _configuracao_service(cfg)
    
    # Resolve os relatórios sem executar tarefas mutáveis no SO
    try:
        st_onb = obter_status_onboarding(dto_cfg)
    except Exception as e:
        logger.exception("Falha ao determinar a etapa inicial do onboarding.")
        st_onb = {"erro": "Falha na análise do ambiente.", "mensagem": str(e)}

    try:
        plano = obter_plano_instalacao(dto_cfg)
    except Exception as e:
        logger.exception("Falha na formatação preditiva do plano de implantação.")
        plano = {"erro": "Falha na construção do plano de ação.", "bloqueios": [str(e)]}

    context = {
        "configuracao_suricata": _serializar_configuracao(cfg),
        "status_onboarding": st_onb,
        "plano_instalacao": plano,
        "pagina_suricata": True,
        "titulo_pagina": "Instalação do Suricata",
    }
    
    return render(request, "incidentes/suricata/onboarding.html", context)


@login_required(login_url="autenticacao:login")
@require_GET
def painel_suricata(request):
    """Cockpit final de gerenciamento day-to-day do Sensor e Regras."""
    cfg = _obter_configuracao_ativa(criar=False)
    
    if not cfg or not cfg.onboarding_concluido:
        # Nota: A view "suricata_onboarding" precisa estar mapeada no urls.py
        return redirect("incidentes:suricata_onboarding")
        
    dto_cfg = _configuracao_service(cfg)
    
    try:
        st_stack = obter_status_stack_completo(dto_cfg, incluir_diagnostico=False)
        cards = obter_resumo_cards(dto_cfg)
    except Exception:
        logger.exception("Falha ao ler status da Stack.")
        st_stack = {}
        cards = {}

    context = {
        "configuracao_suricata": _serializar_configuracao(cfg),
        "status_stack": st_stack,
        "cards_suricata": cards,
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
    """Consulta consolidada leve (AJAX Fetch/Poll)."""
    cfg = _obter_configuracao_ativa(criar=False)
    dto_cfg = _configuracao_service(cfg)
    
    inc_diag = request.GET.get("diagnostico") == "1"
    
    payload = obter_status_para_api(dto_cfg, incluir_diagnostico=inc_diag)
    if payload.get("ok"):
        return _json_sucesso("Status obtido.", payload.get("dados"))
    
    return _json_erro(payload.get("mensagem", "Erro"), 500, dados=payload)


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
        
        return _json_sucesso("Status Onboarding lido.", {
            "configuracao": _serializar_configuracao(cfg),
            "status_onboarding": onb,
            "plano_instalacao": plano,
            "tarefas_disponiveis": tipos_disp,
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
    """Aciona o Doctor Healthcheck com todos os módulos (Deep Scan)."""
    cfg = _obter_configuracao_ativa(criar=False)
    dto_cfg = _configuracao_service(cfg)
    
    try:
        diag = executar_diagnostico(dto_cfg)
        from .services.suricata.diagnostico import executar_diagnostico_resumido, obter_acoes_recomendadas
        resumo = executar_diagnostico_resumido(dto_cfg)
        acoes = obter_acoes_recomendadas(diag)
        
        return _json_sucesso("Healthcheck finalizado.", {
            "diagnostico": diag.to_dict(),
            "resumo": resumo,
            "acoes_recomendadas": acoes
        })
    except Exception as e:
        logger.exception("Crash do módulo diagnóstico HTTP.")
        return _json_erro("Colapso durante checagem de saúde.", 500, [str(e)])


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
    """Libera o lock do painel de setup, promovendo a máquina a um Sensor Vivo operante."""
    cfg = _obter_configuracao_ativa(criar=False)
    if not cfg:
         return _json_erro("Mestre em branco. Onboarding não executado.")

    dto_cfg = _configuracao_service(cfg)
    st = obter_status_stack_completo(dto_cfg, incluir_diagnostico=False)

    if not st.get("stack_pronta"):
        erros_b = st.get("erros", [])
        return _json_erro(
            "Finalização vetada: Cluster não preenche os pré-requisitos essenciais.",
            status_http=409,
            erros=erros_b if erros_b else ["Falta de integridade em dependências do Daemon Suricata."]
        )

    try:
        with transaction.atomic():
            cfg.onboarding_concluido = True
            
            s_suri = st.get("suricata", {})
            cfg.suricata_instalado = s_suri.get("instalado", False)
            cfg.versao_suricata = s_suri.get("versao", "")
            cfg.suricata_configurado = s_suri.get("configurado", False)
            
            if st.get("saudavel"):
                cfg.instalacao_concluida = True
                
            cfg.atualizar_status(status=st, salvar=True)

        return _json_sucesso("Assistente dispensado e plataforma empossada.", _serializar_configuracao(cfg))
    except Exception as e:
        logger.exception("Incompatibilidade ao fechar os locks de onboarding.")
        return _json_erro("Falha inesperada ao selar a base de dados.", 500, [str(e)])


@login_required(login_url="autenticacao:login")
@require_POST
@csrf_protect
def api_reabrir_onboarding(request):
    """Devolve a navegação para o Modo Assistente. (Apenas flag, sem destruir sistema instalado)."""
    cfg = _obter_configuracao_ativa(criar=False)
    if not cfg:
        return _json_erro("Nenhuma configuração local ativa presente no ambiente.")

    try:
        with transaction.atomic():
            cfg.onboarding_concluido = False
            cfg.save(update_fields=["onboarding_concluido", "atualizado_em"])
            
        return _json_sucesso("Cockpit trancado. Assistente recuado com sucesso.", _serializar_configuracao(cfg))
    except Exception as e:
        logger.exception("Atrito ao destravar lock de assistente.")
        return _json_erro("Trava de base de dados impediu downgrade de Onboarding.", 500, [str(e)])