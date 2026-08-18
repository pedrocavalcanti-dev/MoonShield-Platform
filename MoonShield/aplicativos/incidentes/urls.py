from django.urls import path

from . import views
from . import views_suricata
from .receptor.consumidor import receber_eventos


app_name = "incidentes"


urlpatterns = [
    # =========================================================================
    # PÁGINAS — INCIDENTES
    # =========================================================================

    path(
        "",
        views.incidentes_view,
        name="painel",
    ),

    path(
        "sensores/",
        views.painel_sensores,
        name="painel_sensores",
    ),

    path(
        "investigar/<str:ip>/",
        views.investigacao_view,
        name="investigar",
    ),

    path(
        "<int:incidente_id>/",
        views.incidente_detalhe_view,
        name="detalhe",
    ),

    # =========================================================================
    # APIs — INCIDENTES
    # =========================================================================

    path(
        "api/data/",
        views.api_incidentes_data,
        name="api_data",
    ),

    path(
        "api/stats/",
        views.api_estatisticas,
        name="api_stats",
    ),

    path(
        "api/<int:incidente_id>/",
        views.api_incidente_detalhe,
        name="api_detalhe",
    ),

    path(
        "api/<int:incidente_id>/status/",
        views.api_atualizar_status,
        name="api_status",
    ),

    # =========================================================================
    # APIs — CONTEXTO POR IP
    # =========================================================================

    path(
        "api/ip/<str:ip>/contexto/",
        views.api_contexto_ip,
        name="api_contexto_ip",
    ),

    path(
        "api/ip/<str:ip>/timeline/",
        views.api_timeline_ip,
        name="api_timeline_ip",
    ),

    # =========================================================================
    # INGESTÃO DE EVENTOS
    # =========================================================================

    path(
        "api/ingest/",
        receber_eventos,
        name="api_ingest",
    ),

    # =========================================================================
    # CONFIGURAÇÕES AUXILIARES
    # =========================================================================

    path(
        "api/preset/salvar/",
        views.api_salvar_preset,
        name="api_salvar_preset",
    ),

    path(
        "api/supressao/",
        views.api_criar_supressao,
        name="api_supressao",
    ),

    # =========================================================================
    # COMPATIBILIDADE LEGADA — SURICATA
    # =========================================================================

    path(
        "api/status-suricata/",
        views.api_status_suricata,
        name="api_status_suricata",
    ),

    # =========================================================================
    # SURICATA — PÁGINAS
    # =========================================================================

    path(
        "suricata/",
        views_suricata.painel_suricata,
        name="suricata_painel",
    ),

    path(
        "suricata/instalacao/",
        views_suricata.onboarding_suricata,
        name="suricata_onboarding",
    ),

    # =========================================================================
    # SURICATA — STATUS / LEITURA
    # =========================================================================

    path(
        "api/suricata/status/",
        views_suricata.api_status_suricata,
        name="api_suricata_status",
    ),

    path(
        "api/suricata/onboarding/status/",
        views_suricata.api_onboarding_status,
        name="api_suricata_onboarding_status",
    ),

    path(
        "api/suricata/interfaces/detectar/",
        views_suricata.api_detectar_interfaces,
        name="api_suricata_detectar_interfaces",
    ),

    path(
        "api/suricata/diagnostico/",
        views_suricata.api_diagnostico_suricata,
        name="api_suricata_diagnostico",
    ),

    # =========================================================================
    # SURICATA — CONFIGURAÇÃO
    # =========================================================================

    path(
        "api/suricata/configuracao/salvar/",
        views_suricata.api_salvar_configuracao,
        name="api_suricata_salvar_configuracao",
    ),

    path(
        "api/suricata/onboarding/concluir/",
        views_suricata.api_marcar_onboarding_concluido,
        name="api_suricata_concluir_onboarding",
    ),

    path(
        "api/suricata/onboarding/reabrir/",
        views_suricata.api_reabrir_onboarding,
        name="api_suricata_reabrir_onboarding",
    ),

    # =========================================================================
    # SURICATA — TAREFAS
    # =========================================================================

    path(
        "api/suricata/tarefas/",
        views_suricata.api_listar_tarefas,
        name="api_suricata_listar_tarefas",
    ),

    path(
        "api/suricata/tarefas/criar/",
        views_suricata.api_criar_tarefa,
        name="api_suricata_criar_tarefa",
    ),

    path(
        "api/suricata/tarefas/<str:tarefa_id>/",
        views_suricata.api_detalhe_tarefa,
        name="api_suricata_detalhe_tarefa",
    ),

    path(
        "api/suricata/tarefas/<str:tarefa_id>/executar/",
        views_suricata.api_executar_tarefa_sincrona,
        name="api_suricata_executar_tarefa",
    ),

    path(
        "api/suricata/tarefas/<str:tarefa_id>/cancelar/",
        views_suricata.api_solicitar_cancelamento,
        name="api_suricata_cancelar_tarefa",
    ),

    path(
        "api/suricata/tarefas/<str:tarefa_id>/logs/",
        views_suricata.api_logs_tarefa,
        name="api_suricata_logs_tarefa",
    ),
]