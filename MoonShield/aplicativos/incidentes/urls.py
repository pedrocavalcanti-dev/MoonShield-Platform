from django.urls import path

from . import views
from .receptor.consumidor import receber_eventos


app_name = "incidentes"


urlpatterns = [
    # ── Páginas HTML ─────────────────────────────────────────────────────────
    path("", views.incidentes_view, name="painel"),

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

    # ── APIs JSON ─────────────────────────────────────────────────────────────
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

    # ── APIs de contexto por IP ──────────────────────────────────────────────
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

    # ── Ingestão de sensores ─────────────────────────────────────────────────
    path(
        "api/ingest/",
        receber_eventos,
        name="api_ingest",
    ),

    # ── Configurações e ações auxiliares ─────────────────────────────────────
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

    # ── Status do Suricata Local ─────────────────────────────────────────────
    path(
        "api/status-suricata/",
        views.api_status_suricata,
        name="api_status_suricata",
    ),
]