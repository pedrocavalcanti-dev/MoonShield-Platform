"""
dns/urls.py — MoonShield
"""
from django.urls import path
from . import views

app_name = 'dns'

urlpatterns = [
    # ── Páginas ───────────────────────────────────────────────────────────
    path('',         views.dns_view,    name='painel'),
    path('feed/',    views.feed_view,   name='feed'),
    path('regras/',  views.regras_view, name='regras'),

    # ── API dados / querylog ──────────────────────────────────────────────
    path('api/data/',      views.api_dns_data, name='api_data'),
    path('api/querylog/',  views.api_querylog, name='api_querylog'),

    # ── API ações rápidas ─────────────────────────────────────────────────
    path('api/block/',          views.api_block_domain,   name='api_block'),
    path('api/allow/',          views.api_allow_domain,   name='api_allow'),
    path('api/flush/',          views.api_flush_cache,    name='api_flush'),
    path('api/update-filters/', views.api_update_filters, name='api_update_filters'),

    # ── API regras customizadas ───────────────────────────────────────────
    path('api/regras/',        views.api_regras_list,   name='api_regras_list'),
    path('api/regras/salvar/', views.api_regras_salvar, name='api_regras_salvar'),
]