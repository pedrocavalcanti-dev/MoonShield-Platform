from django.urls import path
from . import views
from .receptor.consumidor import receber_eventos

app_name = 'firewall'

urlpatterns = [
    # ── Páginas HTML (Frontend) ───────────────────────────────────────────────
    path('', views.firewall_view, name='painel'),
    path('feed/', views.feed_view, name='feed'),
    path('regras/', views.regras_view, name='regras'),

    # ── API: Leitura de Dados e Feed ──────────────────────────────────────────
    path('api/data/', views.api_fw_data, name='api_data'),
    path('api/feed/', views.api_fw_feed, name='api_feed'),
    path('api/interfaces/', views.api_interfaces, name='api_interfaces'),

    # ── API: Ações Rápidas e Integrações ──────────────────────────────────────
    path('api/bloqueio-rapido/', views.api_bloqueio_rapido, name='api_bloqueio_rapido'),
    path('api/autoban/', views.api_autoban, name='api_autoban'),

    # ── API: Ingestão do Sensor nftables ──────────────────────────────────────
    path('api/ingest/', receber_eventos, name='api_ingest'),

    # ── API: Sincronização de Regras ──────────────────────────────────────────
    path('api/push-rules/', views.api_push_rules, name='api_push_rules'),
    path('api/pending-rules/', views.api_pending_rules, name='api_pending_rules'),
    path('api/confirm-rules/', views.api_confirm_rules, name='api_confirm_rules'),

    # ── API: Exportação ───────────────────────────────────────────────────────
    path('api/export-nft/', views.api_export_nft, name='api_export_nft'),

    # ── API: CRUD Regras e Tabelas ────────────────────────────────────────────
    path('api/rules/', views.api_rules, name='api_rules'),
    path('api/rules/<int:rule_id>/', views.api_rule_detail, name='api_rule_detail'),

    path('api/nat/', views.api_nat, name='api_nat'),
    path('api/nat/<int:nat_id>/', views.api_nat_detail, name='api_nat_detail'),

    path('api/blocklist/', views.api_blocklist, name='api_blocklist'),
    path('api/blocklist/<int:entry_id>/', views.api_blocklist_detail, name='api_blocklist_detail'),

    path('api/allowlist/', views.api_allowlist, name='api_allowlist'),
    path('api/allowlist/<int:entry_id>/', views.api_allowlist_detail, name='api_allowlist_detail'),

    path('api/geoblock/', views.api_geoblock, name='api_geoblock'),
    path('api/geoblock/<int:entry_id>/', views.api_geoblock_detail, name='api_geoblock_detail'),
]