"""
MoonShield Platform — Firewall / URLs
=====================================

Rotas da arquitetura local do Firewall.

Removidos da arquitetura nova:
- /api/ingest/
- /api/autoban/
- /api/pending-rules/
- /api/confirm-rules/

O MoonShield-Agent não chama mais o Django por HTTP.
A comunicação Django -> Agent ocorre exclusivamente por Unix Socket.
"""

from django.urls import path

from . import views


app_name = "firewall"


urlpatterns = [
    # =========================================================================
    # PÁGINAS
    # =========================================================================
    path(
        "",
        views.firewall_view,
        name="painel",
    ),
    path(
        "feed/",
        views.feed_view,
        name="feed",
    ),
    path(
        "regras/",
        views.regras_view,
        name="regras",
    ),
    path(
        "instalacao/",
        views.instalacao_view,
        name="instalacao",
    ),

    # =========================================================================
    # API — DASHBOARD / LEITURA
    # =========================================================================
    path(
        "api/data/",
        views.api_fw_data,
        name="api_data",
    ),
    path(
        "api/feed/",
        views.api_fw_feed,
        name="api_feed",
    ),
    path(
        "api/status/",
        views.api_status,
        name="api_status",
    ),
    path(
        "api/diagnostico/",
        views.api_diagnostico,
        name="api_diagnostico",
    ),
    path(
        "api/interfaces/",
        views.api_interfaces,
        name="api_interfaces",
    ),

    # =========================================================================
    # API — INSTALAÇÃO / MANUTENÇÃO
    # =========================================================================
    path(
        "api/install/",
        views.api_install,
        name="api_install",
    ),
    path(
        "api/repair/",
        views.api_repair,
        name="api_repair",
    ),
    path(
        "api/uninstall/",
        views.api_uninstall,
        name="api_uninstall",
    ),
    path(
        "api/rollback/",
        views.api_rollback,
        name="api_rollback",
    ),

    # =========================================================================
    # API — TAREFAS
    # =========================================================================
    path(
        "api/tasks/",
        views.api_tasks,
        name="api_tasks",
    ),
    path(
        "api/tasks/<int:task_id>/",
        views.api_task_detail,
        name="api_task_detail",
    ),

    # =========================================================================
    # API — REGRAS
    # =========================================================================
    path(
        "api/rules/",
        views.api_rules,
        name="api_rules",
    ),
    path(
        "api/rules/<int:rule_id>/",
        views.api_rule_detail,
        name="api_rule_detail",
    ),
    path(
        "api/rules/apply/",
        views.api_apply_rules,
        name="api_apply_rules",
    ),

    # Compatibilidade temporária com frontend antigo.
    path(
        "api/push-rules/",
        views.api_push_rules,
        name="api_push_rules",
    ),

    # =========================================================================
    # API — BLOQUEIO LOCAL / EMERGÊNCIA
    # =========================================================================
    path(
        "api/block/",
        views.api_block,
        name="api_block",
    ),
    path(
        "api/unblock/",
        views.api_unblock,
        name="api_unblock",
    ),

    # Compatibilidade temporária com o frontend atual.
    path(
        "api/bloqueio-rapido/",
        views.api_bloqueio_rapido,
        name="api_bloqueio_rapido",
    ),

    # =========================================================================
    # API — EXPORTAÇÃO / DIAGNÓSTICO
    # =========================================================================
    path(
        "api/export-nft/",
        views.api_export_nft,
        name="api_export_nft",
    ),

    # =========================================================================
    # API — NAT
    # =========================================================================
    path(
        "api/nat/",
        views.api_nat,
        name="api_nat",
    ),
    path(
        "api/nat/<int:nat_id>/",
        views.api_nat_detail,
        name="api_nat_detail",
    ),

    # =========================================================================
    # API — BLOCKLIST
    # =========================================================================
    path(
        "api/blocklist/",
        views.api_blocklist,
        name="api_blocklist",
    ),
    path(
        "api/blocklist/<int:entry_id>/",
        views.api_blocklist_detail,
        name="api_blocklist_detail",
    ),

    # =========================================================================
    # API — ALLOWLIST
    # =========================================================================
    path(
        "api/allowlist/",
        views.api_allowlist,
        name="api_allowlist",
    ),
    path(
        "api/allowlist/<int:entry_id>/",
        views.api_allowlist_detail,
        name="api_allowlist_detail",
    ),

    # =========================================================================
    # API — GEOBLOCK
    # =========================================================================
    path(
        "api/geoblock/",
        views.api_geoblock,
        name="api_geoblock",
    ),
    path(
        "api/geoblock/<int:entry_id>/",
        views.api_geoblock_detail,
        name="api_geoblock_detail",
    ),
]