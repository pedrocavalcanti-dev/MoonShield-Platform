from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.shortcuts import redirect
from django.urls import include, path

# APIs globais do painel
from painel.views import (
    api_alertas,
    api_alertas_count,
    api_badges,
    api_sensores,
    api_uptime,
)


urlpatterns = [
    # =========================================================================
    # DJANGO ADMIN
    # =========================================================================

    path(
        "admin/",
        admin.site.urls,
    ),


    # =========================================================================
    # AUTENTICAÇÃO
    # =========================================================================

    path(
        "auth/",
        include("autenticacao.urls"),
    ),


    # =========================================================================
    # PAINEL PRINCIPAL
    # =========================================================================

    path(
        "painel/",
        include("painel.urls"),
    ),


    # =========================================================================
    # APIs GLOBAIS
    # =========================================================================

    path(
        "api/sensores/",
        api_sensores,
        name="api_sensores_global",
    ),

    path(
        "api/badges/",
        api_badges,
        name="api_badges_global",
    ),

    path(
        "api/uptime/",
        api_uptime,
        name="api_uptime_global",
    ),

    path(
        "api/alertas/",
        api_alertas,
        name="api_alertas_global",
    ),

    path(
        "api/alertas/count/",
        api_alertas_count,
        name="api_alertas_count_global",
    ),


    # =========================================================================
    # MAPA DE AMEAÇAS
    # =========================================================================

    path(
        "mapa/",
        include("mapa_ameacas.urls"),
    ),


    # =========================================================================
    # INCIDENTES / SOC / SURICATA
    # =========================================================================

    path(
        "incidentes/",
        include("incidentes.urls"),
    ),


    # =========================================================================
    # REDE
    # =========================================================================

    path(
        "rede/",
        include("rede.urls"),
    ),


    # =========================================================================
    # DNS
    # =========================================================================

    path(
        "dns/",
        include("dns.urls"),
    ),


    # =========================================================================
    # FIREWALL
    # =========================================================================

    path(
        "firewall/",
        include("firewall.urls"),
    ),


    # =========================================================================
    # DISPOSITIVOS
    # =========================================================================

    path(
        "dispositivos/",
        include("dispositivos.urls"),
    ),


    # =========================================================================
    # MOONSHIELD AI
    # =========================================================================

    path(
        "moonai/",
        include("MoonShield.urls"),
    ),


    # =========================================================================
    # RELATÓRIOS
    # =========================================================================

    path(
        "relatorios/",
        include("relatorios.urls"),
    ),


    # =========================================================================
    # CONFIGURAÇÕES
    # =========================================================================

    path(
        "configuracoes/",
        include("configuracoes.urls"),
    ),


    # =========================================================================
    # RAIZ
    # =========================================================================

    path(
        "",
        lambda request: redirect(
            "auth/login/",
            permanent=False,
        ),
    ),
]


# =============================================================================
# MEDIA — DESENVOLVIMENTO
# =============================================================================

if settings.DEBUG:
    urlpatterns += static(
        settings.MEDIA_URL,
        document_root=settings.MEDIA_ROOT,
    )