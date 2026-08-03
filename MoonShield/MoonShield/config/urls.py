from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect
from django.conf import settings
from django.conf.urls.static import static

# Importa todas as views de API global diretamente do app painel
from painel.views import (
    api_sensores,
    api_badges,
    api_uptime,
    api_alertas,
    api_alertas_count,
)

urlpatterns = [
    path('admin/', admin.site.urls),

    # Autenticação
    path('auth/', include('autenticacao.urls')),

    # Painel principal
    path('painel/', include('painel.urls')),

    # ── Rotas /api/* globais ─────────────────────────────────────────────────
    path('api/sensores/',      api_sensores,      name='api_sensores_global'),
    path('api/badges/',        api_badges,        name='api_badges_global'),
    path('api/uptime/',        api_uptime,        name='api_uptime_global'),
    path('api/alertas/',       api_alertas,       name='api_alertas_global'),
    path('api/alertas/count/', api_alertas_count, name='api_alertas_count_global'),

    # Mapa de Ameaças
    path('mapa/', include('mapa_ameacas.urls')),

    # Incidentes (SOC)
    path('incidentes/', include('incidentes.urls')),

    # DNS & Rede (AdGuard)
    path('dns/', include('dns.urls')),

    # Firewall
    path('firewall/', include('firewall.urls')),

    # Dispositivos
    path('dispositivos/', include('dispositivos.urls')),

    # MoonShield AI  ← era: Moon AI
    path('moonai/', include('MoonShield.urls')),

    # Relatórios
    path('relatorios/', include('relatorios.urls')),

    # Configurações
    path('configuracoes/', include('configuracoes.urls')),

    # Redireciona raiz para login
    path('', lambda request: redirect('auth/login/', permanent=False)),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)