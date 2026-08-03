from django.urls import path
from . import views

app_name = "painel"

urlpatterns = [
    path("",                   views.index,             name="index"),
    path("api/overview/",      views.api_overview,      name="api_overview"),
    # As rotas abaixo também ficam aqui como fallback com prefixo /painel/
    path("api/sensores/",      views.api_sensores,      name="api_sensores"),
    path("api/badges/",        views.api_badges,        name="api_badges"),
    path("api/uptime/",        views.api_uptime,        name="api_uptime"),
    path("api/alertas/",       views.api_alertas,       name="api_alertas"),
    path("api/alertas/count/", views.api_alertas_count, name="api_alertas_count"),
]