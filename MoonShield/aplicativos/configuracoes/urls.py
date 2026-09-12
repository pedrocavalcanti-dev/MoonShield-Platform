from django.urls import path

from . import views


app_name = "configuracoes"


urlpatterns = [
    path("", views.configuracoes_view, name="index"),
    path("api/config/", views.api_get_config, name="api_config"),
    path("api/salvar/", views.api_salvar_config, name="api_salvar"),
    path("api/servicos/", views.api_servicos, name="api_servicos"),
    path("api/sysinfo/", views.api_sysinfo, name="api_sysinfo"),
    path("api/quick-test/", views.api_quick_test, name="api_quick_test"),
]
