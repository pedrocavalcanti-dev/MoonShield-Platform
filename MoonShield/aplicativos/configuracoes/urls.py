from django.urls import path
from . import views

app_name = "configuracoes"

urlpatterns = [
    # Página principal
    path("", views.configuracoes_view, name="index"),

    # APIs REST
    path("api/config/",          views.api_get_config,      name="api_config"),
    path("api/salvar/",          views.api_salvar_config,   name="api_salvar"),
    path("api/sysinfo/",         views.api_sysinfo,         name="api_sysinfo"),
    path("api/interfaces/",      views.api_interfaces,      name="api_interfaces"),
    path("api/auto-discover/",   views.api_auto_discover,   name="api_auto_discover"),
    path("api/testar-provider/", views.api_testar_provider, name="api_testar_provider"),

    # Quick Tests — testes reais de rede (?test=ping|dns|latency|internet)
    path("api/quick-test/",      views.api_quick_test,      name="api_quick_test"),

    # Status dos sensores IDS (Suricata)
    path("api/sensor-status/",    views.api_sensor_status,    name="api_sensor_status"),

    # Status dos sensores Firewall (nftables)
    path("api/fw-sensor-status/", views.api_fw_sensor_status, name="api_fw_sensor_status"),
    path('api/testar-agente/', views.api_testar_agente, name='api_testar_agente'),

]