from django.urls import path

from . import views


app_name = "configuracoes"


urlpatterns = [
    # ============================================================
    # PÁGINA PRINCIPAL
    # ============================================================
    path(
        "",
        views.configuracoes_view,
        name="index",
    ),

    # ============================================================
    # CONFIGURAÇÃO GERAL
    # ============================================================
    path(
        "api/config/",
        views.api_get_config,
        name="api_config",
    ),
    path(
        "api/salvar/",
        views.api_salvar_config,
        name="api_salvar",
    ),

    # ============================================================
    # SERVIÇOS — NOVA ARQUITETURA
    #
    # Fonte principal para:
    # - AdGuard
    # - Suricata
    # - Firewall
    # ============================================================
    path(
        "api/servicos/",
        views.api_servicos,
        name="api_servicos",
    ),

    # ============================================================
    # SISTEMA / INFRAESTRUTURA
    # ============================================================
    path(
        "api/sysinfo/",
        views.api_sysinfo,
        name="api_sysinfo",
    ),
    path(
        "api/interfaces/",
        views.api_interfaces,
        name="api_interfaces",
    ),
    path(
        "api/auto-discover/",
        views.api_auto_discover,
        name="api_auto_discover",
    ),

    # ============================================================
    # TESTES RÁPIDOS
    #
    # ?test=ping
    # ?test=dns
    # ?test=latency
    # ?test=internet
    # ============================================================
    path(
        "api/quick-test/",
        views.api_quick_test,
        name="api_quick_test",
    ),

    # ============================================================
    # TESTE DE SERVIÇO / PROVIDER
    #
    # Compatibilidade temporária com o frontend atual.
    #
    # dns -> AdGuard real
    # ids -> estado local do Suricata
    # fw  -> placeholder nftables
    # ============================================================
    path(
        "api/testar-provider/",
        views.api_testar_provider,
        name="api_testar_provider",
    ),

    # ============================================================
    # COMPATIBILIDADE LEGADA — SENSORES IDS
    #
    # Não é mais utilizado como health da stack local Suricata.
    # Mantido enquanto o frontend antigo ainda depender da rota.
    # ============================================================
    path(
        "api/sensor-status/",
        views.api_sensor_status,
        name="api_sensor_status",
    ),

    # ============================================================
    # COMPATIBILIDADE LEGADA — FIREWALL
    #
    # Endpoint mantido temporariamente.
    # A nova arquitetura utilizará nftables local.
    # ============================================================
    path(
        "api/fw-sensor-status/",
        views.api_fw_sensor_status,
        name="api_fw_sensor_status",
    ),

    # ============================================================
    # COMPATIBILIDADE LEGADA — AGENTE FIREWALL
    #
    # A view atual é somente um stub de compatibilidade.
    # Não acessa mais Flask / :8765.
    # ============================================================
    path(
        "api/testar-agente/",
        views.api_testar_agente,
        name="api_testar_agente",
    ),
]