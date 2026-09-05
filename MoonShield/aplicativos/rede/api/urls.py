from django.urls import path

from . import alteracoes, diagnostico, interfaces, nat, roteamento, status, topologia


app_name = "rede_api"


urlpatterns = [
    # -------------------------------------------------------------------------
    # Status geral
    # -------------------------------------------------------------------------
    path("status/", status.api_status_rede, name="status"),

    # -------------------------------------------------------------------------
    # Topologia
    # -------------------------------------------------------------------------
    path("topologia/", topologia.api_topologia, name="topologia"),

    # -------------------------------------------------------------------------
    # Interfaces
    # -------------------------------------------------------------------------
    path("interfaces/", interfaces.api_interfaces, name="interfaces"),
    path("interfaces/detectar/", interfaces.api_interfaces_detectar, name="interfaces_detectar"),
    path("interfaces/<int:interface_id>/", interfaces.api_interface_detalhe, name="interface_detalhe"),
    path("interfaces/<int:interface_id>/configurar/", interfaces.api_interface_configurar, name="interface_configurar"),
    path("interfaces/<int:interface_id>/aplicar/", interfaces.api_interface_aplicar, name="interface_aplicar"),

    # -------------------------------------------------------------------------
    # Roteamento
    # -------------------------------------------------------------------------
    path("roteamento/", roteamento.api_roteamento, name="roteamento"),
    path("roteamento/real/", roteamento.api_roteamento_real, name="roteamento_real"),
    path("roteamento/configurar/", roteamento.api_roteamento_configurar, name="roteamento_configurar"),
    path("roteamento/rotas/", roteamento.api_rotas, name="rotas"),
    path("roteamento/rotas/<int:rota_id>/", roteamento.api_rota_detalhe, name="rota_detalhe"),
    path("roteamento/aplicar/", roteamento.api_roteamento_aplicar, name="roteamento_aplicar"),

    # -------------------------------------------------------------------------
    # NAT
    # -------------------------------------------------------------------------
    path("nat/", nat.api_nat, name="nat"),
    path("nat/real/", nat.api_nat_real, name="nat_real"),
    path("nat/aplicar/", nat.api_nat_aplicar, name="nat_aplicar"),
    path("nat/<int:regra_id>/", nat.api_nat_detalhe, name="nat_detalhe"),

    # -------------------------------------------------------------------------
    # Diagnóstico
    # -------------------------------------------------------------------------
    path("diagnostico/", diagnostico.api_diagnostico, name="diagnostico"),

    # -------------------------------------------------------------------------
    # Alterações / Safe Apply
    # -------------------------------------------------------------------------
    path("alteracoes/", alteracoes.api_alteracoes, name="alteracoes"),
    path("alteracoes/reconciliar/", alteracoes.api_alteracoes_reconciliar, name="alteracoes_reconciliar"),
    path("alteracoes/aplicar-tudo/", alteracoes.api_aplicar_tudo, name="aplicar_tudo"),
    path("alteracoes/<uuid:alteracao_id>/", alteracoes.api_alteracao_detalhe, name="alteracao_detalhe"),
    path("alteracoes/<uuid:alteracao_id>/confirmar/", alteracoes.api_alteracao_confirmar, name="alteracao_confirmar"),
    path("alteracoes/<uuid:alteracao_id>/rollback/", alteracoes.api_alteracao_rollback, name="alteracao_rollback"),
    path("alteracoes/<uuid:alteracao_id>/cancelar/", alteracoes.api_alteracao_cancelar, name="alteracao_cancelar"),
    path("alteracoes/<uuid:alteracao_id>/status-agent/", alteracoes.api_alteracao_status_agent, name="alteracao_status_agent"),
]
