from django.urls import path
from . import views

app_name = 'relatorios'

urlpatterns = [
    # Rota: /relatorios/
    path('', views.index, name='index'),

    # Rota: /relatorios/diagnostico/
    path('diagnostico/', views.diagnostico, name='diagnostico'),

    # APIs de Diagnostico
    path('diagnostico/api/contexto/', views.diagnostico_contexto_api, name='api_contexto'),
    path('diagnostico/api/executar/', views.diagnostico_executar_api, name='api_executar'),
    path('diagnostico/api/historico/', views.diagnostico_historico_api, name='api_historico'),
    path('diagnostico/api/execucao/<uuid:execucao_id>/', views.diagnostico_execucao_api, name='api_execucao'),
    path('diagnostico/api/live/iniciar/', views.diagnostico_live_start_api, name='api_live_start'),
    path('diagnostico/api/live/<uuid:session_id>/', views.diagnostico_live_status_api, name='api_live_status'),
    path('diagnostico/api/live/<uuid:session_id>/parar/', views.diagnostico_live_stop_api, name='api_live_stop'),
]
