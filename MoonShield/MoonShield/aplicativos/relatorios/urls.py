from django.urls import path
from . import views

app_name = 'relatorios'

urlpatterns = [
    # Rota: /relatorios/
    path('', views.index, name='index'),
    
    # Rota: /relatorios/diagnostico/
    path('diagnostico/', views.diagnostico, name='diagnostico'),
]