from django.urls import path
from . import views

app_name = 'mapa_ameacas'

urlpatterns = [
    path('', views.mapa_view, name='mapa'),
    path('api/overview/', views.api_map_overview, name='api_map_overview'),
]