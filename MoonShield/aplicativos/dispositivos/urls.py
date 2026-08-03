from django.urls import path, include
from . import views

app_name = 'dispositivos'

urlpatterns = [
    # A sua página HTML principal
    path('', views.dispositivos_view, name='dispositivos_view'), 
    
    # Nossa "via expressa" para os dados reais (API)
    path('api/', include('aplicativos.dispositivos.api_urls')),
]