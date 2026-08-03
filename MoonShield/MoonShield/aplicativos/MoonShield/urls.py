from django.urls import path
from . import views

app_name = 'MoonShield'

urlpatterns = [
    # Rota raiz do aplicativo MoonShieldai que aponta para a view
    path('', views.moonai_view, name='painel'),
]