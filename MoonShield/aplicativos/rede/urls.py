from django.urls import include, path

from . import views


app_name = "rede"


urlpatterns = [
    # Painel principal de Rede
    path("", views.painel_rede, name="painel"),

    # APIs do módulo de Rede
    path("api/", include("rede.api.urls")),
]