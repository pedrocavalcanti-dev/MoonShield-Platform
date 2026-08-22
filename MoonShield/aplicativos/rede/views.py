from django.contrib.auth.decorators import login_required
from django.shortcuts import render


@login_required
def painel_rede(request):
    """
    Painel principal de gerenciamento de rede do MoonShield.

    A view não consulta diretamente o sistema operacional, NetworkManager,
    nftables ou MoonShield Agent. Todo estado operacional é carregado pelo
    frontend através das APIs do módulo de Rede.
    """

    context = {
        "modulo_atual": "rede",
        "pagina_atual": "visao-geral",
        "titulo_pagina": "Rede",
    }

    return render(request, "rede/painel.html", context)