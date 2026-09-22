from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.views.decorators.csrf import ensure_csrf_cookie


@ensure_csrf_cookie
@login_required(login_url="autenticacao:login")
def dispositivos_view(request):
    return render(request, "dispositivos/dispositivos.html")
