from django.shortcuts import render
from django.contrib.auth.decorators import login_required

@login_required(login_url='autenticacao:login')
def dispositivos_view(request):
    return render(request, 'dispositivos/dispositivos.html')