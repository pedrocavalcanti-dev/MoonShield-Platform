from django.shortcuts import render
from django.contrib.auth.decorators import login_required

# View para a página principal de Relatórios
@login_required
def index(request):
    contexto = {
        'titulo': 'Relatórios do Sistema'
    }
    return render(request, 'relatorios/relatorios.html', contexto)

# Nova View para a página de Diagnóstico & Testes (Ping, etc.)
@login_required
def diagnostico(request):
    contexto = {
        'titulo': 'Diagnóstico e Testes de Rede'
    }
    return render(request, 'relatorios/diagnostico.html', contexto)