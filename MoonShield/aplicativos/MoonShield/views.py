from django.http import HttpResponse
from django.template.loader import render_to_string

def custom_400(request, exception=None):
    return HttpResponse(render_to_string('errors/400.html'), status=400)

def custom_403(request, exception=None):
    return HttpResponse(render_to_string('errors/403.html'), status=403)

def custom_404(request, exception=None):
    return HttpResponse(render_to_string('errors/404.html'), status=404)

def custom_500(request):
    return HttpResponse(render_to_string('errors/500.html'), status=500)

from django.contrib.auth.decorators import login_required

@login_required(login_url='autenticacao:login')
def moonai_view(request):
    return render(request, 'MoonShieldai/MoonShieldai.html')
