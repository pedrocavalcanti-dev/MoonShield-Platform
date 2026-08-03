"""
aplicativos/autenticacao/context_processors.py

Substitui as duas funções antigas (user_profile_ctx + user_prefs) por uma só.

Registrar em settings.py → TEMPLATES[0]['OPTIONS']['context_processors']:
    'aplicativos.autenticacao.context_processors.user_profile_ctx',
"""

from .models import UserProfile


def user_profile_ctx(request):
    """
    Disponibiliza em todos os templates:
      - user_profile       → instância de UserProfile (ou None)
      - sidebar_collapsed  → bool ('collapsed' ou '') para o data-sidebar do <html>
    """
    if not request.user.is_authenticated:
        return {
            "user_profile":      None,
            "sidebar_collapsed": False,
        }

    try:
        profile, _ = UserProfile.objects.get_or_create(user=request.user)
        return {
            "user_profile":      profile,
            "sidebar_collapsed": profile.sidebar_collapsed,
        }
    except Exception:
        return {
            "user_profile":      None,
            "sidebar_collapsed": False,
        }