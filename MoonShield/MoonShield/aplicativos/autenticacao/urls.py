from django.urls import path
from . import views

app_name = "autenticacao"

urlpatterns = [
    # ── Auth ──────────────────────────────────────────────────────────────────
    path("login/",           views.login_view,   name="login"),
    path("logout/",          views.logout_view,  name="logout"),
    path("recuperar-senha/", views.login_view,   name="password_reset"),

    # ── Perfil ────────────────────────────────────────────────────────────────
    path("perfil/",          views.perfil_view,  name="perfil"),

    # ── APIs do perfil ────────────────────────────────────────────────────────
    path("api/perfil/salvar/",           views.api_salvar_perfil,    name="api_salvar_perfil"),
    path("api/perfil/foto/",             views.api_upload_avatar,    name="api_upload_avatar"),
    path("api/perfil/senha/",            views.api_trocar_senha,     name="api_trocar_senha"),
    path("api/perfil/regen-key/",        views.api_regen_api_key,    name="api_regen_api_key"),
    path("api/perfil/prefs/",            views.api_salvar_prefs,     name="api_salvar_prefs"),
    path("api/perfil/sysinfo/",          views.api_sysinfo,          name="api_sysinfo"),
    path("api/perfil/encerrar-sessoes/", views.api_encerrar_sessoes, name="api_encerrar_sessoes"),

    # ── APIs de UI global (tema + sidebar) ────────────────────────────────────
    path("api/ui/tema/",    views.api_salvar_tema,    name="api_salvar_tema"),
    path("api/ui/sidebar/", views.api_salvar_sidebar, name="api_salvar_sidebar"),

    # ── Onboarding ────────────────────────────────────────────────────────────
    path("onboarding/",                     views.onboarding_view,          name="onboarding"),
    path("api/onboarding/completar/",       views.api_completar_onboarding, name="api_completar_onboarding"),
    path("api/onboarding/credenciais/",     views.api_salvar_credenciais,   name="api_salvar_credenciais"),
]