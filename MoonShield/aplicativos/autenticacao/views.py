import json
import os
import platform
import re
import socket
from datetime import datetime

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.http import require_GET, require_POST

from .models import UserProfile


# ─────────────────────────────────────────────────────────────────────────────
# AUTH & ONBOARDING
# ─────────────────────────────────────────────────────────────────────────────

def login_view(request):
    if request.user.is_authenticated:
        return redirect("painel:index")

    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            profile, criado = UserProfile.objects.get_or_create(user=user)

            if not profile.onboarding_completo:
                return redirect("autenticacao:onboarding")

            # ← SÓ chega aqui se onboarding já foi feito (2ª vez+)
            request.session["mostrar_boasvindas"] = True  # ← essa linha tem que estar aqui
            return redirect("painel:index")
        else:
            messages.error(request, "ACESSO NEGADO: Credenciais Inválidas.")

    return render(request, "autenticacao/login.html")


def logout_view(request):
    logout(request)
    return redirect("autenticacao:login")


@login_required(login_url="autenticacao:login")
def onboarding_view(request):
    """Mostra o onboarding. Se já completou, manda pro dashboard."""
    profile, _ = UserProfile.objects.get_or_create(user=request.user)

    if profile.onboarding_completo:
        return redirect("painel:index")

    return render(request, "autenticacao/onboarding.html", {"profile": profile})


def api_completar_onboarding(request):
    profile, _ = UserProfile.objects.get_or_create(user=request.user)
    profile.onboarding_completo = True
    profile.save(update_fields=["onboarding_completo"])
    request.session["mostrar_boasvindas"] = "onboarding"  # flag diferente
    return JsonResponse({"ok": True})

@require_POST
@login_required(login_url="autenticacao:login")
def api_salvar_credenciais(request):
    """
    Step 2 do onboarding: permite ao usuário substituir o username padrão
    e definir sua própria senha. Mantém a sessão ativa após a troca.
    """
    try:
        data     = json.loads(request.body)
        username = data.get("username", "").strip()
        senha    = data.get("senha", "")

        # ── Validações ────────────────────────────────────────────────────────
        if not username:
            return JsonResponse({"ok": False, "msg": "Informe um nome de usuário."}, status=400)

        if not re.match(r'^[\w.@+\-]+$', username):
            return JsonResponse(
                {"ok": False, "msg": "Apenas letras, números, @, ., +, -, _"},
                status=400,
            )

        if len(username) > 150:
            return JsonResponse({"ok": False, "msg": "Nome de usuário muito longo (máx. 150)."}, status=400)

        if len(senha) < 8:
            return JsonResponse({"ok": False, "msg": "A senha deve ter pelo menos 8 caracteres."}, status=400)

        # ── Verifica conflito de username ──────────────────────────────────────
        if User.objects.filter(username=username).exclude(pk=request.user.pk).exists():
            return JsonResponse({"ok": False, "msg": "Este nome de usuário já está em uso."}, status=400)

        # ── Aplica as mudanças ─────────────────────────────────────────────────
        user          = request.user
        user.username = username
        user.set_password(senha)
        user.save(update_fields=["username", "password"])

        # Mantém a sessão ativa após a troca de senha
        update_session_auth_hash(request, user)

        return JsonResponse({"ok": True, "msg": "Credenciais salvas com sucesso."})

    except Exception as e:
        return JsonResponse({"ok": False, "msg": str(e)}, status=400)


# ─────────────────────────────────────────────────────────────────────────────
# PERFIL — PÁGINA
# ─────────────────────────────────────────────────────────────────────────────

@login_required(login_url="autenticacao:login")
def perfil_view(request):
    profile, _ = UserProfile.objects.get_or_create(user=request.user)
    return render(request, "autenticacao/perfil.html", {"profile": profile})


# ─────────────────────────────────────────────────────────────────────────────
# APIs — PERFIL
# ─────────────────────────────────────────────────────────────────────────────

@require_POST
@login_required(login_url="autenticacao:login")
def api_salvar_perfil(request):
    """Salva informações pessoais e preferências."""
    try:
        data       = json.loads(request.body)
        profile, _ = UserProfile.objects.get_or_create(user=request.user)
        user       = request.user

        first_name   = data.get("first_name",   "").strip()
        last_name    = data.get("last_name",    "").strip()
        display_name = data.get("display_name", "").strip()
        email        = data.get("email",        "").strip()

        if first_name: user.first_name = first_name
        if last_name:  user.last_name  = last_name
        if email:      user.email      = email
        user.save(update_fields=["first_name", "last_name", "email"])

        profile.display_name = display_name
        profile.cargo        = data.get("cargo",        profile.cargo)
        profile.departamento = data.get("departamento", profile.departamento)
        profile.ramal        = data.get("ramal",        profile.ramal)
        profile.bio          = data.get("bio",          profile.bio)
        profile.telefone     = data.get("telefone",     profile.telefone)
        profile.save()

        return JsonResponse({"ok": True, "msg": "Perfil atualizado com sucesso."})

    except Exception as e:
        return JsonResponse({"ok": False, "msg": str(e)}, status=400)


@require_POST
@login_required(login_url="autenticacao:login")
def api_upload_avatar(request):
    """Faz upload da foto de perfil."""
    if "avatar" not in request.FILES:
        return JsonResponse({"ok": False, "msg": "Nenhuma imagem enviada."}, status=400)

    arquivo = request.FILES["avatar"]

    tipos_validos = ["image/jpeg", "image/png", "image/gif", "image/webp"]
    if arquivo.content_type not in tipos_validos:
        return JsonResponse({"ok": False, "msg": "Formato inválido. Use JPG, PNG, GIF ou WebP."}, status=400)
    if arquivo.size > 2 * 1024 * 1024:
        return JsonResponse({"ok": False, "msg": "Arquivo muito grande. Máx 2MB."}, status=400)

    try:
        profile, _ = UserProfile.objects.get_or_create(user=request.user)

        if profile.avatar:
            old_path = profile.avatar.path
            if os.path.exists(old_path):
                os.remove(old_path)

        profile.avatar = arquivo
        profile.save(update_fields=["avatar"])

        return JsonResponse({
            "ok":         True,
            "avatar_url": profile.get_avatar_url(),
            "msg":        "Foto atualizada com sucesso.",
        })

    except Exception as e:
        return JsonResponse({"ok": False, "msg": str(e)}, status=500)


@require_POST
@login_required(login_url="autenticacao:login")
def api_trocar_senha(request):
    """Troca a senha do usuário autenticado."""
    try:
        data        = json.loads(request.body)
        senha_atual = data.get("senha_atual", "")
        nova_senha  = data.get("nova_senha",  "")
        confirmar   = data.get("confirmar",   "")

        if not senha_atual or not nova_senha:
            return JsonResponse({"ok": False, "msg": "Preencha todos os campos."}, status=400)

        if nova_senha != confirmar:
            return JsonResponse({"ok": False, "msg": "As senhas não coincidem."}, status=400)

        if len(nova_senha) < 8:
            return JsonResponse({"ok": False, "msg": "A senha deve ter ao menos 8 caracteres."}, status=400)

        user = authenticate(request, username=request.user.username, password=senha_atual)
        if user is None:
            return JsonResponse({"ok": False, "msg": "Senha atual incorreta."}, status=400)

        user.set_password(nova_senha)
        user.save()
        update_session_auth_hash(request, user)

        profile = user.profile
        profile.last_password_change = datetime.now()
        profile.save(update_fields=["last_password_change"])

        return JsonResponse({"ok": True, "msg": "Senha alterada com sucesso."})

    except Exception as e:
        return JsonResponse({"ok": False, "msg": str(e)}, status=400)


@require_POST
@login_required(login_url="autenticacao:login")
def api_regen_api_key(request):
    """Regenera a chave de API do usuário."""
    profile, _ = UserProfile.objects.get_or_create(user=request.user)
    nova_chave  = profile.regenerate_api_key()
    return JsonResponse({"ok": True, "api_key": nova_chave})


@require_POST
@login_required(login_url="autenticacao:login")
def api_salvar_prefs(request):
    """Salva preferências de interface."""
    try:
        data       = json.loads(request.body)
        profile, _ = UserProfile.objects.get_or_create(user=request.user)

        profile.tema          = data.get("tema",          profile.tema)
        profile.densidade     = data.get("densidade",     profile.densidade)
        profile.scan_interval = data.get("scan_interval", profile.scan_interval)
        profile.auto_scan     = data.get("auto_scan",     profile.auto_scan)
        profile.notificacoes  = data.get("notificacoes",  profile.notificacoes)
        profile.som_alerta    = data.get("som_alerta",    profile.som_alerta)
        profile.save()

        return JsonResponse({"ok": True, "msg": "Preferências salvas."})

    except Exception as e:
        return JsonResponse({"ok": False, "msg": str(e)}, status=400)


@require_GET
@login_required(login_url="autenticacao:login")
def api_sysinfo(request):
    """Retorna informações do host para a aba Ambiente."""
    try:
        hostname = socket.gethostname()
        try:
            ip_local = socket.gethostbyname(hostname)
        except Exception:
            ip_local = "—"

        info = {
            "os":       f"{platform.system()} {platform.release()}",
            "hostname": hostname,
            "python":   platform.python_version(),
            "ip":       ip_local,
            "uptime":   _get_uptime(),
        }
    except Exception as e:
        info = {"erro": str(e)}

    return JsonResponse({"ok": True, "sysinfo": info})


@require_POST
@login_required(login_url="autenticacao:login")
def api_encerrar_sessoes(request):
    """Encerra todas as sessões do usuário (exceto a atual)."""
    from django.contrib.sessions.models import Session
    from django.utils import timezone

    sessions_deletadas = 0
    current_key = request.session.session_key

    for session in Session.objects.filter(expire_date__gte=timezone.now()):
        data = session.get_decoded()
        if data.get("_auth_user_id") == str(request.user.pk):
            if session.session_key != current_key:
                session.delete()
                sessions_deletadas += 1

    return JsonResponse({
        "ok":  True,
        "msg": f"{sessions_deletadas} sessão(ões) encerrada(s).",
    })


# ─────────────────────────────────────────────────────────────────────────────
# APIs DE UI GLOBAL (TEMA E SIDEBAR)
# ─────────────────────────────────────────────────────────────────────────────

@require_POST
@login_required(login_url="autenticacao:login")
def api_salvar_tema(request):
    """Salva o tema (dark/light) no banco de dados."""
    try:
        data  = json.loads(request.body)
        tema  = data.get("tema", "").strip()

        if tema not in ("dark", "light"):
            return JsonResponse({"ok": False, "msg": "Tema inválido."}, status=400)

        profile, _ = UserProfile.objects.get_or_create(user=request.user)
        profile.tema = tema
        profile.save(update_fields=["tema"])

        return JsonResponse({"ok": True, "tema": tema})

    except Exception as e:
        return JsonResponse({"ok": False, "msg": str(e)}, status=400)


@require_POST
@login_required(login_url="autenticacao:login")
def api_salvar_sidebar(request):
    """Salva o estado collapsed/expanded da sidebar."""
    try:
        data      = json.loads(request.body)
        collapsed = bool(data.get("collapsed", False))

        profile, _ = UserProfile.objects.get_or_create(user=request.user)
        profile.sidebar_collapsed = collapsed
        profile.save(update_fields=["sidebar_collapsed"])

        return JsonResponse({"ok": True, "collapsed": collapsed})

    except Exception as e:
        return JsonResponse({"ok": False, "msg": str(e)}, status=400)


# ─────────────────────────────────────────────────────────────────────────────
# UTIL
# ─────────────────────────────────────────────────────────────────────────────

def _get_uptime():
    try:
        if platform.system() == "Linux":
            with open("/proc/uptime") as f:
                secs = float(f.read().split()[0])
            d = int(secs // 86400)
            h = int((secs % 86400) // 3600)
            m = int((secs % 3600) // 60)
            return f"{d}d {h}h {m}m"
        elif platform.system() == "Windows":
            import subprocess
            out = subprocess.check_output("net statistics workstation", shell=True).decode("cp850", errors="ignore")
            for line in out.splitlines():
                if "Statistics since" in line or "Estatísticas desde" in line:
                    return line.split("since")[-1].strip()
            return "—"
    except Exception:
        pass
    return "—"