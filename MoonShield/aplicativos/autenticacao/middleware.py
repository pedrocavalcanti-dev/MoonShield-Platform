import json
from django.http import JsonResponse, HttpResponseRedirect
from django.urls import reverse
from django.utils.deprecation import MiddlewareMixin

from configuracoes.models import ConfigSistema

class GlobalOnboardingGateMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if not request.user.is_authenticated:
            return None

        # Some static/media paths are handled by web server, but in dev we might hit this
        path = request.path_info
        if path.startswith("/static/") or path.startswith("/media/"):
            return None

        config = ConfigSistema.get_solo()
        if config.appliance_onboarding_completo:
            return None

        # Allowlist for First Boot functionality
        # We need to allow login, logout, onboarding UI, and required APIs
        allowed_prefixes = [
            "/auth/login/",
            "/auth/logout/",
            "/auth/onboarding/",
            "/auth/api/",
            "/configuracoes/api/",
            "/rede/api/",
            "/firewall/instalacao/",
            "/firewall/api/",
            "/incidentes/suricata/instalacao/",
            "/incidentes/api/suricata/",
        ]

        if any(path.startswith(prefix) for prefix in allowed_prefixes):
            return None

        # Se não está na allowlist, e a requisição é API/JSON (ex: fetch)
        # retornamos JSON com erro e redirect
        onboarding_url = reverse("autenticacao:onboarding")
        
        is_ajax = (
            request.headers.get("x-requested-with") == "XMLHttpRequest"
            or "application/json" in request.headers.get("accept", "")
            or path.startswith("/api/")
        )
        
        # A API root em MoonShield geralmente está dispersa por apps, 
        # mas muitos apps usam /app/api/
        if is_ajax or "/api/" in path:
            return JsonResponse(
                {
                    "ok": False,
                    "codigo": "appliance_onboarding_pendente",
                    "redirect": onboarding_url,
                    "erro": "O First Boot da appliance ainda não foi concluído.",
                },
                status=403,
            )

        # Se for requisição HTML padrão, redirecionar
        return HttpResponseRedirect(onboarding_url)

