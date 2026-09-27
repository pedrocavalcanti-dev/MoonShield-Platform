from io import StringIO

from django.apps import apps
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.db.models.signals import post_migrate
from django.test import Client, TestCase, override_settings
from django.urls import clear_url_caches, reverse


class SecurityHardeningTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username="moonshield_user", password="password123")
        self.superuser = User.objects.create_superuser(username="admin_user", password="password123")
        from configuracoes.models import ConfigSistema

        cfg = ConfigSistema.get_solo()
        cfg.appliance_onboarding_completo = True
        cfg.save()

    @override_settings(DEBUG=False)
    def test_404_page(self):
        response = self.client.get("/qualquer-coisa-que-nao-existe/")
        self.assertEqual(response.status_code, 404)
        self.assertTemplateUsed(response, "errors/404.html")
        self.assertContains(response, "Página não encontrada", status_code=404)
        self.assertNotContains(response, "Traceback", status_code=404)

    @override_settings(DEBUG=False)
    def test_500_page(self):
        from django.test import RequestFactory
        from MoonShield.views import custom_500

        request = RequestFactory().get("/")
        response = custom_500(request)
        self.assertEqual(response.status_code, 500)
        self.assertIn(b"Erro Interno do Servidor", response.content)
        self.assertNotIn(b"Traceback", response.content)

    def _reload_urlconf(self):
        import importlib
        import config.urls

        importlib.reload(config.urls)
        clear_url_caches()

    def test_admin_disabled_is_404_for_any_user(self):
        with override_settings(
            DJANGO_ADMIN_ENABLED=False,
            DJANGO_ADMIN_PATH="admin-moonshield-hidden/",
        ):
            self._reload_urlconf()
            for user, password in ((self.user, "password123"), (self.superuser, "password123")):
                client = Client()
                client.force_login(user)
                for path in ("/admin/", "/admin-moonshield-hidden/"):
                    self.assertEqual(client.get(path).status_code, 404)
        self._reload_urlconf()

    def test_admin_enabled_allows_only_django_superuser(self):
        with override_settings(
            DJANGO_ADMIN_ENABLED=True,
            DJANGO_ADMIN_PATH="admin-moonshield-hidden/",
        ):
            self._reload_urlconf()
            self.client.force_login(self.user)
            response = self.client.get("/admin-moonshield-hidden/")
            self.assertEqual(response.status_code, 302)
            self.assertIn("/admin-moonshield-hidden/login/", response["Location"])

            self.client.force_login(self.superuser)
            self.assertEqual(self.client.get("/admin-moonshield-hidden/").status_code, 200)
        self._reload_urlconf()

    @override_settings(ALLOWED_HOSTS=["moonshield"])
    def test_invalid_host_returns_safe_400(self):
        client = Client(raise_request_exception=False)
        response = client.get("/", HTTP_HOST="atacante.example")
        self.assertEqual(response.status_code, 400)
        body = response.content.decode("utf-8", errors="replace")
        for sensitive in ("Traceback", "DisallowedHost", "settings.py", "SECRET_KEY", "DATABASE_URL"):
            self.assertNotIn(sensitive, body)

    @override_settings(ALLOWED_HOSTS=["moonshield"])
    def test_allowed_hosts_production(self):
        from django.conf import settings

        self.assertNotIn("*", settings.ALLOWED_HOSTS)

    def test_post_migrate_does_not_create_or_change_users(self):
        before = list(User.objects.values_list("pk", "is_staff", "is_superuser"))
        post_migrate.send(sender=apps.get_app_config("autenticacao"), app_config=apps.get_app_config("autenticacao"))
        self.assertEqual(list(User.objects.values_list("pk", "is_staff", "is_superuser")), before)

    def test_superuser_receives_profile_and_remains_untouched_without_target(self):
        from autenticacao.models import UserProfile

        self.assertTrue(UserProfile.objects.filter(user=self.superuser).exists())
        self.assertTrue(self.superuser.is_staff)
        self.assertTrue(self.superuser.is_superuser)
        output = StringIO()
        from django.core.management import call_command

        call_command("normalize_moonshield_users", commit=True, stdout=output)
        self.superuser.refresh_from_db()
        self.assertTrue(self.superuser.is_staff)
        self.assertTrue(self.superuser.is_superuser)
        self.assertIn("Nenhum alvo explícito", output.getvalue())

    def test_normalize_dry_run_does_not_modify_user(self):
        from django.core.management import call_command

        call_command("normalize_moonshield_users", username="admin_user", stdout=StringIO())
        self.superuser.refresh_from_db()
        self.assertTrue(self.superuser.is_staff)
        self.assertTrue(self.superuser.is_superuser)

    def test_normalize_commit_changes_only_selected_flags(self):
        from django.core.management import call_command

        user_password = self.superuser.password
        profile_id = self.superuser.profile.pk
        call_command("normalize_moonshield_users", username="admin_user", commit=True, stdout=StringIO())
        self.superuser.refresh_from_db()
        self.assertFalse(self.superuser.is_staff)
        self.assertFalse(self.superuser.is_superuser)
        self.assertEqual(self.superuser.password, user_password)
        self.assertEqual(self.superuser.profile.pk, profile_id)
        self.assertTrue(self.superuser.is_active)


class FirstSetupTests(TestCase):
    def setUp(self):
        User.objects.all().delete()
        self.client = Client()

    def test_empty_database_shows_first_setup_and_creates_regular_user(self):
        login_url = reverse("autenticacao:login")
        response = self.client.get(login_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Criar conta inicial")
        self.assertEqual(User.objects.count(), 0)

        response = self.client.post(login_url, {
            "username": "operador",
            "password": "L0ng-Unique-First-Setup-Password!",
            "first_name": "Pedro",
            "last_name": "Silva",
        })
        self.assertEqual(response.status_code, 302)
        user = User.objects.get(username="operador")
        self.assertTrue(user.is_active)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertEqual(user.profile.display_name, "Pedro Silva")
        self.assertIsNotNone(user.profile.last_password_change)
        self.assertIsNotNone(authenticate(username="operador", password="L0ng-Unique-First-Setup-Password!"))
        self.assertEqual(User.objects.count(), 1)

    def test_post_migrate_remains_empty_before_and_after_first_setup(self):
        config = apps.get_app_config("autenticacao")
        post_migrate.send(sender=config, app_config=config)
        self.assertEqual(User.objects.count(), 0)
        self.client.post(reverse("autenticacao:login"), {
            "username": "operador",
            "password": "L0ng-Unique-First-Setup-Password!",
            "first_name": "Pedro",
        })
        post_migrate.send(sender=config, app_config=config)
        self.assertEqual(User.objects.count(), 1)

    def test_first_setup_rejects_weak_password_without_creating_user(self):
        response = self.client.post(reverse("autenticacao:login"), {
            "username": "operador",
            "password": "123",
            "first_name": "Pedro",
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(User.objects.count(), 0)

    def test_existing_user_prevents_public_first_setup_creation(self):
        User.objects.create_user(username="existing", password="L0ng-Unique-Existing-Password!")
        response = self.client.post(reverse("autenticacao:login"), {
            "username": "second-admin",
            "password": "L0ng-Unique-Second-Password!",
            "first_name": "Segundo",
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(User.objects.count(), 1)


class LoginRedirectTests(TestCase):
    def setUp(self):
        from configuracoes.models import ConfigSistema

        self.user = User.objects.create_user(username="redirect-user", password="valid-login-password")
        config = ConfigSistema.get_solo()
        config.appliance_onboarding_completo = True
        config.save(update_fields=["appliance_onboarding_completo", "updated_at"])

    def _login_with_next(self, next_url):
        return self.client.post(reverse("autenticacao:login"), {
            "username": "redirect-user",
            "password": "valid-login-password",
            "next": next_url,
        })

    def test_internal_next_is_allowed(self):
        response = self._login_with_next("/incidentes/")
        self.assertRedirects(response, "/incidentes/", fetch_redirect_response=False)

    def test_external_next_is_rejected(self):
        for next_url in ("https://evil.example/", "//evil.example/", "http://evil.example/"):
            with self.subTest(next=next_url):
                response = self._login_with_next(next_url)
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response["Location"], reverse("painel:index"))

    def test_logout_requires_post_and_csrf(self):
        from django.test import Client

        self.client.force_login(self.user)
        self.assertEqual(self.client.get(reverse("autenticacao:logout")).status_code, 405)

        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.user)
        response = csrf_client.post(reverse("autenticacao:logout"))
        self.assertEqual(response.status_code, 403)


class IncidentIngestSecurityTests(TestCase):
    def test_unprovisioned_sensor_cannot_register_or_receive_token(self):
        from incidentes.models import Sensor

        response = self.client.post(
            "/incidentes/api/ingest/",
            data='{"sensor":"remote-sensor","eventos":[]}',
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 403)
        self.assertNotIn("token", response.json())
        self.assertFalse(Sensor.objects.filter(nome="remote-sensor").exists())

    def test_invalid_ingest_token_does_not_rotate_or_accept_events(self):
        from incidentes.models import Sensor

        sensor = Sensor.objects.create(nome="provisioned-sensor", ip="127.0.0.1", token="known-secret")
        response = self.client.post(
            "/incidentes/api/ingest/",
            data='{"sensor":"provisioned-sensor","eventos":[]}',
            content_type="application/json",
            HTTP_X_MS_TOKEN="wrong-secret",
        )
        sensor.refresh_from_db()
        self.assertEqual(response.status_code, 403)
        self.assertEqual(sensor.token, "known-secret")
        self.assertNotIn("token", response.json())


class SecuritySurfaceTests(TestCase):
    def setUp(self):
        from configuracoes.models import ConfigSistema

        self.user = User.objects.create_user(username="surface-user", password="surface-password")
        config = ConfigSistema.get_solo()
        config.appliance_onboarding_completo = True
        config.save(update_fields=["appliance_onboarding_completo", "updated_at"])

    def test_sensitive_pages_require_authentication(self):
        paths = (
            "/painel/", "/mapa/", "/incidentes/", "/rede/", "/dns/",
            "/firewall/", "/dispositivos/", "/moonai/", "/relatorios/",
            "/configuracoes/",
        )
        for path in paths:
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertIn(response.status_code, (302, 401, 403))

    def test_sensitive_apis_require_authentication(self):
        paths = (
            "/painel/api/overview/", "/mapa/api/overview/", "/incidentes/api/data/",
            "/rede/api/status/", "/dns/api/data/", "/firewall/api/data/",
            "/dispositivos/api/inventory/", "/relatorios/diagnostico/api/contexto/",
            "/configuracoes/api/config/",
        )
        for path in paths:
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertIn(response.status_code, (302, 401, 403))

    def test_write_endpoint_rejects_get_and_session_post_requires_csrf(self):
        self.assertEqual(self.client.get("/auth/api/onboarding/completar/").status_code, 405)
        csrf_client = Client(enforce_csrf_checks=True)
        response = csrf_client.post(reverse("autenticacao:login"), {
            "username": "no-user", "password": "invalid",
        })
        self.assertEqual(response.status_code, 403)
