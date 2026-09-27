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
        from django.contrib.auth.models import AnonymousUser
        from django.test import RequestFactory
        from MoonShield.views import custom_500

        request = RequestFactory().get("/")
        request.user = AnonymousUser()
        response = custom_500(request)
        self.assertEqual(response.status_code, 500)
        self.assertIn(b"Erro Interno do Servidor", response.content)
        self.assertNotIn(b"Traceback", response.content)

    @override_settings(DJANGO_ADMIN_ENABLED=True)
    def test_moonshield_user_cannot_access_admin(self):
        import importlib
        import sys

        if "config.urls" in sys.modules:
            importlib.reload(sys.modules["config.urls"])
        clear_url_caches()
        self.client.login(username="moonshield_user", password="password123")
        response = self.client.get("/admin-moonshield-hidden/", follow=True)
        self.assertTrue(any("/admin-moonshield-hidden/login/" in url for url, _ in response.redirect_chain))

    @override_settings(DJANGO_ADMIN_ENABLED=True)
    def test_superuser_can_access_admin(self):
        import importlib
        import sys

        if "config.urls" in sys.modules:
            importlib.reload(sys.modules["config.urls"])
        clear_url_caches()
        self.client.login(username="admin_user", password="password123")
        response = self.client.get("/admin-moonshield-hidden/", follow=True)
        self.assertEqual(response.status_code, 200)

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
