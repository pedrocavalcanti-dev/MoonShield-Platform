from django.apps import AppConfig


class AutenticacaoConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'autenticacao'
    verbose_name = 'Autenticação'

    def ready(self):
        # Conecta os signals do models
        import autenticacao.models  # noqa: F401

        # Cria usuário padrão APÓS o migrate (sem warning de banco)
        from django.db.models.signals import post_migrate
        from django.apps import apps

        def criar_usuario_padrao(sender, **kwargs):
            import secrets
            from django.contrib.auth.models import User
            from autenticacao.models import UserProfile

            USUARIO = "admin"
            SENHA   = "admin"

            if not User.objects.filter(username=USUARIO).exists():
                user = User.objects.create_superuser(
                    username=USUARIO,
                    password=SENHA,
                    email="admin@moonshield.io",
                )
                profile, _ = UserProfile.objects.get_or_create(user=user)
                profile.onboarding_completo = False
                if not profile.api_key:
                    profile.api_key = "ms_sk_" + secrets.token_hex(28)
                profile.save(update_fields=["onboarding_completo", "api_key"])

                print(f"\n{'─'*50}")
                print(f"  ✓ Usuário padrão criado: {USUARIO}")
                print(f"  ✓ Senha inicial: {SENHA}")
                print(f"  ⚠ Troque no onboarding antes de usar em produção!")
                print(f"{'─'*50}\n")

        post_migrate.connect(criar_usuario_padrao, sender=self)