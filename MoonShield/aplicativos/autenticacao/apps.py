from django.apps import AppConfig

class AutenticacaoConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'autenticacao'
    verbose_name = 'Autenticação'

    def ready(self):
        import autenticacao.models  # noqa: F401
