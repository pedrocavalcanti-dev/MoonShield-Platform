from django.apps import AppConfig

class DispositivosConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    # Adicione "aplicativos." antes do nome
    name = 'aplicativos.dispositivos'