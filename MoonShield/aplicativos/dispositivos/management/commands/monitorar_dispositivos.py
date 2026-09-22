"""Uma execução do monitor leve, chamada pelo timer systemd."""
import json

from django.core.management.base import BaseCommand
from dispositivos.monitoring import monitor_once


class Command(BaseCommand):
    help = "Verifica apenas dispositivos conhecidos das redes monitoradas."

    def handle(self, *args, **options):
        self.stdout.write(json.dumps(monitor_once(), ensure_ascii=False))
