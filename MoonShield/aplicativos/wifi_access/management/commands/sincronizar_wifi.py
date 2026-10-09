from django.core.management.base import BaseCommand
import json

from wifi_access.services.reconciliation import reconcile_wifi_access

class Command(BaseCommand):
    help = "Sincroniza o controle de acesso Wi-Fi: reconcilia MAC->IP, expira sessÃµes e aplica regras no firewall."

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Exibe as aÃ§Ãµes que seriam tomadas sem modificar o banco ou o firewall.',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']

        self.stdout.write("Iniciando sincronizaÃ§Ã£o do Wi-Fi...")

        result = reconcile_wifi_access(dry_run=dry_run)

        if result.get("ok"):
            self.stdout.write(self.style.SUCCESS("SincronizaÃ§Ã£o concluÃ­da com sucesso."))
            if dry_run:
                self.stdout.write(self.style.WARNING("--- MODO DRY RUN ---"))
                for action in result.get("actions_taken", []):
                    self.stdout.write(f"- {action}")

                state = result.get("state", {})
                self.stdout.write("\nEstado de Enforcement Configurado:")
                self.stdout.write(f"  WIFI_ENFORCEMENT_ENABLED = {state.get('enforcement_enabled')}")
                self.stdout.write(f"  WIFI_CLIENT_CIDRS = {state.get('cidrs')}")
                self.stdout.write(f"  WIFI_INGRESS_INTERFACES = {state.get('interfaces')}")

                desired = state.get('desired_ips', [])
                self.stdout.write(f"\nIPs desejados (estado atual, sem aplicar aÃ§Ãµes): {len(desired)}")
                for ip in sorted(desired):
                    self.stdout.write(f"  - {ip}")
            else:
                for action in result.get("actions_taken", []):
                    self.stdout.write(self.style.SUCCESS(f"AÃ§Ã£o: {action}"))

                sync = result.get("sync_result", {})
                self.stdout.write(f"Sincronizado no firewall: {sync.get('total_regras', 0)} regras, {sync.get('total_allowlist', 0)} itens na allowlist.")
        else:
            self.stderr.write(self.style.ERROR(f"Falha na sincronizaÃ§Ã£o: {result.get('error')}"))
            for action in result.get("actions_taken", []):
                self.stdout.write(f"AÃ§Ã£o antes do erro: {action}")
