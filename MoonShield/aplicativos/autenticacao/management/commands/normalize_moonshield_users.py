from django.contrib.auth.models import User
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction


class Command(BaseCommand):
    help = "Remove flags de Django Admin de uma conta escolhida explicitamente."

    def add_arguments(self, parser):
        target = parser.add_mutually_exclusive_group()
        target.add_argument("--username", type=str, help="Username exato da conta alvo.")
        target.add_argument("--user-id", type=int, help="ID exato da conta alvo.")
        parser.add_argument(
            "--commit",
            action="store_true",
            help="Aplica a alteração; sem esta opção, executa somente dry-run.",
        )

    def handle(self, *args, **options):
        username = options.get("username")
        user_id = options.get("user_id")
        if username is None and user_id is None:
            self.stdout.write(self.style.WARNING(
                "Nenhum alvo explícito informado. Nenhuma conta foi alterada."
            ))
            return

        try:
            user = User.objects.get(username=username) if username is not None else User.objects.get(pk=user_id)
        except User.DoesNotExist as exc:
            alvo = f"username={username}" if username is not None else f"id={user_id}"
            raise CommandError(f"Conta não encontrada ({alvo}).") from exc

        self.stdout.write(
            f"ID={user.pk} username={user.username} "
            f"is_staff={user.is_staff} is_superuser={user.is_superuser}"
        )
        self.stdout.write("Ação proposta: definir is_staff=False e is_superuser=False.")

        if not options["commit"]:
            self.stdout.write(self.style.WARNING("DRY-RUN: nenhuma alteração foi salva. Use --commit para aplicar."))
            return

        with transaction.atomic():
            user.is_staff = False
            user.is_superuser = False
            user.save(update_fields=["is_staff", "is_superuser"])
        self.stdout.write(self.style.SUCCESS("Conta selecionada normalizada."))
