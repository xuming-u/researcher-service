"""Re-encrypt persisted credentials with the first configured key."""

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from chat.models import Pairing
from containers.models import Instance


class CredentialKeyRotation:
    def rotate(self) -> tuple[int, int]:
        instance_count = self._rotate_instances()
        pairing_count = self._rotate_pairings()
        return instance_count, pairing_count

    def _rotate_instances(self) -> int:
        count = 0
        for primary_key in Instance.objects.values_list("pk", flat=True).iterator():
            with transaction.atomic():
                instance = Instance.objects.get(pk=primary_key)
                instance.token = instance.token
                instance.save(update_fields=["token"])
            count += 1
        return count

    def _rotate_pairings(self) -> int:
        count = 0
        for primary_key in Pairing.objects.values_list("pk", flat=True).iterator():
            with transaction.atomic():
                pairing = Pairing.objects.get(pk=primary_key)
                pairing.private_key_pem = pairing.private_key_pem
                pairing.device_token = pairing.device_token
                pairing.save(update_fields=["private_key_pem", "device_token"])
            count += 1
        return count


class Command(BaseCommand):
    help = "Re-encrypt all persisted credentials using the current key."

    def add_arguments(self, parser):
        parser.add_argument(
            "--maintenance-window",
            action="store_true",
            help="Confirm that application credential writes are stopped for this rotation.",
        )

    def handle(self, *args, **options):
        if not options["maintenance_window"]:
            raise CommandError(
                "Credential rotation requires an exclusive maintenance window; "
                "rerun with --maintenance-window after stopping application writes.",
            )
        instances, pairings = CredentialKeyRotation().rotate()
        self.stdout.write(
            self.style.SUCCESS(
                f"Rotated credentials for {instances} instances and {pairings} pairings.",
            ),
        )
