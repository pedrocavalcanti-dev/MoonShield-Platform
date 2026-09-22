from django.db import models


class Dispositivo(models.Model):
    """Inventário persistente de ativos observados pelo MoonShield."""

    class Status(models.TextChoices):
        ONLINE = "online", "Online"
        OFFLINE = "offline", "Offline"
        STALE = "stale", "Desatualizado"
        UNKNOWN = "unknown", "Desconhecido"

    # A PK é o identificador estável exposto pela API como ``device_id``.
    identity_key = models.CharField(max_length=180, unique=True, db_index=True)
    identity_temporary = models.BooleanField(default=True)
    current_ip = models.GenericIPAddressField(protocol="IPv4", blank=True, null=True, db_index=True)
    mac = models.CharField(max_length=17, blank=True, null=True, db_index=True)
    detected_hostname = models.CharField(max_length=120, blank=True, null=True)
    custom_name = models.CharField(max_length=120, blank=True, null=True)
    vendor = models.CharField(max_length=120, blank=True, null=True)
    os_guess = models.CharField(max_length=80, blank=True, null=True)
    device_type = models.CharField(max_length=80, blank=True, null=True)
    icon = models.CharField(max_length=60, blank=True, null=True)
    classification_confidence = models.PositiveSmallIntegerField(default=0)
    observed_ports = models.JSONField(default=list, blank=True)
    interface_name = models.CharField(max_length=64, blank=True, default="")
    network_role = models.CharField(max_length=20, blank=True, default="")
    network_cidr = models.CharField(max_length=43, blank=True, default="")
    network_id = models.CharField(max_length=128, blank=True, default="", db_index=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.UNKNOWN, db_index=True)
    risk_score = models.IntegerField(default=10)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(blank=True, null=True)
    last_scan = models.DateTimeField(blank=True, null=True)

    def display_name(self):
        if self.custom_name:
            return self.custom_name
        if self.detected_hostname:
            return self.detected_hostname
        if self.vendor and self.current_ip:
            return f"{self.vendor} {self.current_ip}"
        return f"Dispositivo {self.current_ip or self.pk}"

    def __str__(self):
        return f"{self.current_ip or 'sem IP'} — {self.display_name()}"


class RedeDiscovery(models.Model):
    """Preferência persistida para redes oficialmente elegíveis ao discovery."""

    network_id = models.CharField(max_length=128, unique=True)
    role = models.CharField(max_length=20)
    interface_name = models.CharField(max_length=64)
    cidr = models.CharField(max_length=43)
    selected = models.BooleanField(default=False)
    last_scan = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["role", "interface_name"]


class ScanRun(models.Model):
    class Status(models.TextChoices):
        RUNNING = "running", "Em andamento"
        COMPLETED = "completed", "Concluído"
        PARTIAL = "partial", "Parcial"
        FAILED = "failed", "Falhou"

    # ``cidr`` e ``payload`` são preservados para registros históricos V1.
    cidr = models.CharField(max_length=32, blank=True, default="")
    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(blank=True, null=True)
    found = models.IntegerField(default=0)
    payload = models.JSONField(default=dict, blank=True)
    requested_networks = models.JSONField(default=list, blank=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.RUNNING)
    origin = models.CharField(max_length=32, default="manual")
    errors_by_network = models.JSONField(default=dict, blank=True)
    summary = models.JSONField(default=dict, blank=True)
    lock_key = models.CharField(max_length=64, unique=True, blank=True, null=True)

    class Meta:
        ordering = ["-started_at"]

    def __str__(self):
        return f"Scan {self.pk} @ {self.started_at:%Y-%m-%d %H:%M:%S}"
