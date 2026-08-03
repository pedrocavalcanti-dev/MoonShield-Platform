from django.db import models


class Dispositivo(models.Model):
    ip = models.GenericIPAddressField(unique=True, protocol="IPv4")
    mac = models.CharField(max_length=17, blank=True, null=True)
    hostname = models.CharField(max_length=120, blank=True, null=True)
    vendor = models.CharField(max_length=120, blank=True, null=True)

    os = models.CharField(max_length=80, blank=True, null=True)
    tipo = models.CharField(max_length=80, blank=True, null=True)
    icon = models.CharField(max_length=60, blank=True, null=True)

    status = models.CharField(max_length=20, default="offline")  # online / offline / suspeito
    risk_score = models.IntegerField(default=10)

    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(blank=True, null=True)
    last_scan = models.DateTimeField(blank=True, null=True)

    # nome salvo pelo usuário (sobrescreve hostname na exibição)
    custom_name = models.CharField(max_length=120, blank=True, null=True)

    def display_name(self):
        return self.custom_name or self.hostname or f"Host-{str(self.ip).split('.')[-1]}"

    def __str__(self):
        return f"{self.ip} — {self.display_name()}"


class ScanRun(models.Model):
    cidr = models.CharField(max_length=32)
    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(blank=True, null=True)
    found = models.IntegerField(default=0)
    payload = models.JSONField(default=dict, blank=True)   # cache do último resultado

    def __str__(self):
        return f"Scan {self.cidr} @ {self.started_at:%Y-%m-%d %H:%M:%S}"