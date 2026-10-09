from __future__ import annotations

import re

from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q


_MAC_RE = re.compile(r"^[0-9A-F]{2}(?::[0-9A-F]{2}){5}$")
_INVALID_MACS = {"00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"}


def normalize_mac(value: object) -> str:
    """Normaliza e valida um MAC Ethernet unicast para armazenamento."""
    mac = str(value or "").strip().upper().replace("-", ":")
    if not _MAC_RE.fullmatch(mac) or mac in _INVALID_MACS:
        raise ValidationError("Informe um endereço MAC unicast válido.")
    if int(mac[:2], 16) & 1:
        raise ValidationError("Endereços MAC multicast não são aceitos.")
    return mac


class WifiTrustedDevice(models.Model):
    """Equipamento liberado permanentemente no controle Wi-Fi."""

    nome = models.CharField(max_length=120)
    mac_address = models.CharField(max_length=17, unique=True, db_index=True)
    ip_address = models.GenericIPAddressField(protocol="IPv4", blank=True, null=True)
    descricao = models.TextField(blank=True)
    active = models.BooleanField(default=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["nome", "id"]
        verbose_name = "dispositivo Wi-Fi confiável"
        verbose_name_plural = "dispositivos Wi-Fi confiáveis"

    def clean(self) -> None:
        self.mac_address = normalize_mac(self.mac_address)

    def save(self, *args, **kwargs):
        self.full_clean()
        return super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f"{self.nome} ({self.mac_address})"


class WifiAuthorization(models.Model):
    """Autorização emitida pelo AUTH01; nunca armazena credenciais."""

    class Source(models.TextChoices):
        AUTH01 = "AUTH01", "AUTH01"

    username = models.CharField(max_length=150, db_index=True)
    ip_address = models.GenericIPAddressField(protocol="IPv4", db_index=True)
    mac_address = models.CharField(max_length=17, db_index=True)
    authorized_at = models.DateTimeField()
    expires_at = models.DateTimeField(blank=True, null=True)
    last_seen_at = models.DateTimeField(blank=True, null=True)
    active = models.BooleanField(default=True, db_index=True)
    revoked_at = models.DateTimeField(blank=True, null=True)
    revoked_reason = models.CharField(max_length=255, blank=True)
    auth_source = models.CharField(max_length=32, choices=Source.choices, default=Source.AUTH01)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-authorized_at", "-id"]
        constraints = [
            models.UniqueConstraint(
                fields=["mac_address"],
                condition=Q(active=True),
                name="wifi_one_active_authorization_per_mac",
            ),
        ]
        indexes = [
            models.Index(fields=["active", "ip_address"], name="wifi_auth_active_ip_idx"),
        ]

    def clean(self) -> None:
        self.mac_address = normalize_mac(self.mac_address)

    def save(self, *args, **kwargs):
        self.full_clean()
        return super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f"{self.username} — {self.ip_address}"
