from django.db import models
from django.contrib.auth import get_user_model
import uuid

User = get_user_model()

class ExecucaoDiagnostico(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    usuario = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    ferramenta = models.CharField(max_length=64, db_index=True)
    alvo = models.TextField()
    opcoes = models.JSONField(default=dict)

    ORIGEM_CHOICES = (
        ("quick", "Quick"),
        ("guided", "Guided"),
        ("terminal", "Terminal"),
        ("auto", "Auto"),
    )
    origem = models.CharField(max_length=32, choices=ORIGEM_CHOICES, default="guided")

    STATUS_CHOICES = (
        ("ok", "OK"),
        ("warn", "Warning"),
        ("err", "Error"),
    )
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, db_index=True)

    resumo = models.TextField(blank=True)
    stdout = models.TextField(blank=True)
    stderr = models.TextField(blank=True)
    resultado_estruturado = models.JSONField(default=dict, blank=True)

    duration_ms = models.PositiveIntegerField(null=True, blank=True)
    exit_code = models.IntegerField(null=True, blank=True)

    contexto_snapshot = models.JSONField(default=dict, blank=True)

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Execução de Diagnóstico"
        verbose_name_plural = "Execuções de Diagnóstico"

    def __str__(self):
        return f"{self.ferramenta} -> {self.alvo} ({self.status})"
