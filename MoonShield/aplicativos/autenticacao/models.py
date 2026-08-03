import secrets
import os
from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver


def avatar_upload_path(instance, filename):
    ext = os.path.splitext(filename)[1].lower()
    return f"avatars/user_{instance.user.id}{ext}"


class UserProfile(models.Model):
    """Extensão 1-para-1 do User padrão do Django."""

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")

    # ── Informações pessoais ──────────────────────────────────────────────────
    avatar       = models.ImageField(upload_to=avatar_upload_path, null=True, blank=True)
    display_name = models.CharField(max_length=80,  blank=True)
    cargo        = models.CharField(max_length=100, blank=True, default="Analista SOC / Redes")
    departamento = models.CharField(max_length=100, blank=True, default="Blue Team · CSIRT")
    ramal        = models.CharField(max_length=40,  blank=True)
    bio          = models.TextField(max_length=500, blank=True)
    telefone     = models.CharField(max_length=30,  blank=True)

    # ── Segurança / API ───────────────────────────────────────────────────────
    api_key              = models.CharField(max_length=64, blank=True, editable=False)
    totp_enabled         = models.BooleanField(default=False)
    last_password_change = models.DateTimeField(null=True, blank=True)

    # ── Preferências ─────────────────────────────────────────────────────────
    THEME_CHOICES    = [("dark", "Escuro"), ("light", "Claro")]
    DENSITY_CHOICES  = [("compacto", "Compacto"), ("normal", "Normal"), ("espacoso", "Espaçoso")]
    INTERVAL_CHOICES = [("1", "1 min"), ("2", "2 min"), ("5", "5 min"), ("0", "Manual")]

    tema          = models.CharField(max_length=10, choices=THEME_CHOICES,    default="dark")
    densidade     = models.CharField(max_length=10, choices=DENSITY_CHOICES,  default="normal")
    scan_interval = models.CharField(max_length=5,  choices=INTERVAL_CHOICES, default="5")
    auto_scan     = models.BooleanField(default=True)
    notificacoes  = models.BooleanField(default=True)
    som_alerta    = models.BooleanField(default=False)

    # ── Estado da UI ─────────────────────────────────────────────────────────
    sidebar_collapsed   = models.BooleanField(default=False)
    onboarding_completo = models.BooleanField(default=False)  # ← NOVO

    # ── Meta ─────────────────────────────────────────────────────────────────
    criado_em     = models.DateTimeField(auto_now_add=True)
    atualizado_em = models.DateTimeField(auto_now=True)

    class Meta:
        app_label           = "autenticacao"
        verbose_name        = "Perfil do Usuário"
        verbose_name_plural = "Perfis dos Usuários"

    def __str__(self):
        return f"Perfil de {self.user.username}"

    def get_display_name(self):
        return self.display_name or self.user.get_full_name() or self.user.username

    def get_initials(self):
        name  = self.get_display_name()
        parts = name.strip().split()
        if len(parts) >= 2:
            return (parts[0][0] + parts[-1][0]).upper()
        return name[:2].upper()

    def regenerate_api_key(self):
        self.api_key = "jg_sk_" + secrets.token_hex(28)
        self.save(update_fields=["api_key"])
        return self.api_key

    def get_avatar_url(self):
        if self.avatar:
            return self.avatar.url
        return None


# ── Signals ──────────────────────────────────────────────────────────────────

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        profile         = UserProfile.objects.create(user=instance)
        profile.api_key = "jg_sk_" + secrets.token_hex(28)
        profile.save(update_fields=["api_key"])

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    if hasattr(instance, "profile"):
        instance.profile.save()