from django.db import models


class ConfigSistema(models.Model):
    """
    Singleton de configuração global do MoonShield.
    Sempre use ConfigSistema.get_solo() para acessar.
    """

    MODO_CHOICES = [
        ("demo", "Demo / Mock"),
        ("prod", "Produção"),
    ]

    AMBIENTE_CHOICES = [
        ("lab", "LAB"),
        ("prod", "Produção"),
    ]

    LOG_LEVEL_CHOICES = [
        ("DEBUG", "DEBUG"),
        ("INFO", "INFO"),
        ("WARNING", "WARNING"),
        ("ERROR", "ERROR"),
    ]

    # ── Modo Global ──────────────────────────────────────────────────────
    modo = models.CharField(
        max_length=10, choices=MODO_CHOICES, default="demo",
        help_text="Demo: dados simulados. Produção: integrações reais."
    )

    # ── Identidade do Node ───────────────────────────────────────────────
    node_name   = models.CharField(max_length=64, blank=True, default="MS-NODE-01")
    node_ambiente = models.CharField(max_length=10, choices=AMBIENTE_CHOICES, default="lab")
    node_tag    = models.CharField(max_length=128, blank=True, default="")
    node_desc   = models.CharField(max_length=255, blank=True, default="")

    # ── Rede Monitorada ─────────────────────────────────────────────────
    cidr          = models.CharField(max_length=32,  blank=True, default="192.168.0.0/24")
    gateway       = models.CharField(max_length=64,  blank=True, default="192.168.0.1")
    dns1          = models.CharField(max_length=64,  blank=True, default="1.1.1.1")
    dns2          = models.CharField(max_length=64,  blank=True, default="8.8.8.8")
    ips_criticos  = models.TextField(blank=True, default="")
    excluir_scan  = models.CharField(max_length=512, blank=True, default="")
    iface_principal = models.CharField(max_length=64, blank=True, default="")

    # ── Scanner ─────────────────────────────────────────────────────────
    scan_interval    = models.IntegerField(default=60)
    ping_timeout     = models.IntegerField(default=1000)
    max_hosts        = models.IntegerField(default=254)
    scan_method      = models.CharField(max_length=32, default="ping_arp")
    scan_hostname    = models.BooleanField(default=True)
    scan_mac         = models.BooleanField(default=True)
    scan_oui         = models.BooleanField(default=True)

    # ── Retenção ─────────────────────────────────────────────────────────
    ret_devices   = models.IntegerField(default=30)
    ret_logs      = models.IntegerField(default=7)
    ret_dns       = models.IntegerField(default=7)
    ret_incidents = models.IntegerField(default=90)

    # ── Integrações: Toggles ─────────────────────────────────────────────
    dns_enabled = models.BooleanField(default=False)
    ids_enabled = models.BooleanField(default=False)
    fw_enabled  = models.BooleanField(default=False)

    # ── AdGuard Home ─────────────────────────────────────────────────────
    adguard_url      = models.CharField(max_length=255, blank=True, default="")
    adguard_user     = models.CharField(max_length=80,  blank=True, default="")
    adguard_pass     = models.CharField(max_length=120, blank=True, default="")
    adguard_https    = models.BooleanField(default=False)
    adguard_interval = models.IntegerField(default=30)
    adguard_mode     = models.CharField(max_length=16, default="mock")

    # ── Suricata IDS ─────────────────────────────────────────────────────
    suricata_mode         = models.CharField(max_length=16, default="mock")
    suricata_eve_path     = models.CharField(max_length=255, blank=True, default="/var/log/suricata/eve.json")
    suricata_interval     = models.IntegerField(default=5)
    suricata_min_severity = models.IntegerField(default=2)

    # ── Firewall ─────────────────────────────────────────────────────────
    fw_mode   = models.CharField(max_length=16, default="mock")
    fw_target = models.CharField(max_length=16, default="local")
    fw_host   = models.CharField(max_length=255, blank=True, default="")
    fw_token  = models.CharField(max_length=255, blank=True, default="")
    fw_agente_porta = models.IntegerField(
        default=8765,
        help_text="Porta do agente Flask no sensor Linux (padrão 8765)"
    )

    # ── Segurança ─────────────────────────────────────────────────────────
    session_expiry      = models.IntegerField(default=480)
    max_login_attempts  = models.IntegerField(default=5)
    force_https         = models.BooleanField(default=False)
    access_log          = models.BooleanField(default=True)
    ip_ban              = models.BooleanField(default=True)
    log_level           = models.CharField(max_length=10, choices=LOG_LEVEL_CHOICES, default="INFO")

    # ── Dados Detectados (Novo) ───────────────────────────────────────────
    detected_sysinfo    = models.JSONField(default=dict, blank=True)
    detected_interfaces = models.JSONField(default=list, blank=True)
    detected_at         = models.DateTimeField(null=True, blank=True)

    # ── Metadata ──────────────────────────────────────────────────────────
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Configuração do Sistema"
        verbose_name_plural = "Configurações do Sistema"

    def __str__(self):
        return f"ConfigSistema [modo={self.modo}] — atualizado {self.updated_at:%d/%m/%Y %H:%M}"

    @classmethod
    def get_solo(cls):
        """Sempre retorna o objeto único (pk=1). Cria se não existir."""
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj

    def to_dict(self):
        """Serializa para JSON (enviado ao frontend)."""
        return {
            "modo": self.modo,

            "node": {
                "name":     self.node_name,
                "ambiente": self.node_ambiente,
                "tag":      self.node_tag,
                "desc":     self.node_desc,
            },

            "rede": {
                "cidr":          self.cidr,
                "gateway":       self.gateway,
                "dns1":          self.dns1,
                "dns2":          self.dns2,
                "ips_criticos":  self.ips_criticos,
                "excluir":       self.excluir_scan,
                "iface_principal": self.iface_principal,
            },

            "scanner": {
                "interval":    self.scan_interval,
                "pingTimeout": self.ping_timeout,
                "maxHosts":    self.max_hosts,
                "method":      self.scan_method,
                "hostname":    self.scan_hostname,
                "mac":         self.scan_mac,
                "oui":         self.scan_oui,
            },

            "retencao": {
                "devices":   self.ret_devices,
                "logs":      self.ret_logs,
                "dns":       self.ret_dns,
                "incidents": self.ret_incidents,
            },

            "providers": {
                "dns": {
                    "active":   self.dns_enabled,
                    "mode":     self.adguard_mode,
                    "url":      self.adguard_url,
                    "user":     self.adguard_user,
                    "https":    self.adguard_https,
                    "interval": self.adguard_interval,
                },
                "ids": {
                    "active":      self.ids_enabled,
                    "mode":        self.suricata_mode,
                    "evePath":     self.suricata_eve_path,
                    "interval":    self.suricata_interval,
                    "minSeverity": self.suricata_min_severity,
                },
                "fw": {
                    "active": self.fw_enabled,
                    "mode":   self.fw_mode,
                    "target": self.fw_target,
                    "host":   self.fw_host,
                },
            },

            "seguranca": {
                "sessionExpiry":    self.session_expiry,
                "maxLoginAttempts": self.max_login_attempts,
                "forceHttps":       self.force_https,
                "accessLog":        self.access_log,
                "ipBan":            self.ip_ban,
                "logLevel":         self.log_level,
            },
            
            "detectado": {
                "sysinfo": self.detected_sysinfo,
                "interfaces": self.detected_interfaces,
                "ultima_deteccao": self.detected_at.isoformat() if self.detected_at else None,
            },

            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }