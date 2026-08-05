from django.db import models


class ConfigSistema(models.Model):
    """
    Configuração global do MoonShield.

    Este model funciona como singleton. Sempre utilize:

        ConfigSistema.get_solo()

    Valores internos do modo:
        demo -> Modo Demonstração
        prod -> Modo Operacional

    O valor interno "prod" foi mantido para preservar compatibilidade
    com o backend e o frontend existentes.
    """

    MODO_CHOICES = [
        ("demo", "Modo Demonstração"),
        ("prod", "Modo Operacional"),
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

    # ──────────────────────────────────────────────────────────────────────
    # MODO GLOBAL
    # ──────────────────────────────────────────────────────────────────────

    modo = models.CharField(
        max_length=10,
        choices=MODO_CHOICES,
        default="demo",
        help_text=(
            "Modo Demonstração: utiliza dados simulados e bloqueia integrações reais. "
            "Modo Operacional: permite instalar, conectar e utilizar componentes reais."
        ),
    )

    # ──────────────────────────────────────────────────────────────────────
    # IDENTIDADE DO NODE
    # ──────────────────────────────────────────────────────────────────────

    node_name = models.CharField(
        max_length=64,
        blank=True,
        default="MS-NODE-01",
    )

    node_ambiente = models.CharField(
        max_length=10,
        choices=AMBIENTE_CHOICES,
        default="lab",
    )

    node_tag = models.CharField(
        max_length=128,
        blank=True,
        default="",
    )

    node_desc = models.CharField(
        max_length=255,
        blank=True,
        default="",
    )

    # ──────────────────────────────────────────────────────────────────────
    # REDE MONITORADA
    # ──────────────────────────────────────────────────────────────────────

    cidr = models.CharField(
        max_length=32,
        blank=True,
        default="192.168.0.0/24",
    )

    gateway = models.CharField(
        max_length=64,
        blank=True,
        default="192.168.0.1",
    )

    dns1 = models.CharField(
        max_length=64,
        blank=True,
        default="1.1.1.1",
    )

    dns2 = models.CharField(
        max_length=64,
        blank=True,
        default="8.8.8.8",
    )

    ips_criticos = models.TextField(
        blank=True,
        default="",
    )

    excluir_scan = models.CharField(
        max_length=512,
        blank=True,
        default="",
    )

    iface_principal = models.CharField(
        max_length=64,
        blank=True,
        default="",
    )

    # ──────────────────────────────────────────────────────────────────────
    # SCANNER
    # ──────────────────────────────────────────────────────────────────────

    scan_interval = models.IntegerField(
        default=60,
        help_text="Intervalo entre varreduras, em segundos.",
    )

    ping_timeout = models.IntegerField(
        default=1000,
        help_text="Tempo limite do ping, em milissegundos.",
    )

    max_hosts = models.IntegerField(
        default=254,
    )

    scan_method = models.CharField(
        max_length=32,
        default="ping_arp",
    )

    scan_hostname = models.BooleanField(
        default=True,
    )

    scan_mac = models.BooleanField(
        default=True,
    )

    scan_oui = models.BooleanField(
        default=True,
    )

    # ──────────────────────────────────────────────────────────────────────
    # RETENÇÃO
    # ──────────────────────────────────────────────────────────────────────

    ret_devices = models.IntegerField(
        default=30,
        help_text="Retenção de dispositivos, em dias.",
    )

    ret_logs = models.IntegerField(
        default=7,
        help_text="Retenção de logs, em dias.",
    )

    ret_dns = models.IntegerField(
        default=7,
        help_text="Retenção de eventos DNS, em dias.",
    )

    ret_incidents = models.IntegerField(
        default=90,
        help_text="Retenção de incidentes, em dias.",
    )

    # ──────────────────────────────────────────────────────────────────────
    # INTEGRAÇÕES — TOGGLES
    # ──────────────────────────────────────────────────────────────────────

    dns_enabled = models.BooleanField(
        default=False,
        help_text="Indica se o provider DNS está habilitado.",
    )

    ids_enabled = models.BooleanField(
        default=False,
        help_text="Indica se o provider IDS está habilitado.",
    )

    fw_enabled = models.BooleanField(
        default=False,
        help_text="Indica se o provider Firewall está habilitado.",
    )

    # ──────────────────────────────────────────────────────────────────────
    # ADGUARD HOME
    # ──────────────────────────────────────────────────────────────────────

    adguard_url = models.CharField(
        max_length=255,
        blank=True,
        default="",
    )

    adguard_user = models.CharField(
        max_length=80,
        blank=True,
        default="",
    )

    adguard_pass = models.CharField(
        max_length=120,
        blank=True,
        default="",
    )

    adguard_https = models.BooleanField(
        default=False,
    )

    adguard_interval = models.IntegerField(
        default=30,
    )

    adguard_mode = models.CharField(
        max_length=16,
        default="mock",
        help_text="mock no modo demonstração; real no modo operacional.",
    )

    # ──────────────────────────────────────────────────────────────────────
    # SURICATA IDS
    # ──────────────────────────────────────────────────────────────────────
    #
    # Estes campos continuam existindo para compatibilidade com o sistema
    # geral de providers e com o consumo atual do frontend.
    #
    # O estado de instalação, configuração, tarefas e saúde do Suricata
    # permanece nos models próprios do módulo Suricata:
    #
    #   ConfiguracaoSuricata
    #   TarefaSuricata
    #   LogTarefaSuricata
    #
    # Portanto, não duplicamos aqui campos como:
    #   suricata_instalado
    #   suricata_configurado
    #   suricata_status
    #   suricata_progresso
    # ──────────────────────────────────────────────────────────────────────

    suricata_mode = models.CharField(
        max_length=16,
        default="mock",
        help_text=(
            "mock no Modo Demonstração; eve no Modo Operacional "
            "quando o Suricata estiver configurado."
        ),
    )

    suricata_eve_path = models.CharField(
        max_length=255,
        blank=True,
        default="/var/log/suricata/eve.json",
    )

    suricata_interval = models.IntegerField(
        default=5,
        help_text="Intervalo de leitura do eve.json, em segundos.",
    )

    suricata_min_severity = models.IntegerField(
        default=2,
        help_text="Severidade mínima dos eventos IDS.",
    )

    # ──────────────────────────────────────────────────────────────────────
    # FIREWALL
    # ──────────────────────────────────────────────────────────────────────

    fw_mode = models.CharField(
        max_length=16,
        default="mock",
    )

    fw_target = models.CharField(
        max_length=16,
        default="local",
    )

    fw_host = models.CharField(
        max_length=255,
        blank=True,
        default="",
    )

    fw_token = models.CharField(
        max_length=255,
        blank=True,
        default="",
    )

    fw_agente_porta = models.IntegerField(
        default=8765,
        help_text="Porta do agente Flask no sensor Linux.",
    )

    # ──────────────────────────────────────────────────────────────────────
    # SEGURANÇA
    # ──────────────────────────────────────────────────────────────────────

    session_expiry = models.IntegerField(
        default=480,
        help_text="Tempo de expiração da sessão, em minutos.",
    )

    max_login_attempts = models.IntegerField(
        default=5,
    )

    force_https = models.BooleanField(
        default=False,
    )

    access_log = models.BooleanField(
        default=True,
    )

    ip_ban = models.BooleanField(
        default=True,
    )

    log_level = models.CharField(
        max_length=10,
        choices=LOG_LEVEL_CHOICES,
        default="INFO",
    )

    # ──────────────────────────────────────────────────────────────────────
    # DADOS DETECTADOS
    # ──────────────────────────────────────────────────────────────────────

    detected_sysinfo = models.JSONField(
        default=dict,
        blank=True,
    )

    detected_interfaces = models.JSONField(
        default=list,
        blank=True,
    )

    detected_at = models.DateTimeField(
        null=True,
        blank=True,
    )

    # ──────────────────────────────────────────────────────────────────────
    # METADADOS
    # ──────────────────────────────────────────────────────────────────────

    updated_at = models.DateTimeField(
        auto_now=True,
    )

    class Meta:
        verbose_name = "Configuração do Sistema"
        verbose_name_plural = "Configurações do Sistema"

    def __str__(self):
        atualizado = (
            self.updated_at.strftime("%d/%m/%Y %H:%M")
            if self.updated_at
            else "nunca"
        )

        return (
            f"ConfigSistema [modo={self.modo}] "
            f"— atualizado {atualizado}"
        )

    @classmethod
    def get_solo(cls):
        """
        Retorna sempre o registro singleton de configuração.

        O objeto principal utiliza pk=1 e será criado automaticamente
        quando ainda não existir.
        """
        objeto, _ = cls.objects.get_or_create(pk=1)
        return objeto

    @property
    def modo_demo(self):
        """Retorna True quando o MoonShield está em demonstração."""
        return self.modo == "demo"

    @property
    def modo_operacional(self):
        """Retorna True quando o MoonShield está no modo operacional."""
        return self.modo == "prod"

    @property
    def total_providers_habilitados(self):
        """Quantidade de providers habilitados."""
        return sum(
            [
                bool(self.dns_enabled),
                bool(self.ids_enabled),
                bool(self.fw_enabled),
            ]
        )

    def to_dict(self):
        """
        Serializa a configuração para o frontend.

        A estrutura atual foi preservada para não quebrar:
        - cfg-nucleo.js
        - cfg-conexoes.js
        - cfg-infraestrutura.js
        - APIs e telas que já consomem ConfigSistema
        """

        return {
            "modo": self.modo,

            "modo_info": {
                "valor": self.modo,
                "demo": self.modo_demo,
                "operacional": self.modo_operacional,
                "label": (
                    "Modo Operacional"
                    if self.modo_operacional
                    else "Modo Demonstração"
                ),
            },

            "node": {
                "name": self.node_name,
                "ambiente": self.node_ambiente,
                "tag": self.node_tag,
                "desc": self.node_desc,
            },

            "rede": {
                "cidr": self.cidr,
                "gateway": self.gateway,
                "dns1": self.dns1,
                "dns2": self.dns2,
                "ips_criticos": self.ips_criticos,
                "excluir": self.excluir_scan,
                "iface_principal": self.iface_principal,
            },

            "scanner": {
                "interval": self.scan_interval,
                "pingTimeout": self.ping_timeout,
                "maxHosts": self.max_hosts,
                "method": self.scan_method,
                "hostname": self.scan_hostname,
                "mac": self.scan_mac,
                "oui": self.scan_oui,
            },

            "retencao": {
                "devices": self.ret_devices,
                "logs": self.ret_logs,
                "dns": self.ret_dns,
                "incidents": self.ret_incidents,
            },

            "providers": {
                "dns": {
                    "active": self.dns_enabled,
                    "mode": self.adguard_mode,
                    "url": self.adguard_url,
                    "user": self.adguard_user,
                    "https": self.adguard_https,
                    "interval": self.adguard_interval,
                },

                "ids": {
                    "active": self.ids_enabled,
                    "mode": self.suricata_mode,
                    "evePath": self.suricata_eve_path,
                    "interval": self.suricata_interval,
                    "minSeverity": self.suricata_min_severity,
                },

                "fw": {
                    "active": self.fw_enabled,
                    "mode": self.fw_mode,
                    "target": self.fw_target,
                    "host": self.fw_host,
                    "agente_porta": self.fw_agente_porta,
                },
            },

            "providers_resumo": {
                "habilitados": self.total_providers_habilitados,
                "total": 3,
                "dns": self.dns_enabled,
                "ids": self.ids_enabled,
                "fw": self.fw_enabled,
            },

            "seguranca": {
                "sessionExpiry": self.session_expiry,
                "maxLoginAttempts": self.max_login_attempts,
                "forceHttps": self.force_https,
                "accessLog": self.access_log,
                "ipBan": self.ip_ban,
                "logLevel": self.log_level,
            },

            "detectado": {
                "sysinfo": self.detected_sysinfo,
                "interfaces": self.detected_interfaces,
                "ultima_deteccao": (
                    self.detected_at.isoformat()
                    if self.detected_at
                    else None
                ),
            },

            "updated_at": (
                self.updated_at.isoformat()
                if self.updated_at
                else None
            ),
        }