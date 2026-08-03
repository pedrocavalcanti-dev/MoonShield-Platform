# =============================================================================
# firewall/models.py  v3
#
# Adições v3:
#   RegraFirewall:
#     + deletado → True quando o usuário clicou em deletar
#       Soft-delete: a regra fica no banco até o sensor confirmar o sync,
#       depois é removida definitivamente pelo api_confirm_rules.
#       Isso evita que a regra suma do frontend antes do nftables ser atualizado.
# =============================================================================

import hashlib

from django.db import models


# ─────────────────────────────────────────────────────────────────────────────
# REGRAS
# ─────────────────────────────────────────────────────────────────────────────

class RegraFirewall(models.Model):

    ACAO_CHOICES  = [('allow', 'ALLOW'), ('deny', 'DENY')]
    IFACE_CHOICES = [('WAN', 'WAN'), ('LAN', 'LAN'), ('VPN', 'VPN'), ('any', 'ANY')]
    DIR_CHOICES   = [('in', 'IN'), ('out', 'OUT')]
    PROTO_CHOICES = [('TCP', 'TCP'), ('UDP', 'UDP'), ('ICMP', 'ICMP'), ('any', 'ANY')]

    priority      = models.IntegerField(default=100, db_index=True)
    action        = models.CharField(max_length=10, choices=ACAO_CHOICES,  default='deny')
    iface         = models.CharField(max_length=30, default='any')
    dir           = models.CharField(max_length=5,  choices=DIR_CHOICES,   default='in')
    proto         = models.CharField(max_length=10, choices=PROTO_CHOICES, default='TCP')
    src           = models.CharField(max_length=100, default='any')
    dst           = models.CharField(max_length=100, default='any')
    port          = models.CharField(max_length=50,  default='any')
    desc          = models.CharField(max_length=255, blank=True)
    enabled       = models.BooleanField(default=True, db_index=True)
    log           = models.BooleanField(default=True)

    # ── Controle de sincronização com o sensor ────────────────────────────────
    # pendente=True     → regra criada/editada, aguardando envio ao sensor
    # sincronizada=True → sensor confirmou que aplicou esta regra
    # deletado=True     → usuário deletou, aguarda sync para remoção definitiva
    pendente      = models.BooleanField(default=True,  db_index=True)
    sincronizada  = models.BooleanField(default=False, db_index=True)
    deletado      = models.BooleanField(default=False, db_index=True)

    criado_em     = models.DateTimeField(auto_now_add=True)
    atualizado_em = models.DateTimeField(auto_now=True)

    def marcar_pendente(self):
        """Chama após qualquer edição — reseta o status de sync."""
        self.pendente     = True
        self.sincronizada = False
        self.save(update_fields=['pendente', 'sincronizada', 'atualizado_em'])

    def __str__(self):
        status = '🗑' if self.deletado else ('✓' if self.sincronizada else ('⏳' if self.pendente else '?'))
        return f"[{self.priority}] {self.action.upper()} {self.iface} {self.src}→{self.dst}:{self.port} {status}"

    class Meta:
        ordering            = ['priority']
        verbose_name        = 'Regra de Firewall'
        verbose_name_plural = 'Regras de Firewall'
        indexes = [
            models.Index(fields=['enabled', 'priority'],      name='idx_fw_rule_ativo_prio'),
            models.Index(fields=['pendente', 'sincronizada'],  name='idx_fw_rule_sync'),
            models.Index(fields=['deletado'],                  name='idx_fw_rule_deletado'),
        ]


# ─────────────────────────────────────────────────────────────────────────────
# NAT / PORT FORWARD
# ─────────────────────────────────────────────────────────────────────────────

class NatEntry(models.Model):

    IFACE_CHOICES = [('WAN', 'WAN'), ('LAN', 'LAN'), ('VPN', 'VPN')]
    PROTO_CHOICES = [('TCP', 'TCP'), ('UDP', 'UDP'), ('any', 'ANY')]

    name      = models.CharField(max_length=100)
    iface     = models.CharField(max_length=10, choices=IFACE_CHOICES, default='WAN')
    wan_port  = models.CharField(max_length=10)
    lan_ip    = models.GenericIPAddressField()
    lan_port  = models.CharField(max_length=10)
    proto     = models.CharField(max_length=10, choices=PROTO_CHOICES, default='TCP')
    enabled   = models.BooleanField(default=True)
    criado_em = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name}: WAN:{self.wan_port} → {self.lan_ip}:{self.lan_port}"

    class Meta:
        ordering            = ['name']
        verbose_name        = 'NAT / Port Forward'
        verbose_name_plural = 'NAT / Port Forwards'


# ─────────────────────────────────────────────────────────────────────────────
# BLOCKLIST
# ─────────────────────────────────────────────────────────────────────────────

class BlocklistEntry(models.Model):

    SOURCE_CHOICES = [('Manual', 'Manual'), ('Auto', 'Auto'), ('SOC', 'SOC')]

    ip        = models.CharField(max_length=50, db_index=True)
    reason    = models.CharField(max_length=255, blank=True)
    source    = models.CharField(max_length=20, choices=SOURCE_CHOICES, default='Manual')
    expires   = models.CharField(max_length=20, default='∞')
    criado_em = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"BLOCK {self.ip}"

    class Meta:
        ordering            = ['-criado_em']
        verbose_name        = 'Blocklist'
        verbose_name_plural = 'Blocklist'


# ─────────────────────────────────────────────────────────────────────────────
# ALLOWLIST
# ─────────────────────────────────────────────────────────────────────────────

class AllowlistEntry(models.Model):

    ip        = models.CharField(max_length=255, db_index=True)
    reason    = models.CharField(max_length=255, blank=True)
    criado_em = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"ALLOW {self.ip}"

    class Meta:
        ordering            = ['-criado_em']
        verbose_name        = 'Allowlist'
        verbose_name_plural = 'Allowlist'


# ─────────────────────────────────────────────────────────────────────────────
# GEOBLOCK
# ─────────────────────────────────────────────────────────────────────────────

class GeoblockEntry(models.Model):

    DIR_CHOICES = [('IN', 'IN'), ('OUT', 'OUT'), ('BOTH', 'BOTH')]

    country   = models.CharField(max_length=100)
    code      = models.CharField(max_length=5, unique=True, db_index=True)
    dir       = models.CharField(max_length=5, choices=DIR_CHOICES, default='IN')
    enabled   = models.BooleanField(default=True)
    criado_em = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"GEO {self.code} ({self.country})"

    class Meta:
        ordering            = ['country']
        verbose_name        = 'GeoBlock'
        verbose_name_plural = 'GeoBlock'


# ─────────────────────────────────────────────────────────────────────────────
# EVENTO DE FIREWALL
# ─────────────────────────────────────────────────────────────────────────────

class EventoFirewall(models.Model):

    ACAO_CHOICES = [
        ('ALLOW', 'Allow'),
        ('DROP',  'Drop'),
        ('DENY',  'Deny'),
        ('LOG',   'Log'),
    ]

    sensor = models.ForeignKey(
        'incidentes.Sensor',
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name='eventos_firewall',
    )

    timestamp   = models.DateTimeField(db_index=True)
    acao        = models.CharField(max_length=10, choices=ACAO_CHOICES, default='ALLOW', db_index=True)
    chain       = models.CharField(max_length=20, blank=True)
    proto       = models.CharField(max_length=10, blank=True)
    src_ip      = models.GenericIPAddressField(db_index=True)
    src_port    = models.IntegerField(null=True, blank=True)
    dst_ip      = models.GenericIPAddressField(null=True, blank=True)
    dst_port    = models.IntegerField(null=True, blank=True)
    iface       = models.CharField(max_length=30, blank=True, db_index=True)
    iface_saida = models.CharField(max_length=30, blank=True)
    tamanho     = models.IntegerField(null=True, blank=True)
    ttl         = models.IntegerField(null=True, blank=True)
    flags_tcp   = models.CharField(max_length=50, blank=True)
    prefixo     = models.CharField(max_length=20, blank=True)

    event_hash = models.CharField(max_length=64, unique=True, db_index=True)

    raw_json  = models.JSONField(null=True, blank=True)
    criado_em = models.DateTimeField(auto_now_add=True)

    @staticmethod
    def calcular_hash(src_ip, dst_ip, src_port, dst_port, proto, timestamp, prefixo) -> str:
        ts  = timestamp.strftime('%Y%m%d%H%M%S%f') if hasattr(timestamp, 'strftime') else str(timestamp)
        raw = f"{src_ip}|{dst_ip}|{src_port}|{dst_port}|{proto}|{ts}|{prefixo}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def __str__(self):
        return (
            f"[{self.acao}] {self.src_ip}:{self.src_port or '?'} → "
            f"{self.dst_ip or '?'}:{self.dst_port or '?'} ({self.proto})"
        )

    class Meta:
        ordering            = ['-timestamp']
        verbose_name        = 'Evento de Firewall'
        verbose_name_plural = 'Eventos de Firewall'
        indexes = [
            models.Index(fields=['src_ip',   'timestamp'], name='idx_fw_srcip_ts'),
            models.Index(fields=['acao',     'timestamp'], name='idx_fw_acao_ts'),
            models.Index(fields=['dst_port', 'timestamp'], name='idx_fw_dstport_ts'),
        ]