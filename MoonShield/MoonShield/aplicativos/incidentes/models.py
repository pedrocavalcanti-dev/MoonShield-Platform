# =============================================================================
# incidentes/models.py  v6
#
# Mudanças v6:
#   ✓ Sensor.interfaces = JSONField(default=list)
#     — armazena interfaces detectadas pelo sensor Linux
#     — EXIGE migration: 0003_sensor_interfaces.py
# =============================================================================

import hashlib

from django.db import models
from django.utils import timezone


# ─────────────────────────────────────────────────────────────────────────────
# CHOICES REUTILIZÁVEIS
# ─────────────────────────────────────────────────────────────────────────────

class SeveridadeJG(models.TextChoices):
    CRITICO     = 'critico',     'Crítico'
    ALTO        = 'alto',        'Alto'
    MEDIO       = 'medio',       'Médio'
    BAIXO       = 'baixo',       'Baixo'
    INFORMATIVO = 'informativo', 'Informativo'


class CategoriaJG(models.TextChoices):
    RECON    = 'recon',    'Reconhecimento'
    AUTH     = 'auth',     'Autenticação / Brute Force'
    LATERAL  = 'lateral',  'Movimento Lateral'
    DNS      = 'dns',      'DNS / Policy'
    WEB      = 'web',      'Web / HTTP'
    TLS      = 'tls',      'TLS / QUIC'
    MALWARE  = 'malware',  'Malware / C2'
    EXFIL    = 'exfil',    'Exfiltração'
    P2P      = 'p2p',      'P2P / Mineração'
    ANOMALIA = 'anomalia', 'Anomalia'
    INFO     = 'info',     'Informativo'


# Janelas de correlação por categoria (em minutos)
JANELAS_CORRELACAO = {
    'recon':    5,
    'auth':     30,
    'lateral':  15,
    'dns':      20,
    'web':      10,
    'tls':      30,
    'malware':  60,
    'exfil':    30,
    'p2p':      60,
    'anomalia': 10,
    'info':     5,
}
JANELA_DEFAULT = 15


# ─────────────────────────────────────────────────────────────────────────────
# SENSOR
# ─────────────────────────────────────────────────────────────────────────────

class Sensor(models.Model):

    ONLINE_THRESHOLD_SEGUNDOS = 45

    nome       = models.CharField(max_length=100, unique=True)
    ip         = models.GenericIPAddressField()
    token      = models.CharField(max_length=64, unique=True)
    ativo      = models.BooleanField(default=True)
    criado_em  = models.DateTimeField(auto_now_add=True)
    last_seen  = models.DateTimeField(null=True, blank=True, db_index=True)
    interfaces = models.JSONField(
        default=list, blank=True,
        help_text='Interfaces de rede detectadas pelo sensor Linux',
    )

    def __str__(self):
        return f"{self.nome} ({self.ip})"

    @property
    def segundos_desde_ultimo_evento(self):
        if not self.last_seen:
            return None
        return int((timezone.now() - self.last_seen).total_seconds())

    @property
    def online(self) -> bool:
        s = self.segundos_desde_ultimo_evento
        if s is None:
            return False
        return s < self.ONLINE_THRESHOLD_SEGUNDOS

    @property
    def status_detalhado(self) -> str:
        s = self.segundos_desde_ultimo_evento
        if s is None:
            return 'nunca'
        if s < 120:
            return 'online'
        if s < self.ONLINE_THRESHOLD_SEGUNDOS:
            return 'degradado'
        return 'offline'

    class Meta:
        verbose_name        = 'Sensor'
        verbose_name_plural = 'Sensores'


# ─────────────────────────────────────────────────────────────────────────────
# GEO CACHE
# ─────────────────────────────────────────────────────────────────────────────

class GeoCache(models.Model):
    ip          = models.GenericIPAddressField(unique=True, db_index=True)
    pais        = models.CharField(max_length=100, blank=True)
    pais_codigo = models.CharField(max_length=5,   blank=True)
    cidade      = models.CharField(max_length=100, blank=True)
    latitude    = models.FloatField(null=True, blank=True)
    longitude   = models.FloatField(null=True, blank=True)
    asn_number  = models.CharField(max_length=20,  blank=True)
    asn_org     = models.CharField(max_length=200, blank=True)
    rdns        = models.CharField(max_length=255, blank=True)
    source      = models.CharField(max_length=20,  default='maxmind')
    updated_at  = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.ip} → {self.pais_codigo} {self.asn_org}"

    @property
    def asn(self) -> str:
        if self.asn_number and self.asn_org:
            return f"{self.asn_number} {self.asn_org}"
        return self.asn_number or self.asn_org or ''

    class Meta:
        verbose_name        = 'Cache GeoIP'
        verbose_name_plural = 'Cache GeoIP'


# ─────────────────────────────────────────────────────────────────────────────
# RISK SCORE
# ─────────────────────────────────────────────────────────────────────────────

class RiskScore(models.Model):
    ip            = models.GenericIPAddressField(unique=True, db_index=True)
    score         = models.FloatField(default=0.0)
    total_alertas = models.IntegerField(default=0)
    criticos      = models.IntegerField(default=0)
    altos         = models.IntegerField(default=0)
    medios        = models.IntegerField(default=0)
    ultimo_alerta = models.DateTimeField(null=True, blank=True)
    updated_at    = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.ip}  score={self.score:.1f}"

    class Meta:
        verbose_name        = 'Risk Score'
        verbose_name_plural = 'Risk Scores'
        ordering            = ['-score']


# ─────────────────────────────────────────────────────────────────────────────
# REGRA DE MAPEAMENTO
# ─────────────────────────────────────────────────────────────────────────────

class RegraDeMapeamento(models.Model):

    TIPO_MATCH = [
        ('sid',       'SID exato'),
        ('signature', 'Signature exata'),
        ('regex',     'Regex na signature'),
        ('classtype', 'Classtype'),
        ('categoria', 'Categoria Suricata'),
        ('fallback',  'Fallback (captura tudo)'),
    ]

    nome_interno  = models.CharField(max_length=100, unique=True)
    ativo         = models.BooleanField(default=True, db_index=True)
    prioridade    = models.IntegerField(default=50)
    versao        = models.CharField(max_length=20, default='1.0')

    tipo_match    = models.CharField(max_length=20, choices=TIPO_MATCH, default='sid')
    valor_match   = models.CharField(max_length=500, blank=True)

    titulo_jg     = models.CharField(max_length=200)
    resumo_jg     = models.TextField(blank=True)
    categoria_jg  = models.CharField(
        max_length=20, choices=CategoriaJG.choices, default=CategoriaJG.INFO,
    )
    severidade_jg = models.CharField(
        max_length=20, choices=SeveridadeJG.choices, default=SeveridadeJG.MEDIO,
    )
    tags_jg       = models.JSONField(default=list, blank=True)
    recomendacoes = models.JSONField(default=list, blank=True)

    criado_em     = models.DateTimeField(auto_now_add=True)
    atualizado_em = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"[{self.tipo_match}:{self.valor_match}] → {self.titulo_jg}"

    class Meta:
        verbose_name        = 'Regra de Mapeamento'
        verbose_name_plural = 'Regras de Mapeamento'
        ordering            = ['prioridade', 'id']
        indexes = [
            models.Index(fields=['ativo', 'prioridade'], name='idx_regra_ativo_prio'),
            models.Index(fields=['tipo_match'],           name='idx_regra_tipo'),
        ]


# ─────────────────────────────────────────────────────────────────────────────
# SUPRESSÃO
# ─────────────────────────────────────────────────────────────────────────────

class Supressao(models.Model):

    TIPO = [
        ('sid',       'SID'),
        ('signature', 'Signature (contém)'),
        ('ip_src',    'IP de origem'),
        ('ip_dst',    'IP de destino'),
        ('dominio',   'Domínio (DNS/TLS/HTTP)'),
        ('categoria', 'Categoria Suricata'),
        ('classtype', 'Classtype'),
    ]

    ESCOPO = [
        ('global', 'Global (todos os sensores)'),
        ('sensor', 'Sensor específico'),
    ]

    tipo      = models.CharField(max_length=20, choices=TIPO)
    valor     = models.CharField(max_length=500)
    escopo    = models.CharField(max_length=10, choices=ESCOPO, default='global')
    sensor    = models.ForeignKey(
        Sensor, null=True, blank=True, on_delete=models.CASCADE,
    )
    ativo     = models.BooleanField(default=True, db_index=True)
    expira_em = models.DateTimeField(null=True, blank=True)
    motivo    = models.TextField(blank=True)
    criado_em = models.DateTimeField(auto_now_add=True)
    criado_por= models.CharField(max_length=100, blank=True)

    def __str__(self):
        exp = f" até {self.expira_em:%d/%m/%Y %H:%M}" if self.expira_em else ' (permanente)'
        return f"Suprimir {self.tipo}={self.valor}{exp}"

    @property
    def expirado(self) -> bool:
        if not self.expira_em:
            return False
        return timezone.now() > self.expira_em

    class Meta:
        verbose_name        = 'Supressão'
        verbose_name_plural = 'Supressões'
        ordering            = ['-criado_em']
        indexes = [
            models.Index(fields=['ativo', 'tipo'], name='idx_sup_ativo_tipo'),
            models.Index(fields=['expira_em'],      name='idx_sup_expira'),
        ]


# ─────────────────────────────────────────────────────────────────────────────
# EVENTO BRUTO
# ─────────────────────────────────────────────────────────────────────────────

class EventoBruto(models.Model):

    TIPO = [
        ('alert', 'Alert'),
        ('dns',   'DNS'),
        ('http',  'HTTP'),
        ('tls',   'TLS'),
        ('outro', 'Outro'),
    ]

    sensor     = models.ForeignKey(
        Sensor, null=True, blank=True, on_delete=models.SET_NULL,
        related_name='eventos_brutos',
    )
    timestamp  = models.DateTimeField(db_index=True)
    event_type = models.CharField(max_length=10, choices=TIPO, default='outro', db_index=True)

    src_ip    = models.GenericIPAddressField(db_index=True)
    src_porta = models.IntegerField(null=True, blank=True)
    dest_ip   = models.GenericIPAddressField(null=True, blank=True)
    dest_porta= models.IntegerField(null=True, blank=True)
    protocolo = models.CharField(max_length=10, blank=True)

    sid        = models.CharField(max_length=20, blank=True, db_index=True)
    signature  = models.CharField(max_length=255, blank=True)
    categoria  = models.CharField(max_length=120, blank=True)
    severidade = models.CharField(max_length=20, blank=True)

    event_hash = models.CharField(max_length=64, unique=True, db_index=True)

    raw_json   = models.JSONField(null=True, blank=True)
    criado_em  = models.DateTimeField(auto_now_add=True)

    incidente  = models.ForeignKey(
        'Incidente',
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name='eventos_brutos',
    )

    @staticmethod
    def calcular_hash(src_ip, dest_ip, src_porta, dest_porta, protocolo, sid, timestamp, raw_json=None) -> str:
        ts      = timestamp.strftime('%Y%m%d%H%M%S%f') if timestamp else ''
        flow_id = str(raw_json.get('flow_id', '')) if raw_json else ''
        tx_id   = str(raw_json.get('tx_id',   '')) if raw_json else ''
        raw = f"{src_ip}|{dest_ip}|{src_porta}|{dest_porta}|{protocolo}|{sid}|{ts}|{flow_id}|{tx_id}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def __str__(self):
        return f"[{self.event_type}] {self.src_ip} → {self.dest_ip} | {self.sid or self.categoria}"

    class Meta:
        verbose_name        = 'Evento Bruto'
        verbose_name_plural = 'Eventos Brutos'
        ordering            = ['-timestamp']
        indexes = [
            models.Index(fields=['src_ip',     'timestamp'], name='idx_eb_srcip_ts'),
            models.Index(fields=['event_type', 'timestamp'], name='idx_eb_tipo_ts'),
            models.Index(fields=['sid',        'timestamp'], name='idx_eb_sid_ts'),
        ]


# ─────────────────────────────────────────────────────────────────────────────
# INCIDENTE
# ─────────────────────────────────────────────────────────────────────────────

class Incidente(models.Model):

    SEVERIDADE = [
        ('critico',     'Crítico'),
        ('alto',        'Alto'),
        ('medio',       'Médio'),
        ('baixo',       'Baixo'),
        ('informativo', 'Informativo'),
    ]
    STATUS = [
        ('novo',         'Novo'),
        ('investigando', 'Investigando'),
        ('resolvido',    'Resolvido'),
        ('falso',        'Falso Positivo'),
    ]
    DIRECTION = [
        ('inbound',  'Inbound'),
        ('outbound', 'Outbound'),
        ('lateral',  'Lateral'),
        ('external', 'External'),
        ('unknown',  'Unknown'),
    ]

    sensor    = models.ForeignKey(
        Sensor, null=True, blank=True, on_delete=models.SET_NULL,
    )

    fingerprint = models.CharField(max_length=64, db_index=True)

    ocorrencias = models.IntegerField(default=1)
    first_seen  = models.DateTimeField(db_index=True)
    last_seen   = models.DateTimeField(db_index=True)

    src_ip     = models.GenericIPAddressField(db_index=True)
    src_porta  = models.IntegerField(null=True, blank=True)
    dest_ip    = models.GenericIPAddressField(null=True, blank=True)
    dest_porta = models.IntegerField(null=True, blank=True)
    protocolo  = models.CharField(max_length=10, default='TCP')

    direction    = models.CharField(
        max_length=10, choices=DIRECTION, default='unknown', db_index=True,
    )
    src_is_local = models.BooleanField(default=False)
    dst_is_local = models.BooleanField(default=False)

    signature  = models.TextField()
    categoria  = models.CharField(max_length=120, blank=True)
    sid        = models.CharField(max_length=20,  blank=True)
    rev        = models.CharField(max_length=10,  blank=True)
    acao       = models.CharField(max_length=20,  default='alert')
    severidade = models.CharField(
        max_length=20, choices=SEVERIDADE, default='medio', db_index=True,
    )

    titulo_jg     = models.CharField(max_length=200, blank=True)
    resumo_jg     = models.TextField(blank=True)
    categoria_jg  = models.CharField(
        max_length=20,
        choices=CategoriaJG.choices,
        default=CategoriaJG.INFO,
        db_index=True,
    )
    severidade_jg = models.CharField(
        max_length=20,
        choices=SeveridadeJG.choices,
        default=SeveridadeJG.INFORMATIVO,
        db_index=True,
    )
    tags_jg        = models.JSONField(default=list, blank=True)
    recomendacoes  = models.JSONField(default=list, blank=True)
    regra_aplicada = models.ForeignKey(
        RegraDeMapeamento,
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name='incidentes',
    )

    pais        = models.CharField(max_length=100, blank=True)
    pais_codigo = models.CharField(max_length=5,   blank=True)
    cidade      = models.CharField(max_length=100, blank=True)
    latitude    = models.FloatField(null=True, blank=True)
    longitude   = models.FloatField(null=True, blank=True)
    asn_number  = models.CharField(max_length=20,  blank=True)
    asn_org     = models.CharField(max_length=200, blank=True)
    asn         = models.CharField(max_length=220, blank=True)
    rdns        = models.CharField(max_length=255, blank=True)

    risk_score = models.FloatField(default=0.0)

    status = models.CharField(
        max_length=20, choices=STATUS, default='novo', db_index=True,
    )
    nota   = models.TextField(blank=True)

    raw_json      = models.JSONField(null=True, blank=True)
    criado_em     = models.DateTimeField(auto_now_add=True)
    atualizado_em = models.DateTimeField(auto_now=True)

    @staticmethod
    def calcular_fingerprint(sensor_id, sid, src_ip, dest_ip, dest_porta) -> str:
        raw = f"{sensor_id}|{sid}|{src_ip}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def __str__(self):
        titulo = self.titulo_jg or self.signature
        return (
            f"[{self.severidade_jg.upper()}] {titulo} | "
            f"{self.src_ip} → {self.dest_ip} | "
            f"{self.ocorrencias}x"
        )

    @property
    def evidencia_principal(self) -> str:
        raw = self.raw_json or {}

        rrname = raw.get('dns', {}).get('rrname', '')
        if rrname:
            return f"DNS: {rrname} ({self.src_ip})"

        sni = raw.get('tls', {}).get('sni', '')
        if sni:
            dst = self.dest_ip or '?'
            return f"TLS: {sni} ({self.src_ip} → {dst})"

        hostname = raw.get('http', {}).get('hostname', '')
        if hostname:
            url = raw.get('http', {}).get('url', '')[:60]
            return f"HTTP: {self.src_ip} → {hostname}{url}"

        src = f"{self.src_ip}:{self.src_porta}"   if self.src_porta  else self.src_ip
        dst = f"{self.dest_ip}:{self.dest_porta}" if self.dest_porta else (self.dest_ip or '?')
        return f"{src} → {dst} ({self.protocolo})"

    class Meta:
        verbose_name        = 'Incidente'
        verbose_name_plural = 'Incidentes'
        ordering            = ['-last_seen']
        indexes = [
            models.Index(fields=['fingerprint', 'status'],         name='idx_inc_fp_status'),
            models.Index(fields=['first_seen'],                    name='idx_inc_first'),
            models.Index(fields=['last_seen'],                     name='idx_inc_last'),
            models.Index(fields=['src_ip',        'last_seen'],    name='idx_inc_srcip_ts'),
            models.Index(fields=['dest_ip',       'last_seen'],    name='idx_inc_dstip_ts'),
            models.Index(fields=['severidade',    'last_seen'],    name='idx_inc_sev_ts'),
            models.Index(fields=['severidade_jg', 'last_seen'],    name='idx_inc_sevjg_ts'),
            models.Index(fields=['categoria_jg',  'last_seen'],    name='idx_inc_catjg_ts'),
            models.Index(fields=['status',        'last_seen'],    name='idx_inc_status_ts'),
            models.Index(fields=['pais_codigo'],                   name='idx_inc_pais'),
            models.Index(fields=['sid'],                           name='idx_inc_sid'),
            models.Index(fields=['direction'],                     name='idx_inc_direction'),
        ]


# ─────────────────────────────────────────────────────────────────────────────
# EVENTO DNS
# ─────────────────────────────────────────────────────────────────────────────

class EventoDNS(models.Model):
    sensor     = models.ForeignKey(Sensor, null=True, blank=True, on_delete=models.SET_NULL)
    timestamp  = models.DateTimeField(db_index=True)
    src_ip     = models.GenericIPAddressField(db_index=True)
    src_porta  = models.IntegerField(null=True, blank=True)
    dest_ip    = models.GenericIPAddressField(null=True, blank=True)
    query      = models.TextField(blank=True, db_index=True)
    tipo       = models.CharField(max_length=10, blank=True)
    rcode      = models.CharField(max_length=20, blank=True)
    resposta   = models.TextField(blank=True)
    event_hash = models.CharField(max_length=64, blank=True, db_index=True)
    raw_json   = models.JSONField(null=True, blank=True)
    criado_em  = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"DNS {self.query} ({self.tipo}) de {self.src_ip}"

    @staticmethod
    def calcular_hash(src_ip, dest_ip, src_porta, query, tipo, timestamp) -> str:
        ts  = timestamp.strftime('%Y%m%d%H%M%S%f') if timestamp else ''
        raw = f"{src_ip}|{dest_ip}|{src_porta}|{query}|{tipo}|{ts}"
        return hashlib.sha256(raw.encode()).hexdigest()

    class Meta:
        verbose_name        = 'Evento DNS'
        verbose_name_plural = 'Eventos DNS'
        ordering            = ['-timestamp']
        constraints = [
            models.UniqueConstraint(
                fields=['event_hash'],
                name='uq_dns_event_hash',
                condition=models.Q(event_hash__gt=''),
            )
        ]
        indexes = [
            models.Index(fields=['src_ip', 'timestamp'], name='idx_dns_srcip_ts'),
            models.Index(fields=['rcode'],               name='idx_dns_rcode'),
        ]


# ─────────────────────────────────────────────────────────────────────────────
# EVENTO HTTP
# ─────────────────────────────────────────────────────────────────────────────

class EventoHTTP(models.Model):
    sensor        = models.ForeignKey(Sensor, null=True, blank=True, on_delete=models.SET_NULL)
    timestamp     = models.DateTimeField(db_index=True)
    src_ip        = models.GenericIPAddressField(db_index=True)
    src_porta     = models.IntegerField(null=True, blank=True)
    dest_ip       = models.GenericIPAddressField(null=True, blank=True)
    dest_porta    = models.IntegerField(null=True, blank=True)
    hostname      = models.CharField(max_length=255, blank=True, db_index=True)
    url           = models.TextField(blank=True)
    metodo        = models.CharField(max_length=10,  blank=True)
    user_agent    = models.TextField(blank=True)
    status_code   = models.IntegerField(null=True, blank=True)
    tamanho_bytes = models.IntegerField(null=True, blank=True)
    event_hash    = models.CharField(max_length=64, blank=True, db_index=True)
    raw_json      = models.JSONField(null=True, blank=True)
    criado_em     = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"HTTP {self.metodo} {self.hostname}{self.url}"

    @staticmethod
    def calcular_hash(src_ip, dest_ip, src_porta, dest_porta, metodo, hostname, url, timestamp) -> str:
        ts  = timestamp.strftime('%Y%m%d%H%M%S%f') if timestamp else ''
        raw = f"{src_ip}|{dest_ip}|{src_porta}|{dest_porta}|{metodo}|{hostname}|{url[:120]}|{ts}"
        return hashlib.sha256(raw.encode()).hexdigest()

    class Meta:
        verbose_name        = 'Evento HTTP'
        verbose_name_plural = 'Eventos HTTP'
        ordering            = ['-timestamp']
        constraints = [
            models.UniqueConstraint(
                fields=['event_hash'],
                name='uq_http_event_hash',
                condition=models.Q(event_hash__gt=''),
            )
        ]
        indexes = [
            models.Index(fields=['src_ip',   'timestamp'], name='idx_http_srcip_ts'),
            models.Index(fields=['hostname', 'timestamp'], name='idx_http_host_ts'),
        ]


# ─────────────────────────────────────────────────────────────────────────────
# EVENTO TLS
# ─────────────────────────────────────────────────────────────────────────────

class EventoTLS(models.Model):
    sensor      = models.ForeignKey(Sensor, null=True, blank=True, on_delete=models.SET_NULL)
    timestamp   = models.DateTimeField(db_index=True)
    src_ip      = models.GenericIPAddressField(db_index=True)
    src_porta   = models.IntegerField(null=True, blank=True)
    dest_ip     = models.GenericIPAddressField(null=True, blank=True)
    dest_porta  = models.IntegerField(null=True, blank=True)
    sni         = models.CharField(max_length=255, blank=True, db_index=True)
    versao      = models.CharField(max_length=20,  blank=True)
    issuer      = models.TextField(blank=True)
    subject     = models.TextField(blank=True)
    fingerprint = models.CharField(max_length=100, blank=True)
    ja3         = models.CharField(max_length=64,  blank=True)
    event_hash  = models.CharField(max_length=64,  blank=True, db_index=True)
    raw_json    = models.JSONField(null=True, blank=True)
    criado_em   = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"TLS {self.sni} de {self.src_ip}"

    @staticmethod
    def calcular_hash(src_ip, dest_ip, src_porta, dest_porta, sni, ja3, timestamp) -> str:
        ts  = timestamp.strftime('%Y%m%d%H%M%S%f') if timestamp else ''
        raw = f"{src_ip}|{dest_ip}|{src_porta}|{dest_porta}|{sni}|{ja3}|{ts}"
        return hashlib.sha256(raw.encode()).hexdigest()

    class Meta:
        verbose_name        = 'Evento TLS'
        verbose_name_plural = 'Eventos TLS'
        ordering            = ['-timestamp']
        constraints = [
            models.UniqueConstraint(
                fields=['event_hash'],
                name='uq_tls_event_hash',
                condition=models.Q(event_hash__gt=''),
            )
        ]
        indexes = [
            models.Index(fields=['src_ip', 'timestamp'], name='idx_tls_srcip_ts'),
            models.Index(fields=['sni',    'timestamp'], name='idx_tls_sni_ts'),
        ]