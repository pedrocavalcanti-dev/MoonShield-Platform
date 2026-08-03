# =============================================================================
# incidentes/admin.py
#
# Registra todos os modelos do módulo incidentes no Django Admin.
# Inclui:
#   • RegraDeMapeamento — catálogo de tradução MS (editável pelo admin)
#   • Supressao         — regras de silêncio
#   • Incidente         — somente leitura (consolidado v4)
#   • EventoBruto       — somente leitura (log técnico completo)
#   • EventoDNS / HTTP / TLS — somente leitura
#   • GeoCache, RiskScore, Sensor
#
# Campos corrigidos para o models v4:
#   Incidente NÃO tem: timestamp, event_hash
#   Incidente TEM:     first_seen, last_seen, fingerprint, ocorrencias
# =============================================================================

from django.contrib import admin
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.utils.html import format_html

from .models import (
    Incidente, EventoBruto, EventoDNS, EventoHTTP, EventoTLS,
    GeoCache, RiskScore, Sensor,
    RegraDeMapeamento, Supressao,
)


# ─────────────────────────────────────────────────────────────────────────────
# SIGNALS — invalida cache do tradutor quando regras mudam
# ─────────────────────────────────────────────────────────────────────────────

def _invalidar_cache_tradutor(sender, **kwargs):
    try:
        from .services.tradutor import resetar_cache
        resetar_cache()
    except Exception:
        pass


post_save.connect(_invalidar_cache_tradutor,   sender=RegraDeMapeamento)
post_delete.connect(_invalidar_cache_tradutor, sender=RegraDeMapeamento)
post_save.connect(_invalidar_cache_tradutor,   sender=Supressao)
post_delete.connect(_invalidar_cache_tradutor, sender=Supressao)


# ─────────────────────────────────────────────────────────────────────────────
# REGRA DE MAPEAMENTO
# ─────────────────────────────────────────────────────────────────────────────

@admin.register(RegraDeMapeamento)
class RegraDeMapeamentoAdmin(admin.ModelAdmin):
    list_display = (
        'prioridade', 'nome_interno', 'tipo_match', 'valor_match_curto',
        'titulo_jg', 'badge_categoria', 'badge_severidade', 'ativo',
    )
    list_display_links = ('nome_interno',)
    list_editable      = ('prioridade', 'ativo')
    list_filter        = ('ativo', 'tipo_match', 'categoria_jg', 'severidade_jg')
    search_fields      = ('nome_interno', 'titulo_jg', 'valor_match', 'resumo_jg')
    ordering           = ('prioridade', 'nome_interno')

    fieldsets = (
        ('Identificação', {
            'fields': ('nome_interno', 'ativo', 'prioridade', 'versao'),
        }),
        ('Condição de Match', {
            'fields': ('tipo_match', 'valor_match'),
            'description': (
                '<b>SID:</b> número exato (ex: 9900005) · '
                '<b>Signature:</b> texto exato · '
                '<b>Regex:</b> expressão Python · '
                '<b>Classtype/Categoria:</b> valor exato · '
                '<b>Fallback:</b> deixe valor_match vazio'
            ),
        }),
        ('Saída MS (o que o usuário vê)', {
            'fields': ('titulo_jg', 'resumo_jg', 'categoria_jg', 'severidade_jg'),
        }),
        ('Tags e Recomendações', {
            'fields': ('tags_jg', 'recomendacoes'),
            'classes': ('collapse',),
        }),
    )

    @admin.display(description='Match')
    def valor_match_curto(self, obj):
        return obj.valor_match[:40] if obj.valor_match else '—'

    @admin.display(description='Categoria')
    def badge_categoria(self, obj):
        cores = {
            'recon':    '#6366f1', 'auth':    '#ef4444', 'dns':     '#3b82f6',
            'web':      '#f59e0b', 'tls':     '#8b5cf6', 'p2p':     '#f97316',
            'malware':  '#dc2626', 'exfil':   '#b91c1c', 'lateral': '#7c3aed',
            'anomalia': '#0891b2', 'infra':   '#059669', 'info':    '#6b7280',
        }
        cor = cores.get(obj.categoria_jg, '#6b7280')
        return format_html(
            '<span style="background:{};color:#fff;padding:2px 8px;'
            'border-radius:9999px;font-size:11px">{}</span>',
            cor, obj.get_categoria_jg_display()
        )

    @admin.display(description='Severidade')
    def badge_severidade(self, obj):
        cores = {
            'critico':     '#dc2626',
            'alto':        '#f97316',
            'medio':       '#f59e0b',
            'baixo':       '#6b7280',
            'informativo': '#9ca3af',
        }
        cor = cores.get(obj.severidade_jg, '#6b7280')
        return format_html(
            '<span style="background:{};color:#fff;padding:2px 8px;'
            'border-radius:9999px;font-size:11px">{}</span>',
            cor, obj.get_severidade_jg_display()
        )

    actions = ['popular_builtin']

    @admin.action(description='Popular regras builtin (seed inicial)')
    def popular_builtin(self, request, queryset):
        from .services.tradutor import popular_regras_builtin
        resultado = popular_regras_builtin(sobrescrever=False)
        self.message_user(
            request,
            f"Builtin: {resultado['criadas']} criadas, {resultado['atualizadas']} já existiam."
        )


# ─────────────────────────────────────────────────────────────────────────────
# SUPRESSÃO
# ─────────────────────────────────────────────────────────────────────────────

@admin.register(Supressao)
class SupressaoAdmin(admin.ModelAdmin):
    list_display = (
        'tipo', 'valor', 'escopo', 'sensor',
        'expira_em', 'motivo', 'ativo', 'criado_em',
    )
    list_display_links = ('tipo', 'valor')
    list_editable      = ('ativo',)
    list_filter        = ('ativo', 'tipo', 'escopo')
    search_fields      = ('valor', 'motivo')
    ordering           = ('-criado_em',)

    fieldsets = (
        ('Regra de Silêncio', {
            'fields': ('tipo', 'valor', 'escopo', 'sensor'),
        }),
        ('Duração', {
            'fields': ('expira_em',),
            'description': 'Deixe em branco para supressão permanente.',
        }),
        ('Contexto', {
            'fields': ('motivo', 'criado_por', 'ativo'),
        }),
    )


# ─────────────────────────────────────────────────────────────────────────────
# SENSOR
# ─────────────────────────────────────────────────────────────────────────────

@admin.register(Sensor)
class SensorAdmin(admin.ModelAdmin):
    list_display    = ('nome', 'ip', 'ativo', 'status_online', 'last_seen', 'criado_em')
    list_filter     = ('ativo',)
    search_fields   = ('nome', 'ip')
    readonly_fields = ('criado_em',)

    @admin.display(description='Online', boolean=True)
    def status_online(self, obj):
        return obj.online


# ─────────────────────────────────────────────────────────────────────────────
# INCIDENTE — consolidado v4
# Campos existentes: first_seen, last_seen, fingerprint, ocorrencias
# Campos REMOVIDOS do Incidente: timestamp, event_hash
# ─────────────────────────────────────────────────────────────────────────────

@admin.register(Incidente)
class IncidenteAdmin(admin.ModelAdmin):
    list_display = (
        'last_seen', 'badge_sev_jg', 'titulo_jg_curto', 'badge_cat_jg',
        'src_ip', 'ocorrencias', 'sensor', 'status', 'sid',
    )
    list_filter    = ('severidade_jg', 'categoria_jg', 'status', 'sensor', 'direction')
    search_fields  = ('titulo_jg', 'signature', 'src_ip', 'dest_ip', 'sid', 'fingerprint')
    ordering       = ('-last_seen',)
    date_hierarchy = 'last_seen'

    readonly_fields = (
        # Consolidação
        'fingerprint', 'ocorrencias', 'first_seen', 'last_seen',
        # Campos JG
        'titulo_jg', 'resumo_jg', 'categoria_jg', 'severidade_jg',
        'tags_jg', 'recomendacoes', 'regra_aplicada',
        # Técnico Suricata
        'signature', 'sid', 'rev', 'acao', 'categoria', 'severidade',
        # Rede
        'src_ip', 'src_porta', 'dest_ip', 'dest_porta',
        'protocolo', 'direction', 'src_is_local', 'dst_is_local',
        # GeoIP
        'pais', 'pais_codigo', 'cidade', 'latitude', 'longitude',
        'asn_number', 'asn_org', 'asn', 'rdns',
        # Outros
        'risk_score', 'sensor', 'raw_json',
        'criado_em', 'atualizado_em',
    )

    fieldsets = (
        ('Consolidação', {
            'fields': ('fingerprint', 'ocorrencias', 'first_seen', 'last_seen'),
            'description': 'Um incidente agrupa múltiplas ocorrências do mesmo comportamento.',
        }),
        ('Alerta MS (visão do usuário)', {
            'fields': (
                'titulo_jg', 'resumo_jg', 'categoria_jg', 'severidade_jg',
                'tags_jg', 'recomendacoes', 'regra_aplicada',
            ),
        }),
        ('Gestão', {
            'fields': ('status', 'nota'),
        }),
        ('Técnico — Suricata', {
            'fields': (
                'signature', 'sid', 'rev', 'acao', 'categoria', 'severidade',
                'src_ip', 'src_porta', 'dest_ip', 'dest_porta',
                'protocolo', 'direction', 'src_is_local', 'dst_is_local',
            ),
            'classes': ('collapse',),
        }),
        ('GeoIP', {
            'fields': (
                'pais', 'pais_codigo', 'cidade',
                'latitude', 'longitude',
                'asn_number', 'asn_org', 'asn', 'rdns',
            ),
            'classes': ('collapse',),
        }),
        ('Risk Score', {
            'fields': ('risk_score',),
            'classes': ('collapse',),
        }),
        ('Raw JSON', {
            'fields': ('raw_json',),
            'classes': ('collapse',),
        }),
    )

    @admin.display(description='Sev JG')
    def badge_sev_jg(self, obj):
        cores = {
            'critico':     '#dc2626',
            'alto':        '#f97316',
            'medio':       '#f59e0b',
            'baixo':       '#6b7280',
            'informativo': '#9ca3af',
        }
        cor = cores.get(obj.severidade_jg, '#6b7280')
        return format_html(
            '<span style="background:{};color:#fff;padding:2px 8px;'
            'border-radius:9999px;font-size:11px">{}</span>',
            cor, obj.get_severidade_jg_display()
        )

    @admin.display(description='Categoria JG')
    def badge_cat_jg(self, obj):
        return obj.get_categoria_jg_display()

    @admin.display(description='Título')
    def titulo_jg_curto(self, obj):
        titulo = obj.titulo_jg or obj.signature
        return titulo[:55] + '…' if len(titulo) > 55 else titulo


# ─────────────────────────────────────────────────────────────────────────────
# EVENTO BRUTO — log técnico completo (tem timestamp e event_hash)
# ─────────────────────────────────────────────────────────────────────────────

@admin.register(EventoBruto)
class EventoBrutoAdmin(admin.ModelAdmin):
    list_display    = (
        'timestamp', 'event_type', 'src_ip', 'dest_ip',
        'sid', 'categoria', 'sensor', 'incidente',
    )
    list_filter     = ('event_type', 'sensor')
    search_fields   = ('src_ip', 'dest_ip', 'sid', 'signature', 'event_hash')
    ordering        = ('-timestamp',)
    date_hierarchy  = 'timestamp'
    readonly_fields = [f.name for f in EventoBruto._meta.fields] + ['incidente']


# ─────────────────────────────────────────────────────────────────────────────
# EVENTOS DNS / HTTP / TLS — somente leitura
# ─────────────────────────────────────────────────────────────────────────────

@admin.register(EventoDNS)
class EventoDNSAdmin(admin.ModelAdmin):
    list_display    = ('timestamp', 'src_ip', 'query', 'tipo', 'rcode', 'sensor')
    list_filter     = ('tipo', 'rcode', 'sensor')
    search_fields   = ('src_ip', 'query')
    ordering        = ('-timestamp',)
    date_hierarchy  = 'timestamp'
    readonly_fields = [f.name for f in EventoDNS._meta.fields]


@admin.register(EventoHTTP)
class EventoHTTPAdmin(admin.ModelAdmin):
    list_display    = ('timestamp', 'src_ip', 'metodo', 'hostname', 'url_curta', 'status_code', 'sensor')
    list_filter     = ('metodo', 'status_code', 'sensor')
    search_fields   = ('src_ip', 'hostname', 'url', 'user_agent')
    ordering        = ('-timestamp',)
    date_hierarchy  = 'timestamp'
    readonly_fields = [f.name for f in EventoHTTP._meta.fields]

    @admin.display(description='URL')
    def url_curta(self, obj):
        return obj.url[:60] if obj.url else ''


@admin.register(EventoTLS)
class EventoTLSAdmin(admin.ModelAdmin):
    list_display    = ('timestamp', 'src_ip', 'sni', 'versao', 'ja3_curto', 'sensor')
    list_filter     = ('versao', 'sensor')
    search_fields   = ('src_ip', 'sni', 'ja3', 'fingerprint')
    ordering        = ('-timestamp',)
    date_hierarchy  = 'timestamp'
    readonly_fields = [f.name for f in EventoTLS._meta.fields]

    @admin.display(description='JA3')
    def ja3_curto(self, obj):
        return obj.ja3[:16] if obj.ja3 else ''


# ─────────────────────────────────────────────────────────────────────────────
# GEO CACHE e RISK SCORE
# ─────────────────────────────────────────────────────────────────────────────

@admin.register(GeoCache)
class GeoCacheAdmin(admin.ModelAdmin):
    list_display  = ('ip', 'pais_codigo', 'pais', 'cidade', 'asn_number', 'asn_org', 'source', 'updated_at')
    search_fields = ('ip', 'pais', 'asn_org')
    ordering      = ('-updated_at',)


@admin.register(RiskScore)
class RiskScoreAdmin(admin.ModelAdmin):
    list_display  = ('ip', 'score', 'total_alertas', 'criticos', 'altos', 'medios', 'ultimo_alerta')
    ordering      = ('-score',)
    search_fields = ('ip',)