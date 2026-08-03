# =============================================================================
# incidentes/services/correlacionador.py  v6
#
# Mudanças v6:
#   ✓ _criar_incidente() agora salva regra_aplicada_id=alerta.get('regra_id')
# =============================================================================

import logging
import math
from datetime import timedelta

from django.db import IntegrityError, transaction
from django.db.models import Count as models_Count
from django.utils import timezone

from ..models import (
    EventoBruto, EventoDNS, EventoHTTP, EventoTLS,
    Incidente, RiskScore, JANELAS_CORRELACAO, JANELA_DEFAULT,
)

logger = logging.getLogger(__name__)

_PESO_SEV = {
    'critico': 10.0,
    'alto':     5.0,
    'medio':    2.0,
    'baixo':    0.5,
}

_HALFLIFE_HORAS = 24


# ─────────────────────────────────────────────────────────────────────────────
# PIPELINE PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

def consolidar_alertas(alertas: list, sensor) -> list:
    """
    Para cada alerta:
      1. Salva EventoBruto (log exato)
      2. Busca Incidente ativo com mesmo fingerprint dentro da janela
         — janela calculada a partir do timestamp DO ALERTA (não do servidor)
         — ordenado por -last_seen para pegar o mais recente
      3. Se existe → incrementa ocorrencias e atualiza last_seen
      4. Se não existe → cria novo Incidente
    """
    incidentes_tocados = []

    with transaction.atomic():
        for alerta in alertas:

            # ── 1. Salvar EventoBruto ─────────────────────────────────────────
            evento_bruto, duplicata = _salvar_evento_bruto(alerta, sensor)

            if evento_bruto is None:
                if duplicata:
                    logger.debug(
                        f"EventoBruto duplicado ignorado: hash={alerta.get('event_hash', '?')[:16]}"
                    )
                continue

            # ── 2. Calcular janela baseada no timestamp DO ALERTA ─────────────
            categoria_jg = alerta.get('categoria_jg', 'info')
            janela_min   = JANELAS_CORRELACAO.get(categoria_jg, JANELA_DEFAULT)
            ts_alerta    = alerta['timestamp']
            corte        = ts_alerta - timedelta(minutes=janela_min)

            fingerprint = alerta['fingerprint']

            # ── 3. Buscar incidente ativo ─────────────────────────────────────
            incidente = (
                Incidente.objects
                .filter(
                    fingerprint=fingerprint,
                    last_seen__gte=corte,
                )
                .exclude(status='resolvido')
                .order_by('-last_seen')
                .first()
            )

            if incidente:
                incidente.ocorrencias += 1
                incidente.last_seen    = ts_alerta
                incidente.save(update_fields=['ocorrencias', 'last_seen', 'atualizado_em'])
                logger.debug(
                    f"Incidente atualizado: id={incidente.pk} "
                    f"ocorrencias={incidente.ocorrencias} "
                    f"src={alerta['src_ip']}"
                )
            else:
                incidente = _criar_incidente(alerta, sensor, fingerprint)
                logger.info(
                    f"Incidente criado: id={incidente.pk} "
                    f"sid={alerta.get('sid','?')} "
                    f"src={alerta['src_ip']} "
                    f"sev={alerta.get('severidade_jg','?')}"
                )

            evento_bruto.incidente = incidente
            evento_bruto.save(update_fields=['incidente'])

            incidentes_tocados.append(incidente)

    return incidentes_tocados

def _salvar_evento_bruto(alerta: dict, sensor) -> tuple[EventoBruto | None, bool]:
    try:
        with transaction.atomic():  # ← savepoint — não corrompe a transação externa
            eb = EventoBruto.objects.create(
                sensor     = sensor,
                timestamp  = alerta['timestamp'],
                event_type = 'alert',
                src_ip     = alerta['src_ip'],
                src_porta  = alerta.get('src_porta'),
                dest_ip    = alerta.get('dest_ip'),
                dest_porta = alerta.get('dest_porta'),
                protocolo  = alerta.get('protocolo', 'TCP'),
                sid        = alerta.get('sid', ''),
                signature  = alerta.get('signature', ''),
                categoria  = alerta.get('categoria', ''),
                severidade = alerta.get('severidade', 'medio'),
                event_hash = alerta['event_hash'],
                raw_json   = alerta.get('raw_json'),
            )
            return eb, False

    except IntegrityError:
        return None, True

    except Exception as e:
        logger.error(
            f"Falha ao salvar EventoBruto: {e} | "
            f"src={alerta.get('src_ip','?')} "
            f"sid={alerta.get('sid','?')} "
            f"hash={alerta.get('event_hash','?')[:16]}"
        )
        return None, False


def _criar_incidente(alerta: dict, sensor, fingerprint: str) -> Incidente:
    ts = alerta['timestamp']
    return Incidente.objects.create(
        sensor             = sensor,
        fingerprint        = fingerprint,
        ocorrencias        = 1,
        first_seen         = ts,
        last_seen          = ts,
        src_ip             = alerta['src_ip'],
        src_porta          = alerta.get('src_porta'),
        dest_ip            = alerta.get('dest_ip'),
        dest_porta         = alerta.get('dest_porta'),
        protocolo          = alerta.get('protocolo', 'TCP'),
        signature          = alerta.get('signature', ''),
        categoria          = alerta.get('categoria', ''),
        sid                = alerta.get('sid', ''),
        rev                = alerta.get('rev', ''),
        acao               = alerta.get('acao', 'alert'),
        severidade         = alerta.get('severidade', 'medio'),
        titulo_jg          = alerta.get('titulo_jg', ''),
        resumo_jg          = alerta.get('resumo_jg', ''),
        categoria_jg       = alerta.get('categoria_jg', 'info'),
        severidade_jg      = alerta.get('severidade_jg', 'informativo'),
        tags_jg            = alerta.get('tags_jg', []),
        recomendacoes      = alerta.get('recomendacoes', []),
        regra_aplicada_id  = alerta.get('regra_id'),      # ← v6: salva FK da regra
        direction          = alerta.get('direction', 'unknown'),
        src_is_local       = alerta.get('src_is_local', False),
        dst_is_local       = alerta.get('dst_is_local', False),
        pais               = alerta.get('pais', ''),
        pais_codigo        = alerta.get('pais_codigo', ''),
        cidade             = alerta.get('cidade', ''),
        latitude           = alerta.get('latitude'),
        longitude          = alerta.get('longitude'),
        asn_number         = alerta.get('asn_number', ''),
        asn_org            = alerta.get('asn_org', ''),
        asn                = alerta.get('asn', ''),
        rdns               = alerta.get('rdns', ''),
        raw_json           = alerta.get('raw_json'),
        status             = 'novo',
    )


# ─────────────────────────────────────────────────────────────────────────────
# RISK SCORE com decaimento no persistido
# ─────────────────────────────────────────────────────────────────────────────

def atualizar_risk_score(incidentes_tocados: list):
    """
    Atualiza RiskScore por IP e snapshot no Incidente.

    Antes de somar, aplica decaimento no score persistido do RiskScore
    proporcional ao tempo desde o último alerta — impede acúmulo infinito.

    Fórmula:
      score_atual_decaido = score_salvo × e^(-horas_desde_ultimo / 24)
      score_novo = score_atual_decaido + contribuição_dos_novos_alertas
    """
    if not incidentes_tocados:
        return

    por_ip: dict = {}

    for inc in incidentes_tocados:
        ip = inc.src_ip

        horas        = (timezone.now() - inc.last_seen).total_seconds() / 3600
        fator_tempo  = math.exp(-horas / _HALFLIFE_HORAS)
        peso         = _PESO_SEV.get(inc.severidade, 1.0)
        contribuicao = peso * inc.ocorrencias * fator_tempo

        Incidente.objects.filter(pk=inc.pk).update(
            risk_score=round(min(contribuicao, 100.0), 1)
        )

        if ip not in por_ip:
            por_ip[ip] = {
                'score':    0.0,
                'total':    0,
                'criticos': 0,
                'altos':    0,
                'medios':   0,
                'ultimo':   inc.last_seen,
            }

        d = por_ip[ip]
        d['score']  += contribuicao
        d['total']  += 1
        if inc.severidade == 'critico': d['criticos'] += 1
        elif inc.severidade == 'alto':  d['altos']    += 1
        elif inc.severidade == 'medio': d['medios']   += 1
        if inc.last_seen and inc.last_seen > d['ultimo']:
            d['ultimo'] = inc.last_seen

    with transaction.atomic():
        for ip, d in por_ip.items():
            risk, _ = RiskScore.objects.get_or_create(ip=ip)

            if risk.ultimo_alerta:
                horas_desde_ultimo = (timezone.now() - risk.ultimo_alerta).total_seconds() / 3600
                fator_decaimento   = math.exp(-horas_desde_ultimo / _HALFLIFE_HORAS)
                risk.score         = round(risk.score * fator_decaimento, 1)

            risk.score         = round(min(risk.score + d['score'], 999.9), 1)
            risk.total_alertas += d['total']
            risk.criticos      += d['criticos']
            risk.altos         += d['altos']
            risk.medios        += d['medios']
            if d['ultimo']:
                risk.ultimo_alerta = d['ultimo']

            risk.save(update_fields=[
                'score', 'total_alertas', 'criticos', 'altos',
                'medios', 'ultimo_alerta', 'updated_at',
            ])


# ─────────────────────────────────────────────────────────────────────────────
# CORRELAÇÃO POR JANELA (drawer de um incidente)
# ─────────────────────────────────────────────────────────────────────────────

def correlacionar_incidente(incidente, janela_minutos: int = 5) -> dict:
    ip     = incidente.src_ip
    inicio = incidente.first_seen - timedelta(minutes=janela_minutos)
    fim    = incidente.last_seen  + timedelta(minutes=janela_minutos)

    dns  = EventoDNS.objects.filter(src_ip=ip,  timestamp__range=(inicio, fim)).order_by('timestamp')
    http = EventoHTTP.objects.filter(src_ip=ip, timestamp__range=(inicio, fim)).order_by('timestamp')
    tls  = EventoTLS.objects.filter(src_ip=ip,  timestamp__range=(inicio, fim)).order_by('timestamp')

    return {
        'dns':    dns,
        'http':   http,
        'tls':    tls,
        'resumo': _montar_resumo(dns, http, tls),
    }


# ─────────────────────────────────────────────────────────────────────────────
# CONTEXTO IP
# ─────────────────────────────────────────────────────────────────────────────

def contexto_ip(src_ip: str, horas: int = 24) -> dict:
    desde = timezone.now() - timedelta(hours=horas)

    alertas = Incidente.objects.filter(src_ip=src_ip, last_seen__gte=desde).order_by('-last_seen')
    dns     = EventoDNS.objects.filter(src_ip=src_ip,  timestamp__gte=desde).order_by('-timestamp')
    http    = EventoHTTP.objects.filter(src_ip=src_ip, timestamp__gte=desde).order_by('-timestamp')
    tls     = EventoTLS.objects.filter(src_ip=src_ip,  timestamp__gte=desde).order_by('-timestamp')

    risk = RiskScore.objects.filter(ip=src_ip).first()

    direction_counts = {}
    for row in alertas.values('direction').annotate(n=models_Count('direction')):
        direction_counts[row['direction']] = row['n']

    return {
        'alertas_recentes': list(alertas.values(
            'id', 'first_seen', 'last_seen', 'ocorrencias', 'severidade',
            'signature', 'categoria', 'sid', 'direction', 'dest_ip',
            'dest_porta', 'protocolo', 'pais_codigo', 'asn_org',
            'status', 'risk_score',
        )[:20]),
        'top_sids': list(
            alertas.values('sid', 'signature')
            .annotate(n=models_Count('sid'))
            .order_by('-n')[:10]
        ),
        'top_categorias': list(
            alertas.values('categoria')
            .annotate(n=models_Count('categoria'))
            .order_by('-n')[:5]
        ),
        'total_alertas': alertas.count(),

        'dns_recentes': list(dns.values(
            'id', 'timestamp', 'query', 'tipo', 'rcode', 'resposta',
        )[:20]),
        'top_dominios': list(
            dns.values('query')
            .annotate(n=models_Count('query'))
            .order_by('-n')[:10]
        ),
        'nxdomains':  dns.filter(rcode='NXDOMAIN').count(),
        'total_dns':  dns.count(),

        'http_recentes': list(http.values(
            'id', 'timestamp', 'metodo', 'hostname', 'url',
            'status_code', 'user_agent', 'tamanho_bytes',
        )[:20]),
        'top_hosts': list(
            http.values('hostname')
            .annotate(n=models_Count('hostname'))
            .order_by('-n')[:10]
        ),
        'top_user_agents': list(
            http.values('user_agent')
            .annotate(n=models_Count('user_agent'))
            .order_by('-n')[:5]
        ),
        'total_http': http.count(),

        'tls_recentes': list(tls.values(
            'id', 'timestamp', 'sni', 'versao', 'ja3', 'fingerprint',
        )[:20]),
        'top_snis': list(
            tls.values('sni')
            .annotate(n=models_Count('sni'))
            .order_by('-n')[:10]
        ),
        'total_tls': tls.count(),

        'risk_score':       risk.score if risk else 0.0,
        'direction_counts': direction_counts,
        'janela_horas':     horas,
    }


# ─────────────────────────────────────────────────────────────────────────────
# CORRELAÇÃO POR IP
# ─────────────────────────────────────────────────────────────────────────────

def correlacionar_por_ip(src_ip: str, limite: int = 50) -> dict:
    dns  = EventoDNS.objects.filter(src_ip=src_ip).order_by('-timestamp')[:limite]
    http = EventoHTTP.objects.filter(src_ip=src_ip).order_by('-timestamp')[:limite]
    tls  = EventoTLS.objects.filter(src_ip=src_ip).order_by('-timestamp')[:limite]

    return {
        'dns':    dns,
        'http':   http,
        'tls':    tls,
        'resumo': _montar_resumo(dns, http, tls),
    }


# ─────────────────────────────────────────────────────────────────────────────
# RESUMO INTERNO
# ─────────────────────────────────────────────────────────────────────────────

def _montar_resumo(dns, http, tls) -> dict:
    dominios    = list(dns.values_list('query',       flat=True).distinct()[:20])
    hosts_http  = list(http.values_list('hostname',   flat=True).distinct()[:20])
    snis_tls    = list(tls.values_list('sni',         flat=True).distinct()[:20])
    user_agents = list(http.values_list('user_agent', flat=True).distinct()[:10])
    nxdomains   = dns.filter(rcode='NXDOMAIN').count()

    return {
        'total_dns':   dns.count(),
        'total_http':  http.count(),
        'total_tls':   tls.count(),
        'dominios':    [d for d in dominios    if d],
        'hosts_http':  [h for h in hosts_http  if h],
        'snis_tls':    [s for s in snis_tls    if s],
        'nxdomains':   nxdomains,
        'user_agents': [u for u in user_agents if u],
    }


# ─────────────────────────────────────────────────────────────────────────────
# COMPATIBILIDADE
# ─────────────────────────────────────────────────────────────────────────────

def noise_filter(alertas: list, **kwargs) -> list:
    """DEPRECIADO. Use consolidar_alertas() no consumidor."""
    return alertas