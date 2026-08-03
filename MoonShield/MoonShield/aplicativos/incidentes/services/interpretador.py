# =============================================================================
# incidentes/services/interpretador.py  v4
#
# Mudanças v4:
#   ✓ Log de eventos ignorados por tipo desconhecido
#   ✓ Log de falha no parse de timestamp (antes silencioso)
#   ✓ Sem mudanças na lógica — v3.1 estava correto
# =============================================================================

import logging
from datetime import datetime, timezone

from ..models import Incidente, EventoBruto, EventoDNS, EventoHTTP, EventoTLS

logger = logging.getLogger(__name__)

MAPA_SEVERIDADE = {
    1: 'critico',
    2: 'alto',
    3: 'medio',
    4: 'baixo',
}

TIPOS_SUPORTADOS = {'alert', 'dns', 'http', 'tls'}


# ─────────────────────────────────────────────────────────────────────────────
# FUNÇÃO PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

def interpretar_eventos(eventos_brutos: list, sensor_id=None) -> dict:
    resultado = {
        'alertas':      [],
        'eventos_dns':  [],
        'eventos_http': [],
        'eventos_tls':  [],
        'ignorados':    0,
    }

    for evento in eventos_brutos:
        tipo = evento.get('event_type', '').lower()

        if tipo not in TIPOS_SUPORTADOS:
            resultado['ignorados'] += 1
            logger.debug(f"Evento ignorado: event_type='{tipo}' não suportado")
            continue

        ts = _parsear_timestamp(evento.get('timestamp', ''))

        if tipo == 'alert':
            resultado['alertas'].append(_parsear_alerta(evento, ts, sensor_id))
        elif tipo == 'dns':
            resultado['eventos_dns'].append(_parsear_dns(evento, ts))
        elif tipo == 'http':
            resultado['eventos_http'].append(_parsear_http(evento, ts))
        elif tipo == 'tls':
            resultado['eventos_tls'].append(_parsear_tls(evento, ts))

    return resultado


# ─────────────────────────────────────────────────────────────────────────────
# PARSERS
# ─────────────────────────────────────────────────────────────────────────────

def _parsear_alerta(ev: dict, ts: datetime, sensor_id=None) -> dict:
    alerta    = ev.get('alert', {})
    sev_num   = alerta.get('severity', 3)
    src_ip    = ev.get('src_ip',   '0.0.0.0')
    dest_ip   = ev.get('dest_ip',  '') or None
    src_porta = ev.get('src_port')
    dst_porta = ev.get('dest_port')
    protocolo = ev.get('proto', 'TCP').upper()
    sid       = str(alerta.get('signature_id', ''))

    # classtype pode vir dentro de alert{} ou na raiz do evento
    classtype = (
        alerta.get('classtype', '')
        or alerta.get('class_type', '')
        or ev.get('classtype', '')
        or ''
    ).lower().strip()

    # Hash do evento EXATO (microssegundos + flow_id) → vai para EventoBruto
    event_hash = EventoBruto.calcular_hash(
        src_ip, dest_ip, src_porta, dst_porta, protocolo, sid, ts, raw_json=ev
    )

    # Fingerprint do TIPO de ataque (sem timestamp) → vai para Incidente
    fingerprint = Incidente.calcular_fingerprint(
        sensor_id, sid, src_ip, dest_ip, dst_porta
    )

    return {
        'timestamp':   ts,
        'event_type':  'alert',
        'src_ip':      src_ip,
        'src_porta':   src_porta,
        'dest_ip':     dest_ip,
        'dest_porta':  dst_porta,
        'protocolo':   protocolo,
        'signature':   alerta.get('signature', 'Desconhecida'),
        'categoria':   alerta.get('category', ''),
        'classtype':   classtype,
        'sid':         sid,
        'rev':         str(alerta.get('rev', '')),
        'acao':        alerta.get('action', 'alert'),
        'severidade':  MAPA_SEVERIDADE.get(sev_num, 'medio'),
        'event_hash':  event_hash,
        'fingerprint': fingerprint,
        'raw_json':    ev,
    }


def _parsear_dns(ev: dict, ts: datetime) -> dict:
    dns       = ev.get('dns', {})
    src_ip    = ev.get('src_ip',  '0.0.0.0')
    dest_ip   = ev.get('dest_ip', '') or None
    src_porta = ev.get('src_port')
    query     = dns.get('rrname', '')
    tipo      = dns.get('rrtype', '')
    respostas = dns.get('answers', [])
    ips_resp  = ', '.join(r.get('rdata', '') for r in respostas if r.get('rdata'))

    return {
        'timestamp':  ts,
        'src_ip':     src_ip,
        'src_porta':  src_porta,
        'dest_ip':    dest_ip,
        'query':      query,
        'tipo':       tipo,
        'rcode':      dns.get('rcode', ''),
        'resposta':   ips_resp,
        'event_hash': EventoDNS.calcular_hash(src_ip, dest_ip, src_porta, query, tipo, ts),
        'raw_json':   ev,
    }


def _parsear_http(ev: dict, ts: datetime) -> dict:
    http      = ev.get('http', {})
    src_ip    = ev.get('src_ip',   '0.0.0.0')
    dest_ip   = ev.get('dest_ip',  '') or None
    src_porta = ev.get('src_port')
    dst_porta = ev.get('dest_port')
    metodo    = http.get('http_method', 'GET').upper()
    hostname  = http.get('hostname', '')
    url       = http.get('url', '/')

    return {
        'timestamp':     ts,
        'src_ip':        src_ip,
        'src_porta':     src_porta,
        'dest_ip':       dest_ip,
        'dest_porta':    dst_porta,
        'hostname':      hostname,
        'url':           url,
        'metodo':        metodo,
        'user_agent':    http.get('http_user_agent', ''),
        'status_code':   http.get('status'),
        'tamanho_bytes': http.get('length'),
        'event_hash':    EventoHTTP.calcular_hash(
            src_ip, dest_ip, src_porta, dst_porta, metodo, hostname, url, ts
        ),
        'raw_json': ev,
    }


def _parsear_tls(ev: dict, ts: datetime) -> dict:
    tls       = ev.get('tls', {})
    src_ip    = ev.get('src_ip',   '0.0.0.0')
    dest_ip   = ev.get('dest_ip',  '') or None
    src_porta = ev.get('src_port')
    dst_porta = ev.get('dest_port')
    sni       = tls.get('sni', '')
    ja3_info  = tls.get('ja3', {})
    ja3_hash  = ja3_info.get('hash', '') if isinstance(ja3_info, dict) else ''

    return {
        'timestamp':   ts,
        'src_ip':      src_ip,
        'src_porta':   src_porta,
        'dest_ip':     dest_ip,
        'dest_porta':  dst_porta,
        'sni':         sni,
        'versao':      tls.get('version', ''),
        'issuer':      tls.get('issuerdn', ''),
        'subject':     tls.get('subject', ''),
        'fingerprint': tls.get('fingerprint', ''),
        'ja3':         ja3_hash,
        'event_hash':  EventoTLS.calcular_hash(
            src_ip, dest_ip, src_porta, dst_porta, sni, ja3_hash, ts
        ),
        'raw_json': ev,
    }


# ─────────────────────────────────────────────────────────────────────────────
# TIMESTAMP
# ─────────────────────────────────────────────────────────────────────────────

def _parsear_timestamp(ts_str: str) -> datetime:
    if not ts_str:
        return datetime.now(tz=timezone.utc)

    # Suricata às vezes manda offset sem ':' ex: +0300 → +03:00
    if len(ts_str) > 6 and ts_str[-5] in ('+', '-') and ':' not in ts_str[-5:]:
        ts_str = ts_str[:-2] + ':' + ts_str[-2:]

    try:
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        logger.warning(f"Timestamp inválido recebido: '{ts_str}' — usando now()")
        return datetime.now(tz=timezone.utc)