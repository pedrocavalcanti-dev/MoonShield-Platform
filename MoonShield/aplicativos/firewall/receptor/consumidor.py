# =============================================================================
# firewall/receptor/consumidor.py
#
# Endpoint de ingestão de eventos nftables vindos do ms_firewall.py.
#
# Reutiliza incidentes.Sensor para autenticação por token —
# mesmo sensor pode rodar IDS + Firewall em paralelo.
#
# POST /firewall/api/ingest/
# Header: X-MS-TOKEN: <token>
# Body:
# {
#   "sensor": "nome-do-sensor",
#   "eventos": [...],
#   "interfaces": [                 ← opcional, enviado no heartbeat
#     {"nome": "enp0s3", "ip": "10.53.49.100", "mac": "aa:bb:cc", "up": true}
#   ]
# }
# =============================================================================

import ipaddress
import hmac
import json
import logging
import re
from datetime import datetime, timezone as dt_tz

from django.db import transaction
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from ..models import EventoFirewall

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# MAPA DE AÇÕES
# nftables LOG  → tráfego que passou = ALLOW
# nftables DROP → silencioso         = DROP
# nftables REJECT → com resposta     = DENY
# ─────────────────────────────────────────────────────────────────────────────

_ACAO_MAP = {
    'LOG':    'ALLOW',
    'DROP':   'DROP',
    'REJECT': 'DENY',
}


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _validar_ip(ip: str) -> str | None:
    """Valida IP. Retorna None se inválido (em vez de '0.0.0.0')."""
    if not ip:
        return None
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        logger.debug(f"IP inválido ignorado: '{ip}'")
        return None


def _parse_timestamp(ts_str) -> datetime:
    """
    Aceita:
      - ISO completo:  '2025-02-22T14:30:22.123456'
      - Só hora:       '14:30:22'
      - Fallback:       timezone.now()
    """
    if not ts_str:
        return timezone.now()
    # Tenta ISO
    try:
        dt = datetime.fromisoformat(str(ts_str))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=dt_tz.utc)
        return dt
    except (ValueError, TypeError):
        pass
    # Tenta HH:MM:SS — combina com hoje
    try:
        t   = datetime.strptime(str(ts_str), '%H:%M:%S').time()
        now = timezone.now()
        return now.replace(hour=t.hour, minute=t.minute, second=t.second, microsecond=0)
    except (ValueError, TypeError):
        pass
    return timezone.now()


def _obter_sensor_configurado(sensor_nome: str):
    """
    Procura apenas sensores provisionados pelo fluxo local/operator.
    """
    try:
        from incidentes.models import Sensor
    except ImportError:
        logger.warning('App incidentes não encontrado — processando sem Sensor.')
        return None

    try:
        sensor = Sensor.objects.filter(nome=sensor_nome).order_by('-last_seen').first()
        return sensor

    except Sensor.MultipleObjectsReturned:
        logger.warning(
            f"Múltiplos sensores com nome '{sensor_nome}'. Usando o mais recente."
        )
        sensor = (
            Sensor.objects
            .filter(nome=sensor_nome)
            .order_by('-last_seen')
            .first()
        )
        return sensor


def _validar_token(sensor, token_recv: str):
    """
    Valida o token X-MS-TOKEN enviado pelo sensor.
    Retorna None se OK, ou JsonResponse de erro se inválido.

    O endpoint não provisiona sensores nem recupera tokens a partir de pedidos
    não autenticados. A rotação deve ocorrer por fluxo administrativo local.
    """
    if sensor is None or not token_recv or not hmac.compare_digest(token_recv, sensor.token):
        logger.warning(f"Token inválido para sensor '{sensor.nome}'.")
        return JsonResponse(
            {'ok': False, 'error': 'Token inválido. Acesso negado.'},
            status=403,
        )

    return None   # tudo OK


# ─────────────────────────────────────────────────────────────────────────────
# PROCESSAMENTO DO LOTE
# ─────────────────────────────────────────────────────────────────────────────

def _processar_lote(eventos_raw: list, sensor) -> dict:
    """
    Parseia, valida e persiste eventos nftables em bulk.
    Retorna resumo do processamento.
    """
    objs      = []
    ignorados = 0

    for ev in eventos_raw:
        src_ip = _validar_ip(ev.get('src_ip', ''))
        if not src_ip:
            ignorados += 1
            continue

        dst_ip_raw = _validar_ip(ev.get('dst_ip', ''))

        ts       = _parse_timestamp(ev.get('timestamp'))
        prefixo  = ev.get('prefixo', 'MS-FWD')
        proto    = (ev.get('proto') or '').upper()
        acao_raw = (ev.get('acao') or 'LOG').upper()
        acao     = _ACAO_MAP.get(acao_raw, 'ALLOW')

        src_port = ev.get('src_port')
        dst_port = ev.get('dst_port')

        event_hash = EventoFirewall.calcular_hash(
            src_ip, dst_ip_raw, src_port, dst_port, proto, ts, prefixo,
        )

        objs.append(EventoFirewall(
            sensor      = sensor,
            timestamp   = ts,
            acao        = acao,
            chain       = ev.get('chain', ''),
            proto       = proto,
            src_ip      = src_ip,
            src_port    = src_port,
            dst_ip      = dst_ip_raw,
            dst_port    = dst_port,
            iface       = ev.get('iface_entrada', ''),
            iface_saida = ev.get('iface_saida', ''),
            tamanho     = ev.get('tamanho'),
            ttl         = ev.get('ttl'),
            flags_tcp   = ev.get('flags_tcp', ''),
            prefixo     = prefixo,
            event_hash  = event_hash,
            raw_json    = ev,
        ))

    with transaction.atomic():
        criados = EventoFirewall.objects.bulk_create(objs, ignore_conflicts=True)

    sensor_nome = sensor.nome if sensor else 'desconhecido'
    logger.info(
        f"[fw/{sensor_nome}] lote: "
        f"{len(criados)} salvos | {ignorados} ignorados | "
        f"{len(objs) - len(criados)} duplicados"
    )

    return {
        'salvos':     len(criados),
        'ignorados':  ignorados,
        'duplicados': len(objs) - len(criados),
    }


# ─────────────────────────────────────────────────────────────────────────────
# VIEW — endpoint
# ─────────────────────────────────────────────────────────────────────────────

@csrf_exempt
@require_POST
def receber_eventos(request):
    """Ingestão de serviço, autenticada por token de sensor provisionado."""
    try:
        payload = json.loads(request.body.decode('utf-8') or '{}')
        if not isinstance(payload, dict):
            return JsonResponse({'ok': False, 'error': 'Corpo JSON inválido.'}, status=400)
        eventos = payload.get('eventos', [])
        sensor_nome = payload.get('sensor', '')
        if not isinstance(sensor_nome, str):
            return JsonResponse({'ok': False, 'error': 'Sensor inválido.'}, status=400)
        sensor_nome = sensor_nome.strip()
        if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,100}', sensor_nome):
            return JsonResponse({'ok': False, 'error': 'Sensor inválido.'}, status=400)
        token_recv  = request.headers.get('X-MS-TOKEN', '').strip()

        if not isinstance(eventos, list) or any(not isinstance(evento, dict) for evento in eventos):
            return JsonResponse(
                {'ok': False, 'error': "campo 'eventos' deve ser uma lista de objetos"},
                status=400,
            )

        # IP de origem do sensor
        ip_raw    = (
            request.META.get('REMOTE_ADDR', '0.0.0.0')
        )
        ip_origem = _validar_ip(ip_raw) or '0.0.0.0'

        # ── Sensor ──────────────────────────────────────────────────────────
        sensor = _obter_sensor_configurado(sensor_nome)
        if sensor is None:
            return JsonResponse({'ok': False, 'error': 'Sensor não autorizado.'}, status=403)

        erro_token = _validar_token(sensor, token_recv)
        if erro_token:
            return erro_token

        agora_ts = timezone.now()
        campos = ['last_seen']
        sensor.last_seen = agora_ts
        if sensor.ip != ip_origem:
            sensor.ip = ip_origem
            campos.append('ip')
        sensor.save(update_fields=campos)


        # ── Heartbeat (lote vazio) ───────────────────────────────────────────
        if not eventos:
            logger.debug(f"[fw/{sensor_nome}] heartbeat")

            # Salva interfaces enviadas pelo sensor, se existirem
            interfaces = payload.get('interfaces', [])
            if interfaces and sensor:
                sensor.interfaces = interfaces
                sensor.save(update_fields=['interfaces', 'last_seen'])

            return JsonResponse({
                'ok':          True,
                'sensor':      sensor_nome,
                'novo_sensor': False,
                'heartbeat':   True,
                'last_seen':   agora_ts.isoformat(),
            })

        # ── Pipeline ────────────────────────────────────────────────────────
        logger.info(
            f"[fw/{sensor_nome}] ingest recebido: "
            f"{len(eventos)} eventos de {ip_origem}"
        )
        resumo = _processar_lote(eventos, sensor)

        return JsonResponse({
            'ok':          True,
            'sensor':      sensor_nome,
            'novo_sensor': False,
            'last_seen':   agora_ts.isoformat(),
            **resumo,
        })

    except json.JSONDecodeError:
        return JsonResponse({'ok': False, 'error': 'JSON inválido'}, status=400)
    except Exception as exc:
        logger.exception('Erro no ingest do firewall')
        return JsonResponse({'ok': False, 'error': 'Falha interna ao processar eventos.'}, status=500)
