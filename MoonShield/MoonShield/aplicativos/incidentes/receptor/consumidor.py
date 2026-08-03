# =============================================================================
# incidentes/receptor/consumidor.py  v5.2
#
# Mudanças v5.2:
#   ✓ Auto-recovery de token INVÁLIDO: quando o sensor manda um token que não
#     bate com o banco, o servidor aceita e emite um novo token no response.
#     Isso resolve o loop de 403 após restart/downtime prolongado.
#   ✓ Lógica: se o sensor já existe E o token recebido é não-vazio E errado,
#     o servidor regenera o token, salva e devolve no body do 200 (aceita
#     o lote) em vez de rejeitar — o sensor vai salvar o novo token
#     automaticamente via _enviar() do sensor.py.
#   ✓ Mantido: token AUSENTE ainda dispara re-bootstrap com 403 + novo token.
# =============================================================================

import ipaddress
import json
import logging
import uuid

from django.db import transaction
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from ..models import EventoDNS, EventoHTTP, EventoTLS, Sensor
from ..services.interpretador import interpretar_eventos
from ..services.enriquecedor import enriquecer_ip, calcular_direction
from ..services.correlacionador import consolidar_alertas, atualizar_risk_score
from ..services.tradutor import traduzir

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _validar_ip(ip: str) -> str:
    if not ip:
        return '0.0.0.0'
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        logger.warning(f"IP de origem inválido recebido: '{ip}' — substituído por 0.0.0.0")
        return '0.0.0.0'


def _obter_sensor(sensor_nome: str, ip_origem: str) -> tuple[Sensor, bool]:
    try:
        sensor, created = Sensor.objects.get_or_create(
            nome=sensor_nome,
            defaults={
                'ip':    ip_origem,
                'token': uuid.uuid4().hex,
            },
        )
        return sensor, created

    except Sensor.MultipleObjectsReturned:
        logger.warning(
            f"Múltiplos sensores com nome '{sensor_nome}' encontrados. "
            f"Usando o mais recente."
        )
        sensor = (
            Sensor.objects
            .filter(nome=sensor_nome)
            .order_by('-last_seen')
            .first()
        )
        return sensor, False


# ─────────────────────────────────────────────────────────────────────────────
# PIPELINE PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

def processar_lote(eventos_brutos: list, sensor: Sensor) -> dict:
    interpretado = interpretar_eventos(eventos_brutos, sensor_id=sensor.pk)

    alertas      = interpretado.get('alertas',      [])
    eventos_dns  = interpretado.get('eventos_dns',  [])
    eventos_http = interpretado.get('eventos_http', [])
    eventos_tls  = interpretado.get('eventos_tls',  [])

    logger.debug(
        f"[{sensor.nome}] interpretado: "
        f"{len(alertas)} alertas | {len(eventos_dns)} dns | "
        f"{len(eventos_http)} http | {len(eventos_tls)} tls | "
        f"{interpretado.get('ignorados', 0)} ignorados"
    )

    alertas_prontos = []
    suprimidos = 0

    for dados in alertas:
        traducao = traduzir(dados, sensor_id=sensor.pk)

        if traducao.get('suprimido'):
            suprimidos += 1
            continue

        geo      = enriquecer_ip(dados['src_ip'])
        dir_info = calcular_direction(
            dados['src_ip'],
            dados.get('dest_ip') or '',
        )

        dados.update({
            'titulo_jg':     traducao['titulo_jg'],
            'resumo_jg':     traducao.get('resumo_jg', ''),
            'categoria_jg':  traducao['categoria_jg'],
            'severidade_jg': traducao['severidade_jg'],
            'tags_jg':       traducao.get('tags_jg', []),
            'recomendacoes': traducao.get('recomendacoes', []),
            'regra_id':      traducao.get('regra_id'),

            'pais':          geo['pais'],
            'pais_codigo':   geo['pais_codigo'],
            'cidade':        geo['cidade'],
            'latitude':      geo['latitude'],
            'longitude':     geo['longitude'],
            'asn_number':    geo['asn_number'],
            'asn_org':       geo['asn_org'],
            'asn':           geo['asn'],
            'rdns':          geo['rdns'],

            'direction':     dir_info['direction'],
            'src_is_local':  dir_info['src_is_local'],
            'dst_is_local':  dir_info['dst_is_local'],
        })

        alertas_prontos.append(dados)

    logger.debug(
        f"[{sensor.nome}] prontos para consolidar: "
        f"{len(alertas_prontos)} alertas | {suprimidos} suprimidos"
    )

    incidentes_tocados = consolidar_alertas(alertas_prontos, sensor)

    try:
        atualizar_risk_score(incidentes_tocados)
    except Exception as e:
        logger.warning(f'[{sensor.nome}] Falha ao atualizar RiskScore: {e}')

    objs_dns = [
        EventoDNS(
            sensor     = sensor,
            timestamp  = d['timestamp'],
            src_ip     = d['src_ip'],
            src_porta  = d['src_porta'],
            dest_ip    = d['dest_ip'],
            query      = d['query'],
            tipo       = d['tipo'],
            rcode      = d['rcode'],
            resposta   = d['resposta'],
            event_hash = d['event_hash'],
            raw_json   = d['raw_json'],
        )
        for d in eventos_dns
    ]

    objs_http = [
        EventoHTTP(
            sensor        = sensor,
            timestamp     = d['timestamp'],
            src_ip        = d['src_ip'],
            src_porta     = d['src_porta'],
            dest_ip       = d['dest_ip'],
            dest_porta    = d['dest_porta'],
            hostname      = d['hostname'],
            url           = d['url'],
            metodo        = d['metodo'],
            user_agent    = d['user_agent'],
            status_code   = d['status_code'],
            tamanho_bytes = d['tamanho_bytes'],
            event_hash    = d['event_hash'],
            raw_json      = d['raw_json'],
        )
        for d in eventos_http
    ]

    objs_tls = [
        EventoTLS(
            sensor      = sensor,
            timestamp   = d['timestamp'],
            src_ip      = d['src_ip'],
            src_porta   = d['src_porta'],
            dest_ip     = d['dest_ip'],
            dest_porta  = d['dest_porta'],
            sni         = d['sni'],
            versao      = d['versao'],
            issuer      = d['issuer'],
            subject     = d['subject'],
            fingerprint = d['fingerprint'],
            ja3         = d['ja3'],
            event_hash  = d['event_hash'],
            raw_json    = d['raw_json'],
        )
        for d in eventos_tls
    ]

    with transaction.atomic():
        dns_criados  = EventoDNS.objects.bulk_create(objs_dns,   ignore_conflicts=True)
        http_criados = EventoHTTP.objects.bulk_create(objs_http,  ignore_conflicts=True)
        tls_criados  = EventoTLS.objects.bulk_create(objs_tls,   ignore_conflicts=True)

    incidentes_novos       = [i for i in incidentes_tocados if i.ocorrencias == 1]
    incidentes_atualizados = [i for i in incidentes_tocados if i.ocorrencias >  1]

    resumo = {
        'alertas_recebidos':      len(alertas),
        'alertas_suprimidos':     suprimidos,
        'incidentes_novos':       len(incidentes_novos),
        'incidentes_atualizados': len(incidentes_atualizados),
        'eventos_brutos_salvos':  len(alertas_prontos),
        'dns_salvos':             len(dns_criados),
        'http_salvos':            len(http_criados),
        'tls_salvos':             len(tls_criados),
        'ignorados':              interpretado.get('ignorados', 0),
    }

    logger.info(
        f"[{sensor.nome}] lote processado: "
        f"novos={resumo['incidentes_novos']} | "
        f"atualizados={resumo['incidentes_atualizados']} | "
        f"dns={resumo['dns_salvos']} | "
        f"http={resumo['http_salvos']} | "
        f"tls={resumo['tls_salvos']}"
    )

    return resumo


# ─────────────────────────────────────────────────────────────────────────────
# VIEW — endpoint do sensor
# ─────────────────────────────────────────────────────────────────────────────

@csrf_exempt
@require_POST
def receber_eventos(request):
    try:
        payload     = json.loads(request.body.decode('utf-8') or '{}')
        eventos     = payload.get('eventos', [])
        sensor_nome = (payload.get('sensor') or 'sensor-1').strip()

        token_recebido = request.headers.get('X-MS-TOKEN', '').strip()

        if not isinstance(eventos, list):
            return JsonResponse(
                {'ok': False, 'error': "campo 'eventos' deve ser uma lista"},
                status=400,
            )

        ip_raw = (
            request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
            or request.META.get('REMOTE_ADDR', '0.0.0.0')
        )
        ip_origem = _validar_ip(ip_raw)

        sensor, created = _obter_sensor(sensor_nome, ip_origem)

        if sensor is None:
            logger.error(f"Não foi possível obter ou criar sensor '{sensor_nome}'")
            return JsonResponse(
                {'ok': False, 'error': 'Erro interno ao registrar sensor.'},
                status=500,
            )

        # ── Validação de token ────────────────────────────────────────────────
        if not created:

            # Caso 1: token AUSENTE → re-bootstrap com 403 + novo token
            if not token_recebido:
                sensor.token = uuid.uuid4().hex
                sensor.save(update_fields=['token'])
                logger.warning(
                    f"Token ausente para sensor '{sensor_nome}' (IP: {ip_origem}). "
                    f"Novo token emitido via re-bootstrap."
                )
                return JsonResponse(
                    {
                        'ok':    False,
                        'error': 'Token ausente. Novo token emitido.',
                        'token': sensor.token,
                    },
                    status=403,
                )

            # Caso 2: token INVÁLIDO (divergência após downtime/restart)
            # → regenera token, aceita o lote normalmente e devolve o novo token.
            # O sensor.py salva o novo token automaticamente via _enviar().
            if token_recebido != sensor.token:
                novo_token   = uuid.uuid4().hex
                sensor.token = novo_token
                sensor.save(update_fields=['token'])
                logger.warning(
                    f"Token inválido para sensor '{sensor_nome}' (IP: {ip_origem}). "
                    f"Token regenerado automaticamente — auto-recovery ativo."
                )
                # Não rejeita: processa o lote e devolve o novo token.
                # Na próxima requisição o sensor já usa o token correto.
                token_para_resposta = novo_token
            else:
                token_para_resposta = sensor.token

        else:
            # Sensor recém-criado: token já foi definido no get_or_create
            token_para_resposta = sensor.token

        # ── Atualiza last_seen e IP ───────────────────────────────────────────
        agora         = timezone.now()
        campos_update = ['last_seen']
        sensor.last_seen = agora

        if sensor.ip != ip_origem:
            sensor.ip = ip_origem
            campos_update.append('ip')

        sensor.save(update_fields=campos_update)

        # ── Heartbeat (lote vazio) ────────────────────────────────────────────
        if not eventos:
            logger.debug(f"[{sensor.nome}] heartbeat recebido")
            return JsonResponse({
                'ok':          True,
                'sensor':      sensor.nome,
                'novo_sensor': created,
                'token':       token_para_resposta,
                'heartbeat':   True,
                'last_seen':   agora.isoformat(),
            })

        # ── Pipeline ──────────────────────────────────────────────────────────
        logger.info(
            f"[{sensor.nome}] lote recebido: {len(eventos)} eventos de {ip_origem}"
        )
        resumo = processar_lote(eventos, sensor)

        return JsonResponse({
            'ok':          True,
            'sensor':      sensor.nome,
            'novo_sensor': created,
            'token':       token_para_resposta,
            'last_seen':   agora.isoformat(),
            **resumo,
        })

    except json.JSONDecodeError:
        return JsonResponse({'ok': False, 'error': 'JSON inválido'}, status=400)
    except Exception as exc:
        logger.exception('Falha ao receber/processar eventos')
        return JsonResponse({'ok': False, 'error': str(exc)}, status=500)