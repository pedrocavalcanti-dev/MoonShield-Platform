# =============================================================================
# incidentes/views.py  v11
#
# Mudanças v11:
#   ✓ _get_modo_sistema() agora retorna 'prod' como padrão quando
#     ConfigSistema não existe ou lança exceção — antes retornava 'demo',
#     o que fazia o painel mostrar dados falsos mesmo com eventos reais no banco
#   ✓ Sem mudanças na lógica de queries, serialização ou filtros
# =============================================================================

import json
from datetime import timedelta

from django.contrib.auth.decorators import login_required
from django.db.models import Count, Sum
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, render
from django.utils import timezone
from django.views.decorators.http import require_GET, require_http_methods

from .demo import (
    get_demo_contexto,
    get_demo_eventos,
    get_demo_stats,
    get_demo_timeline,
    get_demo_totais,
)
from .models import (
    EventoDNS, EventoHTTP, EventoTLS,
    Incidente, RiskScore, Supressao,
    SeveridadeJG, CategoriaJG,
)
from .services.correlacionador import correlacionar_incidente, contexto_ip
from .services.classificador import (
    classificar_lista,
    get_preset_ativo,
    get_info_preset,
    PRESETS,
)

try:
    from configuracoes.models import ConfigSistema
except ImportError:
    ConfigSistema = None


# =============================================================================
# HELPERS
# =============================================================================

def _get_modo_sistema() -> str:
    """
    FIX v11: retorna 'prod' como padrão.
    Antes retornava 'demo' quando ConfigSistema não existia, causando o painel
    mostrar dados falsos mesmo com eventos reais no banco.

    Para ativar modo demo explicitamente: setar ConfigSistema.modo = 'demo'
    no Django admin.
    """
    if ConfigSistema:
        try:
            return ConfigSistema.get_solo().modo
        except Exception:
            pass
    return 'prod'   # ← era 'demo'


def _calcular_top_ip(qs) -> dict | None:
    """
    Retorna o IP com maior volume de ocorrências reais.
    Usa Sum('ocorrencias') — não Count('src_ip').
    """
    row = (
        qs.values('src_ip')
        .annotate(total=Sum('ocorrencias'))
        .order_by('-total')
        .first()
    )
    if not row:
        return None
    return {'ip': row['src_ip'], 'count': row['total']}


# =============================================================================
# PÁGINAS HTML
# =============================================================================

@login_required(login_url='autenticacao:login')
def incidentes_view(request):
    return render(request, 'incidentes/incidente.html')


@login_required(login_url='autenticacao:login')
def investigacao_view(request, ip):
    return render(request, 'incidentes/investigacao.html', {'ip': ip})



@login_required(login_url='autenticacao:login')
def incidente_detalhe_view(request, incidente_id: int):
    """Página dedicada de detalhe do incidente — /incidentes/<id>/"""
    # Valida que o incidente existe antes de renderizar
    get_object_or_404(Incidente, pk=incidente_id)
    return render(request, 'incidentes/incidente-detalhe.html', {
        'incidente_id': incidente_id,
    })


# =============================================================================
# API: GET /incidentes/api/data/
# =============================================================================

@require_GET
@login_required(login_url='autenticacao:login')
def api_incidentes_data(request):
    count         = int(request.GET.get('count', 200))
    horas         = int(request.GET.get('horas', 24))
    preset        = request.GET.get('preset') or get_preset_ativo()
    filtro_sev    = request.GET.get('severidade_jg', '').strip()
    filtro_cat    = request.GET.get('categoria_jg',  '').strip()
    filtro_status = request.GET.get('status', '').strip()
    filtro_sensor = request.GET.get('sensor', '').strip()
    agrupado      = request.GET.get('agrupado', '1') == '1'

    desde = timezone.now() - timedelta(hours=horas)

    qs = Incidente.objects.select_related('sensor').filter(last_seen__gte=desde)

    if filtro_sev and filtro_sev in SeveridadeJG.values:
        qs = qs.filter(severidade_jg=filtro_sev)
    if filtro_cat and filtro_cat in CategoriaJG.values:
        qs = qs.filter(categoria_jg=filtro_cat)
    if filtro_status:
        qs = qs.filter(status=filtro_status)
    if filtro_sensor:
        qs = qs.filter(sensor__nome__icontains=filtro_sensor)

    qs = qs.order_by('-last_seen')[:count]
    eventos_raw = [_incidente_para_evento(inc) for inc in qs]

    is_demo = False
    if not eventos_raw:
        if _get_modo_sistema() == 'demo':
            eventos_raw = get_demo_eventos()
            is_demo = True

    eventos_agrupados = classificar_lista(eventos_raw, preset_nome=preset)

    if not agrupado:
        for ev in eventos_agrupados:
            ev['group_key']           = None
            ev['group_count']         = 1
            ev['primeira_ocorrencia'] = ev.get('first_seen')

    totais_sev = {s: 0 for s in SeveridadeJG.values}
    totais_cat = {c: 0 for c in CategoriaJG.values}
    for ev in eventos_agrupados:
        sev = ev.get('severidade_jg', 'informativo')
        cat = ev.get('categoria_jg',  'info')
        totais_sev[sev] = totais_sev.get(sev, 0) + 1
        totais_cat[cat] = totais_cat.get(cat, 0) + 1

    if is_demo:
        totais_class = get_demo_totais()
    else:
        totais_class = {'incidente': 0, 'evento': 0, 'telemetria': 0}
        for ev in eventos_agrupados:
            classe = ev.get('classificacao') or 'telemetria'
            totais_class[classe] = totais_class.get(classe, 0) + 1

    return JsonResponse({
        'ok':                  True,
        'demo':                is_demo,
        'agrupado':            agrupado,
        'preset':              preset,
        'preset_info':         get_info_preset(preset),
        'presets_disponiveis': {k: v['nome'] for k, v in PRESETS.items()},
        'totais':              totais_class,
        'totais_severidade':   totais_sev,
        'totais_categoria':    totais_cat,
        'total':               len(eventos_agrupados),
        'eventos':             eventos_agrupados,
    })


# =============================================================================
# API: GET /incidentes/api/preset/salvar/?preset=casa
# =============================================================================

@require_GET
@login_required(login_url='autenticacao:login')
def api_salvar_preset(request):
    preset = request.GET.get('preset', '').strip()
    if preset not in PRESETS:
        return JsonResponse({'ok': False, 'erro': f'Preset inválido: {preset}'}, status=400)

    if ConfigSistema:
        try:
            cfg = ConfigSistema.get_solo()
            if hasattr(cfg, 'active_preset'):
                cfg.active_preset = preset
                cfg.save(update_fields=['active_preset'])
        except Exception:
            pass

    return JsonResponse({'ok': True, 'preset': preset, 'nome': PRESETS[preset]['nome']})


# =============================================================================
# API: GET /incidentes/api/stats/
# =============================================================================

@require_GET
@login_required(login_url='autenticacao:login')
def api_estatisticas(request):
    agora = timezone.now()
    desde = agora - timedelta(hours=24)
    qs    = Incidente.objects.filter(last_seen__gte=desde)

    if not qs.exists():
        if _get_modo_sistema() == 'demo':
            return JsonResponse(get_demo_stats())

        return JsonResponse({
            'ultimas_24h': {
                'total_incidentes':        0,
                'total_ocorrencias':       0,
                'criticos_incidentes':     0,
                'altos_incidentes':        0,
                'medios_incidentes':       0,
                'baixos_incidentes':       0,
                'informativos_incidentes': 0,
                'novos':                   0,
                'investigando':            0,
                'top_categorias':          [],
            },
            'dns_24h':        0,
            'http_24h':       0,
            'tls_24h':        0,
            'resolvidos_hoje': 0,
            'top_ip':          None,
            'taxa_min':        0.0,
            'delta_criticos':  0,
        })

    total_ocorrencias = qs.aggregate(s=Sum('ocorrencias'))['s'] or 0

    resolvidos_hoje = Incidente.objects.filter(
        status='resolvido',
        atualizado_em__date=agora.date(),
    ).count()

    top_ip   = _calcular_top_ip(qs)
    taxa_min = round(total_ocorrencias / (24 * 60), 3)

    desde_anterior    = desde - timedelta(hours=24)
    criticos_anterior = Incidente.objects.filter(
        last_seen__gte=desde_anterior,
        last_seen__lt=desde,
        severidade_jg='critico',
    ).count()
    criticos_incidentes = qs.filter(severidade_jg='critico').count()
    delta_criticos      = criticos_incidentes - criticos_anterior

    return JsonResponse({
        'ultimas_24h': {
            'total_incidentes':        qs.count(),
            'total_ocorrencias':       total_ocorrencias,
            'criticos_incidentes':     criticos_incidentes,
            'altos_incidentes':        qs.filter(severidade_jg='alto').count(),
            'medios_incidentes':       qs.filter(severidade_jg='medio').count(),
            'baixos_incidentes':       qs.filter(severidade_jg='baixo').count(),
            'informativos_incidentes': qs.filter(severidade_jg='informativo').count(),
            'novos':        qs.filter(status='novo').count(),
            'investigando': qs.filter(status='investigando').count(),
            'top_categorias': list(
                qs.values('categoria_jg')
                .annotate(n=Count('categoria_jg'))
                .order_by('-n')[:5]
            ),
        },
        'dns_24h':  EventoDNS.objects.filter(timestamp__gte=desde).count(),
        'http_24h': EventoHTTP.objects.filter(timestamp__gte=desde).count(),
        'tls_24h':  EventoTLS.objects.filter(timestamp__gte=desde).count(),

        'resolvidos_hoje': resolvidos_hoje,
        'top_ip':          top_ip,
        'taxa_min':        taxa_min,
        'delta_criticos':  delta_criticos,
    })


# =============================================================================
# API: GET /incidentes/api/<id>/
# =============================================================================

@require_GET
@login_required(login_url='autenticacao:login')
def api_incidente_detalhe(request, incidente_id: int):
    incidente = get_object_or_404(Incidente, pk=incidente_id)

    duracao_min = max(
        10,
        int((incidente.last_seen - incidente.first_seen).total_seconds() / 60) + 5,
    )
    correlacao = correlacionar_incidente(incidente, janela_minutos=duracao_min)

    return JsonResponse({
        'incidente':  _incidente_para_evento(incidente, completo=True),
        'correlacao': {
            'resumo': correlacao['resumo'],
            'dns':    [_serializar_dns(e)  for e in correlacao['dns'][:30]],
            'http':   [_serializar_http(e) for e in correlacao['http'][:30]],
            'tls':    [_serializar_tls(e)  for e in correlacao['tls'][:30]],
        },
        'dns':  [_serializar_dns(e)  for e in correlacao['dns'][:30]],
        'http': [_serializar_http(e) for e in correlacao['http'][:30]],
        'tls':  [_serializar_tls(e)  for e in correlacao['tls'][:30]],
    })


# =============================================================================
# API: PATCH /incidentes/api/<id>/status/
# =============================================================================

@login_required(login_url='autenticacao:login')
@require_http_methods(['PATCH', 'POST'])
def api_atualizar_status(request, incidente_id: int):
    incidente = get_object_or_404(Incidente, pk=incidente_id)

    try:
        dados = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'erro': 'JSON inválido'}, status=400)

    status_validos = [s[0] for s in Incidente.STATUS]
    novo_status    = dados.get('status')

    if novo_status and novo_status not in status_validos:
        return JsonResponse({'erro': f'Status inválido. Opcoes: {status_validos}'}, status=400)

    if novo_status:
        incidente.status = novo_status
    if 'nota' in dados:
        incidente.nota = dados['nota']

    incidente.save(update_fields=['status', 'nota', 'atualizado_em'])
    return JsonResponse({'ok': True, 'status': incidente.status})


# =============================================================================
# API: GET /incidentes/api/ip/<ip>/contexto/
# =============================================================================

@require_GET
@login_required(login_url='autenticacao:login')
def api_contexto_ip(request, ip):
    try:
        horas = int(request.GET.get('horas', 24))
        since = timezone.now() - timedelta(hours=horas)

        tem_dados = Incidente.objects.filter(src_ip=ip, last_seen__gte=since).exists()
        if not tem_dados:
            if _get_modo_sistema() == 'demo':
                ctx = get_demo_contexto(ip)
                return JsonResponse({'ok': True, 'demo': True, 'contexto': ctx})

            return JsonResponse({
                'ok': True, 'demo': False,
                'contexto': {
                    'total_alertas': 0, 'total_dns': 0, 'total_http': 0, 'total_tls': 0,
                    'geo': {},
                    'risk_score': {
                        'score': 0.0, 'total_alertas': 0, 'criticos': 0,
                        'altos': 0, 'medios': 0, 'ultimo_alerta': None,
                    },
                    'direction_counts': {}, 'direction_dominant': 'unknown',
                    'top_sids': [], 'top_dominios': [], 'top_user_agents': [],
                }
            })

        ctx = contexto_ip(ip, horas=horas)

        from .models import GeoCache
        geo_entry = GeoCache.objects.filter(ip=ip).first()
        geo = {}
        if geo_entry:
            geo = {
                'flag':        _flag_por_codigo(geo_entry.pais_codigo),
                'pais':        geo_entry.pais,
                'pais_codigo': geo_entry.pais_codigo,
                'cidade':      geo_entry.cidade,
                'asn_number':  geo_entry.asn_number,
                'asn_org':     geo_entry.asn_org,
                'rdns':        geo_entry.rdns,
                'latitude':    geo_entry.latitude,
                'longitude':   geo_entry.longitude,
            }
        else:
            ultimo = Incidente.objects.filter(src_ip=ip).order_by('-last_seen').first()
            if ultimo:
                geo = {
                    'flag':        _flag_por_codigo(ultimo.pais_codigo),
                    'pais':        ultimo.pais,
                    'pais_codigo': ultimo.pais_codigo,
                    'cidade':      ultimo.cidade,
                    'asn_number':  ultimo.asn_number,
                    'asn_org':     ultimo.asn_org,
                    'rdns':        ultimo.rdns,
                    'latitude':    ultimo.latitude,
                    'longitude':   ultimo.longitude,
                }

        risk_obj = RiskScore.objects.filter(ip=ip).first()
        risk = {
            'score':         risk_obj.score         if risk_obj else 0.0,
            'total_alertas': risk_obj.total_alertas if risk_obj else 0,
            'criticos':      risk_obj.criticos      if risk_obj else 0,
            'altos':         risk_obj.altos         if risk_obj else 0,
            'medios':        risk_obj.medios        if risk_obj else 0,
            'ultimo_alerta': risk_obj.ultimo_alerta.isoformat() if risk_obj and risk_obj.ultimo_alerta else None,
        }

        direction_counts   = ctx.get('direction_counts', {})
        direction_dominant = max(direction_counts, key=direction_counts.get) if direction_counts else 'unknown'

        top_sids = [
            {'sid': row['sid'], 'signature': row.get('signature', row['sid']), 'total': row['n']}
            for row in ctx.get('top_sids', [])
        ]
        top_dominios = [
            {'query': row['query'], 'total': row['n']}
            for row in ctx.get('top_dominios', [])
        ]
        top_user_agents = [
            {'ua': row['user_agent'], 'total': row['n']}
            for row in ctx.get('top_user_agents', [])
        ]

        return JsonResponse({
            'ok': True,
            'contexto': {
                **ctx,
                'geo':                geo,
                'risk_score':         risk,
                'direction_dominant': direction_dominant,
                'top_sids':           top_sids,
                'top_dominios':       top_dominios,
                'top_user_agents':    top_user_agents,
            }
        })

    except Exception as e:
        return JsonResponse({'ok': False, 'erro': str(e)}, status=500)


# =============================================================================
# API: GET /incidentes/api/ip/<ip>/timeline/
# =============================================================================

@require_GET
@login_required(login_url='autenticacao:login')
def api_timeline_ip(request, ip):
    try:
        horas = int(request.GET.get('horas', 24))
        since = timezone.now() - timedelta(hours=horas)

        tem_dados = (
            Incidente.objects.filter(src_ip=ip, last_seen__gte=since).exists()
            or EventoDNS.objects.filter(src_ip=ip,  timestamp__gte=since).exists()
            or EventoHTTP.objects.filter(src_ip=ip, timestamp__gte=since).exists()
            or EventoTLS.objects.filter(src_ip=ip,  timestamp__gte=since).exists()
        )

        if not tem_dados:
            if _get_modo_sistema() == 'demo':
                eventos = get_demo_timeline(ip, horas)
                return JsonResponse({
                    'ok': True, 'demo': True,
                    'ip': ip, 'total': len(eventos), 'eventos': eventos,
                })
            return JsonResponse({'ok': True, 'demo': False, 'ip': ip, 'total': 0, 'eventos': []})

        eventos = []

        for a in Incidente.objects.filter(src_ip=ip, last_seen__gte=since).order_by('-last_seen')[:100]:
            eventos.append({
                'tipo':           'alert',
                'timestamp':      a.last_seen.isoformat(),
                'first_seen':     a.first_seen.isoformat(),
                'last_seen':      a.last_seen.isoformat(),
                'ocorrencias':    a.ocorrencias,
                'severidade':     a.severidade,
                'severidade_jg':  a.severidade_jg,
                'titulo':         a.titulo_jg or a.signature,
                'titulo_tecnico': a.signature,
                'detalhe':        f"{a.src_ip}:{a.src_porta or '?'} → {a.dest_ip or '?'}:{a.dest_porta or '?'}",
                'categoria_jg':   a.categoria_jg,
                'sid':            a.sid,
                'protocolo':      a.protocolo,
                'direction':      a.direction,
                'status':         a.status,
                'risk_score':     a.risk_score,
                'id':             a.id,
            })

        for d in EventoDNS.objects.filter(src_ip=ip, timestamp__gte=since).order_by('-timestamp')[:100]:
            eventos.append({
                'tipo':       'dns',
                'timestamp':  d.timestamp.isoformat(),
                'severidade': 'informativo',
                'titulo':     d.query or '(sem query)',
                'detalhe':    f"tipo={d.tipo} rcode={d.rcode}",
                'rcode':      d.rcode,
                'tipo_query': d.tipo,
            })

        for h in EventoHTTP.objects.filter(src_ip=ip, timestamp__gte=since).order_by('-timestamp')[:100]:
            eventos.append({
                'tipo':        'http',
                'timestamp':   h.timestamp.isoformat(),
                'severidade':  'informativo',
                'titulo':      f"{h.metodo} {h.hostname}{h.url[:60]}",
                'detalhe':     f"status={h.status_code} ua={h.user_agent[:40] if h.user_agent else ''}",
                'status_code': h.status_code,
                'metodo':      h.metodo,
                'hostname':    h.hostname,
            })

        for t in EventoTLS.objects.filter(src_ip=ip, timestamp__gte=since).order_by('-timestamp')[:100]:
            eventos.append({
                'tipo':       'tls',
                'timestamp':  t.timestamp.isoformat(),
                'severidade': 'informativo',
                'titulo':     t.sni or '(sem SNI)',
                'detalhe':    f"versao={t.versao} ja3={t.ja3[:16] if t.ja3 else '—'}",
                'versao':     t.versao,
                'ja3':        t.ja3,
            })

        eventos.sort(key=lambda x: x['timestamp'], reverse=True)
        return JsonResponse({'ok': True, 'ip': ip, 'total': len(eventos), 'eventos': eventos})

    except Exception as e:
        return JsonResponse({'ok': False, 'erro': str(e)}, status=500)


# =============================================================================
# API: POST /incidentes/api/supressao/
# =============================================================================

@login_required(login_url='autenticacao:login')
@require_http_methods(['POST'])
def api_criar_supressao(request):
    try:
        dados = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'erro': 'JSON inválido'}, status=400)

    tipo   = dados.get('tipo', '').strip()
    motivo = dados.get('motivo', '').strip()
    ip     = dados.get('ip', '').strip()
    sid    = dados.get('sid', '').strip()
    expira = dados.get('expira') or None

    tipos_validos = [t[0] for t in Supressao.TIPO]
    if tipo not in tipos_validos:
        return JsonResponse({'erro': f'Tipo inválido. Opções: {tipos_validos}'}, status=400)
    if not motivo:
        return JsonResponse({'erro': 'Motivo obrigatório'}, status=400)

    if tipo == 'ip_src':   valor = ip
    elif tipo == 'sid':    valor = sid
    else:                  valor = ip or sid or dados.get('valor', '').strip()

    if not valor:
        return JsonResponse({'erro': 'Valor para supressão não informado'}, status=400)

    sup = Supressao.objects.create(
        tipo       = tipo,
        valor      = valor,
        escopo     = 'global',
        motivo     = motivo,
        expira_em  = expira,
        criado_por = request.user.username,
    )
    return JsonResponse({'ok': True, 'id': sup.pk, 'tipo': sup.tipo, 'valor': sup.valor})


# =============================================================================
# SERIALIZADORES
# =============================================================================

def _incidente_para_evento(inc, completo: bool = False) -> dict:
    risk_score = round(inc.risk_score, 1) if inc.risk_score else 0.0

    evento = {
        'id':          str(inc.pk),
        'first_seen':  inc.first_seen.isoformat(),
        'last_seen':   inc.last_seen.isoformat(),
        'timestamp':   inc.last_seen.isoformat(),
        'ocorrencias': inc.ocorrencias,
        'sensor':      inc.sensor.nome if inc.sensor else None,
        'status':      inc.status,

        'titulo_jg':     inc.titulo_jg or inc.signature,
        'resumo_jg':     inc.resumo_jg,
        'categoria_jg':  inc.categoria_jg,
        'severidade_jg': inc.severidade_jg,
        'tags_jg':       inc.tags_jg or [],
        'recomendacoes': inc.recomendacoes or [],
        'evidencia':     inc.evidencia_principal,

        'tecnico': {
            'signature':  inc.signature,
            'sid':        inc.sid,
            'categoria':  inc.categoria,
            'severidade': inc.severidade,
            'protocolo':  inc.protocolo,
            'src_ip':     inc.src_ip,
            'src_porta':  inc.src_porta,
            'dest_ip':    inc.dest_ip or '',
            'dest_porta': inc.dest_porta,
            'direction':  inc.direction,
            'acao':       inc.acao,
            'rev':        inc.rev,
        },

        'pais_codigo': inc.pais_codigo or '',
        'pais':        inc.pais or '',
        'cidade':      inc.cidade or '',
        'asn_org':     inc.asn_org or '',
        'asn_number':  inc.asn_number or '',
        'rdns':        inc.rdns or '',
        'latitude':    inc.latitude,
        'longitude':   inc.longitude,
        'flag':        _flag_por_codigo(inc.pais_codigo),

        'risk_score':   risk_score,
        'src_is_local': inc.src_is_local,
        'dst_is_local': inc.dst_is_local,

        'classificacao':       None,
        'score_evento':        None,
        'group_key':           None,
        'group_count':         inc.ocorrencias,
        'primeira_ocorrencia': inc.first_seen.isoformat(),

        'sev':   inc.severidade,
        'fonte': 'IDS',
        'sig': {
            'name':   inc.signature,
            'cat':    inc.categoria,
            'sid':    inc.sid,
            'rev':    inc.rev,
            'action': inc.acao,
            'sev':    inc.severidade,
            'port':   inc.dest_porta or 0,
            'proto':  inc.protocolo,
        },
        'srcIp':   inc.src_ip,
        'dstIp':   inc.dest_ip or '',
        'country': {
            'flag': _flag_por_codigo(inc.pais_codigo),
            'name': inc.pais or 'Desconhecido',
            'code': inc.pais_codigo or '',
        },
        'direction': inc.direction or 'unknown',
    }

    if completo:
        evento['nota']        = inc.nota
        evento['raw_json']    = inc.raw_json
        evento['criado_em']   = inc.criado_em.isoformat()
        evento['fingerprint'] = inc.fingerprint

    return evento


def _flag_por_codigo(codigo: str) -> str:
    if not codigo or len(codigo) != 2:
        return '🇧🇷'
    return ''.join(chr(0x1F1E0 + ord(c) - ord('A')) for c in codigo.upper())

def _serializar_dns(ev) -> dict:
    return {
        'timestamp': ev.timestamp.isoformat(),
        'src_ip':    ev.src_ip,
        'query':     ev.query,
        'tipo':      ev.tipo,
        'rcode':     ev.rcode,
        'resposta':  ev.resposta,
    }


def _serializar_http(ev) -> dict:
    return {
        'timestamp':   ev.timestamp.isoformat(),
        'src_ip':      ev.src_ip,
        'metodo':      ev.metodo,
        'hostname':    ev.hostname,
        'url':         ev.url,
        'status_code': ev.status_code,
        'user_agent':  ev.user_agent,
    }


def _serializar_tls(ev) -> dict:
    return {
        'timestamp': ev.timestamp.isoformat(),
        'src_ip':    ev.src_ip,
        'sni':       ev.sni,
        'versao':    ev.versao,
        'ja3':       ev.ja3,
        'issuer':    ev.issuer,
    }