# =============================================================================
# firewall/views.py
# =============================================================================

import json
import logging

from datetime import datetime

from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from .models import (
    AllowlistEntry, BlocklistEntry, EventoFirewall,
    GeoblockEntry, NatEntry, RegraFirewall,
)
from .auxiliares import (
    get_modo, delta_horas, map_iface,
    rule_to_dict, nat_to_dict, block_to_dict, allow_to_dict, geo_to_dict, evento_to_log,
    sync_status, get_sensor_firewall,
    notificar_agente, push_regras_ao_agente,
    validar_regra_segura,
    regra_para_nft_inline,
    prod_waiting, prod_data, demo_data,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# HELPER — iface_map do sensor
# Busca o iface_map real do sensor cadastrado no banco.
# O sensor envia suas interfaces via heartbeat → salvo em sensor.interfaces.
# Montamos o mapa logico→real a partir disso.
# Se nao tiver, manda vazio — o conversor do sensor usa o config.json dele.
# ─────────────────────────────────────────────────────────────────────────────

def _get_iface_map() -> dict:
    """
    Retorna iface_map {logico: real} baseado nas interfaces reportadas
    pelo sensor de firewall.

    O sensor ja tem o iface_map completo no config.json dele —
    mandamos vazio e o conversor resolve automaticamente.
    Mantemos este helper para casos futuros onde o Django precise
    resolver interfaces (ex: exportar .nft com nomes reais).
    """
    try:
        sensor = get_sensor_firewall()
        if sensor and hasattr(sensor, 'iface_map') and sensor.iface_map:
            return sensor.iface_map
    except Exception:
        pass
    # Vazio = sensor usa config.json proprio (comportamento correto)
    return {}


# ─────────────────────────────────────────────────────────────────────────────
# PÁGINAS HTML
# ─────────────────────────────────────────────────────────────────────────────

@login_required(login_url='autenticacao:login')
def firewall_view(request):
    return render(request, 'firewall/firewall.html')


@login_required(login_url='autenticacao:login')
def feed_view(request):
    return render(request, 'firewall/feed.html')


@login_required(login_url='autenticacao:login')
def regras_view(request):
    return render(request, 'firewall/regras.html')


# ─────────────────────────────────────────────────────────────────────────────
# API: DATA GERAL
# ─────────────────────────────────────────────────────────────────────────────

@require_GET
@login_required(login_url='autenticacao:login')
def api_fw_data(request):
    period = request.GET.get('period', '24h')

    if get_modo() == 'demo':
        return JsonResponse(demo_data(period))

    try:
        has_data = EventoFirewall.objects.exists()
    except Exception:
        has_data = False

    if not has_data:
        return JsonResponse(prod_waiting())

    return JsonResponse(prod_data(period))


# ─────────────────────────────────────────────────────────────────────────────
# API: FEED
# ─────────────────────────────────────────────────────────────────────────────

@require_GET
@login_required(login_url='autenticacao:login')
def api_fw_feed(request):
    if get_modo() == 'demo':
        from .auxiliares import _gen_log
        return JsonResponse({
            'ok':   True,
            'mode': 'demo',
            'interfaces': [
                {'nome': 'WAN', 'ip': '1.2.3.4'},
                {'nome': 'LAN', 'ip': '10.0.0.1'},
            ],
            'eventos': [_gen_log() for _ in range(5)],
        })

    limit = min(int(request.GET.get('limit', 50)), 200)
    since = request.GET.get('since')
    qs    = EventoFirewall.objects.order_by('-timestamp')

    if since:
        try:
            from django.utils import timezone as tz
            ts = datetime.fromisoformat(since)
            if ts.tzinfo is None:
                ts = tz.make_aware(ts)
            qs = qs.filter(timestamp__gt=ts)
        except (ValueError, TypeError):
            pass

    eventos    = list(qs[:limit])
    sensor     = get_sensor_firewall()
    interfaces = sensor.interfaces if sensor else []

    return JsonResponse({
        'ok':         True,
        'mode':       'prod',
        'interfaces': interfaces,
        'eventos': [
            {
                'time':     e.timestamp.strftime('%H:%M:%S'),
                'action':   e.acao,
                'iface':    e.iface or '—',
                'src_ip':   e.src_ip,
                'src_port': e.src_port,
                'dst_ip':   str(e.dst_ip or '—'),
                'dst_port': e.dst_port,
                'proto':    e.proto or '—',
                'bytes':    e.tamanho or 0,
                'flags':    e.flags_tcp or '',
                'chain':    e.chain or '',
            }
            for e in reversed(eventos)
        ],
    })


# ─────────────────────────────────────────────────────────────────────────────
# API: INTERFACES
# ─────────────────────────────────────────────────────────────────────────────

@require_GET
@login_required(login_url='autenticacao:login')
def api_interfaces(request):
    if get_modo() == 'demo':
        return JsonResponse({
            'ok': True,
            'interfaces': [
                {'nome': 'WAN', 'ip': '1.2.3.4',    'mac': '', 'up': True},
                {'nome': 'LAN', 'ip': '10.0.0.1',   'mac': '', 'up': True},
                {'nome': 'VPN', 'ip': '192.168.1.1', 'mac': '', 'up': True},
            ],
            'sensor': None,
        })

    try:
        from incidentes.models import Sensor
        sensor = get_sensor_firewall()
        if not sensor or not sensor.interfaces:
            sensor = (
                Sensor.objects
                .filter(ativo=True)
                .exclude(interfaces=[])
                .order_by('-last_seen')
                .first()
            )
        if not sensor or not sensor.interfaces:
            return JsonResponse({'ok': True, 'interfaces': [], 'sensor': None})
        return JsonResponse({
            'ok':         True,
            'interfaces': sensor.interfaces,
            'sensor':     sensor.nome,
        })
    except Exception as e:
        return JsonResponse({'ok': False, 'erro': str(e)}, status=500)


# ─────────────────────────────────────────────────────────────────────────────
# API: BLOQUEIO RÁPIDO
# ─────────────────────────────────────────────────────────────────────────────

@require_POST
@login_required(login_url='autenticacao:login')
def api_bloqueio_rapido(request):
    try:
        d = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'ok': False, 'erro': 'JSON inválido'}, status=400)

    ip      = (d.get('ip') or '').strip()
    iface   = (d.get('iface') or '').strip()
    porta   = (d.get('porta') or '').strip()
    proto   = (d.get('proto') or '').strip().upper() or 'any'
    expires = (d.get('expires') or '').strip() or '∞'
    motivo  = (d.get('motivo') or 'Bloqueio rápido').strip()
    source  = (d.get('source') or 'Manual').strip()

    if not ip:
        return JsonResponse({'ok': False, 'erro': 'IP obrigatório'}, status=400)

    segura, motivo_seg = validar_regra_segura({'action': 'deny', 'src': ip})
    if not segura:
        return JsonResponse({'ok': False, 'erro': motivo_seg}, status=400)

    proto_valido = proto if proto in ('TCP', 'UDP', 'ICMP', 'ANY') else 'any'

    regra = RegraFirewall.objects.create(
        priority=50, action='deny',
        iface=iface or 'any', dir='in',
        proto=proto_valido, src=ip, dst='any',
        port=porta or 'any', desc=motivo[:255],
        enabled=True, log=True,
        pendente=True, sincronizada=False,
    )

    block_entry = BlocklistEntry.objects.create(
        ip=ip, reason=motivo, source=source, expires=expires,
    )

    # Notifica o agente diretamente via /bloquear
    agente_ok, agente_msg = notificar_agente("/bloquear", {
        "ip":      ip,
        "iface":   iface or "",
        "porta":   porta or "",
        "proto":   proto_valido.lower() if proto_valido != 'any' else "",
        "motivo":  motivo,
        "expires": expires if expires != '∞' else "",
    })

    # Se agente OK, marca como sincronizada
    if agente_ok:
        regra.pendente     = False
        regra.sincronizada = True
        regra.save(update_fields=['pendente', 'sincronizada'])

    return JsonResponse({
        'ok': True,
        'agente_ok':   agente_ok,
        'agente_msg':  agente_msg,
        'regra': {
            'id': regra.id, 'ip': ip,
            'iface': regra.iface, 'porta': regra.port, 'proto': regra.proto,
            'pendente': not agente_ok,
        },
        'blocklist_id': block_entry.id,
    }, status=201)


# ─────────────────────────────────────────────────────────────────────────────
# API: AUTOBAN (chamado pelo sensor, sem login)
# ─────────────────────────────────────────────────────────────────────────────

@csrf_exempt
@require_POST
def api_autoban(request):
    token = request.headers.get('X-MS-TOKEN', '').strip()

    try:
        from incidentes.models import Sensor
        sensor = Sensor.objects.filter(token=token, ativo=True).first()
        if not sensor:
            return JsonResponse({'ok': False, 'error': 'Token inválido'}, status=403)

        d      = json.loads(request.body.decode('utf-8') or '{}')
        ip     = (d.get('ip') or '').strip()
        motivo = d.get('motivo', 'auto_ban')
        hits   = d.get('hits', 0)
        iface  = d.get('iface', '')

        if not ip:
            return JsonResponse({'ok': False, 'erro': 'IP obrigatório'}, status=400)

        block_entry, criada = BlocklistEntry.objects.get_or_create(
            ip=ip,
            defaults={
                'reason':  f'Auto-ban: {motivo} ({hits} hits)',
                'source':  'Auto',
                'expires': '∞',
            },
        )

        regra = RegraFirewall.objects.create(
            priority=20, action='deny',
            iface=iface or 'any', dir='in',
            proto='any', src=ip, dst='any', port='any',
            desc=f'Auto-ban: {motivo} — {sensor.nome}'[:255],
            enabled=True, log=True,
            pendente=False, sincronizada=True,
        )

        logger.warning(f"[autoban/{sensor.nome}] {ip} banido — motivo={motivo} hits={hits}")

        return JsonResponse({
            'ok': True, 'ip': ip,
            'regra_id': regra.id, 'blocklist_id': block_entry.id,
            'novo_bloqueio': criada,
        })

    except json.JSONDecodeError:
        return JsonResponse({'ok': False, 'error': 'JSON inválido'}, status=400)
    except Exception as e:
        return JsonResponse({'ok': False, 'error': str(e)}, status=500)


# ─────────────────────────────────────────────────────────────────────────────
# API: CRUD REGRAS
# ─────────────────────────────────────────────────────────────────────────────

@login_required(login_url='autenticacao:login')
@require_http_methods(['POST'])
def api_rules(request):
    try:
        d = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'erro': 'JSON inválido'}, status=400)

    segura, motivo = validar_regra_segura(d)
    if not segura:
        return JsonResponse({'ok': False, 'erro': motivo}, status=400)

    r = RegraFirewall.objects.create(
        priority=int(d.get('priority', 500)), action=d.get('action', 'deny'),
        iface=d.get('iface', 'WAN'),          dir=d.get('dir', 'in'),
        proto=d.get('proto', 'TCP'),           src=d.get('src', 'any'),
        dst=d.get('dst', 'any'),               port=d.get('port', 'any'),
        desc=d.get('desc', ''),                enabled=d.get('enabled', True),
        log=d.get('log', True),                pendente=True, sincronizada=False,
    )

    # Envia todas as regras ativas pro agente — iface_map vazio, sensor resolve
    agente_ok, agente_msg = push_regras_ao_agente()

    # So marca sincronizada se o agente confirmou
    if agente_ok:
        r.pendente     = False
        r.sincronizada = True
        r.save(update_fields=['pendente', 'sincronizada'])

    return JsonResponse({
        'ok': True,
        'rule':       rule_to_dict(r),
        'agente_ok':  agente_ok,
        'agente_msg': agente_msg,
    }, status=201)


@login_required(login_url='autenticacao:login')
@require_http_methods(['PUT', 'PATCH', 'DELETE'])
def api_rule_detail(request, rule_id: int):
    r = get_object_or_404(RegraFirewall, pk=rule_id)

    if request.method == 'DELETE':
        r.enabled      = False
        r.pendente     = True
        r.sincronizada = False
        r.deletado     = True
        r.save()
        RegraFirewall.objects.filter(enabled=True).update(pendente=True, sincronizada=False)

        if r.src and r.src != 'any':
            BlocklistEntry.objects.filter(ip=r.src).delete()

        agente_ok, agente_msg = push_regras_ao_agente()
        return JsonResponse({'ok': True, 'agente_ok': agente_ok, 'agente_msg': agente_msg})

    try:
        d = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'erro': 'JSON inválido'}, status=400)

    payload_check = {
        **{'action': r.action, 'src': r.src},
        **{k: v for k, v in d.items() if k in ('action', 'src')},
    }
    segura, motivo = validar_regra_segura(payload_check)
    if not segura:
        return JsonResponse({'ok': False, 'erro': motivo}, status=400)

    for field in ('priority', 'action', 'iface', 'dir', 'proto', 'src', 'dst', 'port', 'desc', 'enabled', 'log'):
        if field in d:
            setattr(r, field, d[field])

    r.pendente     = True
    r.sincronizada = False
    r.deletado     = False
    r.save()

    if 'enabled' in d:
        RegraFirewall.objects.filter(enabled=True).update(pendente=True, sincronizada=False)

    agente_ok, agente_msg = push_regras_ao_agente()

    if agente_ok:
        r.pendente     = False
        r.sincronizada = True
        r.save(update_fields=['pendente', 'sincronizada'])

    return JsonResponse({
        'ok': True,
        'rule':       rule_to_dict(r),
        'agente_ok':  agente_ok,
        'agente_msg': agente_msg,
    })


# ─────────────────────────────────────────────────────────────────────────────
# API: PUSH / PENDING / CONFIRM RULES
# ─────────────────────────────────────────────────────────────────────────────

@login_required(login_url='autenticacao:login')
@require_POST
def api_push_rules(request):
    # Marca todas como pendentes para forcар reenvio
    count = RegraFirewall.objects.filter(enabled=True).update(
        pendente=True, sincronizada=False
    )

    rules = list(
        RegraFirewall.objects.filter(enabled=True, deletado=False)
        .order_by('priority').values()
    )

    # iface_map vazio — o conversor do sensor usa o config.json dele
    agente_ok, agente_msg = notificar_agente("/aplicar", {
        "rules":     rules,
        "iface_map": {},
    })

    if agente_ok:
        RegraFirewall.objects.filter(enabled=True).update(
            pendente=False, sincronizada=True
        )

    logger.info(f"[push-rules] {count} regras | agente={'OK' if agente_ok else 'ERRO'} | {agente_msg}")

    return JsonResponse({
        'ok':         True,
        'msg':        f'{count} regra(s) enviadas ao sensor.',
        'agente_ok':  agente_ok,
        'agente_msg': agente_msg,
        'sync':       sync_status(),
    })


@csrf_exempt
@require_GET
def api_pending_rules(request):
    """
    Endpoint consultado pelo sincronizador do sensor a cada 30s.
    Retorna as regras pendentes (nao sincronizadas ainda).
    iface_map vazio — sensor usa config.json proprio.
    """
    token = request.headers.get('X-MS-TOKEN', '').strip()

    try:
        from incidentes.models import Sensor
        sensor = Sensor.objects.filter(token=token, ativo=True).first()
        if not sensor:
            return JsonResponse({'ok': False, 'error': 'Token inválido'}, status=403)
    except Exception:
        return JsonResponse({'ok': False, 'error': 'Erro interno'}, status=500)

    pendentes = RegraFirewall.objects.filter(
        enabled=True, deletado=False, pendente=True
    ).order_by('priority')

    todas = RegraFirewall.objects.filter(
        enabled=True, deletado=False
    ).order_by('priority')

    desativadas_pending = RegraFirewall.objects.filter(
        enabled=False, deletado=False, pendente=True
    ).exists()

    tem_pendentes = pendentes.exists() or desativadas_pending

    return JsonResponse({
        'ok':            True,
        'tem_pendentes': tem_pendentes,
        'total_regras':  todas.count(),
        'pendentes':     pendentes.count(),
        # Manda TODAS as regras quando ha pendentes (sensor faz flush + reescreve)
        'rules':         [rule_to_dict(r) for r in todas] if tem_pendentes else [],
        # Vazio — sensor resolve com config.json proprio
        'iface_map':     {},
    })


@csrf_exempt
@require_POST
def api_confirm_rules(request):
    """
    Chamado pelo sensor apos aplicar as regras com sucesso.
    Marca as regras como sincronizadas.
    """
    token = request.headers.get('X-MS-TOKEN', '').strip()

    try:
        from incidentes.models import Sensor
        sensor = Sensor.objects.filter(token=token, ativo=True).first()
        if not sensor:
            return JsonResponse({'ok': False, 'error': 'Token inválido'}, status=403)

        payload  = json.loads(request.body.decode('utf-8') or '{}')
        rule_ids = payload.get('rule_ids', [])
        success  = payload.get('success', True)
        msg      = payload.get('msg', '')

        if success and rule_ids:
            RegraFirewall.objects.filter(id__in=rule_ids).update(
                pendente=False, sincronizada=True
            )

        if success:
            # Limpa pendentes de regras desativadas e remove deletadas confirmadas
            RegraFirewall.objects.filter(
                enabled=False, pendente=True, deletado=False
            ).update(pendente=False)
            RegraFirewall.objects.filter(deletado=True).delete()

        logger.info(
            f"[fw/{sensor.nome}] confirm-rules: {len(rule_ids)} regras | "
            f"{'OK' if success else 'ERRO'} | {msg}"
        )

        return JsonResponse({'ok': True, 'sync': sync_status()})

    except json.JSONDecodeError:
        return JsonResponse({'ok': False, 'error': 'JSON inválido'}, status=400)
    except Exception as e:
        return JsonResponse({'ok': False, 'error': str(e)}, status=500)


# ─────────────────────────────────────────────────────────────────────────────
# API: EXPORT NFT
# ─────────────────────────────────────────────────────────────────────────────

@login_required(login_url='autenticacao:login')
@require_GET
def api_export_nft(request):
    rules = RegraFirewall.objects.filter(enabled=True).order_by('priority')

    linhas = [
        '# MoonShield — Regras de Firewall exportadas',
        f'# Gerado em: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
        f'# Total: {rules.count()} regras ativas',
        '#',
        '# Aplicar com: nft -f moonshield-rules.nft',
        '',
        'add table inet moonshield',
        'add chain inet moonshield ms_rules',
        'flush chain inet moonshield ms_rules',
        '',
    ]

    for r in rules:
        # iface_map vazio no export — usa nomes logicos (WAN/LAN)
        # Para export com nomes reais, o usuario deve adaptar
        cmd = regra_para_nft_inline(r, {})
        if cmd:
            # Comentario em linha separada (nft nao aceita # inline)
            linhas.append(f'# [{r.priority}] {r.desc}')
            linhas.append(f'add rule inet moonshield ms_rules {cmd}')

    linhas.append('')
    conteudo = '\n'.join(linhas)
    filename = f'moonshield-rules-{datetime.now().strftime("%Y%m%d-%H%M")}.nft'
    response = HttpResponse(conteudo, content_type='text/plain; charset=utf-8')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


# ─────────────────────────────────────────────────────────────────────────────
# API: CRUD — NAT, BLOCKLIST, ALLOWLIST, GEOBLOCK
# ─────────────────────────────────────────────────────────────────────────────

@login_required(login_url='autenticacao:login')
@require_http_methods(['POST'])
def api_nat(request):
    try:
        d = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'erro': 'JSON inválido'}, status=400)
    n = NatEntry.objects.create(
        name=d.get('name', 'Port Forward'), iface=d.get('iface', 'WAN'),
        wan_port=str(d.get('wan_port', '')), lan_ip=d.get('lan_ip', ''),
        lan_port=str(d.get('lan_port', '')), proto=d.get('proto', 'TCP'),
        enabled=d.get('enabled', True),
    )
    return JsonResponse({'ok': True, 'nat': nat_to_dict(n)}, status=201)


@login_required(login_url='autenticacao:login')
@require_http_methods(['PUT', 'PATCH', 'DELETE'])
def api_nat_detail(request, nat_id: int):
    n = get_object_or_404(NatEntry, pk=nat_id)
    if request.method == 'DELETE':
        n.delete()
        return JsonResponse({'ok': True})
    try:
        d = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'erro': 'JSON inválido'}, status=400)
    for field in ('name', 'iface', 'wan_port', 'lan_ip', 'lan_port', 'proto', 'enabled'):
        if field in d:
            setattr(n, field, d[field])
    n.save()
    return JsonResponse({'ok': True, 'nat': nat_to_dict(n)})


@login_required(login_url='autenticacao:login')
@require_http_methods(['POST'])
def api_blocklist(request):
    try:
        d = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'erro': 'JSON inválido'}, status=400)
    ip = (d.get('ip') or '').strip()
    if not ip:
        return JsonResponse({'erro': 'IP obrigatório'}, status=400)
    b = BlocklistEntry.objects.create(
        ip=ip, reason=d.get('reason', 'Bloqueio manual'),
        source=d.get('source', 'Manual'), expires=d.get('expires', '∞'),
    )
    return JsonResponse({'ok': True, 'entry': block_to_dict(b)}, status=201)


@login_required(login_url='autenticacao:login')
@require_http_methods(['DELETE'])
def api_blocklist_detail(request, entry_id: int):
    get_object_or_404(BlocklistEntry, pk=entry_id).delete()
    return JsonResponse({'ok': True})


@login_required(login_url='autenticacao:login')
@require_http_methods(['POST'])
def api_allowlist(request):
    try:
        d = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'erro': 'JSON inválido'}, status=400)
    ip = (d.get('ip') or '').strip()
    if not ip:
        return JsonResponse({'erro': 'IP/domínio obrigatório'}, status=400)
    a = AllowlistEntry.objects.create(ip=ip, reason=d.get('reason', 'Liberação manual'))
    return JsonResponse({'ok': True, 'entry': allow_to_dict(a)}, status=201)


@login_required(login_url='autenticacao:login')
@require_http_methods(['DELETE'])
def api_allowlist_detail(request, entry_id: int):
    get_object_or_404(AllowlistEntry, pk=entry_id).delete()
    return JsonResponse({'ok': True})


@login_required(login_url='autenticacao:login')
@require_http_methods(['POST'])
def api_geoblock(request):
    try:
        d = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'erro': 'JSON inválido'}, status=400)
    code = (d.get('code') or '').strip().upper()
    if not code:
        return JsonResponse({'erro': 'Código de país obrigatório'}, status=400)
    g, _ = GeoblockEntry.objects.get_or_create(
        code=code,
        defaults={
            'country': d.get('country', code),
            'dir':     d.get('dir', 'IN'),
            'enabled': d.get('enabled', True),
        },
    )
    return JsonResponse({'ok': True, 'entry': geo_to_dict(g)}, status=201)


@login_required(login_url='autenticacao:login')
@require_http_methods(['PUT', 'PATCH', 'DELETE'])
def api_geoblock_detail(request, entry_id: int):
    g = get_object_or_404(GeoblockEntry, pk=entry_id)
    if request.method == 'DELETE':
        g.delete()
        return JsonResponse({'ok': True})
    try:
        d = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'erro': 'JSON inválido'}, status=400)
    for field in ('country', 'dir', 'enabled'):
        if field in d:
            setattr(g, field, d[field])
    g.save()
    return JsonResponse({'ok': True, 'entry': geo_to_dict(g)})