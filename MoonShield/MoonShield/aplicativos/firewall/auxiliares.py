# =============================================================================
# firewall/auxiliares.py
#
# Funções de suporte ao views.py — sem nenhuma view Django aqui.
# Contém:
#   - Serializers (_rule_to_dict, _nat_to_dict, etc.)
#   - Helpers internos (_get_modo, _map_iface, _sync_status, etc.)
#   - Comunicação com o agente (_notificar_agente, _push_regras_ao_agente)
#   - Proteção anti-auto-bloqueio (_get_ip_django, _validar_regra_segura)
#   - Dados de produção (_prod_data, _prod_waiting)
# =============================================================================

import json
import random
import socket
import threading
import urllib.request as _urllib_req
import uuid
from datetime import datetime, timedelta

from django.db.models import Count, Sum
from django.db.models.functions import TruncHour
from django.utils import timezone

from .models import (
    AllowlistEntry, BlocklistEntry, EventoFirewall,
    GeoblockEntry, NatEntry, RegraFirewall,
)

try:
    from configuracoes.models import ConfigSistema
except ImportError:
    ConfigSistema = None


# ─────────────────────────────────────────────────────────────────────────────
# MODO / PERÍODO
# ─────────────────────────────────────────────────────────────────────────────

def get_modo() -> str:
    if ConfigSistema:
        try:
            return ConfigSistema.get_solo().modo
        except Exception:
            pass
    return 'demo'


def delta_horas(period: str) -> int:
    return {'1h': 1, '24h': 24, '7d': 168, '30d': 720}.get(period, 24)


# ─────────────────────────────────────────────────────────────────────────────
# SERIALIZERS
# ─────────────────────────────────────────────────────────────────────────────

def map_iface(raw: str) -> str:
    if not raw:
        return 'WAN'
    r = raw.lower()
    if any(k in r for k in ('tun', 'vpn', 'wg', 'ipsec')):
        return 'VPN'
    if any(k in r for k in ('eth1', 'ens4', 'enp0s8', 'br-', 'br0', 'lan')):
        return 'LAN'
    return 'WAN'


def rule_to_dict(r: RegraFirewall) -> dict:
    return {
        'id':           r.id,
        'enabled':      r.enabled,
        'priority':     r.priority,
        'action':       r.action,
        'iface':        r.iface,
        'dir':          r.dir,
        'proto':        r.proto,
        'src':          r.src,
        'dst':          r.dst,
        'port':         r.port,
        'desc':         r.desc,
        'pendente':     r.pendente,
        'sincronizada': r.sincronizada,
    }


def nat_to_dict(n: NatEntry) -> dict:
    return {
        'id': n.id, 'name': n.name, 'iface': n.iface,
        'wan_port': n.wan_port, 'lan_ip': str(n.lan_ip),
        'lan_port': n.lan_port, 'proto': n.proto, 'enabled': n.enabled,
    }


def block_to_dict(b: BlocklistEntry) -> dict:
    return {
        'id': b.id, 'ip': b.ip, 'reason': b.reason,
        'source': b.source, 'date': b.criado_em.strftime('%Y-%m-%d'), 'expires': b.expires,
    }


def allow_to_dict(a: AllowlistEntry) -> dict:
    return {
        'id': a.id, 'ip': a.ip, 'reason': a.reason,
        'date': a.criado_em.strftime('%Y-%m-%d'),
    }


def geo_to_dict(g: GeoblockEntry) -> dict:
    return {
        'id': g.id, 'country': g.country, 'code': g.code,
        'dir': g.dir, 'enabled': g.enabled,
    }


def evento_to_log(e: EventoFirewall) -> dict:
    return {
        'id':        str(e.id),
        'time':      e.timestamp.strftime('%H:%M:%S'),
        'action':    e.acao,
        'iface':     map_iface(e.iface),
        'src_ip':    e.src_ip,
        'dst_ip':    str(e.dst_ip or '—'),
        'dst_port':  str(e.dst_port or '—'),
        'proto':     e.proto,
        'rule_id':   0,
        'rule_desc': f"{e.prefixo} {e.chain}".strip() or '—',
        'bytes':     e.tamanho or 0,
        'reason':    e.flags_tcp or e.chain or '—',
    }


# ─────────────────────────────────────────────────────────────────────────────
# SYNC / SENSOR
# ─────────────────────────────────────────────────────────────────────────────

def sync_status() -> dict:
    total     = RegraFirewall.objects.filter(enabled=True, deletado=False).count()
    pendentes = RegraFirewall.objects.filter(enabled=True, deletado=False, pendente=True).count()
    aplicadas = RegraFirewall.objects.filter(enabled=True, deletado=False, sincronizada=True).count()
    return {
        'total':     total,
        'pendentes': pendentes,
        'aplicadas': aplicadas,
        'em_sync':   total > 0 and pendentes == 0,
    }


def get_sensor_firewall():
    try:
        from incidentes.models import Sensor
        sensor_ids = (
            EventoFirewall.objects
            .exclude(sensor__isnull=True)
            .values_list('sensor_id', flat=True)
            .distinct()
        )
        return (
            Sensor.objects
            .filter(id__in=sensor_ids, ativo=True)
            .order_by('-last_seen')
            .first()
        )
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# COMUNICAÇÃO COM O AGENTE
# ─────────────────────────────────────────────────────────────────────────────

def notificar_agente(endpoint: str, payload: dict) -> tuple[bool, str]:
    """
    Chama o agente Flask diretamente no sensor Linux.
    Retorna (True, msg) se respondeu, (False, erro) se falhou.
    Fallback silencioso — poll de 30s pega se o agente estiver offline.
    """
    try:
        from incidentes.models import Sensor

        sensor = get_sensor_firewall()
        if not sensor:
            sensor = Sensor.objects.filter(ativo=True).order_by('-last_seen').first()
        if not sensor:
            return False, 'Nenhum sensor ativo encontrado'

        porta = 8765
        if ConfigSistema:
            try:
                porta = ConfigSistema.get_solo().fw_agente_porta or 8765
            except Exception:
                pass

        url  = f"http://{sensor.ip}:{porta}{endpoint}"
        data = json.dumps(payload).encode()
        req  = _urllib_req.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("X-MS-TOKEN",   sensor.token)
        resp   = _urllib_req.urlopen(req, timeout=3)
        result = json.loads(resp.read())
        if result.get('ok'):
            n = result.get('aplicadas', 0)
            return True, f'{n} regra(s) aplicada(s) no Linux'
        return False, result.get('error', 'Agente retornou erro')

    except Exception as e:
        return False, str(e)


def push_regras_ao_agente() -> tuple[bool, str]:
    """
    Envia todas as regras ativas ao agente em thread separada.
    Aguarda até 4s e retorna (ok, msg) para o frontend.

    Nota sobre iface_map:
      O Django não sabe o mapeamento WAN→enp0s3 do sensor.
      Mandamos iface_map={} — o agente usa seu próprio config.json.
      Evita o bug de mandar {"enp0s3":"enp0s3"} que não resolve
      os nomes lógicos WAN/LAN das regras.
    """
    result = [False, 'Enviando...']

    def _enviar():
        try:
            rules = list(
                RegraFirewall.objects
                .filter(enabled=True, deletado=False)
                .order_by('priority')
                .values()
            )
            # iface_map vazio → agente usa seu próprio config.json
            ok, msg   = notificar_agente("/aplicar", {"rules": rules, "iface_map": {}})
            result[0] = ok
            result[1] = msg
        except Exception as e:
            result[0] = False
            result[1] = str(e)

    t = threading.Thread(target=_enviar, daemon=True)
    t.start()
    t.join(timeout=4)
    return result[0], result[1]


# ─────────────────────────────────────────────────────────────────────────────
# PROTEÇÃO ANTI-AUTO-BLOQUEIO
# ─────────────────────────────────────────────────────────────────────────────

def _get_ips_criticos() -> list[str]:
    """
    Detecta automaticamente todos os IPs críticos do ambiente,
    igual o sincronizador do sensor faz — sem hardcode.

    Retorna lista com:
      - IP do próprio Django (UDP trick)
      - IP do sensor ativo (do banco)
      - IP do gateway padrão (tabela de roteamento do Django)
      - settings.MOONSHIELD_IPS_CRITICOS (lista opcional, para adicionar mais)
    """
    import subprocess, re as _re
    ips = []

    # 1. IP do Django via UDP trick
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith('127.') and ip not in ips:
            ips.append(ip)
    except Exception:
        pass

    # 2. IP(s) do(s) sensor(es) ativo(s) — lido do banco
    try:
        from incidentes.models import Sensor
        for s in Sensor.objects.filter(ativo=True).values_list('ip', flat=True):
            if s and s not in ips:
                ips.append(s)
    except Exception:
        pass

    # 3. Gateway padrão via tabela de roteamento
    try:
        result = subprocess.run(
            ['ip', 'route', 'show', 'default'],
            capture_output=True, text=True, timeout=3,
        )
        m = _re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
        if m:
            gw = m.group(1)
            if gw not in ips:
                ips.append(gw)
    except Exception:
        pass

    # 4. IPs extras definidos manualmente no settings.py (opcional)
    try:
        from django.conf import settings
        extras = getattr(settings, 'MOONSHIELD_IPS_CRITICOS', [])
        for ip in extras:
            if ip and ip not in ips:
                ips.append(ip)
    except Exception:
        pass

    return ips


def validar_regra_segura(payload: dict) -> tuple[bool, str]:
    """
    Verifica se a regra não bloqueará nenhum IP crítico do ambiente.
    IPs críticos: Django, sensor(es), gateway — todos auto-detectados.
    Retorna (True, '') se segura, (False, mensagem) se perigosa.
    """
    if payload.get('action') != 'deny':
        return True, ''

    src = (payload.get('src') or 'any').strip()
    if src == 'any':
        return True, ''

    ips_criticos = _get_ips_criticos()
    if not ips_criticos:
        return True, ''

    import ipaddress
    try:
        rede_regra = ipaddress.ip_network(src, strict=False)
        for ip_critico in ips_criticos:
            try:
                if ipaddress.ip_address(ip_critico) in rede_regra:
                    return False, (
                        f'Não é possível bloquear {src} — '
                        f'este range inclui um servidor crítico do MoonShield ({ip_critico}). '
                        f'Isso causaria perda de acesso ou comunicação entre componentes.'
                    )
            except ValueError:
                continue
    except ValueError:
        pass

    return True, ''


# ─────────────────────────────────────────────────────────────────────────────
# DADOS DE DEMONSTRAÇÃO
# ─────────────────────────────────────────────────────────────────────────────

_SRC_IPS    = ['185.22.11.4','45.142.212.5','91.108.4.12','198.51.100.4','103.235.46.3','77.88.55.88','185.220.101.2','194.165.16.4','5.188.86.172','46.148.127.9']
_DST_IPS    = ['10.0.0.10','10.0.0.21','10.0.0.5','10.0.0.15','192.168.1.100']
_PORTS      = ['22','80','443','3389','8080','23','21','25','53','3306','1194','161']
_IFACES     = ['WAN','LAN','VPN']
_PROTOS     = ['TCP','UDP','ICMP']
_REASONS    = ['Policy match','Port scan detected','Brute force limit','GeoBlock','Default deny','Rate limit SSH','Blocklist match','Auto-ban']
_RULE_DESCS = {100:'HTTPS Inbound WAN',101:'HTTP Inbound WAN',102:'Bloquear SSH externo',103:'Bloquear Telnet',104:'Bloquear RDP externo',105:'LAN → HTTPS out',106:'LAN → DNS out',107:'Bloquear SMTP saída',108:'OpenVPN Tunnel',109:'Permitir ICMP Ping',110:'Bloquear range TOR',111:'LAN → Proxy',112:'Bloquear SNMP externo',113:'Gateway LAN livre',114:'Default deny ALL WAN',115:'Rate limit SSH'}

def _ri(a, b):     return random.randint(a, b)
def _pick(lst):    return random.choice(lst)
def _arr(n, a, b): return [_ri(a, b) for _ in range(n)]

def _hour_labels():
    h = datetime.now().hour
    return [f'{(h - 23 + i) % 24:02d}h' for i in range(24)]

def _gen_log() -> dict:
    d = datetime.now()
    rule_id = _ri(100, 115)
    return {
        'id':        str(uuid.uuid4()),
        'time':      f'{d.hour:02d}:{d.minute:02d}:{d.second:02d}',
        'action':    _pick(['DENY','DENY','DROP','DROP','ALLOW']),
        'iface':     _pick(_IFACES),
        'src_ip':    _pick(_SRC_IPS),
        'dst_ip':    _pick(_DST_IPS),
        'dst_port':  _pick(_PORTS),
        'proto':     _pick(_PROTOS),
        'rule_id':   rule_id,
        'rule_desc': _RULE_DESCS.get(rule_id, 'Regra genérica'),
        'bytes':     _ri(64, 65535),
        'reason':    _pick(_REASONS),
    }

def demo_data(period: str) -> dict:
    mult         = {'1h': .15, '24h': 1, '7d': 4.5, '30d': 18}.get(period, 1)
    src_ips_demo = _SRC_IPS[:5]
    return {
        'ok': True, 'mode': 'demo',
        'metrics': {
            'traffic_in':    int(_ri(800,  2800) * mult),
            'traffic_out':   int(_ri(200,  900)  * mult),
            'conexoes':      _ri(80, 450),
            'drops':         int(_ri(1200, 4800) * mult),
            'allows':        int(_ri(8000, 28000) * mult),
            'top_port':      _pick(_PORTS),
            'top_port_hits': _ri(300, 900),
            'top_ip':        _pick(_SRC_IPS),
            'top_ip_hits':   _ri(80, 400),
            'cpu':           _ri(8, 28),
            'ram':           _ri(30, 55),
        },
        'charts': {
            'hours':       _hour_labels(),
            'traffic_in':  _arr(24, 10, 180),
            'traffic_out': _arr(24, 5,  80),
            'drops':       _arr(24, 20, 500),
            'denies':      _arr(24, 10, 200),
        },
        'top_ips': [
            {'ip': src_ips_demo[0], 'hits': _ri(200, 500)},
            {'ip': src_ips_demo[1], 'hits': _ri(100, 200)},
            {'ip': src_ips_demo[2], 'hits': _ri(50,  120)},
            {'ip': src_ips_demo[3], 'hits': _ri(20,   60)},
            {'ip': src_ips_demo[4], 'hits': _ri(5,    25)},
        ],
        'rules': [
            {'id':100,'enabled':True, 'priority':10, 'action':'allow','iface':'WAN','dir':'in', 'proto':'TCP', 'src':'any','dst':'10.0.0.0/8','port':'443','desc':'HTTPS Inbound WAN','pendente':False,'sincronizada':True},
            {'id':101,'enabled':True, 'priority':20, 'action':'allow','iface':'WAN','dir':'in', 'proto':'TCP', 'src':'any','dst':'10.0.0.0/8','port':'80', 'desc':'HTTP Inbound WAN','pendente':False,'sincronizada':True},
            {'id':102,'enabled':True, 'priority':30, 'action':'deny', 'iface':'WAN','dir':'in', 'proto':'TCP', 'src':'any','dst':'any','port':'22', 'desc':'Bloquear SSH externo','pendente':False,'sincronizada':True},
            {'id':103,'enabled':True, 'priority':40, 'action':'deny', 'iface':'WAN','dir':'in', 'proto':'TCP', 'src':'any','dst':'any','port':'23', 'desc':'Bloquear Telnet','pendente':False,'sincronizada':True},
            {'id':104,'enabled':True, 'priority':50, 'action':'deny', 'iface':'WAN','dir':'in', 'proto':'TCP', 'src':'any','dst':'any','port':'3389','desc':'Bloquear RDP externo','pendente':True,'sincronizada':False},
            {'id':105,'enabled':True, 'priority':60, 'action':'allow','iface':'LAN','dir':'out','proto':'TCP', 'src':'10.0.0.0/24','dst':'any','port':'443','desc':'LAN → HTTPS out','pendente':False,'sincronizada':True},
            {'id':106,'enabled':True, 'priority':70, 'action':'allow','iface':'LAN','dir':'out','proto':'UDP', 'src':'10.0.0.0/24','dst':'any','port':'53', 'desc':'LAN → DNS out','pendente':False,'sincronizada':True},
            {'id':107,'enabled':True, 'priority':80, 'action':'deny', 'iface':'LAN','dir':'out','proto':'TCP', 'src':'any','dst':'any','port':'25', 'desc':'Bloquear SMTP saída','pendente':False,'sincronizada':True},
            {'id':108,'enabled':False,'priority':90, 'action':'allow','iface':'VPN','dir':'in', 'proto':'UDP', 'src':'192.168.1.0/24','dst':'10.0.0.0/8','port':'1194','desc':'OpenVPN Tunnel','pendente':False,'sincronizada':False},
            {'id':109,'enabled':True, 'priority':100,'action':'allow','iface':'WAN','dir':'in', 'proto':'ICMP','src':'any','dst':'any','port':'any','desc':'Permitir ICMP Ping','pendente':False,'sincronizada':True},
            {'id':110,'enabled':True, 'priority':110,'action':'deny', 'iface':'WAN','dir':'in', 'proto':'TCP', 'src':'185.220.0.0/14','dst':'any','port':'any','desc':'Bloquear range TOR','pendente':False,'sincronizada':True},
            {'id':111,'enabled':True, 'priority':120,'action':'allow','iface':'LAN','dir':'out','proto':'TCP', 'src':'10.0.0.0/24','dst':'any','port':'8080','desc':'LAN → Proxy','pendente':False,'sincronizada':True},
            {'id':112,'enabled':False,'priority':130,'action':'deny', 'iface':'WAN','dir':'in', 'proto':'UDP', 'src':'any','dst':'any','port':'161','desc':'Bloquear SNMP externo','pendente':False,'sincronizada':False},
            {'id':113,'enabled':True, 'priority':140,'action':'allow','iface':'LAN','dir':'in', 'proto':'any', 'src':'10.0.0.1','dst':'any','port':'any','desc':'Gateway LAN livre','pendente':False,'sincronizada':True},
            {'id':114,'enabled':True, 'priority':999,'action':'deny', 'iface':'WAN','dir':'in', 'proto':'any', 'src':'any','dst':'any','port':'any','desc':'Default deny ALL WAN','pendente':False,'sincronizada':True},
        ],
        'logs': [_gen_log() for _ in range(80)],
        'nat': [
            {'id':1,'name':'HTTP Public', 'iface':'WAN','wan_port':'80',  'lan_ip':'10.0.0.10','lan_port':'80',  'proto':'TCP','enabled':True},
            {'id':2,'name':'HTTPS Public','iface':'WAN','wan_port':'443', 'lan_ip':'10.0.0.10','lan_port':'443', 'proto':'TCP','enabled':True},
            {'id':3,'name':'VPN OpenVPN', 'iface':'WAN','wan_port':'1194','lan_ip':'10.0.0.1', 'lan_port':'1194','proto':'UDP','enabled':True},
            {'id':4,'name':'SSH Admin',   'iface':'WAN','wan_port':'2222','lan_ip':'10.0.0.1', 'lan_port':'22',  'proto':'TCP','enabled':True},
        ],
        'blocklist': [
            {'ip':'185.22.11.4',     'reason':'Port scan',       'source':'Auto','date':'2025-02-20','expires':'2025-03-20'},
            {'ip':'45.142.212.0/24', 'reason':'Brute force SSH', 'source':'SOC', 'date':'2025-02-18','expires':'∞'},
            {'ip':'91.108.4.12',     'reason':'Malware C2',      'source':'SOC', 'date':'2025-02-15','expires':'∞'},
        ],
        'allowlist': [
            {'ip':'8.8.8.8',   'reason':'Google DNS',    'date':'2024-12-01'},
            {'ip':'1.1.1.1',   'reason':'Cloudflare DNS','date':'2024-12-01'},
            {'ip':'10.0.0.0/8','reason':'Rede local',    'date':'2024-12-01'},
        ],
        'geoblock': [
            {'country':'Rússia',         'code':'RU','dir':'IN','enabled':True},
            {'country':'China',          'code':'CN','dir':'IN','enabled':True},
            {'country':'Coreia do Norte','code':'KP','dir':'IN','enabled':True},
        ],
        'sync': {'total': 15, 'pendentes': 1, 'aplicadas': 12, 'em_sync': False},
        'last_update': datetime.now().isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# EXPORT NFT
# ─────────────────────────────────────────────────────────────────────────────

def regra_para_nft_inline(r: RegraFirewall, iface_map: dict) -> str | None:
    partes = []
    iface_nome = iface_map.get(r.iface, '')
    if iface_nome:
        direcao = 'iifname' if r.dir == 'in' else 'oifname'
        partes.append(f'{direcao} "{iface_nome}"')
    if r.src and r.src != 'any':
        partes.append(f'ip saddr {r.src}')
    if r.dst and r.dst != 'any':
        partes.append(f'ip daddr {r.dst}')
    proto = r.proto.lower()
    if proto not in ('any', ''):
        partes.append('ip protocol icmp' if proto == 'icmp' else proto)
    port = str(r.port)
    if port and port != 'any' and proto in ('tcp', 'udp'):
        if '-' in port:
            a, b = port.split('-', 1)
            partes.append(f'dport {a.strip()}-{b.strip()}')
        else:
            partes.append(f'dport {port}')
    partes.append('accept' if r.action == 'allow' else 'drop')
    return ' '.join(partes) if partes else None


# ─────────────────────────────────────────────────────────────────────────────
# DADOS DE PRODUÇÃO
# ─────────────────────────────────────────────────────────────────────────────

def prod_waiting() -> dict:
    agora_ts    = timezone.now()
    hour_labels = [(agora_ts - timedelta(hours=23 - i)).strftime('%Hh') for i in range(24)]
    rules     = [rule_to_dict(r)  for r in RegraFirewall.objects.filter(deletado=False).order_by('priority')]
    nat       = [nat_to_dict(n)   for n in NatEntry.objects.all()]
    blocklist = [block_to_dict(b) for b in BlocklistEntry.objects.all()]
    allowlist = [allow_to_dict(a) for a in AllowlistEntry.objects.all()]
    geoblock  = [geo_to_dict(g)   for g in GeoblockEntry.objects.all()]
    return {
        'ok': True, 'mode': 'prod', 'waiting': True,
        'msg': 'Modo Produção ativo. Aguardando o primeiro evento do ms_firewall.py.',
        'metrics': {
            'traffic_in': 0, 'traffic_out': 0, 'conexoes': 0,
            'drops': 0, 'allows': 0,
            'top_port': '—', 'top_port_hits': 0,
            'top_ip': '—', 'top_ip_hits': 0, 'cpu': 0, 'ram': 0,
        },
        'charts': {
            'hours': hour_labels,
            'traffic_in': [0] * 24, 'traffic_out': [0] * 24,
            'drops': [0] * 24, 'denies': [0] * 24,
        },
        'rules': rules, 'logs': [], 'nat': nat,
        'blocklist': blocklist, 'allowlist': allowlist, 'geoblock': geoblock,
        'sync': sync_status(),
        'last_update': agora_ts.isoformat(),
    }


def prod_data(period: str) -> dict:
    delta_h  = delta_horas(period)
    agora_ts = timezone.now()
    desde    = agora_ts - timedelta(hours=delta_h)

    qs     = EventoFirewall.objects.filter(timestamp__gte=desde)
    drops  = qs.filter(acao__in=['DROP', 'DENY']).count()
    allows = qs.filter(acao__in=['ALLOW', 'LOG']).count()

    total_bytes = qs.aggregate(s=Sum('tamanho'))['s'] or 0
    traffic_mb  = max(0, total_bytes // 1_048_576)
    traffic_in  = int(traffic_mb * 0.7)
    traffic_out = int(traffic_mb * 0.3)

    recente  = agora_ts - timedelta(minutes=5)
    conexoes = (
        EventoFirewall.objects
        .filter(timestamp__gte=recente, acao__in=['ALLOW', 'LOG'])
        .values('src_ip').distinct().count()
    )

    top_port_row = (
        qs.filter(acao__in=['DROP', 'DENY']).exclude(dst_port__isnull=True)
        .values('dst_port').annotate(n=Count('dst_port')).order_by('-n').first()
    )
    top_port      = str(top_port_row['dst_port']) if top_port_row else '—'
    top_port_hits = top_port_row['n']             if top_port_row else 0

    top_ip_row = (
        qs.filter(acao__in=['DROP', 'DENY'])
        .values('src_ip').annotate(n=Count('src_ip')).order_by('-n').first()
    )
    top_ip      = top_ip_row['src_ip'] if top_ip_row else '—'
    top_ip_hits = top_ip_row['n']      if top_ip_row else 0

    top_ips = [
        {'ip': r['src_ip'], 'hits': r['hits']}
        for r in (
            qs.filter(acao__in=['DROP', 'DENY'])
            .values('src_ip').annotate(hits=Count('src_ip')).order_by('-hits')[:5]
        )
    ]

    qs_24  = EventoFirewall.objects.filter(timestamp__gte=agora_ts - timedelta(hours=24))
    hourly = (
        qs_24.annotate(hora=TruncHour('timestamp'))
        .values('hora', 'acao')
        .annotate(n=Count('id'), total_bytes=Sum('tamanho'))
        .order_by('hora')
    )

    hour_data: dict[str, dict] = {}
    for row in hourly:
        lbl = row['hora'].strftime('%Hh')
        if lbl not in hour_data:
            hour_data[lbl] = {'in': 0, 'out': 0, 'drops': 0, 'denies': 0}
        b = (row['total_bytes'] or 0) // 1_048_576
        if row['acao'] in ('ALLOW', 'LOG'):
            hour_data[lbl]['in']  += int(b * 0.7)
            hour_data[lbl]['out'] += int(b * 0.3)
        elif row['acao'] == 'DROP':
            hour_data[lbl]['drops']  += row['n']
        elif row['acao'] == 'DENY':
            hour_data[lbl]['denies'] += row['n']

    hour_labels  = [(agora_ts - timedelta(hours=23 - i)).strftime('%Hh') for i in range(24)]
    chart_in     = [hour_data.get(h, {}).get('in',     0) for h in hour_labels]
    chart_out    = [hour_data.get(h, {}).get('out',    0) for h in hour_labels]
    chart_drops  = [hour_data.get(h, {}).get('drops',  0) for h in hour_labels]
    chart_denies = [hour_data.get(h, {}).get('denies', 0) for h in hour_labels]

    rules     = [rule_to_dict(r)  for r in RegraFirewall.objects.filter(deletado=False).order_by('priority')]
    nat       = [nat_to_dict(n)   for n in NatEntry.objects.all()]
    blocklist = [block_to_dict(b) for b in BlocklistEntry.objects.all()]
    allowlist = [allow_to_dict(a) for a in AllowlistEntry.objects.all()]
    geoblock  = [geo_to_dict(g)   for g in GeoblockEntry.objects.all()]
    logs      = [
        evento_to_log(e)
        for e in EventoFirewall.objects.filter(timestamp__gte=desde).order_by('-timestamp')[:100]
    ]

    return {
        'ok': True, 'mode': 'prod',
        'metrics': {
            'traffic_in': traffic_in, 'traffic_out': traffic_out,
            'conexoes': conexoes, 'drops': drops, 'allows': allows,
            'top_port': top_port, 'top_port_hits': top_port_hits,
            'top_ip': top_ip, 'top_ip_hits': top_ip_hits, 'cpu': 0, 'ram': 0,
        },
        'charts': {
            'hours': hour_labels,
            'traffic_in': chart_in, 'traffic_out': chart_out,
            'drops': chart_drops, 'denies': chart_denies,
        },
        'top_ips':   top_ips,
        'rules':     rules, 'logs': logs, 'nat': nat,
        'blocklist': blocklist, 'allowlist': allowlist, 'geoblock': geoblock,
        'sync':        sync_status(),
        'last_update': agora_ts.isoformat(),
    }