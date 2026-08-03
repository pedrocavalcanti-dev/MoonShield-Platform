# =============================================================================
# incidentes/services/enriquecedor.py  v3
# Fix v3:
#   ✓ _cidr_cache agora tem TTL real de 60s (antes ficava preso para sempre)
#   ✓ Troca de CIDR no ConfigSistema reflete em até 60s sem reiniciar servidor
# =============================================================================

import ipaddress
import logging
import os
import socket
import time
from datetime import timedelta

from django.utils import timezone

logger = logging.getLogger(__name__)

# ─── Caminhos MaxMind ─────────────────────────────────────────────────────────
try:
    from django.conf import settings as _dj_settings
    _BASE = getattr(_dj_settings, 'GEOIP_PATH',
                    os.path.join(_dj_settings.BASE_DIR, 'data', 'geoip'))
except Exception:
    _BASE = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'data', 'geoip')

CAMINHO_CITY = os.path.join(str(_BASE), 'GeoLite2-City.mmdb')
CAMINHO_ASN  = os.path.join(str(_BASE), 'GeoLite2-ASN.mmdb')

# ─── Cache em memória ─────────────────────────────────────────────────────────
_mem_cache: dict = {}
_GEO_TTL = timedelta(hours=24)

_VAZIO = {
    'pais':        '',
    'pais_codigo': '',
    'cidade':      '',
    'latitude':    None,
    'longitude':   None,
    'asn_number':  '',
    'asn_org':     '',
    'asn':         '',
    'rdns':        '',
    'is_private':  False,
    'source':      '',
}

# ─── Cache do CIDR com TTL real ───────────────────────────────────────────────
_cidr_cache:    str   = ''
_cidr_cache_ts: float = 0.0
_CIDR_TTL = 60.0   # segundos


# ─────────────────────────────────────────────────────────────────────────────
# API PÚBLICA
# ─────────────────────────────────────────────────────────────────────────────

def enriquecer_ip(ip: str) -> dict:
    if not ip:
        return _VAZIO.copy()

    if ip in _mem_cache:
        return _mem_cache[ip]

    info = _ip_info(ip)

    if info['is_private']:
        resultado = {**_VAZIO, 'is_private': True}
        _mem_cache[ip] = resultado
        return resultado

    resultado = _buscar_geocache(ip)

    if not resultado:
        geo = _consultar_maxmind(ip)
        if not geo['pais']:
            geo = _consultar_ipapi(ip)

        geo['rdns']       = _rdns(ip)
        geo['is_private'] = False

        _salvar_geocache(ip, geo)
        resultado = geo

    _mem_cache[ip] = resultado
    return resultado


def calcular_direction(src_ip: str, dst_ip: str) -> dict:
    cidr      = _get_cidr_monitorado()
    src_local = _ip_esta_na_rede(src_ip, cidr)
    dst_local = _ip_esta_na_rede(dst_ip or '', cidr)

    if src_local and dst_local:
        direction = 'lateral'
    elif src_local and not dst_local:
        direction = 'outbound'
    elif not src_local and dst_local:
        direction = 'inbound'
    else:
        direction = 'external'

    return {
        'direction':    direction,
        'src_is_local': src_local,
        'dst_is_local': dst_local,
    }


# ─────────────────────────────────────────────────────────────────────────────
# GEO CACHE
# ─────────────────────────────────────────────────────────────────────────────

def _buscar_geocache(ip: str) -> dict | None:
    try:
        from ..models import GeoCache
        entrada = GeoCache.objects.filter(ip=ip).first()
        if not entrada:
            return None
        if (timezone.now() - entrada.updated_at) > _GEO_TTL:
            return None
        return {
            'pais':        entrada.pais,
            'pais_codigo': entrada.pais_codigo,
            'cidade':      entrada.cidade,
            'latitude':    entrada.latitude,
            'longitude':   entrada.longitude,
            'asn_number':  entrada.asn_number,
            'asn_org':     entrada.asn_org,
            'asn':         entrada.asn,
            'rdns':        entrada.rdns,
            'is_private':  False,
            'source':      entrada.source,
        }
    except Exception as e:
        logger.debug(f"GeoCache lookup falhou para {ip}: {e}")
        return None


def _salvar_geocache(ip: str, geo: dict):
    try:
        from ..models import GeoCache
        GeoCache.objects.update_or_create(
            ip=ip,
            defaults={
                'pais':        geo.get('pais', ''),
                'pais_codigo': geo.get('pais_codigo', ''),
                'cidade':      geo.get('cidade', ''),
                'latitude':    geo.get('latitude'),
                'longitude':   geo.get('longitude'),
                'asn_number':  geo.get('asn_number', ''),
                'asn_org':     geo.get('asn_org', ''),
                'rdns':        geo.get('rdns', ''),
                'source':      geo.get('source', 'unknown'),
            }
        )
    except Exception as e:
        logger.debug(f"GeoCache save falhou para {ip}: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# MAXMIND (offline)
# ─────────────────────────────────────────────────────────────────────────────

def _consultar_maxmind(ip: str) -> dict:
    resultado = {**_VAZIO}

    try:
        import geoip2.database

        if os.path.exists(CAMINHO_CITY):
            with geoip2.database.Reader(CAMINHO_CITY) as reader:
                r = reader.city(ip)
                resultado['pais']        = r.country.name or ''
                resultado['pais_codigo'] = r.country.iso_code or ''
                resultado['cidade']      = r.city.name or ''
                if r.location.latitude:
                    resultado['latitude']  = float(r.location.latitude)
                    resultado['longitude'] = float(r.location.longitude)

        if os.path.exists(CAMINHO_ASN):
            with geoip2.database.Reader(CAMINHO_ASN) as reader:
                r = reader.asn(ip)
                resultado['asn_number'] = f"AS{r.autonomous_system_number}"
                resultado['asn_org']    = r.autonomous_system_organization or ''
                resultado['asn']        = f"AS{r.autonomous_system_number} {r.autonomous_system_organization}"

        resultado['source'] = 'maxmind'

    except ImportError:
        logger.debug("geoip2 não instalado — usando ip-api.com")
    except Exception as e:
        logger.debug(f"MaxMind falhou para {ip}: {e}")

    return resultado


# ─────────────────────────────────────────────────────────────────────────────
# ip-api.com (online, fallback)
# ─────────────────────────────────────────────────────────────────────────────

def _consultar_ipapi(ip: str) -> dict:
    resultado = {**_VAZIO}

    try:
        import requests
        url  = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,as,org"
        resp = requests.get(url, timeout=3)

        if resp.status_code == 200:
            dados = resp.json()
            if dados.get('status') == 'success':
                asn_raw = dados.get('as', '')
                org_raw = dados.get('org', '')

                if asn_raw and asn_raw.startswith('AS'):
                    partes = asn_raw.split(' ', 1)
                    resultado['asn_number'] = partes[0]
                    resultado['asn_org']    = partes[1] if len(partes) > 1 else org_raw
                else:
                    resultado['asn_number'] = ''
                    resultado['asn_org']    = org_raw or asn_raw

                resultado['pais']        = dados.get('country', '')
                resultado['pais_codigo'] = dados.get('countryCode', '')
                resultado['cidade']      = dados.get('city', '')
                resultado['latitude']    = dados.get('lat')
                resultado['longitude']   = dados.get('lon')
                resultado['asn']         = asn_raw
                resultado['source']      = 'ip-api'

    except Exception as e:
        logger.debug(f"ip-api.com falhou para {ip}: {e}")

    return resultado


# ─────────────────────────────────────────────────────────────────────────────
# rDNS
# ─────────────────────────────────────────────────────────────────────────────

def _rdns(ip: str) -> str:
    try:
        socket.setdefaulttimeout(1.0)
        nome = socket.getfqdn(ip)
        socket.setdefaulttimeout(None)
        return nome if nome != ip else ''
    except Exception:
        return ''


# ─────────────────────────────────────────────────────────────────────────────
# IP INFO
# ─────────────────────────────────────────────────────────────────────────────

def _ip_info(ip: str) -> dict:
    try:
        obj = ipaddress.ip_address(ip)
        return {
            'is_private':   obj.is_private,
            'is_loopback':  obj.is_loopback,
            'is_multicast': obj.is_multicast,
            'is_reserved':  obj.is_reserved,
        }
    except ValueError:
        return {'is_private': False, 'is_loopback': False,
                'is_multicast': False, 'is_reserved': False}


# ─────────────────────────────────────────────────────────────────────────────
# DIREÇÃO DO TRÁFEGO — CIDR com TTL real de 60s
# ─────────────────────────────────────────────────────────────────────────────

def _get_cidr_monitorado() -> str:
    """
    Pega o CIDR configurado no banco.
    Cache em memória com TTL de 60s — mudanças no ConfigSistema
    refletem automaticamente sem reiniciar o servidor.
    """
    global _cidr_cache, _cidr_cache_ts

    agora = time.monotonic()
    if _cidr_cache and (agora - _cidr_cache_ts) < _CIDR_TTL:
        return _cidr_cache

    try:
        from configuracoes.models import ConfigSistema
        cfg = ConfigSistema.get_solo()
        _cidr_cache    = cfg.cidr or '192.168.0.0/24'
        _cidr_cache_ts = agora
    except Exception:
        # Não atualiza o timestamp no erro — tenta de novo na próxima chamada
        if not _cidr_cache:
            _cidr_cache = '192.168.0.0/24'

    return _cidr_cache


def _ip_esta_na_rede(ip: str, cidr: str) -> bool:
    if not ip or not cidr:
        return False
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False