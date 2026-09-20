# =============================================================================
# incidentes/services/enriquecedor.py  v3
# GeoIP e direção de rede são derivados da SSOT em contexto_rede.
# =============================================================================

import logging
import os
import socket
from datetime import timedelta

from django.utils import timezone

from .contexto_rede import classificar_fluxo, classificar_ip_rede

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

# ─────────────────────────────────────────────────────────────────────────────
# API PÚBLICA
# ─────────────────────────────────────────────────────────────────────────────

def enriquecer_ip(ip: str) -> dict:
    if not ip:
        return _VAZIO.copy()

    contexto_rede = classificar_ip_rede(ip)
    if not contexto_rede['geoip_allowed']:
        return {**_VAZIO, 'is_private': contexto_rede['is_private'], 'rdns': _rdns(ip)}

    if ip in _mem_cache:
        return _mem_cache[ip]

    resultado = _buscar_geocache(ip)

    if not resultado:
        geo = _consultar_maxmind(ip)

        geo['rdns']       = _rdns(ip)
        geo['is_private'] = False

        _salvar_geocache(ip, geo)
        resultado = geo

    _mem_cache[ip] = resultado
    return resultado


def calcular_direction(src_ip: str, dst_ip: str) -> dict:
    fluxo = classificar_fluxo(src_ip, dst_ip)
    # O campo persistido legado ainda usa "lateral" para tráfego interno.
    # As APIs expõem ``flow_scope=internal`` calculado dinamicamente.
    fluxo['direction'] = 'lateral' if fluxo['flow_scope'] == 'internal' else fluxo['flow_scope']
    return fluxo


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
