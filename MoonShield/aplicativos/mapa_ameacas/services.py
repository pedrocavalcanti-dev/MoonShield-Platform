import logging
from datetime import datetime
from django.utils import timezone
from django.db.models import Count, Max, Q
import ipaddress
from configuracoes.models import ConfigSistema
from incidentes.models import EventoBruto, GeoCache
from firewall.models import EventoFirewall

logger = logging.getLogger(__name__)

def _is_global_ip(ip_str: str) -> bool:
    """Retorna True apenas se o IP for publicamente roteável e geolocalizável."""
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_global
    except ValueError:
        return False

class FeedNormalizer:
    def __init__(self, start_time: datetime, severities: list = None, sources: list = None,
                 category: str = None, country: str = None, query: str = None):
        self.start_time = start_time
        self.severities = severities or ['all']
        self.sources = sources or ['all']
        self.category = category
        self.country = country
        self.query = query

        self.cfg = ConfigSistema.get_solo()
        # Inicializa o estado de saúde como online para todas as fontes solicitadas
        self.source_health = {
            'ids': 'online',
            'firewall': 'online',
            'dns': 'online',
        }

    def _get_node_location(self) -> dict:
        """Obtém a localização local configurada do Node (MoonShield Appliance)."""
        loc = {
            "latitude": self.cfg.node_latitude,
            "longitude": self.cfg.node_longitude,
            "city": self.cfg.node_city,
            "country_code": self.cfg.node_country_code,
            "geolocatable": bool(self.cfg.node_latitude and self.cfg.node_longitude)
        }
        return loc

    def _get_geo(self, ip: str) -> dict:
        """Consulta GeoCache offline de maneira determinística."""
        if not ip or not _is_global_ip(ip):
            return {"geolocatable": False}

        cached = GeoCache.objects.filter(ip=ip).first()
        if cached and cached.latitude and cached.longitude:
            return {
                "latitude": float(cached.latitude),
                "longitude": float(cached.longitude),
                "city": cached.cidade,
                "country_code": cached.pais_codigo,
                "geolocatable": True
            }
        return {"geolocatable": False}

    def _normalize_severity(self, sev: str) -> str:
        if not sev:
            return "low"
        sev = sev.lower()
        if sev in ["1", "high", "critical"]: return "critical"
        if sev in ["2", "medium", "warning"]: return "medium"
        return "low"

    def _determine_direction_and_external(self, src_ip: str, dst_ip: str):
        """
        Determina a direção e o endpoint geográfico externo baseado em validade global.
        Retorna (direction, external_ip).
        """
        src_global = _is_global_ip(src_ip)
        dst_global = _is_global_ip(dst_ip)

        if src_global and not dst_global:
            return "inbound", src_ip
        elif not src_global and dst_global:
            return "outbound", dst_ip
        elif not src_global and not dst_global:
            return "internal", None
        else:
            # Caso ambos sejam globais ou situação ambígua, mantemos unknown com o source atuando como external
            return "unknown", src_ip

    def get_suricata_events(self, max_limit=200):
        if 'ids' not in self.sources and 'all' not in self.sources:
            return []

        qs = EventoBruto.objects.filter(
            event_type='alert',
            timestamp__gte=self.start_time
        )
        if self.category and self.category != 'all':
            qs = qs.filter(categoria__iexact=self.category)

        # Filtro de país: se for inbound, o src_ip é o external endpoint.
        # Como o Suricata pode registrar inbound ou outbound, tentamos buscar IPs no GeoCache
        if self.country and self.country != 'all':
            geo_ips = GeoCache.objects.filter(pais_codigo__iexact=self.country).values('ip')
            qs = qs.filter(Q(src_ip__in=geo_ips) | Q(dest_ip__in=geo_ips))

        if self.query:
            qs = qs.filter(Q(src_ip__icontains=self.query) | Q(dest_ip__icontains=self.query) | Q(signature__icontains=self.query))

        qs = qs.values(
            'src_ip', 'dest_ip', 'dest_porta', 'protocolo',
            'signature', 'sid', 'categoria', 'severidade', 'incidente_id'
        ).annotate(
            count=Count('id'),
            last_seen=Max('timestamp')
        ).order_by('-last_seen')[:max_limit]

        events = []
        for item in qs:
            sev = self._normalize_severity(item['severidade'])
            if self.severities and sev not in self.severities and 'all' not in self.severities:
                continue

            src_ip = item.get('src_ip')
            dst_ip = item.get('dest_ip')

            direction, external_ip = self._determine_direction_and_external(src_ip, dst_ip)

            # Filtro país (post-filtro) caso o país bata mas a direção do evento torne o IP filtrado interno
            if self.country and self.country != 'all':
                if not external_ip: continue
                ext_geo = self._get_geo(external_ip)
                if ext_geo.get("country_code", "").lower() != self.country.lower():
                    continue

            src_geo = self._get_geo(src_ip)
            dst_geo = self._get_geo(dst_ip)

            ext_geo = self._get_geo(external_ip) if external_ip else {"geolocatable": False}

            events.append({
                "id": f"suricata-{src_ip}-{item['signature']}-{item['last_seen'].timestamp()}",
                "timestamp": item['last_seen'].strftime("%H:%M:%S"),
                "ts": item['last_seen'].isoformat(),
                "source": "ids",
                "event_class": "threat",
                "category": item['categoria'] or "other",
                "severity": sev,
                "src_ip": src_ip,
                "src_port": None,
                "dst_ip": dst_ip,
                "dst_port": item['dest_porta'],
                "protocol": item['protocolo'],
                "direction": direction,
                "signature": item['signature'] or None,
                "action": "detected",
                "src_geo": src_geo,
                "dst_geo": dst_geo,
                "external_ip": external_ip,
                "external_geo": ext_geo,
                "geolocatable": ext_geo.get('geolocatable', False),
                "count": item['count'],
                "incident_id": item['incidente_id'],
                "rule_id": item['sid'] or None,
                "domain": None
            })
        return events

    def get_firewall_events(self, max_limit=200):
        if 'firewall' not in self.sources and 'all' not in self.sources:
            return []

        qs = EventoFirewall.objects.filter(
            timestamp__gte=self.start_time,
            acao__in=["DROP", "DENY", "REJECT"]
        )
        if self.category and self.category != 'all' and self.category != 'firewall_block':
            return []

        if self.country and self.country != 'all':
            geo_ips = GeoCache.objects.filter(pais_codigo__iexact=self.country).values('ip')
            qs = qs.filter(Q(src_ip__in=geo_ips) | Q(dst_ip__in=geo_ips))

        if self.query:
            qs = qs.filter(Q(src_ip__icontains=self.query) | Q(dst_ip__icontains=self.query))

        qs = qs.values(
            'src_ip', 'dst_ip', 'dst_port', 'proto', 'acao', 'chain'
        ).annotate(
            count=Count('id'),
            last_seen=Max('timestamp')
        ).order_by('-last_seen')[:max_limit]

        events = []
        for item in qs:
            sev = "low" # Default firewall block severity
            if self.severities and sev not in self.severities and 'all' not in self.severities:
                continue

            src_ip = item.get('src_ip')
            dst_ip = item.get('dst_ip')

            direction, external_ip = self._determine_direction_and_external(src_ip, dst_ip)

            if self.country and self.country != 'all':
                if not external_ip: continue
                ext_geo = self._get_geo(external_ip)
                if ext_geo.get("country_code", "").lower() != self.country.lower():
                    continue

            src_geo = self._get_geo(src_ip)
            dst_geo = self._get_geo(dst_ip)
            ext_geo = self._get_geo(external_ip) if external_ip else {"geolocatable": False}

            events.append({
                "id": f"fw-{src_ip}-{item['last_seen'].timestamp()}",
                "timestamp": item['last_seen'].strftime("%H:%M:%S"),
                "ts": item['last_seen'].isoformat(),
                "source": "firewall",
                "event_class": "block",
                "category": "firewall_block",
                "severity": sev,
                "src_ip": src_ip,
                "src_port": None,
                "dst_ip": dst_ip,
                "dst_port": item['dst_port'],
                "protocol": item['proto'],
                "direction": direction,
                "signature": f"Firewall {item['acao']} ({item['chain']})",
                "action": "blocked",
                "src_geo": src_geo,
                "dst_geo": dst_geo,
                "external_ip": external_ip,
                "external_geo": ext_geo,
                "geolocatable": ext_geo.get('geolocatable', False),
                "count": item['count'],
                "incident_id": None,
                "rule_id": None,
                "domain": None
            })
        return events

    def get_dns_events(self, max_limit=200):
        if 'dns' not in self.sources and 'all' not in self.sources:
            return []

        try:
            from dns.services.adguard_bootstrap import criar_cliente_adguard_local
            client = criar_cliente_adguard_local()
            raw_logs = client.get_querylog_raw(limit=500)
        except Exception as e:
            logger.error(f"Erro ao buscar logs AdGuard: {e}")
            self.source_health['dns'] = 'offline'
            return []

        events = []

        agg = {}
        for entry in raw_logs:
            if self.category and self.category != 'all' and self.category != 'dns_block':
                continue
            if self.query:
                q_val = self.query.lower()
                if q_val not in str(entry.get('client', '')).lower() and q_val not in str(entry.get('question', {}).get('name', '')).lower():
                    continue

            entry_time_str = entry.get('time', '')
            if not entry_time_str:
                continue
            try:
                # Tratar possiveis naive datetimes com timezone awareness.
                # Como AdGuard retorna 'Z', timezone.datetime.fromisoformat substitui +00:00
                dt = timezone.datetime.fromisoformat(entry_time_str.replace('Z', '+00:00'))
                if dt < self.start_time:
                    continue
            except Exception:
                continue

            reason = entry.get('reason', '')
            if reason not in ['FilteredBlackList', 'FilteredSafeBrowsing', 'FilteredParental', 'Rewrite']:
                continue

            src_ip = entry.get('client', '')
            domain = entry.get('question', {}).get('name', '')
            key = f"{src_ip}-{domain}"

            if key not in agg:
                agg[key] = {
                    "count": 0,
                    "last_seen": dt,
                    "domain": domain,
                    "src_ip": src_ip,
                    "reason": reason
                }
            agg[key]["count"] += 1
            if dt > agg[key]["last_seen"]:
                agg[key]["last_seen"] = dt

        for key, item in list(agg.items())[:max_limit]:
            sev = "medium" if item['reason'] == "FilteredSafeBrowsing" else "low"
            if self.severities and sev not in self.severities and 'all' not in self.severities:
                continue

            src_ip = item['src_ip']
            direction = "outbound"

            src_geo = self._get_geo(src_ip)
            # Para DNS bloqueado, nao fazemos GeoIP do dominio/destino, senao estariamos resolvendo externamente
            dst_geo = {"geolocatable": False}
            ext_geo = {"geolocatable": False}

            events.append({
                "id": f"dns-{key}-{item['last_seen'].timestamp()}",
                "timestamp": item['last_seen'].strftime("%H:%M:%S"),
                "ts": item['last_seen'].isoformat(),
                "source": "dns",
                "event_class": "policy",
                "category": "dns_block",
                "severity": sev,
                "src_ip": src_ip,
                "src_port": None,
                "dst_ip": None, # DNS query interceptada nao gera um dst_ip valido, usamos domain
                "dst_port": 53,
                "protocol": "UDP",
                "direction": direction,
                "signature": f"DNS Block: {item['domain']}",
                "action": "blocked",
                "src_geo": src_geo,
                "dst_geo": dst_geo,
                "external_ip": None,
                "external_geo": ext_geo,
                "geolocatable": False,
                "count": item['count'],
                "incident_id": None,
                "rule_id": None,
                "domain": item['domain']
            })

        events.sort(key=lambda x: x['ts'], reverse=True)
        return events[:max_limit]

    def get_all_events(self, max_limit=200):
        evs = []
        evs.extend(self.get_suricata_events(max_limit))
        evs.extend(self.get_firewall_events(max_limit))
        evs.extend(self.get_dns_events(max_limit))

        evs.sort(key=lambda x: x['ts'], reverse=True)
        return evs[:max_limit]
