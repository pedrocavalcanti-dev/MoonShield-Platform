import logging
import ipaddress
from datetime import datetime
from django.db.models import Count, Min, Max
from incidentes.models import EventoBruto, GeoCache
from incidentes.services.enriquecedor import _buscar_geocache
from firewall.models import EventoFirewall
from configuracoes.models import ConfigSistema

logger = logging.getLogger(__name__)

class FeedNormalizer:
    def __init__(self, start_time: datetime, severities: list, sources: list, category: str = None, country: str = None, query: str = None):
        self.start_time = start_time
        self.severities = severities
        self.sources = sources
        self.category = category
        self.country = country
        self.query = query
        self.cfg = ConfigSistema.get_solo()

    def _normalize_severity(self, raw_sev: str) -> str:
        # Normalize to critical, high, medium, low, info
        raw = str(raw_sev).lower() if raw_sev else ""
        if raw in ['1', 'critical', 'crítico']: return 'critical'
        if raw in ['2', 'high', 'alto']: return 'high'
        if raw in ['3', 'medium', 'médio']: return 'medium'
        if raw in ['4', 'low', 'baixo']: return 'low'
        return 'info'

    def _get_geo(self, ip: str) -> dict:
        if not ip:
            return {"geolocatable": False}

        try:
            ip_obj = ipaddress.ip_address(ip)
            if not ip_obj.is_global:
                return {"geolocatable": False}
        except ValueError:
            return {"geolocatable": False}

        geo = _buscar_geocache(ip)
        if geo and geo.get('latitude') and geo.get('longitude'):
            return {
                "geolocatable": True,
                "country_code": geo.get('pais_codigo', ''),
                "country": geo.get('pais', ''),
                "city": geo.get('cidade', ''),
                "latitude": geo.get('latitude'),
                "longitude": geo.get('longitude')
            }
        return {"geolocatable": False}

    def _get_node_location(self) -> dict:
        return {
            "latitude": self.cfg.node_latitude,
            "longitude": self.cfg.node_longitude,
            "city": self.cfg.node_city,
            "country_code": self.cfg.node_country_code,
            "geolocatable": bool(self.cfg.node_latitude and self.cfg.node_longitude)
        }

    def get_suricata_events(self, max_limit=200):
        if 'ids' not in self.sources and 'all' not in self.sources:
            return []

        from django.db.models import Q

        qs = EventoBruto.objects.filter(
            event_type='alert',
            timestamp__gte=self.start_time
        )
        if self.category and self.category != 'all':
            qs = qs.filter(categoria__iexact=self.category)
        if self.country and self.country != 'all':
            qs = qs.filter(src_ip__in=GeoCache.objects.filter(pais_codigo__iexact=self.country).values('ip'))
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
        node_loc = self._get_node_location()
        for item in qs:
            sev = self._normalize_severity(item['severidade'])
            if self.severities and sev not in self.severities and 'all' not in self.severities:
                continue

            src_geo = self._get_geo(item['src_ip'])

            events.append({
                "id": f"suricata-{item['src_ip']}-{item['signature']}-{item['last_seen'].timestamp()}",
                "timestamp": item['last_seen'].strftime("%H:%M:%S"),
                "ts": item['last_seen'].isoformat(),
                "source": "ids",
                "event_class": "threat",
                "category": item['categoria'] or "other",
                "severity": sev,
                "src_ip": item['src_ip'],
                "src_port": None,
                "dst_ip": item['dest_ip'],
                "dst_port": item['dest_porta'],
                "protocol": item['protocolo'],
                "direction": "inbound",
                "signature": item['signature'],
                "action": "detected",
                "src_geo": src_geo,
                "dst_geo": node_loc,
                "count": item['count'],
                "incident_id": item['incidente_id'],
                "geolocatable": src_geo['geolocatable'],
                "rule_id": item['sid']
            })
        return events

    def get_firewall_events(self, max_limit=200):
        if 'firewall' not in self.sources and 'all' not in self.sources:
            return []

        from django.db.models import Q

        qs = EventoFirewall.objects.filter(
            timestamp__gte=self.start_time,
            acao__in=["DROP", "DENY", "REJECT"]
        )
        if self.category and self.category != 'all' and self.category != 'firewall_block':
            return []
        if self.country and self.country != 'all':
            qs = qs.filter(src_ip__in=GeoCache.objects.filter(pais_codigo__iexact=self.country).values('ip'))
        if self.query:
            qs = qs.filter(Q(src_ip__icontains=self.query) | Q(dest_ip__icontains=self.query))

        qs = qs.values(
            'src_ip', 'dest_ip', 'dest_port', 'proto', 'acao', 'chain'
        ).annotate(
            count=Count('id'),
            last_seen=Max('timestamp')
        ).order_by('-last_seen')[:max_limit]

        events = []
        node_loc = self._get_node_location()
        for item in qs:
            sev = "low" # Default firewall block severity
            if self.severities and sev not in self.severities and 'all' not in self.severities:
                continue

            src_geo = self._get_geo(item['src_ip'])

            events.append({
                "id": f"fw-{item['src_ip']}-{item['last_seen'].timestamp()}",
                "timestamp": item['last_seen'].strftime("%H:%M:%S"),
                "ts": item['last_seen'].isoformat(),
                "source": "firewall",
                "event_class": "block",
                "category": "firewall_block",
                "severity": sev,
                "src_ip": item['src_ip'],
                "src_port": None,
                "dst_ip": item['dest_ip'],
                "dst_port": item['dest_port'],
                "protocol": item['proto'],
                "direction": "inbound",
                "signature": f"Firewall {item['acao']} ({item['chain']})",
                "action": "blocked",
                "src_geo": src_geo,
                "dst_geo": node_loc,
                "count": item['count'],
                "incident_id": None,
                "geolocatable": src_geo['geolocatable']
            })
        return events

    def get_dns_events(self, max_limit=200):
        if 'dns' not in self.sources and 'all' not in self.sources:
            return []

        try:
            from dns.services.adguard_client import AdGuardClient
            client = AdGuardClient(url=self.cfg.adguard_url, user=self.cfg.adguard_user, password=self.cfg.adguard_password, https=self.cfg.adguard_https)
            # Limit is passed to avoid huge payload, AdGuard returns newest first
            raw_logs = client.get_querylog_raw(limit=500)
        except Exception as e:
            logger.error(f"Erro ao buscar logs AdGuard: {e}")
            return []

        events = []
        node_loc = self._get_node_location()

        # Aggregation in python for DNS since it comes from API
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
                dt = datetime.fromisoformat(entry_time_str.replace('Z', '+00:00'))
                if dt < self.start_time:
                    continue
            except Exception:
                pass

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

            events.append({
                "id": f"dns-{key}-{item['last_seen'].timestamp()}",
                "timestamp": item['last_seen'].strftime("%H:%M:%S"),
                "ts": item['last_seen'].isoformat(),
                "source": "dns",
                "event_class": "policy",
                "category": "dns_block",
                "severity": sev,
                "src_ip": item['src_ip'],
                "src_port": None,
                "dst_ip": item['domain'], # We don't have IP for blocked domain usually
                "dst_port": 53,
                "protocol": "UDP",
                "direction": "outbound",
                "signature": f"DNS Block: {item['domain']}",
                "action": "blocked",
                "src_geo": node_loc,
                "dst_geo": {"geolocatable": False},
                "count": item['count'],
                "incident_id": None,
                "geolocatable": False
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

