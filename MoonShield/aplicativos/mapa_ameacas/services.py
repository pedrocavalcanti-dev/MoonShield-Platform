"""Normalizacao do feed do Mapa de Ameacas a partir dos eventos reais."""

from __future__ import annotations

import logging
import math
import unicodedata
from datetime import datetime

from django.db.models import Count, Max
from django.utils import timezone

from configuracoes.models import ConfigSistema
from firewall.models import EventoFirewall
from incidentes.models import EventoBruto, GeoCache
from incidentes.services.contexto_rede import classificar_fluxo, classificar_ip_rede

logger = logging.getLogger(__name__)


def _is_global_ip(ip_str: str) -> bool:
    """Compatibilidade para consumidores antigos; a decisao e da SSOT de rede."""
    return bool(classificar_ip_rede(ip_str).get("geoip_allowed"))


def _coordenadas_validas(latitude, longitude) -> bool:
    """Aceita somente coordenadas numericas finitas fora do ponto sentinela 0,0."""
    try:
        lat = float(latitude)
        lon = float(longitude)
    except (TypeError, ValueError):
        return False
    return (
        math.isfinite(lat)
        and math.isfinite(lon)
        and -90 <= lat <= 90
        and -180 <= lon <= 180
        and (lat, lon) != (0.0, 0.0)
    )


class FeedNormalizer:
    """Consolida IDS, Firewall e DNS sem criar uma segunda SSOT de rede."""

    def __init__(
        self,
        start_time: datetime,
        severities: list | None = None,
        sources: list | None = None,
        category: str | None = None,
        country: str | None = None,
        query: str | None = None,
        protocol: str | None = None,
        direction: str | None = None,
        zone: str | None = None,
    ):
        self.start_time = start_time
        self.severities = {str(value).lower() for value in (severities or ["all"])}
        self.sources = {str(value).lower() for value in (sources or ["all"])}
        self.category = (category or "all").strip().lower()
        self.country = (country or "all").strip().upper()
        self.query = (query or "").strip()
        self.protocol = (protocol or "all").strip().upper()
        self.direction = (direction or "all").strip().lower()
        self.zone = (zone or "all").strip().upper()
        self.cfg = ConfigSistema.get_solo()
        self.source_health = {"ids": "online", "firewall": "online", "dns": "online"}
        self._geo_cache: dict[str, dict] = {}
        self._flow_cache: dict[tuple[str | None, str | None], dict] = {}

    def _is_internal_ip(self, ip_str: str) -> bool:
        """Compatibilidade; a classificacao permanece centralizada no servico SOC."""
        return classificar_ip_rede(ip_str).get("scope") == "internal"

    def _get_node_location(self) -> dict:
        """Le a localizacao configurada sem mudar o contrato de localizacao do node."""
        return {
            "latitude": self.cfg.node_latitude,
            "longitude": self.cfg.node_longitude,
            "city": self.cfg.node_city,
            "country_code": self.cfg.node_country_code,
            "geolocatable": _coordenadas_validas(
                self.cfg.node_latitude, self.cfg.node_longitude
            ),
        }

    def _prime_geo_cache(self, ips) -> None:
        candidatos = {
            str(ip)
            for ip in ips
            if ip and classificar_ip_rede(str(ip)).get("geoip_allowed")
        }
        faltantes = candidatos.difference(self._geo_cache)
        if not faltantes:
            return
        encontrados = GeoCache.objects.in_bulk(faltantes, field_name="ip")
        for ip in faltantes:
            cached = encontrados.get(ip)
            if cached and _coordenadas_validas(cached.latitude, cached.longitude):
                self._geo_cache[ip] = {
                    "latitude": float(cached.latitude),
                    "longitude": float(cached.longitude),
                    "country": cached.pais or None,
                    "country_code": cached.pais_codigo or None,
                    "city": cached.cidade or None,
                    "asn": cached.asn_number or None,
                    "org": cached.asn_org or None,
                    "geolocatable": True,
                }
            else:
                self._geo_cache[ip] = {"geolocatable": False}

    def _get_geo(self, ip: str | None, context: dict | None = None) -> dict:
        """Retorna GeoIP apenas para IP externo elegivel e com coordenadas validas."""
        contexto = context or classificar_ip_rede(ip)
        if not ip or not contexto.get("geoip_allowed"):
            return {"geolocatable": False}
        self._prime_geo_cache([ip])
        return self._geo_cache.get(str(ip), {"geolocatable": False})

    @staticmethod
    def _normalize_severity(severity: str | None) -> str:
        if not severity:
            return "low"
        raw = unicodedata.normalize("NFKD", str(severity)).encode(
            "ASCII", "ignore"
        ).decode("utf-8").lower()
        if raw in {"1", "critical", "critico"}:
            return "critical"
        if raw in {"2", "high", "alto"}:
            return "high"
        if raw in {"3", "medium", "medio", "warning"}:
            return "medium"
        if raw in {"4", "low", "baixo", "info", "informativo"}:
            return "low"
        return "low"

    def _classify_flow(self, src_ip: str | None, dst_ip: str | None) -> dict:
        chave = (src_ip, dst_ip)
        if chave not in self._flow_cache:
            self._flow_cache[chave] = classificar_fluxo(src_ip, dst_ip)
        return self._flow_cache[chave]

    def _determine_direction_and_external(self, src_ip: str | None, dst_ip: str | None):
        """Contrato legado derivado da classificacao oficial de contexto de rede."""
        contexto = self._classify_flow(src_ip, dst_ip)
        if contexto["direction"] == "inbound":
            return "inbound", src_ip
        if contexto["direction"] == "outbound":
            return "outbound", dst_ip
        return contexto["direction"], None

    def _event_context(self, src_ip: str | None, dst_ip: str | None) -> tuple[dict, str | None, dict]:
        fluxo = self._classify_flow(src_ip, dst_ip)
        direction, external_ip = self._determine_direction_and_external(src_ip, dst_ip)
        if external_ip is None:
            if fluxo["src"].get("geoip_allowed"):
                external_ip = src_ip
            elif fluxo["dst"].get("geoip_allowed"):
                external_ip = dst_ip
        context = fluxo["src"] if external_ip == src_ip else fluxo["dst"]
        return fluxo, external_ip, self._get_geo(external_ip, context)

    def _matches_filters(self, event: dict) -> bool:
        if "all" not in self.severities and event["severity"] not in self.severities:
            return False
        if self.category != "all" and event["category"].lower() != self.category:
            return False
        if self.country != "ALL" and (event.get("country_code") or "").upper() != self.country:
            return False
        if self.protocol != "ALL" and (event.get("protocol") or "").upper() != self.protocol:
            return False
        if self.direction != "all" and event.get("direction") != self.direction:
            return False
        if self.zone != "ALL" and self.zone not in {
            (event.get("src_role") or "").upper(),
            (event.get("dst_role") or "").upper(),
        }:
            return False
        if not self.query:
            return True
        haystack = " ".join(str(value or "") for value in (
            event.get("src_ip"), event.get("dst_ip"), event.get("signature"),
            event.get("domain"), event.get("sid"), event.get("asn"), event.get("org"),
        )).lower()
        return self.query.lower() in haystack

    def _base_event(self, *, source, event_class, category, severity, src_ip, src_port,
                    dst_ip, dst_port, protocol, signature, action, timestamp, count,
                    incident_id=None, sid=None, domain=None) -> dict:
        fluxo, external_ip, external_geo = self._event_context(src_ip, dst_ip)
        src_geo = self._get_geo(src_ip, fluxo["src"])
        dst_geo = self._get_geo(dst_ip, fluxo["dst"])
        has_geo = bool(external_geo.get("geolocatable"))
        return {
            "id": f"{source}-{src_ip or 'none'}-{sid or signature or domain or 'event'}-{timestamp.timestamp()}",
            "timestamp": timestamp.strftime("%H:%M:%S"),
            "ts": timestamp.isoformat(),
            "source": source,
            "event_class": event_class,
            "category": category or "other",
            "severity": severity,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": (protocol or "").upper() or None,
            "direction": fluxo["direction"],
            "flow_scope": fluxo["flow_scope"],
            "src_scope": fluxo["src"]["scope"],
            "src_role": fluxo["src"].get("role"),
            "dst_scope": fluxo["dst"]["scope"],
            "dst_role": fluxo["dst"].get("role"),
            "signature": signature or None,
            "action": action,
            "src_geo": src_geo,
            "dst_geo": dst_geo,
            "external_ip": external_ip,
            "external_geo": external_geo,
            "has_geo": has_geo,
            "geolocatable": has_geo,
            "country": external_geo.get("country"),
            "country_code": external_geo.get("country_code"),
            "city": external_geo.get("city"),
            "asn": external_geo.get("asn"),
            "org": external_geo.get("org"),
            "latitude": external_geo.get("latitude"),
            "longitude": external_geo.get("longitude"),
            "count": count,
            "incident_id": incident_id,
            "sid": sid or None,
            "rule_id": sid or None,
            "domain": domain,
        }

    def get_suricata_events(self, max_limit=500):
        if "ids" not in self.sources and "all" not in self.sources:
            return []
        rows = list(EventoBruto.objects.filter(
            event_type="alert", timestamp__gte=self.start_time
        ).values(
            "src_ip", "src_porta", "dest_ip", "dest_porta", "protocolo", "signature",
            "sid", "categoria", "severidade", "incidente_id"
        ).annotate(count=Count("id"), last_seen=Max("timestamp")).order_by("-last_seen")[:max_limit])
        self._prime_geo_cache(ip for row in rows for ip in (row["src_ip"], row["dest_ip"]))
        events = []
        for row in rows:
            event = self._base_event(
                source="ids", event_class="threat", category=row["categoria"],
                severity=self._normalize_severity(row["severidade"]), src_ip=row["src_ip"],
                src_port=row["src_porta"], dst_ip=row["dest_ip"], dst_port=row["dest_porta"],
                protocol=row["protocolo"], signature=row["signature"], action="detected",
                timestamp=row["last_seen"], count=row["count"], incident_id=row["incidente_id"], sid=row["sid"],
            )
            if self._matches_filters(event):
                events.append(event)
        return events

    def get_firewall_events(self, max_limit=500):
        if "firewall" not in self.sources and "all" not in self.sources:
            return []
        rows = list(EventoFirewall.objects.filter(
            timestamp__gte=self.start_time, acao__in=["DROP", "DENY", "REJECT"]
        ).values("src_ip", "src_port", "dst_ip", "dst_port", "proto", "acao", "chain").annotate(
            count=Count("id"), last_seen=Max("timestamp")
        ).order_by("-last_seen")[:max_limit])
        self._prime_geo_cache(ip for row in rows for ip in (row["src_ip"], row["dst_ip"]))
        events = []
        for row in rows:
            event = self._base_event(
                source="firewall", event_class="block", category="firewall_block", severity="low",
                src_ip=row["src_ip"], src_port=row["src_port"], dst_ip=row["dst_ip"],
                dst_port=row["dst_port"], protocol=row["proto"],
                signature=f"Firewall {row['acao']} ({row['chain']})", action="blocked",
                timestamp=row["last_seen"], count=row["count"],
            )
            if self._matches_filters(event):
                events.append(event)
        return events

    def get_dns_events(self, max_limit=500):
        if "dns" not in self.sources and "all" not in self.sources:
            return []
        try:
            from dns.services.adguard_bootstrap import criar_cliente_adguard_local
            raw_logs = criar_cliente_adguard_local().get_querylog_raw(limit=500)
        except Exception as exc:
            logger.warning("Nao foi possivel consultar o feed DNS: %s", exc)
            self.source_health["dns"] = "offline"
            return []
        aggregate = {}
        reasons = {"FilteredBlackList", "FilteredSafeBrowsing", "FilteredParental", "Rewrite"}
        for entry in raw_logs:
            if entry.get("reason") not in reasons:
                continue
            try:
                timestamp = timezone.datetime.fromisoformat(entry.get("time", "").replace("Z", "+00:00"))
            except (TypeError, ValueError):
                continue
            if timestamp < self.start_time:
                continue
            src_ip = entry.get("client") or None
            domain = entry.get("question", {}).get("name") or ""
            key = (src_ip, domain, entry.get("reason"))
            aggregate.setdefault(key, {"count": 0, "timestamp": timestamp})
            aggregate[key]["count"] += 1
            aggregate[key]["timestamp"] = max(aggregate[key]["timestamp"], timestamp)
        events = []
        for (src_ip, domain, reason), data in sorted(
            aggregate.items(), key=lambda item: item[1]["timestamp"], reverse=True
        )[:max_limit]:
            event = self._base_event(
                source="dns", event_class="policy", category="dns_block",
                severity="medium" if reason == "FilteredSafeBrowsing" else "low",
                src_ip=src_ip, src_port=None, dst_ip=None, dst_port=53, protocol="UDP",
                signature=f"DNS Block: {domain}", action="blocked", timestamp=data["timestamp"],
                count=data["count"], domain=domain,
            )
            if self._matches_filters(event):
                events.append(event)
        return events

    def get_all_events(self, max_limit=500, geo_only=False):
        events = self.get_suricata_events(max_limit)
        events.extend(self.get_firewall_events(max_limit))
        events.extend(self.get_dns_events(max_limit))
        events.sort(key=lambda event: event["ts"], reverse=True)
        if geo_only:
            events = [event for event in events if event["has_geo"]]
        return events[:max_limit]

    @staticmethod
    def get_facets(events: list[dict]) -> dict:
        facets = {key: {} for key in (
            "severities", "sources", "categories", "countries", "protocols", "directions", "zones",
        )}
        for event in events:
            count = event["count"]
            values = {
                "severities": event["severity"],
                "sources": event["source"],
                "categories": event["category"],
                "countries": event.get("country_code"),
                "protocols": event.get("protocol"),
                "directions": event.get("direction"),
            }
            for key, value in values.items():
                if value:
                    facets[key][value] = facets[key].get(value, 0) + count
            for role in {event.get("src_role"), event.get("dst_role")} - {None, ""}:
                facets["zones"][role] = facets["zones"].get(role, 0) + count
        return facets
