import json
from datetime import timedelta
from unittest.mock import patch

from django.test import RequestFactory, TestCase
from django.utils import timezone

from configuracoes.models import ConfigSistema
from incidentes.models import EventoBruto, GeoCache

from .services import FeedNormalizer
from .views import api_map_facets, api_map_feed, api_map_overview, api_map_search


TOPOLOGIA = {
    "lan": {"interfaces": [{
        "desejado": {"ipv4_endereco": "192.168.10.1", "ipv4_prefixo": 24},
        "real": {},
    }]},
    "mgmt": {"interfaces": []},
    "dmz": {"interfaces": []},
    "custom": {"interfaces": []},
    "wan": {"interfaces": []},
}


class ThreatMapBackendTests(TestCase):
    def setUp(self):
        self.start_time = timezone.now() - timedelta(days=1)
        self.factory = RequestFactory()
        cfg = ConfigSistema.get_solo()
        cfg.node_latitude = -23.55
        cfg.node_longitude = -46.63
        cfg.save()
        self.topologia = patch(
            "incidentes.services.contexto_rede.obter_topologia",
            return_value=TOPOLOGIA,
        )
        self.topologia.start()
        self.addCleanup(self.topologia.stop)

    def _alert(self, *, src_ip, dest_ip, signature, severity="high", category="network",
               protocol="TCP", sid="1001", timestamp=None):
        return EventoBruto.objects.create(
            timestamp=timestamp or timezone.now(),
            event_type="alert",
            src_ip=src_ip,
            dest_ip=dest_ip,
            src_porta=54000,
            dest_porta=443,
            protocolo=protocol,
            signature=signature,
            sid=sid,
            categoria=category,
            severidade=severity,
            event_hash=f"map-{signature}-{timezone.now().timestamp()}",
        )

    def _geo(self, ip="8.8.8.8", **values):
        defaults = {
            "pais": "United States",
            "pais_codigo": "US",
            "cidade": "Mountain View",
            "latitude": 37.386,
            "longitude": -122.0838,
            "asn_number": "AS15169",
            "asn_org": "Google LLC",
        }
        defaults.update(values)
        return GeoCache.objects.create(ip=ip, **defaults)

    def _request(self, path):
        request = self.factory.get(path)
        request.user = type("User", (), {"is_authenticated": True})()
        return request

    def test_internal_event_has_network_context_without_geo(self):
        self._geo("192.168.10.50")
        self._alert(
            src_ip="192.168.10.50",
            dest_ip="192.168.10.60",
            signature="Internal movement",
        )

        event = FeedNormalizer(self.start_time, sources=["ids"]).get_suricata_events()[0]

        self.assertEqual(event["flow_scope"], "internal")
        self.assertEqual(event["src_scope"], "internal")
        self.assertEqual(event["src_role"], "LAN")
        self.assertFalse(event["has_geo"])
        self.assertFalse(event["src_geo"]["geolocatable"])

    def test_public_geo_event_exposes_complete_contract(self):
        self._geo()
        self._alert(src_ip="8.8.8.8", dest_ip="192.168.10.50", signature="Inbound scan")

        event = FeedNormalizer(self.start_time, sources=["ids"]).get_suricata_events()[0]

        self.assertEqual(event["direction"], "inbound")
        self.assertEqual(event["flow_scope"], "inbound")
        self.assertEqual(event["dst_role"], "LAN")
        self.assertTrue(event["has_geo"])
        self.assertEqual(event["country_code"], "US")
        self.assertEqual(event["asn"], "AS15169")
        self.assertEqual(event["src_port"], 54000)
        self.assertEqual(event["sid"], "1001")
        self.assertEqual(event["external_ip"], "8.8.8.8")

    def test_invalid_or_sentinel_coordinates_are_not_map_eligible(self):
        self._geo(latitude=0, longitude=0)
        self._alert(src_ip="8.8.8.8", dest_ip="192.168.10.50", signature="Invalid geo")

        event = FeedNormalizer(self.start_time, sources=["ids"]).get_suricata_events()[0]

        self.assertFalse(event["has_geo"])
        self.assertFalse(event["geolocatable"])

    def test_filters_apply_together_for_country_protocol_direction_and_zone(self):
        self._geo()
        self._alert(
            src_ip="8.8.8.8",
            dest_ip="192.168.10.50",
            signature="Filtered alert",
            severity="critical",
            category="recon",
            protocol="TCP",
        )
        normalizer = FeedNormalizer(
            self.start_time,
            severities=["critical"],
            sources=["ids"],
            category="recon",
            country="US",
            protocol="TCP",
            direction="inbound",
            zone="LAN",
        )

        self.assertEqual(len(normalizer.get_all_events()), 1)
        normalizer.protocol = "UDP"
        self.assertEqual(normalizer.get_all_events(), [])

    def test_period_excludes_old_event(self):
        self._geo()
        self._alert(
            src_ip="8.8.8.8",
            dest_ip="192.168.10.50",
            signature="Old alert",
            timestamp=timezone.now() - timedelta(hours=2),
        )

        self.assertEqual(
            FeedNormalizer(timezone.now() - timedelta(hours=1), sources=["ids"]).get_all_events(),
            [],
        )

    def test_facets_have_real_counts_for_all_filter_dimensions(self):
        self._geo()
        self._alert(
            src_ip="8.8.8.8",
            dest_ip="192.168.10.50",
            signature="Facet alert",
            severity="critical",
            category="recon",
        )

        facets = FeedNormalizer.get_facets(
            FeedNormalizer(self.start_time, sources=["ids"]).get_all_events()
        )

        self.assertEqual(facets["severities"]["critical"], 1)
        self.assertEqual(facets["sources"]["ids"], 1)
        self.assertEqual(facets["categories"]["recon"], 1)
        self.assertEqual(facets["countries"]["US"], 1)
        self.assertEqual(facets["protocols"]["TCP"], 1)
        self.assertEqual(facets["directions"]["inbound"], 1)
        self.assertEqual(facets["zones"]["LAN"], 1)

    def test_overview_counts_all_events_and_returns_only_geo_feed(self):
        self._geo()
        self._alert(
            src_ip="8.8.8.8",
            dest_ip="192.168.10.50",
            signature="Map event",
            severity="critical",
        )
        self._alert(
            src_ip="192.168.10.50",
            dest_ip="192.168.10.60",
            signature="SOC only",
            severity="critical",
        )

        response = api_map_overview(self._request("/mapa/api/overview/?source=ids"))
        payload = json.loads(response.content)

        self.assertEqual(payload["kpis"]["events"], 2)
        self.assertEqual(payload["kpis"]["critical"], 2)
        self.assertEqual(payload["kpis"]["geo_on_map"], 1)
        self.assertEqual(payload["kpis"]["top_country"], "US")
        self.assertEqual(len(payload["events"]), 1)
        self.assertTrue(payload["events"][0]["has_geo"])

    def test_geo_only_feed_can_be_requested_explicitly(self):
        self._geo()
        self._alert(src_ip="8.8.8.8", dest_ip="192.168.10.50", signature="Geo")
        self._alert(src_ip="192.168.10.50", dest_ip="192.168.10.60", signature="Internal")

        geo_payload = json.loads(
            api_map_feed(self._request("/mapa/api/feed/?source=ids")).content
        )
        all_payload = json.loads(
            api_map_feed(self._request("/mapa/api/feed/?source=ids&geo_only=0")).content
        )

        self.assertTrue(geo_payload["geo_only"])
        self.assertEqual(len(geo_payload["events"]), 1)
        self.assertEqual(len(all_payload["events"]), 2)

    def test_search_supports_asn_and_internal_ip_context(self):
        self._geo()
        self._alert(src_ip="8.8.8.8", dest_ip="192.168.10.50", signature="ASN search")
        self._alert(src_ip="192.168.10.50", dest_ip="192.168.10.60", signature="Internal search")

        asn_payload = json.loads(
            api_map_search(self._request("/mapa/api/search/?source=ids&q=AS15169")).content
        )
        ip_payload = json.loads(
            api_map_search(self._request("/mapa/api/search/?source=ids&q=192.168.10.50")).content
        )

        self.assertEqual(asn_payload["total"], 1)
        self.assertTrue(asn_payload["results"][0]["has_geo"])
        internal_result = next(
            result for result in ip_payload["results"]
            if result.get("signature") == "Internal search"
        )
        self.assertEqual(internal_result["src_scope"], "internal")
        self.assertFalse(internal_result["has_geo"])

    def test_empty_ip_search_returns_explicit_internal_context(self):
        payload = json.loads(
            api_map_search(self._request("/mapa/api/search/?source=ids&q=192.168.10.99")).content
        )

        self.assertEqual(payload["results"][0]["type"], "ip")
        self.assertEqual(payload["results"][0]["scope"], "internal")
        self.assertEqual(payload["results"][0]["role"], "LAN")
        self.assertFalse(payload["results"][0]["has_geo"])

    def test_facets_endpoint_uses_the_same_filtered_context(self):
        self._geo()
        self._alert(src_ip="8.8.8.8", dest_ip="192.168.10.50", signature="Facet endpoint")

        payload = json.loads(
            api_map_facets(self._request("/mapa/api/facets/?source=ids&direction=inbound")).content
        )

        self.assertEqual(payload["facets"]["directions"], {"inbound": 1})

    def _multifilter_events(self):
        self._geo()
        self._geo(
            "1.1.1.1",
            pais="Germany",
            pais_codigo="DE",
            cidade="Frankfurt",
            latitude=50.1109,
            longitude=8.6821,
            asn_number="AS13335",
            asn_org="Cloudflare",
        )
        self._alert(
            src_ip="8.8.8.8",
            dest_ip="192.168.10.50",
            signature="Recon US",
            category="recon",
        )
        self._alert(
            src_ip="1.1.1.1",
            dest_ip="192.168.10.50",
            signature="Web DE",
            category="web_attack",
        )

    def test_category_single_and_multiple_use_or_semantics(self):
        self._multifilter_events()

        single = FeedNormalizer(
            self.start_time, sources=["ids"], category="recon"
        ).get_all_events()
        multiple = FeedNormalizer(
            self.start_time, sources=["ids"], category=["recon", "web_attack"]
        ).get_all_events()

        self.assertEqual([event["category"] for event in single], ["recon"])
        self.assertEqual({event["category"] for event in multiple}, {"recon", "web_attack"})

    def test_country_single_and_multiple_use_or_semantics(self):
        self._multifilter_events()

        single = FeedNormalizer(
            self.start_time, sources=["ids"], country="US"
        ).get_all_events()
        multiple = FeedNormalizer(
            self.start_time, sources=["ids"], country=["US", "DE"]
        ).get_all_events()

        self.assertEqual([event["country_code"] for event in single], ["US"])
        self.assertEqual({event["country_code"] for event in multiple}, {"US", "DE"})

    def test_multi_dimensions_are_or_within_and_between_dimensions(self):
        self._multifilter_events()

        events = FeedNormalizer(
            self.start_time,
            sources=["ids"],
            category=["recon", "web_attack"],
            country=["DE"],
        ).get_all_events()

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["signature"], "Web DE")

    def test_empty_and_duplicate_multifilters_do_not_change_the_recorte(self):
        self._multifilter_events()

        empty = FeedNormalizer(
            self.start_time, sources=["ids"], category=[], country=[]
        ).get_all_events()
        duplicates = FeedNormalizer(
            self.start_time,
            sources=["ids"],
            category=["recon", "recon"],
            country=["US", "US"],
        ).get_all_events()

        self.assertEqual(len(empty), 2)
        self.assertEqual(len(duplicates), 1)
        self.assertEqual(duplicates[0]["signature"], "Recon US")

    def test_endpoints_accept_repeated_and_csv_multifilters(self):
        self._multifilter_events()

        repeated = (
            "?source=ids&category=recon&category=web_attack&country=US&country=DE"
        )
        overview = json.loads(
            api_map_overview(self._request(f"/mapa/api/overview/{repeated}")).content
        )
        feed = json.loads(
            api_map_feed(self._request(f"/mapa/api/feed/{repeated}")).content
        )
        facets = json.loads(
            api_map_facets(self._request(f"/mapa/api/facets/{repeated}")).content
        )
        csv_feed = json.loads(
            api_map_feed(
                self._request("/mapa/api/feed/?source=ids&category=recon,web_attack&country=US,DE")
            ).content
        )

        self.assertEqual(overview["kpis"]["events"], 2)
        self.assertEqual(len(feed["events"]), 2)
        self.assertEqual(facets["facets"]["categories"], {"recon": 1, "web_attack": 1})
        self.assertEqual(len(csv_feed["events"]), 2)
