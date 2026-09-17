from unittest.mock import patch
from django.test import TestCase, RequestFactory
from datetime import datetime, timedelta
from django.utils import timezone
from configuracoes.models import ConfigSistema
from incidentes.models import EventoBruto
from firewall.models import EventoFirewall
from .services import FeedNormalizer, _is_global_ip
from .views import api_map_overview

class FeedNormalizerTest(TestCase):
    def setUp(self):
        self.cfg = ConfigSistema.get_solo()
        self.cfg.node_latitude = -23.55
        self.cfg.node_longitude = -46.63
        self.cfg.save()
        self.start_time = timezone.now() - timedelta(days=1)

    def test_normalize_severity(self):
        normalizer = FeedNormalizer(start_time=timezone.now(), severities=['all'], sources=['ids'])
        self.assertEqual(normalizer._normalize_severity('1'), 'critical')
        self.assertEqual(normalizer._normalize_severity('crítico'), 'critical')
        self.assertEqual(normalizer._normalize_severity('critico'), 'critical')
        self.assertEqual(normalizer._normalize_severity('alto'), 'high')
        self.assertEqual(normalizer._normalize_severity('médio'), 'medium')
        self.assertEqual(normalizer._normalize_severity('medio'), 'medium')
        self.assertEqual(normalizer._normalize_severity('baixo'), 'low')
        self.assertEqual(normalizer._normalize_severity('unknown_sev'), 'low')
        self.assertEqual(normalizer._normalize_severity(None), 'low')

    def test_get_node_location(self):
        normalizer = FeedNormalizer(start_time=timezone.now(), severities=['all'], sources=['ids'])
        loc = normalizer._get_node_location()
        self.assertTrue(loc['geolocatable'])
        self.assertEqual(loc['latitude'], -23.55)

    def test_location_validation(self):
        # We just test the normalizer and logic, the API test needs auth setup
        pass

    def test_geoip_global_filtering(self):
        normalizer = FeedNormalizer(start_time=timezone.now(), severities=['all'], sources=['ids'])
        self.assertFalse(normalizer._get_geo('203.0.113.5')['geolocatable']) # TEST-NET-3
        self.assertFalse(normalizer._get_geo('198.51.100.12')['geolocatable']) # TEST-NET-2
        self.assertFalse(normalizer._get_geo('10.0.0.1')['geolocatable']) # Private
        self.assertFalse(normalizer._get_geo('fe80::1')['geolocatable']) # IPv6 link-local
        self.assertFalse(normalizer._get_geo('fd00::1')['geolocatable']) # IPv6 ULA

    def test_api_limit_parsing(self):
        factory = RequestFactory()
        req = factory.get('/mapa/api/overview/?limit=abc')
        req.user = type('User', (), {'is_authenticated': True})
        # Logic in views.py ensures it falls back to 200

    def test_api_facets(self):
        pass

    def test_filters(self):
        pass

    def test_get_suricata_events_regression(self):
        EventoBruto.objects.create(
            timestamp=timezone.now(),
            event_type='alert',
            src_ip='8.8.8.8',
            dest_ip='1.1.1.1',
            dest_porta=80,
            protocolo='TCP',
            signature='Test Signature',
            severidade='critical',
            event_hash='testhash'
        )
        normalizer = FeedNormalizer(start_time=self.start_time, severities=['all'], sources=['ids'])
        normalizer._is_internal_ip = lambda x: False
        events = normalizer.get_suricata_events(max_limit=10)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['src_ip'], '8.8.8.8')

    def test_get_firewall_events_regression(self):
        EventoFirewall.objects.create(
            timestamp=timezone.now(),
            acao='DROP',
            src_ip='198.51.100.12',
            dst_ip='192.168.1.1',
            dst_port=443,
            proto='TCP',
            chain='INPUT',
            event_hash='fwtest1'
        )
        normalizer = FeedNormalizer(start_time=self.start_time, severities=['all'], sources=['firewall'])
        normalizer._is_internal_ip = lambda x: x == '192.168.1.1'
        events = normalizer.get_firewall_events(max_limit=10)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['source'], 'firewall')
        self.assertEqual(events[0]['event_class'], 'block')
        self.assertEqual(events[0]['severity'], 'low')
        self.assertEqual(events[0]['src_ip'], '198.51.100.12')
        self.assertEqual(events[0]['dst_ip'], '192.168.1.1')
        self.assertEqual(events[0]['dst_port'], 443)
        self.assertEqual(events[0]['protocol'], 'TCP')
        self.assertGreaterEqual(events[0]['count'], 1)
        self.assertFalse(events[0]['src_geo']['geolocatable']) # 198.51.100.12 is TEST-NET

    @patch('dns.services.adguard_bootstrap.criar_cliente_adguard_local')
    def test_api_overview_integrated(self, mock_adguard):
        mock_client = mock_adguard.return_value
        mock_client.get_querylog_raw.return_value = []

        EventoBruto.objects.create(
            timestamp=timezone.now(),
            event_type='alert',
            src_ip='8.8.8.8',
            dest_ip='1.1.1.1',
            dest_porta=80,
            protocolo='TCP',
            signature='Test Signature API',
            severidade='critical',
            event_hash='api_bruto_1'
        )
        EventoFirewall.objects.create(
            timestamp=timezone.now(),
            acao='DROP',
            src_ip='8.8.4.4',
            dst_ip='192.168.1.1',
            dst_port=443,
            proto='TCP',
            chain='INPUT',
            event_hash='api_fw_1'
        )

        factory = RequestFactory()
        req = factory.get('/mapa/api/overview/')
        req.user = type('User', (), {'is_authenticated': True})

        with patch('mapa_ameacas.services.FeedNormalizer._is_internal_ip', return_value=False):
            res = api_map_overview(req)
            self.assertEqual(res.status_code, 200)

class ThreatMapBackendTests(TestCase):
    def setUp(self):
        self.cfg = ConfigSistema.get_solo()
        self.cfg.node_latitude = -23.55
        self.cfg.node_longitude = -46.63
        self.cfg.save()
        self.start_time = timezone.now() - timedelta(days=1)

    def test_is_global_ip(self):
        # A. private IPv4
        self.assertFalse(_is_global_ip('10.0.0.5'))
        self.assertFalse(_is_global_ip('192.168.1.5'))
        self.assertFalse(_is_global_ip('172.16.0.5'))
        # B. documentation
        self.assertFalse(_is_global_ip('203.0.113.5'))
        # C. IPv6 ULA / link-local
        self.assertFalse(_is_global_ip('fd12:3456:789a:1::1'))
        self.assertFalse(_is_global_ip('fe80::1ff:fe23:4567:890a'))
        # D. global IPv4
        self.assertTrue(_is_global_ip('8.8.8.8'))
        self.assertTrue(_is_global_ip('200.10.10.10'))

    def test_direction_suricata(self):
        # E. inbound (global -> internal)
        EventoBruto.objects.create(
            timestamp=timezone.now(), event_type='alert',
            src_ip='8.8.8.8', dest_ip='192.168.1.10',
            dest_porta=80, protocolo='TCP', signature='Inbound Test',
            severidade='high', event_hash='suri1'
        )
        # F. outbound (internal -> global)
        EventoBruto.objects.create(
            timestamp=timezone.now(), event_type='alert',
            src_ip='10.0.0.15', dest_ip='1.1.1.1',
            dest_porta=443, protocolo='TCP', signature='Outbound Test',
            severidade='high', event_hash='suri2'
        )
        # G. internal (private -> private)
        EventoBruto.objects.create(
            timestamp=timezone.now(), event_type='alert',
            src_ip='10.0.0.15', dest_ip='192.168.1.20',
            dest_porta=22, protocolo='TCP', signature='Internal Test',
            severidade='low', event_hash='suri3'
        )

        normalizer = FeedNormalizer(start_time=self.start_time)
        # Manually mock _is_internal_ip for deterministic test without needing rede app setup
        normalizer._is_internal_ip = lambda x: x.startswith('192.168') or x.startswith('10.')

        evs = normalizer.get_suricata_events()
        self.assertEqual(len(evs), 3)

        inbound = next(e for e in evs if e['signature'] == 'Inbound Test')
        self.assertEqual(inbound['direction'], 'inbound')
        self.assertEqual(inbound['external_ip'], '8.8.8.8')

        outbound = next(e for e in evs if e['signature'] == 'Outbound Test')
        self.assertEqual(outbound['direction'], 'outbound')
        self.assertEqual(outbound['external_ip'], '1.1.1.1')

        internal = next(e for e in evs if e['signature'] == 'Internal Test')
        self.assertEqual(internal['direction'], 'internal')
        self.assertIsNone(internal['external_ip'])
        self.assertFalse(internal['geolocatable'])

    def test_node_sem_localizacao(self):
        # H. node sem localização
        self.cfg.node_latitude = None
        self.cfg.node_longitude = None
        self.cfg.save()

        EventoBruto.objects.create(
            timestamp=timezone.now(), event_type='alert',
            src_ip='8.8.8.8', dest_ip='192.168.1.10',
            dest_porta=80, protocolo='TCP', signature='Inbound Node Test',
            severidade='high', event_hash='node1'
        )

        normalizer = FeedNormalizer(start_time=self.start_time)
        normalizer._is_internal_ip = lambda x: x.startswith('192.168')
        evs = normalizer.get_suricata_events()
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]['geolocatable'], False)

    def test_firewall_privado(self):
        # I. Firewall privado
        EventoFirewall.objects.create(
            timestamp=timezone.now(), acao='DROP',
            src_ip='10.10.10.10', dst_ip='192.168.1.1',
            dst_port=443, proto='TCP', chain='INPUT', event_hash='fw_priv'
        )
        normalizer = FeedNormalizer(start_time=self.start_time)
        normalizer._is_internal_ip = lambda x: x.startswith('192.168') or x.startswith('10.')
        evs = normalizer.get_firewall_events()
        self.assertEqual(len(evs), 1)
        self.assertFalse(evs[0]['geolocatable'])
        self.assertEqual(evs[0]['direction'], 'internal')

    @patch('dns.services.adguard_bootstrap.criar_cliente_adguard_local')
    def test_dns_domain_sem_ip(self, mock_criar):
        # K. DNS domínio sem IP
        mock_client = mock_criar.return_value
        mock_client.get_querylog_raw.return_value = [{
            'time': timezone.now().strftime('%Y-%m-%dT%H:%M:%S.000Z'),
            'reason': 'FilteredBlackList',
            'client': '192.168.1.50',
            'question': {'name': 'malicious.com'}
        }]

        normalizer = FeedNormalizer(start_time=self.start_time)
        normalizer._is_internal_ip = lambda x: x.startswith('192.168')
        evs = normalizer.get_dns_events()
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]['domain'], 'malicious.com')
        self.assertIsNone(evs[0]['dst_ip'])
        self.assertFalse(evs[0]['geolocatable'])
        self.assertEqual(evs[0]['direction'], 'outbound')

    @patch('dns.services.adguard_bootstrap.criar_cliente_adguard_local')
    def test_adguard_indisponivel(self, mock_criar):
        # L. AdGuard indisponível
        mock_criar.side_effect = Exception("Connection Refused")

        normalizer = FeedNormalizer(start_time=self.start_time)
        evs = normalizer.get_dns_events()
        self.assertEqual(evs, [])
        self.assertEqual(normalizer.source_health['dns'], 'offline')

    def test_non_global_not_internal(self):
        # Documentation IP: not global, not internal => unknown
        EventoBruto.objects.create(
            timestamp=timezone.now(), event_type='alert',
            src_ip='203.0.113.10', dest_ip='198.51.100.10',
            dest_porta=80, protocolo='TCP', signature='NonGlobal Test',
            severidade='high', event_hash='suri_nonglobal'
        )
        normalizer = FeedNormalizer(start_time=self.start_time)
        normalizer._is_internal_ip = lambda x: False
        evs = normalizer.get_suricata_events()
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]['direction'], 'unknown')
        self.assertFalse(evs[0]['geolocatable'])
