from django.test import TestCase, RequestFactory
from datetime import datetime, timedelta
from django.utils import timezone
from unittest.mock import patch
from configuracoes.models import ConfigSistema
from incidentes.models import EventoBruto
from firewall.models import EventoFirewall
from .services import FeedNormalizer, _is_global_ip
from .views import api_map_overview

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
        evs = normalizer.get_suricata_events()
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]['dst_geo']['geolocatable'], False)

    def test_firewall_privado(self):
        # I. Firewall privado
        EventoFirewall.objects.create(
            timestamp=timezone.now(), acao='DROP',
            src_ip='10.10.10.10', dst_ip='192.168.1.1',
            dst_port=443, proto='TCP', chain='INPUT', event_hash='fw_priv'
        )
        normalizer = FeedNormalizer(start_time=self.start_time)
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
        evs = normalizer.get_dns_events()
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]['domain'], 'malicious.com')
        self.assertIsNone(evs[0]['dst_ip'])
        self.assertFalse(evs[0]['geolocatable'])

    @patch('dns.services.adguard_bootstrap.criar_cliente_adguard_local')
    def test_adguard_indisponivel(self, mock_criar):
        # L. AdGuard indisponível
        mock_criar.side_effect = Exception("Connection Refused")

        normalizer = FeedNormalizer(start_time=self.start_time)
        evs = normalizer.get_dns_events()
        self.assertEqual(evs, [])
        self.assertEqual(normalizer.source_health['dns'], 'offline')

    @patch('dns.services.adguard_bootstrap.criar_cliente_adguard_local')
    def test_api_overview_integrated(self, mock_criar):
        # M. integração
        mock_client = mock_criar.return_value
        mock_client.get_querylog_raw.return_value = []

        EventoBruto.objects.create(
            timestamp=timezone.now(), event_type='alert',
            src_ip='8.8.8.8', dest_ip='1.1.1.1',
            dest_porta=80, protocolo='TCP', signature='API Test',
            severidade='critical', event_hash='api1'
        )
        EventoFirewall.objects.create(
            timestamp=timezone.now(), acao='DROP',
            src_ip='192.168.1.20', dst_ip='10.0.0.5',
            dst_port=443, proto='TCP', chain='INPUT', event_hash='api2'
        )

        factory = RequestFactory()
        req = factory.get('/mapa/api/overview/')
        req.user = type('User', (), {'is_authenticated': True})

        res = api_map_overview(req)
        self.assertEqual(res.status_code, 200)
        import json
        data = json.loads(res.content)
        self.assertTrue(data['ok'])
        self.assertEqual(len(data['events']), 2)

        # Verify geolocatable flag only true for real external IP
        for e in data['events']:
            if e['source'] == 'ids':
                self.assertIsNotNone(e['external_ip'])
            else:
                self.assertFalse(e['geolocatable'])
