from unittest.mock import patch

from django.test import SimpleTestCase
from django.utils import timezone

from incidentes.models import Incidente
from incidentes.services import enriquecedor
from incidentes.services.contexto_rede import classificar_fluxo, classificar_ip_rede
from incidentes.services.enriquecedor import enriquecer_ip
from incidentes.views import _incidente_para_evento


def _topologia_lan():
    interface_lan = {
        "desejado": {"ipv4_endereco": "192.168.52.1", "ipv4_prefixo": 24},
        "real": {"enderecos_ipv4": ["192.168.52.1/24"]},
    }
    return {
        "lan": {"interfaces": [interface_lan]},
        "mgmt": {"interfaces": []},
        "dmz": [],
        "custom": [],
        "wan": {"interfaces": []},
    }


class ContextoRedeTests(SimpleTestCase):
    @patch("incidentes.services.contexto_rede.obter_topologia", side_effect=lambda: _topologia_lan())
    def test_classifica_ssot_e_fallbacks_privados(self, _topologia):
        casos = {
            "192.168.52.2": ("internal", "LAN"),
            "192.168.52.1": ("internal", "LAN"),
            "192.168.0.106": ("internal", None),
            "10.0.0.10": ("internal", None),
            "172.16.50.10": ("internal", None),
            "127.0.0.1": ("internal", "LOCAL"),
            "169.254.1.1": ("internal", None),
            "::1": ("internal", "LOCAL"),
            "fe80::1": ("internal", None),
            "fc00::1": ("internal", None),
            "8.8.8.8": ("external", None),
            "1.1.1.1": ("external", None),
        }

        for ip, (scope, role) in casos.items():
            with self.subTest(ip=ip):
                contexto = classificar_ip_rede(ip)
                self.assertEqual(contexto["scope"], scope)
                self.assertEqual(contexto["role"], role)
                self.assertEqual(contexto["geoip_allowed"], scope == "external")

    @patch("incidentes.services.contexto_rede.obter_topologia", side_effect=lambda: _topologia_lan())
    def test_classifica_fluxos_de_rede(self, _topologia):
        casos = (
            ("192.168.52.2", "192.168.52.1", "internal"),
            ("192.168.52.2", "8.8.8.8", "outbound"),
            ("8.8.8.8", "192.168.52.1", "inbound"),
            ("8.8.8.8", "1.1.1.1", "external"),
        )

        for src, dst, esperado in casos:
            with self.subTest(src=src, dst=dst):
                fluxo = classificar_fluxo(src, dst)
                self.assertEqual(fluxo["flow_scope"], esperado)

    @patch("incidentes.services.enriquecedor._rdns", return_value="")
    @patch("incidentes.services.enriquecedor._consultar_maxmind")
    @patch("incidentes.services.contexto_rede.obter_topologia", side_effect=lambda: _topologia_lan())
    def test_geoip_nao_e_consultado_para_ip_interno(self, _topologia, consultar_maxmind, _rdns):
        resultado = enriquecer_ip("192.168.52.2")

        consultar_maxmind.assert_not_called()
        self.assertEqual(resultado["pais"], "")
        self.assertTrue(resultado["is_private"])

    @patch("incidentes.services.enriquecedor._salvar_geocache")
    @patch("incidentes.services.enriquecedor._rdns", return_value="dns.google")
    @patch("incidentes.services.enriquecedor._buscar_geocache", return_value=None)
    @patch("incidentes.services.enriquecedor._consultar_maxmind", return_value={
        "pais": "United States", "pais_codigo": "US", "cidade": "", "latitude": None,
        "longitude": None, "asn_number": "", "asn_org": "", "asn": "", "source": "maxmind",
    })
    @patch("incidentes.services.contexto_rede.obter_topologia", side_effect=lambda: _topologia_lan())
    def test_geoip_pode_ser_consultado_para_ip_publico(self, _topologia, consultar_maxmind, _buscar_geocache, _rdns, _salvar_geocache):
        enriquecedor._mem_cache.pop("8.8.8.8", None)
        enriquecer_ip("8.8.8.8")

        consultar_maxmind.assert_called_once_with("8.8.8.8")

    @patch("incidentes.services.contexto_rede.obter_topologia", side_effect=lambda: _topologia_lan())
    def test_serializer_corrige_contexto_de_incidente_historico(self, _topologia):
        agora = timezone.now()
        incidente = Incidente(
            fingerprint="teste",
            first_seen=agora,
            last_seen=agora,
            src_ip="192.168.52.2",
            dest_ip="192.168.52.1",
            direction="external",
            pais="Brasil",
            pais_codigo="BR",
        )

        evento = _incidente_para_evento(incidente, completo=True)

        self.assertEqual(evento["src_scope"], "internal")
        self.assertEqual(evento["dst_scope"], "internal")
        self.assertEqual(evento["src_role"], "LAN")
        self.assertEqual(evento["flow_scope"], "internal")
        self.assertEqual(evento["direction"], "internal")
        self.assertIsNone(evento["country"]["code"])
        self.assertIsNone(evento["country"]["name"])
