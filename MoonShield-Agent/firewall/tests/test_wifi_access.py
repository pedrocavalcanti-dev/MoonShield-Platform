import unittest
from unittest.mock import patch
from firewall.nucleo import aplicador
from firewall.nucleo.status import ContextoSeguranca

class WifiAccessTests(unittest.TestCase):
    def setUp(self):
        self.contexto = ContextoSeguranca(
            interface_wan="eth0",
            interface_lan="eth1",
            interface_mgmt="eth2",
            home_net="10.10.0.0/24"
        )
        self.allowlist = {"ipv4": [], "ipv6": []}

    @patch("firewall.nucleo.aplicador.tabela_existe", return_value=False)
    def test_gerar_script_com_wifi_disabled(self, mock_existe):
        script = aplicador._gerar_script(
            regras=[],
            allowlist=self.allowlist,
            wifi_access={"enabled": False, "range_start": "10.10.0.100", "range_end": "10.10.0.254"},
            contexto=self.contexto
        )
        self.assertIn("chain ms_wifi_access {", script)
        self.assertNotIn("10.10.0.100-10.10.0.254", script)

    @patch("firewall.nucleo.aplicador.tabela_existe", return_value=False)
    def test_gerar_script_com_wifi_enabled_sem_autorizados(self, mock_existe):
        script = aplicador._gerar_script(
            regras=[],
            allowlist=self.allowlist,
            wifi_access={
                "enabled": True,
                "range_start": "10.10.0.100",
                "range_end": "10.10.0.254",
                "egress_interfaces": ["eth0"],
                "authorized_ips": []
            },
            contexto=self.contexto
        )
        self.assertIn("chain ms_wifi_access {", script)
        self.assertNotIn("wifi:authorized", script)
        self.assertIn("10.10.0.100-10.10.0.254 oifname { \"eth0\" } counter drop", script)

    @patch("firewall.nucleo.aplicador.tabela_existe", return_value=False)
    def test_gerar_script_com_wifi_enabled_com_autorizados(self, mock_existe):
        script = aplicador._gerar_script(
            regras=[],
            allowlist=self.allowlist,
            wifi_access={
                "enabled": True,
                "range_start": "10.10.0.100",
                "range_end": "10.10.0.254",
                "egress_interfaces": ["eth0"],
                "authorized_ips": ["10.10.0.137", "10.10.0.150"]
            },
            contexto=self.contexto
        )
        self.assertIn("chain ms_wifi_access {", script)
        self.assertIn("{ 10.10.0.137, 10.10.0.150 } oifname { \"eth0\" } counter accept comment \"wifi:authorized\"", script)
        self.assertIn("10.10.0.100-10.10.0.254 oifname { \"eth0\" } counter drop comment \"wifi:unauthorized-drop\"", script)

    @patch("firewall.nucleo.aplicador.tabela_existe", return_value=False)
    def test_gerar_script_com_wifi_sem_egress(self, mock_existe):
        script = aplicador._gerar_script(
            regras=[],
            allowlist=self.allowlist,
            wifi_access={
                "enabled": True,
                "range_start": "10.10.0.100",
                "range_end": "10.10.0.254",
                "egress_interfaces": [],
                "authorized_ips": ["10.10.0.137"]
            },
            contexto=self.contexto
        )
        # Without egress interfaces, it drops for all egress traffic for the range
        self.assertIn("{ 10.10.0.137 }  counter accept", script)
        self.assertIn("10.10.0.100-10.10.0.254  counter drop", script)

    @patch("firewall.nucleo.aplicador.tabela_existe", return_value=False)
    def test_gerar_script_wifi_missing_range(self, mock_existe):
        script = aplicador._gerar_script(
            regras=[],
            allowlist=self.allowlist,
            wifi_access={
                "enabled": True,
                "range_start": "",
                "range_end": "10.10.0.254",
                "egress_interfaces": ["eth0"],
                "authorized_ips": ["10.10.0.137"]
            },
            contexto=self.contexto
        )
        # Se no tem start/end, no deve gerar drop ou regras de wifi
        self.assertIn("chain ms_wifi_access {", script)
        self.assertNotIn("wifi:authorized", script)
        self.assertNotIn("wifi:unauthorized-drop", script)
