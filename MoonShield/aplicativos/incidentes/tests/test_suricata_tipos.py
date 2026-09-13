import unittest
from aplicativos.incidentes.services.suricata.tipos import ConfiguracaoSuricataDados, ModoCaptura

class TestSuricataTopologiaValidacao(unittest.TestCase):
    def test_lan_wan_valido(self):
        # CASO 1 — LAN_WAN válido
        cfg = ConfiguracaoSuricataDados(
            interface_wan="enp0s3",
            interface_lan="enp0s8",
            interfaces_monitoradas=["enp0s8", "enp0s3"],
            home_net=["192.168.0.0/24"],
            modo_captura=ModoCaptura.LAN_WAN,
            yaml_path="/etc/suricata/suricata.yaml",
            eve_path="/var/log/suricata/eve.json",
        )
        erros = cfg.validar()
        self.assertEqual(erros, [], "A topologia LAN_WAN com ambas as interfaces monitoradas deve ser válida")

    def test_lan_wan_invalido_sem_wan(self):
        # CASO 2 — LAN_WAN sem WAN
        cfg = ConfiguracaoSuricataDados(
            interface_wan="enp0s3",
            interface_lan="enp0s8",
            interfaces_monitoradas=["enp0s8"],
            home_net=["192.168.0.0/24"],
            modo_captura=ModoCaptura.LAN_WAN,
            yaml_path="/etc/suricata/suricata.yaml",
            eve_path="/var/log/suricata/eve.json",
        )
        erros = cfg.validar()
        self.assertIn("No modo LAN_WAN, as interfaces LAN e WAN precisam estar nas interfaces monitoradas.", erros)

    def test_lan_wan_invalido_sem_lan(self):
        # CASO 3 — LAN_WAN sem LAN
        cfg = ConfiguracaoSuricataDados(
            interface_wan="enp0s3",
            interface_lan="enp0s8",
            interfaces_monitoradas=["enp0s3"],
            home_net=["192.168.0.0/24"],
            modo_captura=ModoCaptura.LAN_WAN,
            yaml_path="/etc/suricata/suricata.yaml",
            eve_path="/var/log/suricata/eve.json",
        )
        erros = cfg.validar()
        self.assertIn("No modo LAN_WAN, as interfaces LAN e WAN precisam estar nas interfaces monitoradas.", erros)

    def test_lan_wan_valido_ordem_invertida(self):
        # CASO 4 — ordem invertida
        cfg = ConfiguracaoSuricataDados(
            interface_wan="enp0s3",
            interface_lan="enp0s8",
            interfaces_monitoradas=["enp0s3", "enp0s8"],
            home_net=["192.168.0.0/24"],
            modo_captura=ModoCaptura.LAN_WAN,
            yaml_path="/etc/suricata/suricata.yaml",
            eve_path="/var/log/suricata/eve.json",
        )
        erros = cfg.validar()
        self.assertEqual(erros, [], "A topologia LAN_WAN não deve depender da ordem das interfaces monitoradas")

