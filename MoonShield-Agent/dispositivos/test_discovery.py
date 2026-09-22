import ipaddress
import unittest
from unittest.mock import patch

from firewall.ipc.protocolo import decodificar_requisicao
from dispositivos.discovery import DiscoveryError, _agent_interfaces, _targets

try:
    from firewall.ipc.servidor import _despachar
except ModuleNotFoundError as exc:
    if exc.name != "grp":
        raise
    _despachar = None


class DiscoveryTargetValidationTest(unittest.TestCase):
    @patch("dispositivos.discovery._agent_interfaces")
    def test_accepts_private_network_bound_to_real_interface(self, interfaces):
        interfaces.return_value = {"lan0": [ipaddress.IPv4Interface("192.168.50.1/24")]}
        targets = _targets({"max_hosts": 254, "targets": [{"network_id": "lan:lan0", "interface": "lan0", "role": "lan", "cidr": "192.168.50.0/24"}]})
        self.assertEqual(targets[0]["interface"], "lan0")

    @patch("dispositivos.discovery._agent_interfaces")
    def test_rejects_cidr_not_owned_by_agent_interface(self, interfaces):
        interfaces.return_value = {"lan0": [ipaddress.IPv4Interface("192.168.50.1/24")]}
        with self.assertRaises(DiscoveryError):
            _targets({"targets": [{"network_id": "lan:lan0", "interface": "lan0", "role": "lan", "cidr": "8.8.8.0/24"}]})

    @patch("dispositivos.discovery._agent_interfaces")
    def test_rejects_large_or_non_private_network(self, interfaces):
        interfaces.return_value = {"wan0": [ipaddress.IPv4Interface("10.0.0.1/16")]}
        with self.assertRaises(DiscoveryError):
            _targets({"max_hosts": 254, "targets": [{"network_id": "wan:wan0", "interface": "wan0", "role": "wan", "cidr": "10.0.0.0/16"}]})


class DiscoveryDispatcherTest(unittest.TestCase):
    @patch("rede.nucleo.inventario.obter_inventario")
    def test_reads_networkmanager_inventory_address_objects(self, inventory):
        inventory.return_value = {
            "interfaces": [{
                "nome": "lan0",
                "ipv4": [{"endereco": "192.168.50.1", "prefixo": 24}],
            }],
        }

        interfaces = _agent_interfaces()

        self.assertEqual(interfaces["lan0"], [ipaddress.IPv4Interface("192.168.50.1/24")])

    @unittest.skipUnless(_despachar is not None, "Dispatcher IPC requer ambiente Unix.")
    @patch("dispositivos.discovery.executar_device_scan")
    def test_devices_scan_protocol_reaches_dispatcher_handler(self, execute_scan):
        execute_scan.return_value = {"targets": [{"network_id": "lan:lan0", "ok": True, "devices": []}]}
        request = decodificar_requisicao(
            b'{"versao":1,"id":"devices-scan-test","acao":"devices.scan","dados":{"targets":[]}}'
        )

        result = _despachar(request)

        execute_scan.assert_called_once_with({"targets": []})
        self.assertTrue(result["targets"][0]["ok"])