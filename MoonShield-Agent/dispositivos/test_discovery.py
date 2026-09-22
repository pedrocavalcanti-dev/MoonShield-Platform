"""Testes unitários do discovery do MoonShield Agent.

Execução (Windows/Linux):
    python -m unittest discover -s dispositivos -p 'test_*.py' -v

Todos os testes usam mocks para ferramentas Linux (ip, ping, nmap, grp).
"""
import ipaddress
import shutil
import unittest
from unittest.mock import MagicMock, patch

from firewall.ipc.protocolo import decodificar_requisicao
from dispositivos.discovery import (
    DiscoveryError,
    _agent_interfaces,
    _mac,
    _parse_nmap,
    _targets,
    device_capabilities,
    executar_device_probe,
    executar_device_scan,
)

try:
    from firewall.ipc.servidor import _despachar
except ModuleNotFoundError as exc:
    if exc.name != "grp":
        raise
    _despachar = None


# ─────────────────────────────────────────────
# UTILITÁRIOS
# ─────────────────────────────────────────────

def _lan_target():
    return {"network_id": "lan:lan0", "interface": "lan0", "role": "lan", "cidr": "192.168.50.0/24"}


def _lan_interfaces():
    return {"lan0": [ipaddress.IPv4Interface("192.168.50.1/24")]}


# ─────────────────────────────────────────────
# VALIDAÇÃO DE TARGETS (SCAN)
# ─────────────────────────────────────────────

class DiscoveryTargetValidationTest(unittest.TestCase):

    @patch("dispositivos.discovery._agent_interfaces")
    def test_accepts_private_network_bound_to_real_interface(self, interfaces):
        interfaces.return_value = _lan_interfaces()
        targets = _targets({"max_hosts": 254, "targets": [_lan_target()]})
        self.assertEqual(targets[0]["interface"], "lan0")

    @patch("dispositivos.discovery._agent_interfaces")
    def test_rejects_cidr_not_owned_by_agent_interface(self, interfaces):
        interfaces.return_value = _lan_interfaces()
        with self.assertRaises(DiscoveryError):
            _targets({"targets": [{"network_id": "lan:lan0", "interface": "lan0", "role": "lan", "cidr": "8.8.8.0/24"}]})

    @patch("dispositivos.discovery._agent_interfaces")
    def test_rejects_large_or_non_private_network(self, interfaces):
        interfaces.return_value = {"wan0": [ipaddress.IPv4Interface("10.0.0.1/16")]}
        with self.assertRaises(DiscoveryError):
            _targets({"max_hosts": 254, "targets": [{"network_id": "wan:wan0", "interface": "wan0", "role": "wan", "cidr": "10.0.0.0/16"}]})

    @patch("dispositivos.discovery._agent_interfaces")
    def test_rejects_duplicate_targets(self, interfaces):
        interfaces.return_value = _lan_interfaces()
        with self.assertRaises(DiscoveryError):
            _targets({"targets": [_lan_target(), _lan_target()]})

    @patch("dispositivos.discovery._agent_interfaces")
    def test_rejects_loopback_network(self, interfaces):
        interfaces.return_value = {"lo": [ipaddress.IPv4Interface("127.0.0.1/8")]}
        with self.assertRaises(DiscoveryError):
            _targets({"targets": [{"network_id": "lan:lo", "interface": "lo", "role": "lan", "cidr": "127.0.0.0/8"}]})

    @patch("dispositivos.discovery._agent_interfaces")
    def test_rejects_wrong_network_id_format(self, interfaces):
        interfaces.return_value = _lan_interfaces()
        target = dict(_lan_target())
        target["network_id"] = "wrong:format"
        with self.assertRaises(DiscoveryError):
            _targets({"targets": [target]})


# ─────────────────────────────────────────────
# VALIDAÇÃO DE PROBE
# ─────────────────────────────────────────────

class ProbeValidationTest(unittest.TestCase):

    @patch("dispositivos.discovery._agent_interfaces")
    def test_probe_accepts_valid_known_hosts(self, interfaces):
        interfaces.return_value = _lan_interfaces()
        payload = {
            "targets": [{**_lan_target(), "hosts": [{"device_id": "1", "ip": "192.168.50.10"}, {"device_id": "2", "ip": "192.168.50.20"}]}],
        }
        # Valida apenas a estrutura (sem executar ferramentas Linux)
        with patch("dispositivos.discovery._link_ready"), \
             patch("dispositivos.discovery._neighbors", return_value={}), \
             patch("dispositivos.discovery._probe_ping", return_value=True):
            result = executar_device_probe(payload)
        self.assertEqual(len(result["targets"]), 1)
        self.assertTrue(result["targets"][0]["ok"])

    @patch("dispositivos.discovery._agent_interfaces")
    def test_probe_rejects_host_outside_network(self, interfaces):
        interfaces.return_value = _lan_interfaces()
        payload = {
            "targets": [{**_lan_target(), "hosts": [{"device_id": "1", "ip": "10.0.0.1"}]}],
        }
        with self.assertRaises(DiscoveryError, msg="Host fora da rede oficial"):
            executar_device_probe(payload)

    @patch("dispositivos.discovery._agent_interfaces")
    def test_probe_rejects_more_than_64_hosts(self, interfaces):
        interfaces.return_value = _lan_interfaces()
        hosts = [{"device_id": str(i), "ip": f"192.168.50.{i}"} for i in range(1, 66)]
        payload = {"targets": [{**_lan_target(), "hosts": hosts}]}
        with self.assertRaises(DiscoveryError):
            executar_device_probe(payload)

    @patch("dispositivos.discovery._agent_interfaces")
    def test_probe_rejects_duplicate_hosts(self, interfaces):
        interfaces.return_value = _lan_interfaces()
        payload = {
            "targets": [{**_lan_target(), "hosts": [{"device_id": "1", "ip": "192.168.50.10"}, {"device_id": "2", "ip": "192.168.50.10"}]}],
        }
        with self.assertRaises(DiscoveryError):
            executar_device_probe(payload)

    @patch("dispositivos.discovery._agent_interfaces")
    def test_probe_rejects_extra_fields(self, interfaces):
        interfaces.return_value = _lan_interfaces()
        with self.assertRaises(DiscoveryError):
            executar_device_probe({"targets": [_lan_target()], "free_cidr": "10.0.0.0/8"})

    @patch("dispositivos.discovery._agent_interfaces")
    def test_probe_does_not_call_nmap(self, interfaces):
        """Nmap NUNCA deve ser chamado pelo probe."""
        interfaces.return_value = _lan_interfaces()
        payload = {
            "targets": [{**_lan_target(), "hosts": [{"device_id": "1", "ip": "192.168.50.10"}]}],
        }
        with patch("dispositivos.discovery._link_ready"), \
             patch("dispositivos.discovery._neighbors", return_value={}), \
             patch("dispositivos.discovery._probe_ping", return_value=True), \
             patch("dispositivos.discovery.shutil.which", return_value=None) as mock_nmap, \
             patch("dispositivos.discovery._advanced") as mock_advanced:
            executar_device_probe(payload)
            mock_advanced.assert_not_called()

    @patch("dispositivos.discovery._agent_interfaces")
    def test_probe_interface_down_returns_error_not_failures(self, interfaces):
        """Interface down deve retornar ok=False no target, não aplicar falhas nos hosts."""
        interfaces.return_value = _lan_interfaces()
        payload = {
            "targets": [{**_lan_target(), "hosts": [{"device_id": "1", "ip": "192.168.50.10"}]}],
        }
        with patch("dispositivos.discovery._link_ready", side_effect=DiscoveryError("Interface indisponível")), \
             patch("dispositivos.discovery._neighbors", return_value={}):
            result = executar_device_probe(payload)
        self.assertFalse(result["targets"][0]["ok"])
        self.assertIn("error", result["targets"][0])


# ─────────────────────────────────────────────
# CAPABILITIES
# ─────────────────────────────────────────────

class CapabilitiesTest(unittest.TestCase):

    def test_capabilities_with_nmap_present(self):
        with patch("dispositivos.discovery.shutil.which", return_value="/usr/bin/nmap"):
            caps = device_capabilities({})
        self.assertTrue(caps["advanced"])
        self.assertIn("advanced_max_hosts", caps)

    def test_capabilities_without_nmap(self):
        with patch("dispositivos.discovery.shutil.which", return_value=None):
            caps = device_capabilities({})
        self.assertFalse(caps["advanced"])

    def test_advanced_scan_without_nmap_raises_error(self):
        with patch("dispositivos.discovery.shutil.which", return_value=None), \
             patch("dispositivos.discovery._agent_interfaces", return_value=_lan_interfaces()):
            with self.assertRaises(DiscoveryError):
                executar_device_scan({"targets": [_lan_target()], "mode": "advanced"})

    def test_quick_scan_works_without_nmap(self):
        """Quick scan não deve exigir Nmap."""
        with patch("dispositivos.discovery.shutil.which", return_value=None), \
             patch("dispositivos.discovery._agent_interfaces", return_value=_lan_interfaces()), \
             patch("dispositivos.discovery._scan_target", return_value={"network_id": "lan:lan0", "ok": True, "devices": []}):
            result = executar_device_scan({"targets": [_lan_target()], "mode": "quick"})
        self.assertTrue(result["targets"][0]["ok"])


# ─────────────────────────────────────────────
# PARSER NMAP XML
# ─────────────────────────────────────────────

class ParseNmapTest(unittest.TestCase):

    _XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.50.10" addrtype="ipv4"/>
    <hostnames><hostname name="myhost.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.4" ostype="Linux"/></port>
      <port protocol="tcp" portid="80"><state state="closed"/></port>
      <port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds" product="" version="" ostype="Windows"/></port>
    </ports>
    <os>
      <osmatch name="Linux 5.4" accuracy="92"/>
    </os>
  </host>
</nmaprun>"""

    def test_parse_extracts_open_tcp_ports(self):
        result = _parse_nmap(self._XML, "192.168.50.10")
        self.assertIn(22, result["open_ports"])
        self.assertNotIn(80, result["open_ports"])  # closed
        self.assertIn(445, result["open_ports"])

    def test_parse_extracts_hostname(self):
        result = _parse_nmap(self._XML, "192.168.50.10")
        self.assertEqual(result["hostname"], "myhost.local")

    def test_parse_extracts_os_with_high_confidence(self):
        result = _parse_nmap(self._XML, "192.168.50.10")
        self.assertEqual(result.get("os_fingerprint"), "Linux 5.4")
        self.assertEqual(result.get("os_confidence"), 92)

    def test_parse_extracts_services(self):
        result = _parse_nmap(self._XML, "192.168.50.10")
        services = result.get("services", [])
        self.assertTrue(any(s["port"] == 22 and s["name"] == "ssh" for s in services))

    def test_parse_returns_empty_for_wrong_ip(self):
        result = _parse_nmap(self._XML, "10.0.0.1")
        self.assertEqual(result, {})

    def test_parse_ignores_low_confidence_os(self):
        xml = self._XML.replace('accuracy="92"', 'accuracy="60"')
        result = _parse_nmap(xml, "192.168.50.10")
        self.assertNotIn("os_fingerprint", result)


# ─────────────────────────────────────────────
# HELPERS MAC / INVENTÁRIO
# ─────────────────────────────────────────────

class MacNormalizationTest(unittest.TestCase):

    def test_accepts_valid_unicast_mac(self):
        self.assertEqual(_mac("AA:BB:CC:DD:EE:FF"), "AA:BB:CC:DD:EE:FF")

    def test_normalizes_hyphen_separator(self):
        self.assertEqual(_mac("aa-bb-cc-dd-ee-ff"), "AA:BB:CC:DD:EE:FF")

    def test_rejects_broadcast(self):
        self.assertIsNone(_mac("FF:FF:FF:FF:FF:FF"))

    def test_rejects_all_zeros(self):
        self.assertIsNone(_mac("00:00:00:00:00:00"))

    def test_rejects_multicast(self):
        # LSB of first octet = 1 → multicast
        self.assertIsNone(_mac("01:00:5E:00:00:01"))


# ─────────────────────────────────────────────
# INVENTÁRIO DO AGENT (NETWORKMANAGER)
# ─────────────────────────────────────────────

class DiscoveryInventarioTest(unittest.TestCase):

    @patch("rede.nucleo.inventario.obter_inventario")
    def test_reads_networkmanager_inventory_address_objects(self, inventory):
        inventory.return_value = {
            "interfaces": [{"nome": "lan0", "ipv4": [{"endereco": "192.168.50.1", "prefixo": 24}]}],
        }
        interfaces = _agent_interfaces()
        self.assertEqual(interfaces["lan0"], [ipaddress.IPv4Interface("192.168.50.1/24")])

    @patch("rede.nucleo.inventario.obter_inventario")
    def test_reads_plain_cidr_format(self, inventory):
        inventory.return_value = {
            "interfaces": [{"nome": "wan0", "ipv4": ["10.20.30.2/24"]}],
        }
        interfaces = _agent_interfaces()
        self.assertEqual(interfaces["wan0"], [ipaddress.IPv4Interface("10.20.30.2/24")])


# ─────────────────────────────────────────────
# DISPATCHER IPC
# ─────────────────────────────────────────────

class DiscoveryDispatcherTest(unittest.TestCase):

    @unittest.skipUnless(_despachar is not None, "Dispatcher IPC requer ambiente Unix (sem módulo grp no Windows).")
    @patch("dispositivos.discovery.executar_device_scan")
    def test_devices_scan_protocol_reaches_dispatcher_handler(self, execute_scan):
        execute_scan.return_value = {"targets": [{"network_id": "lan:lan0", "ok": True, "devices": []}]}
        request = decodificar_requisicao(
            b'{"versao":1,"id":"devices-scan-test","acao":"devices.scan","dados":{"targets":[]}}'
        )
        result = _despachar(request)
        execute_scan.assert_called_once_with({"targets": []})
        self.assertTrue(result["targets"][0]["ok"])

    @unittest.skipUnless(_despachar is not None, "Dispatcher IPC requer ambiente Unix.")
    @patch("dispositivos.discovery.executar_device_probe")
    def test_devices_probe_protocol_reaches_dispatcher_handler(self, execute_probe):
        execute_probe.return_value = {"targets": [{"network_id": "lan:lan0", "ok": True, "devices": []}]}
        request = decodificar_requisicao(
            b'{"versao":1,"id":"probe-test","acao":"devices.probe","dados":{"targets":[]}}'
        )
        result = _despachar(request)
        execute_probe.assert_called_once_with({"targets": []})
        self.assertTrue(result["targets"][0]["ok"])

    @unittest.skipUnless(_despachar is not None, "Dispatcher IPC requer ambiente Unix.")
    @patch("dispositivos.discovery.device_capabilities")
    def test_devices_capabilities_protocol_reaches_dispatcher_handler(self, caps):
        caps.return_value = {"advanced": False, "advanced_max_hosts": 8}
        request = decodificar_requisicao(
            b'{"versao":1,"id":"caps-test","acao":"devices.capabilities","dados":{}}'
        )
        result = _despachar(request)
        caps.assert_called_once_with({})
        self.assertIn("advanced", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)