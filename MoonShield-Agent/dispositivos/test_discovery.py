import ipaddress
import unittest
from unittest.mock import patch

from dispositivos.discovery import DiscoveryError, _targets


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
