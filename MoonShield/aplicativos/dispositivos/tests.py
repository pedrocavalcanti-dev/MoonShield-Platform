import inspect
from unittest.mock import patch

from django.contrib.auth import get_user_model
from configuracoes.models import ConfigSistema
from django.test import Client, TestCase
from django.utils import timezone

from .models import Dispositivo, ScanRun
from .services import (
    _persist_device,
    executar_scan,
    redes_elegiveis,
    selecionar_redes,
    validar_custom_name,
)


class DispositivosV2Test(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="devices-user", password="password")
        self.client.force_login(self.user)
        config = ConfigSistema.get_solo()
        config.appliance_onboarding_completo = True
        config.save(update_fields=["appliance_onboarding_completo", "updated_at"])
        self.topology = {
            "wan": {"interfaces": [self._interface("wan0", "10.20.30.2/24")]},
            "lan": {"interfaces": [self._interface("lan0", "192.168.50.1/24")]},
            "mgmt": {"interfaces": []}, "dmz": [], "custom": [],
        }

    @staticmethod
    def _interface(name, address):
        return {"nome": name, "desejado": {"habilitada": True}, "real": {"enderecos_ipv4": [address]}}

    def _target(self):
        return {"id": "lan:lan0", "role": "lan", "interface": "lan0", "cidr": "192.168.50.0/24", "gateway": "192.168.50.1"}

    def test_inventory_requires_authentication(self):
        response = Client().get("/dispositivos/api/inventory/")
        self.assertEqual(response.status_code, 302)

    def test_scan_and_rename_require_csrf(self):
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.user)
        self.assertEqual(csrf_client.post("/dispositivos/api/scan/", data="{}", content_type="application/json").status_code, 403)
        self.assertEqual(csrf_client.post("/dispositivos/api/rename/", data="{}", content_type="application/json").status_code, 403)

    def test_scan_rejects_free_cidr(self):
        response = self.client.post("/dispositivos/api/scan/", data='{"cidr":"8.8.8.0/24"}', content_type="application/json")
        self.assertEqual(response.status_code, 400)

    @patch("dispositivos.services.obter_topologia")
    def test_lan_default_wan_explicit_and_official_only(self, topology):
        topology.return_value = self.topology
        networks = {network["id"]: network for network in redes_elegiveis()}
        self.assertTrue(networks["lan:lan0"]["selected"])
        self.assertFalse(networks["wan:wan0"]["selected"])
        selected = selecionar_redes(["wan:wan0"])
        self.assertEqual(selected[0]["id"], "wan:wan0")
        with self.assertRaises(ValueError):
            selecionar_redes(["wan:outside"])

    def test_mac_identity_updates_ip_and_preserves_custom_name(self):
        now = timezone.now()
        target = self._target()
        device = _persist_device(target, {"ip": "192.168.50.20", "mac": "aa-bb-cc-dd-ee-ff"}, now)
        device.custom_name = "Notebook da recepção"
        device.save(update_fields=["custom_name"])
        moved = _persist_device(target, {"ip": "192.168.50.40", "mac": "AA:BB:CC:DD:EE:FF"}, now)
        self.assertEqual(device.pk, moved.pk)
        self.assertEqual(moved.current_ip, "192.168.50.40")
        self.assertEqual(moved.custom_name, "Notebook da recepção")

    def test_new_mac_on_old_ip_does_not_inherit_name(self):
        now = timezone.now()
        target = self._target()
        old = _persist_device(target, {"ip": "192.168.50.20", "mac": "AA:BB:CC:DD:EE:01"}, now)
        old.custom_name = "Servidor antigo"
        old.save(update_fields=["custom_name"])
        current = _persist_device(target, {"ip": "192.168.50.20", "mac": "AA:BB:CC:DD:EE:02"}, now)
        old.refresh_from_db()
        self.assertNotEqual(old.pk, current.pk)
        self.assertIsNone(old.current_ip)
        self.assertEqual(old.custom_name, "Servidor antigo")
        self.assertIsNone(current.custom_name)

    @patch("dispositivos.services.requisitar_agent")
    @patch("dispositivos.services.obter_topologia")
    def test_success_marks_missing_device_offline_without_deleting(self, topology, agent):
        topology.return_value = self.topology
        agent.return_value = {"targets": [{"network_id": "lan:lan0", "ok": True, "devices": [{"ip": "192.168.50.20", "mac": "AA:BB:CC:DD:EE:03", "open_ports": []}]}]}
        executar_scan(["lan:lan0"])
        device = Dispositivo.objects.get(identity_key="mac:AA:BB:CC:DD:EE:03")
        agent.return_value = {"targets": [{"network_id": "lan:lan0", "ok": True, "devices": []}]}
        executar_scan(["lan:lan0"])
        device.refresh_from_db()
        self.assertEqual(device.status, Dispositivo.Status.OFFLINE)
        self.assertTrue(Dispositivo.objects.filter(pk=device.pk).exists())

    @patch("dispositivos.services.requisitar_agent")
    @patch("dispositivos.services.obter_topologia")
    def test_failed_network_does_not_mark_devices_offline(self, topology, agent):
        topology.return_value = self.topology
        device = _persist_device(self._target(), {"ip": "192.168.50.30", "mac": "AA:BB:CC:DD:EE:04"}, timezone.now())
        agent.return_value = {"targets": [{"network_id": "lan:lan0", "ok": False, "error": "timeout"}]}
        executar_scan(["lan:lan0"])
        device.refresh_from_db()
        self.assertEqual(device.status, Dispositivo.Status.ONLINE)

    def test_inventory_api_has_no_legacy_missing_fields_or_django_scanner(self):
        _persist_device(self._target(), {"ip": "192.168.50.30", "mac": "AA:BB:CC:DD:EE:05"}, timezone.now())
        response = self.client.get("/dispositivos/api/inventory/")
        self.assertEqual(response.status_code, 200)
        payload = response.json()["devices"][0]
        self.assertEqual(payload["device_id"], str(Dispositivo.objects.first().pk))
        self.assertNotIn("subprocess", inspect.getsource(__import__("dispositivos.api_views", fromlist=["*"])))

    def test_dashboard_counts_the_same_inventory(self):
        _persist_device(self._target(), {"ip": "192.168.50.31", "mac": "AA:BB:CC:DD:EE:06"}, timezone.now())
        from painel.views import _infra_dispositivos
        info = _infra_dispositivos()
        self.assertEqual(info["total"], 1)
        self.assertEqual(info["online"], 1)

    @patch("dispositivos.services.obter_topologia")
    def test_scan_lock_blocks_concurrent_request(self, topology):
        topology.return_value = self.topology
        ScanRun.objects.create(lock_key="devices-discovery", requested_networks=[])
        with self.assertRaises(ValueError):
            executar_scan(["lan:lan0"])

    def test_custom_name_is_limited_to_plain_text(self):
        self.assertEqual(validar_custom_name("  Equipamento A  "), "Equipamento A")
        with self.assertRaises(ValueError):
            validar_custom_name(123)
        with self.assertRaises(ValueError):
            validar_custom_name("x" * 121)
        with self.assertRaises(ValueError):
            validar_custom_name("nome\nquebrado")
        with self.assertRaises(ValueError):
            validar_custom_name("<b>nome</b>")