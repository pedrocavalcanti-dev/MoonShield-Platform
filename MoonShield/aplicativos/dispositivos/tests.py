"""Testes de Dispositivos V2 — inventário, scan, probe, monitoramento e semântica de disponibilidade."""
import inspect
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.utils import timezone

from configuracoes.models import ConfigSistema

from .models import Dispositivo, MonitorDispositivos, RedeDiscovery, ScanRun
from .monitoring import _apply_probe, monitor_config, save_monitor_config
from .services import (
    DiscoveryValidationError,
    _persist_device,
    executar_scan,
    redes_elegiveis,
    selecionar_redes,
    validar_custom_name,
)


def _make_user(username="devices-user"):
    return get_user_model().objects.create_user(username=username, password="password")


def _interface(name, address):
    return {"nome": name, "desejado": {"habilitada": True}, "real": {"enderecos_ipv4": [address]}}


TOPOLOGY = {
    "wan": {"interfaces": [_interface("wan0", "10.20.30.2/24")]},
    "lan": {"interfaces": [_interface("lan0", "192.168.50.1/24")]},
    "mgmt": {"interfaces": []}, "dmz": [], "custom": [],
}


def _target_lan():
    return {"id": "lan:lan0", "role": "lan", "interface": "lan0", "cidr": "192.168.50.0/24", "gateway": "192.168.50.1"}


def _target_wan():
    return {"id": "wan:wan0", "role": "wan", "interface": "wan0", "cidr": "10.20.30.0/24", "gateway": "10.20.30.1"}


def _enable_onboarding():
    config = ConfigSistema.get_solo()
    config.appliance_onboarding_completo = True
    config.save(update_fields=["appliance_onboarding_completo", "updated_at"])


# ─────────────────────────────────────────────
# TESTES DE INVENTÁRIO / SCAN V2
# ─────────────────────────────────────────────

class DispositivosV2Test(TestCase):
    def setUp(self):
        self.user = _make_user()
        self.client.force_login(self.user)
        _enable_onboarding()

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
        topology.return_value = TOPOLOGY
        networks = {n["id"]: n for n in redes_elegiveis()}
        self.assertTrue(networks["lan:lan0"]["selected"])
        self.assertFalse(networks["wan:wan0"]["selected"])
        selected = selecionar_redes(["wan:wan0"])
        self.assertEqual(selected[0]["id"], "wan:wan0")
        with self.assertRaises(ValueError):
            selecionar_redes(["wan:outside"])

    def test_mac_identity_updates_ip_and_preserves_custom_name(self):
        now = timezone.now()
        device = _persist_device(_target_lan(), {"ip": "192.168.50.20", "mac": "aa-bb-cc-dd-ee-ff"}, now)
        device.custom_name = "Notebook da recepção"
        device.save(update_fields=["custom_name"])
        moved = _persist_device(_target_lan(), {"ip": "192.168.50.40", "mac": "AA:BB:CC:DD:EE:FF"}, now)
        self.assertEqual(device.pk, moved.pk)
        self.assertEqual(moved.current_ip, "192.168.50.40")
        self.assertEqual(moved.custom_name, "Notebook da recepção")

    def test_new_mac_on_old_ip_does_not_inherit_name(self):
        now = timezone.now()
        old = _persist_device(_target_lan(), {"ip": "192.168.50.20", "mac": "AA:BB:CC:DD:EE:01"}, now)
        old.custom_name = "Servidor antigo"
        old.save(update_fields=["custom_name"])
        current = _persist_device(_target_lan(), {"ip": "192.168.50.20", "mac": "AA:BB:CC:DD:EE:02"}, now)
        old.refresh_from_db()
        self.assertNotEqual(old.pk, current.pk)
        self.assertIsNone(old.current_ip)
        self.assertEqual(old.custom_name, "Servidor antigo")
        self.assertIsNone(current.custom_name)

    @patch("dispositivos.services.requisitar_agent")
    @patch("dispositivos.services.obter_topologia")
    def test_success_marks_missing_device_with_failure_increment(self, topology, agent):
        """Scan bem-sucedido onde host está ausente = +1 falha (não offline imediato)."""
        topology.return_value = TOPOLOGY
        agent.return_value = {"targets": [{"network_id": "lan:lan0", "ok": True, "devices": [{"ip": "192.168.50.20", "mac": "AA:BB:CC:DD:EE:03", "open_ports": []}]}]}
        executar_scan(["lan:lan0"])
        device = Dispositivo.objects.get(identity_key="mac:AA:BB:CC:DD:EE:03")
        self.assertEqual(device.status, Dispositivo.Status.ONLINE)
        self.assertEqual(device.availability_failures, 0)

        # Segundo scan: host não aparece → +1 falha, ainda não offline
        agent.return_value = {"targets": [{"network_id": "lan:lan0", "ok": True, "devices": []}]}
        executar_scan(["lan:lan0"])
        device.refresh_from_db()
        self.assertEqual(device.availability_failures, 1)
        self.assertNotEqual(device.status, Dispositivo.Status.OFFLINE)

        # Terceiro scan: host não aparece → +2, não offline
        executar_scan(["lan:lan0"])
        device.refresh_from_db()
        self.assertEqual(device.availability_failures, 2)
        self.assertNotEqual(device.status, Dispositivo.Status.OFFLINE)

        # Quarto scan: +3 → offline
        executar_scan(["lan:lan0"])
        device.refresh_from_db()
        self.assertEqual(device.availability_failures, 3)
        self.assertEqual(device.status, Dispositivo.Status.OFFLINE)
        # Registro preservado
        self.assertTrue(Dispositivo.objects.filter(pk=device.pk).exists())

    @patch("dispositivos.services.requisitar_agent")
    @patch("dispositivos.services.obter_topologia")
    def test_failed_network_does_not_mark_devices_offline(self, topology, agent):
        topology.return_value = TOPOLOGY
        device = _persist_device(_target_lan(), {"ip": "192.168.50.30", "mac": "AA:BB:CC:DD:EE:04"}, timezone.now())
        agent.return_value = {"targets": [{"network_id": "lan:lan0", "ok": False, "error": "timeout"}]}
        executar_scan(["lan:lan0"])
        device.refresh_from_db()
        self.assertEqual(device.status, Dispositivo.Status.ONLINE)
        self.assertEqual(device.availability_failures, 0)

    def test_inventory_api_has_no_legacy_missing_fields_or_django_scanner(self):
        _persist_device(_target_lan(), {"ip": "192.168.50.30", "mac": "AA:BB:CC:DD:EE:05"}, timezone.now())
        response = self.client.get("/dispositivos/api/inventory/")
        self.assertEqual(response.status_code, 200)
        payload = response.json()["devices"][0]
        self.assertEqual(payload["device_id"], str(Dispositivo.objects.first().pk))
        self.assertNotIn("subprocess", inspect.getsource(__import__("dispositivos.api_views", fromlist=["*"])))

    def test_dashboard_counts_the_same_inventory(self):
        _persist_device(_target_lan(), {"ip": "192.168.50.31", "mac": "AA:BB:CC:DD:EE:06"}, timezone.now())
        from painel.views import _infra_dispositivos
        info = _infra_dispositivos()
        self.assertEqual(info["total"], 1)
        self.assertEqual(info["online"], 1)

    @patch("dispositivos.services.obter_topologia")
    def test_scan_lock_blocks_concurrent_request(self, topology):
        topology.return_value = TOPOLOGY
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


# ─────────────────────────────────────────────
# TESTES DE MONITORAMENTO — CONFIGURAÇÃO
# ─────────────────────────────────────────────

class MonitorConfigTest(TestCase):
    def setUp(self):
        self.user = _make_user("monitor-user")
        self.client.force_login(self.user)
        _enable_onboarding()

    def test_monitor_get_requires_authentication(self):
        response = Client().get("/dispositivos/api/networks/")
        self.assertEqual(response.status_code, 302)

    @patch("dispositivos.services.obter_topologia")
    def test_monitor_get_returns_config(self, topology):
        topology.return_value = TOPOLOGY
        response = self.client.get("/dispositivos/api/networks/")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("monitor", payload)
        self.assertIn("enabled", payload["monitor"])
        self.assertIn("interval_minutes", payload["monitor"])
        self.assertIn("networks", payload["monitor"])

    def test_monitor_post_requires_authentication(self):
        response = Client().post("/dispositivos/api/monitor/", data='{"enabled":false,"interval_minutes":3,"networks":[]}', content_type="application/json")
        self.assertEqual(response.status_code, 302)

    def test_monitor_post_requires_csrf(self):
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.user)
        response = csrf_client.post("/dispositivos/api/monitor/", data='{"enabled":false,"interval_minutes":3,"networks":[]}', content_type="application/json")
        self.assertEqual(response.status_code, 403)

    @patch("dispositivos.monitoring.redes_elegiveis")
    def test_monitor_post_invalid_interval_rejected(self, elegiveis):
        elegiveis.return_value = []
        response = self.client.post("/dispositivos/api/monitor/", data='{"enabled":false,"interval_minutes":7,"networks":[]}', content_type="application/json")
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.json()["ok"])

    @patch("dispositivos.monitoring.redes_elegiveis")
    def test_monitor_post_invalid_network_id_rejected(self, elegiveis):
        elegiveis.return_value = [{"id": "lan:lan0", "monitor_allowed": True}]
        response = self.client.post("/dispositivos/api/monitor/", data='{"enabled":false,"interval_minutes":3,"networks":["lan:outside"]}', content_type="application/json")
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.json()["ok"])

    @patch("dispositivos.monitoring.redes_elegiveis")
    def test_monitor_post_enabled_without_networks_rejected(self, elegiveis):
        elegiveis.return_value = []
        response = self.client.post("/dispositivos/api/monitor/", data='{"enabled":true,"interval_minutes":3,"networks":[]}', content_type="application/json")
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.json()["ok"])

    @patch("dispositivos.monitoring.redes_elegiveis")
    def test_monitor_post_valid_config_saved(self, elegiveis):
        elegiveis.return_value = [{"id": "lan:lan0", "monitor_allowed": True}]
        RedeDiscovery.objects.get_or_create(network_id="lan:lan0", defaults={"role": "lan", "interface_name": "lan0", "cidr": "192.168.50.0/24"})
        response = self.client.post("/dispositivos/api/monitor/", data='{"enabled":true,"interval_minutes":5,"networks":["lan:lan0"]}', content_type="application/json")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["monitor"]["interval_minutes"], 5)
        self.assertTrue(payload["monitor"]["enabled"])
        self.assertIn("lan:lan0", payload["monitor"]["networks"])

    @patch("dispositivos.monitoring.redes_elegiveis")
    def test_monitor_post_extra_fields_rejected(self, elegiveis):
        elegiveis.return_value = []
        response = self.client.post("/dispositivos/api/monitor/", data='{"enabled":false,"interval_minutes":3,"networks":[],"extra":"hack"}', content_type="application/json")
        self.assertEqual(response.status_code, 400)


# ─────────────────────────────────────────────
# TESTES DE DISPONIBILIDADE — PROBE SEMÂNTICA
# ─────────────────────────────────────────────

class DisponibilidadeProbeTest(TestCase):
    """Testa _apply_probe diretamente, sem IPC real."""

    def _make_device(self, mac="AA:BB:CC:DD:EE:AA", ip="192.168.50.10"):
        return Dispositivo.objects.create(
            identity_key=f"mac:{mac}",
            identity_temporary=False,
            current_ip=ip,
            mac=mac,
            status=Dispositivo.Status.ONLINE,
            availability_failures=0,
            network_id="lan:lan0",
            network_cidr="192.168.50.0/24",
            interface_name="lan0",
        )

    def test_probe_positivo_mantem_online_e_zera_falhas(self):
        device = self._make_device()
        device.availability_failures = 2
        device.save(update_fields=["availability_failures"])
        now = timezone.now()
        _apply_probe(device, {"online": True}, now, 3)
        device.refresh_from_db()
        self.assertEqual(device.status, Dispositivo.Status.ONLINE)
        self.assertEqual(device.availability_failures, 0)

    def test_uma_falha_nao_marca_offline(self):
        device = self._make_device()
        now = timezone.now()
        _apply_probe(device, {"online": False}, now, 3)
        device.refresh_from_db()
        self.assertEqual(device.availability_failures, 1)
        self.assertNotEqual(device.status, Dispositivo.Status.OFFLINE)

    def test_duas_falhas_nao_marcam_offline(self):
        device = self._make_device()
        device.availability_failures = 1
        device.availability_checked_at = timezone.now()
        device.save(update_fields=["availability_failures", "availability_checked_at"])
        now = timezone.now()
        _apply_probe(device, {"online": False}, now, 3)
        device.refresh_from_db()
        self.assertEqual(device.availability_failures, 2)
        self.assertNotEqual(device.status, Dispositivo.Status.OFFLINE)

    def test_tres_falhas_marcam_offline(self):
        device = self._make_device()
        device.availability_failures = 2
        device.availability_checked_at = timezone.now()
        device.save(update_fields=["availability_failures", "availability_checked_at"])
        now = timezone.now()
        _apply_probe(device, {"online": False}, now, 3)
        device.refresh_from_db()
        self.assertEqual(device.availability_failures, 3)
        self.assertEqual(device.status, Dispositivo.Status.OFFLINE)

    def test_probe_positivo_apos_falhas_restaura_online(self):
        device = self._make_device()
        device.status = Dispositivo.Status.OFFLINE
        device.availability_failures = 3
        device.save(update_fields=["status", "availability_failures"])
        now = timezone.now()
        _apply_probe(device, {"online": True}, now, 3)
        device.refresh_from_db()
        self.assertEqual(device.status, Dispositivo.Status.ONLINE)
        self.assertEqual(device.availability_failures, 0)

    def test_probe_atualiza_mac_quando_dispositivo_temporario(self):
        device = Dispositivo.objects.create(
            identity_key="temporary:lan:lan0:192.168.50.20",
            identity_temporary=True,
            current_ip="192.168.50.20",
            status=Dispositivo.Status.ONLINE,
            network_id="lan:lan0",
            network_cidr="192.168.50.0/24",
            interface_name="lan0",
        )
        now = timezone.now()
        _apply_probe(device, {"online": True, "mac": "AA:BB:CC:DD:EE:BB"}, now, 3)
        device.refresh_from_db()
        self.assertEqual(device.mac, "AA:BB:CC:DD:EE:BB")
        self.assertFalse(device.identity_temporary)

    def test_mac_conflitante_nao_reutiliza_identidade(self):
        """MAC diferente do registrado: dispositivo fica stale, não offline."""
        device = self._make_device(mac="AA:BB:CC:DD:EE:CC")
        now = timezone.now()
        _apply_probe(device, {"online": True, "mac": "FF:FF:FF:FF:FF:FF"}, now, 3)
        device.refresh_from_db()
        self.assertEqual(device.status, Dispositivo.Status.STALE)
        self.assertNotEqual(device.status, Dispositivo.Status.OFFLINE)

    def test_falhas_antigas_sao_resetadas_em_ciclo_tardio(self):
        """Se não há verificação há muito tempo, falhas são resetadas antes de contar."""
        device = self._make_device()
        device.availability_failures = 2
        device.availability_checked_at = timezone.now() - timedelta(hours=2)
        device.save(update_fields=["availability_failures", "availability_checked_at"])
        now = timezone.now()
        _apply_probe(device, {"online": False}, now, 3)
        device.refresh_from_db()
        # Falhas antigas resetadas → +1 do ciclo atual
        self.assertEqual(device.availability_failures, 1)
        self.assertNotEqual(device.status, Dispositivo.Status.OFFLINE)


class MonitorOnceTest(TestCase):
    """Testa monitor_once: Agent failure não incrementa falhas."""

    def _make_device(self):
        return Dispositivo.objects.create(
            identity_key="mac:AA:BB:CC:DD:EE:DD",
            identity_temporary=False,
            current_ip="192.168.50.10",
            mac="AA:BB:CC:DD:EE:DD",
            status=Dispositivo.Status.ONLINE,
            availability_failures=0,
            network_id="lan:lan0",
            network_cidr="192.168.50.0/24",
            interface_name="lan0",
        )

    @patch("dispositivos.monitoring.redes_elegiveis")
    @patch("dispositivos.monitoring.requisitar_agent")
    def test_agent_failure_nao_incrementa_falhas(self, agent, elegiveis):
        """Falha de Agent durante probe não deve contar como verificação negativa."""
        RedeDiscovery.objects.get_or_create(
            network_id="lan:lan0",
            defaults={"role": "lan", "interface_name": "lan0", "cidr": "192.168.50.0/24", "monitored": True},
        )
        RedeDiscovery.objects.filter(network_id="lan:lan0").update(monitored=True)
        MonitorDispositivos.objects.get_or_create(pk=1, defaults={"enabled": True, "interval_minutes": 3})
        MonitorDispositivos.objects.filter(pk=1).update(enabled=True, last_attempt=None)
        elegiveis.return_value = [{"id": "lan:lan0", "role": "lan", "interface": "lan0", "cidr": "192.168.50.0/24", "monitored": True, "monitor_allowed": True}]
        device = self._make_device()
        # Agent lança exceção (timeout, socket inacessível, etc.)
        agent.side_effect = Exception("Agent inacessível")
        from dispositivos.monitoring import monitor_once
        result = monitor_once()
        device.refresh_from_db()
        # Falhas não devem ter aumentado
        self.assertEqual(device.availability_failures, 0)
        self.assertEqual(device.status, Dispositivo.Status.ONLINE)
        # Erro registrado no resultado, não no dispositivo
        self.assertIn("lan:lan0", result.get("errors", {}))

    @patch("dispositivos.monitoring.redes_elegiveis")
    @patch("dispositivos.monitoring.requisitar_agent")
    def test_monitor_skipped_when_interval_not_elapsed(self, agent, elegiveis):
        """Monitor não executa se intervalo ainda não passou."""
        MonitorDispositivos.objects.get_or_create(pk=1, defaults={"enabled": True, "interval_minutes": 3})
        MonitorDispositivos.objects.filter(pk=1).update(enabled=True, last_attempt=timezone.now())
        from dispositivos.monitoring import monitor_once
        result = monitor_once()
        self.assertEqual(result.get("skipped"), "interval")
        agent.assert_not_called()

    @patch("dispositivos.monitoring.redes_elegiveis")
    def test_monitor_skipped_when_disabled(self, elegiveis):
        MonitorDispositivos.objects.get_or_create(pk=1, defaults={"enabled": False, "interval_minutes": 3})
        MonitorDispositivos.objects.filter(pk=1).update(enabled=False, last_attempt=None)
        from dispositivos.monitoring import monitor_once
        result = monitor_once()
        self.assertEqual(result.get("skipped"), "disabled")
class ClassificationHeuristicTests(TestCase):
    def test_workstation_heuristic_with_windows_and_445(self):
        from dispositivos.services import _classificar
        # Dispositivo sem tipo (desconhecido), Windows provável como os_guess, e porta 445 aberta
        device = {'ip': '192.168.1.10', 'hostname': 'UnknownHost', 'vendor': 'Micro-Star Intl', 'open_ports': [445, 139]}
        target = {'gateway': '192.168.1.1'}
        device_type, os_guess, icon, conf = _classificar(device, target, inferred_os="Windows provável")
        self.assertEqual(device_type, "Computador provável")
        self.assertEqual(os_guess, "Windows provável")

    def test_gateway_heuristic(self):
        from dispositivos.services import _classificar
        device = {'ip': '192.168.1.1', 'hostname': 'router', 'vendor': 'Cisco'}
        target = {'gateway': '192.168.1.1'}
        device_type, os_guess, icon, conf = _classificar(device, target)
        self.assertEqual(device_type, "Gateway")

    def test_server_heuristic(self):
        from dispositivos.services import _classificar
        device = {'ip': '192.168.1.20', 'hostname': 'srv-app', 'vendor': 'Dell', 'open_ports': [22, 80, 443]}
        target = {'gateway': '192.168.1.1'}
        device_type, os_guess, icon, conf = _classificar(device, target, inferred_os="Linux provável")
        self.assertEqual(device_type, "Servidor")

    def test_unknown_remains_unknown_if_no_evidence(self):
        from dispositivos.services import _classificar
        device = {'ip': '192.168.1.30', 'hostname': '', 'vendor': 'Generic', 'open_ports': []}
        target = {'gateway': '192.168.1.1'}
        device_type, os_guess, icon, conf = _classificar(device, target, inferred_os="Windows provável")
        self.assertEqual(device_type, "Desconhecido")
