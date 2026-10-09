from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta

from dispositivos.models import Dispositivo
from wifi_access.models import WifiAuthorization, WifiTrustedDevice
from wifi_access.services.reconciliation import reconcile_wifi_access, build_mac_to_ip_map


@override_settings(WIFI_API_TOKEN="wifi-test-token", WIFI_API_ALLOWED_IPS=("10.10.0.20",))
class WifiReconciliationTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User
        from configuracoes.models import ConfigSistema
        self.user = User.objects.create_user("admin", password="password", is_staff=True)
        self.client.force_login(self.user)
        config = ConfigSistema.get_solo()
        config.appliance_onboarding_completo = True
        config.save()

    def _firewall_ok(self):
        return patch("wifi_access.services.reconciliation.apply_or_raise", return_value={"ok": True})

    def _agent_neighbors(self, neighbors):
        return patch("wifi_access.services.reconciliation.agent_neighbors", return_value=neighbors)

    def test_build_mac_to_ip_map(self):
        Dispositivo.objects.create(identity_key="mac:AA:BB:CC:11:22:33", mac="AA:BB:CC:11:22:33", current_ip="10.10.0.50", status=Dispositivo.Status.ONLINE)
        Dispositivo.objects.create(identity_key="mac:AA:BB:CC:44:55:66", mac="AA:BB:CC:44:55:66", current_ip="10.10.0.51", status=Dispositivo.Status.STALE) # unreliable

        # Neighbours override inventory
        neighbors = [
            {"lladdr": "AA:BB:CC:11:22:33", "dst": "10.10.0.60", "state": "REACHABLE"},
            {"lladdr": "AA:BB:CC:99:99:99", "dst": "10.10.0.99", "state": "REACHABLE"}
        ]
        with self._agent_neighbors(neighbors):
            mapping = build_mac_to_ip_map()

        self.assertEqual(mapping.get("AA:BB:CC:11:22:33"), "10.10.0.60")
        self.assertEqual(mapping.get("AA:BB:CC:99:99:99"), "10.10.0.99")
        self.assertNotIn("AA:BB:CC:44:55:66", mapping)

    def test_expire_sessions(self):
        now = timezone.now()
        WifiAuthorization.objects.create(username="U1", mac_address="AA:BB:CC:11:22:33", ip_address="10.10.0.50", authorized_at=now, expires_at=now - timedelta(minutes=1))
        WifiAuthorization.objects.create(username="U2", mac_address="AA:BB:CC:22:33:44", ip_address="10.10.0.51", authorized_at=now, expires_at=now + timedelta(minutes=10))

        with self._firewall_ok(), self._agent_neighbors([]):
            result = reconcile_wifi_access()

        self.assertTrue(result["ok"])
        self.assertFalse(WifiAuthorization.objects.get(username="U1").active)
        self.assertTrue(WifiAuthorization.objects.get(username="U2").active)

    def test_mac_troca_ip(self):
        now = timezone.now()
        auth = WifiAuthorization.objects.create(username="U1", mac_address="AA:BB:CC:11:22:33", ip_address="10.10.0.50", authorized_at=now)

        neighbors = [{"lladdr": "AA:BB:CC:11:22:33", "dst": "10.10.0.90", "state": "REACHABLE"}]
        with self._firewall_ok(), self._agent_neighbors(neighbors):
            reconcile_wifi_access()

        auth.refresh_from_db()
        self.assertEqual(auth.ip_address, "10.10.0.90")
        self.assertTrue(auth.active)

    def test_trusted_muda_ip(self):
        device = WifiTrustedDevice.objects.create(nome="Device 1", mac_address="AA:BB:CC:11:22:33", ip_address="10.10.0.50")
        neighbors = [{"lladdr": "AA:BB:CC:11:22:33", "dst": "10.10.0.90", "state": "REACHABLE"}]
        with self._firewall_ok(), self._agent_neighbors(neighbors):
            reconcile_wifi_access()

        device.refresh_from_db()
        self.assertEqual(device.ip_address, "10.10.0.90")

    def test_ip_reutilizado(self):
        now = timezone.now()
        # U1 has .50, older. U2 has .50, newer.
        WifiAuthorization.objects.create(username="U1", mac_address="AA:BB:CC:11:22:33", ip_address="10.10.0.50", authorized_at=now - timedelta(hours=1))
        WifiAuthorization.objects.create(username="U2", mac_address="AA:BB:CC:44:55:66", ip_address="10.10.0.50", authorized_at=now)

        with self._firewall_ok(), self._agent_neighbors([]):
            reconcile_wifi_access()

        u1 = WifiAuthorization.objects.get(username="U1")
        u2 = WifiAuthorization.objects.get(username="U2")

        self.assertFalse(u1.active)
        self.assertEqual(u1.revoked_reason, "ip_reatribuido")
        self.assertTrue(u2.active)

    def test_dry_run(self):
        now = timezone.now()
        WifiAuthorization.objects.create(username="U1", mac_address="AA:BB:CC:11:22:33", ip_address="10.10.0.50", authorized_at=now, expires_at=now - timedelta(minutes=1))

        with self._firewall_ok(), self._agent_neighbors([]):
            result = reconcile_wifi_access(dry_run=True)

        self.assertTrue(result["dry_run"])
        self.assertTrue(WifiAuthorization.objects.get(username="U1").active) # NÃ£o mudou o banco!

    def test_sync_now_endpoint_requires_staff(self):
        # Admin is staff in setUp
        with self._firewall_ok(), self._agent_neighbors([]):
            response = self.client.post(reverse("wifi:sync_now"))
        self.assertEqual(response.status_code, 200)

        # Non-staff
        from django.contrib.auth.models import User
        u2 = User.objects.create_user("normal", password="password", is_staff=False)
        self.client.force_login(u2)
        response2 = self.client.post(reverse("wifi:sync_now"))
        self.assertEqual(response2.status_code, 403)
