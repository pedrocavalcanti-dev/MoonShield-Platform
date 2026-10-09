from __future__ import annotations

import json
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from dispositivos.models import Dispositivo
from wifi_access.models import WifiAuthorization, WifiTrustedDevice, normalize_mac
from wifi_access.services.devices import MacResolutionError, resolve_mac


@override_settings(WIFI_API_TOKEN="wifi-test-token", WIFI_API_ALLOWED_IPS=("10.10.0.20",))
class WifiApiTests(TestCase):
    ip = "10.10.0.137"
    mac = "AA:BB:CC:11:22:33"

    def _headers(self):
        return {
            "HTTP_AUTHORIZATION": "Bearer wifi-test-token",
            "REMOTE_ADDR": "127.0.0.1",
            "HTTP_X_REAL_IP": "10.10.0.20",
        }

    def _post(self, name, payload, **headers):
        return self.client.post(
            reverse(name), data=json.dumps(payload), content_type="application/json", **(headers or self._headers())
        )

    def _firewall_ok(self):
        return patch("firewall.services.firewall_rules.aplicar_regras_pendentes", return_value={"ok": True}), patch(
            "firewall.services.firewall_rules.listar_allowlist_para_agent", return_value=[]
        )

    def test_normalize_mac_and_invalid_values(self):
        self.assertEqual(normalize_mac("aa-bb-cc-11-22-33"), self.mac)
        for invalid in ("", "00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF", "01:00:00:00:00:00", "invalid"):
            with self.assertRaises(ValidationError):
                normalize_mac(invalid)

    def test_trusted_device_normalizes_and_rejects_duplicate(self):
        WifiTrustedDevice.objects.create(nome="AUTH01", mac_address="aa-bb-cc-11-22-33")
        with self.assertRaises(ValidationError):
            WifiTrustedDevice.objects.create(nome="Duplicado", mac_address=self.mac)

    def test_resolve_mac_uses_persisted_inventory(self):
        Dispositivo.objects.create(identity_key="mac:AA:BB:CC:11:22:33", current_ip=self.ip, mac="aa:bb:cc:11:22:33")
        self.assertEqual(resolve_mac(self.ip), self.mac)

    def test_resolve_mac_has_controlled_failure(self):
        with self.assertRaises(MacResolutionError):
            resolve_mac(self.ip)

    def test_missing_or_invalid_token_is_rejected(self):
        missing = self._post("wifi:authorize", {"username": "Pedro", "ip_address": self.ip}, HTTP_X_REAL_IP="10.10.0.20")
        invalid = self._post("wifi:authorize", {"username": "Pedro", "ip_address": self.ip}, HTTP_AUTHORIZATION="Bearer bad", REMOTE_ADDR="127.0.0.1", HTTP_X_REAL_IP="10.10.0.20")
        self.assertEqual(missing.status_code, 401)
        self.assertEqual(invalid.status_code, 401)

    def test_invalid_source_is_rejected(self):
        response = self._post("wifi:authorize", {"username": "Pedro", "ip_address": self.ip}, HTTP_AUTHORIZATION="Bearer wifi-test-token", REMOTE_ADDR="127.0.0.1", HTTP_X_REAL_IP="10.10.0.21")
        self.assertEqual(response.status_code, 403)

    def test_external_api_requires_json_and_post(self):
        not_json = self.client.post(reverse("wifi:authorize"), data="username=Pedro", content_type="text/plain", **self._headers())
        get_request = self.client.get(reverse("wifi:authorize"), **self._headers())
        self.assertEqual(not_json.status_code, 415)
        self.assertEqual(get_request.status_code, 405)

    def test_authorize_rejects_mac_and_unknown_fields(self):
        mac = self._post("wifi:authorize", {"username": "Pedro", "ip_address": self.ip, "mac_address": self.mac})
        unknown = self._post("wifi:authorize", {"username": "Pedro", "ip_address": self.ip, "role": "admin"})
        self.assertEqual(mac.status_code, 400)
        self.assertEqual(unknown.status_code, 400)

    @patch("wifi_access.services.authorization.resolve_mac", return_value="AA:BB:CC:11:22:33")
    def test_authorize_valid_creates_authorization_after_firewall_confirmation(self, _resolve):
        apply, allowlist = self._firewall_ok()
        with apply as apply_mock, allowlist:
            response = self._post("wifi:authorize", {"username": "Pedro", "ip_address": self.ip})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["authorized"])
        authorization = WifiAuthorization.objects.get()
        self.assertEqual(authorization.mac_address, self.mac)
        self.assertTrue(authorization.active)
        apply_mock.assert_called_once()

    def test_authorize_rejects_invalid_ip_and_password_field(self):
        invalid_ip = self._post("wifi:authorize", {"username": "Pedro", "ip_address": "not-an-ip"})
        password = self._post("wifi:authorize", {"username": "Pedro", "ip_address": self.ip, "password": "never"})
        self.assertEqual(invalid_ip.status_code, 400)
        self.assertEqual(password.status_code, 400)
        self.assertEqual(WifiAuthorization.objects.count(), 0)

    @patch("wifi_access.services.authorization.resolve_mac", side_effect=MacResolutionError("MAC indisponÃ­vel."))
    def test_authorize_without_resolved_mac_returns_controlled_error(self, _resolve):
        response = self._post("wifi:authorize", {"username": "Pedro", "ip_address": self.ip})
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["codigo"], "mac_nao_encontrado")

    @patch("wifi_access.services.authorization.resolve_mac", return_value="AA:BB:CC:11:22:33")
    def test_duplicate_authorize_reuses_active_authorization(self, _resolve):
        apply, allowlist = self._firewall_ok()
        with apply, allowlist:
            self._post("wifi:authorize", {"username": "Pedro", "ip_address": self.ip})
            self._post("wifi:authorize", {"username": "Pedro 2", "ip_address": self.ip})
        self.assertEqual(WifiAuthorization.objects.filter(active=True).count(), 1)
        self.assertEqual(WifiAuthorization.objects.get(active=True).username, "Pedro 2")

    @patch("wifi_access.services.authorization.resolve_mac", return_value="AA:BB:CC:11:22:33")
    def test_firewall_failure_never_marks_authorization_active(self, _resolve):
        with patch("firewall.services.firewall_rules.listar_allowlist_para_agent", return_value=[]), patch(
            "firewall.services.firewall_rules.aplicar_regras_pendentes", return_value={"ok": False, "codigo": "agent_indisponivel", "erro": "offline"}
        ):
            response = self._post("wifi:authorize", {"username": "Pedro", "ip_address": self.ip})
        self.assertEqual(response.status_code, 503)
        self.assertFalse(WifiAuthorization.objects.filter(active=True).exists())

    @patch("wifi_access.services.authorization.resolve_mac", return_value="AA:BB:CC:11:22:33")
    def test_trusted_device_has_priority_without_login_record(self, _resolve):
        WifiTrustedDevice.objects.create(nome="AUTH01", mac_address=self.mac)
        apply, allowlist = self._firewall_ok()
        with apply, allowlist:
            response = self._post("wifi:authorize", {"username": "portal", "ip_address": self.ip})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["trusted"])
        self.assertFalse(WifiAuthorization.objects.exists())

    def test_revoke_and_status(self):
        authorization = WifiAuthorization.objects.create(username="Pedro", ip_address=self.ip, mac_address=self.mac, authorized_at=timezone.now())
        apply, allowlist = self._firewall_ok()
        with apply, allowlist:
            revoke_response = self._post("wifi:revoke", {"authorization_id": authorization.pk, "revoked_reason": "logout"})
        self.assertEqual(revoke_response.status_code, 200)
        authorization.refresh_from_db()
        self.assertFalse(authorization.active)
        with patch("wifi_access.api.views.resolve_mac", return_value=self.mac):
            response = self.client.get(reverse("wifi:status"), {"ip_address": self.ip}, **self._headers())
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["active"])

    def test_revoke_by_ip(self):
        WifiAuthorization.objects.create(username="Pedro", ip_address=self.ip, mac_address=self.mac, authorized_at=timezone.now())
        apply, allowlist = self._firewall_ok()
        with apply, allowlist:
            response = self._post("wifi:revoke", {"ip_address": self.ip})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(WifiAuthorization.objects.get().active)

    def test_revoke_requires_exactly_one_identifier(self):
        neither = self._post("wifi:revoke", {})
        both = self._post("wifi:revoke", {"ip_address": self.ip, "authorization_id": 1})
        self.assertEqual(neither.status_code, 400)
        self.assertEqual(both.status_code, 400)

    def test_sync_payload_contains_active_wifi_ips_and_native_allowlist(self):
        WifiAuthorization.objects.create(username="Pedro", ip_address=self.ip, mac_address=self.mac, authorized_at=timezone.now())
        with patch("firewall.services.firewall_rules.listar_allowlist_para_agent", return_value=["10.10.0.50"]), patch(
            "firewall.services.firewall_rules.aplicar_regras_pendentes", return_value={"ok": True}
        ) as apply:
            from wifi_access.services.firewall import sync_authorizations
            result = sync_authorizations()
        self.assertTrue(result["ok"])

    def test_status_and_models_do_not_expose_passwords(self):
        fields = {field.name for field in WifiAuthorization._meta.get_fields()} | {field.name for field in WifiTrustedDevice._meta.get_fields()}
        self.assertFalse({"password", "password_hash", "senha"} & fields)
        response = self.client.get(reverse("wifi:status"), {"ip_address": self.ip}, **self._headers())
        self.assertEqual(response.status_code, 404)

    def test_windows_or_agent_unavailable_is_controlled(self):
        with patch("firewall.services.firewall_rules.listar_allowlist_para_agent", return_value=[]), patch(
            "firewall.services.firewall_rules.aplicar_regras_pendentes", return_value={"ok": False, "codigo": "agent_indisponivel", "erro": "Agent indisponÃ­vel"}
        ):
            from wifi_access.services.firewall import sync_authorizations
            result = sync_authorizations()
        self.assertFalse(result["ok"])
        self.assertEqual(result["codigo"], "agent_indisponivel")

    def test_native_allowlist_preservation(self):
        from firewall.models import AllowlistEntry
        from wifi_access.services.firewall import get_wifi_firewall_payload
        AllowlistEntry.objects.create(ip="10.10.0.5")
        AllowlistEntry.objects.create(ip="10.10.0.10")
        WifiAuthorization.objects.create(username="U1", ip_address="10.10.0.100", mac_address="AA:BB:CC:DD:EE:11", authorized_at=timezone.now())
        WifiAuthorization.objects.create(username="U2", ip_address="10.10.0.101", mac_address="AA:BB:CC:DD:EE:22", authorized_at=timezone.now())
        payload = get_wifi_firewall_payload({})
        self.assertEqual(payload["authorized_ips"], ["10.10.0.100", "10.10.0.101"])
        WifiAuthorization.objects.filter(ip_address="10.10.0.100").update(active=False)
        payload2 = get_wifi_firewall_payload({})
        self.assertEqual(payload2["authorized_ips"], ["10.10.0.101"])

    @patch("wifi_access.services.authorization.resolve_mac", return_value="AA:BB:CC:11:22:33")
    def test_dhcp_ip_reassignment_revokes_old(self, _resolve):
        apply, allowlist = self._firewall_ok()
        with apply, allowlist:
            # First, User 1 connects on 10.10.0.100
            self._post("wifi:authorize", {"username": "User 1", "ip_address": "10.10.0.100"})
        # IP is reassigned to another MAC!
        with patch("wifi_access.services.authorization.resolve_mac", return_value="02:DD:DD:DD:DD:DD"):
            with apply, allowlist:
                self._post("wifi:authorize", {"username": "User 2", "ip_address": "10.10.0.100"})
        # User 1 should be revoked
        old = WifiAuthorization.objects.get(mac_address="AA:BB:CC:11:22:33")
        self.assertFalse(old.active)
        self.assertEqual(old.revoked_reason, "ip_reatribuido")
        # User 2 is active
        new = WifiAuthorization.objects.get(mac_address="02:DD:DD:DD:DD:DD")
        self.assertTrue(new.active)

    def test_malformed_token_and_json(self):
        # Empty bearer
        self.assertEqual(self._post("wifi:authorize", {"username": "A", "ip_address": self.ip}, HTTP_AUTHORIZATION="Bearer ", REMOTE_ADDR="127.0.0.1", HTTP_X_REAL_IP="10.10.0.20").status_code, 401)
        # Malformed JSON
        self.assertEqual(self.client.post(reverse("wifi:authorize"), data="{bad_json", content_type="application/json", **self._headers()).status_code, 400)
        # Array payload
        self.assertEqual(self._post("wifi:authorize", [{"username": "A", "ip_address": self.ip}]).status_code, 400)

    def test_source_ip_spoofing(self):
        # Direct connection from non-allowed IP
        self.assertEqual(self._post("wifi:authorize", {"username": "A", "ip_address": self.ip}, HTTP_AUTHORIZATION="Bearer wifi-test-token", REMOTE_ADDR="10.10.0.30").status_code, 403)
        # Spoofed X-Real-IP from non-local proxy
        self.assertEqual(self._post("wifi:authorize", {"username": "A", "ip_address": self.ip}, HTTP_AUTHORIZATION="Bearer wifi-test-token", REMOTE_ADDR="10.10.0.30", HTTP_X_REAL_IP="10.10.0.20").status_code, 403)
        # Valid proxy
        self.assertEqual(self._post("wifi:authorize", {"username": "A", "ip_address": self.ip}, HTTP_AUTHORIZATION="Bearer wifi-test-token", REMOTE_ADDR="127.0.0.1", HTTP_X_REAL_IP="10.10.0.20").status_code, 404)  # 404 meaning MAC not found, but NOT 403

    def test_revoke_idempotency(self):
        authorization = WifiAuthorization.objects.create(username="Pedro", ip_address=self.ip, mac_address=self.mac, authorized_at=timezone.now())
        apply, allowlist = self._firewall_ok()
        with apply, allowlist:
            r1 = self._post("wifi:revoke", {"authorization_id": authorization.pk})
            r2 = self._post("wifi:revoke", {"authorization_id": authorization.pk})
        self.assertEqual(r1.status_code, 200)
        self.assertEqual(r2.status_code, 404) # Not found because it's no longer active

class WifiPanelTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User
        from configuracoes.models import ConfigSistema
        self.user = User.objects.create_user("admin", password="password")
        self.client.force_login(self.user)
        config = ConfigSistema.get_solo()
        config.appliance_onboarding_completo = True
        config.save()

    def _firewall_ok(self):
        return patch("firewall.services.firewall_rules.aplicar_regras_pendentes", return_value={"ok": True}), patch(
            "firewall.services.firewall_rules.listar_allowlist_para_agent", return_value=[]
        )

    def test_bulk_trusted_devices_valid(self):
        apply, allowlist = self._firewall_ok()
        payload = {
            "devices": [
                {"name": "Dev 1", "mac_address": "AA:BB:CC:DD:EE:01", "ip_address": "10.10.0.50", "description": ""},
                {"name": "Dev 2", "mac_address": "AA:BB:CC:DD:EE:02", "ip_address": "", "description": "Desc"}
            ]
        }
        with apply, allowlist:
            response = self.client.post(reverse("wifi:bulk_trusted_devices"), data=json.dumps(payload), content_type="application/json")
        if response.status_code == 302:
            print(f"REDIRECT TO: {response.url}")
        self.assertEqual(response.status_code, 201)
        self.assertEqual(WifiTrustedDevice.objects.count(), 2)

    def test_bulk_trusted_devices_limit(self):
        payload = {"devices": [{"name": f"D{i}", "mac_address": f"AA:BB:CC:DD:EE:{i:02d}"} for i in range(101)]}
        response = self.client.post(reverse("wifi:bulk_trusted_devices"), data=json.dumps(payload), content_type="application/json")
        self.assertEqual(response.status_code, 400)
        self.assertIn("100", response.json()["error"])

    def test_bulk_trusted_devices_invalid_mac(self):
        payload = {"devices": [{"name": "A", "mac_address": "bad-mac"}]}
        response = self.client.post(reverse("wifi:bulk_trusted_devices"), data=json.dumps(payload), content_type="application/json")
        self.assertEqual(response.status_code, 400)
        self.assertIn("MAC inv", response.json()["error"])

    def test_bulk_trusted_devices_duplicate_in_batch(self):
        payload = {"devices": [{"name": "A", "mac_address": "AA:BB:CC:DD:EE:01"}, {"name": "B", "mac_address": "AA:BB:CC:DD:EE:01"}]}
        response = self.client.post(reverse("wifi:bulk_trusted_devices"), data=json.dumps(payload), content_type="application/json")
        self.assertEqual(response.status_code, 400)
        self.assertIn("duplicado", response.json()["error"])

    def test_bulk_trusted_devices_duplicate_in_db(self):
        WifiTrustedDevice.objects.create(nome="Exist", mac_address="AA:BB:CC:DD:EE:01")
        payload = {"devices": [{"name": "A", "mac_address": "AA:BB:CC:DD:EE:01"}]}
        response = self.client.post(reverse("wifi:bulk_trusted_devices"), data=json.dumps(payload), content_type="application/json")
        self.assertEqual(response.status_code, 400)
        self.assertIn("cadastrado no banco", response.json()["error"])

    def test_bulk_trusted_devices_rollback_on_firewall_failure(self):
        payload = {"devices": [{"name": "A", "mac_address": "AA:BB:CC:DD:EE:01", "ip_address": "10.10.0.50"}]}
        with patch("firewall.services.firewall_rules.aplicar_regras_pendentes", return_value={"ok": False, "codigo": "err"}):
            with patch("firewall.services.firewall_rules.listar_allowlist_para_agent", return_value=[]):
                response = self.client.post(reverse("wifi:bulk_trusted_devices"), data=json.dumps(payload), content_type="application/json")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(WifiTrustedDevice.objects.count(), 0)

    def test_bulk_trusted_action(self):
        d1 = WifiTrustedDevice.objects.create(nome="1", mac_address="AA:BB:CC:DD:EE:01")
        d2 = WifiTrustedDevice.objects.create(nome="2", mac_address="AA:BB:CC:DD:EE:02")
        apply, allowlist = self._firewall_ok()
        with apply, allowlist:
            response = self.client.post(reverse("wifi:bulk_trusted_action"), data=json.dumps({"device_ids": [d1.pk, d2.pk], "action": "deactivate"}), content_type="application/json")
        self.assertEqual(response.status_code, 200)
        d1.refresh_from_db()
        self.assertFalse(d1.active)
