"""Testes puros do enforcement de precedencia e allowlist do Firewall."""

import unittest
from unittest.mock import patch

from firewall.nucleo import aplicador, instalador


class _ContextoMinimo:
    def iface_map(self):
        return {}


class FirewallPolicyAllowlistTests(unittest.TestCase):
    def test_allowlist_normaliza_e_remove_duplicatas(self):
        resultado = aplicador._normalizar_allowlist([
            "192.168.52.10",
            "192.168.52.10/32",
            "2001:db8::1",
            {"ip": "192.168.52.0/24"},
        ])

        self.assertEqual(
            resultado["ipv4"],
            ["192.168.52.0/24", "192.168.52.10/32"],
        )
        self.assertEqual(resultado["ipv6"], ["2001:db8::1/128"])

    def test_allowlist_rejeita_payload_inseguro_e_redes_globais(self):
        for entrada in (
            "192.168.52.10; flush ruleset",
            'teste"; flush ruleset; #',
            "0.0.0.0/0",
            "::/0",
            "127.0.0.1",
            "224.0.0.1",
        ):
            with self.subTest(entrada=entrada):
                with self.assertRaises(ValueError):
                    aplicador._normalizar_allowlist([entrada])

    def test_allowlist_rejeita_gateway_e_ip_administrativo(self):
        contexto = _ContextoMinimo()
        contexto.gateway = "10.53.52.1"
        contexto.ips_gerenciamento = ["192.168.52.1"]

        for entrada in ("10.53.52.1", "192.168.52.0/24"):
            with self.subTest(entrada=entrada):
                with self.assertRaises(ValueError):
                    aplicador._normalizar_allowlist([entrada], contexto=contexto)

    @patch("firewall.nucleo.aplicador.gerar_regras_sistema", return_value=[])
    @patch("firewall.nucleo.aplicador.tabela_existe", return_value=False)
    def test_precedencia_emergency_allowlist_regras_conntrack(
        self,
        _tabela_existe,
        _regras_sistema,
    ):
        script = aplicador._gerar_script(
            regras=[],
            allowlist=aplicador._normalizar_allowlist(["192.168.52.10"]),
            contexto=_ContextoMinimo(),
        )

        forward = script.split("chain ms_forward", 1)[1].split("}", 1)[0]
        self.assertLess(forward.index("jump ms_emergency"), forward.index("jump ms_allowlist"))
        self.assertLess(forward.index("jump ms_allowlist"), forward.index("jump ms_rules_forward"))
        self.assertLess(forward.index("jump ms_rules_forward"), forward.index("ct state established,related accept"))
        self.assertIn("set ms_allow_ipv4", script)
        self.assertIn("elements = { 192.168.52.10/32 }", script)
        self.assertNotIn("flush ruleset", script)
        self.assertNotIn("conntrack -F", script)

    @patch("firewall.nucleo.instalador.gerar_regras_sistema", return_value=[])
    @patch("firewall.nucleo.instalador.tabela_existe", return_value=False)
    @patch("firewall.nucleo.instalador.carregar_allowlist_cache")
    def test_base_de_restore_contem_allowlist_e_precedencia(
        self,
        cache,
        _tabela_existe,
        _regras_sistema,
    ):
        cache.return_value = {
            "ipv4": ["192.168.52.10/32"],
            "ipv6": [],
        }
        script = instalador._gerar_base(_ContextoMinimo())
        forward = script.split("chain ms_forward", 1)[1].split("}", 1)[0]

        self.assertIn("set ms_allow_ipv4", script)
        self.assertIn("set ms_allow_ipv6", script)
        self.assertIn("chain ms_allowlist", script)
        self.assertIn("elements = { 192.168.52.10/32 }", script)
        self.assertLess(forward.index("jump ms_emergency"), forward.index("jump ms_allowlist"))
        self.assertNotIn("flush ruleset", script)

