"""Testes unitários do isolamento entre MASQUERADE e Port Forward."""

from __future__ import annotations

import unittest

from rede.nucleo import nat


class RegrasNatRulesetTests(unittest.TestCase):
    def setUp(self):
        self.regra = {
            "id": "1",
            "interface_origem": "lan-teste",
            "interface_saida": "wan-teste",
            "rede_origem": "192.168.52.0/24",
            "ativa": True,
            "prioridade": 100,
        }

    def test_masquerade_cria_tabela_e_postrouting_quando_runtime_ausente(self):
        script = nat._gerar_ruleset_masquerade(
            [self.regra],
            tabela_existente=False,
            postrouting_existe=False,
        )

        self.assertIn("add table ip moonshield_nat", script)
        self.assertIn("add chain ip moonshield_nat postrouting", script)
        self.assertIn('iifname "lan-teste" oifname "wan-teste"', script)
        self.assertIn("ip saddr 192.168.52.0/24 masquerade", script)

    def test_reaplicar_masquerade_preserva_prerouting_port_forward(self):
        script = nat._gerar_ruleset_masquerade(
            [self.regra],
            tabela_existente=True,
            postrouting_existe=True,
        )

        self.assertIn("flush chain ip moonshield_nat postrouting", script)
        self.assertNotIn("delete table ip moonshield_nat", script)
        self.assertNotIn("prerouting", script)

    def test_remover_masquerade_nao_remove_tabela_que_pode_conter_dnat(self):
        script = nat._gerar_ruleset_masquerade(
            [],
            tabela_existente=True,
            postrouting_existe=True,
        )

        self.assertEqual(script, "flush chain ip moonshield_nat postrouting\n")
        self.assertNotIn("delete table", script)


if __name__ == "__main__":
    unittest.main()
