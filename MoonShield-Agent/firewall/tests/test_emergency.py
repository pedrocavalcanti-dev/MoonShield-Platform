import unittest
from types import SimpleNamespace
from unittest.mock import patch

from firewall.nucleo import aplicador


class EmergencyBlockTests(unittest.TestCase):
    def _run_ok(self, *args, **kwargs):
        return SimpleNamespace(returncode=0, stderr="", stdout="")

    @patch("firewall.nucleo.aplicador.existe_alteracao_pendente", return_value=False)
    @patch("firewall.nucleo.aplicador.tabela_existe", return_value=True)
    @patch("firewall.nucleo.aplicador.shutil.which", return_value="/usr/sbin/nft")
    @patch("firewall.nucleo.aplicador.subprocess.run")
    def test_motivo_nunca_compoe_expressao_nft(
        self,
        run,
        _which,
        _tabela,
        _pendente,
    ):
        run.side_effect = self._run_ok
        motivos = [
            "simples",
            "com espacos",
            "com-hifen",
            'com "aspas"',
            "caracteres !@#$%^&*()",
            'teste"; flush ruleset; #',
        ]

        for motivo in motivos:
            resultado = aplicador.bloquear_ip(
                {"ip": "192.168.52.2", "motivo": motivo}
            )

            self.assertTrue(resultado["ok"])
            self.assertEqual(resultado["motivo"], motivo)
            args = run.call_args[0][0]
            self.assertNotIn(motivo, args)
            self.assertNotIn("flush ruleset", args)
            self.assertRegex(
                args[-1],
                r'^"moonshield-emergency:[0-9a-f]{20}"$',
            )

    @patch("firewall.nucleo.aplicador.existe_alteracao_pendente", return_value=False)
    @patch("firewall.nucleo.aplicador.tabela_existe", return_value=True)
    @patch("firewall.nucleo.aplicador.shutil.which", return_value="/usr/sbin/nft")
    @patch("firewall.nucleo.aplicador.subprocess.run")
    def test_aceita_ipv4_e_cidr_normalizados(
        self,
        run,
        _which,
        _tabela,
        _pendente,
    ):
        run.side_effect = self._run_ok

        host = aplicador.bloquear_ip({"ip": "192.168.52.2"})
        host_args = run.call_args[0][0]
        rede = aplicador.bloquear_ip({"ip": "192.168.52.0/24"})
        rede_args = run.call_args[0][0]

        self.assertEqual(host["ip"], "192.168.52.2")
        self.assertEqual(rede["ip"], "192.168.52.0/24")
        self.assertEqual(host_args[host_args.index("saddr") + 1], "192.168.52.2")
        self.assertEqual(rede_args[rede_args.index("saddr") + 1], "192.168.52.0/24")

    @patch("firewall.nucleo.aplicador.existe_alteracao_pendente", return_value=False)
    @patch("firewall.nucleo.aplicador.shutil.which", return_value="/usr/sbin/nft")
    @patch("firewall.nucleo.aplicador.subprocess.run")
    def test_unblock_remove_regra_com_marcador_controlado(
        self,
        run,
        _which,
        _pendente,
    ):
        comentario = aplicador._comentario_emergency("192.168.52.2", "ip")
        run.side_effect = [
            SimpleNamespace(
                returncode=0,
                stderr="",
                stdout=(
                    f'ip saddr 192.168.52.2 counter drop '
                    f'comment "{comentario}" # handle 42\n'
                ),
            ),
            SimpleNamespace(returncode=0, stderr="", stdout=""),
        ]

        resultado = aplicador.liberar_ip({"ip": "192.168.52.2"})

        self.assertTrue(resultado["ok"])
        self.assertEqual(resultado["removidos"], 1)
        delete_args = run.call_args_list[1][0][0]
        self.assertEqual(delete_args[-2:], ["handle", "42"])

