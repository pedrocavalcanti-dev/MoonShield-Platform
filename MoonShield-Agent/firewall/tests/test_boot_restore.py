import unittest
from unittest.mock import patch, MagicMock
import sys

# Mock grp e UnixStreamServer para testes no Windows
sys.modules['grp'] = MagicMock()
import socketserver
import socket
if not hasattr(socketserver, 'UnixStreamServer'):
    socketserver.UnixStreamServer = type('UnixStreamServer', (object,), {})
if not hasattr(socket, 'AF_UNIX'):
    socket.AF_UNIX = getattr(socket, 'AF_INET', 2)

# The function to test
from firewall.ipc.servidor import _inicializar_firewall
from firewall.nucleo.analisador import parsear_linha

class TestFirewallBootRestore(unittest.TestCase):
    @patch("firewall.nucleo.rollback.inicializar_rollback_pendente")
    @patch("firewall.nucleo.status.ARQUIVO_CONFIG")
    @patch("firewall.nucleo.status.obter_status")
    @patch("firewall.nucleo.instalador.reparar_firewall")
    def test_boot_restore_config_exists_table_missing(
        self, mock_reparar, mock_obter_status, mock_arquivo, mock_rollback
    ):
        """1. configuração persistente existente + table ausente: restore/reparar é chamado exatamente uma vez."""
        mock_rollback.return_value = {"recuperadas": [], "revertidas": [], "erros": []}
        mock_arquivo.exists.return_value = True
        # Firewall is not installed (table is missing)
        mock_obter_status.return_value = {"instalado": False}
        mock_reparar.return_value = {"ok": True}

        _inicializar_firewall()

        mock_reparar.assert_called_once()


    @patch("firewall.nucleo.rollback.inicializar_rollback_pendente")
    @patch("firewall.nucleo.status.ARQUIVO_CONFIG")
    @patch("firewall.nucleo.status.obter_status")
    @patch("firewall.nucleo.instalador.reparar_firewall")
    def test_boot_restore_config_exists_table_healthy(
        self, mock_reparar, mock_obter_status, mock_arquivo, mock_rollback
    ):
        """2. configuração persistente + table já saudável: nenhuma aplicação ocorre."""
        mock_rollback.return_value = {"recuperadas": [], "revertidas": [], "erros": []}
        mock_arquivo.exists.return_value = True
        # Firewall is already healthy
        mock_obter_status.return_value = {"instalado": True}

        _inicializar_firewall()

        mock_reparar.assert_not_called()

    @patch("firewall.nucleo.rollback.inicializar_rollback_pendente")
    @patch("firewall.nucleo.status.ARQUIVO_CONFIG")
    @patch("firewall.nucleo.status.obter_status")
    @patch("firewall.nucleo.instalador.reparar_firewall")
    def test_boot_restore_never_configured(
        self, mock_reparar, mock_obter_status, mock_arquivo, mock_rollback
    ):
        """3. Firewall nunca configurado: startup não instala Firewall sozinho."""
        mock_rollback.return_value = {"recuperadas": [], "revertidas": [], "erros": []}
        # Never configured
        mock_arquivo.exists.return_value = False

        _inicializar_firewall()

        mock_reparar.assert_not_called()
        mock_obter_status.assert_not_called()

    @patch("firewall.nucleo.rollback.inicializar_rollback_pendente")
    @patch("firewall.nucleo.status.ARQUIVO_CONFIG")
    @patch("firewall.nucleo.status.obter_status")
    @patch("firewall.nucleo.instalador.reparar_firewall")
    def test_boot_restore_yields_to_safe_apply(
        self, mock_reparar, mock_obter_status, mock_arquivo, mock_rollback
    ):
        """4. Safe Apply pendente: restore normal não atropela recuperação pendente."""
        # A pending rollback exists
        mock_rollback.return_value = {"recuperadas": ["fake_id"], "revertidas": [], "erros": []}
        mock_arquivo.exists.return_value = True
        mock_obter_status.return_value = {"instalado": False}

        _inicializar_firewall()

        mock_reparar.assert_not_called()

    @patch("firewall.nucleo.rollback.inicializar_rollback_pendente")
    @patch("firewall.nucleo.status.ARQUIVO_CONFIG")
    @patch("firewall.nucleo.status.obter_status")
    @patch("firewall.nucleo.instalador.reparar_firewall")
    def test_boot_restore_failure_handled_gracefully(
        self, mock_reparar, mock_obter_status, mock_arquivo, mock_rollback
    ):
        """5. falha em restore: erro é registrado/tratado; Agent consegue continuar inicialização."""
        mock_rollback.return_value = {"recuperadas": [], "revertidas": [], "erros": []}
        mock_arquivo.exists.return_value = True
        mock_obter_status.return_value = {"instalado": False}
        mock_reparar.return_value = {"ok": False, "erro": "Falha simulada"}

        try:
            _inicializar_firewall()
        except Exception as e:
            self.fail(f"_inicializar_firewall raised {type(e).__name__} unexpectedly!")

        mock_reparar.assert_called_once()

    @patch("firewall.nucleo.rollback.inicializar_rollback_pendente")
    @patch("firewall.nucleo.status.ARQUIVO_CONFIG")
    @patch("firewall.nucleo.status.obter_status")
    @patch("firewall.nucleo.instalador.reparar_firewall")
    def test_boot_restore_exception_handled_gracefully(
        self, mock_reparar, mock_obter_status, mock_arquivo, mock_rollback
    ):
        """6. falha em restore com exception: erro é tratado e Agent não crasha."""
        mock_rollback.return_value = {"recuperadas": [], "revertidas": [], "erros": []}
        mock_arquivo.exists.return_value = True
        mock_obter_status.return_value = {"instalado": False}
        mock_reparar.side_effect = RuntimeError("Falha grave e inesperada simulada")

        try:
            _inicializar_firewall()
        except Exception as e:
            self.fail(f"_inicializar_firewall raised {type(e).__name__} unexpectedly despite exception block!")

        mock_reparar.assert_called_once()


class TestFirewallJournalParser(unittest.TestCase):
    def test_parseia_drop_icmp(self):
        evento = parsear_linha(
            '2026-09-24T10:00:00+00:00 host kernel: MS-FW-DROP: '
            'IN=enp0s8 OUT=enp0s3 SRC=192.168.52.10 DST=8.8.8.8 '
            'LEN=60 PROTO=ICMP TYPE=8 CODE=0'
        )

        self.assertEqual(evento['acao'], 'DROP')
        self.assertEqual(evento['proto'], 'ICMP')
        self.assertEqual(evento['iface_entrada'], 'enp0s8')
        self.assertEqual(evento['iface_saida'], 'enp0s3')
        self.assertEqual(evento['src_ip'], '192.168.52.10')
        self.assertEqual(evento['dst_ip'], '8.8.8.8')

    def test_parseia_tcp_e_udp_com_portas(self):
        tcp = parsear_linha(
            'MS-FW-DROP: IN=lan0 OUT=wan0 SRC=10.0.0.2 DST=1.1.1.1 '
            'PROTO=TCP SPT=49700 DPT=443 SYN'
        )
        udp = parsear_linha(
            'MS-FW-ALLOW: IN=lan0 OUT=wan0 SRC=10.0.0.2 DST=8.8.8.8 '
            'PROTO=UDP SPT=53000 DPT=53'
        )

        self.assertEqual((tcp['proto'], tcp['src_port'], tcp['dst_port']), ('TCP', 49700, 443))
        self.assertEqual((udp['proto'], udp['src_port'], udp['dst_port']), ('UDP', 53000, 53))

    def test_ignora_linha_invalida_ou_nao_moonshield(self):
        self.assertIsNone(parsear_linha('kernel: evento sem estrutura'))
        self.assertIsNone(parsear_linha('kernel: ACCEPT IN=lan0 SRC=10.0.0.2'))
