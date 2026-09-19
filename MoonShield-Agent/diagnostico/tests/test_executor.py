import unittest
from unittest.mock import patch, MagicMock
from diagnostico.executor import dispatch_tool

class TestExecutor(unittest.TestCase):
    @patch("diagnostico.executor._get_bin")
    @patch("diagnostico.executor.subprocess.run")
    def test_dispatch_ping_success(self, mock_run, mock_get_bin):
        mock_get_bin.return_value = "/bin/ping"
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = '''4 packets transmitted, 4 received, 0% packet loss
rtt min/avg/max/mdev = 1.0/2.0/3.0/0.1 ms'''
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        result = dispatch_tool("ping", "8.8.8.8", {"count": 4})

        self.assertTrue(result["ok"])
        self.assertEqual(result["tool"], "ping")
        self.assertEqual(result["target"], "8.8.8.8")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["structured"]["sent"], 4)
        self.assertEqual(result["structured"]["received"], 4)
        self.assertEqual(result["structured"]["loss_percent"], 0.0)

    @patch("diagnostico.executor._get_bin")
    def test_dispatch_tool_not_allowed(self, mock_get_bin):
        result = dispatch_tool("rm", "/", {})
        self.assertFalse(result["ok"])
        self.assertEqual(result["error_code"], "tool_not_allowed")

    @patch("diagnostico.executor._get_bin")
    def test_dispatch_tool_unavailable(self, mock_get_bin):
        mock_get_bin.side_effect = FileNotFoundError("Ferramenta 'mtr' não encontrada")
        result = dispatch_tool("mtr", "8.8.8.8", {})
        self.assertFalse(result["ok"])
        self.assertEqual(result["error_code"], "tool_unavailable")

    def test_dispatch_invalid_target(self):
        result = dispatch_tool("ping", "8.8.8.8;id", {})
        self.assertFalse(result["ok"])
        self.assertEqual(result["error_code"], "invalid_target")

    @patch("diagnostico.executor.socket.socket")
    def test_tcp_connect_mock(self, mock_socket):
        mock_sock_inst = MagicMock()
        mock_socket.return_value = mock_sock_inst

        result = dispatch_tool("tcp_connect", "8.8.8.8", {"port": 80})
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["structured"]["reachable"])
        self.assertEqual(result["structured"]["port"], 80)
        mock_sock_inst.connect.assert_called_with(("8.8.8.8", 80))

    @patch("diagnostico.executor.urllib.request.urlopen")
    def test_http_check_mock(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.geturl.return_value = "https://google.com"
        mock_resp.headers = {"Server": "gws"}

        # Needs to handle context manager from urlopen
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        result = dispatch_tool("http_check", "https://google.com", {})
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["structured"]["status_code"], 200)
