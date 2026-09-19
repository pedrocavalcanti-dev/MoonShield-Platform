import unittest
from unittest.mock import patch, MagicMock

from diagnostico.live import start_live_session, status_live_session, stop_live_session, cleanup_sessions, _sessions

class TestLiveSessions(unittest.TestCase):
    def setUp(self):
        _sessions.clear()

    @patch("subprocess.Popen")
    @patch("diagnostico.executor.validar_alvo_rede")
    @patch("diagnostico.executor._get_bin")
    def test_start_ping(self, mock_bin, mock_val, mock_popen):
        mock_bin.return_value = "/bin/ping"
        mock_val.return_value = "8.8.8.8"
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        
        res = start_live_session("ping", "8.8.8.8", {})
        self.assertTrue(res["ok"])
        self.assertIn("session_id", res)
        self.assertEqual(res["tool"], "ping")
        self.assertEqual(len(_sessions), 1)

    @patch("subprocess.Popen")
    @patch("diagnostico.executor.validar_alvo_rede")
    @patch("diagnostico.executor._get_bin")
    def test_start_mtr(self, mock_bin, mock_val, mock_popen):
        mock_bin.return_value = "/bin/mtr"
        mock_val.return_value = "8.8.8.8"
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        
        res = start_live_session("mtr", "8.8.8.8", {})
        self.assertTrue(res["ok"])
        self.assertEqual(res["tool"], "mtr")

    def test_start_invalid_tool(self):
        res = start_live_session("invalid", "8.8.8.8", {})
        self.assertFalse(res["ok"])
        self.assertEqual(res["error_code"], "invalid_tool")

    @patch("diagnostico.executor.validar_alvo_rede")
    def test_start_invalid_target(self, mock_val):
        mock_val.side_effect = ValueError("Alvo invalido")
        res = start_live_session("ping", "invalid!target", {})
        self.assertFalse(res["ok"])
        self.assertEqual(res["error_code"], "invalid_target")

    @patch("subprocess.Popen")
    @patch("diagnostico.executor.validar_alvo_rede")
    @patch("diagnostico.executor._get_bin")
    def test_max_sessions(self, mock_bin, mock_val, mock_popen):
        mock_bin.return_value = "/bin/ping"
        mock_val.return_value = "8.8.8.8"
        mock_popen.return_value = MagicMock()
        
        for _ in range(4):
            start_live_session("ping", "8.8.8.8", {})
            
        res = start_live_session("ping", "8.8.8.8", {})
        self.assertFalse(res["ok"])
        self.assertEqual(res["error_code"], "max_sessions")

    @patch("subprocess.Popen")
    @patch("diagnostico.executor.validar_alvo_rede")
    @patch("diagnostico.executor._get_bin")
    def test_status_and_stop(self, mock_bin, mock_val, mock_popen):
        mock_bin.return_value = "/bin/ping"
        mock_val.return_value = "8.8.8.8"
        mock_process = MagicMock()
        mock_process.poll.return_value = None
        mock_process.stderr.read.return_value = ""
        mock_process.stdout = []
        mock_popen.return_value = mock_process
        
        start_res = start_live_session("ping", "8.8.8.8", {})
        sid = start_res["session_id"]
        
        # Test status
        status_res = status_live_session(sid)
        self.assertTrue(status_res["ok"])
        self.assertEqual(status_res["status"], "running")
        
        # Test stop
        stop_res = stop_live_session(sid)
        self.assertTrue(stop_res["ok"])
        self.assertEqual(stop_res["status"], "stopped")
        mock_process.terminate.assert_called_once()
        self.assertEqual(len(_sessions), 0)

    def test_session_missing(self):
        res = status_live_session("missing_id")
        self.assertFalse(res["ok"])
        self.assertEqual(res["error_code"], "not_found")
        
        res_stop = stop_live_session("missing_id")
        self.assertFalse(res_stop["ok"])
        self.assertEqual(res_stop["error_code"], "not_found")

    @patch("diagnostico.live.time.time")
    @patch("subprocess.Popen")
    @patch("diagnostico.executor.validar_alvo_rede")
    @patch("diagnostico.executor._get_bin")
    def test_ttl_cleanup(self, mock_bin, mock_val, mock_popen, mock_time):
        mock_bin.return_value = "/bin/ping"
        mock_val.return_value = "8.8.8.8"
        mock_popen.return_value = MagicMock()
        
        # Started at 0
        mock_time.return_value = 0
        start_res = start_live_session("ping", "8.8.8.8", {})
        sid = start_res["session_id"]
        self.assertEqual(len(_sessions), 1)
        
        # Move time to 30 minutes + 1 second
        mock_time.return_value = 1801
        
        # Cleanup should happen in status call
        status_res = status_live_session(sid)
        self.assertFalse(status_res["ok"])
        self.assertEqual(status_res["error_code"], "not_found")
        self.assertEqual(len(_sessions), 0)


    @patch("diagnostico.executor._get_bin")
    @patch("diagnostico.executor.validar_alvo_rede")
    @patch("subprocess.Popen")
    def test_idempotent_stop(self, mock_popen, mock_val, mock_bin):
        mock_bin.return_value = "/bin/ping"
        mock_val.return_value = "8.8.8.8"
        mock_process = MagicMock()
        mock_process.poll.return_value = None
        mock_process.stderr.read.return_value = ""
        mock_process.stdout = []
        mock_popen.return_value = mock_process
        
        start_res = start_live_session("ping", "8.8.8.8", {})
        sid = start_res["session_id"]
        
        # Stop 1
        stop_res1 = stop_live_session(sid)
        self.assertTrue(stop_res1["ok"])
        self.assertEqual(stop_res1["session_id"], sid)
        
        # Stop 2
        stop_res2 = stop_live_session(sid)
        self.assertFalse(stop_res2["ok"])
        self.assertEqual(stop_res2["error_code"], "not_found")
