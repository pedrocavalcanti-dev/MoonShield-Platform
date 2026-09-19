import unittest
import json
from unittest.mock import patch

from firewall.ipc.protocolo import RequisicaoIPC, resposta_ok, codificar_resposta
from diagnostico.ipc.handlers import executar_acao_diagnostico

class TestCorrelationID(unittest.TestCase):
    @patch("diagnostico.executor.validar_alvo_rede")
    @patch("diagnostico.executor._get_bin")
    @patch("subprocess.Popen")
    def test_live_correlation_start(self, mock_popen, mock_bin, mock_val):
        mock_bin.return_value = "/bin/ping"
        mock_val.return_value = "8.8.8.8"
        
        req = RequisicaoIPC(
            id="request-123",
            acao="diagnostic.live.start",
            dados={"tool": "ping", "target": "8.8.8.8", "options": {}}
        )
        
        dados = executar_acao_diagnostico(req.acao, req.dados)
        resp_obj = resposta_ok(req, dados)
        raw = codificar_resposta(resp_obj)
        resp = json.loads(raw)
        
        self.assertEqual(resp["id"], "request-123")
        self.assertIn("dados", resp)
        self.assertIn("session_id", resp["dados"])
        self.assertNotEqual(resp["dados"]["session_id"], "request-123")
        
    @patch("diagnostico.live.status_live_session")
    def test_live_correlation_status(self, mock_status):
        mock_status.return_value = {"ok": True, "session_id": "sess-456", "status": "running"}
        
        req = RequisicaoIPC(
            id="request-789",
            acao="diagnostic.live.status",
            dados={"session_id": "sess-456"}
        )
        
        dados = executar_acao_diagnostico(req.acao, req.dados)
        resp_obj = resposta_ok(req, dados)
        raw = codificar_resposta(resp_obj)
        resp = json.loads(raw)
        
        self.assertEqual(resp["id"], "request-789")
        self.assertEqual(resp["dados"]["session_id"], "sess-456")
        
    @patch("diagnostico.live.stop_live_session")
    def test_live_correlation_stop(self, mock_stop):
        mock_stop.return_value = {"ok": True, "session_id": "sess-456", "status": "stopped"}
        
        req = RequisicaoIPC(
            id="request-abc",
            acao="diagnostic.live.stop",
            dados={"session_id": "sess-456"}
        )
        
        dados = executar_acao_diagnostico(req.acao, req.dados)
        resp_obj = resposta_ok(req, dados)
        raw = codificar_resposta(resp_obj)
        resp = json.loads(raw)
        
        self.assertEqual(resp["id"], "request-abc")
        self.assertEqual(resp["dados"]["session_id"], "sess-456")

