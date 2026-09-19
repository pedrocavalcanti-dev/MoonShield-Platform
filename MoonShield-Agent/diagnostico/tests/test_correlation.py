import json
import unittest
from unittest.mock import patch

from firewall.ipc.protocolo import decodificar_requisicao, AcaoNaoPermitida, resposta_ok, codificar_resposta
from diagnostico.ipc.handlers import executar_acao_diagnostico

class TestCorrelationID(unittest.TestCase):
    def test_decodificar_requisicao_allowlist_start(self):
        raw_json = json.dumps({
            "versao": 1,
            "id": "request-123",
            "acao": "diagnostic.live.start",
            "dados": {
                "tool": "ping",
                "target": "8.8.8.8",
                "options": {}
            }
        })

        req = decodificar_requisicao(raw_json)
        self.assertEqual(req.id, "request-123")
        self.assertEqual(req.acao, "diagnostic.live.start")

    def test_decodificar_requisicao_allowlist_status(self):
        raw_json = json.dumps({
            "versao": 1,
            "id": "request-456",
            "acao": "diagnostic.live.status",
            "dados": {
                "session_id": "sess-xyz"
            }
        })

        req = decodificar_requisicao(raw_json)
        self.assertEqual(req.id, "request-456")
        self.assertEqual(req.acao, "diagnostic.live.status")

    def test_decodificar_requisicao_allowlist_stop(self):
        raw_json = json.dumps({
            "versao": 1,
            "id": "request-789",
            "acao": "diagnostic.live.stop",
            "dados": {
                "session_id": "sess-xyz"
            }
        })

        req = decodificar_requisicao(raw_json)
        self.assertEqual(req.id, "request-789")
        self.assertEqual(req.acao, "diagnostic.live.stop")

    def test_decodificar_requisicao_acao_nao_permitida(self):
        raw_json = json.dumps({
            "versao": 1,
            "id": "request-bad",
            "acao": "diagnostic.live.qualquercoisa",
            "dados": {}
        })

        with self.assertRaises(AcaoNaoPermitida):
            decodificar_requisicao(raw_json)

    @patch("diagnostico.executor.validar_alvo_rede")
    @patch("diagnostico.executor._get_bin")
    @patch("subprocess.Popen")
    def test_live_correlation_start_e2e(self, mock_popen, mock_bin, mock_val):
        mock_bin.return_value = "/bin/ping"
        mock_val.return_value = "8.8.8.8"

        raw_json = json.dumps({
            "versao": 1,
            "id": "request-e2e-start",
            "acao": "diagnostic.live.start",
            "dados": {
                "tool": "ping",
                "target": "8.8.8.8",
                "options": {}
            }
        })

        req = decodificar_requisicao(raw_json)
        dados = executar_acao_diagnostico(req.acao, req.dados)
        resp_obj = resposta_ok(req, dados)
        raw_resp = codificar_resposta(resp_obj)
        resp = json.loads(raw_resp)

        self.assertEqual(resp["id"], "request-e2e-start")
        self.assertIn("dados", resp)
        self.assertIn("session_id", resp["dados"])
        self.assertNotEqual(resp["dados"]["session_id"], "request-e2e-start")

    @patch("diagnostico.live.status_live_session")
    def test_live_correlation_status_e2e(self, mock_status):
        mock_status.return_value = {"ok": True, "session_id": "sess-456", "status": "running"}

        raw_json = json.dumps({
            "versao": 1,
            "id": "request-e2e-status",
            "acao": "diagnostic.live.status",
            "dados": {
                "session_id": "sess-456"
            }
        })

        req = decodificar_requisicao(raw_json)
        dados = executar_acao_diagnostico(req.acao, req.dados)
        resp_obj = resposta_ok(req, dados)
        raw_resp = codificar_resposta(resp_obj)
        resp = json.loads(raw_resp)

        self.assertEqual(resp["id"], "request-e2e-status")
        self.assertEqual(resp["dados"]["session_id"], "sess-456")

    @patch("diagnostico.live.stop_live_session")
    def test_live_correlation_stop_e2e(self, mock_stop):
        mock_stop.return_value = {"ok": True, "session_id": "sess-456", "status": "stopped"}

        raw_json = json.dumps({
            "versao": 1,
            "id": "request-e2e-stop",
            "acao": "diagnostic.live.stop",
            "dados": {
                "session_id": "sess-456"
            }
        })

        req = decodificar_requisicao(raw_json)
        dados = executar_acao_diagnostico(req.acao, req.dados)
        resp_obj = resposta_ok(req, dados)
        raw_resp = codificar_resposta(resp_obj)
        resp = json.loads(raw_resp)

        self.assertEqual(resp["id"], "request-e2e-stop")
        self.assertEqual(resp["dados"]["session_id"], "sess-456")

if __name__ == "__main__":
    unittest.main()
