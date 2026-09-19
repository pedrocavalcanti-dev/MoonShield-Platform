import unittest
from unittest.mock import patch, MagicMock
from diagnostico.ipc.handlers import executar_acao_diagnostico

class TestDiagnosticHandlers(unittest.TestCase):

    @patch('diagnostico.ipc.handlers.dispatch_tool')
    def test_targetless_tools_allowed(self, mock_dispatch):
        mock_dispatch.return_value = {"ok": True, "status": "ok"}
        targetless_tools = ["routes", "interfaces", "arp_table", "sockets"]

        for tool in targetless_tools:
            res = executar_acao_diagnostico(
                "diagnostic.execute", 
                {"tool": tool, "target": "", "options": {}}
            )
            self.assertTrue(res.get("ok"), f"Tool {tool} falhou indevidamente sem target.")
            self.assertEqual(res.get("status"), "ok")

    def test_targeted_tools_rejected_without_target(self):
        targeted_tools = ["ping", "mtr", "tcp_connect"]

        for tool in targeted_tools:
            res = executar_acao_diagnostico(
                "diagnostic.execute", 
                {"tool": tool, "target": "", "options": {}}
            )
            self.assertFalse(res.get("ok"))
            self.assertEqual(res.get("error_code"), "missing_parameters")
            self.assertIn("target' é obrigatório", res.get("summary", ""))

    def test_missing_tool_rejected(self):
        res = executar_acao_diagnostico(
            "diagnostic.execute", 
            {"tool": "", "target": "127.0.0.1"}
        )
        self.assertFalse(res.get("ok"))
        self.assertEqual(res.get("error_code"), "missing_parameters")
        self.assertIn("tool' é obrigatório", res.get("summary", ""))

if __name__ == '__main__':
    unittest.main()
