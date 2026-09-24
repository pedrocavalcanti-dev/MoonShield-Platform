import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from suricata import regras


class RegrasSuricataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        raiz = Path(self.temp.name)
        self.origem = raiz / "regras_ms.rules"
        self.ms = raiz / "moonshield" / "ms.rules"
        self.et = raiz / "suricata.rules"
        self.yaml = raiz / "suricata.yaml"
        self.backups = raiz / "backups"
        self.origem.write_bytes(b"alert tcp any any -> any any (sid:1;)")
        self.yaml.write_text("%YAML 1.1\n")
        self.paths = patch.multiple(
            regras,
            RULES_MS_SOURCE=self.origem,
            RULES_MS_DEST=self.ms,
            RULES_ET_DEST=self.et,
            YAML_PATH=self.yaml,
            BACKUP_DIR=self.backups,
        )
        self.paths.start()
        self.addCleanup(self.paths.stop)
        self.addCleanup(self.temp.cleanup)

    def _executar_ok(self, argumentos, *, timeout):
        return subprocess.CompletedProcess(argumentos, 0, "ok", "")

    def test_moonshield_sem_et_valida(self):
        with patch.object(regras, "_validar_suricata", return_value={"ok": True, "executada": True, "aprovada": True}):
            resultado = regras.atualizar({"atualizar_moonshield": True, "atualizar_et": False, "validar_depois": True, "reiniciar_depois": False})
        self.assertTrue(resultado["ok"])
        self.assertTrue(resultado["moonshield"]["mudou"])
        self.assertTrue(resultado["validacao"]["aprovada"])

    def test_moonshield_et_valida(self):
        def executar(argumentos, *, timeout):
            if "--no-reload" in argumentos:
                self.et.write_bytes(b"et nova")
            return self._executar_ok(argumentos, timeout=timeout)

        with patch.object(regras, "_executar", side_effect=executar), patch.object(regras.shutil, "which", side_effect=lambda nome: nome), patch.object(regras, "_validar_suricata", return_value={"ok": True, "executada": True, "aprovada": True}):
            resultado = regras.atualizar({"atualizar_moonshield": True, "atualizar_et": True, "validar_depois": True, "reiniciar_depois": False})
        self.assertTrue(resultado["ok"])
        self.assertTrue(resultado["et_open"]["executada"])
        self.assertTrue(resultado["et_open"]["mudou"])

    def test_suricata_update_ausente(self):
        with patch.object(regras.shutil, "which", return_value=None):
            resultado = regras.atualizar({"atualizar_moonshield": False, "atualizar_et": True, "validar_depois": False, "reiniciar_depois": False})
        self.assertFalse(resultado["ok"])
        self.assertEqual(resultado["codigo"], "suricata_update_indisponivel")

    def test_suricata_update_com_erro(self):
        def executar(argumentos, *, timeout):
            code = 1 if "--no-reload" in argumentos else 0
            return subprocess.CompletedProcess(argumentos, code, "", "falhou")

        with patch.object(regras, "_executar", side_effect=executar), patch.object(regras.shutil, "which", side_effect=lambda nome: nome):
            resultado = regras.atualizar({"atualizar_moonshield": False, "atualizar_et": True, "validar_depois": False, "reiniciar_depois": False})
        self.assertFalse(resultado["ok"])
        self.assertEqual(resultado["codigo"], "suricata_update_falhou")

    def test_rules_moonshield_invalidas_acionam_rollback(self):
        self.ms.parent.mkdir(parents=True)
        self.ms.write_bytes(b"regra anterior")
        with patch.object(regras, "_validar_suricata", side_effect=[{"ok": False, "executada": True, "aprovada": False, "erro": "inválida"}, {"ok": True, "executada": True, "aprovada": True}]):
            resultado = regras.atualizar({"atualizar_moonshield": True, "atualizar_et": False, "validar_depois": True, "reiniciar_depois": False})
        self.assertFalse(resultado["ok"])
        self.assertEqual(self.ms.read_bytes(), b"regra anterior")
        self.assertTrue(resultado["rollback"]["ok"])

    def test_suricata_t_falha_gera_erro_real(self):
        with patch.object(regras, "_validar_suricata", return_value={"ok": False, "executada": True, "aprovada": False, "erro": "suricata -T falhou"}):
            resultado = regras.atualizar({"atualizar_moonshield": True, "atualizar_et": False, "validar_depois": True, "reiniciar_depois": False})
        self.assertEqual(resultado["codigo"], "regras_validacao_falhou")

    def test_rollback_revalida_estado_anterior(self):
        with patch.object(regras, "_validar_suricata", side_effect=[{"ok": False, "executada": True, "aprovada": False, "erro": "nova inválida"}, {"ok": True, "executada": True, "aprovada": True}]) as validar:
            regras.atualizar({"atualizar_moonshield": True, "atualizar_et": False, "validar_depois": True, "reiniciar_depois": False})
        self.assertEqual(validar.call_count, 2)

    def test_rules_sem_mudanca_real(self):
        self.ms.parent.mkdir(parents=True)
        self.ms.write_bytes(self.origem.read_bytes())
        with patch.object(regras, "_validar_suricata", return_value={"ok": True, "executada": True, "aprovada": True}):
            resultado = regras.atualizar({"atualizar_moonshield": True, "atualizar_et": False, "validar_depois": True, "reiniciar_depois": False})
        self.assertFalse(resultado["moonshield"]["mudou"])

    def test_reiniciar_false_nunca_reinicia(self):
        with patch.object(regras, "_validar_suricata", return_value={"ok": True, "executada": True, "aprovada": True}), patch.object(regras, "reiniciar") as reiniciar:
            resultado = regras.atualizar({"atualizar_moonshield": True, "atualizar_et": False, "validar_depois": True, "reiniciar_depois": False})
        self.assertTrue(resultado["ok"])
        reiniciar.assert_not_called()

    def test_reiniciar_true_apos_validacao(self):
        with patch.object(regras, "_validar_suricata", return_value={"ok": True, "executada": True, "aprovada": True}), patch.object(regras, "reiniciar", return_value={"ok": True, "estado": "active"}) as reiniciar:
            resultado = regras.atualizar({"atualizar_moonshield": True, "atualizar_et": False, "validar_depois": True, "reiniciar_depois": True})
        self.assertTrue(resultado["ok"])
        reiniciar.assert_called_once_with({})

    def test_payload_com_caminho_arbitrario_e_recusado(self):
        resultado = regras.atualizar({"yaml_path": "/tmp/arbitrario"})
        self.assertFalse(resultado["ok"])
        self.assertEqual(resultado["codigo"], "regras_payload_invalido")
