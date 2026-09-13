import unittest
from pathlib import Path
import tempfile
import os
from unittest.mock import patch, MagicMock

from suricata.aplicador import _garantir_regras_moonshield, _validar_candidato
from suricata.configuracao import _patch_rule_files

class TestProvisionamentoRegras(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.rules_ms_path = Path(self.tmp_dir.name) / "ms.rules"
        self.fake_bundled = Path(self.tmp_dir.name) / "regras_ms.rules"

        self.conteudo_base = b"# MoonShield Rules\nregras operacionais fake...\n"
        self.fake_bundled.write_bytes(self.conteudo_base)

        self.dest_patcher = patch('suricata.aplicador.RULES_MS_PADRAO', self.rules_ms_path)
        self.src_patcher = patch('suricata.aplicador.RULES_MS_BUNDLED', self.fake_bundled)

        self.dest_patcher.start()
        self.src_patcher.start()

    def tearDown(self):
        self.dest_patcher.stop()
        self.src_patcher.stop()
        self.tmp_dir.cleanup()

    def test_bundled_com_bom_runtime_produzido_sem_bom(self):
        self.fake_bundled.write_bytes(b"\xef\xbb\xbf" + self.conteudo_base)
        config = {"instalar_regras_moonshield": True}

        _garantir_regras_moonshield(config)

        runtime_data = self.rules_ms_path.read_bytes()
        self.assertFalse(runtime_data.startswith(b"\xef\xbb\xbf"))
        self.assertEqual(runtime_data, self.conteudo_base)

    def test_bundled_sem_bom_conteudo_permanece_identico(self):
        self.fake_bundled.write_bytes(self.conteudo_base)
        config = {"instalar_regras_moonshield": True}

        _garantir_regras_moonshield(config)

        runtime_data = self.rules_ms_path.read_bytes()
        self.assertEqual(runtime_data, self.conteudo_base)

    def test_destino_existente_com_bom_bom_removido_restante_igual(self):
        conteudo_custom = b"regras customizadas do admin\n" * 2
        self.rules_ms_path.write_bytes(b"\xef\xbb\xbf" + conteudo_custom)
        config = {"instalar_regras_moonshield": True}

        _garantir_regras_moonshield(config)

        runtime_data = self.rules_ms_path.read_bytes()
        self.assertFalse(runtime_data.startswith(b"\xef\xbb\xbf"))
        self.assertEqual(runtime_data, conteudo_custom)

    def test_destino_existente_sem_bom_nao_e_sobrescrito(self):
        conteudo_custom = b"regras customizadas do admin\n" * 2
        self.rules_ms_path.write_bytes(conteudo_custom)

        # Altera timestamps ou algo para verificar que nao foi sobrescrito
        mtime = self.rules_ms_path.stat().st_mtime

        config = {"instalar_regras_moonshield": True}
        _garantir_regras_moonshield(config)

        self.assertEqual(self.rules_ms_path.stat().st_mtime, mtime)
        self.assertEqual(self.rules_ms_path.read_bytes(), conteudo_custom)

    def test_regras_customizadas_existentes_com_bom_remove_somente_bom(self):
        conteudo_custom = b"regras customizadas do admin 2\n" * 2
        self.rules_ms_path.write_bytes(b"\xef\xbb\xbf" + conteudo_custom)
        config = {"instalar_regras_moonshield": True}

        _garantir_regras_moonshield(config)

        runtime_data = self.rules_ms_path.read_bytes()
        self.assertNotIn(b"regras operacionais fake", runtime_data) # Nao usa o bundle
        self.assertEqual(runtime_data, conteudo_custom)

    @patch('suricata.aplicador.os.replace')
    def test_temp_continua_sendo_limpo_em_falha(self, mock_replace):
        mock_replace.side_effect = PermissionError("Acesso negado simulado")
        config = {"instalar_regras_moonshield": True}

        with self.assertRaises(PermissionError):
            _garantir_regras_moonshield(config)

        arquivos = list(self.rules_ms_path.parent.glob("tmp*")) + list(self.rules_ms_path.parent.glob("*.tmp"))
        self.assertEqual(len(arquivos), 0)

    def test_asset_bundled_real_nunca_e_modificado_pelos_testes(self):
        # Como iteramos tudo sobre tmp_dir e mockamos a constante,
        # basta validar que o arquivo real não foi adulterado/não possui os mocks
        asset_real = Path(__file__).parent / "regras_ms.rules"
        data = asset_real.read_bytes()
        self.assertNotIn(b"regras operacionais fake", data)

    def test_flag_falsa_nao_instala_e_remove_referencia(self):
        config = {"instalar_regras_moonshield": False}
        _garantir_regras_moonshield(config)
        self.assertFalse(self.rules_ms_path.exists())

        yaml_base = "rule-files:\n  - moonshield/ms.rules\n"
        novo_yaml = _patch_rule_files(yaml_base, False)
        self.assertNotIn("moonshield/ms.rules", novo_yaml)

    def test_destino_arbitrario_ignorado(self):
        arbitrario_path = Path(self.tmp_dir.name) / "arbitrario.rules"
        config = {
            "instalar_regras_moonshield": True,
            "rules_ms_path": str(arbitrario_path)
        }

        _garantir_regras_moonshield(config)

        self.assertTrue(self.rules_ms_path.exists())
        self.assertFalse(arbitrario_path.exists())

    def test_asset_bundled_ausente(self):
        self.fake_bundled.unlink()
        config = {"instalar_regras_moonshield": True}

        with self.assertRaisesRegex(ValueError, "ausente ou vazio"):
            _garantir_regras_moonshield(config)

    @patch('suricata.aplicador.subprocess.run')
    @patch('suricata.aplicador.shutil.which')
    def test_ordem_garantir_antes_suricata_T(self, mock_which, mock_run):
        mock_which.return_value = "/usr/bin/suricata"
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        config = {"instalar_regras_moonshield": True}
        self.assertFalse(self.rules_ms_path.exists())

        res = _validar_candidato("yaml", "original.yaml", config)
        self.assertTrue(self.rules_ms_path.exists())
        self.assertTrue(res.get("ok", True))

if __name__ == "__main__":
    unittest.main()
