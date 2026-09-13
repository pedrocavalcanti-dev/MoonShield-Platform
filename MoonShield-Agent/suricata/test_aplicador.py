import unittest
from pathlib import Path
import tempfile
import shutil
import os
from unittest.mock import patch, MagicMock

from suricata.aplicador import _garantir_regras_moonshield, _validar_candidato
from suricata.configuracao import RULES_MS_PADRAO, _patch_rule_files

class TestProvisionamentoRegras(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.rules_ms_path = Path(self.tmp_dir.name) / "ms.rules"

        # Arquivo fake isolado no tempdir (NUNCA sobrescreve o real)
        self.fake_bundled = Path(self.tmp_dir.name) / "regras_ms.rules"
        self.fake_bundled.write_bytes(b"regras fake bundled com mais de 50 bytes de tamanho para teste.\n"*2)

        # Mock RULES_MS_PADRAO (destino) e RULES_MS_BUNDLED (origem) para nossos tmp files
        self.dest_patcher = patch('suricata.aplicador.RULES_MS_PADRAO', self.rules_ms_path)
        self.src_patcher = patch('suricata.aplicador.RULES_MS_BUNDLED', self.fake_bundled)

        self.dest_patcher.start()
        self.src_patcher.start()

    def tearDown(self):
        self.dest_patcher.stop()
        self.src_patcher.stop()
        self.tmp_dir.cleanup()

    def test_rules_ausente_provisiona_bundled(self):
        config = {"instalar_regras_moonshield": True}
        self.assertFalse(self.rules_ms_path.exists())

        _garantir_regras_moonshield(config)

        self.assertTrue(self.rules_ms_path.exists())
        self.assertTrue(self.rules_ms_path.stat().st_size > 50)
        self.assertIn(b"regras fake bundled", self.rules_ms_path.read_bytes())

    def test_rules_nao_sobrescreve_se_existir_operacional(self):
        self.rules_ms_path.parent.mkdir(parents=True, exist_ok=True)
        self.rules_ms_path.write_bytes(b"existente e operacional com mais de 50 bytes de conteudo\n"*2)

        config = {"instalar_regras_moonshield": True}
        _garantir_regras_moonshield(config)

        self.assertIn(b"existente e operacional", self.rules_ms_path.read_bytes())
        self.assertNotIn(b"regras fake bundled", self.rules_ms_path.read_bytes())

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

        # O payload tenta injetar arbitrario.rules, mas o agent
        # deve escrever no destino fixo mockado (self.rules_ms_path)
        self.assertTrue(self.rules_ms_path.exists())
        self.assertFalse(arbitrario_path.exists())

    def test_asset_bundled_ausente(self):
        self.fake_bundled.unlink() # Forca ausencia
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

        # Como o subprocess e mockado, se provisionou antes, o arquivo deve existir agora
        self.assertTrue(self.rules_ms_path.exists())
        self.assertTrue(res.get("ok", True))

    @patch('suricata.aplicador.os.replace')
    def test_temp_file_limpo_em_falha(self, mock_replace):
        mock_replace.side_effect = PermissionError("Acesso negado simulado")
        config = {"instalar_regras_moonshield": True}

        with self.assertRaises(PermissionError):
            _garantir_regras_moonshield(config)

        # Nao deve haver lixo .tmp no diretorio
        arquivos = list(self.rules_ms_path.parent.glob("tmp*")) + list(self.rules_ms_path.parent.glob("*.tmp"))
        self.assertEqual(len(arquivos), 0)

if __name__ == "__main__":
    unittest.main()
