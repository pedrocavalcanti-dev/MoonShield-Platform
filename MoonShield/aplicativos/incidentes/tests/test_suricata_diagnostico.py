from django.test import SimpleTestCase

from incidentes.views_suricata import (
    _normalizar_diagnostico_serializado,
    _resumir_diagnostico_serializado,
)


class DiagnosticoSuricataSerializadoTests(SimpleTestCase):
    def test_checks_do_agent_todos_saudaveis(self):
        diagnostico = {
            "checks": {
                "sem_drift": True,
                "eve_existe": True,
                "yaml_existe": True,
                "servico_ativo": True,
                "topologia_valida": True,
                "suricata_instalado": True,
                "rules_ms_instaladas": True,
            },
        }

        normalizado = _normalizar_diagnostico_serializado(diagnostico)
        resumo = _resumir_diagnostico_serializado(diagnostico)

        self.assertEqual(len(normalizado["itens"]), 7)
        self.assertEqual(resumo["total_checks"], 7)
        self.assertEqual(resumo["total_saudaveis"], 7)
        self.assertEqual(resumo["total_avisos"], 0)
        self.assertEqual(resumo["total_falhas"], 0)
        self.assertEqual(resumo["total_criticos"], 0)
        self.assertEqual(resumo["score"], 100)
        self.assertTrue(resumo["pronto"])
        self.assertTrue(resumo["grupos"])
        self.assertEqual(
            resumo["mensagem"],
            "Infraestrutura pronta e sem falhas críticas.",
        )

    def test_checks_do_agent_com_falha_real(self):
        diagnostico = {
            "checks": {
                "suricata_instalado": True,
                "servico_ativo": True,
                "eve_existe": False,
            },
        }

        resumo = _resumir_diagnostico_serializado(diagnostico)

        self.assertEqual(resumo["total_checks"], 3)
        self.assertEqual(resumo["total_saudaveis"], 2)
        self.assertEqual(resumo["total_falhas"], 1)
        self.assertEqual(resumo["total_avisos"], 0)
        self.assertEqual(resumo["total_criticos"], 1)
        self.assertEqual(resumo["score_integridade"], 67)
        self.assertFalse(resumo["pronto"])
        self.assertEqual(resumo["falhas_criticas"][0]["id"], "eve_existe")
        self.assertEqual(
            resumo["mensagem"],
            "Existem falhas críticas que exigem correção.",
        )

    def test_itens_legado_permanece_compativel(self):
        diagnostico = {
            "itens": [
                {"id": "ok", "grupo": "Legado", "ok": True},
                {"id": "aviso", "grupo": "Legado", "ok": False, "critico": False},
            ],
        }

        resumo = _resumir_diagnostico_serializado(diagnostico)

        self.assertEqual(resumo["total_checks"], 2)
        self.assertEqual(resumo["total_saudaveis"], 1)
        self.assertEqual(resumo["total_avisos"], 1)
        self.assertEqual(resumo["total_criticos"], 0)
        self.assertEqual(resumo["score"], 50)
        self.assertTrue(resumo["pronto"])

    def test_diagnostico_vazio(self):
        resumo = _resumir_diagnostico_serializado({})

        self.assertEqual(resumo["total_checks"], 0)
        self.assertEqual(resumo["score"], 0)
        self.assertEqual(resumo["grupos"], {})
        self.assertFalse(resumo["pronto"])

    def test_payload_malformado_nao_cria_checks(self):
        diagnostico = {
            "checks": ["nao", "e", "um", "dicionario"],
        }

        normalizado = _normalizar_diagnostico_serializado(diagnostico)
        resumo = _resumir_diagnostico_serializado(diagnostico)

        self.assertEqual(normalizado["itens"], [])
        self.assertEqual(resumo["total_checks"], 0)
        self.assertEqual(resumo["total_saudaveis"], 0)
        self.assertEqual(resumo["total_criticos"], 0)
        self.assertFalse(resumo["pronto"])
