from unittest.mock import patch

from django.test import SimpleTestCase

from incidentes.services.suricata.agent import atualizar_regras


class AtualizacaoRulesAdapterTests(SimpleTestCase):
    @patch("incidentes.services.suricata.agent.requisitar_agent")
    def test_envia_apenas_flags_permitidas_ao_agent(self, requisitar_agent):
        requisitar_agent.return_value = {"ok": True}

        atualizar_regras(
            atualizar_moonshield=True,
            atualizar_et=False,
            validar_depois=True,
            reiniciar_depois=False,
        )

        requisitar_agent.assert_called_once_with(
            "suricata.rules.update",
            {
                "atualizar_moonshield": True,
                "atualizar_et": False,
                "validar_depois": True,
                "reiniciar_depois": False,
            },
            timeout=960,
        )
