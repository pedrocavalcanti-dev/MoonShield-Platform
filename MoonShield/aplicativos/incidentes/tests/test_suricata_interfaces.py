import unittest
from types import SimpleNamespace
from unittest.mock import patch

from configuracoes import views as configuracoes_views
from incidentes.services.suricata.agent import montar_payload_topologia
from incidentes.services.suricata.tarefas import executar_tarefa
from incidentes.services.suricata.tipos import (
    ConfiguracaoSuricataDados,
    ModoCaptura,
    ProgressoTarefa,
    TipoTarefaSuricata,
)


TOPOLOGIA = {
    "valida": True,
    "wan": {"principal": {"nome": "wan0"}},
    "lan": {"principal": {"nome": "lan0"}},
    "mgmt": {"principal": {"nome": "mgmt0"}},
    "home_net": ["192.168.52.0/24"],
}


class ProgressoAuditado(ProgressoTarefa):
    def __post_init__(self):
        super().__post_init__()
        self.historico_percentuais = []

    def atualizar(self, progresso, etapa, mensagem, nivel=None):
        self.historico_percentuais.append(progresso)
        if nivel is None:
            super().atualizar(progresso, etapa, mensagem)
        else:
            super().atualizar(progresso, etapa, mensagem, nivel)


class TestContratoCapturaSuricata(unittest.TestCase):
    @patch("incidentes.services.suricata.agent.obter_topologia", return_value=TOPOLOGIA)
    def test_somente_lan_monitora_apenas_lan(self, _topologia):
        payload = montar_payload_topologia({"modo_captura": "somente_lan"})
        self.assertEqual(payload["interfaces_monitoradas"], ["lan0"])

    @patch("incidentes.services.suricata.agent.obter_topologia", return_value=TOPOLOGIA)
    def test_lan_wan_preserva_lan_e_wan(self, _topologia):
        payload = montar_payload_topologia({"modo_captura": "lan_wan"})
        self.assertEqual(payload["interfaces_monitoradas"], ["lan0", "wan0"])

    @patch("incidentes.services.suricata.agent.obter_topologia", return_value=TOPOLOGIA)
    def test_wan_nao_entra_no_home_net(self, _topologia):
        payload = montar_payload_topologia({"modo_captura": "lan_wan"})
        self.assertEqual(payload["home_net"], ["192.168.52.0/24"])
        self.assertNotIn("wan0", payload["home_net"])

    @patch("incidentes.services.suricata.agent.obter_topologia", return_value=TOPOLOGIA)
    def test_mgmt_nao_e_incluida_automaticamente(self, _topologia):
        payload = montar_payload_topologia({"modo_captura": "lan_wan"})
        self.assertNotIn("mgmt0", payload["interfaces_monitoradas"])

    @patch("incidentes.services.suricata.agent.obter_topologia", return_value=TOPOLOGIA)
    def test_personalizado_preserva_selecao_explicita(self, _topologia):
        payload = montar_payload_topologia({
            "modo_captura": "personalizado",
            "interfaces_monitoradas": ["dmz0", "lan0", "dmz0"],
        })
        self.assertEqual(payload["interfaces_monitoradas"], ["dmz0", "lan0"])


class TestEstadoSuricata(unittest.TestCase):
    def _estado(self, stack):
        configuracao = SimpleNamespace(
            interfaces_monitoradas=["lan0", "wan0"],
            versao_suricata="7.0.10",
        )
        with patch.object(configuracoes_views, "obter_status_stack_completo", return_value=stack), patch.object(configuracoes_views, "ConfiguracaoSuricata") as model:
            model.objects.filter.return_value.order_by.return_value.first.return_value = configuracao
            return configuracoes_views._estado_suricata({"home_net": ["192.168.52.0/24"]})

    @staticmethod
    def _stack(*, eve=True, monitor=True, worker=True, drift=False):
        return {
            "suricata": {
                "ativo": True,
                "instalado": True,
                "configurado": True,
                "drift": {"tem_drift": drift},
                "versao": "7.0.10",
            },
            "monitor": {
                "ativo": monitor,
                "eve": {"existe": eve, "arquivo": eve, "legivel": eve, "atualizando": False},
                "cursor": {"existe": True, "valido": True},
            },
            "servicos": {"worker_tarefas": {"ativo": worker}},
        }

    def test_sem_drift_em_rede_ociosa_permanece_operacional(self):
        estado = self._estado(self._stack())
        self.assertTrue(estado["eve_ativo"])
        self.assertTrue(estado["saudavel"])
        self.assertEqual(estado["status"], "operacional")
        self.assertEqual(estado["drift"], "Nenhum")

    def test_drift_real_exige_atencao(self):
        estado = self._estado(self._stack(drift=True))
        self.assertFalse(estado["saudavel"])
        self.assertEqual(estado["drift"], "Detectado")

    def test_ausencia_real_do_eve_exige_atencao(self):
        self.assertFalse(self._estado(self._stack(eve=False))["saudavel"])

    def test_monitor_parado_exige_atencao(self):
        self.assertFalse(self._estado(self._stack(monitor=False))["saudavel"])

    def test_worker_parado_exige_atencao(self):
        self.assertFalse(self._estado(self._stack(worker=False))["saudavel"])


class TestProgressoConfiguracao(unittest.TestCase):
    @staticmethod
    def _configuracao():
        return ConfiguracaoSuricataDados(
            interface_wan="wan0",
            interface_lan="lan0",
            interfaces_monitoradas=["lan0", "wan0"],
            home_net=["192.168.52.0/24"],
            modo_captura=ModoCaptura.LAN_WAN,
        )

    @staticmethod
    def _stack_sensor_pronto():
        return {
            "monitor": {"ativo": True, "eve": {"existe": True, "arquivo": True, "legivel": True}},
            "servicos": {"worker_tarefas": {"ativo": True}},
        }

    @patch("incidentes.services.suricata.tarefas.obter_status_stack_completo")
    @patch("incidentes.services.suricata.tarefas.aplicar_configuracao_agent", return_value={"ok": True, "restart": {"ok": True}})
    @patch("incidentes.services.suricata.tarefas.validar_configuracao_agent", return_value={"ok": True})
    @patch("incidentes.services.suricata.tarefas.montar_payload_topologia", return_value=TOPOLOGIA)
    def test_progresso_monotono_e_sucesso_em_100(self, _payload, _validar, _aplicar, status):
        status.return_value = self._stack_sensor_pronto()
        progresso = ProgressoAuditado("progresso-ok", TipoTarefaSuricata.CONFIGURACAO)
        progresso, resultado = executar_tarefa(
            TipoTarefaSuricata.CONFIGURACAO,
            {"configuracao": self._configuracao()},
            progresso=progresso,
        )
        self.assertTrue(resultado.sucesso)
        self.assertEqual(progresso.progresso, 100)
        self.assertEqual(progresso.historico_percentuais, sorted(progresso.historico_percentuais))
        self.assertTrue(all(0 <= valor <= 100 for valor in progresso.historico_percentuais))

    @patch("incidentes.services.suricata.tarefas.validar_configuracao_agent", return_value={"ok": False, "erro": "yaml inválido"})
    @patch("incidentes.services.suricata.tarefas.montar_payload_topologia", return_value=TOPOLOGIA)
    def test_falha_preserva_ultima_etapa_real(self, _payload, _validar):
        progresso = ProgressoAuditado("progresso-erro", TipoTarefaSuricata.CONFIGURACAO)
        progresso, resultado = executar_tarefa(
            TipoTarefaSuricata.CONFIGURACAO,
            {"configuracao": self._configuracao()},
            progresso=progresso,
        )
        self.assertFalse(resultado.sucesso)
        self.assertEqual(progresso.progresso, 40)
        self.assertEqual(progresso.etapa_atual, "validando_configuracao")
