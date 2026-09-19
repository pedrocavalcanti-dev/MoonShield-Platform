import json
import uuid
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from unittest.mock import patch

from rede.services.agent_client import AgentTimeoutErro, AgentIndisponivelErro, AgentOperacaoRecusadaErro
from relatorios.models import ExecucaoDiagnostico

from configuracoes.models import ConfigSistema

User = get_user_model()

class RelatoriosDiagnosticoTests(TestCase):
    def setUp(self):
        self.client = Client()

        # Bypass GlobalOnboardingGateMiddleware
        config = ConfigSistema.get_solo()
        config.appliance_onboarding_completo = True
        config.save()

        self.user = User.objects.create_user(username="testuser", password="testpassword")
        self.client.login(username="testuser", password="testpassword")
        self.contexto_url = reverse("relatorios:api_contexto")
        self.executar_url = reverse("relatorios:api_executar")
        self.historico_url = reverse("relatorios:api_historico")

    def test_contexto_auth_required(self):
        self.client.logout()
        response = self.client.get(self.contexto_url)
        self.assertNotEqual(response.status_code, 200)

    @patch("relatorios.views.obter_topologia")
    @patch("relatorios.views.agent_disponivel")
    def test_contexto_dados_reais_mockados(self, mock_disponivel, mock_topologia):
        mock_disponivel.return_value = True
        mock_topologia.return_value = {
            "wan": {"principal": {"nome": "enp0s3", "desejado": {"papel": "wan", "gateway": "192.168.0.1"}, "real": {"ipv4": "192.168.0.106", "prefixo": "24", "gateway": "192.168.0.1"}}},
            "lan": {"principal": {"nome": "enp0s8", "desejado": {"papel": "lan"}, "real": {"ipv4": "10.10.0.1", "prefixo": "24"}}}
        }
        config = ConfigSistema.get_solo()
        config.node_name = "MoonShield-Test"
        config.save()

        response = self.client.get(self.contexto_url)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["agent"], "online")
        self.assertEqual(data["wan_iface"], "enp0s3")
        self.assertEqual(data["wan_cidr"], "192.168.0.106/24")
        self.assertEqual(data["lan_iface"], "enp0s8")
        self.assertEqual(data["lan_cidr"], "10.10.0.1/24")
        self.assertEqual(data["gateway"], "192.168.0.1")
        self.assertEqual(data["hostname"], "MoonShield-Test")

    @patch("relatorios.views.obter_topologia")
    @patch("relatorios.views.agent_disponivel")
    def test_contexto_estrutura_antiga_falharia(self, mock_disponivel, mock_topologia):
        mock_disponivel.return_value = True
        # Topologia usando apenas as chaves reais "nome" e "real", sem "desejado"
        mock_topologia.return_value = {
            "wan": {"principal": {"nome": "enp0s3", "real": {"ipv4": "192.168.1.100", "prefixo": "24", "gateway": "192.168.1.1"}}}
        }

        response = self.client.get(self.contexto_url)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["wan_iface"], "enp0s3")
        self.assertEqual(data["wan_cidr"], "192.168.1.100/24")
        self.assertEqual(data["gateway"], "192.168.1.1")
        self.assertEqual(data["gateway"], "192.168.1.1")
        self.assertEqual(data["dns1"], "8.8.8.8")
        self.assertEqual(data["dns2"], "1.1.1.1")

    @patch("relatorios.services.diagnostico_agent.agent_disponivel")
    def test_agent_offline(self, mock_disponivel):
        mock_disponivel.return_value = False
        payload = {"tool": "ping", "target": "8.8.8.8", "source": "quick"}
        response = self.client.post(self.executar_url, json.dumps(payload), content_type="application/json")
        self.assertEqual(response.status_code, 503)
        data = response.json()
        self.assertEqual(data["error_code"], "agent_unavailable")
        self.assertEqual(ExecucaoDiagnostico.objects.count(), 1)
        ex = ExecucaoDiagnostico.objects.first()
        self.assertEqual(ex.status, "err")

    @patch("relatorios.services.diagnostico_agent.requisitar_agent")
    @patch("relatorios.services.diagnostico_agent.agent_disponivel")
    def test_execucao_ping_sucesso(self, mock_disponivel, mock_req):
        mock_disponivel.return_value = True
        mock_req.return_value = {
            "dados": {
                "ok": True,
                "status": "ok",
                "summary": "Ping ok",
                "stdout": "...",
                "stderr": "",
                "structured": {"sent": 4, "received": 4},
                "meta": {"duration_ms": 100, "exit_code": 0}
            }
        }
        payload = {"tool": "ping", "target": "8.8.8.8", "source": "guided"}
        response = self.client.post(self.executar_url, json.dumps(payload), content_type="application/json")
        self.assertEqual(response.status_code, 200)

        ex = ExecucaoDiagnostico.objects.first()
        self.assertEqual(ex.ferramenta, "ping")
        self.assertEqual(ex.alvo, "8.8.8.8")
        self.assertEqual(ex.status, "ok")
        self.assertEqual(ex.origem, "guided")

    def test_executar_tool_invalida(self):
        payload = {"tool": "invalid_tool", "target": "8.8.8.8"}
        response = self.client.post(self.executar_url, json.dumps(payload), content_type="application/json")
        self.assertEqual(response.status_code, 400)

    def test_executar_source_invalido(self):
        payload = {"tool": "ping", "target": "8.8.8.8", "source": "invalid_source"}
        response = self.client.post(self.executar_url, json.dumps(payload), content_type="application/json")
        self.assertEqual(response.status_code, 400)

    @patch("relatorios.services.diagnostico_agent.requisitar_agent")
    @patch("relatorios.services.diagnostico_agent.agent_disponivel")
    def test_executar_targetless_tool_sucesso(self, mock_disponivel, mock_req):
        mock_disponivel.return_value = True
        mock_req.return_value = {
            "dados": {
                "ok": True,
                "status": "ok",
                "summary": "Sucesso",
                "structured": {"routes": []}
            }
        }
        for tool in ["routes", "interfaces", "arp_table", "sockets"]:
            payload = {"tool": tool, "target": ""}
            response = self.client.post(self.executar_url, json.dumps(payload), content_type="application/json")
            self.assertEqual(response.status_code, 200, f"Tool {tool} falhou com HTTP {response.status_code}")
            resp_data = json.loads(response.content)
            self.assertTrue(resp_data.get("ok"))

    def test_executar_targeted_tool_sem_target_rejeitado(self):
        for tool in ["ping", "mtr", "tcp_connect"]:
            payload = {"tool": tool, "target": ""}
            response = self.client.post(self.executar_url, json.dumps(payload), content_type="application/json")
            self.assertEqual(response.status_code, 400)
            resp_data = json.loads(response.content)
            self.assertFalse(resp_data.get("ok"))
            self.assertEqual(resp_data.get("error_code"), "validation_error")

    @patch("relatorios.services.diagnostico_agent.requisitar_agent")
    @patch("relatorios.services.diagnostico_agent.agent_disponivel")
    def test_output_truncation(self, mock_disponivel, mock_req):
        mock_disponivel.return_value = True
        large_str = "A" * (257 * 1024)
        mock_req.return_value = {
            "dados": {
                "ok": True,
                "status": "ok",
                "stdout": large_str,
                "stderr": large_str
            }
        }
        payload = {"tool": "ping", "target": "8.8.8.8"}
        response = self.client.post(self.executar_url, json.dumps(payload), content_type="application/json")

        ex = ExecucaoDiagnostico.objects.first()
        self.assertTrue(ex.stdout.endswith("... (TRUNCATED)"))
        self.assertTrue(len(ex.stdout) < 260 * 1024)
        data = response.json()
        self.assertTrue(data["meta"]["output_truncated"])

    def test_historico_e_filtros(self):
        ExecucaoDiagnostico.objects.create(ferramenta="ping", alvo="8.8.8.8", status="ok", origem="guided")
        ExecucaoDiagnostico.objects.create(ferramenta="mtr", alvo="1.1.1.1", status="err", origem="quick")

        # Sem filtro
        resp = self.client.get(self.historico_url)
        self.assertEqual(resp.json()["total"], 2)

        # Filtro tool
        resp = self.client.get(self.historico_url + "?tool=mtr")
        self.assertEqual(resp.json()["total"], 1)
        self.assertEqual(resp.json()["items"][0]["tool"], "mtr")

        # Filtro status
        resp = self.client.get(self.historico_url + "?status=ok")
        self.assertEqual(resp.json()["total"], 1)
        self.assertEqual(resp.json()["items"][0]["status"], "ok")

    def test_detalhe_existente(self):
        ex = ExecucaoDiagnostico.objects.create(ferramenta="ping", alvo="8.8.8.8", opcoes={"password": "123"})
        url = reverse("relatorios:api_execucao", args=[str(ex.id)])
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["options"]["password"], "******")

    def test_detalhe_inexistente(self):
        url = reverse("relatorios:api_execucao", args=[str(uuid.uuid4())])
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 404)

    def test_execucao_detalhe_source(self):
        ex = ExecucaoDiagnostico.objects.create(
            usuario=self.user,
            ferramenta="ping",
            alvo="8.8.8.8",
            origem="terminal",
            status="ok",
            resumo="OK",
            duration_ms=10,
        )
        url = reverse("relatorios:api_execucao", args=[str(ex.id)])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["source"], "terminal")
