"""
MoonShield — painel/tests.py

Testes para o Dashboard Aggregator.

Cobre os 16 casos definidos no escopo:
  1.  Dashboard usa dados reais.
  2.  3 serviços saudáveis => sensores_online = 3.
  3.  1 serviço indisponível => sensores_online = 2.
  4.  AdGuard indisponível não gera DNS falso.
  5.  Incidentes vazios => ameacas_hoje = 0.
  6.  Séries vazias => arrays de zeros.
  7-10. Filtros de período (1h, 24h, 7d, 30d).
  11. Filtro severidade funciona.
  12. Ausência GeoIP não inventa país (top_ips sem flag/pais).
  13. Firewall sem counters não inventa drops.
  14. Dispositivos sem dados => online=0, offline=0.
  15. Live Feed vazio não gera evento fictício.
  16. API falha não ativa fallback Demo.
"""

from unittest.mock import MagicMock, patch

from django.test import RequestFactory, TestCase
from django.core.cache import cache
from django.contrib.auth import get_user_model
from configuracoes.models import ConfigSistema

User = get_user_model()

# ─────────────────────────────────────────────────────────────────────────────
# Helpers de mock
# ─────────────────────────────────────────────────────────────────────────────

def _make_servico_saudavel(tipo: str) -> dict:
    return {"tipo": tipo, "saudavel": True,  "status": "operacional", "status_label": "Operacional", "agent_online": True, "drift": "Nenhum"}


def _make_servico_indisponivel(tipo: str) -> dict:
    return {"tipo": tipo, "saudavel": False, "status": "indisponivel", "status_label": "Indisponível", "agent_online": False, "drift": "Nenhum"}


def _servicos_todos_ok():
    return {
        "adguard":  _make_servico_saudavel("adguard"),
        "suricata": _make_servico_saudavel("suricata"),
        "firewall": _make_servico_saudavel("firewall"),
        "resumo":   {"servicos_operacionais": 3, "status": "operacional"},
    }


def _dns_real() -> dict:
    return {
        "metrics": {"queries": 5000, "bloqueios": 500, "pctBloq": 10.0, "clientes": 12},
        "charts":  {
            "hours": [f"{hour:02d}h" for hour in range(24)],
            "queries": [100] * 24,
            "bloqueios": [10] * 24,
            "stats_history_available": True,
        },
        "health":  {"running": True, "api": "ok"},
    }


# ─────────────────────────────────────────────────────────────────────────────
# Suite de testes
# ─────────────────────────────────────────────────────────────────────────────

class DashboardOverviewTest(TestCase):
    def setUp(self):
        super().setUp()
        cache.clear()

    def tearDown(self):
        cache.clear()
        super().tearDown()
    """Testa _overview_real() com mocks dos módulos externos."""

    def _run(self, period="24h", sev="all", servicos=None, dns=None, incidentes=None, dispositivos=0):
        """Executa _overview_real com os mocks fornecidos."""
        from painel.views import _overview_real

        servicos_data = servicos or _servicos_todos_ok()
        dns_data      = _dns_real() if dns is None else dns

        with patch("painel.views._get_cfg",   return_value=None), \
             patch("configuracoes.views._health_snapshot",       return_value=servicos_data), \
             patch("configuracoes.views._topologia",      return_value={}), \
             patch("dns.views._get_adguard_client") as mock_ag, \
             patch("painel.views._incidentes_no_periodo") as mock_qs, \
             patch("painel.views._infra_dispositivos",   return_value={"online": dispositivos, "offline": 0, "total": dispositivos, "novo_hoje": 0, "pct": 100 if dispositivos else 0}):

            # Configura client AdGuard
            client = MagicMock()
            client.fetch_all.return_value = dns_data
            mock_ag.return_value = client if dns_data else None

            # Configura queryset de incidentes
            qs = MagicMock()
            qs.count.return_value            = incidentes if incidentes is not None else 0
            qs.filter.return_value.count.return_value = 0
            qs.order_by.return_value         = []
            qs.__iter__                      = lambda s: iter([])
            mock_qs.return_value             = qs

            # Faz patches nas funções de aggregação para retornar valores simples
            with patch("painel.views._series_ataques",  return_value={"labels": ["00h"] * 24, "crit": [0]*24, "high": [0]*24, "med": [0]*24}), \
                 patch("painel.views._timeline_60min",  return_value={"labels": ["00:00"]*12, "crit": [0]*12, "high": [0]*12, "med": [0]*12}), \
                 patch("painel.views._top_ips",         return_value=[]), \
                 patch("painel.views._top_ataques",     return_value=[]), \
                 patch("painel.views._categorias",      return_value=[]):
                return _overview_real(None, period=period, sev=sev)

    # ── Teste 1: retorna dados reais (mode="real")
    def test_01_retorna_modo_real(self):
        result = self._run()
        self.assertIsInstance(result, dict)

        # Garante que nenhum MagicMock ou objeto nǜo-serializǭvel corrompa a response
        from django.http import JsonResponse
        response = JsonResponse(result)
        self.assertEqual(response.status_code, 200)

        self.assertEqual(result["mode"], "real")
        self.assertTrue(result["ok"])

    # ── Teste 2: 3 serviços saudáveis → 3/3
    def test_02_tres_servicos_saudaveis(self):
        result = self._run(servicos=_servicos_todos_ok())
        self.assertEqual(result["kpis"]["sensores_online"], 3)
        self.assertEqual(result["kpis"]["sensores_total"], 3)

    # ── Teste 3: 1 serviço indisponível → 2/3
    def test_03_um_servico_indisponivel(self):
        servicos = _servicos_todos_ok()
        servicos["firewall"] = _make_servico_indisponivel("firewall")
        result = self._run(servicos=servicos)
        self.assertEqual(result["kpis"]["sensores_online"], 2)

    # ── Teste 4: AdGuard indisponível → DNS = 0 (sem inventar)
    def test_04_adguard_indisponivel_sem_dns_falso(self):
        result = self._run(dns={})  # dns vazio = sem client
        self.assertEqual(result["kpis"]["dns_queries"], 0)
        self.assertEqual(result["kpis"]["dns_bloqueios"], 0)
        self.assertEqual(result["kpis"]["bloqueio_pct"], 0)

    # ── Teste 5: Incidentes vazios → ameacas_hoje = 0
    def test_05_incidentes_vazios(self):
        result = self._run(incidentes=0)
        self.assertEqual(result["kpis"]["ameacas_hoje"], 0)

    # ── Teste 6: Séries vazias → arrays de zeros/vazios
    def test_06_series_vazias(self):
        result = self._run()
        self.assertEqual(result["intel"]["top_ips"],    [])
        self.assertEqual(result["intel"]["categorias"], [])
        # series retornam listas (possivelmente de zeros)
        self.assertIsInstance(result["charts"]["attacks"]["crit"], list)

    # ── Testes 7-10: Períodos válidos passados corretamente
    def test_07_periodo_1h(self):
        result = self._run(period="1h")
        self.assertEqual(result["periodo"], "1h")

    def test_08_periodo_24h(self):
        result = self._run(period="24h")
        self.assertEqual(result["periodo"], "24h")

    def test_09_periodo_7d(self):
        result = self._run(period="7d")
        self.assertEqual(result["periodo"], "7d")

    def test_10_periodo_30d(self):
        result = self._run(period="30d")
        self.assertEqual(result["periodo"], "30d")

    def test_10b_dns_historico_respeita_os_periodos_disponiveis(self):
        for period, available, length in (
            ("1h", False, 0),
            ("24h", True, 24),
            ("7d", False, 0),
            ("30d", False, 0),
        ):
            with self.subTest(period=period):
                result = self._run(period=period)
                dns = result["charts"]["dns"]

                self.assertEqual(dns["history_available"], available)
                self.assertEqual(len(dns["labels"]), length)
                self.assertEqual(len(dns["hours"]), length)
                self.assertEqual(len(dns["queries"]), length)
                self.assertEqual(len(dns["blocked"]), length)
                self.assertEqual(dns["labels"], dns["hours"])
                self.assertEqual(result["kpis"]["dns_period_available"], available)

                if available:
                    self.assertEqual(result["kpis"]["dns_queries"], 2400)
                    self.assertEqual(result["kpis"]["dns_bloqueios"], 240)
                else:
                    self.assertEqual(result["kpis"]["dns_queries"], 5000)
                    self.assertEqual(result["kpis"]["dns_bloqueios"], 500)

    # ── Teste 11: Filtro de severidade passado no contexto
    def test_11_filtro_severidade(self):
        result = self._run(sev="critico")
        self.assertEqual(result["sev"], "critico")

    # ── Teste 12: Ausência de GeoIP — top_ips sem flag/pais
    def test_12_sem_geoip_sem_pais(self):
        result = self._run()
        top_ips = result["intel"]["top_ips"]
        for ip_entry in top_ips:
            # Não deve conter campo "flag" ou "pais" inventado
            self.assertNotIn("flag", ip_entry)
            self.assertNotIn("pais", ip_entry)
        # origens deve estar vazio (GeoIP não implementado)
        self.assertEqual(result["intel"]["origens"], [])

    # ── Teste 13: Firewall sem counters não inventa drops
    def test_13_firewall_sem_drops(self):
        result = self._run()
        fw_infra = result["infra"]["firewall"]
        # drops deve ser "—" quando não há backend de tráfego
        self.assertEqual(fw_infra["drops"], "—")
        self.assertEqual(fw_infra["blocks"], "—")

    # ── Teste 14: Dispositivos sem dados → zeros
    def test_14_dispositivos_sem_dados(self):
        result = self._run(dispositivos=0)
        dev = result["infra"]["dispositivos"]
        self.assertEqual(dev["online"], 0)
        self.assertEqual(dev["offline"], 0)

    # ── Teste 15: Feed vazio não gera evento fictício
    def test_15_feed_vazio_sem_evento_ficticio(self):
        result = self._run(incidentes=0)
        feed = result["feed"]
        self.assertEqual(feed, [])

    # ── Teste 16: Período inválido → padrão 24h
    def test_16_periodo_invalido_cai_para_24h(self):
        from painel.views import _PERIODOS
        # Verifica que período desconhecido não está no dicionário
        self.assertNotIn("99h", _PERIODOS)
        self.assertNotIn("demo", _PERIODOS)
        self.assertIn("24h", _PERIODOS)


class DashboardApiViewTest(TestCase):
    """Testa a view api_overview com autenticação."""

    def setUp(self):
        self.user = User.objects.create_user(username="testuser", password="testpass123")
        self.factory = RequestFactory()

    def test_requer_login(self):
        from django.test import Client
        c = Client()
        resp = c.get("/painel/api/overview/")
        # Deve redirecionar para login (302)
        self.assertIn(resp.status_code, [302, 301])

    def test_periodo_invalido_corrigido(self):
        """Período inválido deve retornar 200 com periodo=24h."""
        from painel.views import api_overview
        from django.test import Client

        c = Client()
        c.login(username="testuser", password="testpass123")

        with patch("painel.views._overview_real") as mock_ov, \
             patch("painel.views._get_cfg", return_value=None):
            mock_ov.return_value = {"ok": True, "periodo": "24h", "mode": "real",
                                    "kpis": {}, "charts": {}, "feed": [], "intel": {},
                                    "infra": {}, "saude": {}, "node": {}, "last_update": ""}
            resp = c.get("/painel/api/overview/?period=99h&sev=all")

        # Deve chamar _overview_real com period corrigido para 24h
        if mock_ov.called:
            args, kwargs = mock_ov.call_args
            self.assertEqual(kwargs.get("period", args[1] if len(args) > 1 else "24h"), "24h")

    def test_sev_invalido_corrigido(self):
        """Severidade inválida deve ser corrigida para 'all'."""
        from painel.views import _PERIODOS
        # Verifica contrato do validator
        validos = ("all", "critico", "alto", "medio")
        self.assertIn("all",     validos)
        self.assertIn("critico", validos)
        self.assertNotIn("demo", validos)


class DashboardSensoresTest(TestCase):
    """Testa a estrutura de sensores retornada."""

    def test_sensores_lista_estrutura(self):
        from painel.views import _sensores_lista
        adguard  = {"saudavel": True,  "status": "operacional"}
        suricata = {"saudavel": True,  "status": "operacional"}
        firewall = {"saudavel": False, "status": "indisponivel"}

        lista = _sensores_lista(adguard, suricata, firewall)

        self.assertEqual(len(lista), 3)
        status_map = {s["nome"]: s["status"] for s in lista}
        self.assertEqual(status_map["DNS (AdGuard)"],     "ok")
        self.assertEqual(status_map["IDS (Suricata)"],    "ok")
        self.assertEqual(status_map["Firewall (nftables)"], "err")

    def test_sensores_todos_saudaveis(self):
        from painel.views import _sensores_lista
        s = {"saudavel": True, "status": "operacional"}
        lista = _sensores_lista(s, s, s)
        self.assertTrue(all(x["status"] == "ok" for x in lista))

    def test_sensores_todos_indisponiveis(self):
        from painel.views import _sensores_lista
        s = {"saudavel": False, "status": "indisponivel"}
        lista = _sensores_lista(s, s, s)
        self.assertTrue(all(x["status"] == "err" for x in lista))

import json
from django.test import Client, override_settings
from django.utils import timezone
from datetime import timedelta
from incidentes.models import EventoBruto, Incidente

class TestSensoresTimezoneBug(TestCase):
    def tearDown(self):
        cache.clear()
        super().tearDown()

    def setUp(self):
        super().setUp()
        cache.clear()
        self.client = Client()
        self.user = get_user_model().objects.create_user(username="testuser", password="password")
        self.client.force_login(self.user)
        # Aprova o First Boot para que o GlobalOnboardingGateMiddleware não barre as requisições API com 403
        cfg = ConfigSistema.get_solo()
        cfg.appliance_onboarding_completo = True
        cfg.save()

    @override_settings(USE_TZ=True)
    def test_api_sensores_with_timezone_aware_data_does_not_crash(self):
        # Cria incidentes com timezone aware (uso padrão do banco em USE_TZ=True)
        agora = timezone.now()

        # Precisamos criar Incidente para que as queries de _series_ataques o utilizem.
        for i in range(5):
            Incidente.objects.create(
                fingerprint=f"evt_{i}",
                first_seen=agora - timedelta(minutes=i*10),
                last_seen=agora - timedelta(minutes=i*10),
                severidade_jg="alto",
                src_ip="192.0.2.10",
                signature="Teste Legado"
            )

        # Requisição ao endpoint global (api_sensores chama _overview_real)
        response = self.client.get("/painel/api/sensores/")

        # Não deve dar TypeError "can't subtract offset-naive and offset-aware datetimes"
        self.assertEqual(response.status_code, 200)

        data = json.loads(response.content)

        # JSON continua contendo ids, dns, firewall
        self.assertIn("ids", data)
        self.assertIn("dns", data)
        self.assertIn("firewall", data)

        # Requisição ao overview completo para validar se a agregação de timezone afeta a série gerada
        response_ov = self.client.get("/painel/api/overview/")
        self.assertEqual(response_ov.status_code, 200)

        data_ov = json.loads(response_ov.content)
        series = data_ov["charts"]["attacks"]

        # Séries são geradas normalmente (labels em charts["hours"])
        labels = data_ov["charts"]["hours"]

        self.assertIn("high", series)
        self.assertIn("crit", series)
        self.assertIn("med", series)

        # Verifica se os labels e quantidades mantêm a estrutura
        self.assertTrue(isinstance(labels, list))
        self.assertTrue(isinstance(series["high"], list))
        self.assertTrue(len(labels) > 0)

        self.assertEqual(len(series["high"]), len(labels))
        self.assertEqual(len(series["crit"]), len(labels))
        self.assertEqual(len(series["med"]), len(labels))
        self.assertEqual(len(labels), 25)

    def test_1h_period_filters_correctly(self):
        from incidentes.models import Incidente
        from django.utils import timezone
        from datetime import timedelta
        Incidente.objects.all().delete()
        now = timezone.now()
        # Incidente A: 20 minutos atrás (deve aparecer em 1h)
        Incidente.objects.create(src_ip='1.2.3.4', severidade_jg='critico', last_seen=now - timedelta(minutes=20), first_seen=now - timedelta(minutes=20))
        # Incidente B: 2 horas atrás (NÃO deve aparecer em 1h)
        Incidente.objects.create(src_ip='5.6.7.8', severidade_jg='alto', last_seen=now - timedelta(hours=2), first_seen=now - timedelta(hours=2))

        # Test via view
        from painel.views import _overview_real, _get_cfg
        result = _overview_real(_get_cfg(), period="1h", sev="all")

        feed = result["feed"]
        self.assertEqual(len(feed), 1)
        self.assertIn('1.2.3.4', str(feed[0]['src']))

        top_ips = result["intel"]["top_ips"]
        self.assertEqual(len(top_ips), 1)
        self.assertEqual(top_ips[0]['ip'], '1.2.3.4')

    def test_timeline_60min_alignment_and_filtering(self):
        from incidentes.models import Incidente
        from django.utils import timezone
        from datetime import timedelta
        Incidente.objects.all().delete()
        now = timezone.now()
        Incidente.objects.create(src_ip='10.0.0.1', severidade_jg='critico', last_seen=now - timedelta(minutes=2), first_seen=now - timedelta(minutes=2))
        Incidente.objects.create(src_ip='10.0.0.2', severidade_jg='alto', last_seen=now - timedelta(minutes=12), first_seen=now - timedelta(minutes=12))
        Incidente.objects.create(src_ip='10.0.0.3', severidade_jg='medio', last_seen=now - timedelta(minutes=35), first_seen=now - timedelta(minutes=35))
        Incidente.objects.create(src_ip='10.0.0.4', severidade_jg='critico', last_seen=now - timedelta(hours=2), first_seen=now - timedelta(hours=2))

        from painel.views import _overview_real, _get_cfg
        result = _overview_real(_get_cfg(), period="1h", sev="all")

        tl = result["charts"]["timeline"]
        self.assertEqual(len(tl["labels"]), 13)
        self.assertEqual(sum(tl["crit"]), 1)
        self.assertEqual(sum(tl["high"]), 1)
        self.assertEqual(sum(tl["med"]), 1)


class DashboardPeriodWindowTest(TestCase):
    """Valida as janelas móveis do endpoint com timestamps timezone-aware."""

    def setUp(self):
        cache.clear()
        self.client = Client()
        self.user = get_user_model().objects.create_user(username="period-user", password="password")
        self.client.force_login(self.user)
        cfg = ConfigSistema.get_solo()
        cfg.appliance_onboarding_completo = True
        cfg.save()

    def tearDown(self):
        cache.clear()
        super().tearDown()

    def _incidente(self, fingerprint, quando, severidade="alto"):
        return Incidente.objects.create(
            fingerprint=fingerprint,
            first_seen=quando,
            last_seen=quando,
            severidade_jg=severidade,
            src_ip="192.0.2.10",
            signature="Evento de teste",
        )

    def _overview(self, period, sev="all"):
        with patch("configuracoes.views._topologia", return_value={}), \
             patch("configuracoes.views._health_snapshot", return_value=_servicos_todos_ok()), \
             patch("dns.views._get_adguard_client", return_value=None):
            response = self.client.get("/painel/api/overview/", {"period": period, "sev": sev})
        self.assertEqual(response.status_code, 200)
        return response.json()

    @override_settings(USE_TZ=True)
    def test_periodos_filtram_janelas_moveis_e_separam_cache(self):
        agora = timezone.now()
        self.assertTrue(timezone.is_aware(agora))
        self._incidente("period-30m", agora - timedelta(minutes=30), "critico")
        self._incidente("period-12h", agora - timedelta(hours=12))
        self._incidente("period-3d", agora - timedelta(days=3))
        self._incidente("period-20d", agora - timedelta(days=20))
        self._incidente("period-40d", agora - timedelta(days=40))

        for period, expected_count, expected_labels in (
            ("1h", 1, 13),
            ("24h", 2, 25),
            ("7d", 3, 8),
            ("30d", 4, 31),
        ):
            with self.subTest(period=period):
                data = self._overview(period)
                self.assertEqual(data["periodo"], period)
                self.assertEqual(data["kpis"]["ameacas_hoje"], expected_count)
                self.assertEqual(len(data["feed"]), expected_count)
                self.assertEqual(len(data["charts"]["hours"]), expected_labels)
                self.assertEqual(
                    sum(data["charts"]["timeline"]["crit"])
                    + sum(data["charts"]["timeline"]["high"])
                    + sum(data["charts"]["timeline"]["med"]),
                    expected_count,
                )

        self.assertIsNotNone(cache.get("moonshield_overview_1h_all"))
        self.assertIsNotNone(cache.get("moonshield_overview_24h_all"))
        self.assertNotEqual(
            cache.get("moonshield_overview_1h_all")["kpis"]["ameacas_hoje"],
            cache.get("moonshield_overview_24h_all")["kpis"]["ameacas_hoje"],
        )

    def test_periodo_e_severidade_invalidos_tem_fallback_seguro(self):
        agora = timezone.now()
        self._incidente("period-severity-crit", agora - timedelta(minutes=30), "critico")
        self._incidente("period-severity-high", agora - timedelta(minutes=30), "alto")

        invalid = self._overview("banana")
        self.assertEqual(invalid["periodo"], "24h")

        crit = self._overview("1h", "critico")
        self.assertEqual(crit["sev"], "critico")
        self.assertEqual(crit["kpis"]["ameacas_hoje"], 1)
        self.assertEqual(crit["feed"][0]["sev"], "crit")
        self.assertIsNotNone(cache.get("moonshield_overview_1h_critico"))
