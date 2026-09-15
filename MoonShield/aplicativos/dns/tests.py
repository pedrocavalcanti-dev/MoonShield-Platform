import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from configuracoes import views as configuracoes_views
from dns.services import adguard_bootstrap
from dns.services.adguard_bootstrap import (
    _configuracao_desejada,
    _garantir_permissoes_configuracao,
    _reconciliar_yaml,
    AdGuardBootstrapError,
    CaminhosAdGuard,
    detectar_conflitos_porta_dns,
    garantir_secret,
    _hosts_dns_iniciais,
    inventariar_interfaces_dns,
    obter_porta_admin,
    obter_url_admin,
    provisionar_adguard,
    upstreams_aprovados,
)
from dns.services.adguard_client import AdGuardClient, AdGuardError, AdGuardHTTPError


TOPOLOGIA_DNS = {
    "wan": {"interfaces": [{"nome": "wan0", "desejado": {"habilitada": True}, "real": {"ipv4": "203.0.113.2"}}]},
    "lan": {"interfaces": [{"nome": "lan0", "desejado": {"habilitada": True}, "real": {"enderecos_ipv4": ["192.168.52.1"]}}]},
    "mgmt": {"interfaces": [{"nome": "mgmt0", "desejado": {"habilitada": True}, "real": {"ipv4": "198.51.100.2"}}]},
    "dmz": [{"nome": "dmz0", "desejado": {"habilitada": True}, "real": {"ipv4": "172.16.0.1"}}],
    "custom": [{"nome": "custom0", "desejado": {"habilitada": True}, "real": {"ipv4": "10.1.0.1"}}],
    "unassigned": [{"nome": "extra0", "desejado": {"habilitada": True}, "real": {}}],
}


class TestSecretAdGuard(unittest.TestCase):
    def test_secret_e_criado_uma_vez_e_reutilizado_com_permissao_restrita(self):
        with tempfile.TemporaryDirectory() as diretorio:
            caminho = Path(diretorio) / "secrets" / "adguard"
            primeiro = garantir_secret(caminho, grupo=None)
            segundo = garantir_secret(caminho, grupo=None)

            self.assertEqual(primeiro, segundo)
            self.assertEqual(primeiro["username"], "moonshield")
            self.assertEqual(stat.S_IMODE(caminho.stat().st_mode), 0o640)

    def test_secret_invalido_nao_e_regenerado(self):
        with tempfile.TemporaryDirectory() as diretorio:
            caminho = Path(diretorio) / "adguard"
            caminho.write_text('{"username":"moonshield","password":"curta"}', encoding="utf-8")
            caminho.chmod(0o640)
            with self.assertRaises(AdGuardBootstrapError):
                garantir_secret(caminho, grupo=None)


class TestClienteAdGuard(unittest.TestCase):
    def test_cliente_local_usa_basic_auth_e_url_administrativa_com_porta(self):
        client = AdGuardClient("127.0.0.1:3000", "moonshield", "segredo-aleatorio")
        session = client._new_session()
        self.assertEqual(client.base_url, "http://127.0.0.1:3000")
        self.assertEqual(session.auth, ("moonshield", "segredo-aleatorio"))
        self.assertTrue(session.verify)

    def test_url_admin_vem_do_yaml_local(self):
        with tempfile.TemporaryDirectory() as diretorio:
            raiz = Path(diretorio)
            yaml = raiz / "AdGuardHome.yaml"
            yaml.write_text("http:\n  address: 127.0.0.1:3100\n", encoding="utf-8")
            paths = CaminhosAdGuard(raiz / "AdGuardHome", raiz, yaml, raiz / "data")
            self.assertEqual(obter_url_admin(paths), "http://127.0.0.1:3100")
            self.assertEqual(obter_porta_admin(paths), 3100)


class TestInventarioDNS(unittest.TestCase):
    def test_inventario_ativa_todos_os_papeis_habilitados_com_ipv4(self):
        inventario = inventariar_interfaces_dns(TOPOLOGIA_DNS)
        self.assertEqual(
            {item["nome"] for item in inventario["interfaces_disponiveis"]},
            {"wan0", "lan0", "mgmt0", "dmz0", "custom0", "extra0"},
        )
        self.assertEqual(
            [item["nome"] for item in inventario["interfaces_dns_ativas"]],
            ["wan0", "lan0", "mgmt0", "dmz0", "custom0"],
        )
        self.assertEqual(
            _hosts_dns_iniciais(inventario),
            ["127.0.0.1", "203.0.113.2", "192.168.52.1", "198.51.100.2", "172.16.0.1", "10.1.0.1"],
        )

    def test_politica_nao_hardcoda_interfaces_de_laboratorio(self):
        codigo = Path(adguard_bootstrap.__file__).read_text(encoding="utf-8")
        self.assertNotIn("enp0s", codigo)

    @patch("dns.services.adguard_bootstrap._listeners_porta_53")
    def test_conflito_porta_53_e_detectado(self, listeners):
        listeners.return_value = (True, ['udp UNCONN 0 0 127.0.0.53:53 users:(("systemd-resolved",pid=1))'])
        conflitos = detectar_conflitos_porta_dns()
        self.assertEqual(len(conflitos), 1)
        self.assertIn("systemd-resolved", conflitos[0])

    @patch("dns.services.adguard_bootstrap._listeners_porta_53")
    def test_listener_do_proprio_adguard_nao_e_conflito(self, listeners):
        listeners.return_value = (True, ['udp UNCONN 0 0 *:53 users:(("AdGuardHome",pid=1))'])
        self.assertEqual(detectar_conflitos_porta_dns(), [])


class TestProvisionamentoAdGuard(unittest.TestCase):
    def _paths(self):
        raiz = Path("/opt/AdGuardHome")
        return CaminhosAdGuard(raiz / "AdGuardHome", raiz, raiz / "AdGuardHome.yaml", raiz / "data")

    @patch("dns.services.adguard_bootstrap._garantir_permissoes_configuracao")
    @patch("dns.services.adguard_bootstrap.detectar_conflitos_porta_dns", return_value=[])
    @patch("dns.services.adguard_bootstrap.garantir_secret", return_value={"username": "moonshield", "password": "segredo-unico"})
    @patch("dns.services.adguard_bootstrap.descobrir_adguard")
    @patch("dns.services.adguard_bootstrap.AdGuardClient")
    @patch("dns.services.adguard_bootstrap._reconciliar_yaml", return_value=True)
    @patch("dns.services.adguard_bootstrap.validar_resolucao_dns", return_value={"resolver_ok": True, "upstream_ok": True})
    def test_fresh_install_usa_api_sem_html_e_nao_expoe_secret(self, _dns, _yaml, client_class, descobrir, _secret, _conflitos, permissoes):
        descobrir.return_value = self._paths()
        client = client_class.return_value
        client.get_status.side_effect = [
            AdGuardHTTPError(status_code=404, url="http://127.0.0.1:3000/control/status"),
            {"running": True, "dns_addresses": ["127.0.0.1", "203.0.113.2", "192.168.52.1", "198.51.100.2", "172.16.0.1", "10.1.0.1"]},
            {"running": True, "dns_addresses": ["127.0.0.1", "203.0.113.2", "192.168.52.1", "198.51.100.2", "172.16.0.1", "10.1.0.1"]},
        ]
        client.verificar_configuracao_inicial.return_value = {"web": {"status": ""}, "dns": {"status": ""}}
        client.get_dns_info.return_value = {"protection_enabled": True, "port": 53}
        controles = []

        resultado = provisionar_adguard(
            topologia=TOPOLOGIA_DNS,
            controlar_servico=controles.append,
            servico_ativo=lambda _nome: False,
        )

        self.assertIn(["enable", "AdGuardHome.service"], controles)
        self.assertIn(["start", "AdGuardHome.service"], controles)
        client.configurar_instalacao.assert_called_once()
        payload = client.configurar_instalacao.call_args.args[0]
        self.assertEqual(payload["web"], {"ip": "127.0.0.1", "port": 3000})
        self.assertEqual(payload["dns"]["ip"], "203.0.113.2")
        self.assertNotIn("segredo-unico", str(resultado))
        self.assertGreaterEqual(permissoes.call_count, 3)

    @patch("dns.services.adguard_bootstrap._garantir_permissoes_configuracao")
    @patch("dns.services.adguard_bootstrap.garantir_secret", return_value={"username": "moonshield", "password": "segredo-unico"})
    @patch("dns.services.adguard_bootstrap.descobrir_adguard")
    def test_sem_interfaces_com_ipv4_retorna_aguardando_topologia(self, descobrir, _secret, _permissoes):
        descobrir.return_value = self._paths()
        topologia = {
            papel: {"interfaces": [{"nome": f"{papel}0", "desejado": {"habilitada": True}, "real": {}}]}
            for papel in ("wan", "lan", "mgmt", "dmz", "custom", "unassigned")
        }
        resultado = provisionar_adguard(
            topologia=topologia,
            controlar_servico=MagicMock(),
            servico_ativo=lambda _nome: False,
        )
        self.assertEqual(resultado["estado"], "aguardando_topologia")
        self.assertFalse(resultado["setup_realizado"])

    @patch("dns.services.adguard_bootstrap._garantir_permissoes_configuracao")
    @patch("dns.services.adguard_bootstrap.detectar_conflitos_porta_dns", return_value=[])
    @patch("dns.services.adguard_bootstrap.garantir_secret", return_value={"username": "moonshield", "password": "segredo-unico"})
    @patch("dns.services.adguard_bootstrap.descobrir_adguard")
    @patch("dns.services.adguard_bootstrap.AdGuardClient")
    @patch("dns.services.adguard_bootstrap._reconciliar_yaml", return_value=False)
    @patch("dns.services.adguard_bootstrap.validar_resolucao_dns", return_value={"resolver_ok": True, "upstream_ok": True})
    def test_execucao_repetida_preserva_setup_e_customizacoes(self, _dns, _yaml, client_class, descobrir, _secret, _conflitos, _permissoes):
        descobrir.return_value = self._paths()
        client = client_class.return_value
        client.get_status.return_value = {"running": True, "dns_addresses": ["127.0.0.1", "203.0.113.2", "192.168.52.1", "198.51.100.2", "172.16.0.1", "10.1.0.1"]}
        client.get_dns_info.return_value = {"protection_enabled": True, "port": 53, "upstream_dns": ["https://existente/dns-query"]}

        resultado = provisionar_adguard(
            topologia=TOPOLOGIA_DNS,
            controlar_servico=MagicMock(),
            servico_ativo=lambda _nome: True,
        )

        self.assertFalse(resultado["setup_realizado"])
        client.configurar_instalacao.assert_not_called()
        client.get_dns_info.assert_called_once()

    @patch("dns.services.adguard_bootstrap._garantir_permissoes_configuracao")
    @patch("dns.services.adguard_bootstrap.time.sleep")
    @patch("dns.services.adguard_bootstrap.detectar_conflitos_porta_dns", return_value=[])
    @patch("dns.services.adguard_bootstrap.garantir_secret", return_value={"username": "moonshield", "password": "segredo-unico"})
    @patch("dns.services.adguard_bootstrap.descobrir_adguard")
    @patch("dns.services.adguard_bootstrap.AdGuardClient")
    @patch("dns.services.adguard_bootstrap._reconciliar_yaml")
    @patch("dns.services.adguard_bootstrap.validar_resolucao_dns", return_value={"resolver_ok": True})
    def test_reconcile_aguarda_api_apos_restart(self, _dns, reconciliar, client_class, descobrir, _secret, _conflitos, dormir, _permissoes):
        descobrir.return_value = self._paths()
        client = client_class.return_value
        status = {"running": True, "dns_addresses": ["127.0.0.1", "203.0.113.2", "192.168.52.1", "198.51.100.2", "172.16.0.1", "10.1.0.1"]}
        client.get_status.side_effect = [status, AdGuardError("connection refused"), status, status, status]
        client.get_dns_info.return_value = {"protection_enabled": True, "port": 53, "upstream_dns": ["https://cloudflare-dns.com/dns-query"]}
        client.testar_upstreams_dns.return_value = {"https://cloudflare-dns.com:443/dns-query": "OK"}
        reconciliar.side_effect = lambda **kwargs: (kwargs["validar_apos_inicio"]() or True)

        resultado = provisionar_adguard(
            topologia=TOPOLOGIA_DNS,
            controlar_servico=MagicMock(),
            servico_ativo=lambda _nome: True,
        )

        self.assertTrue(resultado["reconciliado"])
        dormir.assert_called_once_with(0.25)


class TestMigracaoYamlAdGuard(unittest.TestCase):
    @patch("dns.services.adguard_bootstrap._senha_confere", return_value=False)
    @patch("dns.services.adguard_bootstrap._bcrypt", return_value="$2y$10$hash-novo")
    def test_legacy_preserva_outros_usuarios_e_upstreams(self, _bcrypt, _confere):
        with tempfile.TemporaryDirectory() as diretorio:
            raiz = Path(diretorio)
            yaml = raiz / "AdGuardHome.yaml"
            yaml.write_text(
                "http:\n  address: 0.0.0.0:3000\n"
                "dns:\n  bind_hosts:\n    - 0.0.0.0\n  upstream_dns:\n    - https://dns10.quad9.net/dns-query\n"
                "users:\n  - name: moonshield\n    password: $2y$10$antigo\n  - name: operador\n    password: $2y$10$preservado\n",
                encoding="utf-8",
            )
            paths = CaminhosAdGuard(raiz / "AdGuardHome", raiz, yaml, raiz / "data")
            _, desejado = _configuracao_desejada(paths, "segredo-unico", ["127.0.0.1", "192.168.52.1"])

        self.assertIn("address: 127.0.0.1:3000", desejado)
        self.assertIn("    - 192.168.52.1", desejado)
        self.assertIn("https://dns10.quad9.net/dns-query", desejado)
        self.assertIn("- name: operador", desejado)
        self.assertIn("$2y$10$preservado", desejado)

    def test_rollback_para_servico_antes_de_restaurar_yaml(self):
        paths = CaminhosAdGuard(Path("bin"), Path("."), Path("config"), Path("data"))
        backup = Path("backup")
        chamadas = []
        with patch("dns.services.adguard_bootstrap._configuracao_desejada", side_effect=[("antes", "depois"), ("antes", "depois")]), patch("dns.services.adguard_bootstrap._escrever_configuracao_atomica", return_value=backup), patch("dns.services.adguard_bootstrap._restaurar_backup") as restaurar:
            with self.assertRaises(RuntimeError):
                _reconciliar_yaml(
                    paths=paths,
                    senha="segredo",
                    hosts_dns=["127.0.0.1"],
                    controlar_servico=chamadas.append,
                    validar_apos_inicio=lambda: (_ for _ in ()).throw(RuntimeError("API falhou")),
                )
        self.assertEqual(chamadas, [["stop", paths.servico], ["start", paths.servico], ["stop", paths.servico], ["start", paths.servico]])
        restaurar.assert_called_once_with(paths, backup)


class TestPermissoesConfiguracaoAdGuard(unittest.TestCase):
    GID_MOONSHIELD = 61234

    def _paths(self, diretorio: str) -> CaminhosAdGuard:
        raiz = Path(diretorio)
        configuracao = raiz / "AdGuardHome.yaml"
        configuracao.write_text("antes\n", encoding="utf-8")
        configuracao.chmod(0o600)
        return CaminhosAdGuard(raiz / "AdGuardHome", raiz, configuracao, raiz / "data")

    @patch("dns.services.adguard_bootstrap.os.chown")
    @patch("dns.services.adguard_bootstrap.grp.getgrnam", return_value=SimpleNamespace(gr_gid=GID_MOONSHIELD))
    def test_helper_aplica_root_moonshield_0640_sem_expor_arquivo(self, _grupo, chown):
        with tempfile.TemporaryDirectory() as diretorio:
            paths = self._paths(diretorio)
            _garantir_permissoes_configuracao(paths)
            _garantir_permissoes_configuracao(paths)

            self.assertEqual(stat.S_IMODE(paths.configuracao.stat().st_mode), 0o640)
            self.assertFalse(stat.S_IMODE(paths.configuracao.stat().st_mode) & 0o004)
            chown.assert_called_with(paths.configuracao, 0, self.GID_MOONSHIELD)

    @patch("dns.services.adguard_bootstrap.os.chown")
    @patch("dns.services.adguard_bootstrap.grp.getgrnam", return_value=SimpleNamespace(gr_gid=GID_MOONSHIELD))
    def test_escrita_atomica_substitui_0600_por_0640(self, _grupo, chown):
        with tempfile.TemporaryDirectory() as diretorio:
            paths = self._paths(diretorio)
            backup = adguard_bootstrap._escrever_configuracao_atomica(paths, "depois\n")

            self.assertEqual(paths.configuracao.read_text(encoding="utf-8"), "depois\n")
            self.assertTrue(backup.is_file())
            self.assertEqual(stat.S_IMODE(paths.configuracao.stat().st_mode), 0o640)
            chown.assert_called_with(paths.configuracao, 0, self.GID_MOONSHIELD)

    @patch("dns.services.adguard_bootstrap.os.chown")
    @patch("dns.services.adguard_bootstrap.grp.getgrnam", return_value=SimpleNamespace(gr_gid=GID_MOONSHIELD))
    def test_rollback_restaura_conteudo_e_reaplica_0640(self, _grupo, chown):
        with tempfile.TemporaryDirectory() as diretorio:
            paths = self._paths(diretorio)
            backup = Path(diretorio) / "AdGuardHome.yaml.moonshield.bak"
            backup.write_text("antes\n", encoding="utf-8")
            backup.chmod(0o600)
            paths.configuracao.write_text("depois\n", encoding="utf-8")
            paths.configuracao.chmod(0o600)

            adguard_bootstrap._restaurar_backup(paths, backup)

            self.assertEqual(paths.configuracao.read_text(encoding="utf-8"), "antes\n")
            self.assertEqual(stat.S_IMODE(paths.configuracao.stat().st_mode), 0o640)
            chown.assert_called_with(paths.configuracao, 0, self.GID_MOONSHIELD)

    @patch("dns.services.adguard_bootstrap.grp.getgrnam", side_effect=KeyError("moonshield"))
    def test_grupo_moonshield_ausente_gera_erro_explicito(self, _grupo):
        with tempfile.TemporaryDirectory() as diretorio:
            with self.assertRaisesRegex(AdGuardBootstrapError, "Grupo de integração moonshield"):
                _garantir_permissoes_configuracao(self._paths(diretorio))

    @patch("dns.services.adguard_bootstrap.os.chown")
    @patch("dns.services.adguard_bootstrap.grp.getgrnam", return_value=SimpleNamespace(gr_gid=GID_MOONSHIELD))
    def test_secret_permanece_root_moonshield_0640(self, _grupo, chown):
        with tempfile.TemporaryDirectory() as diretorio:
            caminho = Path(diretorio) / "secrets" / "adguard"
            garantir_secret(caminho)

            self.assertEqual(stat.S_IMODE(caminho.stat().st_mode), 0o640)
            self.assertFalse(stat.S_IMODE(caminho.stat().st_mode) & 0o004)
            chown.assert_called_with(caminho, 0, self.GID_MOONSHIELD)


class TestUpstreamsAdGuard(unittest.TestCase):
    DNS_INFO = {"upstream_dns": ["https://cloudflare-dns.com/dns-query"], "bootstrap_dns": ["1.1.1.1"]}

    def test_nxdomain_nao_prova_upstream(self):
        self.assertFalse(upstreams_aprovados(self.DNS_INFO, {}))

    def test_erro_tls_do_endpoint_oficial_reprova_upstream(self):
        resultado = {"https://cloudflare-dns.com/dns-query": "x509: certificate signed by unknown authority", "1.1.1.1": "OK"}
        self.assertFalse(upstreams_aprovados(self.DNS_INFO, resultado))

    def test_endpoint_oficial_aprova_somente_todos_upstreams_ok(self):
        resultado = {"https://cloudflare-dns.com/dns-query": "OK", "1.1.1.1": "OK"}
        self.assertTrue(upstreams_aprovados(self.DNS_INFO, resultado))

    def test_porta_https_padrao_explicita_equivale_a_implicita(self):
        resultado = {"https://cloudflare-dns.com:443/dns-query": "OK"}
        self.assertTrue(upstreams_aprovados(self.DNS_INFO, resultado))

    def test_upstream_configurado_ausente_reprova(self):
        dns_info = {"upstream_dns": ["https://cloudflare-dns.com/dns-query", "https://dns10.quad9.net/dns-query"]}
        self.assertFalse(upstreams_aprovados(dns_info, {"https://cloudflare-dns.com/dns-query": "OK"}))


class TestHealthAdGuard(unittest.TestCase):
    ENDERECOS_ESPERADOS = ["127.0.0.1", "203.0.113.2", "192.168.52.1", "198.51.100.2", "172.16.0.1", "10.1.0.1"]

    def _dados_operacionais(self):
        return {
            "health": {
                "api": "ok",
                "running": True,
                "protection_enabled": True,
                "dns_port": 53,
                "dns_addresses": self.ENDERECOS_ESPERADOS,
                "filters_enabled": 3,
                "version": "v0.107.79",
            },
            "dns_info": {"upstream_dns": ["https://cloudflare-dns.com/dns-query"]},
        }

    def _estado_com_erro(self, erro):
        with patch("dns.services.adguard_bootstrap.descobrir_adguard", return_value=object()), patch("dns.views._get_adguard_client") as factory:
            factory.return_value.fetch_all.side_effect = erro
            return configuracoes_views._estado_adguard(SimpleNamespace(), TOPOLOGIA_DNS)

    def test_404_e_auth_invalida_geram_atencao(self):
        for codigo in (404, 401):
            estado = self._estado_com_erro(AdGuardHTTPError(status_code=codigo, url="http://127.0.0.1:3000/control/status"))
            self.assertEqual(estado["status"], "atencao")

    def test_servico_indisponivel_nao_e_reportado_ativo(self):
        estado = self._estado_com_erro(AdGuardError("conexão recusada"))
        self.assertEqual(estado["status"], "atencao")
        self.assertTrue(estado["instalado"])
        self.assertFalse(estado["ativo"])

    def test_health_operacional_usa_contrato_local_completo(self):
        with patch("dns.services.adguard_bootstrap.descobrir_adguard", return_value=object()), patch("dns.services.adguard_bootstrap.validar_resolucao_dns", return_value={"resolver_ok": True}), patch("dns.views._get_adguard_client") as factory:
            factory.return_value.fetch_all.return_value = self._dados_operacionais()
            factory.return_value.testar_upstreams_dns.return_value = {"https://cloudflare-dns.com:443/dns-query": "OK"}
            estado = configuracoes_views._estado_adguard(SimpleNamespace(), TOPOLOGIA_DNS)

        self.assertTrue(estado["configurado"])
        self.assertTrue(estado["saudavel"])
        self.assertEqual(estado["status"], "operacional")
        self.assertTrue(estado["ativo"])
        self.assertTrue(estado["api"])
        self.assertTrue(estado["protecao"])
        self.assertEqual(estado["filtros_ativos"], 3)
        self.assertEqual(estado["versao"], "v0.107.79")

    def test_protecao_versao_e_filtros_vem_do_health_real(self):
        dados = {
            "health": {
                "api": "ok",
                "running": True,
                "protection_enabled": False,
                "dns_port": 53,
                "dns_addresses": ["192.168.52.1"],
                "filters_enabled": 3,
                "version": "v0.107.79",
            }
        }
        with patch("dns.services.adguard_bootstrap.descobrir_adguard", return_value=object()), patch("dns.services.adguard_bootstrap.validar_resolucao_dns", return_value={"resolver_ok": True, "upstream_ok": True}), patch("dns.views._get_adguard_client") as factory:
            factory.return_value.fetch_all.return_value = dados
            estado = configuracoes_views._estado_adguard(SimpleNamespace(), TOPOLOGIA_DNS)

        self.assertFalse(estado["saudavel"])
        self.assertEqual(estado["filtros_ativos"], 3)
        self.assertEqual(estado["versao"], "v0.107.79")

    def test_listener_localhost_apenas_e_wan_indevido_nao_ficam_operacionais(self):
        for enderecos in (["127.0.0.1"], ["127.0.0.1", "192.168.52.1", "203.0.113.2"]):
            dados = {"health": {"api": "ok", "running": True, "protection_enabled": True, "dns_port": 53, "dns_addresses": enderecos}}
            with patch("dns.services.adguard_bootstrap.descobrir_adguard", return_value=object()), patch("dns.views._get_adguard_client") as factory:
                factory.return_value.fetch_all.return_value = dados
                estado = configuracoes_views._estado_adguard(SimpleNamespace(), TOPOLOGIA_DNS)
            self.assertFalse(estado["saudavel"])
            self.assertFalse(estado["configurado"])

    def test_api_ok_sem_resolucao_real_fica_em_atencao(self):
        dados = {"health": {"api": "ok", "running": True, "protection_enabled": True, "dns_port": 53, "dns_addresses": ["127.0.0.1", "192.168.52.1"]}}
        with patch("dns.services.adguard_bootstrap.descobrir_adguard", return_value=object()), patch("dns.services.adguard_bootstrap.validar_resolucao_dns", return_value={"resolver_ok": False, "upstream_ok": False}), patch("dns.views._get_adguard_client") as factory:
            factory.return_value.fetch_all.return_value = dados
            estado = configuracoes_views._estado_adguard(SimpleNamespace(), TOPOLOGIA_DNS)
        self.assertFalse(estado["saudavel"])
        self.assertFalse(estado["upstream_ok"])
