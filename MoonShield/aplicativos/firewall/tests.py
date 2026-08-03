"""
firewall/tests.py
──────────────────────────────────────────────────────────────────────
Testes completos do módulo Firewall.

Cobre:
  - CRUD de Regras (criar, editar, deletar, duplicar, toggle)
  - CRUD de NAT
  - CRUD de Blocklist / Allowlist / Geoblock
  - API de dados (demo / prod-waiting / prod)
  - Sincronização (push-rules, pending-rules, confirm-rules)
  - Exportar .nft
  - Ingest do sensor (receber eventos)
  - Conversor nft (regra → expressão nft)

Rodar:
  python gerenciar.py test firewall -v 2
  python gerenciar.py test firewall.tests.FirewallCRUDTests -v 2
──────────────────────────────────────────────────────────────────────
"""

import json
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.urls import reverse

from .models import (
    AllowlistEntry, BlocklistEntry, EventoFirewall,
    GeoblockEntry, NatEntry, RegraFirewall,
)


# ─────────────────────────────────────────────────────────────────────────────
# BASE — cria usuário e client autenticado
# ─────────────────────────────────────────────────────────────────────────────

class FirewallTestBase(TestCase):

    def setUp(self):
        self.user   = User.objects.create_user('tester', password='tester123')
        self.client = Client()
        self.client.login(username='tester', password='tester123')

    def post_json(self, url, data):
        return self.client.post(
            url,
            data=json.dumps(data),
            content_type='application/json',
        )

    def put_json(self, url, data):
        return self.client.put(
            url,
            data=json.dumps(data),
            content_type='application/json',
        )

    def patch_json(self, url, data):
        return self.client.patch(
            url,
            data=json.dumps(data),
            content_type='application/json',
        )


# ─────────────────────────────────────────────────────────────────────────────
# 1. PÁGINA HTML
# ─────────────────────────────────────────────────────────────────────────────

class FirewallPaginaTests(FirewallTestBase):

    def test_pagina_carrega(self):
        """GET /firewall/ retorna 200."""
        r = self.client.get('/firewall/')
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, 'fwRulesTableBody')

    def test_pagina_redireciona_sem_login(self):
        """Sem autenticação, redireciona para login."""
        c = Client()
        r = c.get('/firewall/')
        self.assertEqual(r.status_code, 302)
        self.assertIn('login', r.url)


# ─────────────────────────────────────────────────────────────────────────────
# 2. API DATA — três estados
# ─────────────────────────────────────────────────────────────────────────────

class FirewallApiDataTests(FirewallTestBase):

    def test_data_modo_demo(self):
        """Sem eventos e modo=demo → retorna dados simulados."""
        with patch('firewall.views._get_modo', return_value='demo'):
            r = self.client.get('/firewall/api/data/')
        self.assertEqual(r.status_code, 200)
        d = r.json()
        self.assertTrue(d['ok'])
        self.assertEqual(d['mode'], 'demo')
        self.assertIn('rules', d)
        self.assertIn('logs', d)
        self.assertIn('charts', d)
        self.assertGreater(len(d['rules']), 0)
        self.assertGreater(len(d['logs']), 0)

    def test_data_prod_waiting(self):
        """Modo=prod sem eventos → waiting=True, KPIs zeros."""
        with patch('firewall.views._get_modo', return_value='prod'):
            r = self.client.get('/firewall/api/data/')
        self.assertEqual(r.status_code, 200)
        d = r.json()
        self.assertTrue(d['ok'])
        self.assertEqual(d['mode'], 'prod')
        self.assertTrue(d.get('waiting'))
        self.assertEqual(d['metrics']['drops'], 0)
        self.assertEqual(d['metrics']['allows'], 0)
        self.assertEqual(d['logs'], [])

    def test_data_prod_com_eventos(self):
        """Modo=prod com eventos → dados reais."""
        from incidentes.models import Sensor
        from django.utils import timezone

        sensor = Sensor.objects.create(
            nome='test-sensor', ip='127.0.0.1', token='abc123'
        )
        EventoFirewall.objects.create(
            sensor=sensor,
            timestamp=timezone.now(),
            acao='DROP',
            proto='TCP',
            src_ip='1.2.3.4',
            dst_ip='10.0.0.1',
            dst_port=22,
            iface='eth0',
            event_hash='hash_unico_test_001',
        )

        with patch('firewall.views._get_modo', return_value='prod'):
            r = self.client.get('/firewall/api/data/')
        d = r.json()
        self.assertTrue(d['ok'])
        self.assertEqual(d['mode'], 'prod')
        self.assertFalse(d.get('waiting', False))
        self.assertGreater(d['metrics']['drops'], 0)

    def test_data_periods(self):
        """Aceita todos os períodos sem erro."""
        for p in ['1h', '24h', '7d', '30d']:
            with patch('firewall.views._get_modo', return_value='demo'):
                r = self.client.get(f'/firewall/api/data/?period={p}')
            self.assertEqual(r.status_code, 200, f"Falhou para period={p}")

    def test_data_sem_auth(self):
        """Sem autenticação → 302."""
        c = Client()
        r = c.get('/firewall/api/data/')
        self.assertEqual(r.status_code, 302)


# ─────────────────────────────────────────────────────────────────────────────
# 3. CRUD — REGRAS
# ─────────────────────────────────────────────────────────────────────────────

class FirewallRulesTests(FirewallTestBase):

    REGRA_BASE = {
        'priority': 50,
        'action':   'deny',
        'iface':    'WAN',
        'dir':      'in',
        'proto':    'TCP',
        'src':      'any',
        'dst':      'any',
        'port':     '22',
        'desc':     'Bloquear SSH teste',
        'enabled':  True,
        'log':      True,
    }

    def test_criar_regra(self):
        """POST /firewall/api/rules/ cria regra com pendente=True."""
        r = self.post_json('/firewall/api/rules/', self.REGRA_BASE)
        self.assertEqual(r.status_code, 201)
        d = r.json()
        self.assertTrue(d['ok'])
        rule = d['rule']
        self.assertEqual(rule['action'],   'deny')
        self.assertEqual(rule['port'],     '22')
        self.assertEqual(rule['priority'], 50)
        self.assertTrue(rule['pendente'])
        self.assertFalse(rule['sincronizada'])
        self.assertEqual(RegraFirewall.objects.count(), 1)

    def test_criar_regra_allow(self):
        """Cria regra ALLOW."""
        dados = {**self.REGRA_BASE, 'action': 'allow', 'port': '443', 'desc': 'HTTPS IN'}
        r = self.post_json('/firewall/api/rules/', dados)
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.json()['rule']['action'], 'allow')

    def test_criar_regra_campos_default(self):
        """Cria regra com payload mínimo — defaults aplicados."""
        r = self.post_json('/firewall/api/rules/', {'desc': 'Minima'})
        self.assertEqual(r.status_code, 201)
        rule = r.json()['rule']
        self.assertEqual(rule['src'],  'any')
        self.assertEqual(rule['dst'],  'any')
        self.assertEqual(rule['port'], 'any')

    def test_editar_regra_put(self):
        """PUT /firewall/api/rules/<id>/ atualiza e marca pendente."""
        regra = RegraFirewall.objects.create(
            **{k: v for k, v in self.REGRA_BASE.items()},
            pendente=False, sincronizada=True,
        )
        r = self.put_json(f'/firewall/api/rules/{regra.id}/', {
            'port': '3389',
            'desc': 'Bloquear RDP',
        })
        self.assertEqual(r.status_code, 200)
        d = r.json()
        self.assertTrue(d['ok'])
        self.assertTrue(d['rule']['pendente'])
        self.assertFalse(d['rule']['sincronizada'])
        regra.refresh_from_db()
        self.assertEqual(regra.port, '3389')
        self.assertTrue(regra.pendente)
        self.assertFalse(regra.sincronizada)

    def test_editar_regra_patch(self):
        """PATCH parcial também funciona."""
        regra = RegraFirewall.objects.create(**{k: v for k, v in self.REGRA_BASE.items()})
        r = self.patch_json(f'/firewall/api/rules/{regra.id}/', {'enabled': False})
        self.assertEqual(r.status_code, 200)
        regra.refresh_from_db()
        self.assertFalse(regra.enabled)

    def test_deletar_regra(self):
        """DELETE /firewall/api/rules/<id>/ remove do banco."""
        regra = RegraFirewall.objects.create(**{k: v for k, v in self.REGRA_BASE.items()})
        r = self.client.delete(f'/firewall/api/rules/{regra.id}/')
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()['ok'])
        self.assertEqual(RegraFirewall.objects.count(), 0)

    def test_deletar_regra_inexistente(self):
        """DELETE de ID inválido → 404."""
        r = self.client.delete('/firewall/api/rules/99999/')
        self.assertEqual(r.status_code, 404)

    def test_criar_multiplas_regras_ordenadas(self):
        """Múltiplas regras ficam ordenadas por prioridade."""
        for prio in [100, 10, 50]:
            RegraFirewall.objects.create(
                priority=prio, action='deny', iface='WAN', dir='in',
                proto='TCP', src='any', dst='any', port='any',
                desc=f'Regra {prio}',
            )
        regras = list(RegraFirewall.objects.all())
        prioridades = [r.priority for r in regras]
        self.assertEqual(sorted(prioridades), prioridades)

    def test_payload_invalido_retorna_400(self):
        """JSON malformado → 400."""
        r = self.client.post(
            '/firewall/api/rules/',
            data='isso nao e json{{{',
            content_type='application/json',
        )
        self.assertEqual(r.status_code, 400)


# ─────────────────────────────────────────────────────────────────────────────
# 4. CRUD — NAT
# ─────────────────────────────────────────────────────────────────────────────

class FirewallNatTests(FirewallTestBase):

    NAT_BASE = {
        'name':     'HTTP Public',
        'iface':    'WAN',
        'wan_port': '80',
        'lan_ip':   '10.0.0.10',
        'lan_port': '8080',
        'proto':    'TCP',
        'enabled':  True,
    }

    def test_criar_nat(self):
        """POST /firewall/api/nat/ cria port forward."""
        r = self.post_json('/firewall/api/nat/', self.NAT_BASE)
        self.assertEqual(r.status_code, 201)
        d = r.json()
        self.assertTrue(d['ok'])
        self.assertEqual(d['nat']['name'],     'HTTP Public')
        self.assertEqual(d['nat']['wan_port'], '80')
        self.assertEqual(d['nat']['lan_ip'],   '10.0.0.10')
        self.assertEqual(NatEntry.objects.count(), 1)

    def test_editar_nat(self):
        """PUT altera o port forward."""
        nat = NatEntry.objects.create(**self.NAT_BASE)
        r = self.put_json(f'/firewall/api/nat/{nat.id}/', {'enabled': False, 'lan_port': '9090'})
        self.assertEqual(r.status_code, 200)
        nat.refresh_from_db()
        self.assertFalse(nat.enabled)
        self.assertEqual(nat.lan_port, '9090')

    def test_deletar_nat(self):
        """DELETE remove o port forward."""
        nat = NatEntry.objects.create(**self.NAT_BASE)
        r = self.client.delete(f'/firewall/api/nat/{nat.id}/')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(NatEntry.objects.count(), 0)

    def test_nat_sem_ip_invalido(self):
        """LAN IP inválido é rejeitado pelo model."""
        from django.core.exceptions import ValidationError
        nat = NatEntry(
            name='Invalido', iface='WAN', wan_port='80',
            lan_ip='nao_e_ip',   # ← valor inválido
            lan_port='8080', proto='TCP', enabled=True,
        )
        with self.assertRaises(ValidationError):
            nat.full_clean()


# ─────────────────────────────────────────────────────────────────────────────
# 5. CRUD — BLOCKLIST
# ─────────────────────────────────────────────────────────────────────────────

class FirewallBlocklistTests(FirewallTestBase):

    def test_adicionar_ip(self):
        """POST /firewall/api/blocklist/ adiciona IP."""
        r = self.post_json('/firewall/api/blocklist/', {
            'ip':      '185.22.11.4',
            'reason':  'Port scan',
            'source':  'Manual',
            'expires': '7d',
        })
        self.assertEqual(r.status_code, 201)
        d = r.json()
        self.assertTrue(d['ok'])
        self.assertEqual(d['entry']['ip'],     '185.22.11.4')
        self.assertEqual(d['entry']['reason'], 'Port scan')

    def test_adicionar_subnet(self):
        """Aceita subnet CIDR."""
        r = self.post_json('/firewall/api/blocklist/', {'ip': '185.220.0.0/14'})
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.json()['entry']['ip'], '185.220.0.0/14')

    def test_ip_obrigatorio(self):
        """Sem IP → 400."""
        r = self.post_json('/firewall/api/blocklist/', {'reason': 'sem ip'})
        self.assertEqual(r.status_code, 400)

    def test_remover_ip(self):
        """DELETE remove da blocklist."""
        entry = BlocklistEntry.objects.create(ip='1.2.3.4', reason='teste')
        r = self.client.delete(f'/firewall/api/blocklist/{entry.id}/')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(BlocklistEntry.objects.count(), 0)

    def test_adicionar_multiplos(self):
        """Múltiplas entradas coexistem."""
        for ip in ['1.1.1.1', '2.2.2.2', '3.3.3.3']:
            self.post_json('/firewall/api/blocklist/', {'ip': ip})
        self.assertEqual(BlocklistEntry.objects.count(), 3)


# ─────────────────────────────────────────────────────────────────────────────
# 6. CRUD — ALLOWLIST
# ─────────────────────────────────────────────────────────────────────────────

class FirewallAllowlistTests(FirewallTestBase):

    def test_adicionar_ip(self):
        """POST /firewall/api/allowlist/ adiciona IP."""
        r = self.post_json('/firewall/api/allowlist/', {
            'ip':     '8.8.8.8',
            'reason': 'Google DNS',
        })
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.json()['entry']['ip'], '8.8.8.8')

    def test_adicionar_dominio(self):
        """Aceita domínio além de IP."""
        r = self.post_json('/firewall/api/allowlist/', {'ip': 'cloudflare.com'})
        self.assertEqual(r.status_code, 201)

    def test_ip_obrigatorio(self):
        """Sem IP → 400."""
        r = self.post_json('/firewall/api/allowlist/', {'reason': 'sem ip'})
        self.assertEqual(r.status_code, 400)

    def test_remover_entry(self):
        """DELETE remove da allowlist."""
        entry = AllowlistEntry.objects.create(ip='10.0.0.0/8', reason='Rede local')
        r = self.client.delete(f'/firewall/api/allowlist/{entry.id}/')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(AllowlistEntry.objects.count(), 0)


# ─────────────────────────────────────────────────────────────────────────────
# 7. CRUD — GEOBLOCK
# ─────────────────────────────────────────────────────────────────────────────

class FirewallGeoblockTests(FirewallTestBase):

    def test_adicionar_pais(self):
        """POST /firewall/api/geoblock/ adiciona país."""
        r = self.post_json('/firewall/api/geoblock/', {
            'code':    'RU',
            'country': 'Rússia',
            'dir':     'IN',
            'enabled': True,
        })
        self.assertEqual(r.status_code, 201)
        d = r.json()
        self.assertEqual(d['entry']['code'],    'RU')
        self.assertEqual(d['entry']['country'], 'Rússia')

    def test_codigo_maiusculo(self):
        """Código é normalizado para maiúsculo."""
        r = self.post_json('/firewall/api/geoblock/', {'code': 'cn', 'country': 'China'})
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.json()['entry']['code'], 'CN')

    def test_codigo_obrigatorio(self):
        """Sem código → 400."""
        r = self.post_json('/firewall/api/geoblock/', {'country': 'Sem codigo'})
        self.assertEqual(r.status_code, 400)

    def test_unico_por_codigo(self):
        """Dois POSTs com mesmo código retornam a mesma entrada (get_or_create)."""
        self.post_json('/firewall/api/geoblock/', {'code': 'KP', 'country': 'Coreia do Norte'})
        self.post_json('/firewall/api/geoblock/', {'code': 'KP', 'country': 'Coreia do Norte'})
        self.assertEqual(GeoblockEntry.objects.filter(code='KP').count(), 1)

    def test_atualizar_geoblock(self):
        """PUT atualiza o geoblock."""
        entry = GeoblockEntry.objects.create(code='IR', country='Irã', dir='IN', enabled=True)
        r = self.put_json(f'/firewall/api/geoblock/{entry.id}/', {'enabled': False})
        self.assertEqual(r.status_code, 200)
        entry.refresh_from_db()
        self.assertFalse(entry.enabled)

    def test_remover_pais(self):
        """DELETE remove o geoblock."""
        entry = GeoblockEntry.objects.create(code='BY', country='Belarus', dir='IN', enabled=True)
        r = self.client.delete(f'/firewall/api/geoblock/{entry.id}/')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(GeoblockEntry.objects.count(), 0)


# ─────────────────────────────────────────────────────────────────────────────
# 8. SINCRONIZAÇÃO
# ─────────────────────────────────────────────────────────────────────────────

class FirewallSyncTests(FirewallTestBase):

    def _criar_sensor(self):
        from incidentes.models import Sensor
        return Sensor.objects.create(
            nome='sync-sensor', ip='127.0.0.1', token='sync_token_123', ativo=True
        )

    def test_push_rules_marca_pendentes(self):
        """POST /firewall/api/push-rules/ marca todas as regras como pendentes."""
        for i in range(3):
            RegraFirewall.objects.create(
                priority=i*10, action='deny', iface='WAN', dir='in',
                proto='TCP', src='any', dst='any', port='any',
                desc=f'Regra {i}', pendente=False, sincronizada=True,
            )
        r = self.client.post('/firewall/api/push-rules/')
        self.assertEqual(r.status_code, 200)
        d = r.json()
        self.assertTrue(d['ok'])
        self.assertIn('sync', d)
        self.assertEqual(RegraFirewall.objects.filter(pendente=True).count(), 3)
        self.assertEqual(RegraFirewall.objects.filter(sincronizada=True).count(), 0)

    def test_push_rules_sem_regras(self):
        """Push sem regras retorna ok com count=0."""
        r = self.client.post('/firewall/api/push-rules/')
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()['ok'])

    def test_pending_rules_sem_token(self):
        """GET /firewall/api/pending-rules/ sem token → 403."""
        r = self.client.get('/firewall/api/pending-rules/')
        self.assertEqual(r.status_code, 403)

    def test_pending_rules_token_invalido(self):
        """Token errado → 403."""
        r = self.client.get(
            '/firewall/api/pending-rules/',
            HTTP_X_MS_TOKEN='token_errado',
        )
        self.assertEqual(r.status_code, 403)

    def test_pending_rules_com_token_valido(self):
        """Token válido → retorna regras pendentes."""
        sensor = self._criar_sensor()
        RegraFirewall.objects.create(
            priority=10, action='deny', iface='WAN', dir='in',
            proto='TCP', src='any', dst='any', port='22',
            desc='SSH block', pendente=True, sincronizada=False,
        )
        r = self.client.get(
            '/firewall/api/pending-rules/',
            HTTP_X_MS_TOKEN='sync_token_123',
        )
        self.assertEqual(r.status_code, 200)
        d = r.json()
        self.assertTrue(d['ok'])
        self.assertTrue(d['tem_pendentes'])
        self.assertGreater(len(d['rules']), 0)

    def test_pending_rules_sem_pendentes(self):
        """Sem regras pendentes → tem_pendentes=False."""
        sensor = self._criar_sensor()
        RegraFirewall.objects.create(
            priority=10, action='deny', iface='WAN', dir='in',
            proto='TCP', src='any', dst='any', port='22',
            desc='SSH block', pendente=False, sincronizada=True,
        )
        r = self.client.get(
            '/firewall/api/pending-rules/',
            HTTP_X_MS_TOKEN='sync_token_123',
        )
        self.assertEqual(r.status_code, 200)
        d = r.json()
        self.assertFalse(d['tem_pendentes'])
        self.assertEqual(d['rules'], [])

    def test_confirm_rules_token_invalido(self):
        """Confirm sem token → 403."""
        r = self.post_json('/firewall/api/confirm-rules/', {
            'rule_ids': [1], 'success': True,
        })
        self.assertEqual(r.status_code, 403)

    def test_confirm_rules_sucesso(self):
        """Confirm com token válido e success=True → marca sincronizadas."""
        sensor = self._criar_sensor()
        regra = RegraFirewall.objects.create(
            priority=10, action='deny', iface='WAN', dir='in',
            proto='TCP', src='any', dst='any', port='22',
            desc='SSH', pendente=True, sincronizada=False,
        )
        r = self.client.post(
            '/firewall/api/confirm-rules/',
            data=json.dumps({'rule_ids': [regra.id], 'success': True, 'msg': 'OK'}),
            content_type='application/json',
            HTTP_X_MS_TOKEN='sync_token_123',
        )
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()['ok'])
        regra.refresh_from_db()
        self.assertFalse(regra.pendente)
        self.assertTrue(regra.sincronizada)

    def test_confirm_rules_falha(self):
        """Confirm com success=False → mantém pendente."""
        sensor = self._criar_sensor()
        regra = RegraFirewall.objects.create(
            priority=10, action='deny', iface='WAN', dir='in',
            proto='TCP', src='any', dst='any', port='22',
            desc='SSH', pendente=True, sincronizada=False,
        )
        r = self.client.post(
            '/firewall/api/confirm-rules/',
            data=json.dumps({'rule_ids': [regra.id], 'success': False, 'msg': 'nft error'}),
            content_type='application/json',
            HTTP_X_MS_TOKEN='sync_token_123',
        )
        self.assertEqual(r.status_code, 200)
        regra.refresh_from_db()
        self.assertTrue(regra.pendente)
        self.assertFalse(regra.sincronizada)

    def test_ciclo_completo_sync(self):
        """Fluxo completo: criar regra → push → pending → confirm."""
        sensor = self._criar_sensor()
        r1 = self.post_json('/firewall/api/rules/', {
            'action': 'deny', 'iface': 'WAN', 'dir': 'in',
            'proto': 'TCP', 'port': '23', 'desc': 'Bloquear Telnet',
        })
        self.assertEqual(r1.status_code, 201)
        rule_id = r1.json()['rule']['id']

        r2 = self.client.get(
            '/firewall/api/pending-rules/',
            HTTP_X_MS_TOKEN='sync_token_123',
        )
        self.assertTrue(r2.json()['tem_pendentes'])

        r3 = self.client.post(
            '/firewall/api/confirm-rules/',
            data=json.dumps({'rule_ids': [rule_id], 'success': True}),
            content_type='application/json',
            HTTP_X_MS_TOKEN='sync_token_123',
        )
        self.assertEqual(r3.status_code, 200)

        regra = RegraFirewall.objects.get(id=rule_id)
        self.assertFalse(regra.pendente)
        self.assertTrue(regra.sincronizada)

        r4 = self.client.get(
            '/firewall/api/pending-rules/',
            HTTP_X_MS_TOKEN='sync_token_123',
        )
        self.assertFalse(r4.json()['tem_pendentes'])


# ─────────────────────────────────────────────────────────────────────────────
# 9. EXPORT .NFT
# ─────────────────────────────────────────────────────────────────────────────

class FirewallExportNftTests(FirewallTestBase):

    def test_export_vazio(self):
        """Export sem regras retorna arquivo válido com header."""
        r = self.client.get('/firewall/api/export-nft/')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r['Content-Type'], 'text/plain; charset=utf-8')
        self.assertIn('attachment', r['Content-Disposition'])
        self.assertIn('.nft', r['Content-Disposition'])
        conteudo = r.content.decode('utf-8')
        self.assertIn('table inet moonshield', conteudo)
        self.assertIn('chain ms_forward', conteudo)

    def test_export_com_regras(self):
        """Export com regras inclui as expressões nft."""
        RegraFirewall.objects.create(
            priority=10, action='deny', iface='WAN', dir='in',
            proto='TCP', src='any', dst='any', port='22',
            desc='Bloquear SSH', enabled=True,
        )
        RegraFirewall.objects.create(
            priority=20, action='allow', iface='LAN', dir='out',
            proto='TCP', src='10.0.0.0/24', dst='any', port='443',
            desc='HTTPS out', enabled=True,
        )
        r = self.client.get('/firewall/api/export-nft/')
        self.assertEqual(r.status_code, 200)
        conteudo = r.content.decode('utf-8')
     
        # Estrutura base sempre presente
        self.assertIn('table inet moonshield', conteudo)
        self.assertIn('chain ms_forward',      conteudo)
        self.assertIn('chain ms_rules',        conteudo)
     
        # Regra SSH — gerada inline dentro da chain
        self.assertIn('dport 22',  conteudo)
        self.assertIn('drop',      conteudo)
     
        # Regra HTTPS
        self.assertIn('dport 443', conteudo)
        self.assertIn('accept',    conteudo)
     
        # Comentários com descrição
        self.assertIn('Bloquear SSH', conteudo)
        self.assertIn('HTTPS out',    conteudo)

    def test_export_ignora_desabilitadas(self):
        """Regras desabilitadas não aparecem no export."""
        RegraFirewall.objects.create(
            priority=10, action='deny', iface='WAN', dir='in',
            proto='TCP', src='any', dst='any', port='8888',
            desc='Desabilitada', enabled=False,
        )
        r = self.client.get('/firewall/api/export-nft/')
        conteudo = r.content.decode('utf-8')
        self.assertNotIn('dport 8888', conteudo)

    def test_export_sem_auth(self):
        """Sem autenticação → 302."""
        c = Client()
        r = c.get('/firewall/api/export-nft/')
        self.assertEqual(r.status_code, 302)


# ─────────────────────────────────────────────────────────────────────────────
# 10. INGEST DO SENSOR
# ─────────────────────────────────────────────────────────────────────────────

class FirewallIngestTests(TestCase):
    """
    Testa o endpoint de ingestão do sensor nftables.
    Não requer autenticação de usuário — usa token do sensor.
    """

    def setUp(self):
        self.client = Client()

    def _post_ingest(self, payload):
        return self.client.post(
            '/firewall/api/ingest/',
            data=json.dumps(payload),
            content_type='application/json',
        )

    def test_primeiro_contato_cria_sensor(self):
        """Primeiro POST cria sensor e retorna token."""
        from incidentes.models import Sensor
        r = self._post_ingest({'sensor': 'fw-lab-01', 'eventos': []})
        self.assertEqual(r.status_code, 200)
        d = r.json()
        self.assertTrue(d['ok'])
        self.assertTrue(d['novo_sensor'])
        self.assertTrue(d['heartbeat'])
        self.assertIn('token', d)
        self.assertEqual(Sensor.objects.filter(nome='fw-lab-01').count(), 1)

    def test_heartbeat_vazio(self):
        """Lote vazio = heartbeat."""
        from incidentes.models import Sensor
        Sensor.objects.create(nome='fw-hb', ip='127.0.0.1', token='hb_token_xyz')
        r = self.client.post(
            '/firewall/api/ingest/',
            data=json.dumps({'sensor': 'fw-hb', 'eventos': []}),
            content_type='application/json',
            HTTP_X_MS_TOKEN='hb_token_xyz',   # ← token no HEADER, não no body
        )
        self.assertEqual(r.status_code, 200)
        d = r.json()
        self.assertTrue(d.get('heartbeat'))
        self.assertTrue(d['ok'])

    def test_ingest_com_eventos(self):
        """Lote com eventos persiste EventoFirewall."""
        from incidentes.models import Sensor
        sensor = Sensor.objects.create(nome='fw-ev', ip='127.0.0.1', token='ev_token_abc')
        eventos = [
            {
                'timestamp':     '14:30:22',
                'prefixo':       'MS-FWD',
                'acao':          'DROP',
                'chain':         'FORWARD',
                'proto':         'TCP',
                'src_ip':        '45.33.32.156',
                'src_port':      54321,
                'dst_ip':        '10.0.0.1',
                'dst_port':      22,
                'iface_entrada': 'eth0',
                'iface_saida':   'eth1',
                'tamanho':       60,
                'ttl':           64,
                'flags_tcp':     'SYN',
            },
            {
                'timestamp':     '14:30:23',
                'prefixo':       'MS-FWD',
                'acao':          'LOG',
                'chain':         'FORWARD',
                'proto':         'UDP',
                'src_ip':        '8.8.8.8',
                'src_port':      53,
                'dst_ip':        '10.0.0.5',
                'dst_port':      53,
                'iface_entrada': 'eth0',
                'tamanho':       80,
            },
        ]
        r = self.client.post(
            '/firewall/api/ingest/',
            data=json.dumps({'sensor': 'fw-ev', 'eventos': eventos}),
            content_type='application/json',
            HTTP_X_MS_TOKEN='ev_token_abc',
        )
        self.assertEqual(r.status_code, 200)
        d = r.json()
        self.assertTrue(d['ok'])
        self.assertGreater(d['salvos'], 0)
        self.assertEqual(EventoFirewall.objects.count(), d['salvos'])

    def test_ingest_token_invalido(self):
        """Token errado → 403."""
        from incidentes.models import Sensor
        Sensor.objects.create(nome='fw-tok', ip='127.0.0.1', token='token_correto')
        r = self.client.post(
            '/firewall/api/ingest/',
            data=json.dumps({'sensor': 'fw-tok', 'eventos': []}),
            content_type='application/json',
            HTTP_X_MS_TOKEN='token_errado',
        )
        self.assertEqual(r.status_code, 403)

    def test_ingest_deduplicacao(self):
        """Mesmo evento enviado duas vezes → salvo só uma vez."""
        from incidentes.models import Sensor
        sensor = Sensor.objects.create(nome='fw-dup', ip='127.0.0.1', token='dup_token')
        evento = {
            'timestamp': '10:00:00', 'prefixo': 'MS-FWD', 'acao': 'DROP',
            'chain': 'FORWARD', 'proto': 'TCP',
            'src_ip': '1.1.1.1', 'src_port': 9999,
            'dst_ip': '10.0.0.1', 'dst_port': 80,
        }
        payload = {'sensor': 'fw-dup', 'eventos': [evento]}

        r1 = self.client.post('/firewall/api/ingest/', data=json.dumps(payload), content_type='application/json', HTTP_X_MS_TOKEN='dup_token')
        r2 = self.client.post('/firewall/api/ingest/', data=json.dumps(payload), content_type='application/json', HTTP_X_MS_TOKEN='dup_token')

        self.assertEqual(r1.status_code, 200)
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(EventoFirewall.objects.count(), 1)

    def test_ingest_ip_invalido_ignorado(self):
        """Evento com IP inválido é ignorado (não quebra o lote)."""
        from incidentes.models import Sensor
        Sensor.objects.create(nome='fw-inv', ip='127.0.0.1', token='inv_token')
        eventos = [
            {'timestamp': '10:00:01', 'prefixo': 'MS-FWD', 'src_ip': 'nao_e_ip', 'dst_ip': '10.0.0.1'},
            {'timestamp': '10:00:02', 'prefixo': 'MS-FWD', 'src_ip': '2.2.2.2',  'dst_ip': '10.0.0.1', 'proto': 'TCP', 'dst_port': 80},
        ]
        r = self.client.post(
            '/firewall/api/ingest/',
            data=json.dumps({'sensor': 'fw-inv', 'eventos': eventos}),
            content_type='application/json',
            HTTP_X_MS_TOKEN='inv_token',
        )
        self.assertEqual(r.status_code, 200)
        d = r.json()
        self.assertGreater(d['ignorados'], 0)   
        self.assertGreater(d['salvos'], 0)       

    def test_ingest_json_invalido(self):
        """JSON malformado → 400."""
        r = self.client.post(
            '/firewall/api/ingest/',
            data='isso nao e json',
            content_type='application/json',
        )
        self.assertEqual(r.status_code, 400)


# ─────────────────────────────────────────────────────────────────────────────
# 11. CONVERSOR NFT
# ─────────────────────────────────────────────────────────────────────────────

class ConversorNftTests(TestCase):

    def setUp(self):
        from firewall.conversor import regra_para_nft_inline, gerar_script_nft, IFACE_MAP_DEFAULT
        self.converter   = regra_para_nft_inline
        self.gen_script  = gerar_script_nft
        self.iface_map   = dict(IFACE_MAP_DEFAULT)

    def test_regra_deny_ssh(self):
        """Regra deny SSH gera expressão correta."""
        regra = {
            'action': 'deny', 'iface': 'WAN', 'dir': 'in',
            'proto': 'tcp', 'src': 'any', 'dst': 'any', 'port': '22',
        }
        expr = self.converter(regra, self.iface_map)
        self.assertIn('drop',      expr)
        self.assertIn('dport 22',  expr)
        self.assertIn('iifname',   expr)
        self.assertIn('"eth0"',    expr)

    def test_regra_allow_https(self):
        """Regra allow HTTPS gera accept."""
        regra = {
            'action': 'allow', 'iface': 'LAN', 'dir': 'out',
            'proto': 'tcp', 'src': '10.0.0.0/24', 'dst': 'any', 'port': '443',
        }
        expr = self.converter(regra, self.iface_map)
        self.assertIn('accept',    expr)
        self.assertIn('dport 443', expr)
        self.assertIn('oifname',   expr)

    def test_regra_range_portas(self):
        """Range de portas 80-443 gerado corretamente."""
        regra = {
            'action': 'deny', 'iface': 'WAN', 'dir': 'in',
            'proto': 'tcp', 'src': 'any', 'dst': 'any', 'port': '80-443',
        }
        expr = self.converter(regra, self.iface_map)
        self.assertIn('dport 80-443', expr)

    def test_regra_src_ip_especifico(self):
        """IP de origem específico aparece na expressão."""
        regra = {
            'action': 'deny', 'iface': 'WAN', 'dir': 'in',
            'proto': 'tcp', 'src': '185.220.0.0/14', 'dst': 'any', 'port': 'any',
        }
        expr = self.converter(regra, self.iface_map)
        self.assertIn('ip saddr 185.220.0.0/14', expr)

    def test_regra_any_iface(self):
        """Iface=any não gera filtro de interface."""
        regra = {
            'action': 'deny', 'iface': 'any', 'dir': 'in',
            'proto': 'tcp', 'src': 'any', 'dst': 'any', 'port': '22',
        }
        expr = self.converter(regra, self.iface_map)
        self.assertNotIn('iifname', expr)
        self.assertNotIn('oifname', expr)

    def test_gerar_script_completo(self):
        """Script gerado contém estrutura nft válida."""
        rules = [
            {'id': 1, 'priority': 10, 'enabled': True, 'action': 'deny',  'iface': 'WAN', 'dir': 'in',  'proto': 'tcp', 'src': 'any', 'dst': 'any', 'port': '22',  'desc': 'SSH'},
            {'id': 2, 'priority': 20, 'enabled': True, 'action': 'allow', 'iface': 'LAN', 'dir': 'out', 'proto': 'tcp', 'src': 'any', 'dst': 'any', 'port': '443', 'desc': 'HTTPS'},
            {'id': 3, 'priority': 30, 'enabled': False,'action': 'deny',  'iface': 'WAN', 'dir': 'in',  'proto': 'udp', 'src': 'any', 'dst': 'any', 'port': '161', 'desc': 'SNMP desabilitado'},
        ]
        script = self.gen_script(rules, self.iface_map)
        self.assertIn('table inet moonshield', script)
        self.assertIn('chain ms_forward',      script)
        self.assertIn('chain ms_rules',        script)
        self.assertIn('flush chain',           script)
        self.assertIn('add rule',              script)
        self.assertNotIn('dport 161', script)
        pos_ssh   = script.find('dport 22')
        pos_https = script.find('dport 443')
        self.assertGreater(pos_https, pos_ssh)  

    def test_script_vazio_sem_regras(self):
        """Script sem regras ainda tem a estrutura base."""
        script = self.gen_script([], self.iface_map)
        self.assertIn('table inet moonshield', script)
        self.assertIn('flush chain', script)
        self.assertNotIn('add rule', script)


# ─────────────────────────────────────────────────────────────────────────────
# 12. MODEL — CAMPOS E MÉTODOS
# ─────────────────────────────────────────────────────────────────────────────

class FirewallModelTests(TestCase):

    def test_regra_marcar_pendente(self):
        """marcar_pendente() reseta sincronização."""
        r = RegraFirewall.objects.create(
            priority=10, action='deny', iface='WAN', dir='in',
            proto='TCP', src='any', dst='any', port='22',
            desc='SSH', pendente=False, sincronizada=True,
        )
        r.marcar_pendente()
        self.assertTrue(r.pendente)
        self.assertFalse(r.sincronizada)

    def test_evento_firewall_hash_unico(self):
        """EventoFirewall com mesmo hash não salva duplicata."""
        from incidentes.models import Sensor
        from django.utils import timezone
        sensor = Sensor.objects.create(nome='h-sensor', ip='127.0.0.1', token='h_tok')
        ts     = timezone.now()
        hash_  = EventoFirewall.calcular_hash('1.1.1.1', '10.0.0.1', 1234, 80, 'TCP', ts, 'MS-FWD')
        EventoFirewall.objects.create(
            sensor=sensor, timestamp=ts, acao='DROP', proto='TCP',
            src_ip='1.1.1.1', dst_ip='10.0.0.1', dst_port=80,
            iface='eth0', event_hash=hash_,
        )
        from django.db import IntegrityError
        with self.assertRaises(IntegrityError):
            EventoFirewall.objects.create(
                sensor=sensor, timestamp=ts, acao='DROP', proto='TCP',
                src_ip='1.1.1.1', dst_ip='10.0.0.1', dst_port=80,
                iface='eth0', event_hash=hash_,
            )

    def test_blocklist_str(self):
        b = BlocklistEntry.objects.create(ip='1.2.3.4', reason='teste')
        self.assertEqual(str(b), 'BLOCK 1.2.3.4')

    def test_allowlist_str(self):
        a = AllowlistEntry.objects.create(ip='8.8.8.8', reason='DNS')
        self.assertEqual(str(a), 'ALLOW 8.8.8.8')

    def test_geoblock_str(self):
        g = GeoblockEntry.objects.create(code='RU', country='Rússia', dir='IN', enabled=True)
        self.assertEqual(str(g), 'GEO RU (Rússia)')