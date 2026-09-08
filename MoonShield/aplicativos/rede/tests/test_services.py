"""
Testes do serviço de alterações seguras da Rede.

Foco:
- single-flight global;
- transições de estado;
- aplicação;
- confirmação idempotente;
- rollback idempotente;
- reconciliação;
- serialização do Safe Apply.

Execute:
    python gerenciar.py test rede.tests.test_services
"""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from rede.dominio.erros import (
    AgentIndisponivelErro,
    AgentRespostaInvalidaErro,
    AlteracaoEstadoInvalidoErro,
    ConflitoInterfaceErro,
    ConfiguracaoRedeInvalidaErro,
)
from rede.models import AlteracaoRede, InterfaceRede, RegraNat, RotaEstatica, SnapshotRede
from rede.services import alteracoes as service
from rede.services import inventario, reconciliacao
from rede.services import nat
from rede.services import roteamento


User = get_user_model()


class AlteracoesServiceTests(TestCase):
    def setUp(self):
        self.usuario = User.objects.create_user(
            username="rede-test",
            password="rede-test-password",
        )

    def criar_modelo(
        self,
        *,
        status=AlteracaoRede.Status.CRIADA,
        tipo=AlteracaoRede.Tipo.GERAL,
        requer_confirmacao=True,
        expira_em=None,
    ):
        return AlteracaoRede.objects.create(
            tipo=tipo,
            status=status,
            titulo="Teste de Rede",
            descricao="Alteração criada pelo teste.",
            configuracao_solicitada={"teste": True},
            requer_confirmacao=requer_confirmacao,
            solicitado_por=self.usuario,
            expira_em=expira_em,
        )

    def patch_criacao(self):
        return (
            patch.object(service, "reconciliar_alteracoes_expiradas", return_value=0),
            patch.object(service, "_bloquear_orquestracao_global"),
            patch.object(service, "registrar_evento"),
        )

    def test_statuses_em_andamento_reservam_pipeline(self):
        esperados = {
            "created",
            "validating",
            "applying",
            "waiting_confirmation",
            "rollback",
        }

        self.assertEqual(
            set(AlteracaoRede.statuses_em_andamento()),
            esperados,
        )

    def test_criar_alteracao_quando_pipeline_livre(self):
        p1, p2, p3 = self.patch_criacao()

        with p1, p2, p3:
            alteracao = service.criar_alteracao(
                tipo=AlteracaoRede.Tipo.GERAL,
                titulo="Aplicar rede",
                configuracao_solicitada={"interfaces": []},
                usuario=self.usuario,
            )

        self.assertEqual(alteracao.status, AlteracaoRede.Status.CRIADA)
        self.assertTrue(alteracao.em_andamento)
        self.assertEqual(AlteracaoRede.objects.count(), 1)
        self.assertEqual(alteracao.solicitado_por, self.usuario)

    def test_segunda_alteracao_e_bloqueada_sem_criar_historico_extra(self):
        ativa = self.criar_modelo(
            status=AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO
        )

        p1, p2, p3 = self.patch_criacao()

        with p1, p2, p3:
            with self.assertRaises(AlteracaoEstadoInvalidoErro) as contexto:
                service.criar_alteracao(
                    tipo=AlteracaoRede.Tipo.NAT,
                    titulo="Aplicar NAT",
                    configuracao_solicitada={"nat": []},
                    usuario=self.usuario,
                )

        self.assertEqual(AlteracaoRede.objects.count(), 1)
        self.assertEqual(
            contexto.exception.detalhes.get("alteracao_id"),
            str(ativa.id),
        )
        self.assertEqual(
            contexto.exception.detalhes.get("status"),
            AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO,
        )

    def test_obter_alteracao_ativa_reconhece_pipeline_inteiro(self):
        for status in AlteracaoRede.statuses_em_andamento():
            AlteracaoRede.objects.all().delete()
            alteracao = self.criar_modelo(status=status)

            encontrada = service.obter_alteracao_ativa()

            self.assertIsNotNone(encontrada)
            self.assertEqual(encontrada.id, alteracao.id)

    def test_status_final_nao_bloqueia_pipeline(self):
        for status in AlteracaoRede.statuses_finais():
            AlteracaoRede.objects.all().delete()
            self.criar_modelo(status=status)

            self.assertIsNone(service.obter_alteracao_ativa())

    def test_aplicar_alteracao_vai_para_aguardando_confirmacao(self):
        alteracao = self.criar_modelo()
        expira = timezone.now() + timedelta(seconds=60)

        resposta_agent = {
            "status": "waiting_confirmation",
            "expira_em": expira.isoformat(),
        }

        with (
            patch.object(service, "_bloquear_orquestracao_global"),
            patch.object(service, "requisitar_agent", return_value=resposta_agent) as agent,
            patch.object(service, "_criar_snapshot_de_resposta", return_value=None),
            patch.object(service, "registrar_evento"),
        ):
            atualizada = service.aplicar_alteracao(alteracao.id)

        self.assertEqual(
            atualizada.status,
            AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO,
        )
        self.assertIsNotNone(atualizada.aplicada_em)
        self.assertEqual(atualizada.expira_em, expira)
        self.assertTrue(atualizada.em_andamento)

        agent.assert_called_once()
        self.assertEqual(
            agent.call_args.args[0],
            "network.change.apply",
        )

    def test_aplicar_sem_confirmacao_finaliza_imediatamente(self):
        alteracao = self.criar_modelo(requer_confirmacao=False)

        with (
            patch.object(service, "_bloquear_orquestracao_global"),
            patch.object(
                service,
                "requisitar_agent",
                return_value={"status": "confirmed"},
            ),
            patch.object(service, "_criar_snapshot_de_resposta", return_value=None),
            patch.object(service, "registrar_evento"),
        ):
            atualizada = service.aplicar_alteracao(alteracao.id)

        self.assertEqual(
            atualizada.status,
            AlteracaoRede.Status.CONFIRMADA,
        )
        self.assertTrue(atualizada.finalizada)
        self.assertFalse(atualizada.em_andamento)
        self.assertIsNone(atualizada.expira_em)

    def test_aplicar_persiste_snapshot_devolvido_pelo_agent(self):
        alteracao = self.criar_modelo()
        snapshot = SnapshotRede.objects.create(
            dados={"snapshot_id": "agent-snapshot"},
        )
        resposta_agent = {
            "status": "waiting_confirmation",
            "snapshot": {"id": "agent-snapshot"},
        }

        with (
            patch.object(service, "_bloquear_orquestracao_global"),
            patch.object(service, "requisitar_agent", return_value=resposta_agent),
            patch.object(
                service,
                "_criar_snapshot_de_resposta",
                return_value=snapshot,
            ) as criar_snapshot,
            patch.object(service, "registrar_evento"),
        ):
            atualizada = service.aplicar_alteracao(alteracao.id)

        self.assertEqual(atualizada.snapshot_anterior, snapshot)
        self.assertEqual(
            criar_snapshot.call_args.args[0],
            resposta_agent["snapshot"],
        )

    def test_confirmar_alteracao_e_idempotente_quando_ja_confirmada(self):
        alteracao = self.criar_modelo(
            status=AlteracaoRede.Status.CONFIRMADA
        )

        with patch.object(service, "requisitar_agent") as agent:
            confirmada = service.confirmar_alteracao(
                alteracao.id,
                usuario=self.usuario,
            )

        self.assertEqual(
            confirmada.status,
            AlteracaoRede.Status.CONFIRMADA,
        )
        agent.assert_not_called()

    def test_confirmar_alteracao_aguardando_chama_agent(self):
        alteracao = self.criar_modelo(
            status=AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO,
            expira_em=timezone.now() + timedelta(seconds=60),
        )

        with (
            patch.object(
                service,
                "requisitar_agent",
                return_value={"status": "confirmed"},
            ) as agent,
            patch.object(service, "registrar_evento"),
        ):
            confirmada = service.confirmar_alteracao(
                alteracao.id,
                usuario=self.usuario,
            )

        self.assertEqual(
            confirmada.status,
            AlteracaoRede.Status.CONFIRMADA,
        )
        self.assertEqual(
            confirmada.confirmado_por,
            self.usuario,
        )
        self.assertIsNone(confirmada.expira_em)
        agent.assert_called_once()

    def criar_interface_para_confirmacao(self, nome="lan-confirmacao"):
        return InterfaceRede.objects.create(
            nome=nome,
            papel=InterfaceRede.Papel.LAN,
            habilitada=True,
            ipv4_modo=InterfaceRede.ModoIPv4.STATIC,
            ipv4_endereco="192.168.50.1",
            ipv4_prefixo=24,
            rota_padrao=False,
            mtu=1500,
            estado_link=InterfaceRede.EstadoLink.UP,
            ipv4_atual="192.168.50.1",
            enderecos_ipv4=["192.168.50.1/24"],
            prefixo_atual=24,
            mtu_atual=1500,
            revisao_desejada=2,
            revisao_aplicada=1,
        )

    def criar_alteracao_interface_aguardando(self, interface):
        p1, p2, p3 = self.patch_criacao()

        with p1, p2, p3:
            alteracao = service.criar_alteracao_interface(
                interface.id,
                usuario=self.usuario,
            )

        alteracao.status = AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO
        alteracao.expira_em = timezone.now() + timedelta(seconds=60)
        alteracao.save(update_fields=["status", "expira_em", "atualizado_em"])
        return alteracao

    def confirmar_alteracao_interface(self, alteracao):
        with (
            patch.object(
                service,
                "requisitar_agent",
                return_value={"status": "confirmed"},
            ),
            patch.object(service, "registrar_evento"),
        ):
            return service.confirmar_alteracao(
                alteracao.id,
                usuario=self.usuario,
            )

    def test_confirmar_interface_promove_revisao_congelada(self):
        interface = self.criar_interface_para_confirmacao()
        alteracao = self.criar_alteracao_interface_aguardando(interface)

        self.confirmar_alteracao_interface(alteracao)
        interface.refresh_from_db()

        self.assertEqual(
            alteracao.configuracao_solicitada["revisoes_interfaces"][str(interface.id)],
            2,
        )
        self.assertEqual(interface.revisao_aplicada, 2)
        self.assertEqual(interface.estado_sincronizacao, "synced")
        self.assertTrue(interface.sincronizada)
        self.assertFalse(interface.pendente)

    def test_confirmar_interface_e_idempotente_para_revisao(self):
        interface = self.criar_interface_para_confirmacao()
        alteracao = self.criar_alteracao_interface_aguardando(interface)

        self.confirmar_alteracao_interface(alteracao)
        self.confirmar_alteracao_interface(alteracao)
        interface.refresh_from_db()

        self.assertEqual(interface.revisao_aplicada, 2)

    def test_confirmar_interface_preserva_desired_posterior(self):
        interface = self.criar_interface_para_confirmacao()
        alteracao = self.criar_alteracao_interface_aguardando(interface)

        interface.ipv4_endereco = "192.168.60.1"
        interface.revisao_desejada = 3
        interface.save(update_fields=[
            "ipv4_endereco",
            "revisao_desejada",
            "atualizado_em",
        ])

        self.confirmar_alteracao_interface(alteracao)
        interface.refresh_from_db()

        self.assertEqual(interface.revisao_desejada, 3)
        self.assertEqual(interface.revisao_aplicada, 2)
        self.assertEqual(interface.estado_sincronizacao, "pending_apply")

    def test_confirmar_interface_nao_promove_outra_interface(self):
        interface = self.criar_interface_para_confirmacao()
        outra = self.criar_interface_para_confirmacao("lan-outra")
        outra.revisao_desejada = 4
        outra.revisao_aplicada = 1
        outra.save(update_fields=[
            "revisao_desejada",
            "revisao_aplicada",
            "atualizado_em",
        ])
        alteracao = self.criar_alteracao_interface_aguardando(interface)

        self.confirmar_alteracao_interface(alteracao)
        outra.refresh_from_db()

        self.assertEqual(outra.revisao_aplicada, 1)

    def test_reconciliar_confirmacao_promove_revisao_congelada(self):
        interface = self.criar_interface_para_confirmacao()
        alteracao = self.criar_alteracao_interface_aguardando(interface)

        with (
            patch.object(
                service,
                "requisitar_agent",
                return_value={"status": "confirmed"},
            ),
            patch.object(service, "registrar_evento"),
        ):
            service.reconciliar_alteracao(alteracao.id)

        interface.refresh_from_db()
        self.assertEqual(interface.revisao_aplicada, 2)

    def test_confirmar_roteamento_sincroniza_apenas_rota_congelada(self):
        interface = self.criar_interface_para_confirmacao()
        rota = RotaEstatica.objects.create(
            destino="10.250.0.0/24",
            gateway="192.168.50.254",
            interface=interface,
            metrica=100,
            ativa=True,
        )
        p1, p2, p3 = self.patch_criacao()

        with p1, p2, p3:
            alteracao = service.criar_alteracao_roteamento(usuario=self.usuario)

        alteracao.status = AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO
        alteracao.expira_em = timezone.now() + timedelta(seconds=60)
        alteracao.save(update_fields=["status", "expira_em", "atualizado_em"])

        self.confirmar_alteracao_interface(alteracao)
        rota.refresh_from_db()

        self.assertTrue(rota.sincronizada)
        self.assertFalse(rota.pendente)

    def test_payload_roteamento_alvo_somente_interface_com_rota(self):
        interface_rota = self.criar_interface_para_confirmacao()
        outra_interface = self.criar_interface_para_confirmacao("wan-sem-rota")
        outra_interface.papel = InterfaceRede.Papel.WAN
        outra_interface.save(update_fields=["papel", "atualizado_em"])
        RotaEstatica.objects.create(
            destino="10.250.0.0/24",
            gateway="192.168.50.254",
            interface=interface_rota,
            metrica=100,
            ativa=True,
        )

        payload = roteamento.montar_payload_roteamento()

        self.assertEqual(payload["interfaces_alvo"], [interface_rota.nome])

    def test_remover_ultima_rota_mantem_tombstone_sincronizado_no_payload(self):
        interface = self.criar_interface_para_confirmacao()
        rota = RotaEstatica.objects.create(
            destino="10.250.0.0/24",
            gateway="192.168.50.254",
            interface=interface,
            metrica=100,
            ativa=True,
            sincronizada=True,
            pendente=False,
        )

        roteamento.excluir_rota(rota.id)
        payload = roteamento.montar_payload_roteamento()

        rota.refresh_from_db()
        self.assertFalse(rota.ativa)
        self.assertTrue(rota.pendente)
        self.assertTrue(rota.sincronizada)
        self.assertEqual(payload["interfaces_alvo"], [interface.nome])
        self.assertEqual(payload["rotas"], [{
            "id": rota.id,
            "destino": "10.250.0.0/24",
            "gateway": "192.168.50.254",
            "interface_nome": interface.nome,
            "metrica": 100,
            "ativa": False,
            "pendente": True,
            "sincronizada": True,
        }])

    def test_remocao_sem_ownership_sincronizado_permanece_segura_no_payload(self):
        interface = self.criar_interface_para_confirmacao()
        rota = RotaEstatica.objects.create(
            destino="10.251.0.0/24",
            gateway="192.168.50.254",
            interface=interface,
            metrica=100,
            ativa=True,
            sincronizada=False,
            pendente=False,
        )

        roteamento.excluir_rota(rota.id)
        payload = roteamento.montar_payload_roteamento()

        self.assertEqual(payload["rotas"][0]["sincronizada"], False)
        self.assertFalse(payload["rotas"][0]["ativa"])
        self.assertTrue(payload["rotas"][0]["pendente"])

    def test_substituir_rota_emite_adicao_e_remocao_na_mesma_interface(self):
        interface = self.criar_interface_para_confirmacao()
        rota_anterior = RotaEstatica.objects.create(
            nome="anterior",
            destino="10.252.0.0/24",
            gateway="192.168.50.254",
            interface=interface,
            metrica=100,
            ativa=True,
            sincronizada=True,
            pendente=False,
        )

        rota_nova = roteamento.salvar_rota({
            "nome": "nova",
            "destino": "10.253.0.0/24",
            "gateway": "192.168.50.254",
            "interface_id": interface.id,
            "metrica": 100,
            "ativa": True,
        }, rota_id=rota_anterior.id)
        payload = roteamento.montar_payload_roteamento()

        self.assertEqual(payload["interfaces_alvo"], [interface.nome])
        self.assertEqual({
            (item["destino"], item["ativa"], item["sincronizada"])
            for item in payload["rotas"]
        }, {
            ("10.252.0.0/24", False, True),
            ("10.253.0.0/24", True, False),
        })
        self.assertEqual(rota_nova.destino, "10.253.0.0/24")

    def test_payload_de_remocao_nao_altera_interface_sem_delta(self):
        interface_alvo = self.criar_interface_para_confirmacao()
        interface_sem_delta = self.criar_interface_para_confirmacao("lan-sem-delta")
        rota = RotaEstatica.objects.create(
            destino="10.254.0.0/24",
            gateway="192.168.50.254",
            interface=interface_alvo,
            metrica=100,
            ativa=True,
            sincronizada=True,
            pendente=False,
        )
        RotaEstatica.objects.create(
            destino="10.255.0.0/24",
            gateway="192.168.50.254",
            interface=interface_sem_delta,
            metrica=100,
            ativa=True,
            sincronizada=True,
            pendente=False,
        )

        roteamento.excluir_rota(rota.id)
        payload = roteamento.montar_payload_roteamento()

        self.assertEqual(payload["interfaces_alvo"], [interface_alvo.nome])
        self.assertEqual(len(payload["rotas"]), 2)

    def test_rota_default_continua_rejeitada_como_rota_estatica(self):
        interface = self.criar_interface_para_confirmacao()

        with self.assertRaises(ConfiguracaoRedeInvalidaErro):
            roteamento.salvar_rota({
                "destino": "0.0.0.0/0",
                "gateway": "192.168.50.254",
                "interface_id": interface.id,
                "metrica": 100,
                "ativa": True,
            })

    def criar_interfaces_nat(self):
        origem = self.criar_interface_para_confirmacao("lan-nat")
        saida = self.criar_interface_para_confirmacao("wan-nat")
        saida.papel = InterfaceRede.Papel.WAN
        saida.save(update_fields=["papel", "atualizado_em"])
        return origem, saida

    def test_nat_lan_wan_valido_exige_forward_e_safe_apply(self):
        origem, saida = self.criar_interfaces_nat()
        regra = nat.salvar_regra_nat({
            "interface_origem_id": origem.id,
            "interface_saida_id": saida.id,
            "ativa": True,
        })
        p1, p2, p3 = self.patch_criacao()

        with p1, p2, p3:
            alteracao = service.criar_alteracao_nat(usuario=self.usuario)

        self.assertTrue(alteracao.requer_confirmacao)
        self.assertEqual(
            alteracao.configuracao_solicitada["roteamento"]["ipv4_forward"],
            True,
        )
        self.assertEqual(
            alteracao.configuracao_solicitada["roteamento"],
            {"ipv4_forward": True},
        )
        self.assertNotIn("interfaces", alteracao.configuracao_solicitada)
        self.assertEqual(
            alteracao.configuracao_solicitada["nat"]["regras"][0]["origem_cidr"],
            "192.168.50.0/24",
        )
        self.assertEqual(regra.tipo, RegraNat.Tipo.MASQUERADE)

    def test_nat_rejeita_interfaces_sem_papeis_validos_ou_iguais(self):
        origem, saida = self.criar_interfaces_nat()
        mgmt = self.criar_interface_para_confirmacao("mgmt-nat")
        mgmt.papel = InterfaceRede.Papel.MGMT
        mgmt.save(update_fields=["papel", "atualizado_em"])
        lan_saida = self.criar_interface_para_confirmacao("lan-saida-nat")

        with self.assertRaises(ConfiguracaoRedeInvalidaErro):
            nat.salvar_regra_nat({
                "interface_origem_id": mgmt.id,
                "interface_saida_id": saida.id,
            })

        with self.assertRaises(ConfiguracaoRedeInvalidaErro):
            nat.salvar_regra_nat({
                "interface_origem_id": origem.id,
                "interface_saida_id": lan_saida.id,
            })

        with self.assertRaises(ConflitoInterfaceErro):
            nat.salvar_regra_nat({
                "interface_origem_id": origem.id,
                "interface_saida_id": origem.id,
            })

    def test_nat_equivalente_nao_duplica_estado_desejado(self):
        origem, saida = self.criar_interfaces_nat()
        primeira = nat.salvar_regra_nat({
            "interface_origem_id": origem.id,
            "interface_saida_id": saida.id,
        })
        segunda = nat.salvar_regra_nat({
            "interface_origem_id": origem.id,
            "interface_saida_id": saida.id,
        })

        self.assertEqual(primeira.id, segunda.id)
        self.assertEqual(RegraNat.objects.count(), 1)

    def test_remover_ultima_regra_nat_mantem_tombstone_e_retorna_forward_global(self):
        origem, saida = self.criar_interfaces_nat()
        regra = RegraNat.objects.create(
            interface_origem=origem,
            interface_saida=saida,
            origem_cidr="192.168.50.0/24",
            ativa=True,
            sincronizada=True,
            pendente=False,
        )

        nat.excluir_regra_nat(regra.id)
        p1, p2, p3 = self.patch_criacao()

        with p1, p2, p3:
            alteracao = service.criar_alteracao_nat(usuario=self.usuario)

        regra.refresh_from_db()
        self.assertFalse(regra.ativa)
        self.assertTrue(regra.pendente)
        self.assertTrue(regra.sincronizada)
        self.assertEqual(
            alteracao.configuracao_solicitada["roteamento"]["ipv4_forward"],
            False,
        )
        self.assertEqual(
            alteracao.configuracao_solicitada["roteamento"],
            {"ipv4_forward": False},
        )
        self.assertNotIn("interfaces", alteracao.configuracao_solicitada)
        self.assertFalse(alteracao.configuracao_solicitada["nat"]["regras"][0]["ativa"])

        alteracao.status = AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO
        alteracao.expira_em = timezone.now() + timedelta(seconds=60)
        alteracao.save(update_fields=["status", "expira_em", "atualizado_em"])
        self.confirmar_alteracao_interface(alteracao)

        regra.refresh_from_db()
        self.assertFalse(regra.sincronizada)
        self.assertFalse(regra.pendente)

    def test_confirmar_agent_indisponivel_mantem_aguardando_confirmacao(self):
        alteracao = self.criar_modelo(
            status=AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO,
            expira_em=timezone.now() + timedelta(seconds=60),
        )

        with patch.object(
            service,
            "requisitar_agent",
            side_effect=AgentIndisponivelErro("Agent indisponível."),
        ):
            with self.assertRaises(AgentIndisponivelErro):
                service.confirmar_alteracao(alteracao.id, usuario=self.usuario)

        alteracao.refresh_from_db()
        self.assertEqual(
            alteracao.status,
            AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO,
        )
        self.assertTrue(alteracao.em_andamento)

    def test_rollback_e_idempotente_quando_ja_revertida(self):
        alteracao = self.criar_modelo(
            status=AlteracaoRede.Status.REVERTIDA
        )

        with patch.object(service, "requisitar_agent") as agent:
            revertida = service.executar_rollback(
                alteracao.id,
                usuario=self.usuario,
            )

        self.assertEqual(
            revertida.status,
            AlteracaoRede.Status.REVERTIDA,
        )
        agent.assert_not_called()

    def test_rollback_manual_finaliza_como_revertida(self):
        alteracao = self.criar_modelo(
            status=AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO,
            expira_em=timezone.now() + timedelta(seconds=60),
        )

        with (
            patch.object(
                service,
                "requisitar_agent",
                return_value={"status": "reverted"},
            ),
            patch.object(service, "registrar_evento"),
            patch.object(service, "_criar_snapshot_de_resposta", return_value=None),
        ):
            revertida = service.executar_rollback(
                alteracao.id,
                usuario=self.usuario,
                motivo="Teste de rollback.",
            )

        self.assertEqual(
            revertida.status,
            AlteracaoRede.Status.REVERTIDA,
        )
        self.assertTrue(revertida.finalizada)
        self.assertFalse(revertida.em_andamento)
        self.assertIsNone(revertida.expira_em)

    def test_rollback_envia_motivo_no_contrato_do_agent(self):
        alteracao = self.criar_modelo(
            status=AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO,
            expira_em=timezone.now() + timedelta(seconds=60),
        )

        with (
            patch.object(
                service,
                "requisitar_agent",
                return_value={"status": "reverted"},
            ) as agent,
            patch.object(service, "registrar_evento"),
        ):
            service.executar_rollback(
                alteracao.id,
                usuario=self.usuario,
                motivo="Motivo de teste.",
            )

        payload = agent.call_args.args[1]
        self.assertEqual(agent.call_args.args[0], "network.change.rollback")
        self.assertEqual(payload["motivo"], "Motivo de teste.")
        self.assertNotIn("reason", payload)

    def test_rollback_agent_indisponivel_mantem_operacao_ativa(self):
        alteracao = self.criar_modelo(
            status=AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO,
            expira_em=timezone.now() + timedelta(seconds=60),
        )

        with patch.object(
            service,
            "requisitar_agent",
            side_effect=AgentIndisponivelErro("Agent indisponível."),
        ):
            with self.assertRaises(AgentIndisponivelErro):
                service.executar_rollback(alteracao.id, usuario=self.usuario)

        alteracao.refresh_from_db()
        self.assertEqual(alteracao.status, AlteracaoRede.Status.ROLLBACK)
        self.assertTrue(alteracao.em_andamento)

    def test_reconciliar_agent_confirmed_atualiza_postgresql(self):
        alteracao = self.criar_modelo(
            status=AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO,
            expira_em=timezone.now() - timedelta(seconds=1),
        )

        with (
            patch.object(
                service,
                "requisitar_agent",
                return_value={"status": "confirmed"},
            ),
            patch.object(service, "registrar_evento"),
        ):
            atualizada = service.reconciliar_alteracao(alteracao.id)

        self.assertEqual(
            atualizada.status,
            AlteracaoRede.Status.CONFIRMADA,
        )
        self.assertTrue(atualizada.finalizada)

    def test_reconciliar_agent_reverted_atualiza_postgresql(self):
        alteracao = self.criar_modelo(
            status=AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO,
            expira_em=timezone.now() - timedelta(seconds=1),
        )

        with (
            patch.object(
                service,
                "requisitar_agent",
                return_value={"status": "reverted"},
            ),
            patch.object(service, "registrar_evento"),
        ):
            atualizada = service.reconciliar_alteracao(alteracao.id)

        self.assertEqual(
            atualizada.status,
            AlteracaoRede.Status.REVERTIDA,
        )
        self.assertTrue(atualizada.finalizada)

    def test_reconciliacao_falha_nao_libera_lock(self):
        alteracao = self.criar_modelo(
            status=AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO,
            expira_em=timezone.now() - timedelta(seconds=1),
        )

        with patch.object(
            service,
            "requisitar_agent",
            side_effect=RuntimeError("Agent offline"),
        ):
            processadas = service.reconciliar_alteracoes_expiradas()

        alteracao.refresh_from_db()

        self.assertEqual(processadas, 0)
        self.assertEqual(
            alteracao.status,
            AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO,
        )
        self.assertTrue(alteracao.em_andamento)

    def test_serializacao_expoe_estado_operacional(self):
        alteracao = self.criar_modelo(
            status=AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO,
            expira_em=timezone.now() + timedelta(seconds=30),
        )

        dados = service.serializar_alteracao(alteracao)

        self.assertEqual(
            dados["status"],
            "waiting_confirmation",
        )
        self.assertTrue(dados["em_andamento"])
        self.assertTrue(dados["pode_confirmar"])
        self.assertTrue(dados["pode_rollback"])
        self.assertIsInstance(
            dados["segundos_restantes"],
            int,
        )

    def test_cancelar_created_e_idempotente_depois(self):
        alteracao = self.criar_modelo()

        with patch.object(service, "registrar_evento"):
            cancelada = service.cancelar_alteracao(
                alteracao.id,
                usuario=self.usuario,
            )
            cancelada2 = service.cancelar_alteracao(
                alteracao.id,
                usuario=self.usuario,
            )

        self.assertEqual(
            cancelada.status,
            AlteracaoRede.Status.CANCELADA,
        )
        self.assertEqual(cancelada2.id, cancelada.id)
        self.assertTrue(cancelada2.finalizada)


class InventarioObservedTests(TestCase):
    def criar_interface(self) -> InterfaceRede:
        return InterfaceRede.objects.create(
            nome="wan-observed",
            papel=InterfaceRede.Papel.WAN,
            estado_link=InterfaceRede.EstadoLink.UP,
            ipv4_atual="192.0.2.10",
            prefixo_atual=24,
            enderecos_ipv4=["192.0.2.10/24"],
        )

    def test_inventario_invalido_nao_vira_lista_vazia(self):
        with patch.object(
            inventario,
            "requisitar_agent",
            return_value={"backend": "networkmanager", "interfaces": {}},
        ):
            with self.assertRaises(AgentRespostaInvalidaErro):
                inventario.obter_inventario()

    def test_agent_offline_preserva_observed_anterior(self):
        interface = self.criar_interface()

        with patch.object(
            reconciliacao,
            "obter_inventario",
            side_effect=AgentIndisponivelErro("Agent offline"),
        ):
            with self.assertRaises(AgentIndisponivelErro):
                reconciliacao.reconciliar_interfaces()

        interface.refresh_from_db()
        self.assertEqual(interface.estado_link, InterfaceRede.EstadoLink.UP)
        self.assertEqual(interface.enderecos_ipv4, ["192.0.2.10/24"])

    def test_inventario_vazio_valido_marca_interface_gerenciada_missing(self):
        interface = self.criar_interface()

        reconciliacao.reconciliar_interfaces(
            inventario={"backend": "networkmanager", "interfaces": []}
        )

        interface.refresh_from_db()
        self.assertEqual(interface.estado_sincronizacao, "missing")
