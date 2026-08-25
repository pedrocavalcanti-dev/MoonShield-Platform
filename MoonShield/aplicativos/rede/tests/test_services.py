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

from rede.dominio.erros import AlteracaoEstadoInvalidoErro
from rede.models import AlteracaoRede
from rede.services import alteracoes as service


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
            "expires_at": expira.isoformat(),
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
        self.assertIsNotNone(atualizada.expira_em)
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
