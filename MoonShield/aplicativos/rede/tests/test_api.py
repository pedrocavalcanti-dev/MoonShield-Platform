"""
Testes das APIs do módulo Rede.

Foco:
- autenticação;
- 202 em aplicações aceitas;
- 409 em single-flight;
- nenhuma criação artificial em conflito;
- operação ativa devolvida ao frontend;
- bloqueio de mutações de desired state durante Safe Apply;
- leitura permanece disponível.

Execute:
    python gerenciar.py test rede.tests.test_api
"""

from __future__ import annotations

import json
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase
from django.utils import timezone

from rede.api import alteracoes as api_alteracoes
from rede.api import interfaces as api_interfaces
from rede.api import nat as api_nat
from rede.api import roteamento as api_roteamento
from rede.dominio.erros import AlteracaoEstadoInvalidoErro
from rede.models import AlteracaoRede


User = get_user_model()


class RedeApiTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.usuario = User.objects.create_user(
            username="api-rede-test",
            password="api-rede-password",
        )

    def request_get(self, path="/rede/api/test/", *, autenticado=True):
        request = self.factory.get(path)
        request.user = self.usuario if autenticado else User()
        return request

    def request_post(
        self,
        path="/rede/api/test/",
        payload=None,
        *,
        autenticado=True,
        content_type="application/json",
    ):
        if content_type == "application/json":
            data = json.dumps(payload or {})
        else:
            data = payload or {}

        request = self.factory.post(
            path,
            data=data,
            content_type=content_type,
        )
        request.user = self.usuario if autenticado else User()
        return request

    def request_delete(self, path="/rede/api/test/", *, autenticado=True):
        request = self.factory.delete(path)
        request.user = self.usuario if autenticado else User()
        return request

    def json(self, response):
        return json.loads(response.content.decode("utf-8"))

    def criar_alteracao(
        self,
        *,
        status=AlteracaoRede.Status.CRIADA,
        tipo=AlteracaoRede.Tipo.GERAL,
    ):
        return AlteracaoRede.objects.create(
            tipo=tipo,
            status=status,
            titulo="Alteração API",
            descricao="Teste",
            configuracao_solicitada={"teste": True},
            requer_confirmacao=True,
            solicitado_por=self.usuario,
            expira_em=(
                timezone.now() + timedelta(seconds=60)
                if status == AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO
                else None
            ),
        )

    def test_api_alteracoes_exige_autenticacao(self):
        response = api_alteracoes.api_alteracoes(
            self.request_get(autenticado=False)
        )

        self.assertEqual(response.status_code, 401)
        self.assertFalse(self.json(response)["ok"])

    def test_listagem_retorna_alteracao_ativa(self):
        ativa = self.criar_alteracao(
            status=AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO
        )

        with patch.object(
            api_alteracoes,
            "listar_alteracoes",
            return_value=[],
        ):
            response = api_alteracoes.api_alteracoes(
                self.request_get()
            )

        dados = self.json(response)["dados"]

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            dados["ativa"]["id"],
            str(ativa.id),
        )

    def test_aplicar_tudo_retorna_202(self):
        alteracao = self.criar_alteracao(
            status=AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO
        )

        with (
            patch.object(
                api_alteracoes,
                "criar_alteracao_geral",
                return_value=alteracao,
            ),
            patch.object(
                api_alteracoes,
                "aplicar_alteracao",
                return_value=alteracao,
            ),
        ):
            response = api_alteracoes.api_aplicar_tudo(
                self.request_post(
                    "/rede/api/alteracoes/aplicar-tudo/"
                )
            )

        payload = self.json(response)

        self.assertEqual(response.status_code, 202)
        self.assertTrue(payload["ok"])
        self.assertEqual(
            payload["dados"]["alteracao"]["id"],
            str(alteracao.id),
        )

    def test_aplicar_tudo_conflito_retorna_409(self):
        ativa = self.criar_alteracao(
            status=AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO
        )

        erro = AlteracaoEstadoInvalidoErro(
            "Existe uma alteração de Rede aguardando conclusão.",
            detalhes={
                "alteracao_id": str(ativa.id),
                "status": ativa.status,
            },
        )

        with patch.object(
            api_alteracoes,
            "criar_alteracao_geral",
            side_effect=erro,
        ):
            response = api_alteracoes.api_aplicar_tudo(
                self.request_post(
                    "/rede/api/alteracoes/aplicar-tudo/"
                )
            )

        payload = self.json(response)

        self.assertEqual(response.status_code, 409)
        self.assertFalse(payload["ok"])
        self.assertEqual(
            payload["erro"]["codigo"],
            "alteracao_rede_em_andamento",
        )
        self.assertEqual(
            payload["erro"]["detalhes"]["alteracao"]["id"],
            str(ativa.id),
        )

    def test_conflito_nao_cria_nova_linha_de_historico(self):
        ativa = self.criar_alteracao(
            status=AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO
        )
        total_antes = AlteracaoRede.objects.count()

        erro = AlteracaoEstadoInvalidoErro(
            "Existe uma alteração de Rede aguardando conclusão.",
            detalhes={
                "alteracao_id": str(ativa.id),
                "status": ativa.status,
            },
        )

        with patch.object(
            api_alteracoes,
            "criar_alteracao_geral",
            side_effect=erro,
        ):
            response = api_alteracoes.api_aplicar_tudo(
                self.request_post()
            )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(
            AlteracaoRede.objects.count(),
            total_antes,
        )

    def test_reconciliar_retorna_estado_ativo(self):
        ativa = self.criar_alteracao(
            status=AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO
        )

        with (
            patch.object(
                api_alteracoes,
                "reconciliar_alteracoes_ativas",
                return_value=1,
            ),
            patch.object(
                api_alteracoes,
                "reconciliar_alteracoes_expiradas",
                return_value=0,
            ),
        ):
            response = api_alteracoes.api_alteracoes_reconciliar(
                self.request_post(
                    "/rede/api/alteracoes/reconciliar/"
                )
            )

        dados = self.json(response)["dados"]

        self.assertEqual(response.status_code, 200)
        self.assertEqual(dados["processadas"], 1)
        self.assertEqual(
            dados["ativa"]["id"],
            str(ativa.id),
        )

    def test_confirmar_retorna_estado_final_e_sem_ativa(self):
        alteracao = self.criar_alteracao(
            status=AlteracaoRede.Status.CONFIRMADA
        )

        with patch.object(
            api_alteracoes,
            "confirmar_alteracao",
            return_value=alteracao,
        ):
            response = api_alteracoes.api_alteracao_confirmar(
                self.request_post(),
                alteracao.id,
            )

        dados = self.json(response)["dados"]

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            dados["alteracao"]["status"],
            "confirmed",
        )
        self.assertIsNone(dados["ativa"])

    def test_rollback_retorna_estado_final_e_sem_ativa(self):
        alteracao = self.criar_alteracao(
            status=AlteracaoRede.Status.REVERTIDA
        )

        with patch.object(
            api_alteracoes,
            "executar_rollback",
            return_value=alteracao,
        ):
            request = self.factory.post(
                "/rede/api/alteracoes/x/rollback/",
                data={"motivo": "teste"},
            )
            request.user = self.usuario

            response = api_alteracoes.api_alteracao_rollback(
                request,
                alteracao.id,
            )

        dados = self.json(response)["dados"]

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            dados["alteracao"]["status"],
            "reverted",
        )
        self.assertIsNone(dados["ativa"])

    def test_interfaces_get_permitido_com_safe_apply_ativo(self):
        ativa = self.criar_alteracao(
            status=AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO
        )

        with patch.object(
            api_interfaces,
            "listar_interfaces",
            return_value=[],
        ):
            response = api_interfaces.api_interfaces(
                self.request_get("/rede/api/interfaces/")
            )

        dados = self.json(response)["dados"]

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            dados["alteracao_ativa"]["id"],
            str(ativa.id),
        )

    def test_configurar_interface_bloqueada_durante_safe_apply(self):
        ativa = self.criar_alteracao(
            status=AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO
        )

        with (
            patch.object(
                api_interfaces,
                "reconciliar_alteracoes_expiradas",
                return_value=0,
            ),
            patch.object(
                api_interfaces,
                "salvar_configuracao_interface",
            ) as salvar,
        ):
            response = api_interfaces.api_interface_configurar(
                self.request_post(
                    "/rede/api/interfaces/1/configurar/",
                    {"papel": "lan"},
                ),
                1,
            )

        payload = self.json(response)

        self.assertEqual(response.status_code, 409)
        self.assertEqual(
            payload["erro"]["codigo"],
            "alteracao_rede_em_andamento",
        )
        self.assertEqual(
            payload["erro"]["detalhes"]["alteracao_id"],
            str(ativa.id),
        )
        salvar.assert_not_called()

    def test_aplicar_interface_retorna_202(self):
        alteracao = self.criar_alteracao(
            status=AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO,
            tipo=AlteracaoRede.Tipo.INTERFACE,
        )

        with (
            patch.object(
                api_interfaces,
                "obter_interface_por_id",
                return_value=object(),
            ),
            patch.object(
                api_interfaces,
                "criar_alteracao_interface",
                return_value=alteracao,
            ),
            patch.object(
                api_interfaces,
                "aplicar_alteracao",
                return_value=alteracao,
            ),
        ):
            response = api_interfaces.api_interface_aplicar(
                self.request_post(
                    "/rede/api/interfaces/1/aplicar/"
                ),
                1,
            )

        self.assertEqual(response.status_code, 202)
        self.assertEqual(
            self.json(response)["dados"]["alteracao"]["id"],
            str(alteracao.id),
        )

    def test_salvar_roteamento_bloqueado_durante_safe_apply(self):
        ativa = self.criar_alteracao(
            status=AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO
        )

        with (
            patch.object(
                api_roteamento,
                "reconciliar_alteracoes_expiradas",
                return_value=0,
            ),
            patch.object(
                api_roteamento,
                "salvar_configuracao",
            ) as salvar,
        ):
            response = api_roteamento.api_roteamento_configurar(
                self.request_post(
                    "/rede/api/roteamento/configurar/",
                    {"ipv4_forward": True},
                )
            )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(
            self.json(response)["erro"]["detalhes"]["alteracao_id"],
            str(ativa.id),
        )
        salvar.assert_not_called()

    def test_criar_nat_bloqueado_durante_safe_apply(self):
        ativa = self.criar_alteracao(
            status=AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO
        )

        with (
            patch.object(
                api_nat,
                "reconciliar_alteracoes_expiradas",
                return_value=0,
            ),
            patch.object(
                api_nat,
                "salvar_regra_nat",
            ) as salvar,
        ):
            response = api_nat.api_nat(
                self.request_post(
                    "/rede/api/nat/",
                    {
                        "nome": "LAN WAN",
                        "ativa": True,
                    },
                )
            )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(
            self.json(response)["erro"]["detalhes"]["alteracao_id"],
            str(ativa.id),
        )
        salvar.assert_not_called()

    def test_aplicar_roteamento_retorna_202(self):
        alteracao = self.criar_alteracao(
            status=AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO,
            tipo=AlteracaoRede.Tipo.ROTEAMENTO,
        )

        with (
            patch.object(
                api_roteamento,
                "criar_alteracao_roteamento",
                return_value=alteracao,
            ),
            patch.object(
                api_roteamento,
                "aplicar_alteracao",
                return_value=alteracao,
            ),
        ):
            response = api_roteamento.api_roteamento_aplicar(
                self.request_post(
                    "/rede/api/roteamento/aplicar/"
                )
            )

        self.assertEqual(response.status_code, 202)

    def test_aplicar_nat_retorna_202(self):
        alteracao = self.criar_alteracao(
            status=AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO,
            tipo=AlteracaoRede.Tipo.NAT,
        )

        with (
            patch.object(
                api_nat,
                "criar_alteracao_nat",
                return_value=alteracao,
            ),
            patch.object(
                api_nat,
                "aplicar_alteracao",
                return_value=alteracao,
            ),
        ):
            response = api_nat.api_nat_aplicar(
                self.request_post(
                    "/rede/api/nat/aplicar/"
                )
            )

        self.assertEqual(response.status_code, 202)
