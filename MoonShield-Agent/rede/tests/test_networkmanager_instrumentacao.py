"""
MoonShield Agent — Testes de Instrumentação NetworkManager + Prova Negativa NAT
================================================================================

Este arquivo testa:

1. A instrumentação de _nmcli — comandos mutáveis geram log, read-only não.
2. Prova negativa: plano tipo=nat NÃO chama funções mutáveis do NetworkManager.
3. Mascaramento de argumentos sensíveis.

Não executa nmcli/nft/sysctl real.
"""

from __future__ import annotations

import logging
import unittest
from typing import Any
from unittest.mock import MagicMock, patch

from rede.backends.base import ResultadoComando
from rede.backends.networkmanager import NetworkManagerBackend


# =============================================================================
# HELPERS
# =============================================================================

def _resultado_ok(stdout: str = "") -> ResultadoComando:
    return ResultadoComando(
        comando=("nmcli",),
        retorno=0,
        stdout=stdout,
        stderr="",
    )


def _backend_mock() -> NetworkManagerBackend:
    """Backend com _executar mockado para não executar subprocessos."""
    backend = NetworkManagerBackend(nmcli="/usr/bin/nmcli", ip="/usr/sbin/ip")
    backend._executar = MagicMock(return_value=_resultado_ok())
    return backend


# =============================================================================
# 1. CLASSIFICAÇÃO DE OPERAÇÕES
# =============================================================================

class TestClassificacaoNmcli(unittest.TestCase):
    """Testa _classificar_nmcli para operações mutáveis e read-only."""

    def test_connection_modify_e_mutavel(self):
        resultado = NetworkManagerBackend._classificar_nmcli(
            ("connection", "modify", "con1", "ipv4.method", "auto")
        )
        self.assertEqual(resultado, "connection.modify")

    def test_connection_add_e_mutavel(self):
        resultado = NetworkManagerBackend._classificar_nmcli(
            ("connection", "add", "type", "ethernet", "ifname", "eth0")
        )
        self.assertEqual(resultado, "connection.add")

    def test_connection_delete_e_mutavel(self):
        resultado = NetworkManagerBackend._classificar_nmcli(
            ("connection", "delete", "con1")
        )
        self.assertEqual(resultado, "connection.delete")

    def test_connection_up_e_mutavel(self):
        resultado = NetworkManagerBackend._classificar_nmcli(
            ("connection", "up", "id", "con1", "ifname", "eth0")
        )
        self.assertEqual(resultado, "connection.up")

    def test_connection_down_e_mutavel(self):
        resultado = NetworkManagerBackend._classificar_nmcli(
            ("connection", "down", "con1")
        )
        self.assertEqual(resultado, "connection.down")

    def test_device_disconnect_e_mutavel(self):
        resultado = NetworkManagerBackend._classificar_nmcli(
            ("device", "disconnect", "eth0")
        )
        self.assertEqual(resultado, "device.disconnect")

    def test_device_reapply_e_mutavel(self):
        resultado = NetworkManagerBackend._classificar_nmcli(
            ("device", "reapply", "eth0")
        )
        self.assertEqual(resultado, "device.reapply")

    def test_connection_show_e_read_only(self):
        resultado = NetworkManagerBackend._classificar_nmcli(
            ("-t", "--escape", "yes", "-f", "NAME,UUID", "connection", "show")
        )
        self.assertIsNone(resultado)

    def test_device_status_e_read_only(self):
        resultado = NetworkManagerBackend._classificar_nmcli(
            ("-t", "--escape", "yes", "-f", "DEVICE,STATE,CONNECTION", "device", "status")
        )
        self.assertIsNone(resultado)

    def test_general_status_e_read_only(self):
        resultado = NetworkManagerBackend._classificar_nmcli(
            ("-t", "-f", "STATE", "general", "status")
        )
        self.assertIsNone(resultado)

    def test_version_e_read_only(self):
        resultado = NetworkManagerBackend._classificar_nmcli(
            ("--version",)
        )
        self.assertIsNone(resultado)

    def test_connection_show_active_e_read_only(self):
        resultado = NetworkManagerBackend._classificar_nmcli(
            ("-t", "--escape", "yes", "-f", "NAME,DEVICE", "connection", "show", "--active")
        )
        self.assertIsNone(resultado)

    def test_connection_modify_com_flags_e_mutavel(self):
        """Flags antes do subcomando não devem impedir a detecção."""
        resultado = NetworkManagerBackend._classificar_nmcli(
            ("-t", "connection", "modify", "con1", "ipv4.method", "auto")
        )
        # -t não consome argumento, então primeiro significativo = connection
        self.assertEqual(resultado, "connection.modify")


# =============================================================================
# 2. MASCARAMENTO DE ARGUMENTOS SENSÍVEIS
# =============================================================================

class TestMascaramentoArgs(unittest.TestCase):

    def test_argumento_com_password_e_mascarado(self):
        resultado = NetworkManagerBackend._mascarar_args(
            ("connection", "modify", "con1", "802-1x.password", "segredo123")
        )
        self.assertEqual(resultado, [
            "connection", "modify", "con1", "802-1x.password", "***"
        ])

    def test_argumento_sem_dado_sensivel_preservado(self):
        resultado = NetworkManagerBackend._mascarar_args(
            ("connection", "modify", "con1", "ipv4.method", "auto")
        )
        self.assertEqual(resultado, [
            "connection", "modify", "con1", "ipv4.method", "auto"
        ])

    def test_argumento_credential_mascarado(self):
        resultado = NetworkManagerBackend._mascarar_args(
            ("connection", "modify", "con1", "wifi.credential-key", "abc123")
        )
        self.assertEqual(resultado, [
            "connection", "modify", "con1", "wifi.credential-key", "***"
        ])


# =============================================================================
# 3. INSTRUMENTAÇÃO — LOG DE MUTAÇÕES
# =============================================================================

class TestInstrumentacaoLog(unittest.TestCase):
    """Verifica que _nmcli gera logs de mutação e silencia read-only."""

    def test_connection_modify_gera_log(self):
        backend = _backend_mock()
        with self.assertLogs("rede.backends.networkmanager", level="INFO") as cm:
            backend._nmcli("connection", "modify", "con1", "ipv4.method", "auto")

        mensagens = " ".join(cm.output)
        self.assertIn("[networkmanager] nmcli mutável", mensagens)
        self.assertIn("connection.modify", mensagens)

    def test_connection_up_gera_log(self):
        backend = _backend_mock()
        with self.assertLogs("rede.backends.networkmanager", level="INFO") as cm:
            backend._nmcli("connection", "up", "id", "con1", "ifname", "eth0")

        mensagens = " ".join(cm.output)
        self.assertIn("connection.up", mensagens)

    def test_device_reapply_gera_log(self):
        backend = _backend_mock()
        with self.assertLogs("rede.backends.networkmanager", level="INFO") as cm:
            backend._nmcli("device", "reapply", "eth0")

        mensagens = " ".join(cm.output)
        self.assertIn("device.reapply", mensagens)

    def test_device_disconnect_gera_log(self):
        backend = _backend_mock()
        with self.assertLogs("rede.backends.networkmanager", level="INFO") as cm:
            backend._nmcli("device", "disconnect", "eth0")

        mensagens = " ".join(cm.output)
        self.assertIn("device.disconnect", mensagens)

    def test_connection_show_nao_gera_log(self):
        backend = _backend_mock()
        # assertNoLogs requer Python 3.10+
        logger_obj = logging.getLogger("rede.backends.networkmanager")
        handler = logging.handlers_module = None  # noqa

        # Abordagem compatível: capturar tudo e verificar que não contém mutação.
        with patch.object(logger_obj, "info") as mock_info:
            backend._nmcli(
                "-t", "--escape", "yes", "-f", "NAME,UUID",
                "connection", "show",
            )
            for chamada in mock_info.call_args_list:
                msg = chamada[0][0] if chamada[0] else ""
                self.assertNotIn("[networkmanager] nmcli mutável", msg)

    def test_general_status_nao_gera_log(self):
        backend = _backend_mock()
        logger_obj = logging.getLogger("rede.backends.networkmanager")

        with patch.object(logger_obj, "info") as mock_info:
            backend._nmcli("-t", "-f", "STATE", "general", "status", verificar=False)
            for chamada in mock_info.call_args_list:
                msg = chamada[0][0] if chamada[0] else ""
                self.assertNotIn("[networkmanager] nmcli mutável", msg)

    def test_log_nao_contem_segredo(self):
        backend = _backend_mock()
        with self.assertLogs("rede.backends.networkmanager", level="INFO") as cm:
            backend._nmcli(
                "connection", "modify", "con1",
                "802-1x.password", "minha_senha_secreta",
            )

        texto_completo = " ".join(cm.output)
        self.assertNotIn("minha_senha_secreta", texto_completo)
        self.assertIn("***", texto_completo)


# =============================================================================
# 4. PROVA NEGATIVA — PLANO NAT NÃO CHAMA NETWORKMANAGER MUTÁVEL
# =============================================================================

class TestNatNaoMutaNetworkManager(unittest.TestCase):
    """
    Prova que um plano tipo=nat NÃO chama funções mutáveis do
    NetworkManagerBackend.

    O fluxo NAT no aplicador:
        _aplicar_nat
          → definir_ipv4_forward  (sysctl, não NM)
          → aplicar_regras_nat    (nftables, não NM)

    Nenhuma das funções acima usa o backend NetworkManager.
    """

    @patch("rede.nucleo.aplicador.obter_backend")
    @patch("rede.nucleo.aplicador.aplicar_regras_nat")
    @patch("rede.nucleo.aplicador.definir_ipv4_forward")
    @patch("rede.nucleo.aplicador.obter_ipv4_forward", return_value=True)
    @patch("rede.nucleo.aplicador.obter_status_nat")
    def test_aplicar_nat_nao_chama_nm_mutavel(
        self,
        mock_status_nat,
        mock_obter_forward,
        mock_definir_forward,
        mock_aplicar_nat_regras,
        mock_obter_backend,
    ):
        from rede.nucleo.aplicador import _aplicar_nat  # noqa: delay import

        # Setup mocks
        mock_definir_forward.return_value = {
            "ok": True,
            "ipv4_forward": True,
            "persistente": True,
            "mecanismo": "/etc/sysctl.d/90-moonshield-network.conf",
        }
        mock_aplicar_nat_regras.return_value = {
            "ok": True,
            "alterado": True,
            "tabela": "moonshield_nat",
            "total_regras": 1,
            "status": {
                "disponivel": True,
                "ativo": True,
                "regras": [],
                "total_regras": 1,
                "tabela_existe": True,
            },
        }
        mock_status_nat.return_value = {
            "disponivel": True,
            "ativo": True,
            "regras": [
                {
                    "id": "1",
                    "interface_origem": "enp0s8",
                    "interface_saida": "enp0s3",
                    "rede_origem": "192.168.52.0/24",
                },
            ],
            "total_regras": 1,
            "tabela_existe": True,
        }

        # Backend mock
        backend_mock = MagicMock(spec=NetworkManagerBackend)
        mock_obter_backend.return_value = backend_mock

        plano = {
            "tipo": "nat",
            "alteracao_id": "test-nat-001",
            "timeout_segundos": 120,
            "nat": {
                "aplicar": True,
                "regras": [
                    {
                        "id": "1",
                        "tipo": "masquerade",
                        "interface_origem": "enp0s8",
                        "interface_saida": "enp0s3",
                        "rede_origem": "192.168.52.0/24",
                        "ativa": True,
                    }
                ],
            },
            "roteamento": {
                "ipv4_forward": True,
            },
        }

        resultado = _aplicar_nat(plano)
        self.assertIsNotNone(resultado)

        # PROVAS NEGATIVAS: NM mutável NÃO deve ter sido chamado.
        backend_mock.configurar_interface.assert_not_called()
        backend_mock.configurar_rotas.assert_not_called()
        backend_mock.ativar_interface.assert_not_called()
        backend_mock.desativar_interface.assert_not_called()
        backend_mock.restaurar_snapshot_interface.assert_not_called()
        backend_mock.restaurar_snapshot.assert_not_called()
        backend_mock.aplicar_interface.assert_not_called()

        # PROVAS POSITIVAS: NAT deve ter chamado nftables e sysctl.
        mock_definir_forward.assert_called_once_with(True)
        mock_aplicar_nat_regras.assert_called_once()

    @patch("rede.nucleo.aplicador.obter_backend")
    @patch("rede.nucleo.aplicador.aplicar_regras_nat")
    @patch("rede.nucleo.aplicador.definir_ipv4_forward")
    @patch("rede.nucleo.aplicador.obter_ipv4_forward", return_value=True)
    @patch("rede.nucleo.aplicador.obter_status_nat")
    def test_aplicar_plano_nat_nao_aplica_interfaces(
        self,
        mock_status_nat,
        mock_obter_forward,
        mock_definir_forward,
        mock_aplicar_nat_regras,
        mock_obter_backend,
    ):
        """
        Testa _aplicar_plano com tipo=nat: não deve chamar
        _aplicar_interfaces nem _aplicar_roteamento.
        """
        from rede.nucleo.aplicador import _aplicar_plano  # noqa

        mock_definir_forward.return_value = {
            "ok": True, "ipv4_forward": True,
            "persistente": True, "mecanismo": "sysctl",
        }
        mock_aplicar_nat_regras.return_value = {
            "ok": True, "alterado": True,
            "tabela": "moonshield_nat", "total_regras": 1,
            "status": {
                "disponivel": True, "ativo": True,
                "regras": [
                    {"id": "1", "interface_origem": "enp0s8",
                     "interface_saida": "enp0s3",
                     "rede_origem": "192.168.52.0/24"},
                ],
                "total_regras": 1, "tabela_existe": True,
            },
        }
        mock_status_nat.return_value = mock_aplicar_nat_regras.return_value["status"]

        backend_mock = MagicMock(spec=NetworkManagerBackend)
        mock_obter_backend.return_value = backend_mock

        plano = {
            "tipo": "nat",
            "alteracao_id": "test-nat-002",
            "timeout_segundos": 120,
            "nat": {
                "aplicar": True,
                "regras": [
                    {
                        "id": "1",
                        "tipo": "masquerade",
                        "interface_origem": "enp0s8",
                        "interface_saida": "enp0s3",
                        "rede_origem": "192.168.52.0/24",
                        "ativa": True,
                    }
                ],
            },
            "roteamento": {
                "ipv4_forward": True,
            },
        }

        resultado = _aplicar_plano(plano)

        # Interfaces e roteamento não devem ter sido chamados.
        self.assertIsNone(resultado.get("interfaces"))
        self.assertIsNone(resultado.get("roteamento"))
        self.assertIsNotNone(resultado.get("nat"))

        # NM não deve ter sido chamado para mutações.
        backend_mock.configurar_interface.assert_not_called()
        backend_mock.configurar_rotas.assert_not_called()
        backend_mock.ativar_interface.assert_not_called()
        backend_mock.restaurar_snapshot_interface.assert_not_called()
        backend_mock.aplicar_interface.assert_not_called()

    @patch("rede.nucleo.aplicador.obter_backend")
    def test_interfaces_impactadas_nat_exclui_rotas_e_nat_interfaces(
        self,
        mock_obter_backend,
    ):
        """
        _interfaces_impactadas com tipo=nat NÃO deve coletar
        interfaces de roteamento nem de regras NAT.
        """
        from rede.nucleo.aplicador import _interfaces_impactadas  # noqa

        plano = {
            "tipo": "nat",
            "interfaces": [],
            "roteamento": {
                "ipv4_forward": True,
                "interfaces_alvo": ["enp0s3", "enp0s8"],
                "rotas": [
                    {"interface_nome": "enp0s3"},
                    {"interface_nome": "enp0s8"},
                ],
            },
            "nat": {
                "aplicar": True,
                "regras": [
                    {
                        "interface_origem": "enp0s8",
                        "interface_saida": "enp0s3",
                    }
                ],
            },
        }

        resultado = _interfaces_impactadas(plano)

        # Para tipo=nat, as interfaces de roteamento e NAT são
        # excluídas propositalmente para que o snapshot não inclua
        # interfaces NM desnecessárias.
        self.assertEqual(resultado, [])


# =============================================================================
# 5. VERIFICAÇÃO EXTRA — connection.show NÃO APARECE COMO MUTÁVEL
# =============================================================================

class TestShowNaoMutavel(unittest.TestCase):
    """
    Garante que variações de 'connection show' com flags diversas
    nunca são classificadas como mutáveis.
    """

    def test_show_simples(self):
        self.assertIsNone(
            NetworkManagerBackend._classificar_nmcli(("connection", "show"))
        )

    def test_show_com_nome(self):
        self.assertIsNone(
            NetworkManagerBackend._classificar_nmcli(("connection", "show", "con1"))
        )

    def test_show_com_flags_completas(self):
        self.assertIsNone(
            NetworkManagerBackend._classificar_nmcli(
                ("-t", "--escape", "yes", "-f", "ALL", "connection", "show", "con1")
            )
        )


if __name__ == "__main__":
    unittest.main()

