"""Contrato externo V1 para ações Suricata no socket do MoonShield Agent."""

from __future__ import annotations

import json
import socket
import socketserver
import sys
import types
import unittest
from unittest.mock import patch

try:
    import grp  # noqa: F401
except ModuleNotFoundError:  # pragma: no cover - compatibilidade do runner Windows
    sys.modules["grp"] = types.SimpleNamespace()

if not hasattr(socketserver, "UnixStreamServer"):  # pragma: no cover - Windows
    socketserver.UnixStreamServer = type("UnixStreamServer", (), {})
if not hasattr(socket, "AF_UNIX"):  # pragma: no cover - Windows
    socket.AF_UNIX = 1

from firewall.ipc import servidor
from firewall.ipc.protocolo import (
    decodificar_requisicao,
    resposta_erro,
    resposta_ok,
)
from suricata.ipc import handlers as handlers_suricata
from suricata.ipc.handlers import ErroHandlerSuricata


REQUEST_ID = "teste-rules-update-123"
ACTION = "suricata.rules.update"


class SuricataRulesUpdateContractTests(unittest.TestCase):
    def _request(self, action: str = ACTION, dados: dict | None = None):
        return decodificar_requisicao(
            json.dumps(
                {
                    "versao": 1,
                    "id": REQUEST_ID,
                    "acao": action,
                    "dados": dados or {},
                }
            )
        )

    def _response(self, executar, *, action: str = ACTION, dados: dict | None = None):
        requisicao = self._request(action, dados)
        modulo = types.SimpleNamespace(executar_acao_suricata=executar)

        with patch.object(servidor.importlib, "import_module", return_value=modulo):
            try:
                resultado = servidor._despachar(requisicao)
            except servidor.ErroOperacao as exc:
                return resposta_erro(
                    requisicao,
                    codigo=exc.codigo,
                    mensagem=str(exc),
                    detalhes=exc.detalhes,
                ).para_dict()

        return resposta_ok(requisicao, resultado).para_dict()

    def _assert_envelope(self, response: dict, *, action: str = ACTION):
        self.assertEqual(response["versao"], 1)
        self.assertEqual(response["id"], REQUEST_ID)
        self.assertEqual(response["acao"], action)
        self.assertIsInstance(response["ok"], bool)

    def test_rules_update_success_preserves_external_envelope(self):
        response = self._response(lambda action, dados: {"atualizado": True})

        self._assert_envelope(response)
        self.assertTrue(response["ok"])

    def test_legacy_suricata_adapter_preserves_external_id_and_action(self):
        request = {
            "versao": 1,
            "id": REQUEST_ID,
            "acao": ACTION,
            "dados": {},
        }
        with patch.object(
            handlers_suricata,
            "executar_acao_suricata",
            return_value={"atualizado": True},
        ):
            response = handlers_suricata.tratar_requisicao_suricata(request)

        self._assert_envelope(response)
        self.assertTrue(response["ok"])

    def test_rules_update_failure_preserves_external_envelope(self):
        def falhar(action, dados):
            raise ErroHandlerSuricata("Falha controlada.", codigo="rules_update_falhou")

        response = self._response(falhar)

        self._assert_envelope(response)
        self.assertFalse(response["ok"])
        self.assertEqual(response["erro"]["codigo"], "rules_update_falhou")

    def test_rules_update_invalid_payload_preserves_external_envelope(self):
        def payload_invalido(action, dados):
            raise ErroHandlerSuricata("Payload inválido.", codigo="regras_payload_invalido")

        response = self._response(payload_invalido, dados={"campo": "não permitido"})

        self._assert_envelope(response)
        self.assertFalse(response["ok"])
        self.assertEqual(response["erro"]["codigo"], "regras_payload_invalido")

    def test_rules_update_internal_exception_preserves_external_envelope(self):
        response = self._response(
            lambda action, dados: (_ for _ in ()).throw(RuntimeError("falha interna"))
        )

        self._assert_envelope(response)
        self.assertFalse(response["ok"])
        self.assertEqual(response["erro"]["codigo"], "suricata_operacao_falhou")

    def test_existing_suricata_actions_keep_their_correlation(self):
        for action in (
            "suricata.status",
            "suricata.diagnostics",
            "suricata.config.validate",
            "suricata.service.status",
        ):
            with self.subTest(action=action):
                response = self._response(lambda received_action, dados: {"acao": received_action}, action=action)

                self._assert_envelope(response, action=action)
                self.assertTrue(response["ok"])

