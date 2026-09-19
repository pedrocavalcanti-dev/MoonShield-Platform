import json
import logging
from typing import Any
from django.utils import timezone

from rede.services.agent_client import (
    requisitar_agent,
    agent_disponivel,
    AgentIndisponivelErro,
    AgentTimeoutErro,
    AgentOperacaoRecusadaErro,
    AgentRespostaInvalidaErro
)

logger = logging.getLogger(__name__)

def executar_diagnostico_no_agent(tool: str, target: str, options: dict[str, Any]) -> dict[str, Any]:
    """
    Executa a ferramenta de diagnóstico através do MoonShield-Agent.
    """
    if not agent_disponivel():
        return {
            "ok": False,
            "status": "err",
            "error_code": "agent_unavailable",
            "summary": "MoonShield Agent indisponível."
        }

    payload = {
        "tool": tool,
        "target": target,
        "options": options or {}
    }

    # timeout: we can pass a higher timeout for things like MTR or traceroute
    timeout = 35.0
    if tool in ("mtr", "traceroute"):
        timeout = 65.0

    try:
        resultado = requisitar_agent("diagnostic.execute", dados=payload, timeout=timeout)

        # O agent_client já valida se "ok" está presente
        # Se resultado for um dict válido retornado pela action do Agent:
        return resultado.get("dados", resultado)

    except AgentTimeoutErro:
        logger.warning(f"Timeout ao executar {tool} no Agent.")
        return {
            "ok": False,
            "status": "err",
            "error_code": "timeout",
            "summary": "Timeout de comunicação com o Agent."
        }
    except (AgentIndisponivelErro, ConnectionError):
        logger.warning(f"Agent indisponível ao tentar executar {tool}.")
        return {
            "ok": False,
            "status": "err",
            "error_code": "agent_unavailable",
            "summary": "MoonShield Agent offline ou indisponível."
        }
    except AgentOperacaoRecusadaErro as exc:
        return {
            "ok": False,
            "status": "err",
            "error_code": "execution_failed",
            "summary": str(exc)
        }
    except Exception as exc:
        logger.exception(f"Erro interno no client IPC durante {tool}.")
        return {
            "ok": False,
            "status": "err",
            "error_code": "internal_error",
            "summary": f"Falha de comunicação: {exc}"
        }
