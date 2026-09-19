"""
MoonShield Agent — Diagnóstico / IPC Handlers
===========================================
"""
import logging
from typing import Any

from diagnostico.executor import dispatch_tool, TARGETLESS_TOOLS

logger = logging.getLogger(__name__)

def executar_acao_diagnostico(acao: str, dados: dict[str, Any]) -> dict[str, Any]:
    """
    Handler principal para as ações diagnostic.*

    Ações suportadas:
    - diagnostic.execute
    """
    if acao == "diagnostic.execute":
        tool = dados.get("tool")
        target = dados.get("target") or ""
        options = dados.get("options", {})

        if not tool:
            return {
                "ok": False,
                "status": "err",
                "error_code": "missing_parameters",
                "summary": "Parâmetro 'tool' é obrigatório."
            }

        if tool not in TARGETLESS_TOOLS and not target:
            return {
                "ok": False,
                "status": "err",
                "error_code": "missing_parameters",
                "summary": "Parâmetro 'target' é obrigatório para esta ferramenta."
            }

        logger.info(f"[diagnostico] Executando tool={tool} target={target}")
        result = dispatch_tool(tool, target, options)
        logger.info(f"[diagnostico] Finalizado tool={tool} status={result.get('status')}")

        return result

    return {
        "ok": False,
        "status": "err",
        "error_code": "unknown_action",
        "summary": f"Ação desconhecida: {acao}"
    }
