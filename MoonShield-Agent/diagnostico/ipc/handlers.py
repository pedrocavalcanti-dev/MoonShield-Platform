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

    if acao == "diagnostic.live.start":
        from diagnostico.live import start_live_session
        tool = dados.get("tool")
        target = dados.get("target") or ""
        options = dados.get("options", {})
        if not tool or not target:
            return {"ok": False, "status": "err", "error_code": "missing_parameters", "summary": "Parâmetros tool e target são obrigatórios."}
        return start_live_session(tool, target, options)

    if acao == "diagnostic.live.status":
        from diagnostico.live import status_live_session
        session_id = dados.get("session_id")
        if not session_id:
            return {"ok": False, "status": "err", "error_code": "missing_parameters", "summary": "session_id obrigatório."}
        return status_live_session(session_id)

    if acao == "diagnostic.live.stop":
        from diagnostico.live import stop_live_session
        session_id = dados.get("session_id")
        if not session_id:
            return {"ok": False, "status": "err", "error_code": "missing_parameters", "summary": "session_id obrigatório."}
        return stop_live_session(session_id)

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
