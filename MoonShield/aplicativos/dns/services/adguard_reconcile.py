"""Gatilho pós-confirmação de Rede para o reconcile privilegiado do DNS."""

from __future__ import annotations

from rede.services.agent_client import requisitar_agent
from rede.services.topologia import obter_topologia


def reconciliar_adguard_apos_rede() -> dict:
    """Envia ao Agent a topologia já confirmada; Django não controla serviços."""
    return requisitar_agent(
        "adguard.reconcile",
        {"topologia": obter_topologia()},
        timeout=20,
    )
