from __future__ import annotations

import ipaddress
import logging

from django.core.exceptions import ValidationError

from dispositivos.models import Dispositivo

from wifi_access.models import normalize_mac


logger = logging.getLogger(__name__)

# Estados do inventário que não garantem que o IP ainda pertence ao MAC.
_UNRELIABLE_STATUS = {Dispositivo.Status.OFFLINE, Dispositivo.Status.STALE}
# Estados de neighbour que não representam associação IP -> MAC utilizável.
_INVALID_NEIGH_STATES = {"FAILED", "INCOMPLETE", "NOARP"}


class MacResolutionError(ValueError):
    def __init__(self, message: str, *, code: str = "mac_nao_encontrado"):
        super().__init__(message)
        self.code = code


def _ip(value: object) -> str:
    try:
        return str(ipaddress.IPv4Address(str(value or "").strip()))
    except ipaddress.AddressValueError as exc:
        raise MacResolutionError("Endereço IPv4 inválido.", code="ip_invalido") from exc


def _safe_mac(value: object) -> str | None:
    try:
        return normalize_mac(value)
    except ValidationError:
        return None


def _inventory_mac(ip: str) -> str | None:
    """Fonte 1: inventário Dispositivo, somente se inequívoco e não obsoleto."""
    rows = Dispositivo.objects.filter(current_ip=ip).exclude(mac__isnull=True).exclude(mac="")
    candidates = {
        mac for raw_mac, status in rows.values_list("mac", "status")
        if status not in _UNRELIABLE_STATUS and (mac := _safe_mac(raw_mac))
    }
    return candidates.pop() if len(candidates) == 1 else None


def agent_neighbors() -> list[dict]:
    """Fonte 2: tabela neighbour lida pelo Agent (ação read-only existente).

    Django nunca executa ``ip neigh``; reutiliza ``diagnostic.execute`` com
    ``arp_table``. Sem Agent (ex.: Windows) retorna lista vazia, sem traceback.
    """
    try:
        from rede.services.agent_client import agent_disponivel, requisitar_agent

        if not agent_disponivel():
            return []
        result = requisitar_agent("diagnostic.execute", dados={"tool": "arp_table", "target": "", "options": {}}, timeout=10)
    except Exception as exc:  # Agent offline, socket inexistente, plataforma sem AF_UNIX etc.
        logger.info("Tabela neighbour indisponível via Agent: %s", exc)
        return []
    data = result.get("dados", result) if isinstance(result, dict) else {}
    if not isinstance(data, dict) or data.get("status") != "ok":
        return []
    neighbors = (data.get("structured") or {}).get("neighbors")
    return [item for item in neighbors if isinstance(item, dict)] if isinstance(neighbors, list) else []


def _neighbor_mac(ip: str) -> str | None:
    candidates = set()
    for item in agent_neighbors():
        states = item.get("state") or []
        states = {str(state).upper() for state in (states if isinstance(states, list) else [states])}
        if str(item.get("dst") or "") != ip or states & _INVALID_NEIGH_STATES:
            continue
        if mac := _safe_mac(item.get("lladdr")):
            candidates.add(mac)
    return candidates.pop() if len(candidates) == 1 else None


def resolve_mac(ip_address: object) -> str:
    """Resolve IP -> MAC pela visão de rede do próprio MoonShield.

    Ordem: inventário confiável -> neighbour do Agent. Ambiguidade ou ausência
    resultam em ``MacResolutionError`` controlado; o MAC nunca vem do cliente.
    """
    ip = _ip(ip_address)
    mac = _inventory_mac(ip) or _neighbor_mac(ip)
    if not mac:
        raise MacResolutionError("Não foi possível associar o IP a um MAC na rede MoonShield.")
    return mac
