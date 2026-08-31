"""
dns/services/adguard_client.py — MoonShield
─────────────────────────────────────────────────────────────────────────────
Cliente da API do AdGuard Home usado pelo módulo DNS/NOC.

Objetivos desta versão:
- nunca inventar métricas em modo PROD;
- expor versão/uptime/estado real do AdGuard;
- enriquecer clientes a partir do Query Log real;
- produzir latência por hora a partir das consultas reais;
- manter compatibilidade com os endpoints e o frontend já existentes.
─────────────────────────────────────────────────────────────────────────────
"""

import logging
import re
import shutil
import socket
import subprocess
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from requests import RequestException, Session

logger = logging.getLogger(__name__)

TIMEOUT = 6
SESSION_TTL = 300

# No laboratório atual ~1k consultas cabem tranquilamente aqui. Em ambientes
# maiores o histórico deverá migrar para persistência própria/paginação.
MAX_QUERYLOG = 2000

EMOJIS = ["💻", "📱", "🖥️", "📺", "🎮", "🔌", "⌚", "🖨️", "📡", "🔊"]

_BLOCKED_REASONS = {
    "FilteredBlackList",
    "FilteredBlockList",
    "FilteredParental",
    "FilteredSafeBrowsing",
    "BlockedService",
    "FilteredCustom",
    "Rewrite",
}

_ALLOWED_REASONS = {
    "NotFilteredNotFound",
    "NotFilteredWhiteList",
    "NotFilteredError",
    "NotFiltered",
}

_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
_ADGUARD_BIN_CANDIDATES = (
    "/opt/moonshield-system/services/adguard/AdGuardHome/AdGuardHome",
    "/opt/AdGuardHome/AdGuardHome",
)


def _is_blocked(entry: dict) -> bool:
    reason = (entry.get("reason") or "").strip()

    if reason in _ALLOWED_REASONS:
        return False
    if reason in _BLOCKED_REASONS:
        return True
    if reason.startswith("Filtered") and not reason.startswith("NotFiltered"):
        return True

    # Alguns retornos do AdGuard trazem regra aplicada mesmo sem reason
    # conhecido. Só consideramos bloqueio se houver evidência explícita.
    rules = entry.get("rules") or []
    if rules and isinstance(rules, list):
        first = rules[0] if rules else None
        if isinstance(first, dict):
            text = (first.get("text") or "").strip()
            if text and not text.startswith("@@"):
                return True

    return False


def _parse_elapsed_ms(entry: dict, blocked: bool) -> Optional[float]:
    if blocked:
        return None

    raw_ms = entry.get("elapsedMs")
    if raw_ms is not None:
        try:
            val = round(float(raw_ms), 2)
            return val if val >= 0 else None
        except (ValueError, TypeError):
            pass

    raw_s = entry.get("elapsed")
    if raw_s is not None:
        try:
            val = round(float(raw_s) * 1000, 2)
            return val if val >= 0 else None
        except (ValueError, TypeError):
            pass

    return None


def _parse_dt(iso: str) -> Optional[datetime]:
    if not iso:
        return None
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone()
    except Exception:
        return None


def _fmt_time(iso: str) -> str:
    dt = _parse_dt(iso)
    if dt:
        return dt.strftime("%H:%M:%S")
    return iso[11:19] if iso and len(iso) >= 19 else ""


def _human_last_seen(iso: str) -> str:
    dt = _parse_dt(iso)
    if not dt:
        return "—"

    delta = datetime.now().astimezone() - dt
    seconds = max(0, int(delta.total_seconds()))

    if seconds < 60:
        return "agora"
    if seconds < 3600:
        return f"{seconds // 60} min atrás"
    if seconds < 86400:
        return f"{seconds // 3600}h atrás"
    return f"{seconds // 86400}d atrás"


def _top_counter(counter: Counter, limit: int = 5) -> list:
    return [{"domain": domain, "n": int(count)} for domain, count in counter.most_common(limit)]


class AdGuardError(Exception):
    """Erro controlado de integração com o AdGuard Home."""


class AdGuardClient:
    def __init__(self, url: str, user: str, password: str, https: bool = False):
        url = (url or "").strip().rstrip("/")
        if not url.startswith(("http://", "https://")):
            url = ("https://" if https else "http://") + url

        self.base_url = url
        self.user = user or ""
        self.password = password or ""
        self._session: Optional[Session] = None
        self._last_login = 0.0

    # ──────────────────────────────────────────────────────────────────────
    # HTTP / sessão
    # ──────────────────────────────────────────────────────────────────────

    def _needs_login(self) -> bool:
        return self._session is None or (time.time() - self._last_login) > SESSION_TTL

    def _new_session(self) -> Session:
        session = Session()
        # Mantém compatibilidade com instalações locais/self-signed.
        # Quando houver PKI própria, isso pode ser tornado configurável.
        session.verify = False
        session.headers.update({"Accept": "application/json"})
        return session

    def _login(self) -> None:
        session = self._new_session()

        # Instalações sem autenticação não precisam do POST /control/login.
        if not self.user:
            self._session = session
            self._last_login = time.time()
            return

        url = f"{self.base_url}/control/login"
        try:
            response = session.post(
                url,
                json={"name": self.user, "password": self.password},
                timeout=TIMEOUT,
            )
            response.raise_for_status()
        except RequestException as exc:
            raise AdGuardError(f"Falha no login AdGuard ({url}): {exc}") from exc

        self._session = session
        self._last_login = time.time()
        logger.info("AdGuard login OK: %s", self.base_url)

    def _ensure_session(self) -> Session:
        if self._needs_login():
            self._login()
        assert self._session is not None
        return self._session

    def _get(self, path: str, params: dict = None):
        session = self._ensure_session()
        url = f"{self.base_url}{path}"

        try:
            response = session.get(url, params=params, timeout=TIMEOUT)

            if response.status_code in (401, 403) and self.user:
                self._last_login = 0
                self._login()
                session = self._ensure_session()
                response = session.get(url, params=params, timeout=TIMEOUT)

            response.raise_for_status()
            return response.json()
        except (RequestException, ValueError) as exc:
            raise AdGuardError(f"Erro GET {url}: {exc}") from exc

    def _post(self, path: str, *, json_data: dict = None):
        session = self._ensure_session()
        url = f"{self.base_url}{path}"

        try:
            response = session.post(url, json=json_data, timeout=TIMEOUT)

            if response.status_code in (401, 403) and self.user:
                self._last_login = 0
                self._login()
                session = self._ensure_session()
                response = session.post(url, json=json_data, timeout=TIMEOUT)

            response.raise_for_status()

            if not response.content:
                return {}
            try:
                return response.json()
            except ValueError:
                return {}
        except RequestException as exc:
            raise AdGuardError(f"Erro POST {url}: {exc}") from exc

    # ──────────────────────────────────────────────────────────────────────
    # Endpoints RAW
    # ──────────────────────────────────────────────────────────────────────

    def get_status(self) -> dict:
        data = self._get("/control/status")
        return data if isinstance(data, dict) else {}

    def get_stats(self) -> dict:
        data = self._get("/control/stats")
        return data if isinstance(data, dict) else {}

    def get_querylog_raw(self, limit: int = MAX_QUERYLOG) -> list:
        limit = max(1, min(int(limit), MAX_QUERYLOG))
        data = self._get("/control/querylog", params={"limit": limit})
        if isinstance(data, dict):
            return data.get("data", []) or []
        return data or []

    def get_filtering_status(self) -> dict:
        data = self._get("/control/filtering/status")
        return data if isinstance(data, dict) else {}

    # ──────────────────────────────────────────────────────────────────────
    # Regras / ações
    # ──────────────────────────────────────────────────────────────────────

    def get_custom_rules(self) -> list:
        data = self.get_filtering_status()
        rules = data.get("user_rules", [])
        return rules if isinstance(rules, list) else []

    def set_custom_rules(self, rules: list) -> bool:
        clean = []
        seen = set()

        for rule in rules or []:
            if not isinstance(rule, str):
                continue
            rule = rule.strip()
            if not rule or rule in seen:
                continue
            seen.add(rule)
            clean.append(rule)

        self._post("/control/filtering/set_rules", json_data={"rules": clean})
        return True

    def flush_cache(self) -> bool:
        self._post("/control/cache/clear")
        return True

    def update_filters(self) -> dict:
        data = self._post("/control/filtering/refresh", json_data={"whitelist": False})
        return {"updated": int(data.get("updated", 0) or 0)}

    # ──────────────────────────────────────────────────────────────────────
    # Runtime / saúde
    # ──────────────────────────────────────────────────────────────────────

    def _is_local(self) -> bool:
        try:
            host = (urlparse(self.base_url).hostname or "").lower()
            if host in _LOCAL_HOSTS:
                return True

            local_ips = {"127.0.0.1", "::1"}
            try:
                for info in socket.getaddrinfo(socket.gethostname(), None):
                    address = info[4][0]
                    if address:
                        local_ips.add(address)
            except OSError:
                pass

            # Em appliances com várias NICs o hostname nem sempre resolve para
            # todos os endereços. hostname -I cobre WAN/LAN/MGMT locais.
            try:
                result = subprocess.run(
                    ["hostname", "-I"],
                    capture_output=True,
                    text=True,
                    timeout=2,
                    check=False,
                )
                local_ips.update((result.stdout or "").split())
            except Exception:
                pass

            return host in local_ips
        except Exception:
            return False

    @staticmethod
    def _local_binary_version() -> str:
        candidates = list(_ADGUARD_BIN_CANDIDATES)
        resolved = shutil.which("AdGuardHome")
        if resolved:
            candidates.append(resolved)

        for candidate in candidates:
            path = Path(candidate)
            if not path.is_file():
                continue
            try:
                result = subprocess.run(
                    [str(path), "--version"],
                    capture_output=True,
                    text=True,
                    timeout=2,
                    check=False,
                )
                raw = (result.stdout or result.stderr or "").strip()
                match = re.search(r"version\s+([^\s,]+)", raw, re.IGNORECASE)
                if match:
                    return match.group(1)
            except Exception:
                continue

        return "—"

    @staticmethod
    def _local_systemd_uptime_seconds() -> int:
        """
        Calcula uptime do serviço usando monotonic clock.
        Não depende de locale nem de parsing de data textual do systemd.
        """
        try:
            result = subprocess.run(
                [
                    "systemctl",
                    "show",
                    "AdGuardHome",
                    "--property=ActiveEnterTimestampMonotonic",
                    "--value",
                ],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
            active_us = int((result.stdout or "0").strip() or 0)
            if active_us <= 0:
                return 0

            with open("/proc/uptime", "r", encoding="utf-8") as handle:
                boot_uptime_s = float(handle.read().split()[0])

            active_s = active_us / 1_000_000
            return max(0, int(boot_uptime_s - active_s))
        except Exception:
            return 0

    def _build_health(self, status: dict, filtering: dict) -> dict:
        version = (
            status.get("version")
            or status.get("running_version")
            or status.get("dns_version")
            or ""
        )

        if not version and self._is_local():
            version = self._local_binary_version()

        uptime_seconds = int(status.get("uptime", 0) or 0)
        if not uptime_seconds and self._is_local():
            uptime_seconds = self._local_systemd_uptime_seconds()

        protection = bool(status.get("protection_enabled", False))
        running = bool(status.get("running", True))

        filters = filtering.get("filters", [])
        enabled_filters = 0
        if isinstance(filters, list):
            enabled_filters = sum(
                1
                for item in filters
                if isinstance(item, dict) and item.get("enabled", True)
            )

        dns_addresses = status.get("dns_addresses") or []
        if not isinstance(dns_addresses, list):
            dns_addresses = [str(dns_addresses)]

        safe_browsing = status.get(
            "safebrowsing_enabled",
            status.get("safe_browsing_enabled"),
        )

        return {
            "api": "ok",
            "running": running,
            "protection_enabled": protection,
            "safe_browsing": (
                bool(safe_browsing)
                if safe_browsing is not None
                else None
            ),
            "version": version or "—",
            "uptime_seconds": uptime_seconds,
            "uptime": self._uptime_str(uptime_seconds),
            "dns_port": status.get("dns_port", 53),
            "dns_addresses": dns_addresses,
            "filters_enabled": enabled_filters,
        }

    # ──────────────────────────────────────────────────────────────────────
    # Query log formatado
    # ──────────────────────────────────────────────────────────────────────

    def get_querylog_formatted(self, limit: int = 50, since: str = None) -> list:
        raw = self.get_querylog_raw(limit=min(limit, MAX_QUERYLOG))

        result = []
        for entry in raw:
            entry_time = entry.get("time", "")
            if since and entry_time and entry_time <= since:
                continue

            question = entry.get("question") or {}
            blocked = _is_blocked(entry)

            rules = entry.get("rules") or []
            filter_name = ""
            if rules and isinstance(rules, list) and isinstance(rules[0], dict):
                filter_name = (rules[0].get("text") or "").strip()

            if not filter_name and blocked:
                filter_name = "AdGuard DNS filter"

            client_info = entry.get("client_info") or {}
            client_name = ""
            if isinstance(client_info, dict):
                client_name = (client_info.get("name") or "").strip()
                whois = client_info.get("whois_info")
                if not client_name and isinstance(whois, dict):
                    client_name = (whois.get("orgname") or "").strip()

            domain = (question.get("name") or "?").rstrip(".")
            qtype = question.get("type") or "—"
            ip = entry.get("client") or "?"

            result.append(
                {
                    "time": entry_time,
                    "time_fmt": _fmt_time(entry_time),
                    "ip": ip,
                    "client_name": client_name or "",
                    "domain": domain,
                    "type": qtype,
                    "blocked": blocked,
                    "status": "Bloqueado" if blocked else "Processado",
                    "elapsed_ms": _parse_elapsed_ms(entry, blocked),
                    "filter": filter_name,
                    "reason": entry.get("reason", ""),
                    "upstream": entry.get("upstream", ""),
                    "cached": bool(entry.get("cached", False)),
                }
            )

        result.sort(key=lambda item: item.get("time", ""), reverse=True)
        return result

    # ──────────────────────────────────────────────────────────────────────
    # Agregação principal
    # ──────────────────────────────────────────────────────────────────────

    def fetch_all(self) -> dict:
        status = self.get_status()
        stats = self.get_stats()
        filtering = self.get_filtering_status()
        raw_querylog = self.get_querylog_raw(limit=MAX_QUERYLOG)

        clientes = self._build_clients_from_querylog(raw_querylog)

        # Se o querylog estiver vazio, ainda expõe os clientes do /stats,
        # sem inventar quantidade de bloqueios.
        if not clientes:
            clientes = self._build_clients_from_stats(stats.get("top_clients", []))

        health = self._build_health(status, filtering)
        metrics = self._build_metrics(status, stats, clientes, health)

        filters = filtering.get("filters", [])
        filter_count = len(filters) if isinstance(filters, list) else 0

        return {
            "ok": True,
            "metrics": metrics,
            "health": health,
            "charts": self._build_charts(stats, raw_querylog),
            "top_consultados": self._build_top(stats.get("top_queried_domains", []), limit=8),
            "top_bloqueados": self._build_top(stats.get("top_blocked_domains", []), limit=8),
            "clientes": clientes,
            "filter_count": filter_count,
        }

    @staticmethod
    def _uptime_str(seconds: int) -> str:
        if not seconds:
            return "—"

        seconds = int(seconds)
        days, rem = divmod(seconds, 86400)
        hours, rem = divmod(rem, 3600)
        minutes, _ = divmod(rem, 60)

        if days:
            return f"{days}d {hours}h"
        if hours:
            return f"{hours}h {minutes}min"
        return f"{minutes}min"

    def _build_metrics(
        self,
        status: dict,
        stats: dict,
        clientes: list,
        health: dict,
    ) -> dict:
        queries = int(stats.get("num_dns_queries", 0) or 0)
        bloqueios = int(stats.get("num_blocked_filtering", 0) or 0)
        pct = round((bloqueios / queries) * 100, 1) if queries else 0.0
        latencia = round((float(stats.get("avg_processing_time", 0) or 0)) * 1000, 1)

        return {
            "queries": queries,
            "bloqueios": bloqueios,
            "pctBloq": pct,
            "clientes": len(clientes),
            "latencia": latencia,
            "uptime": health.get("uptime", "—"),
            "uptime_seconds": int(health.get("uptime_seconds", 0) or 0),
            # Não há comparação com período anterior no AdGuard atual.
            # O frontend usa null para não exibir tendência inventada.
            "trends": {
                "queries": None,
                "bloqueios": None,
            },
        }

    @staticmethod
    def _build_charts(stats: dict, raw_querylog: list) -> dict:
        """
        Queries/bloqueios usam as séries reais do /control/stats.
        Latência média/pico é derivada do Query Log real, sem random.
        """
        now = datetime.now().astimezone().replace(minute=0, second=0, microsecond=0)
        slots = [now - timedelta(hours=23 - i) for i in range(24)]
        labels = [slot.strftime("%Hh") for slot in slots]
        slot_keys = [slot.strftime("%Y-%m-%d-%H") for slot in slots]
        slot_index = {key: idx for idx, key in enumerate(slot_keys)}

        latency_values = [[] for _ in range(24)]
        q_from_log = [0] * 24
        b_from_log = [0] * 24

        for entry in raw_querylog or []:
            dt = _parse_dt(entry.get("time", ""))
            if not dt:
                continue

            key = dt.replace(minute=0, second=0, microsecond=0).strftime("%Y-%m-%d-%H")
            idx = slot_index.get(key)
            if idx is None:
                continue

            q_from_log[idx] += 1
            blocked = _is_blocked(entry)
            if blocked:
                b_from_log[idx] += 1

            elapsed = _parse_elapsed_ms(entry, blocked)
            if elapsed is not None:
                latency_values[idx].append(float(elapsed))

        latency = [
            round(sum(values) / len(values), 1) if values else 0
            for values in latency_values
        ]
        latency_peak = [
            round(max(values), 1) if values else 0
            for values in latency_values
        ]

        stats_q = list(stats.get("dns_queries", []) or [])
        stats_b = list(stats.get("blocked_filtering", []) or [])

        # Algumas versões retornam exatamente 24 posições; quando não retornam,
        # usamos o Query Log real em vez de preencher com números artificiais.
        queries = stats_q[-24:] if len(stats_q) >= 24 else q_from_log
        bloqueios = stats_b[-24:] if len(stats_b) >= 24 else b_from_log

        if len(queries) < 24:
            queries = ([0] * (24 - len(queries))) + queries
        if len(bloqueios) < 24:
            bloqueios = ([0] * (24 - len(bloqueios))) + bloqueios

        return {
            "hours": labels,
            "queries": [int(v or 0) for v in queries[:24]],
            "bloqueios": [int(v or 0) for v in bloqueios[:24]],
            "latency": latency,
            "latency_peak": latency_peak,
        }

    @staticmethod
    def _build_top(raw: list, limit: int = 8) -> list:
        result = []

        for item in (raw or [])[:limit]:
            if not isinstance(item, dict):
                continue

            for key, count in item.items():
                try:
                    count = int(count or 0)
                except (TypeError, ValueError):
                    count = 0

                result.append({"domain": str(key).rstrip("."), "n": count})
                break

        return result

    @staticmethod
    def _build_clients_from_stats(raw: list) -> list:
        """
        Fallback honesto: /stats informa queries por cliente, mas não fornece
        bloqueios por cliente. Por isso não inventamos percentual.
        """
        clients = []

        for index, item in enumerate(raw or []):
            if not isinstance(item, dict):
                continue

            for ip, count in item.items():
                try:
                    count = int(count or 0)
                except (TypeError, ValueError):
                    count = 0

                if count <= 0:
                    break

                clients.append(
                    {
                        "id": index + 1,
                        "emoji": EMOJIS[index % len(EMOJIS)],
                        "name": ip,
                        "ip": ip,
                        "mac": "—",
                        "status": "online",
                        "queries": count,
                        "bloqueios": 0,
                        "pct": 0.0,
                        "lastSeen": "—",
                        "lastSeenIso": "",
                        "reqMin": None,
                        "topConsultados": [],
                        "topBloqueados": [],
                        "activity": [],
                        "sampled": True,
                    }
                )
                break

        return clients

    @staticmethod
    def _build_clients_from_querylog(raw_ql: list) -> list:
        agg = defaultdict(
            lambda: {
                "queries": 0,
                "bloqueios": 0,
                "last_time": "",
                "first_dt": None,
                "last_dt": None,
                "name": "",
                "top_queries": Counter(),
                "top_blocked": Counter(),
                "activity": Counter(),
            }
        )

        for entry in raw_ql or []:
            ip = (entry.get("client") or "").strip()
            if not ip:
                continue

            question = entry.get("question") or {}
            domain = (question.get("name") or "").rstrip(".")
            blocked = _is_blocked(entry)
            entry_time = entry.get("time", "")
            dt = _parse_dt(entry_time)

            data = agg[ip]
            data["queries"] += 1
            data["bloqueios"] += int(blocked)

            if entry_time and entry_time > data["last_time"]:
                data["last_time"] = entry_time

            if dt:
                if data["first_dt"] is None or dt < data["first_dt"]:
                    data["first_dt"] = dt
                if data["last_dt"] is None or dt > data["last_dt"]:
                    data["last_dt"] = dt
                data["activity"][dt.replace(minute=0, second=0, microsecond=0)] += 1

            client_info = entry.get("client_info") or {}
            if isinstance(client_info, dict):
                name = (client_info.get("name") or "").strip()
                if name:
                    data["name"] = name

            if domain:
                data["top_queries"][domain] += 1
                if blocked:
                    data["top_blocked"][domain] += 1

        sorted_clients = sorted(
            agg.items(),
            key=lambda item: item[1]["queries"],
            reverse=True,
        )

        now = datetime.now().astimezone().replace(minute=0, second=0, microsecond=0)
        activity_slots = [now - timedelta(hours=23 - i) for i in range(24)]

        clients = []
        for index, (ip, data) in enumerate(sorted_clients):
            queries = int(data["queries"])
            blocked = int(data["bloqueios"])
            pct = round((blocked / queries) * 100, 1) if queries else 0.0

            first_dt = data["first_dt"]
            last_dt = data["last_dt"]
            req_min = None
            if first_dt and last_dt:
                span_min = max(1.0, (last_dt - first_dt).total_seconds() / 60.0)
                req_min = round(queries / span_min, 1)

            # Um cliente com atividade recente é online; fora dessa janela
            # apenas indica inatividade no Query Log.
            status = "offline"
            if last_dt:
                age_seconds = (
                    datetime.now().astimezone() - last_dt
                ).total_seconds()
                status = "online" if age_seconds <= 300 else "offline"

            activity = [
                int(data["activity"].get(slot, 0))
                for slot in activity_slots
            ]

            clients.append(
                {
                    "id": index + 1,
                    "emoji": EMOJIS[index % len(EMOJIS)],
                    "name": data["name"] or ip,
                    "ip": ip,
                    "mac": "—",
                    "status": status,
                    "queries": queries,
                    "bloqueios": blocked,
                    "pct": pct,
                    "lastSeen": _human_last_seen(data["last_time"]),
                    "lastSeenIso": data["last_time"],
                    "reqMin": req_min,
                    "topConsultados": _top_counter(data["top_queries"], 5),
                    "topBloqueados": _top_counter(data["top_blocked"], 5),
                    "activity": activity,
                    "sampled": len(raw_ql or []) >= MAX_QUERYLOG,
                }
            )

        return clients


def testar_conexao_adguard(
    url: str,
    user: str,
    password: str,
    https: bool = False,
) -> dict:
    try:
        client = AdGuardClient(
            url=url,
            user=user,
            password=password,
            https=https,
        )
        status = client.get_status()
        filtering = client.get_filtering_status()
        health = client._build_health(status, filtering)

        msg = (
            f"AdGuard {health.get('version', '—')} · "
            f"{'rodando' if health.get('running') else 'parado'} · "
            f"proteção {'ativa' if health.get('protection_enabled') else 'inativa'}"
        )
        return {
            "ok": True,
            "msg": msg,
            "status": "ok",
            "health": health,
        }
    except AdGuardError as exc:
        return {"ok": False, "msg": str(exc), "status": "erro"}
    except Exception as exc:
        logger.exception("Erro inesperado ao testar AdGuard")
        return {
            "ok": False,
            "msg": f"Erro inesperado: {exc}",
            "status": "erro",
        }
