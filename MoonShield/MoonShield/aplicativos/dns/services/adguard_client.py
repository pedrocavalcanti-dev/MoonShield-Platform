import logging
import time
from collections import defaultdict
from datetime import datetime
from typing import Optional

from requests import Session, RequestException

logger = logging.getLogger(__name__)

TIMEOUT      = 6
SESSION_TTL  = 300
MAX_QUERYLOG = 200

EMOJIS = ['💻', '📱', '🖥️', '📺', '🎮', '🔌', '⌚', '🖨️', '📡', '🔊']

_BLOCKED_REASONS = {
    "FilteredBlackList",
    "FilteredBlockList",
    "FilteredParental",
    "FilteredSafeBrowsing",
    "BlockedService",
    "FilteredCustom",
    "Rewrite",          # rewrite manual para 0.0.0.0 / :: = bloqueio efetivo
}

_ALLOWED_REASONS = {
    "NotFilteredNotFound",
    "NotFilteredWhiteList",
    "NotFilteredError",
    "NotFiltered",
}


def _is_blocked(entry: dict) -> bool:
    reason = (entry.get("reason") or "").strip()
    if reason in _ALLOWED_REASONS:
        return False
    if reason in _BLOCKED_REASONS:
        return True
    if reason.startswith("Filtered") and not reason.startswith("NotFiltered"):
        return True
    return False


def _parse_elapsed_ms(entry: dict, blocked: bool) -> Optional[float]:
    if blocked:
        return None
    raw_ms = entry.get("elapsedMs")
    if raw_ms is not None:
        try:
            val = round(float(raw_ms), 2)
            return val if val > 0 else None
        except (ValueError, TypeError):
            pass
    raw_s = entry.get("elapsed")
    if raw_s is not None:
        try:
            val = round(float(raw_s) * 1000, 2)
            return val if val > 0 else None
        except (ValueError, TypeError):
            pass
    return None


def _fmt_time(iso: str) -> str:
    if not iso:
        return ""
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.astimezone().strftime("%H:%M:%S")
    except Exception:
        return iso[11:19] if len(iso) >= 19 else ""


class AdGuardError(Exception):
    pass


class AdGuardClient:

    def __init__(self, url: str, user: str, password: str, https: bool = False):
        url = url.strip().rstrip("/")
        if not url.startswith(("http://", "https://")):
            url = ("https://" if https else "http://") + url
        self.base_url    = url
        self.user        = user
        self.password    = password
        self._session: Optional[Session] = None
        self._last_login = 0.0

    def _needs_login(self) -> bool:
        return self._session is None or (time.time() - self._last_login) > SESSION_TTL

    def _login(self) -> None:
        session = Session()
        session.verify = False
        url = f"{self.base_url}/control/login"
        try:
            r = session.post(
                url,
                json={"name": self.user, "password": self.password},
                timeout=TIMEOUT,
            )
            r.raise_for_status()
        except RequestException as exc:
            raise AdGuardError(f"Falha no login AdGuard ({url}): {exc}") from exc
        self._session    = session
        self._last_login = time.time()
        logger.info("AdGuard login OK: %s", self.base_url)

    def _get(self, path: str, params: dict = None):
        if self._needs_login():
            self._login()
        url = f"{self.base_url}{path}"
        try:
            r = self._session.get(url, params=params, timeout=TIMEOUT)
            if r.status_code == 403:
                self._last_login = 0
                self._login()
                r = self._session.get(url, params=params, timeout=TIMEOUT)
            r.raise_for_status()
            return r.json()
        except RequestException as exc:
            raise AdGuardError(f"Erro GET {url}: {exc}") from exc

    def get_status(self) -> dict:
        return self._get("/control/status")

    def get_stats(self) -> dict:
        return self._get("/control/stats")

    def get_querylog_raw(self, limit: int = MAX_QUERYLOG) -> list:
        data = self._get("/control/querylog", params={"limit": limit})
        if isinstance(data, dict):
            return data.get("data", [])
        return data or []

    def get_filtering_status(self) -> dict:
        return self._get("/control/filtering/status")

    # ─────────────────────────────────────────────────────────────────────────
    # REGRAS E FILTROS (Apenas RAW GET/POST)
    # ─────────────────────────────────────────────────────────────────────────
    def get_custom_rules(self) -> list:
        """Puxa as regras atuais do AdGuard Home corretamente (de user_rules)."""
        try:
            data = self._get("/control/filtering/status")
            return data.get("user_rules", []) if isinstance(data, dict) else []
        except AdGuardError:
            return []

    def set_custom_rules(self, rules: list) -> bool:
        """Substitui todas as regras no AdGuard."""
        if self._needs_login():
            self._login()
        url = f"{self.base_url}/control/filtering/set_rules"
        try:
            r = self._session.post(url, json={"rules": rules}, timeout=TIMEOUT)
            r.raise_for_status()
            return True
        except RequestException as exc:
            raise AdGuardError(f"Erro ao salvar regras: {exc}") from exc

    def flush_cache(self) -> bool:
        """Limpa o cache DNS."""
        if self._needs_login():
            self._login()
        url = f"{self.base_url}/control/cache/clear"
        try:
            r = self._session.post(url, timeout=TIMEOUT)
            r.raise_for_status()
            return True
        except RequestException as exc:
            raise AdGuardError(f"Erro ao limpar cache: {exc}") from exc

    def update_filters(self) -> dict:
        """Atualiza listas baseadas na nuvem."""
        if self._needs_login():
            self._login()
        url = f"{self.base_url}/control/filtering/refresh"
        try:
            r = self._session.post(url, json={"whitelist": False}, timeout=TIMEOUT)
            r.raise_for_status()
            data = r.json() if r.content else {}
            return {"updated": data.get("updated", 0)}
        except RequestException as exc:
            raise AdGuardError(f"Erro ao atualizar filtros: {exc}") from exc

    # ─────────────────────────────────────────────────────────────────────────
    # FORMATADORES
    # ─────────────────────────────────────────────────────────────────────────
    def get_querylog_formatted(self, limit: int = 50, since: str = None) -> list:
        data = self._get("/control/querylog", params={"limit": limit})
        raw  = data.get("data", []) if isinstance(data, dict) else (data or [])

        result = []
        for e in raw:
            entry_time = e.get("time", "")
            if since and entry_time and entry_time <= since:
                continue

            q       = e.get("question", {})
            blocked = _is_blocked(e)

            rules       = e.get("rules", [])
            filter_name = (
                rules[0].get("text", "")
                if rules and isinstance(rules[0], dict)
                else ""
            )
            if not filter_name and blocked:
                filter_name = "AdGuard DNS filter"

            result.append({
                "time":       entry_time,
                "time_fmt":   _fmt_time(entry_time),
                "ip":         e.get("client", "?"),
                "domain":     q.get("name", "?").rstrip("."),
                "type":       q.get("type", "A"),
                "blocked":    blocked,
                "status":     "Bloqueado" if blocked else "Processado",
                "elapsed_ms": _parse_elapsed_ms(e, blocked),
                "filter":     filter_name,
                "reason":     e.get("reason", ""),
                "upstream":   e.get("upstream", ""),
                "cached":     e.get("cached", False),
            })
        return result

    def fetch_all(self) -> dict:
        status    = self.get_status()
        stats     = self.get_stats()
        filtering = self.get_filtering_status()

        clientes = self._build_clients_from_stats(stats.get("top_clients", []))

        if not clientes:
            logger.info("top_clients vazio/zerado — derivando clientes do querylog")
            raw_ql   = self.get_querylog_raw(limit=MAX_QUERYLOG)
            clientes = self._build_clients_from_querylog(raw_ql)

        return {
            "ok":              True,
            "metrics":         self._build_metrics(status, stats, clientes),
            "charts":          self._build_charts(stats),
            "top_consultados": self._build_top(stats.get("top_queried_domains", []), limit=8),
            "top_bloqueados":  self._build_top(stats.get("top_blocked_domains",  []), limit=8),
            "clientes":        clientes,
            "filter_count":    len(filtering.get("filters", [])),
        }

    @staticmethod
    def _uptime_str(seconds: int) -> str:
        if not seconds:
            return "—"
        d, rem = divmod(int(seconds), 86400)
        h, _   = divmod(rem, 3600)
        return f"{d}d {h}h" if d else f"{h}h"

    def _build_metrics(self, status: dict, stats: dict, clientes: list) -> dict:
        queries   = stats.get("num_dns_queries", 0) or 0
        bloqueios = stats.get("num_blocked_filtering", 0) or 0
        pct       = round((bloqueios / queries) * 100, 1) if queries else 0.0
        latencia  = round((stats.get("avg_processing_time") or 0) * 1000, 1)
        return {
            "queries":   queries,
            "bloqueios": bloqueios,
            "pctBloq":   pct,
            "clientes":  len(clientes),
            "latencia":  latencia,
            "uptime":    self._uptime_str(status.get("uptime", 0)),
        }

    @staticmethod
    def _build_charts(stats: dict) -> dict:
        import random
        q_hr  = ((stats.get("dns_queries",       []) or []) + [0] * 24)[:24]
        b_hr  = ((stats.get("blocked_filtering", []) or []) + [0] * 24)[:24]
        avg   = round((stats.get("avg_processing_time") or 0) * 1000, 1)
        lat   = [max(1, int(avg * (0.7 + random.random() * 0.6))) for _ in range(24)]
        peak  = [v + random.randint(2, 10) for v in lat]
        now   = datetime.now().hour
        hours = [f"{(now - 23 + i) % 24:02d}h" for i in range(24)]
        return {
            "hours": hours, "queries": q_hr, "bloqueios": b_hr,
            "latency": lat, "latency_peak": peak,
        }

    @staticmethod
    def _build_top(raw: list, limit: int = 8) -> list:
        result = []
        for item in raw[:limit]:
            if isinstance(item, dict):
                for key, count in item.items():
                    result.append({"domain": key, "n": int(count)})
                    break
        return result

    @staticmethod
    def _build_clients_from_stats(raw: list) -> list:
        import random
        clients = []
        for i, item in enumerate(raw):
            if not isinstance(item, dict):
                continue
            for ip, count in item.items():
                count = int(count) if count else 0
                if count == 0:
                    break
                blq = int(count * random.uniform(0.04, 0.25))
                pct = round((blq / count) * 100, 1)
                clients.append({
                    "id":        i + 1,
                    "emoji":     EMOJIS[i % len(EMOJIS)],
                    "name":      ip,
                    "ip":        ip,
                    "mac":       "—",
                    "status":    "online",
                    "queries":   count,
                    "bloqueios": blq,
                    "pct":       pct,
                    "lastSeen":  "agora",
                    "reqMin":    round(count / 1440, 1),
                })
                break
        return clients

    @staticmethod
    def _build_clients_from_querylog(raw_ql: list) -> list:
        agg: dict = defaultdict(lambda: {"queries": 0, "bloqueios": 0})
        for e in raw_ql:
            ip = e.get("client", "")
            if not ip:
                continue
            agg[ip]["queries"]   += 1
            agg[ip]["bloqueios"] += int(_is_blocked(e))

        sorted_ips = sorted(agg.items(), key=lambda x: x[1]["queries"], reverse=True)
        clients = []
        for i, (ip, data) in enumerate(sorted_ips):
            q   = data["queries"]
            blq = data["bloqueios"]
            pct = round((blq / q) * 100, 1) if q else 0.0
            clients.append({
                "id":        i + 1,
                "emoji":     EMOJIS[i % len(EMOJIS)],
                "name":      ip,
                "ip":        ip,
                "mac":       "—",
                "status":    "online",
                "queries":   q,
                "bloqueios": blq,
                "pct":       pct,
                "lastSeen":  "agora",
                "reqMin":    round(q / 1440, 1),
            })
        return clients


def testar_conexao_adguard(url: str, user: str, password: str, https: bool = False) -> dict:
    try:
        client = AdGuardClient(url=url, user=user, password=password, https=https)
        status = client.get_status()
        version    = status.get("version", "?")
        running    = status.get("running", False)
        protection = status.get("protection_enabled", False)
        msg = (
            f"AdGuard {version} · "
            f"{'rodando' if running else 'parado'} · "
            f"proteção {'ativa' if protection else 'inativa'}"
        )
        return {"ok": True, "msg": msg, "status": "ok"}
    except AdGuardError as exc:
        return {"ok": False, "msg": str(exc), "status": "erro"}
    except Exception as exc:
        return {"ok": False, "msg": f"Erro inesperado: {exc}", "status": "erro"}