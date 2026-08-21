/**
 * MOONSHIELD — FIREWALL / FEED v3
 *
 * Integração:
 *   GET  api/feed/
 *   GET  api/status/
 *   POST api/block/
 *   POST api/allowlist/
 *
 * O feed não consulta serviços externos de geolocalização.
 * Tudo exibido vem do backend MoonShield.
 */

document.addEventListener("DOMContentLoaded", () => {
    "use strict";

    const root = document.getElementById("fwfApp");
    if (!root) return;

    const $ = (id) => document.getElementById(id);

    const URLS = {
        feed: root.dataset.urlFeed,
        status: root.dataset.urlStatus,
        block: root.dataset.urlBlock,
        allowlist: root.dataset.urlAllowlist,
        rules: root.dataset.urlRules,
        dashboard: root.dataset.urlDashboard,
    };

    const state = {
        events: [],
        ids: new Set(),
        paused: false,
        autoScroll: true,
        grouped: true,
        filterAction: "all",
        filterIface: "all",
        filterProto: "all",
        search: "",
        lastTimestamp: null,
        currentEvent: null,
        currentGroupHits: 1,
        pollTimer: null,
        pollRunning: false,
        rateWindow: [],
        status: {},
        mode: null,
    };

    let toastTimer = null;

    bindEvents();
    initialLoad();

    /* ======================================================================
       API
       ====================================================================== */

    async function api(url, options = {}) {
        if (!url) throw new Error("Endpoint não configurado.");

        const method = String(options.method || "GET").toUpperCase();
        const headers = new Headers(options.headers || {});
        headers.set("Accept", "application/json");

        if (!["GET", "HEAD"].includes(method)) {
            headers.set("Content-Type", "application/json");
            headers.set("X-CSRFToken", getCsrf());
        }

        let response;

        try {
            response = await fetch(url, {
                credentials: "same-origin",
                ...options,
                method,
                headers,
            });
        } catch (_) {
            throw new Error("Não foi possível conectar ao backend do MoonShield.");
        }

        let payload = {};
        try {
            payload = await response.json();
        } catch (_) {
            payload = {};
        }

        if (!response.ok) {
            const message =
                payload?.erro?.mensagem ||
                payload?.erro ||
                payload?.mensagem ||
                `HTTP ${response.status}`;

            const error = new Error(String(message));
            error.status = response.status;
            error.payload = payload;
            throw error;
        }

        return payload;
    }

    function getCsrf() {
        const match = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]+)/);
        return match ? decodeURIComponent(match[1]) : "";
    }

    /* ======================================================================
       LOAD / POLL
       ====================================================================== */

    async function initialLoad() {
        setLiveState("loading", "CONECTANDO");

        const results = await Promise.allSettled([
            loadStatus(),
            poll({ initial: true }),
        ]);

        if (results[0].status === "rejected") {
            console.warn("Firewall status:", results[0].reason);
            renderStatusError(results[0].reason);
        }

        if (results[1].status === "rejected") {
            console.warn("Firewall feed:", results[1].reason);
            setPollState("error", "Falha na atualização automática");
            setLiveState("error", "ERRO");
        }

        schedulePoll();
    }

    async function loadStatus() {
        const status = await api(URLS.status);
        state.status = status;
        renderStatus(status);
        return status;
    }

    async function poll({ initial = false } = {}) {
        if (state.pollRunning) return;

        state.pollRunning = true;

        try {
            const params = new URLSearchParams({
                limit: initial ? "200" : "100",
            });

            if (!initial && state.lastTimestamp) {
                params.set("since", state.lastTimestamp);
            }

            const data = await api(`${URLS.feed}?${params.toString()}`);

            state.mode = data.modo || data.mode || state.mode;
            renderMode(data);
            populateInterfaces(data.interfaces || []);

            const events = Array.isArray(data.eventos) ? data.eventos : [];
            const normalized = events.map(normalizeEvent).filter(Boolean);

            const added = addEvents(normalized);

            if (added > 0 && !state.paused) {
                renderAll(added);
            } else if (initial) {
                renderAll();
            }

            if (!state.paused) {
                setLiveState("ok", "LIVE");
                setPollState("ok", "Atualização automática ativa");
            }

            updateLastUpdate();
        } catch (error) {
            setPollState("error", "Falha ao consultar novos eventos");
            if (!state.paused) setLiveState("error", "ERRO");
            throw error;
        } finally {
            state.pollRunning = false;
        }
    }

    function schedulePoll() {
        window.clearInterval(state.pollTimer);

        state.pollTimer = window.setInterval(() => {
            if (!state.paused) {
                poll().catch(() => {});
            }
        }, 2000);
    }

    async function refreshNow() {
        const button = $("fwfRefreshBtn");

        if (button) {
            button.disabled = true;
            button.classList.add("is-loading");
        }

        try {
            await Promise.all([
                loadStatus(),
                poll(),
            ]);

            toast("Feed atualizado.");
        } catch (error) {
            toast(error.message, "err");
        } finally {
            if (button) {
                button.disabled = false;
                button.classList.remove("is-loading");
            }
        }
    }

    /* ======================================================================
       STATUS
       ====================================================================== */

    function renderStatus(status) {
        const agentOk = Boolean(status.agent_disponivel || status.agent_ativo);
        const operational = Boolean(status.operacional);

        setStatusValue(
            "fwfAgentStatus",
            agentOk ? "ONLINE" : "OFFLINE",
            agentOk ? "ok" : "error"
        );

        setStatusValue(
            "fwfFirewallStatus",
            operational ? "OPERACIONAL" : agentOk ? "ATENÇÃO" : "INDISPONÍVEL",
            operational ? "ok" : agentOk ? "warn" : "error"
        );

        const wan = status.interface_wan || "—";
        const mgmt = status.interface_mgmt || "—";
        const lan = status.interface_lan || "—";

        setText("fwfTopologyStatus", `WAN ${wan} · MGMT ${mgmt} · LAN ${lan}`);
    }

    function renderStatusError(error) {
        setStatusValue("fwfAgentStatus", "—", "error");
        setStatusValue("fwfFirewallStatus", "—", "error");
        setText("fwfTopologyStatus", "Não foi possível consultar a topologia");
        console.warn(error);
    }

    function renderMode(data) {
        const badge = $("fwfModeBadge");
        if (!badge) return;

        const demo =
            data.modo === "simulacao" ||
            data.mode === "demo";

        badge.hidden = false;
        badge.classList.toggle("is-demo", demo);
        badge.textContent = demo ? "SIMULAÇÃO" : "REAL";

        setStatusValue(
            "fwfSourceStatus",
            demo ? "SIMULAÇÃO" : "LOCAL",
            demo ? "warn" : "ok"
        );
    }

    function setStatusValue(id, text, stateName) {
        const el = $(id);
        if (!el) return;

        el.textContent = text;
        el.classList.remove("is-ok", "is-warn", "is-error");
        el.classList.add(`is-${stateName}`);
    }

    function setLiveState(type, label) {
        const badge = $("fwfLiveBadge");
        if (!badge) return;

        badge.className = `fwf-live fwf-live--${type}`;
        setText("fwfLiveLabel", label);
    }

    function setPollState(type, text) {
        const dot = $("fwfPollDot");
        if (dot) {
            dot.classList.remove("is-paused", "is-error");

            if (type === "paused") dot.classList.add("is-paused");
            if (type === "error") dot.classList.add("is-error");
        }

        setText("fwfPollText", text);
    }

    function updateLastUpdate() {
        const now = new Date();

        setText(
            "fwfLastUpdate",
            `Atualizado ${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}:${String(now.getSeconds()).padStart(2, "0")}`
        );
    }

    /* ======================================================================
       NORMALIZAÇÃO
       ====================================================================== */

    function normalizeEvent(raw) {
        if (!raw || typeof raw !== "object") return null;

        const timestamp =
            raw.timestamp ||
            raw.ts ||
            raw.datetime ||
            null;

        const action = String(
            raw.action ||
            raw.acao ||
            "LOG"
        ).toUpperCase();

        return {
            id: raw.id ?? null,
            timestamp,
            time: raw.time || formatTime(timestamp),
            action,
            iface: raw.iface || "—",
            iface_raw: raw.iface_raw || "",
            iface_saida: raw.iface_saida || "",
            src_ip: raw.src_ip || "",
            src_port: normalizePort(raw.src_port),
            dst_ip: raw.dst_ip || "",
            dst_port: normalizePort(raw.dst_port),
            proto: String(raw.proto || "").toUpperCase(),
            rule_id: raw.rule_id ?? 0,
            rule_desc: raw.rule_desc || "",
            bytes: Number(raw.bytes || raw.tamanho || 0) || 0,
            ttl: raw.ttl ?? null,
            flags_tcp: raw.flags_tcp || raw.flags || "",
            prefixo: raw.prefixo || "",
            reason: raw.reason || raw.motivo || raw.rule_desc || "",
            source: raw.source || "local",
        };
    }

    function normalizePort(value) {
        if (value === null || value === undefined || value === "" || value === "—") {
            return null;
        }

        const n = Number(value);
        return Number.isFinite(n) ? n : value;
    }

    function formatTime(timestamp) {
        if (!timestamp) return "—";

        const date = new Date(timestamp);
        if (Number.isNaN(date.getTime())) return "—";

        return date.toLocaleTimeString("pt-BR", {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
        });
    }

    /* ======================================================================
       STORE / DEDUPE / KPIs
       ====================================================================== */

    function eventKey(event) {
        if (event.id !== null && event.id !== undefined) {
            return `id:${event.id}`;
        }

        return [
            event.timestamp,
            event.action,
            event.src_ip,
            event.src_port,
            event.dst_ip,
            event.dst_port,
            event.proto,
            event.iface_raw || event.iface,
        ].join("|");
    }

    function addEvents(events) {
        if (!events.length) return 0;

        let added = 0;
        let newestTimestamp = state.lastTimestamp;

        for (const event of events) {
            const key = eventKey(event);

            if (state.ids.has(key)) {
                continue;
            }

            state.ids.add(key);
            state.events.unshift(event);
            added += 1;

            state.rateWindow.push(Date.now());

            if (
                event.timestamp &&
                (!newestTimestamp || compareIso(event.timestamp, newestTimestamp) > 0)
            ) {
                newestTimestamp = event.timestamp;
            }
        }

        if (newestTimestamp) {
            state.lastTimestamp = newestTimestamp;
        }

        if (state.events.length > 3000) {
            state.events = state.events.slice(0, 3000);

            state.ids = new Set(
                state.events.map(eventKey)
            );
        }

        pruneRateWindow();
        return added;
    }

    function compareIso(a, b) {
        const da = new Date(a).getTime();
        const db = new Date(b).getTime();

        if (Number.isNaN(da) || Number.isNaN(db)) {
            return String(a).localeCompare(String(b));
        }

        return da - db;
    }

    function pruneRateWindow() {
        const limit = Date.now() - 60000;

        while (
            state.rateWindow.length &&
            state.rateWindow[0] < limit
        ) {
            state.rateWindow.shift();
        }
    }

    function computeStats(events = state.events) {
        const stats = {
            drops: 0,
            denies: 0,
            allows: 0,
            logs: 0,
            ports: new Map(),
            blockedSources: new Map(),
        };

        for (const event of events) {
            if (event.action === "DROP") stats.drops += 1;
            if (event.action === "DENY") stats.denies += 1;
            if (event.action === "ALLOW") stats.allows += 1;
            if (event.action === "LOG") stats.logs += 1;

            if (event.dst_port !== null && event.dst_port !== undefined) {
                const port = String(event.dst_port);
                stats.ports.set(
                    port,
                    (stats.ports.get(port) || 0) + 1
                );
            }

            if (
                ["DROP", "DENY"].includes(event.action) &&
                event.src_ip
            ) {
                stats.blockedSources.set(
                    event.src_ip,
                    (stats.blockedSources.get(event.src_ip) || 0) + 1
                );
            }
        }

        return stats;
    }

    function renderKpis(visibleEvents) {
        const stats = computeStats();

        setText("kpiDrops", stats.drops.toLocaleString("pt-BR"));
        setText("kpiDenies", stats.denies.toLocaleString("pt-BR"));
        setText("kpiAllows", stats.allows.toLocaleString("pt-BR"));
        setText("kpiTotal", state.events.length.toLocaleString("pt-BR"));
        setText("kpiVisible", `${visibleEvents.length.toLocaleString("pt-BR")} visíveis`);

        const topPort = [...stats.ports.entries()]
            .sort((a, b) => b[1] - a[1])[0];

        setText(
            "kpiTopPort",
            topPort ? `:${topPort[0]}` : "—"
        );

        setText(
            "kpiTopPortHits",
            topPort ? `${topPort[1]} evento(s)` : "—"
        );

        pruneRateWindow();
        setText("kpiRate", `${state.rateWindow.length}/m`);

        renderTopSources(stats.blockedSources);
    }

    function renderTopSources(sourceMap) {
        const container = $("kpiTopSrcs");
        if (!container) return;

        const items = [...sourceMap.entries()]
            .sort((a, b) => b[1] - a[1])
            .slice(0, 3);

        if (!items.length) {
            container.innerHTML =
                '<span class="fwf-top-src-empty">Nenhum bloqueio carregado.</span>';
            return;
        }

        const max = items[0][1];

        container.innerHTML = items.map(([ip, hits], index) => {
            const pct = Math.max(
                4,
                Math.round((hits / max) * 100)
            );

            return `
                <div class="fwf-top-src-item">
                    <span class="fwf-top-src-rank">${index + 1}</span>
                    <span class="fwf-top-src-ip" title="${escapeAttr(ip)}">${escapeHtml(ip)}</span>
                    <span class="fwf-top-src-bar-wrap">
                        <span class="fwf-top-src-bar" style="width:${pct}%"></span>
                    </span>
                    <span class="fwf-top-src-hits">${hits}x</span>
                </div>
            `;
        }).join("");
    }

    /* ======================================================================
       FILTER / GROUP
       ====================================================================== */

    function filteredEvents() {
        let events = [...state.events];

        if (state.grouped) {
            const grouped = new Map();

            for (const event of events) {
                const key = [
                    event.src_ip,
                    event.action,
                    event.dst_ip,
                    event.dst_port,
                    event.proto,
                    event.iface,
                ].join("|");

                if (!grouped.has(key)) {
                    grouped.set(key, {
                        event,
                        hits: 1,
                    });
                } else {
                    grouped.get(key).hits += 1;
                }
            }

            events = [...grouped.values()].map((item) => ({
                ...item.event,
                _hits: item.hits,
            }));
        } else {
            events = events.map((event) => ({
                ...event,
                _hits: 1,
            }));
        }

        return events.filter((event) => {
            if (
                state.filterAction !== "all" &&
                event.action !== state.filterAction
            ) {
                return false;
            }

            if (
                state.filterIface !== "all" &&
                event.iface !== state.filterIface &&
                event.iface_raw !== state.filterIface
            ) {
                return false;
            }

            if (
                state.filterProto !== "all" &&
                event.proto !== state.filterProto
            ) {
                return false;
            }

            if (state.search) {
                const q = state.search.toLowerCase();

                const haystack = [
                    event.src_ip,
                    event.src_port,
                    event.dst_ip,
                    event.dst_port,
                    event.proto,
                    event.iface,
                    event.iface_raw,
                    event.rule_desc,
                    event.reason,
                    event.prefixo,
                ]
                    .map((value) => String(value ?? "").toLowerCase())
                    .join(" ");

                if (!haystack.includes(q)) {
                    return false;
                }
            }

            return true;
        });
    }

    /* ======================================================================
       RENDER TABLE
       ====================================================================== */

    function renderAll(newCount = 0) {
        const events = filteredEvents();

        renderKpis(events);
        renderRows(events, newCount);

        setText(
            "fwfFooterCount",
            `${events.length.toLocaleString("pt-BR")} evento${events.length === 1 ? "" : "s"} visível${events.length === 1 ? "" : "is"}`
        );
    }

    function renderRows(events, newCount = 0) {
        const body = $("fwfTableBody");
        if (!body) return;

        if (!events.length) {
            body.innerHTML = `
                <div class="fwf-empty">
                    <i class="bi bi-broadcast"></i>
                    <strong>Nenhum evento para os filtros atuais</strong>
                    <span>Novos registros serão exibidos automaticamente quando o backend retornar eventos.</span>
                </div>
            `;
            return;
        }

        body.innerHTML = "";

        events.slice(0, 800).forEach((event, index) => {
            body.appendChild(
                createRow(
                    event,
                    index < newCount
                )
            );
        });

        if (state.autoScroll) {
            body.scrollTop = 0;
        }
    }

    function createRow(event, isNew) {
        const row = document.createElement("div");

        row.className = [
            "fwf-row",
            `fwf-row--${String(event.action || "log").toLowerCase()}`,
            isNew ? "fwf-row--new" : "",
        ].filter(Boolean).join(" ");

        const hits = Number(event._hits || 1);

        row.innerHTML = `
            <div class="fwf-cell fwf-cell--time">${escapeHtml(event.time || "—")}</div>

            <div class="fwf-cell">
                ${actionBadge(event.action)}
            </div>

            <div class="fwf-cell">
                <span class="fwf-iface-badge" title="${escapeAttr(event.iface_raw || event.iface || "")}">
                    ${escapeHtml(event.iface || "—")}
                </span>
            </div>

            <div class="fwf-cell fwf-cell--ip" title="${escapeAttr(formatEndpoint(event.src_ip, event.src_port))}">
                ${escapeHtml(formatEndpoint(event.src_ip, event.src_port))}
            </div>

            <div class="fwf-cell fwf-cell--ip" title="${escapeAttr(formatEndpoint(event.dst_ip, event.dst_port))}">
                <span>${escapeHtml(event.dst_ip || "—")}</span>
                ${event.dst_port !== null ? `<span class="fwf-dst-port">:${escapeHtml(event.dst_port)}</span>` : ""}
            </div>

            <div class="fwf-cell">${escapeHtml(event.proto || "—")}</div>

            <div class="fwf-cell fwf-cell--rule" title="${escapeAttr(event.reason || event.rule_desc || "")}">
                ${escapeHtml(truncate(event.reason || event.rule_desc || "—", 38))}
            </div>

            <div class="fwf-cell">
                <span class="fwf-hits-badge ${hits === 1 ? "fwf-hits-badge--single" : ""}">
                    ${hits}x
                </span>
            </div>

            <div class="fwf-cell">
                <div class="fwf-row-actions">
                    <button class="fwf-row-btn fwf-row-btn--danger" type="button" data-action="block" title="Bloquear origem">
                        <i class="bi bi-ban"></i>
                    </button>

                    <button class="fwf-row-btn" type="button" data-action="view" title="Detalhes">
                        <i class="bi bi-eye"></i>
                    </button>

                    <button class="fwf-row-btn" type="button" data-action="rule" title="Criar regra">
                        <i class="bi bi-plus-circle"></i>
                    </button>
                </div>
            </div>
        `;

        row.addEventListener("click", (eventClick) => {
            if (eventClick.target.closest(".fwf-row-btn")) {
                return;
            }

            openDrawer(event, hits);
        });

        row.querySelector('[data-action="block"]')
            ?.addEventListener("click", (clickEvent) => {
                clickEvent.stopPropagation();
                blockEventSource(event);
            });

        row.querySelector('[data-action="view"]')
            ?.addEventListener("click", (clickEvent) => {
                clickEvent.stopPropagation();
                openDrawer(event, hits);
            });

        row.querySelector('[data-action="rule"]')
            ?.addEventListener("click", (clickEvent) => {
                clickEvent.stopPropagation();
                createRuleFromEvent(event);
            });

        return row;
    }

    function actionBadge(action) {
        const value = String(action || "LOG").toUpperCase();
        const css = ["DROP", "DENY", "ALLOW", "LOG"].includes(value)
            ? value.toLowerCase()
            : "log";

        return `
            <span class="fwf-action-badge fwf-action-badge--${css}">
                ${escapeHtml(value)}
            </span>
        `;
    }

    function formatEndpoint(ip, port) {
        const host = ip || "—";

        if (
            port === null ||
            port === undefined ||
            port === ""
        ) {
            return host;
        }

        return `${host}:${port}`;
    }

    /* ======================================================================
       DRAWER
       ====================================================================== */

    function openDrawer(event, hits = 1) {
        state.currentEvent = event;
        state.currentGroupHits = hits;

        const badge = $("fwfDrawerBadge");
        const action = String(event.action || "LOG").toUpperCase();

        if (badge) {
            badge.textContent = action;
            badge.className =
                `fwf-action-badge fwf-action-badge--${["DROP", "DENY", "ALLOW", "LOG"].includes(action) ? action.toLowerCase() : "log"}`;
        }

        setText("fwfDetailSrc", event.src_ip || "—");
        setText(
            "fwfDetailSrcMeta",
            event.src_port !== null ? `porta ${event.src_port}` : "sem porta"
        );

        setText("fwfDetailDst", event.dst_ip || "—");
        setText(
            "fwfDetailDstMeta",
            event.dst_port !== null ? `porta ${event.dst_port}` : "sem porta"
        );

        setText(
            "fwfDetailProtoArrow",
            `${event.proto || "?"}${event.dst_port !== null ? ` · :${event.dst_port}` : ""}`
        );

        setText(
            "fwfDetailTime",
            event.timestamp || event.time || "—"
        );

        setText(
            "fwfDetailIface",
            event.iface_raw || event.iface || "—"
        );

        setText(
            "fwfDetailIfaceOut",
            event.iface_saida || "—"
        );

        setText("fwfDetailProto", event.proto || "—");
        setText("fwfDetailBytes", formatBytes(event.bytes));
        setText("fwfDetailTtl", event.ttl ?? "—");
        setText("fwfDetailFlags", event.flags_tcp || "—");
        setText(
            "fwfDetailRule",
            event.prefixo || event.rule_desc || "—"
        );
        setText(
            "fwfDetailReason",
            event.reason || event.rule_desc || "—"
        );

        const raw = buildNormalizedRaw(event);
        setText(
            "fwfDetailRaw",
            JSON.stringify(raw, null, 2)
        );

        const hitsBanner = $("fwfHitsBanner");

        if (hitsBanner) {
            hitsBanner.hidden = hits <= 1;
            setText("fwfHitsCount", hits);
        }

        $("fwfDrawer")?.classList.add("open");
        $("fwfDrawerOverlay")?.classList.add("open");
        $("fwfDrawer")?.setAttribute("aria-hidden", "false");
        document.body.style.overflow = "hidden";
    }

    function closeDrawer() {
        $("fwfDrawer")?.classList.remove("open");
        $("fwfDrawerOverlay")?.classList.remove("open");
        $("fwfDrawer")?.setAttribute("aria-hidden", "true");

        state.currentEvent = null;
        state.currentGroupHits = 1;

        document.body.style.overflow = "";
    }

    function buildNormalizedRaw(event) {
        return {
            id: event.id,
            timestamp: event.timestamp,
            action: event.action,
            iface: event.iface,
            iface_raw: event.iface_raw,
            iface_saida: event.iface_saida,
            src_ip: event.src_ip,
            src_port: event.src_port,
            dst_ip: event.dst_ip,
            dst_port: event.dst_port,
            proto: event.proto,
            bytes: event.bytes,
            ttl: event.ttl,
            flags_tcp: event.flags_tcp,
            prefixo: event.prefixo,
            rule_desc: event.rule_desc,
            reason: event.reason,
            source: event.source,
        };
    }

    /* ======================================================================
       ACTIONS
       ====================================================================== */

    async function blockEventSource(event) {
        if (!event?.src_ip) {
            toast("Este evento não possui IP de origem.", "err");
            return;
        }

        try {
            const result = await api(URLS.block, {
                method: "POST",
                body: JSON.stringify({
                    ip: event.src_ip,
                    motivo: `Bloqueio via Feed${event.reason ? ` — ${event.reason}` : ""}`,
                    source: "SOC",
                    expires: "∞",
                }),
            });

            if (!result.ok) {
                throw new Error(result.erro || "Bloqueio não confirmado.");
            }

            toast(`${event.src_ip} bloqueado pelo MoonShield-Agent.`);
        } catch (error) {
            toast(error.message, "err");
        }
    }

    async function addCurrentToAllowlist() {
        const event = state.currentEvent;
        if (!event?.src_ip) return;

        try {
            const result = await api(URLS.allowlist, {
                method: "POST",
                body: JSON.stringify({
                    ip: event.src_ip,
                    reason: "Cadastro criado a partir do Feed do Firewall",
                }),
            });

            if (!result.ok) {
                throw new Error(result.erro || "Falha ao cadastrar allowlist.");
            }

            toast(
                `${event.src_ip} cadastrado na allowlist. O runtime ainda não é aplicado.`,
                "warn"
            );
        } catch (error) {
            toast(error.message, "err");
        }
    }

    function createRuleFromEvent(event = state.currentEvent) {
        if (!event) return;

        const params = new URLSearchParams({
            nova_regra: "1",
        });

        if (event.src_ip) params.set("src", event.src_ip);
        if (event.dst_ip) params.set("dst", event.dst_ip);
        if (event.dst_port !== null) params.set("port", String(event.dst_port));
        if (event.proto) params.set("proto", event.proto);

        const logicalIface = normalizeLogicalIface(event.iface);
        if (logicalIface) params.set("iface", logicalIface);

        window.location.href =
            `${URLS.rules}?${params.toString()}`;
    }

    function normalizeLogicalIface(value) {
        const upper = String(value || "").toUpperCase();

        if (["WAN", "MGMT", "LAN"].includes(upper)) {
            return upper;
        }

        return "";
    }

    async function copyCurrentIoc() {
        const event = state.currentEvent;
        if (!event) return;

        const text = [
            `src=${formatEndpoint(event.src_ip, event.src_port)}`,
            `dst=${formatEndpoint(event.dst_ip, event.dst_port)}`,
            `proto=${event.proto || "—"}`,
            `action=${event.action || "—"}`,
            `time=${event.timestamp || event.time || "—"}`,
        ].join(" | ");

        await copyText(
            text,
            "IOC copiado."
        );
    }

    async function copyCurrentJson() {
        const event = state.currentEvent;
        if (!event) return;

        await copyText(
            JSON.stringify(buildNormalizedRaw(event), null, 2),
            "JSON copiado."
        );
    }

    async function copyText(text, successMessage) {
        try {
            await navigator.clipboard.writeText(text);
            toast(successMessage);
        } catch (_) {
            toast("Não foi possível copiar para a área de transferência.", "err");
        }
    }

    /* ======================================================================
       UI FILTERS
       ====================================================================== */

    function populateInterfaces(items) {
        const select = $("fwfFilterIface");
        if (!select || !Array.isArray(items) || !items.length) return;

        const current = select.value;
        const names = new Set();

        for (const item of items) {
            const name =
                typeof item === "string"
                    ? item
                    : item.nome || item.name || item.interface || item.iface;

            if (name) names.add(String(name));
        }

        for (const event of state.events) {
            if (event.iface && event.iface !== "—") {
                names.add(event.iface);
            }

            if (event.iface_raw) {
                names.add(event.iface_raw);
            }
        }

        select.innerHTML =
            '<option value="all">Interface: Todas</option>';

        [...names]
            .sort()
            .forEach((name) => {
                const option = document.createElement("option");
                option.value = name;
                option.textContent = name;
                select.appendChild(option);
            });

        if (
            [...select.options]
                .some((option) => option.value === current)
        ) {
            select.value = current;
        }
    }

    function clearView() {
        state.events = [];
        state.ids.clear();
        state.lastTimestamp = null;
        state.rateWindow = [];
        state.currentEvent = null;

        renderAll();

        toast("Eventos removidos apenas desta tela.");
    }

    function togglePause() {
        state.paused = !state.paused;

        if (state.paused) {
            setLiveState("paused", "PAUSADO");
            setPollState("paused", "Atualização automática pausada");
            $("fwfPauseIcon").className = "bi bi-play-fill";
            setText("fwfPauseLabel", "Retomar");
        } else {
            setLiveState("loading", "RETOMANDO");
            setPollState("ok", "Atualização automática ativa");
            $("fwfPauseIcon").className = "bi bi-pause-fill";
            setText("fwfPauseLabel", "Pausar");

            poll()
                .then(() => setLiveState("ok", "LIVE"))
                .catch((error) => {
                    setLiveState("error", "ERRO");
                    toast(error.message, "err");
                });
        }
    }

    /* ======================================================================
       EXPORT
       ====================================================================== */

    function exportCsv() {
        const events = filteredEvents();

        if (!events.length) {
            toast("Não há eventos visíveis para exportar.", "warn");
            return;
        }

        const header = [
            "Timestamp",
            "Hora",
            "Ação",
            "Interface",
            "Interface Física",
            "Interface Saída",
            "Src IP",
            "Src Porta",
            "Dst IP",
            "Dst Porta",
            "Protocolo",
            "Bytes",
            "TTL",
            "Flags TCP",
            "Prefixo",
            "Regra",
            "Motivo",
            "Hits",
        ];

        const rows = events.map((event) => [
            event.timestamp,
            event.time,
            event.action,
            event.iface,
            event.iface_raw,
            event.iface_saida,
            event.src_ip,
            event.src_port,
            event.dst_ip,
            event.dst_port,
            event.proto,
            event.bytes,
            event.ttl,
            event.flags_tcp,
            event.prefixo,
            event.rule_desc,
            event.reason,
            event._hits || 1,
        ]);

        const csv = [
            header.map(csvCell).join(","),
            ...rows.map((row) => row.map(csvCell).join(",")),
        ].join("\r\n");

        const blob = new Blob(
            ["\ufeff", csv],
            { type: "text/csv;charset=utf-8;" }
        );

        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");

        link.href = url;
        link.download =
            `moonshield-firewall-feed-${new Date().toISOString().slice(0, 10)}.csv`;

        document.body.appendChild(link);
        link.click();
        link.remove();

        window.setTimeout(
            () => URL.revokeObjectURL(url),
            1000
        );

        toast("CSV exportado.");
    }

    /* ======================================================================
       EVENTS
       ====================================================================== */

    function bindEvents() {
        document
            .querySelectorAll("[data-action]")
            .forEach((button) => {
                if (!button.closest("#fwfActionChips")) return;

                button.addEventListener("click", () => {
                    document
                        .querySelectorAll("#fwfActionChips [data-action]")
                        .forEach((item) => item.classList.remove("fwf-chip--active"));

                    button.classList.add("fwf-chip--active");
                    state.filterAction = button.dataset.action || "all";
                    renderAll();
                });
            });

        $("fwfFilterIface")?.addEventListener("change", (event) => {
            state.filterIface = event.target.value;
            renderAll();
        });

        $("fwfFilterProto")?.addEventListener("change", (event) => {
            state.filterProto = event.target.value;
            renderAll();
        });

        $("fwfGroupToggle")?.addEventListener("change", (event) => {
            state.grouped = event.target.checked;
            renderAll();
        });

        $("fwfAutoScroll")?.addEventListener("change", (event) => {
            state.autoScroll = event.target.checked;
        });

        $("fwfSearch")?.addEventListener("input", (event) => {
            state.search = event.target.value.trim();
            renderAll();
        });

        $("fwfSearchClear")?.addEventListener("click", () => {
            $("fwfSearch").value = "";
            state.search = "";
            renderAll();
        });

        $("fwfPauseBtn")?.addEventListener("click", togglePause);
        $("fwfClearBtn")?.addEventListener("click", clearView);
        $("fwfExportBtn")?.addEventListener("click", exportCsv);
        $("fwfRefreshBtn")?.addEventListener("click", refreshNow);

        $("fwfDrawerClose")?.addEventListener("click", closeDrawer);
        $("fwfDrawerOverlay")?.addEventListener("click", closeDrawer);

        $("fwfDrawerBlock")?.addEventListener("click", async () => {
            const event = state.currentEvent;
            if (!event) return;

            await blockEventSource(event);
        });

        $("fwfDrawerAllow")?.addEventListener("click", addCurrentToAllowlist);
        $("fwfDrawerRule")?.addEventListener("click", () => createRuleFromEvent());
        $("fwfDrawerCopyIoc")?.addEventListener("click", copyCurrentIoc);
        $("fwfCopyJsonBtn")?.addEventListener("click", copyCurrentJson);

        document.addEventListener("keydown", (event) => {
            if (
                event.key === "Escape" &&
                $("fwfDrawer")?.classList.contains("open")
            ) {
                closeDrawer();
            }
        });
    }

    /* ======================================================================
       HELPERS
       ====================================================================== */

    function formatBytes(value) {
        const bytes = Number(value || 0);

        if (!Number.isFinite(bytes) || bytes <= 0) {
            return bytes === 0 ? "0 B" : "—";
        }

        if (bytes >= 1024 * 1024 * 1024) {
            return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
        }

        if (bytes >= 1024 * 1024) {
            return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
        }

        if (bytes >= 1024) {
            return `${(bytes / 1024).toFixed(1)} KB`;
        }

        return `${bytes} B`;
    }

    function csvCell(value) {
        return `"${String(value ?? "").replace(/"/g, '""')}"`;
    }

    function truncate(value, max) {
        const text = String(value || "");
        return text.length > max
            ? `${text.slice(0, max)}…`
            : text;
    }

    function setText(id, value) {
        const element = $(id);
        if (element) {
            element.textContent = String(value ?? "");
        }
    }

    function toast(message, type = "ok") {
        const element = $("fwfToast");
        if (!element) return;

        element.textContent = message;
        element.className =
            `fwf-toast fwf-toast--${type} show`;

        window.clearTimeout(toastTimer);

        toastTimer = window.setTimeout(
            () => element.classList.remove("show"),
            3000
        );
    }

    function escapeHtml(value) {
        return String(value ?? "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    function escapeAttr(value) {
        return escapeHtml(value);
    }
});
