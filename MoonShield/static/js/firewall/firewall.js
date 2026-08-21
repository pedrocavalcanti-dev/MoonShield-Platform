/**
 * MOONSHIELD — FIREWALL.JS v9
 * Dashboard integrado ao backend local do Firewall.
 *
 * Endpoints utilizados:
 *   GET  /firewall/api/data/
 *   GET  /firewall/api/status/
 *   POST /firewall/api/rules/apply/
 *   GET  /firewall/api/export-nft/
 */

document.addEventListener("DOMContentLoaded", () => {
    "use strict";

    const root = document.getElementById("fwDashboard");
    if (!root) return;

    const $ = (id) => document.getElementById(id);

    const URLS = {
        data: root.dataset.urlData,
        status: root.dataset.urlStatus,
        apply: root.dataset.urlApply,
        exportNft: root.dataset.urlExportNft,
        install: root.dataset.urlInstall,
        rules: root.dataset.urlRules,
        feed: root.dataset.urlFeed,
    };

    const state = {
        period: "24h",
        mode: "desconhecido",
        logs: [],
        sync: null,
        status: null,
        lastData: null,
        charts: {
            traffic: null,
            blocks: null,
        },
    };

    let toastTimer = null;

    initChartDefaults();
    bindEvents();
    refreshAll();

    /* ======================================================================
       API
       ====================================================================== */

    async function apiJson(url, options = {}) {
        if (!url) throw new Error("Endpoint não configurado.");

        const response = await fetch(url, {
            credentials: "same-origin",
            ...options,
        });

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

            const error = new Error(message);
            error.status = response.status;
            error.payload = payload;
            throw error;
        }

        return payload;
    }

    function csrfToken() {
        const match = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]+)/);
        return match ? decodeURIComponent(match[1]) : "";
    }

    /* ======================================================================
       LOAD
       ====================================================================== */

    async function refreshAll() {
        setRefreshing(true);

        let data = null;

        try {
            /*
             * Primeiro carregamos /api/data/.
             *
             * Isso é intencional: o endpoint informa o modo atual.
             * Em SIMULAÇÃO não devemos consultar /api/status/, porque o
             * MoonShield-Agent real pode nem existir nesse host.
             */
            data = await loadData(state.period);

            if (isSimulationData(data)) {
                renderSimulationState(data);
                updateTimestamp();
                return;
            }

            /*
             * Modo REAL:
             * /api/data/ já traz `firewall` como estado consolidado.
             * Renderizamos esse estado imediatamente e depois tentamos o
             * endpoint dedicado /api/status/ para obter a leitura mais recente.
             */
            if (isUsableFirewallStatus(data?.firewall)) {
                state.status = data.firewall;
                renderStatus(data.firewall);
            }

            try {
                await loadStatus();
            } catch (error) {
                console.error("Firewall status:", error);

                /*
                 * Nunca transformar um Firewall operacional em
                 * "não configurado" só porque /api/status/ falhou uma vez.
                 */
                if (isUsableFirewallStatus(data?.firewall)) {
                    state.status = data.firewall;
                    renderStatus(data.firewall);
                } else {
                    renderStatusError(error);
                }
            }

        } catch (error) {
            console.error("Firewall data:", error);

            /*
             * Se já temos um estado real operacional em memória, preserva a
             * tela e apenas informa a falha de atualização via toast.
             */
            if (state.mode === "real" && isUsableFirewallStatus(state.status)) {
                renderStatus(state.status);
            } else if (state.mode !== "simulacao") {
                renderStatusError(error);
            }

            showToast("Não foi possível atualizar os dados do Firewall.", "err");
        } finally {
            updateTimestamp();
            setRefreshing(false);
        }
    }

    async function loadData(period) {
        const data = await apiJson(`${URLS.data}?period=${encodeURIComponent(period)}`);

        state.lastData = data;
        state.logs = Array.isArray(data.logs) ? data.logs : [];
        state.sync = data.sync || null;
        state.mode = isSimulationData(data) ? "simulacao" : "real";

        root.dataset.runtimeMode = state.mode;

        renderKPIs(data.metrics || {});
        renderCharts(data.charts || {});
        renderTopIps(data.top_ips || fallbackTopIp(data.metrics));
        renderFeed(state.logs);
        renderDataSource(data);

        if (state.mode === "simulacao") {
            /*
             * Simulação é somente visual/demonstração.
             * Não mostramos:
             * - Agent offline;
             * - Firewall não configurado;
             * - regras pendentes reais do banco;
             * - botão Aplicar.
             */
            renderSync({});
            renderSimulationState(data);
        } else {
            renderSync(data.sync || {});

            if (isUsableFirewallStatus(data.firewall)) {
                state.status = data.firewall;
                renderStatus(data.firewall);
            }
        }

        return data;
    }

    async function loadStatus() {
        if (state.mode === "simulacao") {
            return null;
        }

        const status = await apiJson(URLS.status);
        state.status = status;

        renderStatus(status);
        return status;
    }

    function isSimulationData(data) {
        const modo = String(data?.modo || "").trim().toLowerCase();
        const mode = String(data?.mode || "").trim().toLowerCase();

        return modo === "simulacao" ||
            modo === "simulação" ||
            mode === "demo" ||
            mode === "simulation" ||
            mode === "simulacao";
    }

    function isUsableFirewallStatus(status) {
        if (!status || typeof status !== "object") return false;

        return status.ok === true ||
            Object.prototype.hasOwnProperty.call(status, "operacional") ||
            Object.prototype.hasOwnProperty.call(status, "instalado") ||
            Object.prototype.hasOwnProperty.call(status, "agent_disponivel");
    }

    function renderDataSource(data) {
        const dot = $("fwSourceDot");
        const text = $("fwSourceText");

        if (!dot || !text) return;

        dot.className = "fw-toolbar__source-dot";

        if (isSimulationData(data)) {
            dot.classList.add("is-warn");
            text.textContent = "Dados simulados";
            return;
        }

        dot.classList.add("is-ok");
        text.textContent = data.waiting
            ? "Aguardando eventos locais"
            : "Eventos locais";
    }

    function renderSimulationState(data = {}) {
        state.mode = "simulacao";
        root.dataset.runtimeMode = "simulacao";

        hideOperationalAlerts();

        setMainStatus("sim", "Simulação");
        setHealthPill("sim", "SIMULAÇÃO");

        setSimulationHealthValue("fwAgentStatus", "SIMULADO");
        setSimulationHealthValue("fwNftStatus", "SIMULADO");
        setSimulationHealthValue("fwTableStatus", "SIMULADO");
        setSimulationHealthValue("fwChainsStatus", "SIMULADO");

        setText("fwAgentDetail", "modo de demonstração");
        setText("fwNftDetail", "sem consulta ao host Linux");

        /*
         * Se a simulação trouxer topologia própria, podemos mostrá-la.
         * Caso contrário não reaproveitamos topologia real/antiga.
         */
        const fw = data?.firewall || {};
        setText("fwIfaceWan", fw.interface_wan || "—");
        setText("fwIfaceMgmt", fw.interface_mgmt || "—");
        setText("fwIfaceLan", fw.interface_lan || "—");
        setText("fwHomeNet", fw.home_net || "rede simulada");
    }

    function hideOperationalAlerts() {
        setElementVisible($("fwSetupCallout"), false);
        setElementVisible($("fwSyncBar"), false);
    }

    /* ======================================================================
       STATUS REAL
       ====================================================================== */

    function renderStatus(status) {
        if (state.mode === "simulacao") {
            renderSimulationState(state.lastData || {});
            return;
        }

        const agentOk = Boolean(status.agent_disponivel || status.agent_ativo);
        const nftOk = Boolean(status.nftables_instalado);
        const tableOk = Boolean(status.tabela_instalada || status.ativo);
        const chainsOk = Boolean(status.chains_ok);
        const installed = Boolean(
            status.instalado ||
            status.tabela_instalada ||
            status.ativo
        );
        const configured = Boolean(status.configurado);
        const operational = Boolean(status.operacional);

        setMainStatus(
            operational ? "ok" : agentOk ? "warn" : "error",
            operational
                ? "Operacional"
                : agentOk
                    ? (status.status_label || "Atenção")
                    : "Agent indisponível"
        );

        setHealthPill(
            operational ? "ok" : agentOk ? "warn" : "error",
            operational ? "OPERACIONAL" : agentOk ? "ATENÇÃO" : "OFFLINE"
        );

        setHealthValue("fwAgentStatus", agentOk, agentOk ? "ONLINE" : "OFFLINE");
        setHealthValue("fwNftStatus", nftOk, nftOk ? "OK" : "—", agentOk && !nftOk);
        setHealthValue("fwTableStatus", tableOk, tableOk ? "ATIVA" : "—", agentOk && !tableOk);
        setHealthValue("fwChainsStatus", chainsOk, chainsOk ? "OK" : "—", agentOk && !chainsOk);

        const socketPath =
            status.ipc?.socket ||
            status.ipc?.caminho ||
            "/run/moonshield/agent.sock";

        setText("fwAgentDetail", socketPath);
        setText(
            "fwNftDetail",
            status.nftables_versao
                ? `versão ${status.nftables_versao}`
                : "versão —"
        );

        setText("fwIfaceWan", status.interface_wan || "—");
        setText("fwIfaceMgmt", status.interface_mgmt || "—");
        setText("fwIfaceLan", status.interface_lan || "—");
        setText("fwHomeNet", status.home_net || "rede protegida");

        /*
         * Um status operacional nunca pode coexistir visualmente com o
         * callout "Firewall não configurado".
         */
        const fullyReady = Boolean(
            operational ||
            (
                status.ok === true &&
                installed &&
                configured &&
                tableOk &&
                chainsOk
            )
        );

        if (fullyReady) {
            setElementVisible($("fwSetupCallout"), false);
            return;
        }

        renderSetupCallout(status);
    }

    function renderSetupCallout(status) {
        const callout = $("fwSetupCallout");
        if (!callout) return;

        if (state.mode === "simulacao") {
            setElementVisible(callout, false);
            return;
        }

        const agentOk = Boolean(status.agent_disponivel || status.agent_ativo);
        const installed = Boolean(
            status.instalado ||
            status.tabela_instalada ||
            status.ativo
        );

        const configured = Boolean(status.configurado);
        const tableOk = Boolean(status.tabela_instalada || status.ativo);
        const chainsOk = Boolean(status.chains_ok);

        if (
            status.operacional ||
            (
                status.ok === true &&
                installed &&
                configured &&
                tableOk &&
                chainsOk
            )
        ) {
            setElementVisible(callout, false);
            return;
        }

        setElementVisible(callout, true);

        if (!agentOk) {
            setText("fwSetupTitle", "MoonShield-Agent indisponível");
            setText(
                "fwSetupText",
                "O Django não consegue acessar o socket local do Agent."
            );
            return;
        }

        if (!installed) {
            setText("fwSetupTitle", "Firewall ainda não instalado");
            setText(
                "fwSetupText",
                "Conclua a instalação do Firewall para ativar a proteção local."
            );
            return;
        }

        setText("fwSetupTitle", "Firewall requer validação");
        setText(
            "fwSetupText",
            status.status_label ||
            "A estrutura existe, mas ainda não está totalmente operacional."
        );
    }

    function renderStatusError(error) {
        if (state.mode === "simulacao") {
            renderSimulationState(state.lastData || {});
            return;
        }

        /*
         * Se o último estado conhecido é operacional, uma falha transitória
         * não deve pintar toda a interface como OFFLINE.
         */
        if (isUsableFirewallStatus(state.status) && state.status.operacional) {
            renderStatus(state.status);
            return;
        }

        setMainStatus("error", "Indisponível");
        setHealthPill("error", "OFFLINE");

        ["fwAgentStatus", "fwNftStatus", "fwTableStatus", "fwChainsStatus"].forEach((id) => {
            setText(id, "—");
            $(id)?.classList.remove("is-ok", "is-warn", "is-error", "is-sim");
            $(id)?.classList.add("is-error");
        });

        const callout = $("fwSetupCallout");
        if (callout) {
            setElementVisible(callout, true);
            setText("fwSetupTitle", "MoonShield-Agent indisponível");
            setText(
                "fwSetupText",
                error?.message || "Não foi possível consultar o Firewall local."
            );
        }
    }

    function setMainStatus(type, text) {
        const badge = $("fwStatusBadge");
        if (!badge) return;

        badge.className = `fw-status-badge fw-status-badge--${type}`;
        setText("fwStatusText", text);
    }

    function setHealthPill(type, text) {
        const pill = $("fwHealthStatus");
        if (!pill) return;

        pill.className = `fw-health-pill fw-health-pill--${type}`;
        pill.textContent = text;
    }

    function setHealthValue(id, ok, text, warning = false) {
        const el = $(id);
        if (!el) return;

        el.textContent = text;
        el.classList.remove("is-ok", "is-warn", "is-error", "is-sim");

        if (ok) {
            el.classList.add("is-ok");
        } else if (warning) {
            el.classList.add("is-warn");
        } else {
            el.classList.add("is-error");
        }
    }

    function setSimulationHealthValue(id, text) {
        const el = $(id);
        if (!el) return;

        el.textContent = text;
        el.classList.remove("is-ok", "is-warn", "is-error");
        el.classList.add("is-sim");
    }

    function setElementVisible(el, visible, display = "flex") {
        if (!el) return;

        el.hidden = !visible;
        el.classList.toggle("fw-is-hidden", !visible);
        el.style.display = visible ? display : "none";
    }

    /* ======================================================================
       SYNC
       ====================================================================== */

    function renderSync(sync) {
        const bar = $("fwSyncBar");
        if (!bar) return;

        if (state.mode === "simulacao") {
            setElementVisible(bar, false);
            return;
        }

        const pending = Number(sync.pendentes || 0);
        const deleted = Number(sync.deletadas_pendentes || 0);
        const totalPending = pending + deleted;

        if (totalPending <= 0) {
            setElementVisible(bar, false);
            return;
        }

        setElementVisible(bar, true);

        setText(
            "fwSyncTitle",
            `${totalPending} alteração${totalPending === 1 ? "" : "ões"} pendente${totalPending === 1 ? "" : "s"}`
        );

        setText(
            "fwSyncText",
            "O estado desejado no Django ainda precisa ser aplicado pelo MoonShield-Agent."
        );
    }

    async function applyPendingRules() {
        const button = $("fwApplyRulesBtn");
        if (!button || button.disabled) return;

        button.disabled = true;
        button.classList.add("is-loading");
        button.innerHTML = '<i class="bi bi-arrow-repeat"></i> Aplicando';

        try {
            const result = await apiJson(URLS.apply, {
                method: "POST",
                headers: {
                    "X-CSRFToken": csrfToken(),
                    "Accept": "application/json",
                },
            });

            if (!result.ok) {
                throw new Error(result?.resultado?.erro || "Não foi possível aplicar as regras.");
            }

            showToast("Regras aplicadas pelo MoonShield-Agent.");
            await refreshAll();
        } catch (error) {
            console.error(error);
            showToast(error.message || "Falha ao aplicar regras.", "err");
        } finally {
            button.disabled = false;
            button.classList.remove("is-loading");
            button.innerHTML = '<i class="bi bi-lightning-charge"></i> Aplicar';
        }
    }

    /* ======================================================================
       KPIs
       ====================================================================== */

    function renderKPIs(metrics) {
        const trafficIn = number(metrics.traffic_in);
        const trafficOut = number(metrics.traffic_out);
        const totalTraffic = trafficIn + trafficOut;

        setText("kpiTraffic", `${formatCompact(totalTraffic)} MB`);
        setText("kpiTrafficTrend", `IN ${formatCompact(trafficIn)} MB · OUT ${formatCompact(trafficOut)} MB`);
        setText("kpiConexoes", formatCompact(number(metrics.conexoes)));
        setText("kpiDrops", formatCompact(number(metrics.drops)));
        setText("kpiAllows", formatCompact(number(metrics.allows)));

        const topPort = metrics.top_port && metrics.top_port !== "—"
            ? `:${metrics.top_port}`
            : "—";

        setText("kpiTopPort", topPort);
        setText(
            "kpiTopPortTrend",
            metrics.top_port_hits
                ? `${formatCompact(number(metrics.top_port_hits))} evento(s)`
                : "—"
        );

        setText("kpiTopIp", metrics.top_ip || "—");
        setText(
            "kpiTopIpTrend",
            metrics.top_ip_hits
                ? `${formatCompact(number(metrics.top_ip_hits))} bloqueio(s)`
                : "—"
        );
    }

    /* ======================================================================
       CHARTS
       ====================================================================== */

    function initChartDefaults() {
        if (typeof Chart === "undefined") return;

        Chart.defaults.color = cssVar("--text-dim", "rgba(255,255,255,.35)");
        Chart.defaults.font.family = "'JetBrains Mono', monospace";
        Chart.defaults.font.size = 9;
        Chart.defaults.plugins.legend.display = false;
        Chart.defaults.plugins.tooltip.backgroundColor = cssVar("--bg-card", "#111");
        Chart.defaults.plugins.tooltip.borderColor = cssVar("--border", "rgba(255,255,255,.1)");
        Chart.defaults.plugins.tooltip.borderWidth = 1;
        Chart.defaults.plugins.tooltip.titleColor = cssVar("--text-primary", "#fff");
        Chart.defaults.plugins.tooltip.bodyColor = cssVar("--text-muted", "#aaa");
        Chart.defaults.plugins.tooltip.padding = 10;
        Chart.defaults.plugins.tooltip.cornerRadius = 7;
    }

    function renderCharts(charts) {
        if (typeof Chart === "undefined") return;

        const labels = Array.isArray(charts.hours) ? charts.hours : [];
        const trafficIn = arrayNumbers(charts.traffic_in);
        const trafficOut = arrayNumbers(charts.traffic_out);
        const drops = arrayNumbers(charts.drops);
        const denies = arrayNumbers(charts.denies);

        renderTrafficChart(labels, trafficIn, trafficOut);
        renderBlockChart(labels, drops, denies);

        renderSpark("sparkTraffic", trafficIn, "#3b82f6");
        renderSpark("sparkConexoes", trafficOut, "#22c55e");
        renderSpark("sparkDrops", drops, "#ef4444");
    }

    function renderTrafficChart(labels, trafficIn, trafficOut) {
        const canvas = $("fwChartTraffic");
        if (!canvas) return;

        destroyChart("traffic");

        const ctx = canvas.getContext("2d");
        const gradientIn = ctx.createLinearGradient(0, 0, 0, 210);
        gradientIn.addColorStop(0, "rgba(59,130,246,.38)");
        gradientIn.addColorStop(1, "rgba(59,130,246,.02)");

        const gradientOut = ctx.createLinearGradient(0, 0, 0, 210);
        gradientOut.addColorStop(0, "rgba(34,197,94,.24)");
        gradientOut.addColorStop(1, "rgba(34,197,94,.01)");

        state.charts.traffic = new Chart(canvas, {
            type: "line",
            data: {
                labels,
                datasets: [
                    {
                        label: "IN",
                        data: trafficIn,
                        borderColor: "#3b82f6",
                        backgroundColor: gradientIn,
                        borderWidth: 1.8,
                        fill: true,
                        tension: .38,
                        pointRadius: 0,
                        pointHoverRadius: 4,
                    },
                    {
                        label: "OUT",
                        data: trafficOut,
                        borderColor: "#22c55e",
                        backgroundColor: gradientOut,
                        borderWidth: 1.5,
                        fill: true,
                        tension: .38,
                        pointRadius: 0,
                        pointHoverRadius: 4,
                    },
                ],
            },
            options: chartOptions(" MB"),
        });
    }

    function renderBlockChart(labels, drops, denies) {
        const canvas = $("fwChartBlocks");
        if (!canvas) return;

        destroyChart("blocks");

        state.charts.blocks = new Chart(canvas, {
            data: {
                labels,
                datasets: [
                    {
                        type: "bar",
                        label: "DROP",
                        data: drops,
                        backgroundColor: "rgba(239,68,68,.55)",
                        borderColor: "#ef4444",
                        borderWidth: 1,
                        borderRadius: 3,
                        order: 2,
                    },
                    {
                        type: "line",
                        label: "DENY",
                        data: denies,
                        borderColor: "#f97316",
                        borderWidth: 1.7,
                        tension: .38,
                        fill: false,
                        pointRadius: 0,
                        pointHoverRadius: 4,
                        order: 1,
                    },
                ],
            },
            options: chartOptions(""),
        });
    }

    function chartOptions(suffix) {
        return {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                mode: "index",
                intersect: false,
            },
            plugins: {
                legend: {
                    display: false,
                },
                tooltip: {
                    callbacks: {
                        label: (ctx) => ` ${ctx.dataset.label}: ${ctx.raw}${suffix}`,
                    },
                },
            },
            scales: {
                x: {
                    grid: {
                        color: cssVar("--border-soft", "rgba(255,255,255,.04)"),
                    },
                    ticks: {
                        maxTicksLimit: 8,
                        color: cssVar("--text-dim", "#777"),
                    },
                    border: {
                        display: false,
                    },
                },
                y: {
                    min: 0,
                    grid: {
                        color: cssVar("--border-soft", "rgba(255,255,255,.04)"),
                    },
                    ticks: {
                        color: cssVar("--text-dim", "#777"),
                    },
                    border: {
                        display: false,
                    },
                },
            },
            animation: {
                duration: 420,
            },
        };
    }

    function renderSpark(id, values, color) {
        const canvas = $(id);
        if (!canvas || !values.length || typeof Chart === "undefined") return;

        const old = Chart.getChart(canvas);
        if (old) old.destroy();

        new Chart(canvas, {
            type: "line",
            data: {
                labels: values.map(() => ""),
                datasets: [{
                    data: values,
                    borderColor: color,
                    backgroundColor: hexToRgba(color, .07),
                    borderWidth: 1.2,
                    fill: true,
                    tension: .38,
                    pointRadius: 0,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                plugins: {
                    legend: { display: false },
                    tooltip: { enabled: false },
                },
                scales: {
                    x: { display: false },
                    y: { display: false },
                },
            },
        });
    }

    function destroyChart(name) {
        if (state.charts[name]) {
            state.charts[name].destroy();
            state.charts[name] = null;
        }
    }

    /* ======================================================================
       TOP IPS / FEED
       ====================================================================== */

    function renderTopIps(items) {
        const container = $("fwTopAtacantesList");
        if (!container) return;

        if (!Array.isArray(items) || !items.length) {
            container.innerHTML = '<div class="fw-empty">Nenhum IP bloqueado no período.</div>';
            return;
        }

        container.innerHTML = items.slice(0, 5).map((item, index) => `
            <div class="fw-top-item">
                <span class="fw-top-item__rank">${String(index + 1).padStart(2, "0")}</span>
                <div class="fw-top-item__main">
                    <strong>${escapeHtml(item.ip || "—")}</strong>
                    <small>origem bloqueada</small>
                </div>
                <span class="fw-top-item__hits">${formatCompact(number(item.hits))} eventos</span>
            </div>
        `).join("");
    }

    function renderFeed(logs) {
        const container = $("fwFeedList");
        if (!container) return;

        const blocked = (Array.isArray(logs) ? logs : [])
            .filter((item) => ["DROP", "DENY"].includes(String(item.action || "").toUpperCase()))
            .slice(0, 20);

        setText("fwFeedCount", String(blocked.length));

        if (!blocked.length) {
            container.innerHTML = '<div class="fw-empty">Nenhum bloqueio recente.</div>';
            return;
        }

        container.innerHTML = blocked.map((log) => {
            const action = String(log.action || "DENY").toUpperCase();
            const klass = action === "DROP" ? "drop" : "deny";

            return `
                <div class="fw-feed-item">
                    <span class="fw-feed-time">${escapeHtml(log.time || "—")}</span>
                    <span class="fw-feed-action fw-feed-action--${klass}">${escapeHtml(action)}</span>
                    <span class="fw-feed-msg">${escapeHtml(log.src_ip || "—")} → ${escapeHtml(log.dst_ip || "—")}:${escapeHtml(log.dst_port ?? "—")}</span>
                </div>
            `;
        }).join("");
    }

    function fallbackTopIp(metrics) {
        if (!metrics?.top_ip || metrics.top_ip === "—") return [];
        return [{
            ip: metrics.top_ip,
            hits: metrics.top_ip_hits || 0,
        }];
    }

    /* ======================================================================
       EXPORT
       ====================================================================== */

    function exportCsv() {
        const rows = Array.isArray(state.logs) ? state.logs : [];

        if (!rows.length) {
            showToast("Não há eventos para exportar.", "warn");
            return;
        }

        const header = [
            "Hora",
            "Ação",
            "Interface",
            "Src IP",
            "Src Porta",
            "Dst IP",
            "Dst Porta",
            "Proto",
            "Regra",
            "Bytes",
            "Motivo",
        ];

        const body = rows.map((log) => [
            log.time,
            log.action,
            log.iface,
            log.src_ip,
            log.src_port,
            log.dst_ip,
            log.dst_port,
            log.proto,
            log.rule_id,
            log.bytes,
            log.reason,
        ].map(csvCell).join(","));

        const csv = [header.map(csvCell).join(","), ...body].join("\r\n");
        const blob = new Blob(["\ufeff", csv], {
            type: "text/csv;charset=utf-8;",
        });

        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");

        link.href = url;
        link.download = `moonshield-firewall-${new Date().toISOString().slice(0, 10)}.csv`;
        document.body.appendChild(link);
        link.click();
        link.remove();

        window.setTimeout(() => URL.revokeObjectURL(url), 1000);

        showToast("CSV exportado.");
    }

    function exportNftReference() {
        if (!URLS.exportNft) return;
        window.location.href = URLS.exportNft;
    }

    /* ======================================================================
       EVENTS
       ====================================================================== */

    function bindEvents() {
        document.querySelectorAll(".fw-period__btn").forEach((button) => {
            button.addEventListener("click", async () => {
                document.querySelectorAll(".fw-period__btn").forEach((item) => {
                    item.classList.remove("fw-period__btn--active");
                });

                button.classList.add("fw-period__btn--active");
                state.period = button.dataset.period || "24h";

                try {
                    setRefreshing(true);
                    const data = await loadData(state.period);

                    if (!isSimulationData(data)) {
                        try {
                            await loadStatus();
                        } catch (error) {
                            if (!isUsableFirewallStatus(data?.firewall)) {
                                renderStatusError(error);
                            }
                        }
                    }

                    updateTimestamp();
                } catch (error) {
                    console.error(error);
                    showToast("Falha ao atualizar o período.", "err");
                } finally {
                    setRefreshing(false);
                }
            });
        });

        $("fwRefreshBtn")?.addEventListener("click", refreshAll);
        $("fwExportBtn")?.addEventListener("click", exportCsv);
        $("fwExportNftBtn")?.addEventListener("click", exportNftReference);
        $("fwApplyRulesBtn")?.addEventListener("click", applyPendingRules);
    }

    /* ======================================================================
       HELPERS
       ====================================================================== */

    function setRefreshing(active) {
        const button = $("fwRefreshBtn");
        if (!button) return;

        button.disabled = active;
        button.classList.toggle("spinning", active);
    }

    function updateTimestamp() {
        const now = new Date();
        setText(
            "fwLastUpdate",
            `Atualizado ${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}`
        );
    }

    function showToast(message, type = "ok") {
        const toast = $("fwToast");
        if (!toast) return;

        toast.textContent = message;
        toast.className = `fw-toast fw-toast--${type} show`;

        window.clearTimeout(toastTimer);
        toastTimer = window.setTimeout(() => {
            toast.classList.remove("show");
        }, 2800);
    }

    function setText(id, value) {
        const el = $(id);
        if (el) el.textContent = value;
    }

    function number(value) {
        const parsed = Number(value);
        return Number.isFinite(parsed) ? parsed : 0;
    }

    function arrayNumbers(value) {
        return Array.isArray(value) ? value.map(number) : [];
    }

    function formatCompact(value) {
        const n = number(value);

        if (Math.abs(n) >= 1_000_000) {
            return `${(n / 1_000_000).toFixed(1).replace(".0", "")}M`;
        }

        if (Math.abs(n) >= 1_000) {
            return `${(n / 1_000).toFixed(1).replace(".0", "")}k`;
        }

        return String(Math.round(n));
    }

    function cssVar(name, fallback) {
        const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
        return value || fallback;
    }

    function hexToRgba(hex, alpha) {
        const value = String(hex).replace("#", "");
        const normalized = value.length === 3
            ? value.split("").map((char) => char + char).join("")
            : value;

        const int = Number.parseInt(normalized, 16);

        if (!Number.isFinite(int)) {
            return `rgba(255,255,255,${alpha})`;
        }

        const r = (int >> 16) & 255;
        const g = (int >> 8) & 255;
        const b = int & 255;

        return `rgba(${r},${g},${b},${alpha})`;
    }

    function csvCell(value) {
        const text = String(value ?? "");
        return `"${text.replace(/"/g, '""')}"`;
    }

    function escapeHtml(value) {
        return String(value ?? "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
});
