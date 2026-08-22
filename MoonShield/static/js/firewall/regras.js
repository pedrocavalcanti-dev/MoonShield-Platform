/**
 * MOONSHIELD — FIREWALL / REGRAS v11
 * Fonte de verdade do frontend: APIs Django da arquitetura local.
 */

document.addEventListener("DOMContentLoaded", () => {
    "use strict";

    const root = document.getElementById("fwrApp");
    if (!root) return;

    const $ = (id) => document.getElementById(id);

    const URLS = {
        data: root.dataset.urlData,
        status: root.dataset.urlStatus,
        interfaces: root.dataset.urlInterfaces,
        rules: root.dataset.urlRules,
        apply: root.dataset.urlApply,
        block: root.dataset.urlBlock,
        blocklist: root.dataset.urlBlocklist,
        allowlist: root.dataset.urlAllowlist,
        geoblock: root.dataset.urlGeoblock,
        nat: root.dataset.urlNat,
        exportNft: root.dataset.urlExport,
        install: root.dataset.urlInstall,
    };

    const state = {
        mode: "real",
        snapshot: null,
        status: {},
        interfaces: [],
        rules: [],
        blocklist: [],
        allowlist: [],
        geoblock: [],
        nat: [],
        sync: {},
        editingRuleId: null,
        editingNatId: null,
        modalResolve: null,
    };

    let toastTimer = null;

    bindStaticEvents();
    refreshAll();
    openFromQueryString();

    /* =====================================================================
       API
       ===================================================================== */

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
                payload?.resultado?.erro?.mensagem ||
                payload?.resultado?.erro ||
                payload?.sync_result?.erro?.mensagem ||
                payload?.sync_result?.erro ||
                payload?.erro?.mensagem ||
                payload?.erro ||
                payload?.mensagem ||
                extractValidationError(payload?.resultado?.detalhes) ||
                extractValidationError(payload?.sync_result?.detalhes) ||
                extractValidationError(payload?.detalhes) ||
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

    function detailUrl(base, id) {
        return `${String(base).replace(/\/$/, "")}/${encodeURIComponent(id)}/`;
    }

    /* =====================================================================
       LOAD
       ===================================================================== */

    async function refreshAll() {
        setRuntime("loading", "Verificando");

        let context = null;

        try {
            context = await api(URLS.data);
            state.snapshot = context || null;
            state.mode = normalizeMode(context);
        } catch (error) {
            console.warn("[firewall/regras] contexto:", error);
            state.snapshot = null;
            state.mode = "real";
        }

        if (isSimulation()) {
            absorbSimulationSnapshot(context || {});
            applyModePresentation();
            renderAll();
            return;
        }

        const requests = [
            ["status", () => api(URLS.status)],
            ["interfaces", () => api(URLS.interfaces)],
            ["rules", () => api(URLS.rules)],
            ["blocklist", () => api(URLS.blocklist)],
            ["allowlist", () => api(URLS.allowlist)],
            ["geoblock", () => api(URLS.geoblock)],
            ["nat", () => api(URLS.nat)],
        ];

        const results = await Promise.allSettled(requests.map(([, fn]) => fn()));

        let statusLoaded = false;
        let interfacesLoaded = false;

        results.forEach((result, index) => {
            const key = requests[index][0];

            if (result.status === "fulfilled") {
                absorbResponse(key, result.value || {});
                if (key === "status") statusLoaded = true;
                if (key === "interfaces") interfacesLoaded = true;
                return;
            }

            console.warn(`[firewall/regras] ${key}:`, result.reason);
        });

        /*
         * /api/data/ já devolve o estado consolidado real em `firewall`.
         * Ele é usado como fallback para não mostrar "Agent offline" por uma
         * falha isolada da chamada dedicada /api/status/.
         */
        if (!statusLoaded && isUsableFirewallStatus(context?.firewall)) {
            state.status = context.firewall;
            renderStatus(context.firewall);
            statusLoaded = true;
        }

        if (!interfacesLoaded) {
            const fallbackInterfaces = interfacesFromFirewall(context?.firewall);
            if (fallbackInterfaces.length) {
                state.interfaces = fallbackInterfaces;
                interfacesLoaded = true;
            }
        }

        if (!statusLoaded) {
            renderStatusError(new Error("Não foi possível consultar o estado do Firewall."));
        }

        applyModePresentation();
        renderAll();
    }

    function normalizeMode(data) {
        const raw = String(data?.modo || data?.mode || "").trim().toLowerCase();
        if (["simulacao", "simulação", "simulation", "demo", "simulado"].includes(raw)) {
            return "simulacao";
        }
        return "real";
    }

    function isSimulation() {
        return state.mode === "simulacao";
    }

    function isUsableFirewallStatus(status) {
        if (!status || typeof status !== "object") return false;
        return status.ok === true ||
            "operacional" in status ||
            "instalado" in status ||
            "agent_disponivel" in status;
    }

    function interfacesFromFirewall(firewall) {
        const direct =
            firewall?.detalhes?.raw?.interfaces ||
            firewall?.detalhes?.interfaces ||
            firewall?.interfaces ||
            [];

        return normalizeInterfaces(Array.isArray(direct) ? direct : []);
    }

    function absorbSimulationSnapshot(data) {
        const firewall = data?.firewall || {};

        state.status = {
            ...firewall,
            modo: "simulacao",
            mode: "demo",
        };

        state.interfaces = interfacesFromFirewall(firewall);

        state.rules = Array.isArray(data?.rules)
            ? data.rules.map((rule) => ({ ...rule, pendente: false, sincronizada: true }))
            : [];

        state.blocklist = Array.isArray(data?.blocklist) ? [...data.blocklist] : [];
        state.allowlist = Array.isArray(data?.allowlist) ? [...data.allowlist] : [];
        state.geoblock = Array.isArray(data?.geoblock) ? [...data.geoblock] : [];
        state.nat = Array.isArray(data?.nat) ? [...data.nat] : [];
        state.sync = {};

        renderStatus(state.status);
    }

    function applyModePresentation() {
        const simulation = isSimulation();

        if (simulation) {
            setRuntime("sim", "Modo simulado");

            const setup = $("fwrSetupCallout");
            const sync = $("fwrSyncBar");
            if (setup) setup.hidden = true;
            if (sync) sync.hidden = true;

            if ($("fwrApplyBtn")) $("fwrApplyBtn").hidden = true;
            if ($("fwrExportNftBtn")) $("fwrExportNftBtn").hidden = true;

            if ($("fwrRuntimeHint")) {
                $("fwrRuntimeHint").innerHTML =
                    '<i class="bi bi-bezier2"></i> simulação local';
            }

            return;
        }

        if ($("fwrApplyBtn")) $("fwrApplyBtn").hidden = false;
        if ($("fwrExportNftBtn")) $("fwrExportNftBtn").hidden = false;

        if ($("fwrRuntimeHint")) {
            $("fwrRuntimeHint").innerHTML =
                '<i class="bi bi-lightning-charge-fill"></i> ms_emergency';
        }
    }

    function absorbResponse(key, data) {
        if (key === "status") {
            state.status = data;
            renderStatus(data);
            return;
        }

        if (key === "interfaces") {
            state.interfaces = normalizeInterfaces(data.interfaces || []);
            renderTopologyMini();
            updatePhysicalIfaceHint();
            return;
        }

        if (key === "rules") {
            state.rules = Array.isArray(data.rules) ? data.rules : [];
            state.sync = data.sync || {};
            renderSync(state.sync);
            return;
        }

        if (key === "blocklist") state.blocklist = Array.isArray(data.entries) ? data.entries : [];
        if (key === "allowlist") state.allowlist = Array.isArray(data.entries) ? data.entries : [];
        if (key === "geoblock") state.geoblock = Array.isArray(data.entries) ? data.entries : [];
        if (key === "nat") state.nat = Array.isArray(data.entries) ? data.entries : [];
    }

    async function reloadRules() {
        const data = await api(URLS.rules);
        state.rules = Array.isArray(data.rules) ? data.rules : [];
        state.sync = data.sync || {};
        renderRules();
        updateCounts();
        renderSync(state.sync);
    }

    async function reloadBlocklist() {
        const data = await api(URLS.blocklist);
        state.blocklist = Array.isArray(data.entries) ? data.entries : [];
        renderBlocklist();
        updateCounts();
    }

    /* =====================================================================
       STATUS / TOPOLOGIA
       ===================================================================== */

    function renderStatus(status) {
        if (isSimulation()) {
            setRuntime("sim", "Modo simulado");
            const setup = $("fwrSetupCallout");
            if (setup) setup.hidden = true;
            renderTopologyMini();
            return;
        }

        const agentOk = Boolean(status.agent_disponivel || status.agent_ativo);
        const operational = Boolean(status.operacional);
        const installed = Boolean(status.instalado || status.tabela_instalada || operational);
        const configured = Boolean(status.configurado);

        if (operational || (agentOk && installed && configured && status.chains_ok)) {
            setRuntime("ok", "Operacional");
            const setup = $("fwrSetupCallout");
            if (setup) setup.hidden = true;
        } else if (agentOk) {
            setRuntime("warn", installed ? "Requer atenção" : "Não instalado");
            showSetup(
                installed ? "Firewall requer validação" : "Firewall ainda não instalado",
                installed
                    ? (status.status_label || "A estrutura existe, mas não está totalmente operacional.")
                    : "Conclua a instalação antes de administrar regras reais."
            );
        } else {
            setRuntime("error", "Agent offline");
            showSetup(
                "MoonShield-Agent indisponível",
                getStatusError(status) || "O Django não conseguiu acessar o socket local do Agent."
            );
        }

        renderTopologyMini();
    }

    function renderStatusError(error) {
        if (isSimulation()) {
            setRuntime("sim", "Modo simulado");
            const setup = $("fwrSetupCallout");
            if (setup) setup.hidden = true;
            return;
        }

        setRuntime("error", "Indisponível");
        showSetup("Não foi possível consultar o Firewall", error?.message || "Verifique o backend e o Agent.");
    }

    function setRuntime(type, text) {
        const badge = $("fwrRuntimeBadge");
        if (!badge) return;
        badge.className = `fwr-runtime fwr-runtime--${type}`;
        setText("fwrRuntimeText", text);
    }

    function showSetup(title, text) {
        const el = $("fwrSetupCallout");
        if (!el) return;
        el.hidden = false;
        setText("fwrSetupTitle", title);
        setText("fwrSetupText", text);
    }

    function renderTopologyMini() {
        const status = state.status || {};
        const wan = status.interface_wan || logicalPhysical("WAN") || "—";
        const mgmt = status.interface_mgmt || logicalPhysical("MGMT") || "—";
        const lan = status.interface_lan || logicalPhysical("LAN") || "—";
        setText("fwrTopologyMini", `WAN ${wan} · MGMT ${mgmt} · LAN ${lan}`);
    }

    function logicalPhysical(role) {
        const status = state.status || {};
        const direct = {
            WAN: status.interface_wan,
            MGMT: status.interface_mgmt,
            LAN: status.interface_lan,
        }[role];
        if (direct) return direct;

        const item = state.interfaces.find((iface) => iface.roles.includes(role));
        return item?.name || "";
    }

    function normalizeInterfaces(items) {
        if (!Array.isArray(items)) return [];
        return items.map((item) => {
            if (typeof item === "string") return { name: item, ip: "", roles: [] };
            const roles = item.papeis || item.roles || item.papel || [];
            return {
                name: String(item.nome || item.name || item.interface || item.iface || ""),
                ip: String(item.ip || item.ipv4 || item.endereco || ""),
                roles: (Array.isArray(roles) ? roles : [roles]).filter(Boolean).map((r) => String(r).toUpperCase()),
            };
        }).filter((i) => i.name && i.name !== "lo");
    }

    function getStatusError(status) {
        const err = status?.erro;
        if (typeof err === "string") return err;
        if (err && typeof err === "object") return err.mensagem || err.erro || "";
        return "";
    }

    /* =====================================================================
       RENDER GERAL
       ===================================================================== */

    function renderAll() {
        renderRules();
        renderBlocklist();
        renderAllowlist();
        renderGeoblock();
        renderNat();
        updateCounts();
        renderSync(state.sync);
        renderTopologyMini();
    }

    function updateCounts() {
        setText("tabCountRegras", state.rules.filter((r) => !r.deletado).length);
        setText("tabCountBloqueados", state.blocklist.length);
        setText("tabCountLiberados", state.allowlist.length);
        setText("tabCountGeoblock", state.geoblock.length);
        setText("tabCountNat", state.nat.length);
        setText("natCount", state.nat.length);
    }

    /* =====================================================================
       SYNC / APPLY
       ===================================================================== */

    function renderSync(sync) {
        const bar = $("fwrSyncBar");
        if (!bar) return;

        if (isSimulation()) {
            bar.hidden = true;
            return;
        }

        const pending = Number(sync?.pendentes || state.rules.filter((r) => r.pendente).length || 0);
        const deleted = Number(sync?.deletadas_pendentes || 0);
        const total = pending + deleted;

        if (total <= 0) {
            bar.hidden = true;
            return;
        }

        bar.hidden = false;
        setText(
            "fwrSyncTitle",
            total === 1
                ? "1 alteração pendente"
                : `${total} alterações pendentes`
        );
        setText("fwrSyncMsg", "O Django mantém a alteração pendente até o MoonShield-Agent confirmar a aplicação.");
    }

    async function applyPending() {
        if (isSimulation()) return;

        const buttons = [$("fwrApplyBtn"), $("fwrSyncApplyBtn")].filter(Boolean);
        buttons.forEach((b) => setButtonLoading(b, true, "Aplicando"));

        try {
            const data = await api(URLS.apply, { method: "POST" });
            const ok = Boolean(data.ok && (data.resultado?.ok ?? true));
            if (!ok) throw new Error(data.resultado?.erro || "Falha ao aplicar regras.");

            toast("Regras aplicadas pelo MoonShield-Agent.");
            await reloadRules();
            await refreshStatusOnly();
        } catch (error) {
            toast(error.message || "Falha ao aplicar regras.", "err");
        } finally {
            buttons.forEach((b) => setButtonLoading(b, false));
            if ($("fwrApplyBtn")) $("fwrApplyBtn").innerHTML = '<i class="bi bi-lightning-charge"></i> Aplicar pendentes';
            if ($("fwrSyncApplyBtn")) $("fwrSyncApplyBtn").innerHTML = '<i class="bi bi-lightning-charge"></i> Aplicar agora';
        }
    }

    async function refreshStatusOnly() {
        if (isSimulation()) {
            renderStatus(state.status || {});
            return;
        }

        try {
            const status = await api(URLS.status);
            state.status = status;
            renderStatus(status);
        } catch (error) {
            renderStatusError(error);
        }
    }

    function nextSimId(items) {
        const values = (Array.isArray(items) ? items : [])
            .map((item) => Number(item?.id))
            .filter(Number.isFinite);
        return values.length ? Math.max(...values) + 1 : 1;
    }

    function simulationDate() {
        return new Date().toLocaleDateString("pt-BR");
    }

    /* =====================================================================
       RULES
       ===================================================================== */

    function filteredRules() {
        const q = ($("fwrSearchRegras")?.value || "").trim().toLowerCase();
        const action = $("fwrFilterAction")?.value || "all";
        const iface = $("fwrFilterIface")?.value || "all";

        return state.rules
            .filter((r) => !r.deletado)
            .filter((r) => action === "all" || r.action === action)
            .filter((r) => iface === "all" || r.iface === iface)
            .filter((r) => {
                if (!q) return true;
                return [r.desc, r.src, r.dst, r.port, r.proto, r.iface]
                    .some((value) => String(value || "").toLowerCase().includes(q));
            })
            .sort((a, b) => Number(a.priority || 0) - Number(b.priority || 0));
    }

    function renderRules() {
        const body = $("fwrRulesBody");
        if (!body) return;
        const rows = filteredRules();

        if (!rows.length) {
            body.innerHTML = '<tr><td colspan="12"><div class="fwr-empty">Nenhuma regra encontrada.</div></td></tr>';
            return;
        }

        body.innerHTML = rows.map((r) => `
            <tr class="${r.enabled ? "" : "fwr-row-disabled"}">
                <td class="fwr-cell-mono">${escapeHtml(r.priority ?? "—")}</td>
                <td><span class="fwr-action-badge fwr-action-badge--${r.action === "allow" ? "allow" : "deny"}">${escapeHtml(String(r.action || "deny").toUpperCase())}</span></td>
                <td><span class="fwr-iface-badge">${escapeHtml(r.iface || "any")}</span></td>
                <td class="fwr-cell-mono fwr-cell-muted">${escapeHtml(String(r.dir || "in").toUpperCase())}</td>
                <td class="fwr-cell-mono">${escapeHtml(r.proto || "any")}</td>
                <td class="fwr-cell-mono" title="${escapeAttr(r.src || "any")}">${escapeHtml(r.src || "any")}</td>
                <td class="fwr-cell-mono" title="${escapeAttr(r.dst || "any")}">${escapeHtml(r.dst || "any")}</td>
                <td class="fwr-cell-mono">${escapeHtml(r.port || "any")}</td>
                <td class="fwr-cell-muted" title="${escapeAttr(r.desc || "")}">${escapeHtml(truncate(r.desc || "—", 34))}</td>
                <td>${ruleStateBadge(r)}</td>
                <td>
                    <label class="fwr-toggle" title="${r.enabled ? "Desativar" : "Ativar"}">
                        <input type="checkbox" class="rule-toggle" data-id="${r.id}" ${r.enabled ? "checked" : ""}>
                        <span></span>
                    </label>
                </td>
                <td>
                    <div class="fwr-row-actions">
                        <button class="fwr-icon-btn" type="button" data-rule-action="edit" data-id="${r.id}" title="Editar"><i class="bi bi-pencil"></i></button>
                        <button class="fwr-icon-btn" type="button" data-rule-action="copy" data-id="${r.id}" title="Duplicar"><i class="bi bi-copy"></i></button>
                        <button class="fwr-icon-btn fwr-icon-btn--danger" type="button" data-rule-action="delete" data-id="${r.id}" title="Remover"><i class="bi bi-trash3"></i></button>
                    </div>
                </td>
            </tr>
        `).join("");

        body.querySelectorAll("[data-rule-action]").forEach((button) => {
            button.addEventListener("click", () => {
                const id = Number(button.dataset.id);
                const action = button.dataset.ruleAction;
                if (action === "edit") openRuleDrawer(id);
                if (action === "copy") duplicateRule(id);
                if (action === "delete") deleteRule(id);
            });
        });

        body.querySelectorAll(".rule-toggle").forEach((toggle) => {
            toggle.addEventListener("change", async () => {
                const id = Number(toggle.dataset.id);
                const previous = !toggle.checked;
                toggle.disabled = true;
                try {
                    await updateRule(id, { enabled: toggle.checked }, false);
                    toast(`Regra ${toggle.checked ? "ativada" : "desativada"}.`);
                } catch (error) {
                    toggle.checked = previous;
                    toast(error.message, "err");
                } finally {
                    toggle.disabled = false;
                }
            });
        });
    }

    function ruleStateBadge(rule) {
        if (isSimulation()) {
            return '<span class="fwr-state-badge fwr-state-badge--sim"><i class="bi bi-bezier2"></i> SIMULADA</span>';
        }

        if (rule.ultimo_erro) {
            return `<span class="fwr-state-badge fwr-state-badge--error" title="${escapeAttr(rule.ultimo_erro)}"><i class="bi bi-exclamation-circle"></i> ERRO</span>`;
        }
        if (rule.pendente) {
            return '<span class="fwr-state-badge fwr-state-badge--pending"><i class="bi bi-hourglass-split"></i> PENDENTE</span>';
        }
        if (rule.sincronizada) {
            return '<span class="fwr-state-badge fwr-state-badge--ok"><i class="bi bi-check-circle"></i> APLICADA</span>';
        }
        return '<span class="fwr-state-badge">—</span>';
    }

    function openRuleDrawer(id = null) {
        const rule = id ? state.rules.find((r) => Number(r.id) === Number(id)) : null;
        state.editingRuleId = rule?.id || null;

        $("fwrRuleDrawerTitle").textContent = rule ? "Editar regra" : "Nova regra";
        $("fwrRuleDrawerDup").hidden = !rule;
        hideFormError("fwrRuleFormError");

        $("rfDesc").value = rule?.desc || "";
        $("rfAction").value = rule?.action || "deny";
        $("rfPriority").value = rule?.priority ?? 100;
        $("rfIface").value = rule?.iface || "WAN";
        $("rfDir").value = normalizeRuleDirection(rule?.dir || "in");
        $("rfProto").value = rule?.proto || "TCP";
        $("rfSrc").value = rule?.src || "any";
        $("rfDst").value = rule?.dst || "any";
        $("rfPort").value = rule?.port || "any";
        $("rfEnabled").checked = rule ? Boolean(rule.enabled) : true;
        $("rfLog").checked = rule ? Boolean(rule.log) : true;

        updateRulePreview();
        updateProtocolPortState();
        updatePhysicalIfaceHint();
        setDrawer("fwrRuleDrawer", "fwrRuleDrawerOverlay", true);
        window.setTimeout(() => $("rfDesc")?.focus(), 180);
    }

    function closeRuleDrawer() {
        state.editingRuleId = null;
        setDrawer("fwrRuleDrawer", "fwrRuleDrawerOverlay", false);
    }

    function normalizeRuleDirection(value) {
        const dir = String(value || "in").trim().toLowerCase();
        if (["in", "out", "forward", "both"].includes(dir)) return dir;
        if (dir === "entrada") return "in";
        if (dir === "saida" || dir === "saída") return "out";
        if (["ambos", "both", "inout", "in/out"].includes(dir)) return "both";
        return "in";
    }

    function collectRule() {
        const src = String($("rfSrc")?.value || "").trim() || "any";
        const dst = String($("rfDst")?.value || "").trim() || "any";
        const port = String($("rfPort")?.value || "").trim() || "any";

        return {
            desc: String($("rfDesc")?.value || "").trim(),
            action: String($("rfAction")?.value || "deny").trim().toLowerCase(),
            priority: Number.parseInt($("rfPriority")?.value, 10) || 100,
            iface: String($("rfIface")?.value || "any").trim(),
            dir: normalizeRuleDirection($("rfDir")?.value),
            proto: String($("rfProto")?.value || "any").trim(),
            src,
            dst,
            port,
            enabled: Boolean($("rfEnabled")?.checked),
            log: Boolean($("rfLog")?.checked),
        };
    }

    function validateRule(payload) {
        if (!["allow", "deny"].includes(payload.action)) return "Ação inválida.";
        if (!["WAN", "MGMT", "LAN", "any"].includes(payload.iface)) return "Interface inválida.";
        if (!["in", "out", "forward", "both"].includes(payload.dir)) return "Direção inválida.";
        if (!["TCP", "UDP", "ICMP", "any"].includes(payload.proto)) return "Protocolo inválido.";
        if (!Number.isInteger(payload.priority) || payload.priority < 1 || payload.priority > 10000) return "Prioridade deve ficar entre 1 e 10000.";
        if (!validAddressOrAny(payload.src)) return "Origem inválida. Use IP, rede CIDR ou 'any'.";
        if (!validAddressOrAny(payload.dst)) return "Destino inválido. Use IP, rede CIDR ou 'any'.";
        if (["TCP", "UDP"].includes(payload.proto) && !validPort(payload.port)) return "Porta inválida. Use any, uma porta ou intervalo (ex.: 8000-8010).";
        return "";
    }

    function normalizedRuleSignature(rule) {
        return JSON.stringify({
            desc: String(rule?.desc || "").trim(),
            action: String(rule?.action || "deny").trim().toLowerCase(),
            priority: Number(rule?.priority || 100),
            iface: String(rule?.iface || "any").trim(),
            dir: normalizeRuleDirection(rule?.dir),
            proto: String(rule?.proto || "any").trim().toUpperCase() === "ANY"
                ? "any"
                : String(rule?.proto || "any").trim().toUpperCase(),
            src: String(rule?.src || "any").trim() || "any",
            dst: String(rule?.dst || "any").trim() || "any",
            port: String(rule?.port || "any").trim() || "any",
            enabled: Boolean(rule?.enabled),
            log: Boolean(rule?.log),
        });
    }

    function findEquivalentRule(payload) {
        const wanted = normalizedRuleSignature(payload);
        return state.rules.find((rule) =>
            !rule?.deletado && normalizedRuleSignature(rule) === wanted
        ) || null;
    }

    async function saveRule() {
        const payload = collectRule();
        const validation = validateRule(payload);
        if (validation) {
            showFormError("fwrRuleFormError", validation);
            return;
        }

        const button = $("fwrRuleSaveBtn");
        setButtonLoading(button, true, "Salvando");
        hideFormError("fwrRuleFormError");

        try {
            if (isSimulation()) {
                if (state.editingRuleId) {
                    const index = state.rules.findIndex((rule) => Number(rule.id) === Number(state.editingRuleId));
                    if (index >= 0) {
                        state.rules[index] = {
                            ...state.rules[index],
                            ...payload,
                            pendente: false,
                            sincronizada: true,
                            ultimo_erro: "",
                        };
                    }
                } else {
                    state.rules.push({
                        id: nextSimId(state.rules),
                        ...payload,
                        pendente: false,
                        sincronizada: true,
                        deletado: false,
                        ultimo_erro: "",
                        criado_em: new Date().toISOString(),
                        atualizado_em: new Date().toISOString(),
                    });
                }

                closeRuleDrawer();
                renderRules();
                updateCounts();
                renderSync({});
                toast("Regra atualizada na simulação.");
                return;
            }

            /*
             * Evita duplicatas durante uma falha de apply. Se já existir no
             * estado do painel uma regra idêntica, reutilizamos a regra
             * existente via PATCH em vez de criar outro registro com POST.
             */
            const equivalent = !state.editingRuleId
                ? findEquivalentRule(payload)
                : null;

            const targetId = state.editingRuleId || equivalent?.id || null;

            const data = targetId
                ? await api(detailUrl(URLS.rules, targetId), {
                    method: "PATCH",
                    body: JSON.stringify(payload),
                })
                : await api(URLS.rules, {
                    method: "POST",
                    body: JSON.stringify(payload),
                });

            /*
             * Se foi um POST e o Agent recusou, a regra já existe no Django.
             * Guardamos o id imediatamente para todo novo clique em Salvar
             * editar a mesma regra, nunca criar outra.
             */
            const persistedId = Number(data?.rule?.id || targetId || 0);
            if (persistedId > 0) {
                state.editingRuleId = persistedId;
            }

            const applied = Boolean(data.aplicado ?? data.sync_result?.ok ?? false);
            const syncError =
                data?.sync_result?.erro?.mensagem ||
                data?.sync_result?.erro ||
                data?.sync_result?.mensagem ||
                "";

            await reloadRules();

            if (!applied) {
                const detail = syncError
                    ? `: ${syncError}`
                    : ".";

                showFormError(
                    "fwrRuleFormError",
                    `A regra foi salva como pendente, mas ainda não foi aplicada pelo Agent${detail}`
                );
                toast("Regra pendente; corrija o erro antes de tentar novamente.", "err");
                return;
            }

            toast(
                data?.reutilizada
                    ? "Regra existente reutilizada e aplicada."
                    : "Regra salva e aplicada.",
                "ok"
            );
            closeRuleDrawer();
        } catch (error) {
            showFormError("fwrRuleFormError", error.message);
        } finally {
            setButtonLoading(button, false);
            button.innerHTML = '<i class="bi bi-floppy"></i> Salvar regra';
        }
    }

    async function updateRule(id, patch, notify = true) {
        if (isSimulation()) {
            const index = state.rules.findIndex((rule) => Number(rule.id) === Number(id));
            if (index >= 0) {
                state.rules[index] = {
                    ...state.rules[index],
                    ...patch,
                    pendente: false,
                    sincronizada: true,
                    atualizado_em: new Date().toISOString(),
                };
            }
            renderRules();
            updateCounts();
            if (notify) toast("Regra atualizada na simulação.");
            return { ok: true, aplicado: false, simulado: true };
        }

        const data = await api(detailUrl(URLS.rules, id), {
            method: "PATCH",
            body: JSON.stringify(patch),
        });
        await reloadRules();
        if (notify) toast(data.aplicado ? "Regra atualizada e aplicada." : "Regra atualizada; aplicação pendente.", data.aplicado ? "ok" : "warn");
        return data;
    }

    async function duplicateRule(id) {
        const source = state.rules.find((r) => Number(r.id) === Number(id));
        if (!source) return;

        const payload = {
            desc: `${source.desc || "Regra"} (cópia)`,
            action: source.action,
            iface: source.iface,
            dir: source.dir,
            proto: source.proto,
            src: source.src,
            dst: source.dst,
            port: source.port,
            priority: Number(source.priority || 100) + 1,
            enabled: source.enabled,
            log: source.log,
        };

        try {
            if (isSimulation()) {
                state.rules.push({
                    id: nextSimId(state.rules),
                    ...payload,
                    pendente: false,
                    sincronizada: true,
                    deletado: false,
                    ultimo_erro: "",
                    criado_em: new Date().toISOString(),
                    atualizado_em: new Date().toISOString(),
                });
                renderRules();
                updateCounts();
                toast("Regra duplicada na simulação.");
                return;
            }

            const data = await api(URLS.rules, { method: "POST", body: JSON.stringify(payload) });
            toast(data.aplicado ? "Regra duplicada e aplicada." : "Regra duplicada; aplicação pendente.", data.aplicado ? "ok" : "warn");
            await reloadRules();
        } catch (error) {
            toast(error.message, "err");
        }
    }

    async function deleteRule(id) {
        const rule = state.rules.find((r) => Number(r.id) === Number(id));
        const confirmed = await confirmModal({
            title: "Remover regra",
            text: `Remover ${rule?.desc ? `“${rule.desc}”` : `a regra #${id}`}? O Agent receberá o novo conjunto de regras.`,
            danger: true,
            confirmText: "Remover",
        });
        if (!confirmed) return;

        try {
            if (isSimulation()) {
                state.rules = state.rules.filter((item) => Number(item.id) !== Number(id));
                renderRules();
                updateCounts();
                renderSync({});
                toast("Regra removida da simulação.");
                return;
            }

            const data = await api(detailUrl(URLS.rules, id), { method: "DELETE" });
            toast(data.aplicado ? "Regra removida do runtime." : "Remoção registrada; aplicação pendente.", data.aplicado ? "ok" : "warn");
            await reloadRules();
        } catch (error) {
            toast(error.message, "err");
        }
    }

    function updateRulePreview() {
        const rule = collectRule();
        const pieces = [];
        const physical = logicalPhysical(rule.iface);
        const iface = physical || rule.iface;

        if (rule.iface !== "any") {
            if (rule.dir === "out") {
                pieces.push(`oifname "${iface}"`);
            } else if (rule.dir === "both") {
                pieces.push(`(iifname "${iface}" OU oifname "${iface}")`);
            } else {
                // IN e FORWARD usam a interface de entrada no core atual.
                pieces.push(`iifname "${iface}"`);
            }
        }
        if (rule.src !== "any") pieces.push(`ip saddr ${rule.src}`);
        if (rule.dst !== "any") pieces.push(`ip daddr ${rule.dst}`);
        if (rule.proto !== "any") pieces.push(rule.proto.toLowerCase());
        if (["TCP", "UDP"].includes(rule.proto) && rule.port !== "any") pieces.push(`dport ${rule.port}`);
        pieces.push(rule.action === "allow" ? "accept" : "drop");

        setText("fwrNftPreviewCode", pieces.join(" ") || "—");
        const badge = $("fwrRuleSummaryAction");
        badge.textContent = rule.action.toUpperCase();
        badge.className = `fwr-action-badge fwr-action-badge--${rule.action}`;
    }

    function updateProtocolPortState() {
        const proto = $("rfProto")?.value;
        const disabled = !["TCP", "UDP"].includes(proto);
        $("rfPort").disabled = disabled;
        if (disabled) $("rfPort").value = "any";
        setText("rfPortHint", disabled ? "Este protocolo não usa porta TCP/UDP." : "Usada como porta de destino.");
        updateRulePreview();
    }

    function updatePhysicalIfaceHint() {
        const role = $("rfIface")?.value || "any";
        const physical = role === "any" ? "Todas as interfaces" : (logicalPhysical(role) || "não mapeada");
        setText("rfIfacePhysical", role === "any" ? physical : `${role} → ${physical}`);
    }

    /* =====================================================================
       QUICK BLOCK / BLOCKLIST
       ===================================================================== */

    function updateQuickPreview() {
        const ip = ($("qbIp")?.value || "").trim();
        const box = $("qbPreview");
        if (!box) return;
        box.hidden = !ip;
        if (ip) setText("qbPreviewCode", `block ${ip} → ms_emergency`);
    }

    async function quickBlock() {
        const ip = ($("qbIp").value || "").trim();
        const reason = ($("qbReason").value || "").trim() || "Bloqueio manual";
        const expires = $("qbExpires").value || "∞";

        if (!validIpOrCidr(ip)) {
            toast("Informe um IP ou rede CIDR válida.", "err");
            $("qbIp").focus();
            return;
        }

        const button = $("qbSubmitBtn");
        setButtonLoading(button, true, "Bloqueando");

        try {
            if (isSimulation()) {
                state.blocklist.unshift({
                    id: nextSimId(state.blocklist),
                    ip,
                    reason,
                    source: "Simulação",
                    expires,
                    date: simulationDate(),
                    criado_em: new Date().toISOString(),
                });
                renderBlocklist();
                updateCounts();
                toast(`${ip} bloqueado na simulação.`);
                $("qbIp").value = "";
                $("qbReason").value = "";
                $("qbExpires").value = "∞";
                updateQuickPreview();
                return;
            }

            const data = await api(URLS.block, {
                method: "POST",
                body: JSON.stringify({ ip, motivo: reason, source: "Manual", expires }),
            });
            if (!data.ok) throw new Error(data.erro || "Bloqueio não confirmado.");
            toast(`${ip} bloqueado pelo Agent.`);
            $("qbIp").value = "";
            $("qbReason").value = "";
            $("qbExpires").value = "∞";
            updateQuickPreview();
            await reloadBlocklist();
        } catch (error) {
            toast(error.message, "err");
        } finally {
            setButtonLoading(button, false);
            button.innerHTML = '<i class="bi bi-ban"></i> Bloquear agora';
        }
    }

    function renderBlocklist() {
        const body = $("fwrBlockBody");
        if (!body) return;
        const q = ($("fwrSearchBlock")?.value || "").trim().toLowerCase();
        const rows = state.blocklist.filter((b) => !q || [b.ip, b.reason, b.source].some((v) => String(v || "").toLowerCase().includes(q)));

        if (!rows.length) {
            body.innerHTML = '<tr><td colspan="6"><div class="fwr-empty">Nenhum IP bloqueado.</div></td></tr>';
            return;
        }

        body.innerHTML = rows.map((b) => `
            <tr>
                <td class="fwr-cell-mono">${escapeHtml(b.ip || "—")}</td>
                <td class="fwr-cell-muted">${escapeHtml(b.reason || "—")}</td>
                <td>${sourceBadge(b.source)}</td>
                <td class="fwr-cell-mono">${escapeHtml(b.expires || "∞")}</td>
                <td class="fwr-cell-mono fwr-cell-muted">${escapeHtml(b.date || b.criado_em || "—")}</td>
                <td><div class="fwr-row-actions"><button class="fwr-icon-btn fwr-icon-btn--danger" type="button" data-unblock-id="${b.id}" data-unblock-ip="${escapeAttr(b.ip || "")}" title="Desbloquear"><i class="bi bi-unlock"></i></button></div></td>
            </tr>
        `).join("");

        body.querySelectorAll("[data-unblock-id]").forEach((button) => {
            button.addEventListener("click", () => unblockEntry(button.dataset.unblockId, button.dataset.unblockIp));
        });
    }

    async function addBlockWithModal() {
        const result = await promptModal({
            title: "Bloquear IP ou rede",
            icon: "bi-ban",
            fields: [
                { id: "ip", label: "IP / CIDR", placeholder: "1.2.3.4 ou 203.0.113.0/24" },
                { id: "reason", label: "Motivo", placeholder: "Bloqueio manual" },
            ],
            confirmText: "Bloquear",
            danger: true,
        });
        if (!result) return;
        const ip = String(result.ip || "").trim();
        if (!validIpOrCidr(ip)) return toast("IP ou rede inválida.", "err");

        try {
            if (isSimulation()) {
                state.blocklist.unshift({
                    id: nextSimId(state.blocklist),
                    ip,
                    reason: result.reason || "Bloqueio manual",
                    source: "Simulação",
                    expires: "∞",
                    date: simulationDate(),
                    criado_em: new Date().toISOString(),
                });
                renderBlocklist();
                updateCounts();
                toast(`${ip} bloqueado na simulação.`);
                return;
            }

            const data = await api(URLS.blocklist, {
                method: "POST",
                body: JSON.stringify({ ip, reason: result.reason || "Bloqueio manual", source: "Manual", expires: "∞" }),
            });
            if (!data.ok) throw new Error(data.erro || "Falha no bloqueio.");
            toast(`${ip} bloqueado.`);
            await reloadBlocklist();
        } catch (error) {
            toast(error.message, "err");
        }
    }

    async function unblockEntry(id, ip) {
        const confirmed = await confirmModal({ title: "Desbloquear IP", text: `Remover ${ip} da blocklist e solicitar desbloqueio ao Agent?`, confirmText: "Desbloquear" });
        if (!confirmed) return;
        try {
            if (isSimulation()) {
                state.blocklist = state.blocklist.filter((item) => String(item.id) !== String(id));
                renderBlocklist();
                updateCounts();
                toast(`${ip} removido da simulação.`);
                return;
            }

            const data = await api(detailUrl(URLS.blocklist, id), { method: "DELETE" });
            if (!data.ok) throw new Error(data.erro || "Desbloqueio não confirmado.");
            toast(`${ip} desbloqueado.`);
            await reloadBlocklist();
        } catch (error) {
            toast(error.message, "err");
        }
    }

    function sourceBadge(source) {
        const value = String(source || "Manual");
        const lower = value.toLowerCase();
        const klass = lower === "auto" ? "auto" : lower === "soc" ? "soc" : "manual";
        return `<span class="fwr-source-badge fwr-source-badge--${klass}">${escapeHtml(value)}</span>`;
    }

    /* =====================================================================
       ALLOWLIST — persistence only
       ===================================================================== */

    function renderAllowlist() {
        const body = $("fwrAllowBody");
        if (!body) return;
        const q = ($("fwrSearchAllow")?.value || "").trim().toLowerCase();
        const rows = state.allowlist.filter((a) => !q || [a.ip, a.reason].some((v) => String(v || "").toLowerCase().includes(q)));

        if (!rows.length) {
            body.innerHTML = '<tr><td colspan="5"><div class="fwr-empty">Nenhum cadastro na allowlist.</div></td></tr>';
            return;
        }

        body.innerHTML = rows.map((a) => `
            <tr>
                <td class="fwr-cell-mono">${escapeHtml(a.ip || "—")}</td>
                <td class="fwr-cell-muted">${escapeHtml(a.reason || "—")}</td>
                <td class="fwr-cell-mono fwr-cell-muted">${escapeHtml(a.date || a.criado_em || "—")}</td>
                <td><span class="fwr-runtime-badge fwr-runtime-badge--off">NÃO APLICADO</span></td>
                <td><div class="fwr-row-actions"><button class="fwr-icon-btn fwr-icon-btn--danger" type="button" data-allow-delete="${a.id}" title="Remover"><i class="bi bi-trash3"></i></button></div></td>
            </tr>
        `).join("");

        body.querySelectorAll("[data-allow-delete]").forEach((button) => {
            button.addEventListener("click", () => deleteAllow(Number(button.dataset.allowDelete)));
        });
    }

    async function addAllow() {
        const result = await promptModal({
            title: "Adicionar à allowlist",
            icon: "bi-check2-circle",
            fields: [
                { id: "ip", label: "IP / rede", placeholder: "10.10.0.10 ou 10.10.0.0/24" },
                { id: "reason", label: "Motivo", placeholder: "Servidor confiável" },
            ],
            confirmText: "Salvar cadastro",
        });
        if (!result) return;
        if (!String(result.ip || "").trim()) return toast("Informe um IP ou rede.", "err");

        try {
            if (isSimulation()) {
                state.allowlist.push({
                    id: nextSimId(state.allowlist),
                    ip: result.ip,
                    reason: result.reason || "Liberação simulada",
                    date: simulationDate(),
                    criado_em: new Date().toISOString(),
                });
                renderAllowlist(); updateCounts();
                toast("Cadastro adicionado à simulação.");
                return;
            }

            const data = await api(URLS.allowlist, { method: "POST", body: JSON.stringify({ ip: result.ip, reason: result.reason || "Liberação manual" }) });
            if (!data.ok) throw new Error(data.erro || "Falha ao salvar allowlist.");
            state.allowlist.push(data.entry);
            renderAllowlist(); updateCounts();
            toast("Cadastro salvo. Ainda não aplicado ao runtime.", "warn");
        } catch (error) { toast(error.message, "err"); }
    }

    async function deleteAllow(id) {
        if (!await confirmModal({ title: "Remover da allowlist", text: "Remover este cadastro?", danger: true, confirmText: "Remover" })) return;
        try {
            if (!isSimulation()) {
                await api(detailUrl(URLS.allowlist, id), { method: "DELETE" });
            }
            state.allowlist = state.allowlist.filter((a) => Number(a.id) !== id);
            renderAllowlist(); updateCounts();
            toast(isSimulation() ? "Cadastro removido da simulação." : "Cadastro removido.");
        } catch (error) { toast(error.message, "err"); }
    }

    /* =====================================================================
       GEOBLOCK — persistence only
       ===================================================================== */

    function renderGeoblock() {
        const body = $("fwrGeoBody");
        if (!body) return;
        const q = ($("fwrSearchGeo")?.value || "").trim().toLowerCase();
        const rows = state.geoblock.filter((g) => !q || [g.country, g.code].some((v) => String(v || "").toLowerCase().includes(q)));

        if (!rows.length) {
            body.innerHTML = '<tr><td colspan="6"><div class="fwr-empty">Nenhum país cadastrado.</div></td></tr>';
            return;
        }

        body.innerHTML = rows.map((g) => `
            <tr class="${g.enabled ? "" : "fwr-row-disabled"}">
                <td>${escapeHtml(g.country || "—")}</td>
                <td class="fwr-cell-mono">${escapeHtml(g.code || "—")}</td>
                <td class="fwr-cell-mono">${escapeHtml(g.dir || "IN")}</td>
                <td><label class="fwr-toggle"><input class="geo-toggle" type="checkbox" data-id="${g.id}" ${g.enabled ? "checked" : ""}><span></span></label></td>
                <td><span class="fwr-runtime-badge fwr-runtime-badge--off">NÃO APLICADO</span></td>
                <td><div class="fwr-row-actions"><button class="fwr-icon-btn fwr-icon-btn--danger" type="button" data-geo-delete="${g.id}" title="Remover"><i class="bi bi-trash3"></i></button></div></td>
            </tr>
        `).join("");

        body.querySelectorAll(".geo-toggle").forEach((toggle) => toggle.addEventListener("change", () => updateGeo(Number(toggle.dataset.id), toggle.checked, toggle)));
        body.querySelectorAll("[data-geo-delete]").forEach((button) => button.addEventListener("click", () => deleteGeo(Number(button.dataset.geoDelete))));
    }

    async function addGeo() {
        const select = $("geoCountrySelect");
        const code = select.value;
        if (!code) return toast("Selecione um país.", "err");
        const country = select.options[select.selectedIndex].text.replace(/\s*\([A-Z]{2}\)\s*$/, "");
        const dir = $("geoDirSelect").value;

        try {
            if (isSimulation()) {
                const exists = state.geoblock.some((item) => String(item.code).toUpperCase() === String(code).toUpperCase());
                if (!exists) {
                    state.geoblock.push({
                        id: nextSimId(state.geoblock),
                        code,
                        country,
                        dir,
                        enabled: true,
                        criado_em: new Date().toISOString(),
                    });
                }
                renderGeoblock(); updateCounts();
                $("fwrGeoAddPanel").hidden = true;
                toast(exists ? "Esse país já existe na simulação." : "GeoBlock adicionado à simulação.", exists ? "warn" : "ok");
                return;
            }

            const data = await api(URLS.geoblock, { method: "POST", body: JSON.stringify({ code, country, dir, enabled: true }) });
            if (!data.ok) throw new Error(data.erro || "Falha ao salvar GeoBlock.");
            if (data.created === false) toast("Esse país já estava cadastrado.", "warn");
            const refreshed = await api(URLS.geoblock);
            state.geoblock = refreshed.entries || [];
            renderGeoblock(); updateCounts();
            $("fwrGeoAddPanel").hidden = true;
            toast("GeoBlock salvo no Django; runtime ainda não aplicado.", "warn");
        } catch (error) { toast(error.message, "err"); }
    }

    async function updateGeo(id, enabled, toggle) {
        try {
            const idx = state.geoblock.findIndex((g) => Number(g.id) === id);

            if (isSimulation()) {
                if (idx >= 0) state.geoblock[idx] = { ...state.geoblock[idx], enabled };
                renderGeoblock();
                toast("GeoBlock atualizado na simulação.");
                return;
            }

            const data = await api(detailUrl(URLS.geoblock, id), { method: "PATCH", body: JSON.stringify({ enabled }) });
            if (idx >= 0 && data.entry) state.geoblock[idx] = data.entry;
            renderGeoblock();
            toast("Cadastro GeoBlock atualizado; runtime ainda não aplicado.", "warn");
        } catch (error) {
            toggle.checked = !enabled;
            toast(error.message, "err");
        }
    }

    async function deleteGeo(id) {
        if (!await confirmModal({ title: "Remover GeoBlock", text: "Remover este país do cadastro?", danger: true, confirmText: "Remover" })) return;
        try {
            if (!isSimulation()) {
                await api(detailUrl(URLS.geoblock, id), { method: "DELETE" });
            }
            state.geoblock = state.geoblock.filter((g) => Number(g.id) !== id);
            renderGeoblock(); updateCounts();
            toast(isSimulation() ? "GeoBlock removido da simulação." : "Cadastro removido.");
        } catch (error) { toast(error.message, "err"); }
    }

    /* =====================================================================
       NAT — persistence only
       ===================================================================== */

    function renderNat() {
        const body = $("fwrNatBody");
        if (!body) return;
        setText("natCount", state.nat.length);

        if (!state.nat.length) {
            body.innerHTML = '<tr><td colspan="8"><div class="fwr-empty">Nenhum port forward cadastrado.</div></td></tr>';
            return;
        }

        body.innerHTML = state.nat.map((n) => `
            <tr class="${n.enabled ? "" : "fwr-row-disabled"}">
                <td>${escapeHtml(n.name || "—")}</td>
                <td><span class="fwr-iface-badge">${escapeHtml(n.iface || "WAN")}</span></td>
                <td class="fwr-cell-mono">:${escapeHtml(n.wan_port || "—")}</td>
                <td class="fwr-cell-mono">${escapeHtml(n.lan_ip || "—")}:${escapeHtml(n.lan_port || "—")}</td>
                <td class="fwr-cell-mono">${escapeHtml(n.proto || "TCP")}</td>
                <td><label class="fwr-toggle"><input class="nat-toggle" type="checkbox" data-id="${n.id}" ${n.enabled ? "checked" : ""}><span></span></label></td>
                <td><span class="fwr-runtime-badge fwr-runtime-badge--off">NÃO APLICADO</span></td>
                <td><div class="fwr-row-actions"><button class="fwr-icon-btn" type="button" data-nat-edit="${n.id}" title="Editar"><i class="bi bi-pencil"></i></button><button class="fwr-icon-btn fwr-icon-btn--danger" type="button" data-nat-delete="${n.id}" title="Remover"><i class="bi bi-trash3"></i></button></div></td>
            </tr>
        `).join("");

        body.querySelectorAll(".nat-toggle").forEach((toggle) => toggle.addEventListener("change", () => patchNat(Number(toggle.dataset.id), { enabled: toggle.checked }, toggle)));
        body.querySelectorAll("[data-nat-edit]").forEach((button) => button.addEventListener("click", () => openNatDrawer(Number(button.dataset.natEdit))));
        body.querySelectorAll("[data-nat-delete]").forEach((button) => button.addEventListener("click", () => deleteNat(Number(button.dataset.natDelete))));
    }

    function openNatDrawer(id = null) {
        const entry = id ? state.nat.find((n) => Number(n.id) === id) : null;
        state.editingNatId = entry?.id || null;
        setText("fwrNatDrawerTitle", entry ? "Editar port forward" : "Novo port forward");
        $("natName").value = entry?.name || "";
        $("natIface").value = entry?.iface || "WAN";
        $("natProto").value = entry?.proto || "TCP";
        $("natWanPort").value = entry?.wan_port || "";
        $("natLanIp").value = entry?.lan_ip || "";
        $("natLanPort").value = entry?.lan_port || "";
        $("natEnabled").checked = entry ? Boolean(entry.enabled) : true;
        hideFormError("fwrNatFormError");
        setDrawer("fwrNatDrawer", "fwrNatDrawerOverlay", true);
    }

    function closeNatDrawer() { state.editingNatId = null; setDrawer("fwrNatDrawer", "fwrNatDrawerOverlay", false); }

    function collectNat() {
        return {
            name: ($("natName").value || "").trim() || "Port Forward",
            iface: $("natIface").value,
            proto: $("natProto").value,
            wan_port: ($("natWanPort").value || "").trim(),
            lan_ip: ($("natLanIp").value || "").trim(),
            lan_port: ($("natLanPort").value || "").trim(),
            enabled: $("natEnabled").checked,
        };
    }

    async function saveNat() {
        const payload = collectNat();
        if (!validSinglePort(payload.wan_port) || !validSinglePort(payload.lan_port)) return showFormError("fwrNatFormError", "As portas devem ficar entre 1 e 65535.");
        if (!validIpv4(payload.lan_ip)) return showFormError("fwrNatFormError", "Informe um IPv4 interno válido.");

        const button = $("fwrNatSaveBtn"); setButtonLoading(button, true, "Salvando");
        try {
            if (isSimulation()) {
                if (state.editingNatId) {
                    const index = state.nat.findIndex((item) => Number(item.id) === Number(state.editingNatId));
                    if (index >= 0) state.nat[index] = { ...state.nat[index], ...payload };
                } else {
                    state.nat.push({ id: nextSimId(state.nat), ...payload });
                }
                renderNat(); updateCounts(); closeNatDrawer();
                toast("Port forward atualizado na simulação.");
                return;
            }

            const data = state.editingNatId
                ? await api(detailUrl(URLS.nat, state.editingNatId), { method: "PATCH", body: JSON.stringify(payload) })
                : await api(URLS.nat, { method: "POST", body: JSON.stringify(payload) });
            if (!data.ok) throw new Error(data.erro || "Falha ao salvar NAT.");
            const refreshed = await api(URLS.nat); state.nat = refreshed.entries || [];
            renderNat(); updateCounts(); closeNatDrawer();
            toast("Port forward salvo no Django; runtime ainda não aplicado.", "warn");
        } catch (error) { showFormError("fwrNatFormError", error.message); }
        finally { setButtonLoading(button, false); button.innerHTML = '<i class="bi bi-floppy"></i> Salvar cadastro'; }
    }

    async function patchNat(id, patch, toggle) {
        try {
            const idx = state.nat.findIndex((n) => Number(n.id) === id);

            if (isSimulation()) {
                if (idx >= 0) state.nat[idx] = { ...state.nat[idx], ...patch };
                renderNat();
                toast("Cadastro NAT atualizado na simulação.");
                return;
            }

            const data = await api(detailUrl(URLS.nat, id), { method: "PATCH", body: JSON.stringify(patch) });
            if (idx >= 0 && data.nat) state.nat[idx] = data.nat;
            renderNat(); toast("Cadastro NAT atualizado; runtime ainda não aplicado.", "warn");
        } catch (error) { if (toggle) toggle.checked = !toggle.checked; toast(error.message, "err"); }
    }

    async function deleteNat(id) {
        if (!await confirmModal({ title: "Remover port forward", text: "Remover este cadastro NAT?", danger: true, confirmText: "Remover" })) return;
        try {
            if (!isSimulation()) {
                await api(detailUrl(URLS.nat, id), { method: "DELETE" });
            }
            state.nat = state.nat.filter((n) => Number(n.id) !== id);
            renderNat(); updateCounts();
            toast(isSimulation() ? "Cadastro NAT removido da simulação." : "Cadastro NAT removido.");
        } catch (error) { toast(error.message, "err"); }
    }

    /* =====================================================================
       TABS / EVENTS
       ===================================================================== */

    function bindStaticEvents() {
        document.querySelectorAll(".fwr-tab").forEach((button) => button.addEventListener("click", () => switchTab(button.dataset.tab)));

        $("fwrApplyBtn")?.addEventListener("click", applyPending);
        $("fwrSyncApplyBtn")?.addEventListener("click", applyPending);
        $("fwrExportNftBtn")?.addEventListener("click", () => {
            if (isSimulation()) return;
            if (URLS.exportNft) window.location.href = URLS.exportNft;
        });

        $("qbIp")?.addEventListener("input", updateQuickPreview);
        $("qbSubmitBtn")?.addEventListener("click", quickBlock);
        $("fwrAddBlockBtn")?.addEventListener("click", addBlockWithModal);

        $("fwrSearchRegras")?.addEventListener("input", renderRules);
        $("fwrFilterAction")?.addEventListener("change", renderRules);
        $("fwrFilterIface")?.addEventListener("change", renderRules);
        $("fwrSearchBlock")?.addEventListener("input", renderBlocklist);
        $("fwrSearchAllow")?.addEventListener("input", renderAllowlist);
        $("fwrSearchGeo")?.addEventListener("input", renderGeoblock);

        $("fwrNewRuleBtn")?.addEventListener("click", () => openRuleDrawer());
        $("fwrRuleSaveBtn")?.addEventListener("click", saveRule);
        $("fwrRuleDrawerCancel")?.addEventListener("click", closeRuleDrawer);
        $("fwrRuleDrawerClose")?.addEventListener("click", closeRuleDrawer);
        $("fwrRuleDrawerOverlay")?.addEventListener("click", closeRuleDrawer);
        $("fwrRuleDrawerDup")?.addEventListener("click", () => { const id = state.editingRuleId; if (id) { closeRuleDrawer(); duplicateRule(id); } });

        ["rfDesc", "rfAction", "rfPriority", "rfIface", "rfDir", "rfProto", "rfSrc", "rfDst", "rfPort", "rfEnabled", "rfLog"].forEach((id) => {
            $(id)?.addEventListener("input", updateRulePreview);
            $(id)?.addEventListener("change", updateRulePreview);
        });
        $("rfProto")?.addEventListener("change", updateProtocolPortState);
        $("rfIface")?.addEventListener("change", updatePhysicalIfaceHint);

        $("fwrAddAllowBtn")?.addEventListener("click", addAllow);
        $("fwrAddGeoBtn")?.addEventListener("click", () => { $("fwrGeoAddPanel").hidden = !$("fwrGeoAddPanel").hidden; });
        $("geoAddCancelBtn")?.addEventListener("click", () => { $("fwrGeoAddPanel").hidden = true; });
        $("geoAddConfirmBtn")?.addEventListener("click", addGeo);

        $("fwrNewNatBtn")?.addEventListener("click", () => openNatDrawer());
        $("fwrNatSaveBtn")?.addEventListener("click", saveNat);
        $("fwrNatDrawerCancel")?.addEventListener("click", closeNatDrawer);
        $("fwrNatDrawerClose")?.addEventListener("click", closeNatDrawer);
        $("fwrNatDrawerOverlay")?.addEventListener("click", closeNatDrawer);

        $("fwrModalOverlay")?.addEventListener("click", (event) => {
            if (event.target === $("fwrModalOverlay")) closeModal(null);
        });

        document.addEventListener("keydown", (event) => {
            if (event.key !== "Escape") return;
            if ($("fwrModalOverlay")?.classList.contains("open")) return closeModal(null);
            if ($("fwrRuleDrawer")?.classList.contains("open")) return closeRuleDrawer();
            if ($("fwrNatDrawer")?.classList.contains("open")) return closeNatDrawer();
        });
    }

    function switchTab(name) {
        document.querySelectorAll(".fwr-tab").forEach((button) => button.classList.toggle("fwr-tab--active", button.dataset.tab === name));
        document.querySelectorAll(".fwr-panel").forEach((panel) => panel.classList.remove("fwr-panel--active"));
        const map = { regras: "panelRegras", bloqueados: "panelBloqueados", liberados: "panelLiberados", geoblock: "panelGeoblock", nat: "panelNat" };
        $(map[name])?.classList.add("fwr-panel--active");
    }

    /* =====================================================================
       MODAL
       ===================================================================== */

    function confirmModal({ title, text, confirmText = "Confirmar", danger = false }) {
        return openModal({ title, text, fields: [], confirmText, danger });
    }

    function promptModal({ title, icon = "bi-pencil", fields = [], confirmText = "Confirmar", danger = false }) {
        return openModal({ title, text: "", icon, fields, confirmText, danger, collect: true });
    }

    function openModal({ title, text, icon = "bi-exclamation-triangle", fields = [], confirmText, danger, collect = false }) {
        setText("fwrModalTitle", title || "Confirmação");
        setText("fwrModalText", text || "");
        $("fwrModalIcon").innerHTML = `<i class="bi ${escapeAttr(icon)}"></i>`;

        const fieldsBox = $("fwrModalFields");
        fieldsBox.innerHTML = fields.map((field) => `
            <div class="fwr-modal-field">
                <label for="fwrModal_${escapeAttr(field.id)}">${escapeHtml(field.label)}</label>
                <input class="fwr-input" id="fwrModal_${escapeAttr(field.id)}" data-modal-field="${escapeAttr(field.id)}" type="text" placeholder="${escapeAttr(field.placeholder || "")}">
            </div>
        `).join("");

        const actions = $("fwrModalActions");
        actions.innerHTML = "";

        const cancel = document.createElement("button");
        cancel.type = "button"; cancel.className = "fwr-btn"; cancel.textContent = "Cancelar";
        cancel.addEventListener("click", () => closeModal(null));

        const confirm = document.createElement("button");
        confirm.type = "button"; confirm.className = `fwr-btn ${danger ? "fwr-btn--danger" : "fwr-btn--primary"}`; confirm.textContent = confirmText || "Confirmar";
        confirm.addEventListener("click", () => {
            if (!collect) return closeModal(true);
            const values = {};
            fieldsBox.querySelectorAll("[data-modal-field]").forEach((input) => { values[input.dataset.modalField] = input.value.trim(); });
            closeModal(values);
        });

        actions.append(cancel, confirm);
        $("fwrModalOverlay").classList.add("open");
        $("fwrModalOverlay").setAttribute("aria-hidden", "false");
        window.setTimeout(() => fieldsBox.querySelector("input")?.focus(), 60);

        return new Promise((resolve) => { state.modalResolve = resolve; });
    }

    function closeModal(value) {
        const overlay = $("fwrModalOverlay");
        const active = document.activeElement;
        if (overlay && active instanceof HTMLElement && overlay.contains(active)) {
            active.blur();
        }
        overlay?.classList.remove("open");
        overlay?.setAttribute("aria-hidden", "true");
        if (state.modalResolve) {
            const resolve = state.modalResolve;
            state.modalResolve = null;
            resolve(value);
        }
    }

    /* =====================================================================
       VALIDATION / HELPERS
       ===================================================================== */

    function validAddressOrAny(value) {
        const text = String(value || "").trim();
        if (text.toLowerCase() === "any") return true;
        if (!text) return false;
        return text.split(",").map((item) => item.trim()).filter(Boolean).every(validIpOrCidr);
    }

    function validIpOrCidr(value) {
        const text = String(value || "").trim();
        const [ip, prefix] = text.split("/");
        if (!validIpv4(ip)) return false;
        if (prefix === undefined) return true;
        if (!/^\d{1,2}$/.test(prefix)) return false;
        const p = Number(prefix); return p >= 0 && p <= 32;
    }

    function validIpv4(value) {
        const parts = String(value || "").trim().split(".");
        if (parts.length !== 4) return false;
        return parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
    }

    function validPort(value) {
        const text = String(value || "").trim().toLowerCase();
        if (text === "any") return true;
        if (/^\d{1,5}$/.test(text)) return validSinglePort(text);
        const match = text.match(/^(\d{1,5})-(\d{1,5})$/);
        if (!match) return false;
        const start = Number(match[1]), end = Number(match[2]);
        return start >= 1 && end <= 65535 && start <= end;
    }

    function validSinglePort(value) {
        if (!/^\d{1,5}$/.test(String(value || ""))) return false;
        const n = Number(value); return n >= 1 && n <= 65535;
    }

    function setDrawer(drawerId, overlayId, open) {
        $(drawerId)?.classList.toggle("open", open);
        $(overlayId)?.classList.toggle("open", open);
        $(drawerId)?.setAttribute("aria-hidden", open ? "false" : "true");
        document.body.style.overflow = open ? "hidden" : "";
    }

    function setButtonLoading(button, loading, label = "Processando") {
        if (!button) return;
        button.disabled = loading;
        button.classList.toggle("is-loading", loading);
        if (loading) button.innerHTML = `<i class="bi bi-arrow-repeat"></i> ${escapeHtml(label)}`;
    }

    function showFormError(id, message) { const el = $(id); if (!el) return; el.hidden = false; el.textContent = message; }
    function hideFormError(id) { const el = $(id); if (!el) return; el.hidden = true; el.textContent = ""; }

    function toast(message, type = "ok") {
        const el = $("fwrToast"); if (!el) return;
        el.textContent = message;
        el.className = `fwr-toast fwr-toast--${type} show`;
        window.clearTimeout(toastTimer);
        toastTimer = window.setTimeout(() => el.classList.remove("show"), 3200);
    }

    function openFromQueryString() {
        const params = new URLSearchParams(window.location.search);
        if (!params.has("nova_regra")) return;
        window.setTimeout(() => {
            openRuleDrawer();
            if (params.get("src")) $("rfSrc").value = params.get("src");
            if (params.get("dst")) $("rfDst").value = params.get("dst");
            if (params.get("port")) $("rfPort").value = params.get("port");
            if (params.get("proto")) $("rfProto").value = String(params.get("proto")).toUpperCase();
            if (params.get("iface")) $("rfIface").value = String(params.get("iface")).toUpperCase();
            updateRulePreview(); updateProtocolPortState(); updatePhysicalIfaceHint();
            window.history.replaceState({}, "", window.location.pathname);
        }, 300);
    }

    function extractValidationError(details) {
        if (!details || typeof details !== "object") return "";
        const first = Object.values(details)[0];
        if (Array.isArray(first)) return first.join(" ");
        return first ? String(first) : "";
    }

    function setText(id, value) { const el = $(id); if (el) el.textContent = String(value ?? ""); }
    function truncate(value, max) { const text = String(value || ""); return text.length > max ? `${text.slice(0, max)}…` : text; }
    function escapeHtml(value) { return String(value ?? "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/\"/g,"&quot;").replace(/'/g,"&#039;"); }
    function escapeAttr(value) { return escapeHtml(value); }
});
