(() => {
    "use strict";

    const APP = window.MS_FIREWALL_INSTALL || {};
    const URLS = APP.urls || {};
    const INITIAL_PRECHECK = APP.precheck || {};

    const state = {
        step: 1,
        maxStep: 1,
        status: {},
        interfaces: [],
        mapping: {},
        installing: false,
        diagnostic: null,
    };

    const $ = (selector, root = document) => root.querySelector(selector);
    const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

    const els = {};

    document.addEventListener("DOMContentLoaded", init);

    function init() {
        cacheDom();
        initTheme();
        bindEvents();
        setOperator();
        hydrateFromPrecheck(INITIAL_PRECHECK);
        refreshEnvironment({ silent: true });
    }

    function cacheDom() {
        els.themeToggle = $("#themeToggle");
        els.operatorName = $("#operatorName");

        els.navSteps = $$("[data-step-nav]");
        els.panels = $$("[data-step-panel]");
        els.goStepButtons = $$("[data-go-step]");

        els.sidebarAgentDot = $("#sidebarAgentDot");
        els.sidebarAgentText = $("#sidebarAgentText");
        els.topStatusDot = $("#topStatusDot");
        els.topStatusText = $("#topStatusText");

        els.btnStartCheck = $("#btnStartCheck");
        els.btnRefreshEnvironment = $("#btnRefreshEnvironment");
        els.btnEnvironmentNext = $("#btnEnvironmentNext");
        els.btnDiagnostic = $("#btnDiagnostic");
        els.btnOpenPanelEnvironment = $("#btnOpenPanelEnvironment");

        els.environmentSummaryIcon = $("#environmentSummaryIcon");
        els.environmentSummaryTitle = $("#environmentSummaryTitle");
        els.environmentSummaryText = $("#environmentSummaryText");

        els.badgeAgent = $("#badgeAgent");
        els.textAgent = $("#textAgent");
        els.valueAgent = $("#valueAgent");

        els.badgeNft = $("#badgeNft");
        els.textNft = $("#textNft");
        els.valueNft = $("#valueNft");

        els.badgeFirewall = $("#badgeFirewall");
        els.textFirewall = $("#textFirewall");
        els.valueFirewall = $("#valueFirewall");

        els.agentRequiredNotice = $("#agentRequiredNotice");
        els.alreadyInstalledNotice = $("#alreadyInstalledNotice");

        els.selectWan = $("#selectWan");
        els.selectMgmt = $("#selectMgmt");
        els.selectLan = $("#selectLan");
        els.inputHomeNet = $("#inputHomeNet");
        els.interfaceCount = $("#interfaceCount");
        els.interfacesList = $("#interfacesList");
        els.btnRefreshInterfaces = $("#btnRefreshInterfaces");
        els.btnNetworkNext = $("#btnNetworkNext");
        els.networkValidationNotice = $("#networkValidationNotice");
        els.networkValidationText = $("#networkValidationText");

        els.reviewWan = $("#reviewWan");
        els.reviewMgmt = $("#reviewMgmt");
        els.reviewLan = $("#reviewLan");
        els.reviewHomeNet = $("#reviewHomeNet");

        els.confirmInstall = $("#confirmInstall");
        els.btnInstall = $("#btnInstall");

        els.reviewState = $("#reviewState");
        els.installRunning = $("#installRunning");
        els.installLog = $("#installLog");
        els.successState = $("#successState");
        els.successMessage = $("#successMessage");
        els.resultNftVersion = $("#resultNftVersion");
        els.errorState = $("#errorState");
        els.errorMessage = $("#errorMessage");
        els.errorDetails = $("#errorDetails");

        els.btnBackAfterError = $("#btnBackAfterError");
        els.btnRepair = $("#btnRepair");

        els.installPageTitle = $("#installPageTitle");
        els.installPageIntro = $("#installPageIntro");

        els.toastContainer = $("#toastContainer");
    }

    function bindEvents() {
        els.btnStartCheck?.addEventListener("click", async () => {
            goToStep(2);
            await refreshEnvironment();
        });

        els.goStepButtons.forEach((button) => {
            button.addEventListener("click", () => {
                const target = Number(button.dataset.goStep || 1);
                goToStep(target);
            });
        });

        els.navSteps.forEach((button) => {
            button.addEventListener("click", () => {
                const target = Number(button.dataset.stepNav || 1);
                if (target <= state.maxStep) {
                    goToStep(target);
                }
            });
        });

        els.btnRefreshEnvironment?.addEventListener("click", () => refreshEnvironment());
        els.btnDiagnostic?.addEventListener("click", runDiagnostic);

        els.btnEnvironmentNext?.addEventListener("click", async () => {
            if (!state.status.agent_disponivel && !state.status.agent_ativo) {
                toast("Agent indisponível", "O MoonShield-Agent precisa estar online para continuar.", "error");
                return;
            }

            goToStep(3);

            if (!state.interfaces.length) {
                await refreshInterfaces();
            }
        });

        els.btnRefreshInterfaces?.addEventListener("click", () => refreshInterfaces());

        [els.selectWan, els.selectMgmt, els.selectLan, els.inputHomeNet].forEach((input) => {
            input?.addEventListener("change", () => {
                hideNetworkError();
                updateReview();
            });

            input?.addEventListener("input", () => {
                hideNetworkError();
                updateReview();
            });
        });

        els.btnNetworkNext?.addEventListener("click", () => {
            const validation = validateNetwork();

            if (!validation.ok) {
                showNetworkError(validation.message);
                return;
            }

            updateReview();
            goToStep(4);
        });

        els.confirmInstall?.addEventListener("change", () => {
            if (els.btnInstall) {
                els.btnInstall.disabled = !els.confirmInstall.checked || state.installing;
            }
        });

        els.btnInstall?.addEventListener("click", installFirewall);

        els.btnBackAfterError?.addEventListener("click", () => {
            resetInstallStates();
            goToStep(3);
        });

        els.btnRepair?.addEventListener("click", repairFirewall);
    }

    /* ----------------------------------------------------------------------
       Theme
       ---------------------------------------------------------------------- */

    function initTheme() {
        const current = document.documentElement.getAttribute("data-theme") || "dark";

        if (els.themeToggle) {
            els.themeToggle.checked = current === "light";
        }

        els.themeToggle?.addEventListener("change", () => {
            const theme = els.themeToggle.checked ? "light" : "dark";
            document.documentElement.setAttribute("data-theme", theme);
            localStorage.setItem("moonshield_theme", theme);
        });
    }

    /* ----------------------------------------------------------------------
       Initial data
       ---------------------------------------------------------------------- */

    function setOperator() {
        const name = APP.usuario?.nome || APP.usuario?.username || "operador";

        if (els.operatorName) {
            els.operatorName.textContent = name;
        }
    }

    function hydrateFromPrecheck(precheck) {
        if (!precheck || typeof precheck !== "object") {
            return;
        }

        if (precheck.estado && typeof precheck.estado === "object") {
            state.status = precheck.estado;
            renderEnvironment(precheck.estado);
            hydrateNetworkFromStatus(precheck.estado);
        }

        const interfaces = normalizeInterfaceResponse(precheck);
        if (interfaces.length) {
            state.interfaces = interfaces;
            state.mapping = normalizeMapping(precheck.mapeamento || {});
            renderInterfaces();
            populateInterfaceSelects();
        }
    }

    /* ----------------------------------------------------------------------
       Step navigation
       ---------------------------------------------------------------------- */

    function goToStep(step) {
        if (!Number.isFinite(step) || step < 1 || step > 4) {
            return;
        }

        state.step = step;
        state.maxStep = Math.max(state.maxStep, step);

        els.panels.forEach((panel) => {
            panel.classList.toggle(
                "active",
                Number(panel.dataset.stepPanel) === step
            );
        });

        els.navSteps.forEach((nav) => {
            const navStep = Number(nav.dataset.stepNav);

            nav.classList.toggle("active", navStep === step);
            nav.classList.toggle("complete", navStep < step);

            if (navStep <= state.maxStep) {
                nav.disabled = false;
            }
        });

        window.scrollTo({
            top: 0,
            behavior: "smooth",
        });
    }

    /* ----------------------------------------------------------------------
       API
       ---------------------------------------------------------------------- */

    async function api(url, options = {}) {
        if (!url) {
            throw new Error("Endpoint não configurado.");
        }

        const method = String(options.method || "GET").toUpperCase();
        const headers = new Headers(options.headers || {});

        headers.set("Accept", "application/json");

        if (method !== "GET" && method !== "HEAD") {
            headers.set("Content-Type", "application/json");
            headers.set("X-CSRFToken", APP.csrfToken || getCookie("csrftoken") || "");
        }

        let response;

        try {
            response = await fetch(url, {
                credentials: "same-origin",
                ...options,
                method,
                headers,
            });
        } catch (error) {
            const networkError = new Error("Não foi possível conectar ao backend do MoonShield.");
            networkError.code = "network_error";
            networkError.original = error;
            throw networkError;
        }

        const contentType = response.headers.get("content-type") || "";
        let data = {};

        if (contentType.includes("application/json")) {
            try {
                data = await response.json();
            } catch (_) {
                data = {};
            }
        } else {
            const text = await response.text();
            data = {
                ok: false,
                erro: text || `HTTP ${response.status}`,
            };
        }

        if (!response.ok) {
            const error = new Error(
                data.erro ||
                data.error ||
                data.mensagem ||
                `HTTP ${response.status}`
            );

            error.status = response.status;
            error.data = data;
            throw error;
        }

        return data;
    }

    function getCookie(name) {
        const prefix = `${name}=`;
        const item = document.cookie
            .split(";")
            .map((part) => part.trim())
            .find((part) => part.startsWith(prefix));

        return item ? decodeURIComponent(item.slice(prefix.length)) : "";
    }

    /* ----------------------------------------------------------------------
       Environment
       ---------------------------------------------------------------------- */

    async function refreshEnvironment({ silent = false } = {}) {
        setEnvironmentLoading(true);

        if (!silent) {
            toast("Verificação iniciada", "Consultando Agent e nftables.", "info", 2200);
        }

        try {
            const [statusResult, interfaceResult] = await Promise.allSettled([
                api(URLS.status),
                api(URLS.interfaces),
            ]);

            let status = {};

            if (statusResult.status === "fulfilled") {
                status = statusResult.value || {};
            } else {
                status = statusResult.reason?.data || {
                    ok: false,
                    agent_disponivel: false,
                    agent_ativo: false,
                    status: "agent_indisponivel",
                    status_label: "Agent indisponível",
                    erro: {
                        mensagem: statusResult.reason?.message || "Falha ao consultar o Agent.",
                    },
                };
            }

            state.status = status;
            renderEnvironment(status);
            hydrateNetworkFromStatus(status);

            if (interfaceResult.status === "fulfilled") {
                const rawInterfaces = interfaceResult.value || {};
                state.interfaces = normalizeInterfaceResponse(rawInterfaces);
                state.mapping = normalizeMapping(rawInterfaces.mapeamento || rawInterfaces.mapping || {});
                populateInterfaceSelects();
                renderInterfaces();
            }

            if (status.agent_disponivel || status.agent_ativo) {
                state.maxStep = Math.max(state.maxStep, 3);
                enableStep(3);
            }

            if (status.operacional) {
                state.maxStep = 4;
                enableStep(4);
            }
        } finally {
            setEnvironmentLoading(false);
        }
    }

    function renderEnvironment(status) {
        const agentOk = Boolean(status.agent_disponivel || status.agent_ativo);
        const nftOk = Boolean(status.nftables_instalado);
        const installed = Boolean(status.instalado || status.tabela_instalada || status.ativo);
        const operational = Boolean(status.operacional);

        setDot(els.sidebarAgentDot, agentOk ? "success" : "error");
        setDot(els.topStatusDot, operational ? "success" : agentOk ? "loading" : "error");

        if (els.sidebarAgentText) {
            els.sidebarAgentText.textContent = agentOk ? "Online · socket local" : "Indisponível";
        }

        if (els.topStatusText) {
            els.topStatusText.textContent = operational
                ? "Firewall operacional"
                : agentOk
                    ? (status.status_label || "Agent conectado")
                    : "Agent indisponível";
        }

        setBadge(
            els.badgeAgent,
            agentOk ? "ONLINE" : "OFFLINE",
            agentOk ? "success" : "error"
        );

        if (els.textAgent) {
            els.textAgent.textContent = agentOk
                ? "Comunicação IPC local disponível."
                : getErrorMessage(status) || "O Django não conseguiu acessar o Agent.";
        }

        const socketPath =
            status.ipc?.socket ||
            status.ipc?.caminho ||
            "/run/moonshield/agent.sock";

        if (els.valueAgent) {
            els.valueAgent.textContent = socketPath;
        }

        setBadge(
            els.badgeNft,
            nftOk ? "INSTALADO" : agentOk ? "SERÁ PREPARADO" : "AGUARDANDO",
            nftOk ? "success" : agentOk ? "warning" : "error"
        );

        if (els.textNft) {
            els.textNft.textContent = nftOk
                ? "nftables disponível no host Linux."
                : agentOk
                    ? "O pacote poderá ser preparado pelo Agent durante a instalação."
                    : "A verificação depende do Agent.";
        }

        if (els.valueNft) {
            els.valueNft.textContent = status.nftables_versao || (nftOk ? "disponível" : "não confirmado");
        }

        setBadge(
            els.badgeFirewall,
            operational ? "OPERACIONAL" : installed ? "INSTALADO" : "NÃO INSTALADO",
            operational ? "success" : installed ? "warning" : agentOk ? "warning" : "error"
        );

        if (els.textFirewall) {
            els.textFirewall.textContent = operational
                ? "Tabela e chains MoonShield estão operacionais."
                : installed
                    ? "Estrutura encontrada, mas ainda não está totalmente operacional."
                    : "Nenhuma instalação ativa foi confirmada.";
        }

        if (els.valueFirewall) {
            els.valueFirewall.textContent = "inet moonshield";
        }

        if (els.environmentSummaryIcon) {
            els.environmentSummaryIcon.classList.remove("is-loading", "is-success", "is-error");
            els.environmentSummaryIcon.classList.add(agentOk ? "is-success" : "is-error");
            els.environmentSummaryIcon.innerHTML = agentOk
                ? '<span style="color:var(--green);font-family:var(--mono);font-weight:700;">✓</span>'
                : '<span style="color:var(--red);font-family:var(--mono);font-weight:700;">!</span>';
        }

        if (els.environmentSummaryTitle) {
            els.environmentSummaryTitle.textContent = agentOk
                ? operational
                    ? "Ambiente pronto e Firewall ativo."
                    : "Ambiente pronto para configuração."
                : "O Agent precisa de atenção.";
        }

        if (els.environmentSummaryText) {
            els.environmentSummaryText.textContent = agentOk
                ? operational
                    ? "A instalação atual está operacional. Você pode revisar a topologia ou abrir o painel."
                    : "O Django consegue delegar operações privilegiadas ao MoonShield-Agent."
                : getErrorMessage(status) || "Verifique o serviço e as permissões do socket local.";
        }

        if (els.agentRequiredNotice) {
            els.agentRequiredNotice.hidden = agentOk;
        }

        if (els.alreadyInstalledNotice) {
            els.alreadyInstalledNotice.hidden = !operational;
        }

        if (els.btnOpenPanelEnvironment) {
            els.btnOpenPanelEnvironment.hidden = !operational;
        }

        if (els.btnEnvironmentNext) {
            els.btnEnvironmentNext.disabled = !agentOk;
        }
    }

    function setEnvironmentLoading(loading) {
        if (els.btnRefreshEnvironment) {
            els.btnRefreshEnvironment.classList.toggle("is-spinning", loading);
            els.btnRefreshEnvironment.disabled = loading;
        }

        if (!loading) {
            return;
        }

        if (els.environmentSummaryIcon) {
            els.environmentSummaryIcon.className = "environment-summary__icon is-loading";
            els.environmentSummaryIcon.innerHTML = '<span class="spinner"></span>';
        }

        if (els.environmentSummaryTitle) {
            els.environmentSummaryTitle.textContent = "Verificando...";
        }

        if (els.environmentSummaryText) {
            els.environmentSummaryText.textContent = "Consultando o MoonShield-Agent e o nftables.";
        }
    }

    async function runDiagnostic() {
        if (!els.btnDiagnostic) return;

        const original = els.btnDiagnostic.textContent;
        els.btnDiagnostic.disabled = true;
        els.btnDiagnostic.textContent = "Executando...";

        try {
            const result = await api(URLS.diagnostico);
            state.diagnostic = result;

            const failed =
                Number(result.total_falhas || 0) > 0 ||
                Number(result.total_criticos || 0) > 0 ||
                result.pronto === false;

            if (failed) {
                toast(
                    "Diagnóstico concluído",
                    `${result.total_falhas || result.total_criticos || 1} verificação(ões) requerem atenção.`,
                    "warning"
                );
            } else {
                toast(
                    "Diagnóstico concluído",
                    "O Agent não reportou falhas críticas.",
                    "success"
                );
            }
        } catch (error) {
            toast("Falha no diagnóstico", error.message, "error");
        } finally {
            els.btnDiagnostic.disabled = false;
            els.btnDiagnostic.textContent = original;
        }
    }

    /* ----------------------------------------------------------------------
       Interfaces
       ---------------------------------------------------------------------- */

    async function refreshInterfaces() {
        setInterfacesLoading();

        try {
            const result = await api(URLS.interfaces);

            state.interfaces = normalizeInterfaceResponse(result);
            state.mapping = normalizeMapping(result.mapeamento || result.mapping || {});

            populateInterfaceSelects();
            renderInterfaces();
            hydrateNetworkFromStatus(state.status);

            toast(
                "Interfaces atualizadas",
                `${state.interfaces.length} interface(s) retornada(s) pelo Agent.`,
                "success",
                2200
            );
        } catch (error) {
            state.interfaces = [];
            renderInterfaces();

            toast(
                "Falha ao detectar interfaces",
                error.message,
                "error"
            );
        }
    }

    function normalizeInterfaceResponse(raw) {
        if (!raw || typeof raw !== "object") {
            return [];
        }

        let list =
            raw.interfaces ||
            raw.itens ||
            raw.dados?.interfaces ||
            [];

        if (!Array.isArray(list)) {
            return [];
        }

        return list
            .map((item) => {
                if (typeof item === "string") {
                    return {
                        nome: item,
                        ip: "",
                        cidr: "",
                        mac: "",
                        up: true,
                        papeis: [],
                    };
                }

                if (!item || typeof item !== "object") {
                    return null;
                }

                const nome =
                    item.nome ||
                    item.name ||
                    item.interface ||
                    item.iface ||
                    "";

                if (!nome || nome === "lo") {
                    return null;
                }

                let roles = item.papeis || item.roles || item.papel || [];
                if (!Array.isArray(roles)) {
                    roles = roles ? [roles] : [];
                }

                return {
                    ...item,
                    nome: String(nome),
                    ip: String(item.ip || item.ipv4 || item.endereco || ""),
                    cidr: String(item.cidr || item.rede || item.network || ""),
                    mac: String(item.mac || item.mac_address || ""),
                    up: item.up !== false && item.ativo !== false && item.state !== "down",
                    papeis: roles.map((role) => String(role).toUpperCase()),
                };
            })
            .filter(Boolean);
    }

    function normalizeMapping(raw) {
        if (!raw || typeof raw !== "object") {
            return {};
        }

        return {
            WAN: raw.WAN || raw.wan || raw.interface_wan || "",
            MGMT: raw.MGMT || raw.mgmt || raw.interface_mgmt || "",
            LAN: raw.LAN || raw.lan || raw.interface_lan || "",
        };
    }

    function populateInterfaceSelects() {
        const selects = [
            els.selectWan,
            els.selectMgmt,
            els.selectLan,
        ].filter(Boolean);

        const current = {
            WAN: els.selectWan?.value || "",
            MGMT: els.selectMgmt?.value || "",
            LAN: els.selectLan?.value || "",
        };

        selects.forEach((select) => {
            const firstLabel = select.options[0]?.textContent || "Selecione";
            select.innerHTML = "";

            const placeholder = document.createElement("option");
            placeholder.value = "";
            placeholder.textContent = firstLabel;
            select.appendChild(placeholder);

            state.interfaces.forEach((iface) => {
                const option = document.createElement("option");
                option.value = iface.nome;

                const suffix = iface.ip
                    ? ` · ${iface.ip}`
                    : iface.cidr
                        ? ` · ${iface.cidr}`
                        : "";

                option.textContent = `${iface.nome}${suffix}`;

                if (!iface.up) {
                    option.textContent += " · DOWN";
                }

                select.appendChild(option);
            });
        });

        setSelectValue(els.selectWan, current.WAN || state.mapping.WAN);
        setSelectValue(els.selectMgmt, current.MGMT || state.mapping.MGMT);
        setSelectValue(els.selectLan, current.LAN || state.mapping.LAN);

        updateReview();
    }

    function setSelectValue(select, value) {
        if (!select || !value) {
            return;
        }

        const exists = Array.from(select.options).some((option) => option.value === value);

        if (exists) {
            select.value = value;
        }
    }

    function renderInterfaces() {
        if (!els.interfacesList) return;

        if (els.interfaceCount) {
            els.interfaceCount.textContent =
                `${state.interfaces.length} ${state.interfaces.length === 1 ? "interface" : "interfaces"}`;
        }

        if (!state.interfaces.length) {
            els.interfacesList.innerHTML = `
                <div class="notice notice--warning" style="margin:0;">
                    <div class="notice__icon">!</div>
                    <div>
                        <strong>Nenhuma interface retornada.</strong>
                        <p>Atualize a detecção ou verifique o Agent.</p>
                    </div>
                </div>
            `;
            return;
        }

        els.interfacesList.innerHTML = state.interfaces
            .map((iface) => {
                const role =
                    findRoleForInterface(iface.nome) ||
                    iface.papeis?.join(" / ") ||
                    "—";

                const address =
                    [iface.ip, iface.cidr, iface.mac]
                        .filter(Boolean)
                        .join(" · ") ||
                    "Sem endereço IPv4 informado";

                return `
                    <div class="interface-row">
                        <div class="interface-row__main">
                            <strong>${escapeHtml(iface.nome)}</strong>
                            <small>${escapeHtml(address)}</small>
                        </div>
                        <span class="interface-row__role">${escapeHtml(role)}</span>
                        <span class="interface-row__state ${iface.up ? "" : "is-down"}">
                            ${iface.up ? "UP" : "DOWN"}
                        </span>
                    </div>
                `;
            })
            .join("");
    }

    function setInterfacesLoading() {
        if (!els.interfacesList) return;

        els.interfacesList.innerHTML = `
            <div class="interface-skeleton"></div>
            <div class="interface-skeleton"></div>
        `;
    }

    function findRoleForInterface(name) {
        for (const [role, iface] of Object.entries(state.mapping || {})) {
            if (iface === name) return role;
        }

        return "";
    }

    function hydrateNetworkFromStatus(status) {
        if (!status || typeof status !== "object") return;

        const mapping = {
            WAN: status.interface_wan || state.mapping.WAN || "",
            MGMT: status.interface_mgmt || state.mapping.MGMT || "",
            LAN: status.interface_lan || state.mapping.LAN || "",
        };

        state.mapping = {
            ...state.mapping,
            ...Object.fromEntries(
                Object.entries(mapping).filter(([, value]) => Boolean(value))
            ),
        };

        setSelectValue(els.selectWan, mapping.WAN);
        setSelectValue(els.selectMgmt, mapping.MGMT);
        setSelectValue(els.selectLan, mapping.LAN);

        if (els.inputHomeNet && !els.inputHomeNet.value && status.home_net) {
            els.inputHomeNet.value = status.home_net;
        }

        updateReview();
    }

    function validateNetwork() {
        const wan = els.selectWan?.value || "";
        const mgmt = els.selectMgmt?.value || "";
        const lan = els.selectLan?.value || "";
        const homeNet = (els.inputHomeNet?.value || "").trim();

        if (!wan || !mgmt || !lan) {
            return {
                ok: false,
                message: "Selecione as interfaces WAN, MGMT e LAN.",
            };
        }

        const unique = new Set([wan, mgmt, lan]);

        if (unique.size !== 3) {
            return {
                ok: false,
                message: "WAN, MGMT e LAN precisam usar interfaces diferentes.",
            };
        }

        if (!homeNet) {
            return {
                ok: false,
                message: "Informe o HOME_NET em formato CIDR.",
            };
        }

        if (!isValidCidr(homeNet)) {
            return {
                ok: false,
                message: "HOME_NET inválido. Use um CIDR IPv4, por exemplo 10.10.0.0/24.",
            };
        }

        return { ok: true };
    }

    function isValidCidr(value) {
        const match = String(value).trim().match(
            /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d|[12]\d|3[0-2])$/
        );

        if (!match) return false;

        return match.slice(1, 5).every((part) => {
            const n = Number(part);
            return n >= 0 && n <= 255;
        });
    }

    function showNetworkError(message) {
        if (els.networkValidationText) {
            els.networkValidationText.textContent = message;
        }

        if (els.networkValidationNotice) {
            els.networkValidationNotice.hidden = false;
        }
    }

    function hideNetworkError() {
        if (els.networkValidationNotice) {
            els.networkValidationNotice.hidden = true;
        }
    }

    function updateReview() {
        const wan = els.selectWan?.value || "—";
        const mgmt = els.selectMgmt?.value || "—";
        const lan = els.selectLan?.value || "—";
        const home = (els.inputHomeNet?.value || "").trim() || "—";

        if (els.reviewWan) els.reviewWan.textContent = wan;
        if (els.reviewMgmt) els.reviewMgmt.textContent = mgmt;
        if (els.reviewLan) els.reviewLan.textContent = lan;
        if (els.reviewHomeNet) els.reviewHomeNet.textContent = home;
    }

    /* ----------------------------------------------------------------------
       Install
       ---------------------------------------------------------------------- */

    async function installFirewall() {
        if (state.installing) return;

        const validation = validateNetwork();

        if (!validation.ok) {
            showNetworkError(validation.message);
            goToStep(3);
            return;
        }

        if (!els.confirmInstall?.checked) {
            toast("Confirmação necessária", "Confirme a topologia antes de instalar.", "warning");
            return;
        }

        const payload = buildInstallPayload();

        state.installing = true;

        if (els.btnInstall) {
            els.btnInstall.disabled = true;
        }

        showRunningState();
        addInstallLog("INFO", "Payload validado pelo frontend.");
        addInstallLog("INFO", `WAN=${payload.interface_wan} | MGMT=${payload.interface_mgmt} | LAN=${payload.interface_lan}`);
        addInstallLog("INFO", `HOME_NET=${payload.home_net}`);
        addInstallLog("INFO", "Enviando solicitação para o backend Django...");

        try {
            const result = await api(URLS.instalar, {
                method: "POST",
                body: JSON.stringify(payload),
            });

            addInstallLog("OK", "Django recebeu confirmação do MoonShield-Agent.");

            const serviceResult = result.resultado || result;
            const stateResult = serviceResult.estado || {};

            showSuccessState(serviceResult, stateResult);

            state.status = {
                ...state.status,
                ...stateResult,
            };

            renderEnvironment(state.status);
        } catch (error) {
            const data = error.data || {};
            const serviceResult = data.resultado || data;

            addInstallLog("ERRO", error.message);
            showErrorState(error.message, serviceResult);

            if (state.status.instalado || state.status.tabela_instalada) {
                if (els.btnRepair) {
                    els.btnRepair.hidden = false;
                }
            }
        } finally {
            state.installing = false;
        }
    }

    function buildInstallPayload() {
        return {
            interface_wan: els.selectWan?.value || "",
            interface_lan: els.selectLan?.value || "",
            interface_mgmt: els.selectMgmt?.value || "",
            home_net: (els.inputHomeNet?.value || "").trim(),
            instalar_pacote: true,
        };
    }

    function showRunningState() {
        if (els.reviewState) els.reviewState.hidden = true;
        if (els.installRunning) els.installRunning.hidden = false;
        if (els.successState) els.successState.hidden = true;
        if (els.errorState) els.errorState.hidden = true;

        if (els.installPageTitle) {
            els.installPageTitle.textContent = "Instalando o Firewall.";
        }

        if (els.installPageIntro) {
            els.installPageIntro.textContent =
                "O Agent está executando as validações e alterações locais necessárias.";
        }
    }

    function showSuccessState(result, status) {
        if (els.reviewState) els.reviewState.hidden = true;
        if (els.installRunning) els.installRunning.hidden = true;
        if (els.errorState) els.errorState.hidden = true;
        if (els.successState) els.successState.hidden = false;

        if (els.installPageTitle) {
            els.installPageTitle.textContent = "Instalação concluída.";
        }

        if (els.installPageIntro) {
            els.installPageIntro.textContent =
                "O MoonShield-Agent confirmou a configuração do Firewall.";
        }

        if (els.successMessage) {
            els.successMessage.textContent =
                result.mensagem ||
                "A tabela MoonShield foi configurada e validada.";
        }

        if (els.resultNftVersion) {
            els.resultNftVersion.textContent =
                status.nftables_versao ||
                state.status.nftables_versao ||
                "Ativo";
        }

        setDot(els.topStatusDot, "success");

        if (els.topStatusText) {
            els.topStatusText.textContent = "Firewall operacional";
        }

        state.maxStep = 4;
        markAllComplete();

        toast("Firewall instalado", "A configuração foi concluída pelo MoonShield-Agent.", "success");
    }

    function showErrorState(message, details) {
        if (els.reviewState) els.reviewState.hidden = true;
        if (els.installRunning) els.installRunning.hidden = true;
        if (els.successState) els.successState.hidden = true;
        if (els.errorState) els.errorState.hidden = false;

        if (els.installPageTitle) {
            els.installPageTitle.textContent = "A instalação precisa de atenção.";
        }

        if (els.installPageIntro) {
            els.installPageIntro.textContent =
                "Nenhuma continuidade automática será executada até você revisar o retorno.";
        }

        if (els.errorMessage) {
            els.errorMessage.textContent = message || "A instalação não foi concluída.";
        }

        const printable = sanitizeDetails(details);

        if (printable) {
            els.errorDetails.hidden = false;
            els.errorDetails.textContent = printable;
        } else {
            els.errorDetails.hidden = true;
            els.errorDetails.textContent = "";
        }

        toast("Instalação não concluída", message || "Verifique o retorno do Agent.", "error");
    }

    function resetInstallStates() {
        if (els.reviewState) els.reviewState.hidden = false;
        if (els.installRunning) els.installRunning.hidden = true;
        if (els.successState) els.successState.hidden = true;
        if (els.errorState) els.errorState.hidden = true;

        if (els.errorDetails) {
            els.errorDetails.hidden = true;
            els.errorDetails.textContent = "";
        }

        if (els.installPageTitle) {
            els.installPageTitle.textContent = "Revise e instale.";
        }

        if (els.installPageIntro) {
            els.installPageIntro.textContent =
                "Confira a topologia. Depois da confirmação, o Agent valida, prepara a configuração e aplica o Firewall.";
        }

        if (els.confirmInstall) {
            els.confirmInstall.checked = false;
        }

        if (els.btnInstall) {
            els.btnInstall.disabled = true;
        }
    }

    async function repairFirewall() {
        if (!URLS.reparar || state.installing) return;

        const validation = validateNetwork();

        if (!validation.ok) {
            toast("Topologia inválida", validation.message, "error");
            goToStep(3);
            return;
        }

        state.installing = true;
        showRunningState();
        addInstallLog("INFO", "Solicitando reparo ao MoonShield-Agent...");

        try {
            const payload = buildInstallPayload();
            delete payload.instalar_pacote;

            const result = await api(URLS.reparar, {
                method: "POST",
                body: JSON.stringify(payload),
            });

            const serviceResult = result.resultado || result;
            const stateResult = serviceResult.estado || {};

            showSuccessState(serviceResult, stateResult);
        } catch (error) {
            showErrorState(error.message, error.data || {});
        } finally {
            state.installing = false;
        }
    }

    function addInstallLog(level, message) {
        if (!els.installLog) return;

        const div = document.createElement("div");
        const label = document.createElement("span");

        label.textContent = level;
        div.appendChild(label);
        div.appendChild(document.createTextNode(` ${message}`));

        els.installLog.appendChild(div);
        els.installLog.scrollTop = els.installLog.scrollHeight;
    }

    /* ----------------------------------------------------------------------
       UI helpers
       ---------------------------------------------------------------------- */

    function enableStep(step) {
        const nav = $(`[data-step-nav="${step}"]`);
        if (nav) nav.disabled = false;
    }

    function markAllComplete() {
        els.navSteps.forEach((nav) => {
            nav.disabled = false;
            nav.classList.remove("active");
            nav.classList.add("complete");
        });

        const last = $('[data-step-nav="4"]');
        if (last) {
            last.classList.add("active");
        }
    }

    function setBadge(element, text, type) {
        if (!element) return;

        element.textContent = text;
        element.classList.remove("is-loading", "is-success", "is-warning", "is-error");
        element.classList.add(`is-${type}`);
    }

    function setDot(element, type) {
        if (!element) return;

        element.classList.remove("is-loading", "is-success", "is-error");
        element.classList.add(`is-${type}`);
    }

    function getErrorMessage(status) {
        if (!status || typeof status !== "object") return "";

        const error = status.erro;

        if (typeof error === "string") return error;

        if (error && typeof error === "object") {
            return error.mensagem || error.erro || "";
        }

        return "";
    }

    function sanitizeDetails(value) {
        if (!value) return "";

        try {
            if (typeof value === "string") {
                return value.slice(0, 5000);
            }

            return JSON.stringify(value, null, 2).slice(0, 5000);
        } catch (_) {
            return "";
        }
    }

    function toast(title, message, type = "info", duration = 4200) {
        if (!els.toastContainer) return;

        const item = document.createElement("div");
        item.className = `toast is-${type}`;

        const dot = document.createElement("span");
        dot.className = "toast__dot";

        const copy = document.createElement("div");

        const strong = document.createElement("strong");
        strong.textContent = title;

        const p = document.createElement("p");
        p.textContent = message;

        copy.append(strong, p);
        item.append(dot, copy);
        els.toastContainer.appendChild(item);

        window.setTimeout(() => {
            item.style.opacity = "0";
            item.style.transform = "translateY(-5px)";

            window.setTimeout(() => item.remove(), 180);
        }, duration);
    }

    function escapeHtml(value) {
        return String(value ?? "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
})();
