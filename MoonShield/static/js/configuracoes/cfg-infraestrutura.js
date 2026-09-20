/* Infraestrutura de leitura, navegação, diagnóstico e persistência da tela. */
(() => {
  "use strict";

  const n = () => window.CfgNucleo;
  const $ = (id) => n().$(id);
  const escapeHtml = (value) => String(value ?? "—").replace(/[&<>"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[char]);

  function principal(role) {
    return n().STATE.rede?.[role]?.principal || null;
  }

  function interfaceText(interfaceData) {
    if (!interfaceData) return "Não configurada";
    const real = interfaceData.real || {};
    const desired = interfaceData.desejado || {};
    const ip = real.ipv4 || desired.ipv4_endereco || "sem IPv4";
    return `${interfaceData.nome || "—"} · ${ip}`;
  }

  function interfaceUp(interfaceData) {
    if (!interfaceData) return false;
    const real = interfaceData.real || {};
    return real.estado_link === "up" || real.carrier === true;
  }

  function renderNetworkSummary() {
    const topologia = n().STATE.rede || {};
    const rows = [
      ["WAN", principal("wan")],
      ["LAN", principal("lan")],
      ["MGMT", principal("mgmt")],
    ];
    const container = $("networkSummary");
    if (!container) return;
    container.innerHTML = rows.map(([role, data]) => `
      <div class="cfg-network-row"><span>${role}</span><strong>${escapeHtml(interfaceText(data))}</strong>
      <small class="cfg-network-row__status cfg-network-row__status--${interfaceUp(data) ? "ok" : "muted"}">${data ? (interfaceUp(data) ? "UP" : "Requer atenção") : "—"}</small></div>`).join("") + `
      <div class="cfg-network-row"><span>Gateway</span><strong>${escapeHtml((principal("wan")?.real || {}).gateway || (principal("wan")?.desejado || {}).gateway || "—")}</strong><small>via WAN</small></div>
      <div class="cfg-network-row"><span>Topologia</span><strong>${topologia.valida ? "Válida" : "Requer atenção"}</strong><small class="cfg-network-row__status cfg-network-row__status--${topologia.valida ? "ok" : "warn"}">${topologia.valida ? "●" : "●"}</small></div>`;
  }

  async function loadSysInfo() {
    const container = $("sysInfoGrid");
    try {
      const data = await n().apiFetch(n().endpoint("sysinfoUrl"));
      const info = data.sysinfo || {};
      const labels = [["Hostname", info.hostname], ["Sistema operacional", info.so], ["IP do appliance", info.ip_local], ["Timezone", info.timezone], ["Uptime", info.uptime], ["Python", info.python], ["Django", info.django], ["RAM", info.ram]];
      if (container) container.innerHTML = labels.map(([label, value]) => `<div class="cfg-info-card"><p class="cfg-info-card__label">${label}</p><p class="cfg-info-card__val">${escapeHtml(value)}</p></div>`).join("");
    } catch (e) {
      if (container) container.innerHTML = '<p class="cfg-hint" style="grid-column: 1/-1;">Informa&ccedil;&otilde;es do servidor indispon&iacute;veis.</p>';
    }
  }

  function renderDiagnostics() {
    const services = n().STATE.servicos || {};
    const topology = n().STATE.rede || {};
    const entries = [
      ["Rede", topology.valida ? "Operacional" : "Requer atenção", Boolean(topology.valida)],
      ["Agent", services.firewall?.agent_online ? "Online" : "Indisponível", Boolean(services.firewall?.agent_online)],
      ["DNS / AdGuard", services.adguard?.status_label, Boolean(services.adguard?.saudavel)],
      ["IDS / Suricata", services.suricata?.status_label, Boolean(services.suricata?.saudavel)],
      ["Firewall", services.firewall?.status_label, Boolean(services.firewall?.saudavel)],
      ["Web", "Online", true],
    ];
    const container = $("diagServices");
    if (container) container.innerHTML = entries.map(([name, state, healthy]) => `<div class="cfg-diag-card"><p>${name}</p><strong class="cfg-diag-card__status cfg-diag-card__status--${healthy ? "ok" : "warn"}"><i></i>${escapeHtml(state || "Indisponível")}</strong></div>`).join("");
  }

  function activateTab(name) {
    document.querySelectorAll(".cfg-tab").forEach((button) => button.classList.toggle("cfg-tab--active", button.dataset.tab === name));
    document.querySelectorAll(".cfg-panel").forEach((panel) => panel.classList.toggle("cfg-panel--active", panel.id === `panel${name[0].toUpperCase()}${name.slice(1)}`));
    localStorage.setItem("moonshield_cfg_tab", name);
  }

  function initTabs() {
    document.querySelectorAll(".cfg-tab").forEach((button) => button.addEventListener("click", () => activateTab(button.dataset.tab)));
    const saved = localStorage.getItem("moonshield_cfg_tab");
    activateTab(document.querySelector(`.cfg-tab[data-tab="${saved}"]`) ? saved : "sistema");
  }

  function initSave() {
    $("cfgSaveAllBtn")?.addEventListener("click", async () => {
      const button = $("cfgSaveAllBtn");
      const original = button.innerHTML;
      button.disabled = true;
      button.innerHTML = '<i class="bi bi-hourglass-split"></i> Salvando...';
      try {
        await n().apiFetch(n().endpoint("salvarUrl"), "POST", n().collectStateFromForm());
        await n().loadConfig();
        await n().loadServicosStatus();
        window.CfgConexoes.refreshFromState();
        renderNetworkSummary();
        renderDiagnostics();
        n().showToast("Alterações salvas.");
      } catch (error) {
        n().showToast(error.message || "Não foi possível salvar.", "erro");
      } finally {
        button.disabled = false;
        button.innerHTML = original;
      }
    });
  }

  function initQuickTests() {
    document.querySelectorAll("[data-quick-test]").forEach((button) => button.addEventListener("click", async () => {
      const result = $(button.dataset.result);
            button.disabled = true;
      if (result) {
          result.innerHTML = 'Executando... <i class="bi bi-arrow-repeat" style="animation: spin 1s linear infinite;"></i>';
      }
      try {
        const data = await n().apiFetch(`${n().endpoint("quickTestUrl")}?test=${button.dataset.quickTest}`);
        if (result) result.textContent = data.ok ? `OK${data.ms != null ? ` — ${data.ms}ms` : ""}` : data.msg || "Falha";
      } catch (error) {
        if (result) result.textContent = "Indisponível";
      } finally {
        button.disabled = false;
      }
    }));
  }

  document.addEventListener("DOMContentLoaded", async () => {
    const loadingTarget = $("cfgApp");
    initTabs();
    initSave();
    initQuickTests();
    $("btnRefreshDiag")?.addEventListener("click", async () => {
      window.MoonShieldLoading?.setRefreshing(loadingTarget, true);
      try {
        await n().loadConfig();
        await n().loadServicosStatus();
        window.CfgConexoes.refreshFromState();
        renderNetworkSummary();
        renderDiagnostics();
        n().showToast("Diagnóstico atualizado.");
      } catch (error) {
        n().showToast("Não foi possível atualizar o diagnóstico.", "erro");
      } finally {
        window.MoonShieldLoading?.setRefreshing(loadingTarget, false);
      }
    });
        window.MoonShieldLoading?.setRefreshing($("cfgStatusBar"), true);

    if ($("sysInfoGrid") && !$("sysInfoGrid").children.length) {
        $("sysInfoGrid").innerHTML = Array(8).fill('<div class="cfg-info-card"></div>').join("");
        document.querySelectorAll("#sysInfoGrid .cfg-info-card").forEach(el => window.MoonShieldLoading?.start(el, { variant: 'card' }));
    }
    if ($("systemServicesSummary") && !$("systemServicesSummary").children.length) {
        $("systemServicesSummary").innerHTML = Array(3).fill('<div class="cfg-service-summary-card"></div>').join("");
        document.querySelectorAll("#systemServicesSummary .cfg-service-summary-card").forEach(el => window.MoonShieldLoading?.start(el, { variant: 'card' }));
    }
    if ($("servicesCards") && !$("servicesCards").children.length) {
        $("servicesCards").innerHTML = Array(3).fill('<div class="cfg-service-card"></div>').join("");
        document.querySelectorAll("#servicesCards .cfg-service-card").forEach(el => window.MoonShieldLoading?.start(el, { variant: 'card' }));
    }
    if ($("diagServices") && !$("diagServices").children.length) {
        $("diagServices").innerHTML = Array(6).fill('<div class="cfg-diag-card"></div>').join("");
        document.querySelectorAll("#diagServices .cfg-diag-card").forEach(el => window.MoonShieldLoading?.start(el, { variant: 'number' }));
    }

    try {
      await n().loadConfig();
      await n().loadServicosStatus();
      await loadSysInfo();
      window.CfgConexoes.refreshFromState();
      renderNetworkSummary();
      renderDiagnostics();
    } catch (error) {
      n().showToast("Não foi possível carregar as configurações da appliance.", "erro");
    } finally {
      window.MoonShieldLoading?.setRefreshing($("cfgStatusBar"), false);
    }
  });

  window.CfgInfraestrutura = { loadSysInfo, renderNetworkSummary, renderDiagnostics };
})();
