/* Renderização dos serviços locais da MoonShield Appliance. */
(() => {
  "use strict";

  const n = () => window.CfgNucleo;
  const escapeHtml = (value) => String(value ?? "—").replace(/[&<>"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[char]);

  function statusLabel(service) {
    return service?.status_label || (service?.saudavel ? "Operacional" : "Indisponível");
  }

  function stateRow(label, value, healthy) {
    const dot = healthy === undefined ? "" : `<span class="cfg-service-dot cfg-service-dot--${healthy ? "ok" : "warn"}"></span>`;
    return `<div class="cfg-service-row"><span>${escapeHtml(label)}</span><strong>${dot}${escapeHtml(value)}</strong></div>`;
  }

  function renderServiceCards() {
    const services = n().getPresentationState().servicos || {};
    const container = n().$("servicesCards");
    if (!container) return;
    const adguard = services.adguard || {};
    const suricata = services.suricata || {};
    const firewall = services.firewall || {};
    container.innerHTML = [
      {
        icon: "bi-shield-check", name: "AdGuard Home", subtitle: "DNS e bloqueio de conteúdo local", service: adguard,
        rows: [stateRow("Serviço", adguard.ativo ? "Ativo" : "Indisponível", adguard.ativo), stateRow("DNS Resolver", adguard.dns_resolver ? "Online" : "Indisponível", adguard.dns_resolver), stateRow("API", adguard.api ? "OK" : "Indisponível", adguard.api), stateRow("Proteção", adguard.protecao ? "Ativa" : "Inativa", adguard.protecao), stateRow("Filtros", `${adguard.filtros_ativos || 0} ativos`), stateRow("Versão", adguard.versao)],
        destination: "dnsPageUrl", action: "Abrir DNS",
      },
      {
        icon: "bi-shield-exclamation", name: "Suricata IDS", subtitle: "Detecção de ameaças local", service: suricata,
        rows: [stateRow("Motor IDS", suricata.ativo ? "Ativo" : "Indisponível", suricata.ativo), stateRow("EVE", suricata.eve_ativo ? "Ativo" : "Requer atenção", suricata.eve_ativo), stateRow("Interface(s)", (suricata.interfaces || []).join(", ") || "—"), stateRow("HOME_NET", (suricata.home_net || []).join(", ") || "—"), stateRow("Drift", suricata.drift || "Nenhum", suricata.drift === "Nenhum"), stateRow("Versão", suricata.versao)],
        destination: "idsPageUrl", action: "Abrir IDS",
      },
      {
        icon: "bi-fire", name: "Firewall MoonShield", subtitle: "Proteção local gerenciada pelo Agent", service: firewall,
        rows: [stateRow("Engine", firewall.engine || "nftables"), stateRow("Agent", firewall.agent_online ? "Online" : "Indisponível", firewall.agent_online), stateRow("Estado", statusLabel(firewall), firewall.saudavel), stateRow("Drift", firewall.drift || "Nenhum", firewall.drift === "Nenhum")],
        destination: "firewallPageUrl", action: "Abrir Firewall",
      },
    ].map((card) => `
      <article class="cfg-service-card">
        <header class="cfg-service-card__header"><i class="bi ${card.icon}"></i><div><h3>${card.name}</h3><p>${card.subtitle}</p></div><span class="cfg-service-badge cfg-service-badge--${n().serviceClass(card.service)}">${statusLabel(card.service)}</span></header>
        <div class="cfg-service-rows">${card.rows.join("")}</div>
        <a class="cfg-service-action" href="${escapeHtml(n().endpoint(card.destination))}">${card.action} <i class="bi bi-arrow-up-right"></i></a>
      </article>`).join("");
  }

  function renderSystemSummary() {
    const container = n().$("systemServicesSummary");
    if (!container) return;
    const cards = [
      ["AdGuard Home", "DNS e proteção", n().getPresentationState().servicos?.adguard],
      ["Suricata IDS", "Detecção de ameaças", n().getPresentationState().servicos?.suricata],
      ["Firewall MoonShield", "nftables", n().getPresentationState().servicos?.firewall],
    ];
    container.innerHTML = cards.map(([name, subtitle, service]) => `
      <div class="cfg-service-summary-card"><p>${name}</p><span>${subtitle}</span>
      <strong class="cfg-service-summary-card__status cfg-service-summary-card__status--${n().serviceClass(service)}"><i></i>${statusLabel(service)}</strong>
      <small>${escapeHtml(service?.versao || service?.engine || "")}</small></div>`).join("");
  }

  function refreshFromState() {
    renderServiceCards();
    renderSystemSummary();
    n().renderStatusBar();
  }

  window.CfgConexoes = { refreshFromState, renderServiceCards, renderSystemSummary };
})();
