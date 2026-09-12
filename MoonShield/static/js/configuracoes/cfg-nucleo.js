/* Estado e transporte da página Configurações da MoonShield Appliance. */
(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const app = () => $("cfgApp");
  let STATE = { node: {}, scanner: {}, retencao: {}, seguranca: {}, rede: {}, servicos: {} };

  function endpoint(name) {
    return app()?.dataset[name] || "";
  }

  function getCsrfToken() {
    return document.cookie.split("; ").find((row) => row.startsWith("csrftoken="))?.split("=")[1] || "";
  }

  async function apiFetch(url, method = "GET", body) {
    const options = { method, headers: { Accept: "application/json" }, credentials: "same-origin" };
    if (body !== undefined) {
      options.headers["Content-Type"] = "application/json";
      options.headers["X-CSRFToken"] = getCsrfToken();
      options.body = JSON.stringify(body);
    }
    const response = await fetch(url, options);
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.erro || data.msg || "Falha ao consultar a appliance.");
    return data;
  }

  function setValue(id, value) {
    const element = $(id);
    if (element) element.value = value ?? "";
  }

  function setChecked(id, value) {
    const element = $(id);
    if (element) element.checked = Boolean(value);
  }

  function fillFormFromState() {
    const { node = {}, scanner = {}, retencao = {}, seguranca = {} } = STATE;
    setValue("fieldNodeName", node.name);
    setValue("fieldAmbiente", node.ambiente);
    setValue("fieldTag", node.tag);
    setValue("fieldDesc", node.desc);
    setValue("fieldScanInterval", scanner.interval);
    setValue("fieldPingTimeout", scanner.pingTimeout);
    setValue("fieldMaxHosts", scanner.maxHosts);
    setValue("fieldScanMethod", scanner.method);
    setChecked("toggleHostname", scanner.hostname);
    setChecked("toggleMac", scanner.mac);
    setChecked("toggleOui", scanner.oui);
    setValue("fieldRetDevices", retencao.devices);
    setValue("fieldRetLogs", retencao.logs);
    setValue("fieldRetDns", retencao.dns);
    setValue("fieldRetIncidents", retencao.incidents);
    setValue("fieldSession", seguranca.sessionExpiry);
    setValue("fieldMaxLogin", seguranca.maxLoginAttempts);
    setValue("fieldLogLevel", seguranca.logLevel);
    setChecked("toggleHttps", seguranca.forceHttps);
    setChecked("toggleAccessLog", seguranca.accessLog);
    setChecked("toggleIpBan", seguranca.ipBan);
  }

  function value(id, fallback) {
    const element = $(id);
    return element ? element.value.trim() : fallback;
  }

  function integer(id, fallback) {
    const parsed = Number.parseInt(value(id, fallback), 10);
    return Number.isFinite(parsed) ? parsed : fallback;
  }

  function checked(id, fallback) {
    const element = $(id);
    return element ? element.checked : fallback;
  }

  function collectStateFromForm() {
    return {
      node: {
        name: value("fieldNodeName", STATE.node?.name || ""),
        ambiente: value("fieldAmbiente", STATE.node?.ambiente || "lab"),
        tag: value("fieldTag", STATE.node?.tag || ""),
        desc: value("fieldDesc", STATE.node?.desc || ""),
      },
      scanner: {
        interval: integer("fieldScanInterval", STATE.scanner?.interval || 60),
        pingTimeout: integer("fieldPingTimeout", STATE.scanner?.pingTimeout || 1000),
        maxHosts: integer("fieldMaxHosts", STATE.scanner?.maxHosts || 254),
        method: value("fieldScanMethod", STATE.scanner?.method || "ping_arp"),
        hostname: checked("toggleHostname", STATE.scanner?.hostname),
        mac: checked("toggleMac", STATE.scanner?.mac),
        oui: checked("toggleOui", STATE.scanner?.oui),
      },
      retencao: {
        devices: integer("fieldRetDevices", STATE.retencao?.devices || 30),
        logs: integer("fieldRetLogs", STATE.retencao?.logs || 7),
        dns: integer("fieldRetDns", STATE.retencao?.dns || 7),
        incidents: integer("fieldRetIncidents", STATE.retencao?.incidents || 90),
      },
      seguranca: {
        sessionExpiry: integer("fieldSession", STATE.seguranca?.sessionExpiry || 480),
        maxLoginAttempts: integer("fieldMaxLogin", STATE.seguranca?.maxLoginAttempts || 5),
        forceHttps: checked("toggleHttps", STATE.seguranca?.forceHttps),
        accessLog: checked("toggleAccessLog", STATE.seguranca?.accessLog),
        ipBan: checked("toggleIpBan", STATE.seguranca?.ipBan),
        logLevel: value("fieldLogLevel", STATE.seguranca?.logLevel || "INFO"),
      },
    };
  }

  function serviceClass(service) {
    return service?.saudavel ? "ok" : service?.status === "atencao" ? "warn" : "erro";
  }

  function renderStatusBar() {
    const topologia = STATE.rede || {};
    const gerenciamento = topologia.gerenciamento?.principal;
    const interfaceGerenciamento = gerenciamento?.nome || "—";
    const setText = (id, text) => { if ($(id)) $(id).textContent = text; };
    setText("cfgNodeName", STATE.node?.name || "MoonShield Appliance");
    setText("cfgNodeSub", "MoonShield Appliance");
    setText("pillInterfaceLabel", `Interface: ${interfaceGerenciamento}`);
    setText("pillRedeLabel", `Rede: ${topologia.valida ? "Válida" : "Requer atenção"}`);
    [["dotDNS", "adguard"], ["dotIDS", "suricata"], ["dotFW", "firewall"]].forEach(([id, key]) => {
      const dot = $(id);
      if (dot) dot.className = `cfg-service-status-dot cfg-service-status-dot--${serviceClass(STATE.servicos?.[key])}`;
    });
  }

  async function loadConfig() {
    const data = await apiFetch(endpoint("configUrl"));
    STATE = { ...STATE, ...(data.config || {}) };
    fillFormFromState();
    renderStatusBar();
    return STATE;
  }

  async function loadServicosStatus() {
    const data = await apiFetch(endpoint("servicosUrl"));
    STATE.servicos = data.servicos || {};
    STATE.servicosResumo = data.resumo || {};
    renderStatusBar();
    return STATE.servicos;
  }

  let toastTimer;
  function showToast(message, type = "ok") {
    const toast = $("cfgToast");
    if (!toast) return;
    toast.textContent = message;
    toast.className = `cfg-toast cfg-toast--${type} show`;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove("show"), 3500);
  }

  window.CfgNucleo = {
    $, endpoint, apiFetch, loadConfig, loadServicosStatus, fillFormFromState, collectStateFromForm,
    renderStatusBar, serviceClass, showToast,
    get STATE() { return STATE; },
    set STATE(value) { STATE = value; },
  };
})();
