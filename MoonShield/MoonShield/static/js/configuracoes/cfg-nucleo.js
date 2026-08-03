/**
 * MOONSHIELD — cfg-nucleo.js  v2
 * ─────────────────────────────────────────────────────────────────────
 * Núcleo do módulo de configurações.
 * v2: STATE.providers.fw inclui agente_porta (porta do Flask local :8765)
 * ─────────────────────────────────────────────────────────────────────
 */

(function () {

  const $ = id => document.getElementById(id);

  function nowStr() {
    return new Date().toLocaleTimeString("pt-BR", {
      hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
    });
  }

  function fmtLastSync(ts) {
    if (!ts) return "nunca";
    return new Date(ts).toLocaleTimeString("pt-BR", {
      hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
    });
  }

  function fmtTempo(segundos) {
    if (segundos === null || segundos === undefined) return "nunca conectou";
    if (segundos < 60)   return `${segundos}s atrás`;
    if (segundos < 3600) return `${Math.floor(segundos / 60)}min atrás`;
    return `${Math.floor(segundos / 3600)}h atrás`;
  }

  function capitalize(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

  let _toastTimer;
  function showToast(msg, type = "ok") {
    const t = $("cfgToast"); if (!t) return;
    t.textContent = msg;
    t.className = `cfg-toast cfg-toast--${type} show`;
    clearTimeout(_toastTimer);
    _toastTimer = setTimeout(() => t.classList.remove("show"), 3500);
  }

  function getCsrfToken() {
    const el = document.querySelector("[name=csrfmiddlewaretoken]");
    if (el) return el.value;
    const match = document.cookie.match(/csrftoken=([^;]+)/);
    return match ? match[1] : "";
  }

  async function apiFetch(url, method = "GET", body = null) {
    const opts = { method, headers: { "Content-Type": "application/json" } };
    if (method !== "GET") {
      opts.headers["X-CSRFToken"] = getCsrfToken();
      if (body) opts.body = JSON.stringify(body);
    }
    const res = await fetch(url, opts);
    if (!res.ok && res.status !== 400) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }

  /* ════════════════════════════════════════════════════════════
     CONFIG DOS PROVIDERS
  ════════════════════════════════════════════════════════════ */
  const PROVIDER_CFG = {
    dns: {
      selectId:        "dnsMode",
      badgeId:         "badgeModeDns",
      overlayId:       "overlayDns",
      statusId:        "statusDns",
      toggleId:        "toggleDnsProvider",
      lastSyncId:      "dnsLastSync",
      label:           "DNS",
      defaultRealMode: "real",
      demoOptions: [{ value: "mock", label: "Mock (simulado)" }],
      prodOptions: [{ value: "real", label: "AdGuard Real" }],
    },
    ids: {
      selectId:        "idsMode",
      badgeId:         "badgeModeIds",
      overlayId:       "overlayIds",
      statusId:        "statusIds",
      toggleId:        "toggleIdsProvider",
      lastSyncId:      "idsLastSync",
      label:           "IDS",
      defaultRealMode: "eve",
      demoOptions: [{ value: "mock", label: "Mock (simulado)" }],
      prodOptions: [
        { value: "eve",    label: "Sensor Linux (ms_sensor.py)" },
        { value: "syslog", label: "Syslog (em breve)", disabled: true },
      ],
    },
    fw: {
      selectId:        "fwMode",
      badgeId:         "badgeModeFw",
      overlayId:       "overlayFw",
      statusId:        "statusFw",
      toggleId:        "toggleFwProvider",
      lastSyncId:      "fwLastSync",
      label:           "Firewall",
      defaultRealMode: "nftables",
      demoOptions: [{ value: "mock", label: "Mock (simulado)" }],
      prodOptions: [
        { value: "nftables", label: "nftables (ms_firewall.py)" },
        { value: "iptables", label: "iptables (em breve)", disabled: true },
        { value: "pfsense",  label: "pfSense API (em breve)", disabled: true },
      ],
    },
  };

  /* ════════════════════════════════════════════════════════════
     STATE — v2: fw.agente_porta adicionado
  ════════════════════════════════════════════════════════════ */
  let STATE = {
    modo: "demo",
    node:      { name: "", ambiente: "lab", tag: "", desc: "" },
    rede:      { cidr: "", gateway: "", dns1: "", dns2: "", ips_criticos: "", excluir: "", iface_principal: "" },
    scanner:   { interval: 60, pingTimeout: 1000, maxHosts: 254, method: "ping_arp", hostname: true, mac: true, oui: true },
    retencao:  { devices: 30, logs: 7, dns: 7, incidents: 90 },
    providers: {
      dns: { active: false, mode: "mock", url: "", user: "", https: false, interval: 30 },
      ids: { active: false, mode: "mock", interval: 5, minSeverity: 2 },
      fw:  { active: false, mode: "mock", target: "local", host: "", agente_porta: 8765 },
    },
    seguranca: { sessionExpiry: 480, maxLoginAttempts: 5, forceHttps: false, accessLog: true, ipBan: true, logLevel: "INFO" },
  };

  const PROV_STATUS = { dns: "off", ids: "off", fw: "off" };

  /* ════════════════════════════════════════════════════════════
     CARREGAR CONFIG DO BANCO
  ════════════════════════════════════════════════════════════ */
  async function loadConfig() {
    try {
      const data = await apiFetch("/configuracoes/api/config/");
      if (data.ok && data.config) {
        STATE = data.config;
        // garante agente_porta com default caso backend antigo
        if (!STATE.providers?.fw?.agente_porta) {
          STATE.providers = STATE.providers || {};
          STATE.providers.fw = STATE.providers.fw || {};
          STATE.providers.fw.agente_porta = 8765;
        }
        window.CfgConexoes.applyMode(STATE.modo, { silent: true });
        fillFormFromState();
        renderStatusBar();

        ["dns", "ids", "fw"].forEach(p => {
          const prov   = STATE.providers?.[p] || {};
          const isReal = prov.mode !== "mock";
          if (prov.active) {
            const status = isReal ? "warn" : "mock";
            PROV_STATUS[p] = status;
            window.CfgConexoes.setProviderStatus(p, status, isReal ? "Ativo — faça um teste" : "Mock ativo");
          }
        });

        logDiag("OK", "Configurações carregadas do banco.");
      }
    } catch (e) {
      logDiag("ERRO", `Falha ao carregar config: ${e.message}`);
      showToast("Falha ao carregar configurações", "erro");
    }
  }

  /* ════════════════════════════════════════════════════════════
     PREENCHER FORMULÁRIO — v2: campo fwAgentePorta
  ════════════════════════════════════════════════════════════ */
  function fillFormFromState() {
    const set    = (id, v) => { if ($(id)) $(id).value   = v ?? ""; };
    const setChk = (id, v) => { if ($(id)) $(id).checked = !!v; };

    set("cfgModeSelect", STATE.modo);

    set("fieldNodeName",  STATE.node?.name);
    set("fieldAmbiente",  STATE.node?.ambiente);
    set("fieldTag",       STATE.node?.tag);
    set("fieldDesc",      STATE.node?.desc);

    const r = STATE.rede || {};
    set("fieldCidr",        r.cidr);
    set("fieldGateway",     r.gateway);
    set("fieldDns1",        r.dns1);
    set("fieldDns2",        r.dns2);
    set("fieldIpsCriticos", r.ips_criticos);
    set("fieldExcluir",     r.excluir);

    const sc = STATE.scanner || {};
    set("fieldScanInterval", sc.interval);
    set("fieldPingTimeout",  sc.pingTimeout);
    set("fieldMaxHosts",     sc.maxHosts);
    set("fieldScanMethod",   sc.method);
    setChk("toggleHostname", sc.hostname);
    setChk("toggleMac",      sc.mac);
    setChk("toggleOui",      sc.oui);

    const ret = STATE.retencao || {};
    set("fieldRetDevices",   ret.devices);
    set("fieldRetLogs",      ret.logs);
    set("fieldRetDns",       ret.dns);
    set("fieldRetIncidents", ret.incidents);

    const dns = STATE.providers?.dns || {};
    setChk("toggleDnsProvider", dns.active);
    _setSelectIfOptionExists("dnsMode", dns.mode);
    set("dnsUrl",      dns.url);
    set("dnsUser",     dns.user);
    setChk("dnsHttps", dns.https);
    set("dnsInterval", dns.interval);
    _updateUrlIndicator("dnsUrl", "dnsUrlStatus", dns.url);

    const ids = STATE.providers?.ids || {};
    setChk("toggleIdsProvider", ids.active);
    _setSelectIfOptionExists("idsMode", ids.mode);
    set("idsInterval",    ids.interval);
    set("idsMinSeverity", ids.minSeverity);

    const fw = STATE.providers?.fw || {};
    setChk("toggleFwProvider", fw.active);
    _setSelectIfOptionExists("fwMode", fw.mode);
    set("fwTarget",      fw.target);
    set("fwHost",        fw.host);
    set("fwAgentePorta", fw.agente_porta ?? 8765);  // v2

    const seg = STATE.seguranca || {};
    set("fieldSession",   seg.sessionExpiry);
    set("fieldMaxLogin",  seg.maxLoginAttempts);
    set("fieldLogLevel",  seg.logLevel);
    setChk("toggleHttps",     seg.forceHttps);
    setChk("toggleAccessLog", seg.accessLog);
    setChk("toggleIpBan",     seg.ipBan);

    _updateDiagLabels();
  }

  function _setSelectIfOptionExists(selectId, value) {
    const el = $(selectId); if (!el || !value) return;
    const opt = el.querySelector(`option[value="${value}"]`);
    if (opt) el.value = value;
  }

  function _updateDiagLabels() {
    const gw   = STATE.rede?.gateway || "—";
    const dns1 = STATE.rede?.dns1    || "1.1.1.1";
    if ($("diagGateway")) $("diagGateway").textContent = `Gateway: ${gw}`;
    if ($("diagDns1"))    $("diagDns1").textContent    = `DNS: ${dns1}`;
  }

  function _updateUrlIndicator(inputId, statusId, url) {
    const el = $(statusId); if (!el) return;
    if (url && url.startsWith("http")) {
      el.innerHTML = `<span style="color:#22c55e;font-size:10px;font-family:var(--font-mono)">✓ ${url}</span>`;
    } else {
      el.innerHTML = `<span style="color:var(--text-dim);font-size:10px;font-family:var(--font-mono)">Não configurada</span>`;
    }
  }

  /* ════════════════════════════════════════════════════════════
     COLETAR STATE DO FORMULÁRIO — v2: agente_porta
  ════════════════════════════════════════════════════════════ */
  function collectStateFromForm() {
    const g   = (id, fb) => $(id) ? $(id).value.trim() : fb;
    const gi  = (id, fb) => $(id) ? (parseInt($(id).value) || fb) : fb;
    const gb  = (id, fb) => $(id) ? $(id).checked : fb;

    return {
      modo: g("cfgModeSelect", STATE.modo),
      node: {
        name:     g("fieldNodeName",  STATE.node?.name),
        ambiente: g("fieldAmbiente",  STATE.node?.ambiente),
        tag:      g("fieldTag",       STATE.node?.tag),
        desc:     g("fieldDesc",      STATE.node?.desc),
      },
      rede: {
        cidr:            g("fieldCidr",        STATE.rede?.cidr),
        gateway:         g("fieldGateway",     STATE.rede?.gateway),
        dns1:            g("fieldDns1",        STATE.rede?.dns1),
        dns2:            g("fieldDns2",        STATE.rede?.dns2),
        ips_criticos:    g("fieldIpsCriticos", STATE.rede?.ips_criticos),
        excluir:         g("fieldExcluir",     STATE.rede?.excluir),
        iface_principal: STATE.rede?.iface_principal || "",
      },
      scanner: {
        interval:    gi("fieldScanInterval", 60),
        pingTimeout: gi("fieldPingTimeout",  1000),
        maxHosts:    gi("fieldMaxHosts",     254),
        method:       g("fieldScanMethod",   "ping_arp"),
        hostname:    gb("toggleHostname",    true),
        mac:         gb("toggleMac",         true),
        oui:         gb("toggleOui",         true),
      },
      retencao: {
        devices:   gi("fieldRetDevices",  30),
        logs:      gi("fieldRetLogs",     7),
        dns:       gi("fieldRetDns",      7),
        incidents: gi("fieldRetIncidents",90),
      },
      providers: {
        dns: {
          active:   gb("toggleDnsProvider", false),
          mode:      g("dnsMode",           "mock"),
          url:       g("dnsUrl",            ""),
          user:      g("dnsUser",           ""),
          pass:      g("dnsPass",           ""),
          https:    gb("dnsHttps",          false),
          interval: gi("dnsInterval",       30),
        },
        ids: {
          active:      gb("toggleIdsProvider", false),
          mode:         g("idsMode",           "mock"),
          interval:    gi("idsInterval",       5),
          minSeverity: gi("idsMinSeverity",    2),
        },
        fw: {
          active:       gb("toggleFwProvider", false),
          mode:          g("fwMode",           "mock"),
          target:        g("fwTarget",         "local"),
          host:          g("fwHost",           ""),
          token:         g("fwToken",          ""),
          agente_porta: gi("fwAgentePorta",    8765),   // v2
        },
      },
      seguranca: {
        sessionExpiry:    gi("fieldSession",   480),
        maxLoginAttempts: gi("fieldMaxLogin",  5),
        forceHttps:       gb("toggleHttps",    false),
        accessLog:        gb("toggleAccessLog",true),
        ipBan:            gb("toggleIpBan",    true),
        logLevel:          g("fieldLogLevel",  "INFO"),
      },
    };
  }

  /* ════════════════════════════════════════════════════════════
     STATUS BAR
  ════════════════════════════════════════════════════════════ */
  function renderStatusBar() {
    if ($("cfgNodeName"))        $("cfgNodeName").textContent        = STATE.node?.name || "MS-NODE-01";
    if ($("cfgNodeSub"))         $("cfgNodeSub").textContent         = `Modo: ${STATE.modo === "demo" ? "Demo" : "Produção"}`;
    if ($("pillRedeLabel"))      $("pillRedeLabel").textContent       = `Rede: ${STATE.rede?.cidr || "—"}`;
    if ($("pillInterfaceLabel")) $("pillInterfaceLabel").textContent  = `Interface: ${STATE.rede?.iface_principal || "—"}`;

    ["dns", "ids", "fw"].forEach(p => renderProviderDot(`dot${p.toUpperCase()}`, PROV_STATUS[p]));

    const connected = Object.values(PROV_STATUS).filter(s => s === "ok").length;
    const badge = $("tabBadgeIntegracoes");
    if (badge) {
      badge.textContent = `${connected}/3`;
      badge.style.background = connected === 3 ? "rgba(34,197,94,.15)"
                             : connected >  0   ? "rgba(234,179,8,.15)"
                             :                    "rgba(255,255,255,.08)";
      badge.style.color = connected === 3 ? "#22c55e"
                        : connected >  0   ? "#eab308"
                        :                    "#888";
    }
  }

  function renderProviderDot(id, status) {
    const el = $(id); if (!el) return;
    const cls = { ok: "ok", mock: "mock", warn: "warn", erro: "erro" }[status] || "off";
    el.className = `cfg-provider-dot cfg-provider-dot--${cls}`;
  }

  /* ════════════════════════════════════════════════════════════
     LOG DE DIAGNÓSTICO
  ════════════════════════════════════════════════════════════ */
  function logDiag(level, msg) {
    const log = $("diagLog"); if (!log) return;
    log.querySelector(".cfg-diag-log__empty")?.remove();
    const row = document.createElement("div");
    row.className = `cfg-diag-log-entry cfg-diag-log-entry--${level.toLowerCase()}`;
    row.innerHTML = `
      <span class="cfg-diag-log-entry__time">${nowStr()}</span>
      <span class="cfg-diag-log-entry__level">${level}</span>
      <span class="cfg-diag-log-entry__msg">${msg}</span>`;
    log.insertBefore(row, log.firstChild);
    if (log.children.length > 60) log.removeChild(log.lastChild);
  }

  /* ════════════════════════════════════════════════════════════
     EXPOR API GLOBAL
  ════════════════════════════════════════════════════════════ */
  window.CfgNucleo = {
    $,
    nowStr,
    fmtLastSync,
    fmtTempo,
    capitalize,
    showToast,
    getCsrfToken,
    apiFetch,
    PROVIDER_CFG,
    get STATE() { return STATE; },
    set STATE(v) { STATE = v; },
    PROV_STATUS,
    loadConfig,
    fillFormFromState,
    collectStateFromForm,
    renderStatusBar,
    renderProviderDot,
    logDiag,
    _updateUrlIndicator,
    _updateDiagLabels,
    _setSelectIfOptionExists,
  };

})();