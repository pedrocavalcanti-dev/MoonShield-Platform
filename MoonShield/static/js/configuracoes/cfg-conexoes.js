/**
 * MOONSHIELD — cfg-conexoes.js  v2
 * ─────────────────────────────────────────────────────────────────────
 * v2: _renderFwSensorCard exibe agente_porta + botão "Testar Agente"
 *     que faz GET direto ao Flask :8765/status para verificar se o
 *     agente está rodando no sensor.
 * ─────────────────────────────────────────────────────────────────────
 */

(function () {

  const n = () => window.CfgNucleo;
  const $ = id => document.getElementById(id);

  const REAL_FIELD_IDS = ["dnsUrl", "dnsUser", "dnsPass", "dnsHttps", "fwHost", "fwToken", "fwAgentePorta"];

  let _sensorPollingTimer   = null;
  let _fwSensorPollingTimer = null;

  /* ════════════════════════════════════════════════════════════
     MODO DE OPERAÇÃO
  ════════════════════════════════════════════════════════════ */
  function applyMode(mode, opts = {}) {
    const { silent = false } = opts;
    const nucleo = n();
    nucleo.STATE.modo = mode;
    const isDemo = mode === "demo";
    const isProd = !isDemo;

    const prodBanner = $("prodModeBanner");
    if (prodBanner) prodBanner.style.display = isProd ? "flex" : "none";

    const badge = $("modeBadge");
    if (badge) {
      badge.textContent = isProd ? "PROD" : "DEMO";
      badge.style.background = isProd ? "rgba(239,68,68,.18)" : "rgba(234,179,8,.18)";
      badge.style.color      = isProd ? "#ef4444"             : "#eab308";
    }

    Object.entries(nucleo.PROVIDER_CFG).forEach(([key, cfg]) => {
      _rebuildProviderSelect(key, cfg, isDemo);
    });

    if (isProd) {
      Object.entries(nucleo.PROVIDER_CFG).forEach(([key, cfg]) => {
        const sel = $(cfg.selectId); if (!sel) return;
        if (sel.value === "mock" || !sel.value) sel.value = cfg.defaultRealMode;
        _updateProviderSelectStyle(sel);
      });
    }

    Object.values(nucleo.PROVIDER_CFG).forEach(cfg => {
      const overlay = $(cfg.overlayId);
      if (overlay) overlay.style.display = isDemo ? "flex" : "none";
    });

    REAL_FIELD_IDS.forEach(id => {
      const el = $(id); if (!el) return;
      el.disabled      = isDemo;
      el.style.opacity = isDemo ? ".35" : "1";
      el.style.cursor  = isDemo ? "not-allowed" : "";
    });

    _updateIdsSensorPanelVisibility(isProd);
    _updateFwSensorPanelVisibility(isProd);
    _updateIntegrationHint(isDemo);
    _updateAllProviderModeBadges();

    if (isProd && !silent) {
      _activateAllProviders();
      _injectConnectButtons();
      _injectConnectAllButton();
    }

    if (isDemo && !silent) {
      _deactivateAllProviders();
      _removeConnectButtons();
      _removeConnectAllButton();
    }

    const { PROVIDER_CFG, PROV_STATUS, STATE } = nucleo;
    Object.keys(PROVIDER_CFG).forEach(p => {
      const prov   = STATE.providers?.[p] || {};
      const sel    = $(PROVIDER_CFG[p].selectId);
      const isReal = sel ? sel.value !== "mock" : prov.mode !== "mock";

      if (!prov.active) {
        PROV_STATUS[p] = "off";
        setProviderStatus(p, "off", "Desconectado");
      } else if (isDemo || !isReal) {
        PROV_STATUS[p] = "mock";
        setProviderStatus(p, "mock", "Mock ativo");
      }
    });

    _manageSensorPolling(isProd);
    _manageFwSensorPolling(isProd);
    nucleo.renderStatusBar();

    if (!silent) {
      nucleo.logDiag("INFO", isProd
        ? "Modo Produção — providers ativos, pronto para conectar."
        : "Modo Demo — integrações bloqueadas.");
    }
  }

  function _rebuildProviderSelect(key, cfg, isDemo) {
    const sel = $(cfg.selectId); if (!sel) return;
    const currentVal = sel.value;
    const options    = isDemo ? cfg.demoOptions : cfg.prodOptions;
    sel.innerHTML = options.map(o =>
      `<option value="${o.value}"${o.disabled ? " disabled" : ""}>${o.label}</option>`
    ).join("");
    const exists = options.find(o => o.value === currentVal && !o.disabled);
    sel.value    = exists ? currentVal : (options.find(o => !o.disabled)?.value || options[0].value);
    sel.disabled      = isDemo;
    sel.style.opacity = isDemo ? ".5" : "1";
    _updateProviderSelectStyle(sel);
  }

  function _updateProviderSelectStyle(sel) {
    if (!sel) return;
    sel.style.borderColor = sel.value !== "mock" ? "rgba(34,197,94,.5)" : "";
  }

  function _updateIntegrationHint(isDemo) {
    const hint = $("integracoesHint"); if (!hint) return;
    if (isDemo) {
      hint.className = "cfg-integrations-hint cfg-integrations-hint--demo";
      hint.innerHTML = `
        <i class="bi bi-lock-fill"></i>
        <span>
          Modo <strong>Demo</strong> — integrações bloqueadas.
          Mude para <strong>Produção</strong> para configurar AdGuard, Suricata e Firewall reais.
        </span>`;
    } else {
      hint.className = "cfg-integrations-hint cfg-integrations-hint--prod";
      hint.innerHTML = `
        <i class="bi bi-unlock-fill"></i>
        <span>
          Modo <strong>Produção</strong> ativo — configure as credenciais e conecte cada provider,
          ou use <strong>Conectar Todos</strong> para testar de uma vez.
        </span>`;
    }
  }

  function _updateAllProviderModeBadges() {
    const { PROVIDER_CFG } = n();
    Object.entries(PROVIDER_CFG).forEach(([, cfg]) => {
      const badge = $(cfg.badgeId); if (!badge) return;
      const sel   = $(cfg.selectId);
      const isReal = sel ? sel.value !== "mock" : false;
      badge.textContent = isReal ? "REAL" : "MOCK";
      badge.className   = `cfg-provider-mode-badge cfg-provider-mode-badge--${isReal ? "real" : "mock"}`;
    });
  }

  /* ════════════════════════════════════════════════════════════
     ATIVAR / DESATIVAR TODOS
  ════════════════════════════════════════════════════════════ */
  function _activateAllProviders() {
    const { PROVIDER_CFG, PROV_STATUS } = n();
    Object.entries(PROVIDER_CFG).forEach(([key, cfg]) => {
      const toggle = $(cfg.toggleId); if (!toggle) return;
      if (!toggle.checked) {
        toggle.checked = true;
        const sel    = $(cfg.selectId);
        const isReal = sel ? sel.value !== "mock" : false;
        PROV_STATUS[key] = isReal ? "warn" : "mock";
        setProviderStatus(key, PROV_STATUS[key], isReal ? "Ativo — clique em Conectar" : "Mock ativo");
      }
    });
    n().renderStatusBar();
  }

  function _deactivateAllProviders() {
    const { PROVIDER_CFG, PROV_STATUS } = n();
    Object.entries(PROVIDER_CFG).forEach(([key, cfg]) => {
      const toggle = $(cfg.toggleId); if (!toggle) return;
      toggle.checked = false;
      PROV_STATUS[key] = "off";
      setProviderStatus(key, "off", "Desconectado");
    });
    n().renderStatusBar();
  }

  /* ════════════════════════════════════════════════════════════
     BOTÕES CONNECT
  ════════════════════════════════════════════════════════════ */
  function _injectConnectButtons() {
    const { PROVIDER_CFG, capitalize } = n();
    Object.entries(PROVIDER_CFG).forEach(([key, cfg]) => {
      if ($(`btnConnect_${key}`)) return;
      const actionsEl = $(`btnTest${capitalize(key)}`)?.closest(".cfg-connector__actions");
      if (!actionsEl) return;
      const btn = document.createElement("button");
      btn.id        = `btnConnect_${key}`;
      btn.className = "cfg-test-btn cfg-connect-btn";
      btn.style.cssText = `
        background:rgba(34,197,94,.1);border-color:rgba(34,197,94,.35);
        color:#22c55e;font-weight:600;margin-bottom:8px;`;
      btn.innerHTML = `<i class="bi bi-plug-fill"></i> Conectar ${cfg.label}`;
      btn.addEventListener("click", () => _connectProvider(key));
      actionsEl.insertBefore(btn, actionsEl.firstChild);
    });
  }

  function _removeConnectButtons() {
    Object.keys(n().PROVIDER_CFG).forEach(key => $(`btnConnect_${key}`)?.remove());
  }

  function _injectConnectAllButton() {
    if ($("btnConnectAll")) return;
    const btn = document.createElement("button");
    btn.id        = "btnConnectAll";
    btn.className = "cfg-save-all-btn";
    btn.style.cssText = `
      background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.35);
      color:#22c55e;margin-left:8px;transition:all .2s;`;
    btn.innerHTML = `<i class="bi bi-lightning-charge-fill"></i> Conectar Todos`;
    btn.addEventListener("click", _connectAll);
    btn.addEventListener("mouseover", () => { btn.style.background = "rgba(34,197,94,.2)"; });
    btn.addEventListener("mouseout",  () => { btn.style.background = "rgba(34,197,94,.12)"; });
    const saveBtn = $("cfgSaveAllBtn");
    saveBtn?.parentElement?.insertBefore(btn, saveBtn.nextSibling);
  }

  function _removeConnectAllButton() { $("btnConnectAll")?.remove(); }

  /* ════════════════════════════════════════════════════════════
     CONEXÃO — INDIVIDUAL
  ════════════════════════════════════════════════════════════ */
  async function _connectProvider(key) {
    const { capitalize, apiFetch, collectStateFromForm, fmtLastSync, logDiag, showToast } = n();
    const connectBtn = $(`btnConnect_${key}`);
    const testBtn    = $(`btnTest${capitalize(key)}`);
    const resEl      = $(`testResult${capitalize(key)}`);
    const origHtml   = connectBtn ? connectBtn.innerHTML : "";

    if (connectBtn) { connectBtn.innerHTML = `<i class="bi bi-hourglass-split"></i> Conectando...`; connectBtn.disabled = true; }
    if (testBtn)    testBtn.disabled = true;
    if (resEl)      { resEl.textContent = "Verificando..."; resEl.className = "cfg-test-result"; }

    try { await apiFetch("/configuracoes/api/salvar/", "POST", collectStateFromForm()); } catch (_) {}

    try {
      const data = await apiFetch("/configuracoes/api/testar-provider/", "POST", { provider: key });
      if (data.ok) {
        const isMock    = data.status === "mock";
        const newStatus = data.status === "ok" ? "ok" : isMock ? "mock" : "warn";
        setProviderStatus(key, newStatus, data.status === "ok" ? "✓ Conectado" : isMock ? "Mock ativo" : "Aguardando");
        if (resEl) { resEl.textContent = `✓ ${data.msg}`; resEl.className = `cfg-test-result cfg-test-result--${isMock ? "mock" : "ok"}`; }
        const ls = $(`${key}LastSync`);
        if (ls) ls.textContent = fmtLastSync(Date.now());
        if (connectBtn) {
          connectBtn.innerHTML = `<i class="bi bi-check-circle-fill"></i> Conectado`;
          connectBtn.style.background = "rgba(34,197,94,.2)";
          setTimeout(() => { connectBtn.innerHTML = origHtml; connectBtn.style.background = "rgba(34,197,94,.1)"; }, 3000);
        }
        if (key === "ids" && data.status === "ok") await loadSensores();
        if (key === "fw"  && data.status === "ok") await loadFwSensores();
        logDiag("OK",  `${key.toUpperCase()}: ${data.msg}`);
        showToast(`${key.toUpperCase()} — ${data.msg}`);
      } else {
        setProviderStatus(key, "erro", "Erro de conexão");
        if (resEl) { resEl.textContent = `✗ ${data.msg}`; resEl.className = "cfg-test-result cfg-test-result--err"; }
        if (connectBtn) {
          connectBtn.innerHTML = `<i class="bi bi-x-circle-fill"></i> Falhou — tentar novamente`;
          connectBtn.style.background = "rgba(239,68,68,.1)"; connectBtn.style.borderColor = "rgba(239,68,68,.35)"; connectBtn.style.color = "#ef4444";
          setTimeout(() => { connectBtn.innerHTML = origHtml; connectBtn.style.background = "rgba(34,197,94,.1)"; connectBtn.style.borderColor = "rgba(34,197,94,.35)"; connectBtn.style.color = "#22c55e"; }, 4000);
        }
        if (key === "ids") await loadSensores();
        if (key === "fw")  await loadFwSensores();
        logDiag("ERRO", `${key.toUpperCase()}: ${data.msg}`);
        showToast(`${key.toUpperCase()} falhou: ${data.msg}`, "erro");
      }
    } catch (e) {
      setProviderStatus(key, "erro", "Falha de rede");
      if (resEl) { resEl.textContent = `✗ ${e.message}`; resEl.className = "cfg-test-result cfg-test-result--err"; }
      if (connectBtn) { connectBtn.innerHTML = origHtml; connectBtn.style.cssText = "background:rgba(34,197,94,.1);border-color:rgba(34,197,94,.35);color:#22c55e;"; }
      logDiag("ERRO", `Teste ${key}: ${e.message}`);
    } finally {
      if (connectBtn) connectBtn.disabled = false;
      if (testBtn)    testBtn.disabled    = false;
    }
  }

  /* ════════════════════════════════════════════════════════════
     CONECTAR TODOS
  ════════════════════════════════════════════════════════════ */
  async function _connectAll() {
    const { apiFetch, collectStateFromForm, PROVIDER_CFG, fmtLastSync, logDiag, showToast } = n();
    const btn      = $("btnConnectAll");
    const origHtml = btn ? btn.innerHTML : "";
    if (btn) { btn.innerHTML = `<i class="bi bi-hourglass-split"></i> Conectando...`; btn.disabled = true; }

    try { await apiFetch("/configuracoes/api/salvar/", "POST", collectStateFromForm()); } catch (_) {}

    let successCount = 0;
    for (const key of ["dns", "ids", "fw"]) {
      const toggle = $(PROVIDER_CFG[key].toggleId);
      if (!toggle?.checked) continue;
      const connectBtn = $(`btnConnect_${key}`);
      const resEl      = $(`testResult${n().capitalize(key)}`);
      if (connectBtn) { connectBtn.innerHTML = `<i class="bi bi-hourglass-split"></i> Conectando...`; connectBtn.disabled = true; }
      if (resEl) { resEl.textContent = "Verificando..."; resEl.className = "cfg-test-result"; }
      try {
        const data = await apiFetch("/configuracoes/api/testar-provider/", "POST", { provider: key });
        if (data.ok) {
          const isMock = data.status === "mock";
          setProviderStatus(key, data.status === "ok" ? "ok" : isMock ? "mock" : "warn",
            data.status === "ok" ? "✓ Conectado" : isMock ? "Mock ativo" : "Aguardando");
          if (resEl) { resEl.textContent = `✓ ${data.msg}`; resEl.className = `cfg-test-result cfg-test-result--${isMock ? "mock" : "ok"}`; }
          if (connectBtn) { connectBtn.innerHTML = `<i class="bi bi-check-circle-fill"></i> Conectado`; connectBtn.disabled = false; }
          if (!isMock) successCount++;
          if (key === "ids" && data.status === "ok") await loadSensores();
          if (key === "fw"  && data.status === "ok") await loadFwSensores();
          const ls = $(`${key}LastSync`);
          if (ls) ls.textContent = fmtLastSync(Date.now());
          logDiag("OK", `[Conectar Todos] ${key.toUpperCase()}: ${data.msg}`);
        } else {
          setProviderStatus(key, "erro", "Erro de conexão");
          if (resEl) { resEl.textContent = `✗ ${data.msg}`; resEl.className = "cfg-test-result cfg-test-result--err"; }
          if (connectBtn) { connectBtn.innerHTML = `<i class="bi bi-x-circle-fill"></i> Falhou`; connectBtn.disabled = false; }
          if (key === "ids") await loadSensores();
          if (key === "fw")  await loadFwSensores();
          logDiag("ERRO", `[Conectar Todos] ${key.toUpperCase()}: ${data.msg}`);
        }
      } catch (e) {
        setProviderStatus(key, "erro", "Falha de rede");
        if (connectBtn) { connectBtn.innerHTML = `<i class="bi bi-x-circle-fill"></i> Falhou`; connectBtn.disabled = false; }
        logDiag("ERRO", `[Conectar Todos] ${key}: ${e.message}`);
      }
    }

    if (btn) {
      const active = ["dns","ids","fw"].filter(p => $(n().PROVIDER_CFG[p].toggleId)?.checked);
      const allOk  = successCount === active.length;
      btn.innerHTML    = allOk ? `<i class="bi bi-check-circle-fill"></i> Todos Conectados` : `<i class="bi bi-exclamation-triangle-fill"></i> Verificar Erros`;
      btn.style.background  = allOk ? "rgba(34,197,94,.2)"  : "rgba(234,179,8,.15)";
      btn.style.borderColor = allOk ? "rgba(34,197,94,.4)"  : "rgba(234,179,8,.4)";
      btn.style.color       = allOk ? "#22c55e"             : "#eab308";
      btn.disabled = false;
      setTimeout(() => { btn.innerHTML = origHtml; btn.style.background = "rgba(34,197,94,.12)"; btn.style.borderColor = "rgba(34,197,94,.35)"; btn.style.color = "#22c55e"; }, 4000);
    }
    showToast(successCount > 0 ? `${successCount} provider(s) conectado(s) ✓` : "Nenhum provider conectou", successCount > 0 ? "ok" : "erro");
  }

  /* ════════════════════════════════════════════════════════════
     STATUS VISUAL
  ════════════════════════════════════════════════════════════ */
  function setProviderStatus(key, status, msg) {
    const { capitalize, PROV_STATUS } = n();
    const el = $(`status${capitalize(key)}`); if (!el) return;
    const colors = {
      ok:   { bg: "#22c55e", sh: "#22c55e66" },
      mock: { bg: "#eab308", sh: "#eab30866" },
      warn: { bg: "#f97316", sh: "#f9731666" },
      erro: { bg: "#ef4444", sh: "#ef444466" },
      off:  { bg: "#555",    sh: "transparent" },
    };
    const c = colors[status] || colors.off;
    el.innerHTML = `<span class="cfg-conn-dot" style="background:${c.bg};box-shadow:0 0 6px ${c.sh}"></span>${msg}`;
    PROV_STATUS[key] = status;
    n().renderStatusBar();
    _refreshConnectorBorders();
  }

  function _refreshConnectorBorders() {
    const { PROVIDER_CFG, PROV_STATUS, capitalize } = n();
    Object.keys(PROVIDER_CFG).forEach(p => {
      const connEl = $(`connector${capitalize(p)}`); if (!connEl) return;
      connEl.style.borderColor = { ok: "rgba(34,197,94,.3)", mock: "rgba(234,179,8,.12)", warn: "rgba(249,115,22,.2)", erro: "rgba(239,68,68,.3)", off: "" }[PROV_STATUS[p]] || "";
    });
  }

  /* ════════════════════════════════════════════════════════════
     PAINEL SENSORES IDS
  ════════════════════════════════════════════════════════════ */
  function _updateIdsSensorPanelVisibility(isProd) {
    const panel = $("idsSensorPanel"); if (!panel) return;
    const sel   = $("idsMode");
    const show  = isProd && sel && sel.value !== "mock";
    panel.style.display = show ? "block" : "none";
    if (show) loadSensores();
  }

  async function loadSensores() {
    const list = $("idsSensorList"); if (!list) return;
    const online = $("idsSensorOnline"), offline = $("idsSensorOffline"), total = $("idsSensorTotal");
    try {
      const data = await n().apiFetch("/configuracoes/api/sensor-status/");
      if (!data.ok) throw new Error(data.erro || "Erro");
      if (online)  online.textContent  = data.online;
      if (offline) offline.textContent = data.total - data.online;
      if (total)   total.textContent   = data.total;
      list.innerHTML = data.sensores.length === 0 ? _renderSensorVazio("ms_sensor.py") : data.sensores.map(s => _renderSensorCard(s)).join("");
    } catch (e) { list.innerHTML = _renderSensorErro(e.message); }
  }

  function _manageSensorPolling(isProd) {
    if (_sensorPollingTimer) { clearInterval(_sensorPollingTimer); _sensorPollingTimer = null; }
    if (isProd) _sensorPollingTimer = setInterval(() => { const p = $("idsSensorPanel"); if (p && p.style.display !== "none") loadSensores(); }, 15000);
  }

  /* ════════════════════════════════════════════════════════════
     PAINEL SENSORES FIREWALL — v2: agente + botão Testar Agente
  ════════════════════════════════════════════════════════════ */
  function _updateFwSensorPanelVisibility(isProd) {
    const panel = $("fwSensorPanel"); if (!panel) return;
    const sel   = $("fwMode");
    const show  = isProd && sel && sel.value !== "mock";
    panel.style.display = show ? "block" : "none";
    if (show) loadFwSensores();
  }

  async function loadFwSensores() {
    const list = $("fwSensorList"); if (!list) return;
    const online = $("fwSensorOnline"), offline = $("fwSensorOffline"), total = $("fwSensorTotal");
    try {
      const data = await n().apiFetch("/configuracoes/api/fw-sensor-status/");
      if (!data.ok) throw new Error(data.erro || "Erro");
      if (online)  online.textContent  = data.online;
      if (offline) offline.textContent = data.total - data.online;
      if (total)   total.textContent   = data.total;
      list.innerHTML = data.sensores.length === 0 ? _renderSensorVazio("ms_firewall.py") : data.sensores.map(s => _renderFwSensorCard(s)).join("");
      // Registra listeners dos botões "Testar Agente" após render
      list.querySelectorAll("[data-test-agente]").forEach(btn => {
        btn.addEventListener("click", () => _testarAgente(btn.dataset.testAgente, btn.dataset.porta));
      });
    } catch (e) { list.innerHTML = _renderSensorErro(e.message); }
  }

  /**
   * v2: Testa o agente Flask diretamente via GET :{porta}/status
   * Usa o Django como proxy para evitar problemas de CORS/rede.
   */
  async function _testarAgente(ip, porta) {
    const { apiFetch, logDiag, showToast } = n();
    const btnId = `btnAgente_${ip.replace(/\./g, "_")}`;
    const btn   = document.getElementById(btnId);
    if (btn) { btn.innerHTML = `<i class="bi bi-hourglass-split"></i>`; btn.disabled = true; }

    try {
      const data = await apiFetch("/configuracoes/api/testar-agente/", "POST", { ip, porta: parseInt(porta) });
      if (data.ok) {
        showToast(`Agente ${ip}:${porta} — ATIVO ✓`);
        logDiag("OK", `Agente ${ip}:${porta} respondeu — versão ${data.versao || "?"}`);
        if (btn) { btn.innerHTML = `<i class="bi bi-check-circle-fill"></i> OK`; btn.style.color = "#22c55e"; }
      } else {
        showToast(`Agente ${ip}:${porta} — ${data.msg}`, "erro");
        logDiag("AVISO", `Agente ${ip}:${porta} — ${data.msg}`);
        if (btn) { btn.innerHTML = `<i class="bi bi-x-circle"></i> Falhou`; btn.style.color = "#ef4444"; }
      }
    } catch (e) {
      showToast(`Agente ${ip}:${porta} — falha de rede`, "erro");
      logDiag("ERRO", `Agente ${e.message}`);
      if (btn) { btn.innerHTML = `<i class="bi bi-x-circle"></i> Erro`; btn.style.color = "#ef4444"; }
    } finally {
      if (btn) {
        btn.disabled = false;
        setTimeout(() => { if (btn) { btn.innerHTML = `<i class="bi bi-activity"></i> Testar Agente`; btn.style.color = ""; } }, 3000);
      }
    }
  }

  function _manageFwSensorPolling(isProd) {
    if (_fwSensorPollingTimer) { clearInterval(_fwSensorPollingTimer); _fwSensorPollingTimer = null; }
    if (isProd) _fwSensorPollingTimer = setInterval(() => { const p = $("fwSensorPanel"); if (p && p.style.display !== "none") loadFwSensores(); }, 15000);
  }

  /* ════════════════════════════════════════════════════════════
     RENDER HELPERS
  ════════════════════════════════════════════════════════════ */
  function _renderSensorVazio(script) {
    return `
      <div style="padding:20px;text-align:center;background:rgba(255,255,255,.02);
           border:1px dashed rgba(255,255,255,.1);border-radius:8px">
        <i class="bi bi-cpu" style="font-size:28px;color:var(--text-dim);display:block;margin-bottom:8px"></i>
        <p style="font-size:12px;color:var(--text-dim);margin-bottom:4px">Nenhum sensor cadastrado ainda.</p>
        <p style="font-size:10px;color:#555;font-family:var(--font-mono)">
          Execute <code style="color:#ef4444">sudo python ${script}</code> no Linux para registrar automaticamente.
        </p>
      </div>`;
  }

  function _renderSensorErro(msg) {
    return `
      <div style="padding:12px;background:rgba(239,68,68,.07);border:1px solid rgba(239,68,68,.2);
           border-radius:6px;font-size:11px;color:#ef4444">
        <i class="bi bi-exclamation-triangle"></i> Falha ao carregar sensores: ${msg}
      </div>`;
  }

  function _renderSensorCard(s) {
    const { fmtTempo } = n();
    const isOnline  = s.online;
    const dotColor  = isOnline ? "#22c55e" : "#ef4444";
    const dotShadow = isOnline ? "#22c55e88" : "#ef444488";
    const borderClr = isOnline ? "rgba(34,197,94,.2)" : "rgba(239,68,68,.15)";
    const statusClr = isOnline ? "#22c55e" : "#ef4444";
    const tempo     = fmtTempo(s.segundos_atras);
    const criado    = new Date(s.criado_em).toLocaleDateString("pt-BR");

    return `
      <div style="display:flex;align-items:center;gap:12px;padding:10px 14px;margin-bottom:8px;
           background:rgba(255,255,255,.03);border:1px solid ${borderClr};border-radius:8px;transition:background .2s"
           onmouseover="this.style.background='rgba(255,255,255,.05)'" onmouseout="this.style.background='rgba(255,255,255,.03)'">
        <span style="flex-shrink:0;width:10px;height:10px;border-radius:50%;background:${dotColor};box-shadow:0 0 8px ${dotShadow};display:inline-block"></span>
        <div style="flex:1;min-width:0">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
            <strong style="font-size:13px;color:var(--text-bright)">${s.nome}</strong>
            <span style="font-size:9px;font-weight:700;color:${statusClr};background:${isOnline ? "rgba(34,197,94,.12)" : "rgba(239,68,68,.12)"};padding:1px 6px;border-radius:3px">${isOnline ? "ONLINE" : "OFFLINE"}</span>
            ${!s.ativo ? '<span style="font-size:9px;color:#555;background:rgba(255,255,255,.05);padding:1px 6px;border-radius:3px">INATIVO</span>' : ''}
          </div>
          <div style="display:flex;gap:16px;margin-top:3px;flex-wrap:wrap">
            <span style="font-size:10px;color:var(--text-dim);font-family:var(--font-mono)"><i class="bi bi-hdd-network" style="font-size:9px"></i> ${s.ip}</span>
            <span style="font-size:10px;color:var(--text-dim)"><i class="bi bi-clock" style="font-size:9px"></i> ${tempo}</span>
            <span style="font-size:10px;color:#555">Cadastrado: ${criado}</span>
          </div>
        </div>
        <i class="bi bi-cpu" style="font-size:18px;color:${isOnline ? "#ef4444" : "#444"};flex-shrink:0"></i>
      </div>`;
  }

  /** v2: card FW com agente_porta + botão Testar Agente */
  function _renderFwSensorCard(s) {
    const { fmtTempo, STATE } = n();
    const isOnline    = s.online;
    const dotColor    = isOnline ? "#22c55e" : "#ef4444";
    const dotShadow   = isOnline ? "#22c55e88" : "#ef444488";
    const borderClr   = isOnline ? "rgba(34,197,94,.2)" : "rgba(239,68,68,.15)";
    const statusClr   = isOnline ? "#22c55e" : "#ef4444";
    const tempo       = fmtTempo(s.segundos_atras);
    const criado      = new Date(s.criado_em).toLocaleDateString("pt-BR");
    const ev1h        = (s.eventos_1h   || 0).toLocaleString("pt-BR");
    const evTotal     = (s.total_eventos || 0).toLocaleString("pt-BR");
    const agentPorta  = STATE.providers?.fw?.agente_porta || 8765;
    const btnId       = `btnAgente_${s.ip.replace(/\./g, "_")}`;

    return `
      <div style="display:flex;align-items:center;gap:12px;padding:10px 14px;margin-bottom:8px;
           background:rgba(255,255,255,.03);border:1px solid ${borderClr};border-radius:8px;transition:background .2s"
           onmouseover="this.style.background='rgba(255,255,255,.05)'" onmouseout="this.style.background='rgba(255,255,255,.03)'">
        <span style="flex-shrink:0;width:10px;height:10px;border-radius:50%;background:${dotColor};box-shadow:0 0 8px ${dotShadow};display:inline-block"></span>
        <div style="flex:1;min-width:0">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
            <strong style="font-size:13px;color:var(--text-bright)">${s.nome}</strong>
            <span style="font-size:9px;font-weight:700;color:${statusClr};background:${isOnline ? "rgba(34,197,94,.12)" : "rgba(239,68,68,.12)"};padding:1px 6px;border-radius:3px">${isOnline ? "ONLINE" : "OFFLINE"}</span>
            ${!s.ativo ? '<span style="font-size:9px;color:#555;background:rgba(255,255,255,.05);padding:1px 6px;border-radius:3px">INATIVO</span>' : ''}
          </div>
          <div style="display:flex;gap:16px;margin-top:3px;flex-wrap:wrap">
            <span style="font-size:10px;color:var(--text-dim);font-family:var(--font-mono)"><i class="bi bi-hdd-network" style="font-size:9px"></i> ${s.ip}</span>
            <span style="font-size:10px;color:var(--text-dim)"><i class="bi bi-clock" style="font-size:9px"></i> ${tempo}</span>
            <span style="font-size:10px;color:var(--text-dim)"><i class="bi bi-activity" style="font-size:9px"></i> ${ev1h} ev/1h</span>
            <span style="font-size:10px;color:#555">Total: ${evTotal} eventos</span>
            <span style="font-size:10px;color:#555">Cadastrado: ${criado}</span>
          </div>
          <!-- v2: agente info -->
          <div style="display:flex;align-items:center;gap:8px;margin-top:5px">
            <span style="font-size:10px;color:var(--text-dim);font-family:var(--font-mono)">
              <i class="bi bi-server" style="font-size:9px"></i> Agente: ${s.ip}:${agentPorta}
            </span>
            <button
              id="${btnId}"
              data-test-agente="${s.ip}"
              data-porta="${agentPorta}"
              style="padding:2px 8px;font-size:9px;font-family:var(--font-mono);
                     background:rgba(59,130,246,.1);border:1px solid rgba(59,130,246,.25);
                     border-radius:3px;color:#3b82f6;cursor:pointer;transition:all .15s"
              onmouseover="this.style.background='rgba(59,130,246,.2)'"
              onmouseout="this.style.background='rgba(59,130,246,.1)'">
              <i class="bi bi-activity"></i> Testar Agente
            </button>
          </div>
        </div>
        <i class="bi bi-shield-fill" style="font-size:18px;color:${isOnline ? "#3b82f6" : "#444"};flex-shrink:0"></i>
      </div>`;
  }

  /* ════════════════════════════════════════════════════════════
     LISTENERS
  ════════════════════════════════════════════════════════════ */
  document.addEventListener("DOMContentLoaded", () => {
    const { PROVIDER_CFG, STATE, PROV_STATUS, showToast, logDiag, capitalize, renderStatusBar, _updateUrlIndicator } = n();

    $("cfgModeSelect")?.addEventListener("change", function () {
      applyMode(this.value);
      showToast(this.value === "prod" ? "⚡ Modo Produção ativado" : "🔒 Modo Demo ativado");
    });

    Object.values(PROVIDER_CFG).forEach(cfg => {
      $(cfg.selectId)?.addEventListener("change", function () {
        if (STATE.modo === "demo") return;
        _updateProviderSelectStyle(this);
        _updateAllProviderModeBadges();
        if (cfg.selectId === "idsMode") _updateIdsSensorPanelVisibility(STATE.modo === "prod");
        if (cfg.selectId === "fwMode")  _updateFwSensorPanelVisibility(STATE.modo === "prod");
      });
    });

    $("dnsUrl")?.addEventListener("input", function () {
      n()._updateUrlIndicator("dnsUrl", "dnsUrlStatus", this.value.trim());
    });

    Object.entries(PROVIDER_CFG).forEach(([key, cfg]) => {
      $(cfg.toggleId)?.addEventListener("change", function () {
        const isDemo = STATE.modo === "demo";
        const sel    = $(cfg.selectId);
        const isReal = sel ? sel.value !== "mock" : false;
        if (this.checked) {
          const status = (isDemo || !isReal) ? "mock" : "warn";
          PROV_STATUS[key] = status;
          setProviderStatus(key, status, status === "mock" ? "Mock ativo" : "Ativo — clique em Conectar");
          if (key === "ids" && !isDemo && isReal) _updateIdsSensorPanelVisibility(true);
          if (key === "fw"  && !isDemo && isReal) _updateFwSensorPanelVisibility(true);
        } else {
          PROV_STATUS[key] = "off";
          setProviderStatus(key, "off", "Desconectado");
          if (key === "ids") { const p = $("idsSensorPanel"); if (p) p.style.display = "none"; }
          if (key === "fw")  { const p = $("fwSensorPanel");  if (p) p.style.display = "none"; }
        }
        renderStatusBar();
      });
    });

    document.querySelectorAll(".cfg-test-btn[data-provider]").forEach(btn => {
      btn.addEventListener("click", async () => { await _connectProvider(btn.dataset.provider); });
    });

    $("btnRefreshSensors")?.addEventListener("click",   () => { loadSensores();   logDiag("INFO", "Lista de sensores IDS atualizada."); });
    $("btnRefreshFwSensors")?.addEventListener("click", () => { loadFwSensores(); logDiag("INFO", "Lista de sensores Firewall atualizada."); });
  });

  /* ════════════════════════════════════════════════════════════
     EXPOR
  ════════════════════════════════════════════════════════════ */
  window.CfgConexoes = {
    applyMode,
    setProviderStatus,
    loadSensores,
    loadFwSensores,
  };

})();