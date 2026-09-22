(() => {
  "use strict";
  document.addEventListener("DOMContentLoaded", () => {
    const runtime = window.MoonShieldDevices; if (!runtime) return;
    const $ = (id) => document.getElementById(id);

    // Scan Modal Elements
    const scanModal = $("devScanModal"), scanOverlay = $("devScanOverlay");
    const scanList = $("devScanNetworks"), scanMsg = $("devScanMessage"), scanConfirm = $("devScanConfirm");
    const quickCard = $("devModeQuickCard"), advCard = $("devModeAdvancedCard"), advRadio = $("devAdvancedMode");
    const advReason = $("devAdvancedReason");
    const scanResult = $("devScanResult"), scanResultSub = $("devScanResultSub");
    const scanBtnLabel = $("devScanBtnLabel"), scanBtnIcon = $("devScanBtnIcon");

    // Monitor Modal Elements
    const monModal = $("devMonitorModal"), monOverlay = $("devMonitorOverlay");
    const monList = $("devMonitorNetworks"), monSave = $("devMonitorSave");
    const monEnabled = $("devMonitorEnabled"), monInterval = $("devMonitorInterval");
    const monBtnLabel = $("devMonitorBtnLabel"), monBtnIcon = $("devMonitorBtnIcon");

    let _capabilities = { advanced: false, reason: "Nmap não verificado." };
    let _monitorConfig = { enabled: false, interval_minutes: 3, networks: [] };
    let _availableNetworks = [];

    // Utilities
    const noteScan = (msg = "", kind = "") => { if (scanMsg) { scanMsg.textContent = msg; scanMsg.className = `dev-scan-message${kind ? ` dev-scan-message--${kind}` : ""}`; } };

    const closeScan = () => { if (scanModal) scanModal.hidden = true; if (scanOverlay) scanOverlay.hidden = true; noteScan(); if (scanResult) scanResult.hidden = true; };
    const closeMon = () => { if (monModal) monModal.hidden = true; if (monOverlay) monOverlay.hidden = true; };

    // Mode Selection Logic
    const setScanMode = (mode) => {
      if (mode === "advanced" && !_capabilities.advanced) return;
      document.querySelectorAll('input[name="deviceScanMode"]').forEach(r => r.checked = (r.value === mode));
      if (quickCard) quickCard.classList.toggle("dev-scan-mode-card--active", mode === "quick");
      if (advCard) advCard.classList.toggle("dev-scan-mode-card--active", mode === "advanced");
    };

    if (quickCard) quickCard.addEventListener("click", (e) => { e.preventDefault(); setScanMode("quick"); });
    if (advCard) advCard.addEventListener("click", (e) => { e.preventDefault(); setScanMode("advanced"); });

    function applyCapabilities() {
      if (advRadio) advRadio.disabled = !_capabilities.advanced;
      if (advCard) advCard.classList.toggle("dev-scan-mode-card--disabled", !_capabilities.advanced);
      if (advReason) advReason.textContent = _capabilities.advanced ? "Nmap, serviços e identificação adicional de sistema." : (_capabilities.reason || "Nmap não instalado.");
      if (!_capabilities.advanced) setScanMode("quick");
    }

    // Render Networks (reusable logic)
    const updateScanSelection = () => {
      if (!scanList) return;
      scanList.querySelectorAll(".dev-scan-network").forEach((row) => {
        const input = row.querySelector("input"), status = row.querySelector(".dev-scan-network__status");
        if (status) status.textContent = input.disabled ? "Indisponível" : input.checked ? (scanList.dataset.scanning === "true" ? "Escaneando…" : "Selecionado") : "Não selecionado";
      });
    };

    function renderScanNetworks(networks) {
      if (!scanList) return;
      scanList.innerHTML = networks.length ? "" : '<p class="dev-no-data">Nenhuma rede disponível para scan.</p>';
      networks.forEach((n) => {
        const label = document.createElement("label"), allowed = Boolean(n.allowed);
        label.className = `dev-scan-network${allowed ? "" : " dev-scan-network--disabled"}`;
        label.innerHTML = `<input type="checkbox" value="${runtime.escapeHtml(n.id)}"${n.selected && allowed ? " checked" : ""}${allowed ? "" : " disabled"}>
          <span><span class="dev-scan-network__name"><i class="bi ${n.role?.toLowerCase() === "wan" ? "bi-globe2" : "bi-diagram-3"}"></i> ${runtime.escapeHtml(n.role || "Rede")}</span>
          <span class="dev-scan-network__meta">${runtime.escapeHtml(n.interface || "—")}<span>${runtime.escapeHtml(n.cidr || "—")}</span></span>
          <span class="dev-scan-network__note">${allowed ? `${Number(n.device_count || 0)} dispositivos` : "Não autorizada pela topologia"}</span>
          <span class="dev-scan-network__status"></span></span>`;
        scanList.appendChild(label);
      });
      updateScanSelection();
    }

    function renderMonitorNetworks(networks) {
      if (!monList) return;
      monList.innerHTML = "";
      const eligible = networks.filter((n) => n.monitor_allowed);
      if (!eligible.length) { monList.innerHTML = '<p class="dev-cell-dim" style="padding:16px;">Nenhuma rede privada elegível para monitoramento.</p>'; return; }
      eligible.forEach((n) => {
        const label = document.createElement("label");
        label.className = "dev-scan-network";
        const checked = _monitorConfig.networks.includes(n.id);
        label.innerHTML = `<input type="checkbox" value="${runtime.escapeHtml(n.id)}"${checked ? " checked" : ""}>
          <span><span class="dev-scan-network__name"><i class="bi ${n.role?.toLowerCase() === "wan" ? "bi-globe2" : "bi-diagram-3"}"></i> ${runtime.escapeHtml(n.role || "Rede")}</span>
          <span class="dev-scan-network__meta">${runtime.escapeHtml(n.interface || "—")}<span>${runtime.escapeHtml(n.cidr || "—")}</span></span></span>`;
        monList.appendChild(label);
      });
    }

    if (scanList) scanList.addEventListener("change", updateScanSelection);

    // Open functions
    const openScan = async () => {
      if (scanModal) { scanModal.hidden = false; if (scanResult) scanResult.hidden = true; }
      if (scanOverlay) scanOverlay.hidden = false;
      if (scanConfirm) scanConfirm.hidden = false;
      noteScan("Consultando redes e configurações…", "working");
      const payload = await runtime.loadNetworks();
      _availableNetworks = Array.isArray(payload.networks) ? payload.networks : [];
      if (payload.capabilities) { _capabilities = payload.capabilities; }
      applyCapabilities();
      renderScanNetworks(_availableNetworks);
      noteScan(_availableNetworks.length ? "" : "Nenhuma rede autorizada foi retornada.");
    };

    const openMonitor = async () => {
      if (monModal) monModal.hidden = false;
      if (monOverlay) monOverlay.hidden = false;
      const payload = await runtime.loadNetworks();
      _availableNetworks = Array.isArray(payload.networks) ? payload.networks : [];
      if (payload.monitor) {
          _monitorConfig = { enabled: Boolean(payload.monitor.enabled), interval_minutes: payload.monitor.interval_minutes || 3, networks: Array.isArray(payload.monitor.networks) ? payload.monitor.networks : [] };
      }
      if (monEnabled) monEnabled.checked = _monitorConfig.enabled;
      if (monInterval) monInterval.value = String(_monitorConfig.interval_minutes);
      renderMonitorNetworks(_availableNetworks);
    };

    // Actions
    const doScan = async () => {
      const selectedNetworks = Array.from((scanList || document.createElement("div")).querySelectorAll("input:checked:not(:disabled)")).map((inp) => inp.value);
      if (!selectedNetworks.length) { noteScan("Selecione ao menos uma rede autorizada.", "error"); return; }
      const modeInput = document.querySelector('input[name="deviceScanMode"]:checked');
      const mode = modeInput?.value || "quick";

      if (scanConfirm) scanConfirm.disabled = true;
      if (scanList) scanList.dataset.scanning = "true";
      updateScanSelection();

      if (scanBtnLabel) scanBtnLabel.textContent = "Escaneando...";
      if (scanBtnIcon) scanBtnIcon.className = "bi bi-radar dev-scan-icon dev-spin";
      noteScan("");

      try {
        const response = await fetch(runtime.urls.scan, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRFToken": runtime.getCsrfToken() }, body: JSON.stringify({ networks: selectedNetworks, mode }) });
        const payload = await response.json();
        if (!response.ok || !payload.ok) throw new Error(payload.error || "O scan não foi iniciado.");

        // Success feedback
        if (scanResult) scanResult.hidden = false;
        if (scanResultSub) scanResultSub.textContent = `${Number(payload.found || 0)} dispositivos encontrados. Inventário atualizado.`;
        if (scanConfirm) scanConfirm.hidden = true; // hide confirm button temporarily

        await runtime.refreshInventory();
        await runtime.loadNetworks();

        // Auto close after small delay, keeping it long enough to see the green success card
        setTimeout(() => { if (scanModal && !scanModal.hidden) closeScan(); }, 3500);

      } catch (err) {
          noteScan(err.message || "Falha ao executar scan.", "error");
      } finally {
          if (scanConfirm) scanConfirm.disabled = false;
          if (scanList) delete scanList.dataset.scanning;
          updateScanSelection();
          if (scanBtnLabel) scanBtnLabel.textContent = "Iniciar scan";
          if (scanBtnIcon) scanBtnIcon.className = "bi bi-radar dev-scan-icon";
      }
    };

    const doSaveMonitor = async () => {
      const monitorNets = Array.from((monList || document.createElement("div")).querySelectorAll("input:checked")).map((inp) => inp.value);
      const body = { enabled: monEnabled?.checked ?? false, interval_minutes: parseInt(monInterval?.value || "3", 10), networks: monitorNets };

      if (monSave) monSave.disabled = true;
      if (monBtnLabel) monBtnLabel.textContent = "Salvando...";
      if (monBtnIcon) monBtnIcon.className = "bi bi-arrow-repeat dev-spin";

      try {
        const response = await fetch(runtime.urls.monitor, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRFToken": runtime.getCsrfToken() }, body: JSON.stringify(body) });
        const payload = await response.json();
        if (!response.ok || !payload.ok) throw new Error(payload.error || "Falha ao salvar monitoramento.");
        if (payload.monitor) { _monitorConfig = payload.monitor; }
        runtime.notify("Monitoramento atualizado.", "success");
        await runtime.loadNetworks();
        closeMon();
      } catch (err) {
          runtime.notify(err.message || "Falha ao salvar monitoramento.", "error");
      } finally {
          if (monSave) monSave.disabled = false;
          if (monBtnLabel) monBtnLabel.textContent = "Salvar";
          if (monBtnIcon) monBtnIcon.className = "bi bi-check-lg";
      }
    };

    // Event Listeners
    document.addEventListener("moonshield:scan:open", openScan);
    document.addEventListener("moonshield:monitor:open", openMonitor);

    $("devScanClose")?.addEventListener("click", closeScan);
    $("devScanCancel")?.addEventListener("click", closeScan);
    scanOverlay?.addEventListener("click", closeScan);
    scanConfirm?.addEventListener("click", doScan);

    $("devMonitorClose")?.addEventListener("click", closeMon);
    $("devMonitorCancel")?.addEventListener("click", closeMon);
    monOverlay?.addEventListener("click", closeMon);
    monSave?.addEventListener("click", doSaveMonitor);
  });
})();
