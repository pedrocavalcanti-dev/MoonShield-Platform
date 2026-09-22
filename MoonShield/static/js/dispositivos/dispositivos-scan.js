(() => {
  "use strict";
  document.addEventListener("DOMContentLoaded", () => {
    const runtime = window.MoonShieldDevices; if (!runtime) return;
    const $ = (id) => document.getElementById(id);
    const modal = $("devScanModal"), overlay = $("devScanOverlay"), list = $("devScanNetworks"), message = $("devScanMessage"), confirm = $("devScanConfirm");
    if (!modal || !overlay || !list || !confirm) return;

    const note = (value = "", kind = "") => { message.textContent = value; message.className = `dev-scan-message${kind ? ` dev-scan-message--${kind}` : ""}`; };
    const close = () => { modal.hidden = true; overlay.hidden = true; note(); };

    // State: capabilities and monitor config received from /networks/ API
    let _capabilities = { advanced: false, reason: "Nmap não instalado." };
    let _monitorConfig = { enabled: false, interval_minutes: 3, networks: [] };
    let _availableNetworks = [];

    function applyCapabilities() {
      const advInput = $("devAdvancedMode"), reasonEl = $("devAdvancedReason");
      if (advInput) advInput.disabled = !_capabilities.advanced;
      if (reasonEl) reasonEl.textContent = _capabilities.advanced ? "" : (_capabilities.reason || "Nmap não instalado.");
      if (!_capabilities.advanced) {
        const quickRadio = document.querySelector('input[name="deviceScanMode"][value="quick"]');
        if (quickRadio) quickRadio.checked = true;
      }
    }

    function renderMonitorNetworks(networks) {
      const container = $("devMonitorNetworks"); if (!container) return;
      container.innerHTML = "";
      const eligible = networks.filter((n) => n.monitor_allowed);
      if (!eligible.length) { container.innerHTML = '<p class="dev-cell-dim">Nenhuma rede privada elegível para monitoramento.</p>'; return; }
      eligible.forEach((n) => {
        const label = document.createElement("label");
        label.className = "dev-scan-network";
        const checked = _monitorConfig.networks.includes(n.id);
        label.innerHTML = `<input type="checkbox" value="${runtime.escapeHtml(n.id)}"${checked ? " checked" : ""}>
          <span><span class="dev-scan-network__name"><i class="bi ${n.role?.toLowerCase() === "wan" ? "bi-globe2" : "bi-diagram-3"}" aria-hidden="true"></i> ${runtime.escapeHtml(n.role || "Rede")}</span>
          <span class="dev-scan-network__meta">${runtime.escapeHtml(n.interface || "—")}<span>${runtime.escapeHtml(n.cidr || "—")}</span></span></span>`;
        container.appendChild(label);
      });
    }

    function applyMonitorConfig(config) {
      if (!config) return;
      _monitorConfig = { enabled: Boolean(config.enabled), interval_minutes: config.interval_minutes || 3, networks: Array.isArray(config.networks) ? config.networks : [] };
      const enabledEl = $("devMonitorEnabled"), intervalEl = $("devMonitorInterval");
      if (enabledEl) enabledEl.checked = _monitorConfig.enabled;
      if (intervalEl) intervalEl.value = String(_monitorConfig.interval_minutes);
      renderMonitorNetworks(_availableNetworks);
    }

    const updateSelection = () => {
      list.querySelectorAll(".dev-scan-network").forEach((row) => {
        const input = row.querySelector("input"), status = row.querySelector(".dev-scan-network__status");
        if (status) status.textContent = input.disabled ? "Indisponível" : input.checked ? (list.dataset.scanning === "true" ? "Escaneando…" : "Selecionado") : "Não selecionado";
      });
    };

    const render = (networks) => {
      list.innerHTML = networks.length ? "" : '<p class="dev-no-data">Nenhuma rede disponível para scan.</p>';
      networks.forEach((n) => {
        const label = document.createElement("label"), allowed = Boolean(n.allowed);
        label.className = `dev-scan-network${allowed ? "" : " dev-scan-network--disabled"}`;
        label.innerHTML = `<input type="checkbox" value="${runtime.escapeHtml(n.id)}"${n.selected && allowed ? " checked" : ""}${allowed ? "" : " disabled"}>
          <span><span class="dev-scan-network__name"><i class="bi ${n.role?.toLowerCase() === "wan" ? "bi-globe2" : "bi-diagram-3"}" aria-hidden="true"></i> ${runtime.escapeHtml(n.role || "Rede")}</span>
          <span class="dev-scan-network__meta">${runtime.escapeHtml(n.interface || "—")}<span>${runtime.escapeHtml(n.cidr || "—")}</span></span>
          <span class="dev-scan-network__note">${allowed ? `${Number(n.device_count || 0)} dispositivos` : "Não autorizada pela topologia"}</span>
          <span class="dev-scan-network__status"></span></span>`;
        list.appendChild(label);
      });
      updateSelection();
    };
    list.addEventListener("change", updateSelection);

    const open = async (focusMonitor = false) => {
      modal.hidden = false; overlay.hidden = false;
      note("Consultando redes e configurações…", "working");
      const payload = await runtime.loadNetworks();
      _availableNetworks = Array.isArray(payload.networks) ? payload.networks : [];
      if (payload.capabilities) { _capabilities = payload.capabilities; applyCapabilities(); }
      if (payload.monitor) applyMonitorConfig(payload.monitor);
      else renderMonitorNetworks(_availableNetworks);
      render(_availableNetworks);
      note(_availableNetworks.length ? "" : "Nenhuma rede autorizada foi retornada.");
      if (focusMonitor) $("devMonitorOptions")?.scrollIntoView({ behavior: "smooth", block: "nearest" });
    };

    const start = async () => {
      const selectedNetworks = Array.from(list.querySelectorAll("input:checked:not(:disabled)")).map((inp) => inp.value);
      if (!selectedNetworks.length) { note("Selecione ao menos uma rede autorizada.", "error"); return; }
      const modeInput = document.querySelector('input[name="deviceScanMode"]:checked');
      const mode = modeInput?.value || "quick";
      confirm.disabled = true; list.dataset.scanning = "true"; updateSelection();
      note("Escaneando as redes selecionadas…", "working");
      try {
        const response = await fetch(runtime.urls.scan, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRFToken": runtime.getCsrfToken() }, body: JSON.stringify({ networks: selectedNetworks, mode }) });
        const payload = await response.json();
        if (!response.ok || !payload.ok) throw new Error(payload.error || "O scan não foi iniciado.");
        note("Atualizando inventário…", "working");
        await runtime.refreshInventory(); await runtime.loadNetworks();
        runtime.notify(`Scan concluído: ${Number(payload.found || 0)} dispositivo(s) encontrado(s).`, "success");
        close();
      } catch (err) { note(err.message || "Falha ao executar scan.", "error"); }
      finally { confirm.disabled = false; delete list.dataset.scanning; updateSelection(); }
    };

    const saveMonitor = async () => {
      const enabledEl = $("devMonitorEnabled"), intervalEl = $("devMonitorInterval");
      const monitorNets = Array.from(($("devMonitorNetworks") || document.createElement("div")).querySelectorAll("input:checked")).map((inp) => inp.value);
      const body = { enabled: enabledEl?.checked ?? false, interval_minutes: parseInt(intervalEl?.value || "3", 10), networks: monitorNets };
      const btn = $("devMonitorSave"); if (btn) btn.disabled = true;
      try {
        const response = await fetch(runtime.urls.monitor, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRFToken": runtime.getCsrfToken() }, body: JSON.stringify(body) });
        const payload = await response.json();
        if (!response.ok || !payload.ok) throw new Error(payload.error || "Falha ao salvar monitoramento.");
        if (payload.monitor) { _monitorConfig = payload.monitor; }
        runtime.notify("Monitoramento salvo.", "success");
        await runtime.loadNetworks();
      } catch (err) { runtime.notify(err.message || "Falha ao salvar monitoramento.", "error"); }
      finally { if (btn) btn.disabled = false; }
    };

    document.addEventListener("moonshield:scan:open", () => open(false));
    document.addEventListener("moonshield:monitor:open", () => open(true));
    $("devScanClose")?.addEventListener("click", close);
    $("devScanCancel")?.addEventListener("click", close);
    overlay.addEventListener("click", close);
    confirm.addEventListener("click", start);
    $("devMonitorSave")?.addEventListener("click", saveMonitor);
  });
})();
