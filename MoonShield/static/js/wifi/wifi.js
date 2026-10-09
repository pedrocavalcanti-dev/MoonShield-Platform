(() => {
  "use strict";
  const app = document.getElementById("wifiApp");
  if (!app) return;

  const $ = (id) => document.getElementById(id);
  const csrf = () => document.cookie.split(";").map((v) => v.trim()).find((v) => v.startsWith("csrftoken="))?.slice(10) || "";
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char]));
  const dt = (value) => value ? new Date(value).toLocaleString("pt-BR") : "—";
  const notice = (message, kind = "") => {
    const el = $("wifiNotice");
    el.textContent = message;
    el.className = `wifi-notice${kind ? ` wifi-notice--${kind}` : ""}`;
  };

  const request = async (url, options = {}) => {
    const response = await fetch(url, {
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRFToken": csrf(), ...(options.headers || {}) },
      ...options
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok || !body.ok) throw new Error(body.error || body.erro || "Operação não concluída.");
    return body;
  };

  let state = { trusted_devices: [], authorizations: [] };
  let currentFilter = "all";
  let currentSearch = "";
  let selectedIds = new Set(); // Store IDs of selected items (only trusted_devices for mass action)

  const applyFilters = () => {
    let rows = [
      ...state.trusted_devices.map(i => ({ ...i, rowType: "trusted", isRevoked: !i.active })),
      ...state.authorizations.map(i => ({ ...i, rowType: "login", isRevoked: !i.active }))
    ];

    if (currentFilter !== "all") {
      rows = rows.filter(r => {
        if (currentFilter === "trusted") return r.rowType === "trusted";
        if (currentFilter === "login") return r.rowType === "login";
        if (currentFilter === "active") return !r.isRevoked;
        if (currentFilter === "revoked") return r.isRevoked;
        return true;
      });
    }

    if (currentSearch) {
      const q = currentSearch.toLowerCase();
      rows = rows.filter(r => {
        const name = (r.name || r.username || "").toLowerCase();
        const ip = (r.ip_address || "").toLowerCase();
        const mac = (r.mac_address || "").toLowerCase();
        return name.includes(q) || ip.includes(q) || mac.includes(q);
      });
    }

    // Sort logic
    rows.sort((a, b) => {
      if (a.isRevoked !== b.isRevoked) return a.isRevoked ? 1 : -1;
      const tA = new Date(a.authorized_at || a.created_at).getTime();
      const tB = new Date(b.authorized_at || b.created_at).getTime();
      return tB - tA;
    });

    return rows;
  };

  const createRowEl = (item) => {
    const tr = document.createElement("tr");
    if (item.isRevoked) tr.className = "wifi-row--revoked";

    const tdCheckbox = document.createElement("td");
    tdCheckbox.className = "wifi-td-checkbox";
    if (item.rowType === "trusted") {
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.dataset.id = item.id;
      cb.checked = selectedIds.has(String(item.id));
      cb.addEventListener("change", (e) => {
        if (e.target.checked) selectedIds.add(String(item.id));
        else selectedIds.delete(String(item.id));
        updateMassActions();
      });
      tdCheckbox.appendChild(cb);
    }
    tr.appendChild(tdCheckbox);

    const tdName = document.createElement("td");
    tdName.textContent = item.name || item.username;
    tr.appendChild(tdName);

    const tdIp = document.createElement("td");
    tdIp.className = "wifi-mono";
    tdIp.textContent = item.ip_address || "—";
    tr.appendChild(tdIp);

    const tdMac = document.createElement("td");
    tdMac.className = "wifi-mono";
    tdMac.textContent = item.mac_address;
    tr.appendChild(tdMac);

    const tdType = document.createElement("td");
    const tagType = document.createElement("span");
    tagType.className = "wifi-tag wifi-tag--muted";
    tagType.textContent = item.rowType === "trusted" ? "PERMANENTE" : "LOGIN";
    tdType.appendChild(tagType);
    tr.appendChild(tdType);

    const tdStatus = document.createElement("td");
    const tagStatus = document.createElement("span");
    tagStatus.className = `wifi-tag ${item.isRevoked ? "wifi-tag--muted" : ""}`;
    tagStatus.textContent = item.isRevoked ? "REVOGADO" : "AUTORIZADO";
    tdStatus.appendChild(tagStatus);
    tr.appendChild(tdStatus);

    const tdAuth = document.createElement("td");
    tdAuth.textContent = dt(item.authorized_at || item.created_at);
    tr.appendChild(tdAuth);

    const tdExp = document.createElement("td");
    tdExp.textContent = dt(item.expires_at);
    tr.appendChild(tdExp);

    const tdActions = document.createElement("td");
    if (item.rowType === "trusted") {
      const btnEdit = document.createElement("button");
      btnEdit.className = "wifi-button wifi-button--quiet";
      btnEdit.textContent = "Editar";
      btnEdit.onclick = () => openTrusted(item);
      tdActions.appendChild(btnEdit);

      const btnDisable = document.createElement("button");
      btnDisable.className = "wifi-button wifi-button--danger";
      btnDisable.textContent = item.active ? "Desativar" : "Inativo";
      btnDisable.onclick = async () => {
        if (!confirm("Desativar este dispositivo permanente?")) return;
        try {
          await request(`${app.dataset.trustedUrl}${item.id}/deactivate/`, { method: "POST", body: "{}" });
          notice("Dispositivo desativado.", "ok");
          load();
        } catch (err) { notice(err.message, "error"); }
      };
      tdActions.appendChild(btnDisable);
    } else if (item.active) {
      const btnRevoke = document.createElement("button");
      btnRevoke.className = "wifi-button wifi-button--danger";
      btnRevoke.textContent = "Revogar";
      btnRevoke.onclick = async () => {
        if (!confirm("Revogar acesso deste dispositivo?")) return;
        try {
          const authUrl = app.dataset.trustedUrl.replace("trusted/", "authorizations/");
          await request(`${authUrl}${item.id}/revoke/`, { method: "POST", body: '{"revoked_reason":"manual"}' });
          notice("Acesso revogado.", "ok");
          load();
        } catch (err) { notice(err.message, "error"); }
      };
      tdActions.appendChild(btnRevoke);
    }
    tr.appendChild(tdActions);

    return tr;
  };

  const updateMassActions = () => {
    const ma = $("wifiMassActions");
    const countEl = $("wifiSelectedCount");
    if (selectedIds.size > 0) {
      ma.style.display = "flex";
      countEl.textContent = selectedIds.size;
    } else {
      ma.style.display = "none";
    }

    // Update select all checkbox state
    const currentTrustedIds = applyFilters().filter(r => r.rowType === "trusted").map(r => String(r.id));
    const allSelected = currentTrustedIds.length > 0 && currentTrustedIds.every(id => selectedIds.has(id));
    $("wifiSelectAll").checked = allSelected;
  };

  const render = () => {
    const trustedActive = state.trusted_devices.filter((item) => item.active).length;
    const authActive = state.authorizations.filter((item) => item.active).length;
    const totalActive = trustedActive + authActive;

    const trustedRevoked = state.trusted_devices.filter((item) => !item.active).length;
    const authRevoked = state.authorizations.filter((item) => !item.active).length;
    const totalRevoked = trustedRevoked + authRevoked;

    $("wifiTrustedCount").textContent = trustedActive;
    $("wifiAuthorizedCount").textContent = authActive;
    $("wifiTotalCount").textContent = totalActive;

    const revokedCard = $("wifiRevokedCard");
    if (totalRevoked > 0) {
      revokedCard.style.display = "flex";
      $("wifiRevokedCount").textContent = totalRevoked;
    } else {
      revokedCard.style.display = "none";
    }

    const tbody = $("wifiRows");
    tbody.innerHTML = "";

    const visibleRows = applyFilters();
    if (visibleRows.length === 0) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 9;
      td.className = "wifi-empty";
      td.textContent = "Nenhum dispositivo encontrado.";
      tr.appendChild(td);
      tbody.appendChild(tr);
    } else {
      visibleRows.forEach(item => {
        tbody.appendChild(createRowEl(item));
      });
    }

    updateMassActions();
  };

  const load = async () => {
    try {
      const data = await request(app.dataset.stateUrl, { headers: {} });
      state = data;
      render();
      notice("");

      // Load diagnostics
      try {
        const diag = await request(app.dataset.diagUrl, { headers: {} });
        if (diag.diagnostics) {
          $("diagAgent").textContent = diag.diagnostics.agent_online ? "ONLINE" : "OFFLINE";
          $("diagAgent").style.color = diag.diagnostics.agent_online ? "var(--accent)" : "#fb7185";

          $("diagSync").textContent = diag.diagnostics.firewall_in_sync ? "Sincronizado" : "Pendente";
          $("diagSync").style.color = diag.diagnostics.firewall_in_sync ? "var(--accent)" : "#fb7185";

          $("diagMode").textContent = diag.diagnostics.enforcement_enabled ? "Enforcement" : "Monitoramento";

          $("diagInconsistencies").textContent = diag.diagnostics.ip_inconsistencies;
          $("diagInconsistencies").style.color = diag.diagnostics.ip_inconsistencies > 0 ? "#fb7185" : "var(--text)";
        }
      } catch (e) {
        console.warn("Falha ao carregar diagnósticos", e);
      }

    } catch (error) {
      notice(error.message, "error");
    }
  };

  // Listeners
  $("wifiRefresh").addEventListener("click", load);

  $("wifiSyncNow").addEventListener("click", async () => {
    const btn = $("wifiSyncNow");
    btn.disabled = true;
    btn.textContent = "Sincronizando...";
    try {
      await request(app.dataset.syncUrl, { method: "POST", body: "{}" });
      notice("Sincronização concluída com sucesso.", "ok");
      load();
    } catch (error) {
      notice(error.message, "error");
    } finally {
      btn.disabled = false;
      btn.textContent = "Sincronizar agora";
    }
  });

  // Search
  $("wifiSearchInput").addEventListener("input", (e) => {
    currentSearch = e.target.value.trim();
    render();
  });

  // Filters
  const filterBtns = document.querySelectorAll(".wifi-filter-btn");
  filterBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      filterBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      currentFilter = btn.dataset.filter;
      render();
    });
  });

  // Mass selection
  $("wifiSelectAll").addEventListener("change", (e) => {
    const isChecked = e.target.checked;
    const currentTrustedIds = applyFilters().filter(r => r.rowType === "trusted").map(r => String(r.id));
    if (isChecked) {
      currentTrustedIds.forEach(id => selectedIds.add(id));
    } else {
      currentTrustedIds.forEach(id => selectedIds.delete(id));
    }
    render();
  });

  const performMassAction = async (actionStr) => {
    if (selectedIds.size === 0) return;
    if (!confirm(`Confirmar ação em ${selectedIds.size} dispositivos permanentes?`)) return;
    try {
      await request(app.dataset.bulkActionUrl, {
        method: "POST",
        body: JSON.stringify({ device_ids: Array.from(selectedIds).map(Number), action: actionStr })
      });
      selectedIds.clear();
      notice("Ação em lote aplicada.", "ok");
      load();
    } catch (error) {
      notice(error.message, "error");
    }
  };

  $("wifiMassActivate").addEventListener("click", () => performMassAction("activate"));
  $("wifiMassDeactivate").addEventListener("click", () => performMassAction("deactivate"));

  // Dialog and Tabs
  const dialog = $("wifiTrustedDialog");
  const closeBtns = document.querySelectorAll(".wifi-close, .wifi-dialog-cancel");
  closeBtns.forEach(btn => btn.addEventListener("click", () => dialog.close()));

  const tabBtns = document.querySelectorAll(".wifi-tab");
  const tabContents = document.querySelectorAll(".wifi-tab-content");
  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      tabBtns.forEach(b => b.classList.remove("active"));
      tabContents.forEach(c => c.classList.remove("active"));
      btn.classList.add("active");
      if (btn.dataset.tab === "individual") $("wifiTabIndividual").classList.add("active");
      else $("wifiTabBulk").classList.add("active");
    });
  });

  const openTrusted = (item = null) => {
    $("wifiDialogTitle").textContent = item ? "Editar dispositivo permanente" : "Adicionar dispositivo";
    $("wifiTrustedId").value = item?.id || "";
    $("wifiTrustedName").value = item?.name || "";
    $("wifiTrustedMac").value = item?.mac_address || "";
    $("wifiTrustedIp").value = item?.ip_address || "";
    $("wifiTrustedDescription").value = item?.description || "";

    // Switch to individual tab and hide bulk tab if editing
    if (item) {
      $("wifiDialogTabs").style.display = "none";
      tabBtns[0].click(); // Force individual tab
    } else {
      $("wifiDialogTabs").style.display = "flex";
      tabBtns[0].click();
      $("wifiBulkTextarea").value = "";
      $("wifiBulkPreview").style.display = "none";
      $("wifiBulkErrorList").innerHTML = "";
    }

    dialog.showModal();
  };

  $("wifiAddTrusted").addEventListener("click", () => openTrusted());

  $("wifiTrustedForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const id = $("wifiTrustedId").value;
    const payload = {
      name: $("wifiTrustedName").value,
      mac_address: $("wifiTrustedMac").value,
      ip_address: $("wifiTrustedIp").value || null,
      description: $("wifiTrustedDescription").value
    };
    try {
      await request(id ? `${app.dataset.trustedUrl}${id}/` : app.dataset.trustedUrl, {
        method: "POST",
        body: JSON.stringify(payload)
      });
      dialog.close();
      notice("Dispositivo permanente salvo.", "ok");
      load();
    } catch (error) {
      notice(error.message, "error");
    }
  });

  // Bulk parser
  let bulkParsed = [];
  $("wifiBulkTextarea").addEventListener("input", (e) => {
    const lines = e.target.value.split("\n").map(l => l.trim()).filter(l => l);
    bulkParsed = [];
    $("wifiBulkErrorList").innerHTML = "";
    let validCount = 0;

    const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;

    lines.forEach((line, index) => {
      const parts = line.split(";").map(p => p.trim());
      const mac = parts[0];
      const name = parts[1] || "";
      const ip = parts[2] || null;
      const desc = parts[3] || "";

      let error = null;
      if (!mac) {
        error = "MAC vazio";
      } else if (!macRegex.test(mac)) {
        error = `MAC inválido (${mac})`;
      } else if (!name) {
        error = "Nome não fornecido";
      }

      if (error) {
        const li = document.createElement("li");
        li.textContent = `Linha ${index + 1}: ${error}`;
        $("wifiBulkErrorList").appendChild(li);
      } else {
        validCount++;
        bulkParsed.push({ mac_address: mac, name: name, ip_address: ip, description: desc });
      }
    });

    const preview = $("wifiBulkPreview");
    if (lines.length > 0) {
      preview.style.display = "block";
      $("wifiBulkValidCount").textContent = validCount;
    } else {
      preview.style.display = "none";
    }
  });

  $("wifiBulkForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (bulkParsed.length === 0) return notice("Nenhum dispositivo válido no lote.", "error");
    if (bulkParsed.length > 100) return notice("O limite máximo é de 100 dispositivos por lote.", "error");

    try {
      await request(app.dataset.bulkTrustedUrl, {
        method: "POST",
        body: JSON.stringify({ devices: bulkParsed })
      });
      dialog.close();
      notice("Lote salvo com sucesso.", "ok");
      load();
    } catch (error) {
      notice(error.message, "error");
    }
  });

  load();
})();
