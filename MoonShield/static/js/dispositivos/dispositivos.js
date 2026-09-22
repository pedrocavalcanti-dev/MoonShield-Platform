(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const csrf = () => document.cookie.split(";").map((s) => s.trim()).find((s) => s.startsWith("csrftoken="))?.slice(10) || "";
  const date = (value) => value && !Number.isNaN(new Date(value).getTime()) ? new Date(value) : null;
  const text = (value, fallback = "—") => value === null || value === undefined || value === "" ? fallback : String(value);
  const relative = (value) => { const d = date(value); if (!d) return "-"; const s = Math.max(0, Math.floor((Date.now() - d) / 1000)); if (s < 60) return "agora"; if (s < 3600) return `${Math.floor(s / 60)} min`; if (s < 86400) return `${Math.floor(s / 3600)} h`; return `${Math.floor(s / 86400)} d`; };
  const formattedDate = (value) => date(value)?.toLocaleString("pt-BR") || "-";
  const iconFor = (type) => ({router:"bi-router-fill",server:"bi-server",servidor:"bi-server","câmera/nvr":"bi-camera-video-fill",camera:"bi-camera-video-fill","dispositivo móvel":"bi-phone-fill",phone:"bi-phone-fill",computador:"bi-pc-display",computer:"bi-pc-display","impressora":"bi-printer-fill",printer:"bi-printer-fill",infraestrutura:"bi-diagram-3",iot:"bi-cpu"}[String(type || "").toLowerCase()] || "bi-hdd-network-fill");
  const statusFor = (status) => ({online:"Online",offline:"Offline",stale:"Desatualizado",unknown:"Desconhecido"}[String(status || "").toLowerCase()] || "Desconhecido");
  const isUnknownType = (device) => !device.type || String(device.type).trim().toLowerCase() === "desconhecido";
  const normalizeDevice = (raw) => ({
    id: String(raw?.device_id ?? ""),
    displayName: text(raw?.display_name ?? raw?.hostname, "Dispositivo sem nome"),
    detectedHostname: raw?.detected_hostname ?? null,
    ip: raw?.current_ip ?? raw?.ip ?? null,
    mac: raw?.mac ?? null,
    vendor: raw?.vendor ?? null,
    type: raw?.device_type ?? raw?.type ?? null,
    os: raw?.os_guess ?? raw?.os ?? null,
    status: String(raw?.status ?? "unknown").toLowerCase(),
    risk: Number.isFinite(Number(raw?.risk_score)) ? Number(raw.risk_score) : null,
    interface: raw?.interface ?? null,
    networkRole: raw?.network_role ?? null,
    networkCidr: raw?.network_cidr ?? null,
    networkId: raw?.network_id ?? null,
    ports: Array.isArray(raw?.open_ports) ? raw.open_ports.filter((p) => Number.isFinite(Number(p))).map(Number) : [],
    firstSeen: raw?.first_seen ?? null,
    lastSeen: raw?.last_seen ?? null,
    lastScan: raw?.last_scan ?? null,
  });

  document.addEventListener("DOMContentLoaded", () => {
    const app = $("devicesApp"); if (!app) return;
    const urls = {
      inventory: app.dataset.urlInventory,
      networks: app.dataset.urlNetworks,
      scan: app.dataset.urlScan,
      rename: app.dataset.urlRename,
      monitor: app.dataset.urlMonitor,
    };
    const state = { devices: [], networks: [], filter: "all", tab: "inventario", search: "", networkFilter: "", groupByNetwork: true, selectedId: null, charts: {} };
    const tbody = $("devTableBody"), toast = $("devToast");
    const set = (id, value) => { const el = $(id); if (el) el.textContent = text(value); };
    const notify = (msg, kind = "") => { if (!toast) return; toast.textContent = msg; toast.className = `dev-toast${kind ? ` dev-toast--${kind}` : ""} show`; setTimeout(() => toast.classList.remove("show"), 3500); };
    const selected = () => state.devices.find((d) => d.id === state.selectedId);

    const matches = (device) => {
      const q = state.search.trim().toLowerCase();
      if (q) {
        const fields = [device.displayName,device.detectedHostname,device.ip,device.mac,device.vendor,device.type,device.os,device.interface,device.networkRole,device.networkCidr].filter(Boolean).join(" ").toLowerCase();
        if (!fields.includes(q)) return false;
      }
      if (state.networkFilter) {
        if (state.networkFilter === "__legacy__") { if (device.networkId) return false; }
        else if (device.networkId !== state.networkFilter) return false;
      }
      if (state.filter === "online" && device.status !== "online") return false;
      if (state.filter === "offline" && device.status !== "offline") return false;
      if (state.filter === "stale" && device.status !== "stale") return false;
      return true;
    };
    const visible = () => state.devices.filter(matches);

    function populateNetworkFilter() {
      const select = $("devNetworkFilter"); if (!select) return;
      const current = select.value;
      select.innerHTML = '<option value="">Todas</option>';
      state.networks.forEach((n) => {
        const opt = document.createElement("option");
        opt.value = n.id;
        opt.textContent = `${(n.role || "rede").toUpperCase()} · ${n.interface || "—"}`;
        select.appendChild(opt);
      });
      if (state.devices.some((d) => !d.networkId)) {
        const opt = document.createElement("option"); opt.value = "__legacy__"; opt.textContent = "Sem rede / Legado"; select.appendChild(opt);
      }
      if ([...select.options].some((o) => o.value === current)) select.value = current;
    }

    function renderNetworks() {
      const target = $("devNetworksList"), count = $("devNetworksCount"); if (!target) return;
      if (count) count.textContent = `${state.networks.length} rede${state.networks.length === 1 ? "" : "s"}`;
      target.innerHTML = state.networks.length ? state.networks.map((n) => `
        <article class="dev-network-item">
          <div class="dev-network-item__top"><span class="dev-network-item__role"><i class="bi ${n.role?.toLowerCase() === "wan" ? "bi-globe2" : "bi-diagram-3"}" aria-hidden="true"></i> ${escapeHtml(n.role || "Rede")}</span><span class="dev-network-item__state${n.allowed ? "" : " dev-network-item__state--unavailable"}">${n.allowed ? "Autorizada" : "Indisponível"}</span></div>
          <p class="dev-network-item__meta">${escapeHtml(n.interface || "—")}<span>${escapeHtml(n.cidr || "—")}</span></p>
          <div class="dev-network-item__last"><span>${Number(n.device_count || 0)} dispositivos</span><span>${n.last_scan ? `Último scan: ${escapeHtml(relative(n.last_scan))}` : "Sem scan registrado"}</span></div>
        </article>`).join("") : '<p class="dev-network-empty">Nenhuma rede monitorada disponível.</p>';
    }

    function renderKpis() {
      const now = Date.now(), items = state.devices;
      const online = items.filter((d) => d.status === "online").length;
      const offline = items.filter((d) => d.status === "offline").length;
      const unknownType = items.filter(isUnknownType).length;
      const monitored = state.networks.filter((n) => n.monitored).length;
      const newest = items.filter((d) => date(d.firstSeen) && now - date(d.firstSeen) <= 86400000).length;
      [["kpiTotal",items.length],["kpiOnline",online],["kpiOffline",offline],["kpiUnknown",unknownType],["kpiMonitored",monitored],["kpiNew",newest]].forEach(([id,v]) => set(id,v));
      const mode = (key) => { const map = items.reduce((acc, d) => { const k = text(d[key], "Desconhecido"); acc[k] = (acc[k] || 0) + 1; return acc; }, {}); return Object.entries(map).sort((a,b) => b[1]-a[1])[0]?.[0] || "-"; };
      set("kpiTopType", mode("type")); set("kpiTopOS", mode("os"));
      const total = items.length || 1;
      [["kpiOnlineBar",online],["kpiOfflineBar",offline],["kpiUnknownBar",unknownType],["kpiMonitoredBar",monitored],["kpiNewBar",newest]].forEach(([id,v]) => { const bar = $(id); if (bar) bar.style.width = `${Math.round((v / total) * 100)}%`; });
      const lastTs = items.map((d) => date(d.lastScan || d.lastSeen)).filter(Boolean).sort((a,b) => b-a)[0];
      set("devLastUpdate", lastTs ? relative(lastTs) : "sem dados");
    }

    const statusBadge = (d) => `<span class="dev-status-badge dev-status-badge--${escapeHtml(d.status)}">${escapeHtml(statusFor(d.status))}</span>`;
    const deviceIdentity = (d) => {
      const generated = d.ip && d.displayName === `Desconhecido ${d.ip}`;
      const detail = generated ? d.ip : [d.detectedHostname !== d.displayName ? d.detectedHostname : null, d.type !== "Desconhecido" ? d.type : null].filter(Boolean)[0];
      return { name: generated ? "Desconhecido" : d.displayName, subtitle: [detail, d.networkRole?.toUpperCase()].filter(Boolean).join(" · ") };
    };
    const renderPortsCell = (ports) => ports.length ? ports.slice(0, 5).join(", ") + (ports.length > 5 ? "…" : "") : "—";

    function appendRow(item) {
      const ident = deviceIdentity(item), row = document.createElement("tr");
      row.dataset.deviceId = item.id;
      const netLabel = item.networkRole ? `${item.networkRole.toUpperCase()} · ${item.interface || ""}`.trim() : "—";
      row.innerHTML = `
        <td><div class="dev-name-cell"><i class="bi ${iconFor(item.type)} dev-device-icon" aria-hidden="true"></i><div class="dev-identity">
          <button type="button" class="dev-device-link" data-action="open">${escapeHtml(ident.name)}</button>
          ${ident.subtitle ? `<div class="dev-name-sub">${escapeHtml(ident.subtitle)}</div>` : ""}
          <div class="dev-name-status">${statusBadge(item)}</div>
        </div></div></td>
        <td class="dev-cell-mono">${escapeHtml(text(item.ip))}</td>
        <td>${escapeHtml(text(item.vendor))}</td>
        <td>${escapeHtml(text(item.os))}</td>
        <td class="dev-cell-dim">${escapeHtml(netLabel)}</td>
        <td title="${escapeHtml(formattedDate(item.lastSeen))}">${escapeHtml(relative(item.lastSeen))}</td>
        <td class="dev-cell-mono dev-cell-dim">${escapeHtml(renderPortsCell(item.ports))}</td>
        <td><div class="dev-row-actions">
          <button type="button" class="dev-row-action" data-action="open" title="Detalhes" aria-label="Detalhes de ${escapeHtml(item.displayName)}"><i class="bi bi-eye" aria-hidden="true"></i></button>
          <button type="button" class="dev-row-action" data-action="rename" title="Renomear" aria-label="Renomear ${escapeHtml(item.displayName)}"><i class="bi bi-pencil" aria-hidden="true"></i></button>
        </div></td>`;
      tbody.appendChild(row);
    }

    const EMPTY_ROW = '<tr><td colspan="8" class="dev-no-data">Nenhum dispositivo no inventário para este filtro. <button type="button" class="dev-link-btn" data-action="scan">Escanear redes</button></td></tr>';

    function renderGrouped(devices) {
      const groups = new Map();
      const LEGACY = "__legacy__";
      devices.forEach((d) => { const k = d.networkId || LEGACY; if (!groups.has(k)) groups.set(k, []); groups.get(k).push(d); });
      const byId = Object.fromEntries(state.networks.map((n) => [n.id, n]));
      const keys = [...groups.keys()].filter((k) => k !== LEGACY).sort((a, b) => { const ra = byId[a]?.role || "z", rb = byId[b]?.role || "z"; return ra.localeCompare(rb) || a.localeCompare(b); });
      if (groups.has(LEGACY)) keys.push(LEGACY);
      keys.forEach((key) => {
        const items = groups.get(key), net = byId[key];
        const hdr = document.createElement("tr"); hdr.className = "dev-group-header";
        const onlineN = items.filter((d) => d.status === "online").length;
        const icon = key === LEGACY ? "bi-archive" : (net?.role?.toLowerCase() === "wan" ? "bi-globe2" : "bi-diagram-3");
        const label = key === LEGACY ? "Sem rede / Legado" : `${(net?.role || key).toUpperCase()} · ${net?.interface || key}`;
        const meta = [net?.cidr, `${items.length} dispositivo${items.length !== 1 ? "s" : ""}`, `${onlineN} online`].filter(Boolean).join(" · ");
        hdr.innerHTML = `<td colspan="8"><span class="dev-group-label"><i class="bi ${icon}"></i> ${escapeHtml(label)}</span><span class="dev-group-meta">${escapeHtml(meta)}</span></td>`;
        tbody.appendChild(hdr);
        items.forEach(appendRow);
      });
    }

    function renderTable() {
      if (!tbody) return;
      const devices = visible();
      set("devTableCount", `${devices.length} dispositivo(s)`);
      tbody.innerHTML = "";
      if (!devices.length) { tbody.innerHTML = EMPTY_ROW; return; }
      if (state.groupByNetwork) { renderGrouped(devices); } else { devices.forEach(appendRow); }
    }

    function renderCharts() {
      const colors = ["#648fcb","#66b6bf","#9386bb","#8496a8","#7aa993","#bca57a"];
      const chartDevices = visible();
      [["chartByType","type"],["chartByOS","os"]].forEach(([id,key]) => {
        state.charts[id]?.destroy(); delete state.charts[id];
        const canvas = $(id), legend = $(`${id}Legend`); if (!canvas || !legend) return;
        const vmap = new Map();
        chartDevices.forEach((d) => { const lbl = text(d[key], "Desconhecido"); vmap.set(lbl, (vmap.get(lbl) || 0) + 1); });
        const entries = [...vmap.entries()].sort((a,b) => b[1]-a[1]);
        legend.innerHTML = entries.length ? entries.map(([lbl,cnt],i) => `<li><span class="dev-chart-key" style="background:${colors[i%colors.length]}" aria-hidden="true"></span><span class="dev-chart-label">${escapeHtml(lbl)}</span><strong>${cnt}</strong></li>`).join("") : '<li class="dev-cell-dim">Sem dispositivos no inventário.</li>';
        canvas.parentElement.hidden = !entries.length || !window.Chart;
        if (!entries.length || !window.Chart) return;
        state.charts[id] = new window.Chart(canvas, {
          type: "doughnut",
          data: { labels: entries.map(([lbl]) => lbl), datasets: [{ data: entries.map(([,cnt]) => cnt), backgroundColor: entries.map((_,i) => colors[i%colors.length]), borderWidth: 0, hoverOffset: 3 }] },
          options: { responsive: true, maintainAspectRatio: false, cutout: "76%", layout: { padding: 4 }, plugins: { legend: { display: false } } },
        });
      });
    }

    function openDrawer(item) {
      if (!item) return; state.selectedId = item.id;
      [["drawerHostname",item.displayName],["drawerIp",item.ip],["drawerType",item.type],["drawerStatusBadge",statusFor(item.status)],["drawerRiskScore",item.risk === null ? "-" : item.risk],["drawerRiskLabel",item.risk === null ? "Risco não informado" : item.risk >= 70 ? "Risco elevado" : item.risk >= 40 ? "Risco moderado" : "Risco baixo"],["drawerVendor",item.vendor],["drawerOS",item.os],["drawerMac",item.mac],["drawerFirstSeen",formattedDate(item.firstSeen)],["drawerLastSeen",formattedDate(item.lastSeen)],["drawerNetworkRole",item.networkRole],["drawerInterface",item.interface],["drawerNetworkCidr",item.networkCidr],["drawerLastScan",formattedDate(item.lastScan)]].forEach(([id,v]) => set(id,v));
      const icon = $("drawerTypeIcon"); if (icon) icon.className = `bi ${iconFor(item.type)} drawer-type-icon`;
      const badge = $("drawerStatusBadge"); if (badge) badge.className = `dev-status-badge dev-status-badge--${item.status}`;
      const score = $("drawerRiskScore"); if (score) score.className = `drawer-risk-score${item.risk === null ? "" : item.risk >= 70 ? " drawer-risk-score--high" : item.risk >= 40 ? " drawer-risk-score--medium" : " drawer-risk-score--low"}`;
      const SERVICES = {22:"SSH",53:"DNS",80:"HTTP",443:"HTTPS",445:"SMB",554:"RTSP",631:"IPP",3389:"RDP",9100:"Print"};
      const ports = $("drawerPortsBody");
      if (ports) {
        ports.innerHTML = item.ports.length ? "" : '<tr><td colspan="2" class="dev-no-data">Nenhuma porta observada.</td></tr>';
        item.ports.forEach((p) => { const row = document.createElement("tr"); [p, SERVICES[p] || "—"].forEach((v) => { const cell = document.createElement("td"); cell.textContent = String(v); row.appendChild(cell); }); ports.appendChild(row); });
      }
      ["drawerFlagNew","drawerFlagMal"].forEach((id) => { const f=$(id); if(f) f.style.display="none"; });
      $("devDrawer")?.classList.add("open"); $("devDrawerOverlay")?.classList.add("open");
    }
    const closeDrawer = () => { $("devDrawer")?.classList.remove("open"); $("devDrawerOverlay")?.classList.remove("open"); };
    const closeRename = () => $("renameModalOverlay")?.classList.remove("open");
    function openRename(item = selected()) {
      if (!item) return; state.selectedId = item.id;
      set("renameModalCurrent",item.displayName); set("renameModalSub",text(item.ip)); set("renameModalIp",item.ip); set("renameModalMac",item.mac);
      const input = $("renameInput"); if (input) { input.value = item.displayName; set("renameCharCount",`${input.value.length}/80`); input.focus(); }
      $("renameModalOverlay")?.classList.add("open");
    }
    async function request(url, options = {}) {
      const response = await fetch(url, { credentials: "same-origin", ...options });
      const payload = await response.json();
      if (!response.ok || payload.ok === false) throw new Error(payload.error || "Falha na solicitação.");
      return payload;
    }
    async function refreshInventory() {
      const btn = $("devRefreshBtn"); if (btn) btn.disabled = true;
      try { const payload = await request(urls.inventory); state.devices = Array.isArray(payload.devices) ? payload.devices.map(normalizeDevice).filter((d) => d.id) : []; renderAll(); }
      catch (err) { if (!state.devices.length && tbody) tbody.innerHTML = `<tr><td colspan="8" class="dev-no-data">Não foi possível carregar o inventário.</td></tr>`; notify(err.message, "error"); }
      finally { if (btn) btn.disabled = false; }
    }
    async function loadNetworks() {
      try { const payload = await request(urls.networks); state.networks = Array.isArray(payload.networks) ? payload.networks : []; populateNetworkFilter(); renderNetworks(); renderKpis(); return payload; }
      catch (err) { state.networks = []; populateNetworkFilter(); renderNetworks(); notify(err.message, "error"); return { networks: [], monitor: null, capabilities: null }; }
    }
    async function saveRename() {
      const item = selected(), name = $("renameInput")?.value.trim(), btn = $("renameModalSave");
      if (!item || !name) { notify("Informe um nome para o dispositivo.", "error"); return; }
      if (btn) btn.disabled = true;
      try { await request(urls.rename, { method: "POST", headers: { "Content-Type": "application/json", "X-CSRFToken": csrf() }, body: JSON.stringify({ device_id: item.id, new_name: name }) }); await refreshInventory(); closeRename(); notify("Nome atualizado.", "success"); }
      catch (err) { notify(err.message, "error"); }
      finally { if (btn) btn.disabled = false; }
    }
    function exportCsv(items = visible()) {
      const rows = [["nome","ip","mac","vendor","tipo","os","status","risco","interface","rede","cidr","primeira_vez_visto","ultima_atividade","ultimo_scan","portas"]];
      items.forEach((d) => rows.push([d.displayName,d.ip,d.mac,d.vendor,d.type,d.os,d.status,d.risk,d.interface,d.networkRole,d.networkCidr,d.firstSeen,d.lastSeen,d.lastScan,d.ports.join("|")]));
      const csv = rows.map((row) => row.map((v) => `"${String(v ?? "").replace(/"/g,'""')}"`).join(",")).join("\r\n");
      const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob(["\uFEFF",csv],{type:"text/csv;charset=utf-8"})); a.download = `moonshield-dispositivos-${new Date().toISOString().replace(/[-:]/g,"").slice(0,13)}.csv`; a.click(); URL.revokeObjectURL(a.href);
    }
    function renderAll() { renderKpis(); renderTable(); renderCharts(); renderNetworks(); if (selected()) openDrawer(selected()); }

    // — Event listeners —
    $("devRefreshBtn")?.addEventListener("click", refreshInventory);
    $("devExportBtn")?.addEventListener("click", () => exportCsv());
    $("daBtnExport")?.addEventListener("click", () => { const item = selected(); if (item) exportCsv([item]); });
    $("devScanBtn")?.addEventListener("click", () => document.dispatchEvent(new CustomEvent("moonshield:scan:open")));
    $("devMonitorBtn")?.addEventListener("click", () => document.dispatchEvent(new CustomEvent("moonshield:monitor:open")));
    $("devSearch")?.addEventListener("input", (e) => { state.search = e.target.value; renderTable(); renderCharts(); });
    $("devSearchClear")?.addEventListener("click", () => { const inp = $("devSearch"); if (inp) { inp.value = ""; state.search = ""; renderTable(); renderCharts(); inp.focus(); } });
    $("devNetworkFilter")?.addEventListener("change", (e) => { state.networkFilter = e.target.value; renderTable(); renderCharts(); renderKpis(); });
    $("devGroupNetworks")?.addEventListener("change", (e) => { state.groupByNetwork = e.target.checked; renderTable(); });
    document.querySelectorAll(".dev-filter-chip").forEach((btn) => btn.addEventListener("click", () => {
      state.filter = btn.dataset.filter || "all";
      document.querySelectorAll(".dev-filter-chip").forEach((b) => b.classList.toggle("dev-filter-chip--active", b === btn));
      renderTable(); renderCharts();
    }));
    document.querySelectorAll(".dev-tab-btn").forEach((btn) => btn.addEventListener("click", () => {
      state.tab = btn.dataset.tab || "inventario";
      document.querySelectorAll(".dev-tab-btn").forEach((b) => b.classList.toggle("dev-tab-btn--active", b === btn));
      renderTable();
    }));
    tbody?.addEventListener("click", (e) => {
      const actionBtn = e.target.closest("[data-action]"), action = actionBtn?.dataset.action;
      if (action === "scan") { document.dispatchEvent(new CustomEvent("moonshield:scan:open")); return; }
      const row = e.target.closest("tr[data-device-id]");
      const item = state.devices.find((d) => d.id === row?.dataset.deviceId);
      if (!item) return;
      if (action === "rename") { openRename(item); return; }
      if (action === "open" || !actionBtn) openDrawer(item);
    });
    $("devDrawerClose")?.addEventListener("click", closeDrawer);
    $("devDrawerOverlay")?.addEventListener("click", closeDrawer);
    $("daBtnRename")?.addEventListener("click", () => openRename());
    $("renameModalClose")?.addEventListener("click", closeRename);
    $("renameModalCancel")?.addEventListener("click", closeRename);
    $("renameModalOverlay")?.addEventListener("click", (e) => { if (e.target === e.currentTarget) closeRename(); });
    $("renameInput")?.addEventListener("input", (e) => set("renameCharCount", `${e.target.value.length}/80`));
    $("renameModalSave")?.addEventListener("click", saveRename);

    // Public API consumed by dispositivos-scan.js
    window.MoonShieldDevices = { urls, state, escapeHtml, getCsrfToken: csrf, notify, refreshInventory, loadNetworks, renderNetworks, renderKpis, renderAll };
    refreshInventory(); loadNetworks();
  });
})();
