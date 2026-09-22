(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char]));
  const csrf = () => document.cookie.split(";").map((item) => item.trim()).find((item) => item.startsWith("csrftoken="))?.slice(10) || "";
  const date = (value) => value && !Number.isNaN(new Date(value).getTime()) ? new Date(value) : null;
  const text = (value, fallback = "—") => value === null || value === undefined || value === "" ? fallback : String(value);
  const relative = (value) => { const item = date(value); if (!item) return "-"; const seconds = Math.max(0, Math.floor((Date.now() - item) / 1000)); if (seconds < 60) return "agora"; if (seconds < 3600) return `${Math.floor(seconds / 60)} min`; if (seconds < 86400) return `${Math.floor(seconds / 3600)} h`; return `${Math.floor(seconds / 86400)} d`; };
  const formattedDate = (value) => date(value)?.toLocaleString("pt-BR") || "-";
  const iconFor = (type) => ({router:"bi-router-fill",server:"bi-server",servidor:"bi-server",camera:"bi-camera-video-fill",celular:"bi-phone-fill",phone:"bi-phone-fill",computador:"bi-pc-display",computer:"bi-pc-display",printer:"bi-printer-fill"}[String(type || "").toLowerCase()] || "bi-hdd-network-fill");
  const statusFor = (status) => ({online:"Online",offline:"Offline",stale:"Desatualizado",suspeito:"Suspeito",unknown:"Desconhecido"}[String(status || "").toLowerCase()] || "Desconhecido");
  const normalizeDevice = (raw) => ({
    id: String(raw?.device_id ?? ""), displayName: text(raw?.display_name ?? raw?.hostname, "Dispositivo sem nome"), detectedHostname: raw?.detected_hostname ?? null,
    ip: raw?.current_ip ?? raw?.ip ?? null, mac: raw?.mac ?? null, vendor: raw?.vendor ?? null, type: raw?.device_type ?? raw?.type ?? null,
    os: raw?.os_guess ?? raw?.os ?? null, status: String(raw?.status ?? "unknown").toLowerCase(), risk: Number.isFinite(Number(raw?.risk_score)) ? Number(raw.risk_score) : null,
    interface: raw?.interface ?? null, networkRole: raw?.network_role ?? null, networkCidr: raw?.network_cidr ?? null, networkId: raw?.network_id ?? null,
    ports: Array.isArray(raw?.open_ports) ? raw.open_ports.filter((item) => Number.isFinite(Number(item))).map(Number) : [], firstSeen: raw?.first_seen ?? null, lastSeen: raw?.last_seen ?? null, lastScan: raw?.last_scan ?? null
  });

  document.addEventListener("DOMContentLoaded", () => {
    const app = $("devicesApp"); if (!app) return;
    const urls = { inventory: app.dataset.urlInventory, networks: app.dataset.urlNetworks, scan: app.dataset.urlScan, rename: app.dataset.urlRename };
    const state = { devices: [], networks: [], filter: "all", tab: "inventario", search: "", selectedId: null, charts: {} };
    const tbody = $("devTableBody"), toast = $("devToast");
    const set = (id, value) => { const element = $(id); if (element) element.textContent = text(value); };
    const notify = (message, kind = "") => { if (!toast) return; toast.textContent = message; toast.className = `dev-toast${kind ? ` dev-toast--${kind}` : ""} show`; setTimeout(() => toast.classList.remove("show"), 3500); };
    const stale = (device) => device.status === "stale";
    const selected = () => state.devices.find((device) => device.id === state.selectedId);
    const matches = (device) => {
      const query = state.search.trim().toLowerCase();
      const fields = [device.displayName,device.detectedHostname,device.ip,device.mac,device.vendor,device.type,device.os,device.interface,device.networkRole,device.networkCidr].filter(Boolean).join(" ").toLowerCase();
      if (query && !fields.includes(query)) return false;
      if (state.tab === "vulneraveis" && !(device.risk >= 70)) return false;
      if (state.tab === "suspeitos" && device.status !== "suspeito") return false;
      if (state.tab === "offline" && device.status !== "offline") return false;
      if (state.filter === "online" && device.status !== "online") return false;
      if (state.filter === "offline" && device.status !== "offline") return false;
      if (state.filter === "suspeito" && device.status !== "suspeito") return false;
      return !(state.filter === "critico" && !(device.risk >= 70));
    };
    const visible = () => state.devices.filter(matches);

    function renderNetworks() {
      const target = $("devNetworksList"), count = $("devNetworksCount"); if (!target) return;
      if (count) count.textContent = `${state.networks.length} rede${state.networks.length === 1 ? "" : "s"}`;
      target.innerHTML = state.networks.length ? state.networks.map((network) => `
        <article class="dev-network-item">
          <div class="dev-network-item__top"><span class="dev-network-item__role"><i class="bi ${network.role?.toLowerCase() === "wan" ? "bi-globe2" : "bi-diagram-3"}" aria-hidden="true"></i> ${escapeHtml(network.role || "Rede")}</span><span class="dev-network-item__state${network.allowed ? "" : " dev-network-item__state--unavailable"}">${network.allowed ? "Autorizada" : "Indisponível"}</span></div>
          <p class="dev-network-item__meta">${escapeHtml(network.interface || "—")}<span>${escapeHtml(network.cidr || "—")}</span></p>
          <div class="dev-network-item__last"><span>${Number(network.device_count || 0)} dispositivos</span><span>${network.last_scan ? `Último scan: ${escapeHtml(relative(network.last_scan))}` : "Sem scan registrado"}</span></div>
        </article>`).join("") : '<p class="dev-network-empty">Nenhuma rede monitorada disponível.</p>';
    }
    function renderKpis() {
      const now = Date.now(), items = state.devices;
      const counts = { total: items.length, online: items.filter((item) => item.status === "online").length, offline: items.filter((item) => item.status === "offline").length, suspect: items.filter((item) => item.status === "suspeito").length, critical: items.filter((item) => item.risk >= 70).length, newest: items.filter((item) => date(item.firstSeen) && now - date(item.firstSeen) <= 86400000).length };
      [["kpiTotal",counts.total],["kpiOnline",counts.online],["kpiOffline",counts.offline],["kpiSuspect",counts.suspect],["kpiCritico",counts.critical],["kpiNew",counts.newest]].forEach(([id,value]) => set(id,value));
      const mode = (key) => { const values = items.reduce((total, item) => { const value = text(item[key], "Desconhecido"); total[value] = (total[value] || 0) + 1; return total; }, {}); return Object.entries(values).sort((a,b) => b[1] - a[1])[0]?.[0] || "-"; };
      set("kpiTopType", mode("type")); set("kpiTopOS", mode("os"));
      [["kpiOnlineBar",counts.online],["kpiOfflineBar",counts.offline],["kpiSuspectBar",counts.suspect],["kpicriticoBar",counts.critical],["kpiNewBar",counts.newest]].forEach(([id,value]) => { const bar = $(id); if (bar) bar.style.width = counts.total ? `${Math.round((value / counts.total) * 100)}%` : "0%"; });
      const newest = items.map((item) => date(item.lastScan || item.lastSeen)).filter(Boolean).sort((a,b) => b-a)[0]; set("devLastUpdate", newest ? relative(newest) : "sem dados");
    }
    const risk = (item) => item.risk === null ? '<span class="dev-cell-dim">-</span>' : `<span class="dev-risk-badge dev-risk-badge--${item.risk >= 70 ? "high" : item.risk >= 40 ? "medium" : "low"}">${escapeHtml(item.risk)}</span>`;
    const statusBadge = (item) => `<span class="dev-status-badge dev-status-badge--${escapeHtml(item.status)}">${escapeHtml(statusFor(item.status))}</span>`;
    // Only the displayed identity is shortened; rename/search/export keep the full name.
    const deviceIdentity = (item) => {
      const generated = item.ip && item.displayName === `Desconhecido ${item.ip}`;
      const detail = generated ? item.ip : [item.detectedHostname !== item.displayName ? item.detectedHostname : null, item.type !== "Desconhecido" ? item.type : null].filter(Boolean)[0];
      return { name: generated ? "Desconhecido" : item.displayName, subtitle: [detail, item.networkRole?.toUpperCase()].filter(Boolean).join(" · ") };
    };
    function renderTable() {
      if (!tbody) return;
      const devices = visible();
      set("devTableCount", `${devices.length} dispositivo(s)`);
      tbody.innerHTML = "";
      if (!devices.length) {
        tbody.innerHTML = '<tr><td colspan="11" class="dev-no-data">Nenhum dispositivo no inventário para este filtro. <button type="button" class="dev-link-btn" data-action="scan">Escanear redes</button></td></tr>';
        return;
      }
      devices.forEach((item) => {
        const identity = deviceIdentity(item), row = document.createElement("tr");
        row.dataset.deviceId = item.id;
        row.innerHTML = `
          <td><div class="dev-name-cell"><i class="bi ${iconFor(item.type)} dev-device-icon" aria-hidden="true"></i><div class="dev-identity">
            <button type="button" class="dev-device-link" data-action="open">${escapeHtml(identity.name)}</button>
            ${identity.subtitle ? `<div class="dev-name-sub">${escapeHtml(identity.subtitle)}</div>` : ""}
            <div class="dev-name-status">${statusBadge(item)}</div>
          </div></div></td>
          <td class="dev-cell-mono">${escapeHtml(text(item.ip))}</td>
          <td class="dev-cell-mono dev-cell-mac">${escapeHtml(text(item.mac))}</td>
          <td>${escapeHtml(text(item.vendor))}</td><td>${escapeHtml(text(item.os))}</td>
          <td title="${escapeHtml(formattedDate(item.lastSeen))}">${escapeHtml(relative(item.lastSeen))}</td>
          <td class="dev-cell-dim">—</td><td class="dev-cell-dim">—</td><td class="dev-cell-dim">—</td>
          <td>${risk(item)}</td><td><div class="dev-row-actions">
            <button type="button" class="dev-row-action" data-action="open" title="Detalhes" aria-label="Detalhes de ${escapeHtml(item.displayName)}"><i class="bi bi-eye" aria-hidden="true"></i></button>
            <button type="button" class="dev-row-action" data-action="rename" title="Renomear" aria-label="Renomear ${escapeHtml(item.displayName)}"><i class="bi bi-pencil" aria-hidden="true"></i></button>
          </div></td>`;
        tbody.appendChild(row);
      });
    }
    function renderCharts() {
      const colors = ["#648fcb", "#66b6bf", "#9386bb", "#8496a8", "#7aa993", "#bca57a"];
      [["chartByType", "type"], ["chartByOS", "os"]].forEach(([id, key]) => {
        state.charts[id]?.destroy();
        delete state.charts[id];
        const canvas = $(id), legend = $(`${id}Legend`);
        if (!canvas || !legend) return;
        const values = new Map();
        state.devices.forEach((item) => { const label = text(item[key], "Desconhecido"); values.set(label, (values.get(label) || 0) + 1); });
        const entries = [...values.entries()].sort((a, b) => b[1] - a[1]);
        legend.innerHTML = entries.length ? entries.map(([label, count], index) =>
          `<li><span class="dev-chart-key" style="background:${colors[index % colors.length]}" aria-hidden="true"></span><span class="dev-chart-label">${escapeHtml(label)}</span><strong>${count}</strong></li>`
        ).join("") : '<li class="dev-cell-dim">Sem dispositivos no inventário.</li>';
        canvas.parentElement.hidden = !entries.length || !window.Chart;
        if (!entries.length || !window.Chart) return;
        state.charts[id] = new window.Chart(canvas, {
          type: "doughnut",
          data: { labels: entries.map(([label]) => label), datasets: [{ data: entries.map(([, count]) => count), backgroundColor: entries.map((_, index) => colors[index % colors.length]), borderWidth: 0, hoverOffset: 3 }] },
          options: { responsive: true, maintainAspectRatio: false, cutout: "76%", layout: { padding: 4 }, plugins: { legend: { display: false } } }
        });
      });
    }
    function openDrawer(item) {
      if (!item) return; state.selectedId = item.id;
      [["drawerHostname",item.displayName],["drawerIp",item.ip],["drawerType",item.type],["drawerStatusBadge",statusFor(item.status)],["drawerRiskScore",item.risk === null ? "-" : item.risk],["drawerRiskLabel",item.risk === null ? "Risco nao informado" : item.risk >= 70 ? "Risco elevado" : item.risk >= 40 ? "Risco moderado" : "Risco baixo"],["drawerVendor",item.vendor],["drawerOS",item.os],["drawerMac",item.mac],["drawerFirstSeen",formattedDate(item.firstSeen)],["drawerLastSeen",formattedDate(item.lastSeen)],["drawerNetworkRole",item.networkRole],["drawerInterface",item.interface],["drawerNetworkCidr",item.networkCidr],["drawerLastScan",formattedDate(item.lastScan)]].forEach(([id,value]) => set(id,value));
      const icon = $("drawerTypeIcon"); if (icon) icon.className = `bi ${iconFor(item.type)} drawer-type-icon`; const badge = $("drawerStatusBadge"); if (badge) badge.className = `dev-status-badge dev-status-badge--${item.status}`; ["dStatDNS","dStatBlock","dStatSOC","dStatFW","dStatRPM"].forEach((id) => set(id,"-"));
      const score = $("drawerRiskScore");
      if (score) score.className = `drawer-risk-score${item.risk === null ? "" : item.risk >= 70 ? " drawer-risk-score--high" : item.risk >= 40 ? " drawer-risk-score--medium" : " drawer-risk-score--low"}`;
      const services = { 22: "SSH", 53: "DNS", 80: "HTTP", 443: "HTTPS", 445: "SMB", 3389: "RDP" };
      const ports = $("drawerPortsBody");
      if (ports) {
        ports.innerHTML = item.ports.length ? "" : '<tr><td colspan="2" class="dev-no-data">Nenhuma porta observada.</td></tr>';
        item.ports.forEach((port) => {
          const row = document.createElement("tr");
          [port, services[port] || "—"].forEach((value) => { const cell = document.createElement("td"); cell.textContent = String(value); row.appendChild(cell); });
          ports.appendChild(row);
        });
      }
      ["drawerFlagNew","drawerFlagMal"].forEach((id) => { const flag=$(id); if(flag) flag.style.display="none"; }); $("devDrawer")?.classList.add("open"); $("devDrawerOverlay")?.classList.add("open");
    }
    const closeDrawer = () => { $("devDrawer")?.classList.remove("open"); $("devDrawerOverlay")?.classList.remove("open"); };
    const closeRename = () => $("renameModalOverlay")?.classList.remove("open");
    function openRename(item = selected()) { if (!item) return; state.selectedId=item.id; set("renameModalCurrent",item.displayName); set("renameModalSub",text(item.ip)); set("renameModalIp", item.ip); set("renameModalMac", item.mac); const input=$("renameInput"); if(input){input.value=item.displayName; set("renameCharCount",`${input.value.length}/80`); input.focus();} $("renameModalOverlay")?.classList.add("open"); }
    async function request(url, options = {}) { const response = await fetch(url,{credentials:"same-origin",...options}); const payload = await response.json(); if(!response.ok || payload.ok === false) throw new Error(payload.error || "Falha na solicitacao."); return payload; }
    async function refreshInventory() { const button=$("devRefreshBtn"); if(button) button.disabled=true; try { const payload=await request(urls.inventory); state.devices=Array.isArray(payload.devices)?payload.devices.map(normalizeDevice).filter((item)=>item.id):[]; renderAll(); } catch(error) { if(!state.devices.length && tbody) tbody.innerHTML='<tr><td colspan="11" class="dev-no-data">Nao foi possivel carregar o inventario.</td></tr>'; notify(error.message,"error"); } finally { if(button) button.disabled=false; } }
    async function loadNetworks() { try { const payload=await request(urls.networks); state.networks=Array.isArray(payload.networks)?payload.networks:[]; renderNetworks(); return state.networks; } catch(error) { state.networks=[]; renderNetworks(); notify(error.message,"error"); return []; } }
    async function saveRename() { const item=selected(), name=$("renameInput")?.value.trim(), button=$("renameModalSave"); if(!item || !name){notify("Informe um nome para o dispositivo.","error");return;} if(button)button.disabled=true; try { await request(urls.rename,{method:"POST",headers:{"Content-Type":"application/json","X-CSRFToken":csrf()},body:JSON.stringify({device_id:item.id,new_name:name})}); await refreshInventory(); closeRename(); notify("Nome atualizado.","success"); } catch(error){notify(error.message,"error");} finally{if(button)button.disabled=false;} }
    function exportCsv(items=visible()) { const rows=[["nome","ip","mac","vendor","tipo","os","status","risco","interface","rede","cidr","primeira_vez_visto","ultima_atividade","ultimo_scan","portas"]]; items.forEach((item)=>rows.push([item.displayName,item.ip,item.mac,item.vendor,item.type,item.os,item.status,item.risk,item.interface,item.networkRole,item.networkCidr,item.firstSeen,item.lastSeen,item.lastScan,item.ports.join("|")])); const csv=rows.map((row)=>row.map((value)=>`"${String(value??"").replace(/"/g,'""')}"`).join(",")).join("\r\n"); const link=document.createElement("a"); link.href=URL.createObjectURL(new Blob(["\uFEFF",csv],{type:"text/csv;charset=utf-8"})); link.download=`moonshield-dispositivos-${new Date().toISOString().replace(/[-:]/g,"").slice(0,13)}.csv`; link.click(); URL.revokeObjectURL(link.href); }
    function renderAll(){renderKpis();renderTable();renderCharts();renderNetworks();if(selected())openDrawer(selected());}
    $("devRefreshBtn")?.addEventListener("click",refreshInventory); $("devExportBtn")?.addEventListener("click",()=>exportCsv()); $("daBtnExport")?.addEventListener("click",()=>{const item=selected();if(item)exportCsv([item]);}); $("devScanBtn")?.addEventListener("click",()=>document.dispatchEvent(new CustomEvent("moonshield:scan:open")));
    $("devSearch")?.addEventListener("input",(event)=>{state.search=event.target.value;renderTable();}); $("devSearchClear")?.addEventListener("click",()=>{const input=$("devSearch");if(input){input.value="";state.search="";renderTable();input.focus();}});
    document.querySelectorAll(".dev-filter-chip").forEach((button)=>button.addEventListener("click",()=>{state.filter=button.dataset.filter||"all";document.querySelectorAll(".dev-filter-chip").forEach((item)=>item.classList.toggle("dev-filter-chip--active",item===button));renderTable();})); document.querySelectorAll(".dev-tab-btn").forEach((button)=>button.addEventListener("click",()=>{state.tab=button.dataset.tab||"inventario";document.querySelectorAll(".dev-tab-btn").forEach((item)=>item.classList.toggle("dev-tab-btn--active",item===button));renderTable();}));
        tbody?.addEventListener("click", (event) => {
      const actionButton = event.target.closest("[data-action]");
      const action = actionButton?.dataset.action;
      if (action === "scan") { document.dispatchEvent(new CustomEvent("moonshield:scan:open")); return; }
      const row = event.target.closest("tr[data-device-id]");
      const item = state.devices.find((device) => device.id === row?.dataset.deviceId);
      if (!item) return;
      if (action === "rename") { openRename(item); return; }
      if (action === "open" || !actionButton) openDrawer(item);
    }); $("devDrawerClose")?.addEventListener("click",closeDrawer); $("devDrawerOverlay")?.addEventListener("click",closeDrawer); $("daBtnRename")?.addEventListener("click",()=>openRename()); $("renameModalClose")?.addEventListener("click",closeRename); $("renameModalCancel")?.addEventListener("click",closeRename); $("renameModalOverlay")?.addEventListener("click",(event)=>{if(event.target===event.currentTarget)closeRename();}); $("renameInput")?.addEventListener("input",(event)=>set("renameCharCount",`${event.target.value.length}/80`)); $("renameModalSave")?.addEventListener("click",saveRename);
    window.MoonShieldDevices={urls,state,escapeHtml,getCsrfToken:csrf,notify,refreshInventory,loadNetworks,renderNetworks}; refreshInventory(); loadNetworks();
  });
})();
