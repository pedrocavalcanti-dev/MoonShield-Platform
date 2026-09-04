/**
 * MOONSHIELD — DISPOSITIVOS.JS  v2
 * SQLite + cache TTL + destaque "EU" + auto-refresh + modal renomear
 */

document.addEventListener('DOMContentLoaded', () => {

    /* ══════════════════════════════════════════════════════
       UTILITÁRIOS
    ══════════════════════════════════════════════════════ */
    const $ = id => document.getElementById(id);

    function rand(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
    function pad(n) { return String(n).padStart(2, '0'); }
    function fmtNum(n) { return n >= 1000 ? (n / 1000).toFixed(1) + 'k' : String(n); }

    function fmtRelative(isoString) {
        if (!isoString) return '—';
        const diff = Math.floor((Date.now() - new Date(isoString)) / 1000);
        if (diff < 10)   return 'Agora';
        if (diff < 60)   return `${diff}s atrás`;
        if (diff < 3600) return `${Math.floor(diff / 60)}min atrás`;
        if (diff < 86400) return `${Math.floor(diff / 3600)}h atrás`;
        return `${Math.floor(diff / 86400)}d atrás`;
    }

    // Estado global
    let DEVICES      = [];
    let ME_IPS       = [];
    let globalSearch = '';
    let activeFilter = 'all';
    let activeTab    = 'inventario';
    let selectedDevice = null;
    let renameTargetIp = null;
    let scanInFlight = false;
    let scanController = null;

    const SCAN_TTL_MS = 120_000;
    const SCAN_TTL_SEC = 120;
    const SCAN_TIMEOUT_MS = 90_000;

    /* ══════════════════════════════════════════════════════
       ÍCONES CORRETOS (Bootstrap Icons)
       Mapeamento por tipo de dispositivo e SO
    ══════════════════════════════════════════════════════ */
    function getDeviceIcon(type, hostname, os, openPorts) {
        const t  = (type     || '').toLowerCase();
        const hn = (hostname || '').toLowerCase();
        const o  = (os       || '').toLowerCase();
        const ports = (openPorts || []).map(p => p.port);

        // Tipo explícito
        if (t.includes('roteador') || t.includes('router') || t.includes('iot'))
            return 'bi-router-fill';
        if (t.includes('servidor') || t.includes('server'))
            return 'bi-server';
        if (t.includes('switch'))
            return 'bi-diagram-3-fill';
        if (t.includes('firewall'))
            return 'bi-shield-fill';
        if (t.includes('impressora') || t.includes('printer'))
            return 'bi-printer-fill';
        if (t.includes('câmera') || t.includes('camera') || t.includes('nvr'))
            return 'bi-camera-video-fill';
        if (t.includes('celular') || t.includes('phone') || t.includes('mobile'))
            return 'bi-phone-fill';
        if (t.includes('tablet'))
            return 'bi-tablet-fill';
        if (t.includes('tv') || t.includes('smart tv'))
            return 'bi-tv-fill';
        if (t.includes('nas') || t.includes('storage'))
            return 'bi-hdd-rack-fill';
        if (t.includes('ap ') || t.includes('access point') || t.includes('ponto de acesso'))
            return 'bi-broadcast-pin';
        if (t.includes('notebook') || t.includes('laptop'))
            return 'bi-laptop-fill';

        // Por SO
        if (o.includes('windows')) {
            if (ports.includes(3389) || hn.includes('srv') || hn.includes('server'))
                return 'bi-server';
            return 'bi-pc-display-horizontal';
        }
        if (o.includes('linux')) {
            if (ports.includes(80) || ports.includes(443) || ports.includes(22))
                return 'bi-server';
            return 'bi-terminal-fill';
        }
        if (o.includes('macos') || o.includes('apple') || o.includes('ios'))
            return 'bi-apple';
        if (o.includes('android'))
            return 'bi-android2';

        // Por hostname heurístico
        if (/\b(rt|router|gw|gateway)\b/.test(hn))  return 'bi-router-fill';
        if (/\b(nas|storage|backup)\b/.test(hn))     return 'bi-hdd-rack-fill';
        if (/\b(srv|server|dc|ad)\b/.test(hn))       return 'bi-server';
        if (/\b(cam|nvr|dvr|cctv)\b/.test(hn))       return 'bi-camera-video-fill';
        if (/\b(nb|laptop|note)\b/.test(hn))         return 'bi-laptop-fill';
        if (/\b(iphone|ipad|android|phone)\b/.test(hn)) return 'bi-phone-fill';
        if (/\b(print|hp|epson|canon|brother)\b/.test(hn)) return 'bi-printer-fill';
        if (/\b(ap|wap|wifi)\b/.test(hn))            return 'bi-broadcast-pin';
        if (/\b(switch|sw)\b/.test(hn))              return 'bi-diagram-3-fill';
        if (/\b(pc|desktop|comp|len|dell|acer|asus|msi)\b/.test(hn)) return 'bi-pc-display-horizontal';

        return 'bi-hdd-network-fill';
    }

    function osIcon(os) {
        const o = (os || '').toLowerCase();
        if (o.includes('windows'))                          return 'bi-windows';
        if (o.includes('linux') || o.includes('servidor'))  return 'bi-terminal-fill';
        if (o.includes('macos') || o.includes('apple') || o.includes('ios')) return 'bi-apple';
        if (o.includes('android'))                          return 'bi-android2';
        if (o.includes('router') || o.includes('iot'))      return 'bi-router-fill';
        return 'bi-cpu-fill';
    }

    /* ══════════════════════════════════════════════════════
       CHART.JS
    ══════════════════════════════════════════════════════ */
    Chart.defaults.color                           = 'rgba(255,255,255,0.25)';
    Chart.defaults.font.family                     = "'JetBrains Mono', monospace";
    Chart.defaults.font.size                       = 10;
    Chart.defaults.plugins.legend.display          = false;
    Chart.defaults.plugins.tooltip.backgroundColor = '#0d1117';
    Chart.defaults.plugins.tooltip.borderColor     = 'rgba(255,255,255,0.10)';

    const HOURS = Array.from({ length: 24 }, (_, i) => {
        const h = (new Date().getHours() - 23 + i + 24) % 24;
        return `${pad(h)}h`;
    });

    let chartTypeInstance = null;
    let chartOSInstance   = null;

    /* ══════════════════════════════════════════════════════
       KPIs — COM BARRAS ANIMADAS
    ══════════════════════════════════════════════════════ */
    function renderKPIs() {
        const total    = DEVICES.length;
        const online   = DEVICES.filter(d => d.status === 'online').length;
        const offline  = DEVICES.filter(d => d.status === 'offline').length;
        const suspeito = DEVICES.filter(d => d.status === 'suspeito').length;
        const critico  = DEVICES.filter(d => d.risk_score >= 60).length;
        const novos    = DEVICES.filter(d => d.is_new).length;
        const topType  = total > 0 ? modeOf(DEVICES.map(d => d.type)) : '—';
        const topOS    = total > 0 ? modeOf(DEVICES.map(d => d.os.split(' ')[0])) : '—';

        $('kpiTotal').textContent   = total    || '—';
        $('kpiOnline').textContent  = online   || '—';
        $('kpiOffline').textContent = offline  || '—';
        $('kpiSuspect').textContent = suspeito || '—';
        $('kpiCritico').textContent = critico  || '—';
        $('kpiNew').textContent     = novos    || '0';
        $('kpiTopType').textContent = topType;
        $('kpiTopOS').textContent   = topOS;

        // Barras de progresso animadas
        if (total > 0) {
            requestAnimationFrame(() => {
                const set = (id, pct) => {
                    const el = $(id);
                    if (el) el.style.width = Math.round(pct) + '%';
                };
                set('kpiOnlineBar',   (online   / total) * 100);
                set('kpiOfflineBar',  (offline  / total) * 100);
                set('kpiSuspectBar',  (suspeito / total) * 100);
                set('kpicriticoBar',  (critico  / total) * 100);
            });
        }
    }

    function modeOf(arr) {
        if (!arr.length) return '—';
        const cnt = {};
        arr.forEach(v => cnt[v] = (cnt[v] || 0) + 1);
        return Object.entries(cnt).sort((a, b) => b[1] - a[1])[0][0];
    }

    function countBy(arr, key) {
        const cnt = {};
        arr.forEach(d => { const v = d[key] || 'Desconhecido'; cnt[v] = (cnt[v] || 0) + 1; });
        return cnt;
    }

    /* ══════════════════════════════════════════════════════
       GRÁFICOS DONUT
    ══════════════════════════════════════════════════════ */
    function mkDonut(id, labels, data, colors, instance) {
        const el = $(id); if (!el) return instance;
        if (instance) instance.destroy();
        return new Chart(el, {
            type: 'doughnut',
            data: { labels, datasets: [{ data, backgroundColor: colors, borderWidth: 0, hoverOffset: 6 }] },
            options: { responsive: true, maintainAspectRatio: false, cutout: '68%' },
        });
    }

    function renderCharts() {
        if (!DEVICES.length) return;
        const byType = countBy(DEVICES, 'type');
        chartTypeInstance = mkDonut('chartByType',
            Object.keys(byType), Object.values(byType),
            ['#3b82f6','#22c55e','#f97316','#a855f7','#06b6d4','#eab308','#ef4444','#64748b'],
            chartTypeInstance);

        const byOS = countBy(DEVICES, 'os');
        chartOSInstance = mkDonut('chartByOS',
            Object.keys(byOS).map(k => k.split(' ')[0]), Object.values(byOS),
            ['#3b82f6','#f97316','#a855f7','#22c55e','#ef4444','#06b6d4','#eab308','#64748b'],
            chartOSInstance);
    }

    /* ══════════════════════════════════════════════════════
       MAPA DE REDE
    ══════════════════════════════════════════════════════ */
    function renderNetworkMap() {
        const wrap   = $('devNetworkMap'); if (!wrap) return;
        const online = DEVICES.filter(d => d.status === 'online').slice(0, 10);

        if (!online.length) {
            wrap.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text-dim)">Nenhum dispositivo mapeado.</div>';
            return;
        }

        wrap.innerHTML = `
          <div class="dev-map-root">
            <div class="dev-map-node dev-map-node--fw" title="Firewall / Gateway">
              <i class="bi bi-shield-fill" style="color:#3b82f6;font-size:18px"></i>
              <span>Firewall</span>
            </div>
            <div class="dev-map-line"></div>
            <div class="dev-map-node dev-map-node--sw" title="Switch Core">
              <i class="bi bi-diagram-3-fill" style="color:#a855f7;font-size:16px"></i>
              <span>Switch</span>
            </div>
            <div class="dev-map-branches">
              ${online.slice(0, 8).map(d => `
                <div class="dev-map-branch">
                  <div class="dev-map-branch-line"></div>
                  <div class="dev-map-node dev-map-node--leaf${d.is_me ? ' dev-map-node--me' : ''}"
                       title="${d.hostname} · ${d.ip}${d.is_me ? ' · VOCÊ' : ''}">
                    <span class="dev-map-dot" style="background:#22c55e"></span>
                    <i class="bi ${d.icon}" style="color:${d.is_me ? '#00D4FF' : '#22c55e'};font-size:12px"></i>
                    <span class="dev-map-ip">${d.ip}</span>
                  </div>
                </div>`).join('')}
            </div>
          </div>`;
    }

    /* ══════════════════════════════════════════════════════
       TABELA PRINCIPAL
    ══════════════════════════════════════════════════════ */
    function filteredDevices() {
        return DEVICES.filter(d => {
            const matchFilter =
                activeFilter === 'all'    ||
                d.status === activeFilter ||
                (activeFilter === 'critico' && d.risk_score >= 60);
            const q = globalSearch.toLowerCase();
            const matchSearch = !q ||
                (d.hostname && d.hostname.toLowerCase().includes(q)) ||
                (d.ip       && d.ip.includes(q))                     ||
                (d.mac      && d.mac.toLowerCase().includes(q))      ||
                (d.vendor   && d.vendor.toLowerCase().includes(q));
            return matchFilter && matchSearch;
        });
    }

    function tabDevices() {
        const base = filteredDevices();
        if (activeTab === 'inventario')  return base;
        if (activeTab === 'vulneraveis') return base.filter(d => d.open_ports?.some(p => p.risk === 'high'));
        if (activeTab === 'suspeitos')   return base.filter(d => d.status === 'suspeito');
        if (activeTab === 'offline')     return base.filter(d => d.status === 'offline');
        return base;
    }

    function riskBadge(score) {
        const cls = score >= 60 ? 'high' : score >= 30 ? 'medium' : 'low';
        const lbl = score >= 60 ? 'Alto'  : score >= 30 ? 'Médio'  : 'Baixo';
        return `<span class="dev-risk-badge dev-risk-badge--${cls}">${score} <span style="font-weight:400;opacity:.75">${lbl}</span></span>`;
    }

    function renderTable() {
        const rows = tabDevices();
        $('devTableCount').textContent = `${rows.length} dispositivo${rows.length !== 1 ? 's' : ''}`;

        if (!rows.length) {
            $('devTableBody').innerHTML =
                '<tr><td colspan="12" style="text-align:center;padding:30px;color:var(--text-dim)">Nenhum dispositivo encontrado.</td></tr>';
            return;
        }

        $('devTableBody').innerHTML = rows.map((d, i) => {
            const isMe = d.is_me === true;
            return `
              <tr data-did="${d.ip}"
                  class="${isMe ? 'dev-row-me' : ''}"
                  style="animation:rowIn .18s ${i * 12}ms both;cursor:pointer">
                <td>
                  <span class="dev-status-dot ${d.status === 'online' ? 'dev-dot--pulse' : ''}"
                        style="background:${d.status === 'online' ? '#22c55e' : d.status === 'suspeito' ? '#f97316' : '#64748b'}">
                  </span>
                </td>
                <td>
                  <div class="dev-name-cell">
                    <i class="bi ${d.icon} dev-type-icon" style="${isMe ? 'color:#00D4FF' : ''}"></i>
                    <div>
                      <p class="dev-name${isMe ? ' dev-name--me' : ''}">${d.hostname}</p>
                      <p class="dev-name-sub">${d.type}</p>
                    </div>
                  </div>
                </td>
                <td class="dev-cell-mono">${d.ip}</td>
                <td class="dev-cell-mono dev-cell-mac">${d.mac}</td>
                <td><span class="dev-vendor-badge">${d.vendor}</span></td>
                <td class="dev-cell-os">
                  <i class="bi ${osIcon(d.os)} dev-os-icon"></i> ${d.os}
                </td>
                <td class="dev-cell-mono dev-cell-dim">${fmtRelative(d.last_seen)}</td>
                <td class="dev-cell-mono">${fmtNum(d.queries_dns)}</td>
                <td class="dev-cell-mono">${fmtNum(d.blocked_dns)}</td>
                <td class="dev-cell-mono">${d.soc_events}</td>
                <td>${riskBadge(d.risk_score)}</td>
                <td>
                  <div class="dev-row-actions">
                    <button class="dev-row-btn" data-did="${d.ip}" data-act="view" title="Ver detalhes">
                      <i class="bi bi-eye-fill"></i>
                    </button>
                    <button class="dev-row-btn" data-did="${d.ip}" data-act="rename" title="Renomear">
                      <i class="bi bi-pencil-fill"></i>
                    </button>
                  </div>
                </td>
              </tr>`;
        }).join('');

        $('devTableBody').querySelectorAll('[data-act]').forEach(btn => {
            btn.addEventListener('click', e => {
                e.stopPropagation();
                const ip = btn.dataset.did;
                if (btn.dataset.act === 'view')   openDrawer(ip);
                if (btn.dataset.act === 'rename') openRenameModal(ip);
            });
        });

        $('devTableBody').querySelectorAll('tr[data-did]').forEach(tr => {
            tr.addEventListener('click', e => {
                if (e.target.closest('[data-act]')) return;
                openDrawer(tr.dataset.did);
            });
        });
    }

    /* ══════════════════════════════════════════════════════
       MODAL RENOMEAR
    ══════════════════════════════════════════════════════ */
    function openRenameModal(ip) {
        const d = DEVICES.find(x => x.ip === ip);
        if (!d) return;

        renameTargetIp = ip;

        $('renameModalSub').textContent     = ip;
        $('renameModalCurrent').textContent = d.hostname;
        $('renameInput').value              = d.hostname;
        $('renameCharCount').textContent    = `${d.hostname.length}/80`;

        $('renameModalOverlay').classList.add('open');
        setTimeout(() => $('renameInput').focus(), 50);
    }

    function closeRenameModal() {
        $('renameModalOverlay').classList.remove('open');
        renameTargetIp = null;
    }

    async function submitRename() {
        const newName = $('renameInput').value.trim();
        if (!newName || !renameTargetIp) return;

        const saveBtn = $('renameModalSave');
        saveBtn.classList.add('saving');
        saveBtn.querySelector('span').textContent = 'Salvando…';

        try {
            const res = await fetch('/dispositivos/api/rename/', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: renameTargetIp, new_name: newName }),
            });

            if (!res.ok) throw new Error(`HTTP ${res.status}`);

            // Atualiza localmente
            const d = DEVICES.find(x => x.ip === renameTargetIp);
            if (d) {
                d.hostname = newName;
                d.icon     = getDeviceIcon(d.type, newName, d.os, d.open_ports);
            }

            renderTable();
            renderNetworkMap();

            // Se o drawer estiver aberto para este dispositivo, atualiza também
            if (selectedDevice && selectedDevice.ip === renameTargetIp) {
                $('drawerHostname').textContent = newName;
            }

            showToast(`✅ "${newName}" salvo com sucesso`);
            closeRenameModal();

        } catch (err) {
            console.error(err);
            showToast('❌ Erro ao salvar nome. Tente novamente.');
        } finally {
            saveBtn.classList.remove('saving');
            saveBtn.querySelector('span').textContent = 'Salvar';
        }
    }

    // Contador de caracteres
    $('renameInput').addEventListener('input', () => {
        const len = $('renameInput').value.length;
        $('renameCharCount').textContent = `${len}/80`;
    });

    // Enter para salvar
    $('renameInput').addEventListener('keydown', e => {
        if (e.key === 'Enter') submitRename();
        if (e.key === 'Escape') closeRenameModal();
    });

    $('renameModalSave').addEventListener('click', submitRename);
    $('renameModalCancel').addEventListener('click', closeRenameModal);
    $('renameModalClose').addEventListener('click', closeRenameModal);
    $('renameModalOverlay').addEventListener('click', e => {
        if (e.target === $('renameModalOverlay')) closeRenameModal();
    });

    /* ══════════════════════════════════════════════════════
       SCAN
    ══════════════════════════════════════════════════════ */
    async function doScan(force = false) {
        if (scanInFlight) {
            if (force) showToast('⏳ Já existe uma varredura em andamento.');
            return;
        }

        const btn = $('devScanBtn');
        const refreshBtn = $('devRefreshBtn');

        scanInFlight = true;
        btn?.classList.add('dev-scanning');

        if (btn) btn.disabled = true;
        if (refreshBtn) refreshBtn.disabled = true;

        showToast(
            force
                ? '🔍 Forçando varredura em todas as interfaces…'
                : '🔄 Verificando WAN, LAN, MGMT e demais interfaces…'
        );

        scanController = new AbortController();
        const timeout = setTimeout(
            () => scanController?.abort(),
            SCAN_TIMEOUT_MS
        );

        try {
            const response = await fetch(
                '/dispositivos/api/scan/',
                {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        ttl_seconds: SCAN_TTL_SEC,
                        force,
                    }),
                    signal: scanController.signal,
                    cache: 'no-store',
                }
            );

            let data = null;

            try {
                data = await response.json();
            } catch (_) {
                throw new Error(
                    `Resposta inválida da API (HTTP ${response.status})`
                );
            }

            if (!response.ok) {
                throw new Error(
                    data?.erro || `HTTP ${response.status}`
                );
            }

            if (!Array.isArray(data.devices)) {
                throw new Error(
                    'A API não retornou a lista de dispositivos.'
                );
            }

            ME_IPS = data.me?.ips || [];

            DEVICES = data.devices.map((d, index) => {
                const icon = getDeviceIcon(
                    d.type,
                    d.hostname,
                    d.os,
                    d.open_ports
                );

                return {
                    id: index + 1,
                    hostname: d.hostname || 'Desconhecido',
                    ip: d.ip,
                    mac: d.mac || 'Desconhecido',
                    vendor: d.vendor || 'Genérico',
                    os: d.os || 'Desconhecido',
                    status: d.status || 'online',
                    type: d.type || 'Dispositivo',
                    icon,
                    open_ports: d.open_ports || [],
                    risk_score: d.risk_score || 10,
                    first_seen: d.first_seen || null,
                    last_seen: d.last_seen || null,
                    is_me: d.is_me === true,
                    is_new: false,
                    malicious_comm: false,
                    network: d.network || null,
                    interfaces: Array.isArray(d.interfaces)
                        ? d.interfaces
                        : [],

                    // Telemetria ainda simulada.
                    telemetry_mode: 'simulated',
                    queries_dns: rand(100, 2000),
                    blocked_dns: rand(0, 50),
                    soc_events: rand(0, 2),
                    fw_connections: rand(10, 300),
                    req_min: rand(1, 10),
                    dns_hourly: Array.from(
                        { length: 24 },
                        () => rand(0, 100)
                    ),
                    blocked_hourly: Array.from(
                        { length: 24 },
                        () => rand(0, 20)
                    ),
                    conn_hourly: Array.from(
                        { length: 24 },
                        () => rand(0, 50)
                    ),
                    ip_history: [{
                        ip: d.ip,
                        since: d.first_seen
                            ? fmtRelative(d.first_seen)
                            : 'Hoje',
                    }],
                    soc_events_list: [],
                };
            });

            const now = new Date();
            const lbl = $('devLastUpdate');

            if (lbl) {
                lbl.textContent = `${pad(now.getHours())}:${pad(now.getMinutes())}`;
            }

            renderKPIs();
            renderTable();
            renderNetworkMap();
            renderCharts();

            const networks = Array.isArray(data.networks)
                ? data.networks
                : [];

            const scanned = networks.filter(
                item => !item.skipped
            );

            const skipped = networks.filter(
                item => item.skipped
            );

            const interfaces = Array.isArray(
                data.scan_interfaces
            )
                ? data.scan_interfaces
                : [];

            const networkText = scanned.length
                ? ` · ${scanned.length} rede${
                    scanned.length !== 1 ? 's' : ''
                }`
                : '';

            const interfaceText = interfaces.length
                ? ` · ${interfaces.join(', ')}`
                : '';

            const skippedText = skipped.length
                ? ` · ${skipped.length} ignorada${
                    skipped.length !== 1 ? 's' : ''
                }`
                : '';

            showToast(
                `✓ ${DEVICES.length} dispositivo${
                    DEVICES.length !== 1 ? 's' : ''
                } encontrado${
                    DEVICES.length !== 1 ? 's' : ''
                }${networkText}${interfaceText}${skippedText}`
            );

        } catch (err) {
            console.error('MoonShield network scan:', err);

            if (err?.name === 'AbortError') {
                showToast(
                    '❌ O scan excedeu 45s e foi cancelado. Verifique a API/rede.'
                );
            } else {
                showToast(
                    `❌ Falha no scan: ${err?.message || 'erro desconhecido'}`
                );
            }

        } finally {
            clearTimeout(timeout);
            scanController = null;
            scanInFlight = false;

            btn?.classList.remove('dev-scanning');

            if (btn) btn.disabled = false;
            if (refreshBtn) refreshBtn.disabled = false;
        }
    }

    $('devScanBtn').addEventListener('click',   () => doScan(true));
    $('devRefreshBtn').addEventListener('click', () => doScan(false));

    // Auto-refresh silencioso (usa cache)
    setInterval(() => doScan(false), SCAN_TTL_MS);

    /* ══════════════════════════════════════════════════════
       DRAWER
    ══════════════════════════════════════════════════════ */
    let drawerDnsChart = null, drawerBlockChart = null, drawerConnChart = null;

    function openDrawer(ip) {
        const d = DEVICES.find(x => x.ip === ip); if (!d) return;
        selectedDevice = d;

        $('drawerHostname').textContent  = d.hostname;
        $('drawerIp').textContent        = d.ip;
        $('drawerMac').textContent       = d.mac;
        $('drawerVendor').textContent    = d.vendor;
        $('drawerOS').textContent        = d.os;
        $('drawerType').textContent      = d.type;
        $('drawerTypeIcon').className    = `bi ${d.icon} drawer-type-icon${d.is_me ? ' drawer-type-icon--me' : ''}`;
        $('drawerLastSeen').textContent  = fmtRelative(d.last_seen);
        $('drawerFirstSeen').textContent = fmtRelative(d.first_seen);

        // Clique no hostname → abre modal de renomear
        const titleEl = $('drawerHostname');
        titleEl.title = 'Clique para renomear';
        titleEl.onclick = () => openRenameModal(d.ip);

        // Badge status
        const sb = $('drawerStatusBadge');
        sb.textContent = d.status.toUpperCase();
        sb.className   = `dev-status-badge dev-status-badge--${d.status}`;

        // Risk score
        const rs    = $('drawerRiskScore');
        const rsCls = d.risk_score >= 60 ? 'high' : d.risk_score >= 30 ? 'medium' : 'low';
        rs.textContent = d.risk_score;
        rs.className   = `drawer-risk-score drawer-risk-score--${rsCls}`;
        $('drawerRiskLabel').textContent = d.risk_score >= 60 ? 'Risco Alto' : d.risk_score >= 30 ? 'Risco Médio' : 'Risco Baixo';

        $('dStatDNS').textContent   = fmtNum(d.queries_dns);
        $('dStatBlock').textContent = fmtNum(d.blocked_dns);
        $('dStatSOC').textContent   = d.soc_events;
        $('dStatFW').textContent    = d.fw_connections;
        $('dStatRPM').textContent   = d.req_min;

        const portRisk = { high: 'dev-risk-badge--high', medium: 'dev-risk-badge--medium', low: 'dev-risk-badge--low' };
        $('drawerPortsBody').innerHTML = d.open_ports?.length
            ? d.open_ports.map(p => `
                <tr>
                  <td class="dev-cell-mono">${p.port}</td>
                  <td>${p.service}</td>
                  <td class="dev-cell-mono">${p.proto}</td>
                  <td><span class="dev-risk-badge ${portRisk[p.risk] || ''}">${p.risk}</span></td>
                </tr>`).join('')
            : '<tr><td colspan="4" class="dev-cell-dim" style="text-align:center;padding:12px">Nenhuma porta aberta detectada.</td></tr>';

        $('drawerSocList').innerHTML =
            '<p class="dev-cell-dim" style="padding:12px;font-size:12px">Nenhum evento registrado.</p>';

        $('drawerIpHistory').innerHTML = d.ip_history.map(h => `
            <div class="drawer-ip-hist">
              <span class="dev-cell-mono">${h.ip}</span>
              <span class="dev-cell-dim" style="font-size:11px">desde ${h.since}</span>
            </div>`).join('');

        $('drawerFlagNew').style.display = d.is_new         ? '' : 'none';
        $('drawerFlagMal').style.display = d.malicious_comm ? '' : 'none';

        if (drawerDnsChart)   drawerDnsChart.destroy();
        if (drawerBlockChart) drawerBlockChart.destroy();
        if (drawerConnChart)  drawerConnChart.destroy();

        drawerDnsChart   = mkMiniLine('drawerChartDNS',   d.dns_hourly,     '#3b82f6');
        drawerBlockChart = mkMiniLine('drawerChartBlock',  d.blocked_hourly, '#ef4444');
        drawerConnChart  = mkMiniLine('drawerChartConn',   d.conn_hourly,    '#22c55e');

        $('devDrawer').classList.add('open');
        $('devDrawerOverlay').classList.add('open');
    }

    // Botão renomear no footer do drawer
    $('daBtnRename').addEventListener('click', () => {
        if (selectedDevice) openRenameModal(selectedDevice.ip);
    });

    function mkMiniLine(id, data, color) {
        const el = $(id); if (!el) return null;
        const [r, g, b] = [
            parseInt(color.slice(1, 3), 16),
            parseInt(color.slice(3, 5), 16),
            parseInt(color.slice(5, 7), 16),
        ];
        return new Chart(el, {
            type: 'line',
            data: {
                labels: HOURS,
                datasets: [{
                    data,
                    borderColor: color, borderWidth: 2,
                    fill: true, backgroundColor: `rgba(${r},${g},${b},0.12)`,
                    tension: 0.4, pointRadius: 0, pointHoverRadius: 4,
                }],
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                interaction: { mode: 'index', intersect: false },
                plugins: { legend: { display: false } },
                scales: { x: { display: false }, y: { display: false, min: 0 } },
                animation: { duration: 600 },
            },
        });
    }

    function closeDrawer() {
        $('devDrawer').classList.remove('open');
        $('devDrawerOverlay').classList.remove('open');
        selectedDevice = null;
    }

    $('devDrawerClose').addEventListener('click', closeDrawer);
    $('devDrawerOverlay').addEventListener('click', closeDrawer);
    document.addEventListener('keydown', e => {
        if (e.key === 'Escape') {
            if ($('renameModalOverlay').classList.contains('open')) closeRenameModal();
            else closeDrawer();
        }
    });

    /* ══════════════════════════════════════════════════════
       FILTROS · TABS · BUSCA
    ══════════════════════════════════════════════════════ */
    document.querySelectorAll('.dev-tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.dev-tab-btn').forEach(b => b.classList.remove('dev-tab-btn--active'));
            btn.classList.add('dev-tab-btn--active');
            activeTab = btn.dataset.tab;
            renderTable();
        });
    });

    document.querySelectorAll('.dev-filter-chip').forEach(chip => {
        chip.addEventListener('click', () => {
            document.querySelectorAll('.dev-filter-chip').forEach(c => c.classList.remove('dev-filter-chip--active'));
            chip.classList.add('dev-filter-chip--active');
            activeFilter = chip.dataset.filter;
            renderTable();
        });
    });

    $('devSearch').addEventListener('input', () => {
        globalSearch = $('devSearch').value.trim();
        $('devSearchClear').classList.toggle('visible', globalSearch.length > 0);
        renderTable();
    });

    $('devSearchClear').addEventListener('click', () => {
        $('devSearch').value = '';
        globalSearch = '';
        $('devSearchClear').classList.remove('visible');
        renderTable();
    });

    /* ══════════════════════════════════════════════════════
       TOAST
    ══════════════════════════════════════════════════════ */
    let toastTimer;
    function showToast(msg) {
        const t = $('devToast');
        t.textContent = msg;
        t.classList.add('show');
        clearTimeout(toastTimer);
        toastTimer = setTimeout(() => t.classList.remove('show'), 3500);
    }

    /* ══════════════════════════════════════════════════════
       CSS DINÂMICO
    ══════════════════════════════════════════════════════ */
    document.head.appendChild(Object.assign(document.createElement('style'), {
        textContent: `
          @keyframes rowIn { from{opacity:0;transform:translateX(-6px)}to{opacity:1;transform:none} }
        `,
    }));

    /* ══════════════════════════════════════════════════════
       INIT
    ══════════════════════════════════════════════════════ */
    renderKPIs();
    renderTable();
    setTimeout(() => doScan(false), 1000);
});