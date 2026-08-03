/**
 * MOONSHIELD — FIREWALL.JS  v6 (Dashboard)
 * Dashboard only: KPIs, Charts, Health, Top Atacantes, Live Feed
 * Regras/Logs/NAT/Listas → firewall/regras/ e firewall/feed/
 */

document.addEventListener('DOMContentLoaded', () => {

  /* ═══════════════════════════════════════════════════════
     UTILITÁRIOS
  ═══════════════════════════════════════════════════════ */
  const $ = id => document.getElementById(id);
  function fmtBytes(b) { return b >= 1073741824 ? (b / 1073741824).toFixed(1) + 'GB' : b >= 1048576 ? (b / 1048576).toFixed(1) + 'MB' : b >= 1024 ? (b / 1024).toFixed(0) + 'KB' : b + 'B'; }
  function pad(n) { return String(n).padStart(2, '0'); }
  function fmtNum(n) { return n >= 1000 ? (n / 1000).toFixed(1) + 'k' : String(n); }

  /* ═══════════════════════════════════════════════════════
     ESTADO GLOBAL
  ═══════════════════════════════════════════════════════ */
  let LOGS = [];
  let SYNC = { total: 0, pendentes: 0, aplicadas: 0, em_sync: true };
  let feedPaused = false;
  let feedCount = 0;
  let chartTraffic = null;
  let chartBlocks = null;

  /* ═══════════════════════════════════════════════════════
     CHART.JS CONFIG
  ═══════════════════════════════════════════════════════ */
  Chart.defaults.color = 'rgba(255,255,255,0.25)';
  Chart.defaults.font.family = "'JetBrains Mono', monospace";
  Chart.defaults.font.size = 10;
  Chart.defaults.plugins.legend.display = false;
  Chart.defaults.plugins.tooltip.backgroundColor = '#0d1117';
  Chart.defaults.plugins.tooltip.borderColor = 'rgba(255,255,255,0.10)';
  Chart.defaults.plugins.tooltip.borderWidth = 1;
  Chart.defaults.plugins.tooltip.titleColor = '#f0f0f0';
  Chart.defaults.plugins.tooltip.bodyColor = 'rgba(255,255,255,0.55)';
  Chart.defaults.plugins.tooltip.padding = 10;
  Chart.defaults.plugins.tooltip.cornerRadius = 8;
  const GRID = 'rgba(255,255,255,0.04)';
  const TICK = 'rgba(255,255,255,0.20)';

  /* ═══════════════════════════════════════════════════════
     SYNC STATUS — barra de sincronização
  ═══════════════════════════════════════════════════════ */
  function renderSyncBar(sync) {
    if (!sync) return;
    SYNC = sync;
    const bar = $('fwSyncBar');
    if (!bar) return;

    if (sync.pendentes === 0) {
      bar.style.display = 'none';
      return;
    }

    bar.style.display = 'flex';
    bar.style.cssText = `
      display:flex;align-items:center;gap:10px;
      margin:0 0 10px;padding:8px 14px;border-radius:6px;
      background:rgba(249,115,22,.08);border:1px solid rgba(249,115,22,.2);
      color:#fb923c;font-size:11px;font-family:var(--font-mono)`;
    bar.innerHTML = `
      <i class="bi bi-hourglass-split" style="font-size:13px;flex-shrink:0"></i>
      <span>
        <strong>${sync.pendentes} regra(s) pendente(s)</strong>
        de ${sync.total} — aguardando sincronização com o sensor Linux.
      </span>
      <button id="fwPushRulesBtn" style="
        margin-left:auto;padding:4px 12px;border-radius:4px;cursor:pointer;
        background:rgba(249,115,22,.15);border:1px solid rgba(249,115,22,.4);
        color:#fb923c;font-size:10px;font-weight:700;font-family:var(--font-mono);
        white-space:nowrap;transition:background .2s">
        <i class="bi bi-lightning-charge-fill"></i> Aplicar no Linux
      </button>`;

    $('fwPushRulesBtn')?.addEventListener('click', pushRules);
  }

  async function pushRules() {
    const btn = $('fwPushRulesBtn');
    if (btn) { btn.innerHTML = '<i class="bi bi-hourglass-split"></i> Enviando…'; btn.disabled = true; }

    try {
      const res = await fetch('/firewall/api/push-rules/', { method: 'POST', headers: { 'X-CSRFToken': getCsrf() } });
      const data = await res.json();
      if (data.ok) {
        showToast(`Sync disparado — sensor vai aplicar em até 30s ✓`);
        if (data.sync) renderSyncBar(data.sync);
      } else {
        showToast('Erro ao disparar sync', 'err');
      }
    } catch (e) {
      showToast('Falha de rede', 'err');
    }
  }

  async function exportNft() {
    showToast('Gerando arquivo .nft…');
    window.location.href = '/firewall/api/export-nft/';
  }

  /* ═══════════════════════════════════════════════════════
     CSRF
  ═══════════════════════════════════════════════════════ */
  function getCsrf() {
    const match = document.cookie.match(/csrftoken=([^;]+)/);
    return match ? match[1] : '';
  }

  /* ═══════════════════════════════════════════════════════
     API FETCH
  ═══════════════════════════════════════════════════════ */
  async function loadData(period = '24h') {
    try {
      if ($('fwRefreshBtn')) $('fwRefreshBtn').classList.add('spinning');
      const res = await fetch(`/firewall/api/data/?period=${period}`);

      if (!res.ok) {
        throw new Error('Servidor retornou erro ' + res.status);
      }

      const data = await res.json();
      if (!data.ok) throw new Error('Erro na API');

      LOGS = data.logs || [];

      if (data.sync) renderSyncBar(data.sync);

      const modeBadge = $('fwModeBadge');
      if (modeBadge) {
        modeBadge.style.display = 'inline-block';
        if (data.mode === 'prod') {
          modeBadge.textContent = 'PROD';
          modeBadge.style.cssText = 'display:inline-block;font-size:10px;font-weight:700;padding:2px 7px;border-radius:4px;margin-right:4px;letter-spacing:.5px;background:rgba(59,130,246,.18);color:#3b82f6;border:1px solid rgba(59,130,246,.3)';
        } else {
          modeBadge.textContent = 'DEMO';
          modeBadge.style.cssText = 'display:inline-block;font-size:10px;font-weight:700;padding:2px 7px;border-radius:4px;margin-right:4px;letter-spacing:.5px;background:rgba(234,179,8,.18);color:#eab308;border:1px solid rgba(234,179,8,.3)';
        }
      }

      const prodBanner = $('fwProdBanner');
      if (prodBanner) {
        if (data.waiting) {
          prodBanner.style.display = 'block';
          prodBanner.style.cssText = 'display:block;margin:0 0 12px;padding:10px 16px;border-radius:6px;background:rgba(59,130,246,.08);border:1px solid rgba(59,130,246,.2);color:#93c5fd;font-size:12px;font-family:var(--font-mono)';
          prodBanner.innerHTML = `<i class="bi bi-hourglass-split" style="margin-right:8px"></i><strong>Modo Produção ativo</strong> — Aguardando o primeiro evento do sensor. Execute no Linux: <code style="margin-left:6px;color:#60a5fa;background:rgba(59,130,246,.14);padding:1px 7px;border-radius:3px;font-size:10px">sudo venv/bin/python3 ms_firewall.py --auto</code>`;
        } else if (data.mode === 'prod') {
          prodBanner.style.display = 'none';
        } else {
          prodBanner.style.display = 'block';
          prodBanner.style.cssText = 'display:block;margin:0 0 12px;padding:10px 16px;border-radius:6px;background:rgba(234,179,8,.07);border:1px solid rgba(234,179,8,.15);color:#ca8a04;font-size:12px;font-family:var(--font-mono)';
          prodBanner.innerHTML = `<i class="bi bi-flask" style="margin-right:8px"></i><strong>Modo Demo</strong> — dados simulados. Para dados reais configure o sensor em <strong>Configurações → Integrações → Firewall</strong>.`;
        }
      }

      renderKPIs(data.metrics);
      renderCharts(data.charts);
      renderHealth(data.metrics);
      renderTopAtacantes(data.top_ips || (data.metrics?.top_ip ? [{ ip: data.metrics.top_ip, hits: data.metrics.top_ip_hits }] : []));
      renderSyncBar(data.sync);
      initFeed();

      if ($('fwLastUpdate')) {
        const d = new Date();
        $('fwLastUpdate').textContent = `Atualizado ${pad(d.getHours())}:${pad(d.getMinutes())}`;
      }
    } catch (e) {
      console.error(e);
      showToast('Erro ao carregar dados do Firewall', 'err');
    } finally {
      if ($('fwRefreshBtn')) $('fwRefreshBtn').classList.remove('spinning');
    }
  }

  /* ═══════════════════════════════════════════════════════
     RENDER: KPIs
  ═══════════════════════════════════════════════════════ */
  function renderKPIs(metrics) {
    if (!metrics) return;
    if ($('kpiTraffic')) $('kpiTraffic').textContent = (metrics.traffic_in + metrics.traffic_out) + ' MB';
    if ($('kpiTrafficTrend')) $('kpiTrafficTrend').textContent = `▲ IN ${metrics.traffic_in}MB  ▼ OUT ${metrics.traffic_out}MB`;
    if ($('kpiConexoes')) $('kpiConexoes').textContent = (metrics.conexoes || 0).toLocaleString();
    if ($('kpiDrops')) $('kpiDrops').textContent = fmtNum(metrics.drops);
    if ($('kpiAllows')) $('kpiAllows').textContent = fmtNum(metrics.allows);
    if ($('kpiTopPort')) $('kpiTopPort').textContent = ':' + metrics.top_port;
    if ($('kpiTopPortTrend')) $('kpiTopPortTrend').textContent = metrics.top_port_hits + ' tentativas';
    if ($('kpiTopIp')) $('kpiTopIp').textContent = metrics.top_ip;
    if ($('kpiTopIpTrend')) $('kpiTopIpTrend').textContent = metrics.top_ip_hits + ' hits bloqueados';
  }

  /* ═══════════════════════════════════════════════════════
     RENDER: HEALTH
  ═══════════════════════════════════════════════════════ */
  function renderHealth(metrics) {
    if (!metrics) return;
    if ($('fwResCpu')) $('fwResCpu').textContent = metrics.cpu + '%';
    if ($('fwResRam')) $('fwResRam').textContent = metrics.ram + '%';
    if ($('fwResCpuBar')) {
      $('fwResCpuBar').style.width = metrics.cpu + '%';
      $('fwResCpuBar').style.background = metrics.cpu > 70 ? 'linear-gradient(90deg,#ef4444,#f97316)' : 'linear-gradient(90deg,#3b82f6,#a855f7)';
    }
    if ($('fwResRamBar')) $('fwResRamBar').style.width = metrics.ram + '%';
  }

  /* ═══════════════════════════════════════════════════════
     RENDER: TOP ATACANTES
  ═══════════════════════════════════════════════════════ */
  function renderTopAtacantes(topIps) {
    const el = $('fwTopAtacantesList');
    if (!el || !topIps?.length) return;
    el.innerHTML = topIps.slice(0, 5).map(item => `
      <div style="display:flex;align-items:center;gap:10px;padding:8px 16px;border-bottom:1px solid rgba(255,255,255,.04)">
          <span style="font-family:var(--font-mono);font-size:12px;color:var(--text-primary);flex:1">${item.ip}</span>
          <span style="font-family:var(--font-mono);font-size:11px;color:#ef4444">${item.hits} drops</span>
          <button onclick="window.location.href='/firewall/regras/'"
              style="padding:3px 10px;border-radius:4px;background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:#ef4444;font-size:10px;font-weight:700;cursor:pointer;font-family:var(--font-mono)">
              BLOQUEAR
          </button>
      </div>`).join('');
  }

  /* ═══════════════════════════════════════════════════════
     RENDER: GRÁFICOS
  ═══════════════════════════════════════════════════════ */
  function renderCharts(chartsData) {
    if (!chartsData) return;
    const ctxT = $('fwChartTraffic');
    if (ctxT) {
      if (chartTraffic) chartTraffic.destroy();
      const ctx = ctxT.getContext('2d');
      const gradIn = (() => { const g = ctx.createLinearGradient(0, 0, 0, 190); g.addColorStop(0, 'rgba(59,130,246,0.7)'); g.addColorStop(1, 'rgba(59,130,246,0.08)'); return g; })();
      const gradOut = (() => { const g = ctx.createLinearGradient(0, 0, 0, 190); g.addColorStop(0, 'rgba(34,197,94,0.5)'); g.addColorStop(1, 'rgba(34,197,94,0.05)'); return g; })();
      chartTraffic = new Chart(ctxT, { type: 'line', data: { labels: chartsData.hours, datasets: [{ label: 'IN (MB)', data: chartsData.traffic_in, borderColor: '#3b82f6', backgroundColor: gradIn, borderWidth: 2, fill: true, tension: .45, pointRadius: 0, pointHoverRadius: 5 }, { label: 'OUT (MB)', data: chartsData.traffic_out, borderColor: '#22c55e', backgroundColor: gradOut, borderWidth: 2, fill: true, tension: .45, pointRadius: 0, pointHoverRadius: 5 }] }, options: { responsive: true, maintainAspectRatio: false, interaction: { mode: 'index', intersect: false }, plugins: { legend: { display: false }, tooltip: { callbacks: { label: i => `  ${i.dataset.label}: ${i.raw} MB` } } }, scales: { x: { grid: { color: GRID }, ticks: { maxTicksLimit: 8, color: TICK } }, y: { grid: { color: GRID }, ticks: { color: TICK }, min: 0 } }, animation: { duration: 900, easing: 'easeOutQuart' } } });
    }
    const ctxB = $('fwChartBlocks');
    if (ctxB) {
      if (chartBlocks) chartBlocks.destroy();
      const ctx = ctxB.getContext('2d');
      const gradD = (() => { const g = ctx.createLinearGradient(0, 0, 0, 150); g.addColorStop(0, 'rgba(239,68,68,0.9)'); g.addColorStop(1, 'rgba(239,68,68,0.2)'); return g; })();
      chartBlocks = new Chart(ctxB, { type: 'bar', data: { labels: chartsData.hours, datasets: [{ label: 'Drops', data: chartsData.drops, backgroundColor: gradD, borderColor: '#ef4444', borderWidth: 1, borderRadius: { topLeft: 3, topRight: 3 }, order: 2 }, { label: 'Denies', data: chartsData.denies, type: 'line', borderColor: '#f97316', borderWidth: 2, fill: false, tension: .45, pointRadius: 0, order: 1 }] }, options: { responsive: true, maintainAspectRatio: false, interaction: { mode: 'index', intersect: false }, plugins: { legend: { display: false } }, scales: { x: { grid: { color: GRID }, ticks: { maxTicksLimit: 8, color: TICK } }, y: { grid: { color: GRID }, ticks: { color: TICK }, min: 0 } }, animation: { duration: 900, easing: 'easeOutQuart' } } });
    }
    mkSpark('sparkTraffic', chartsData.traffic_in, '#3b82f6');
    mkSpark('sparkConexoes', chartsData.traffic_out, '#22c55e');
    mkSpark('sparkDrops', chartsData.drops, '#ef4444');
  }

  function mkSpark(id, data, color) {
    const el = $(id); if (!el) return;
    const old = Chart.getChart(id); if (old) old.destroy();
    new Chart(el, { type: 'line', data: { labels: Array(data.length).fill(''), datasets: [{ data, borderColor: color, borderWidth: 1.5, fill: true, backgroundColor: color.replace('rgb(', 'rgba(').replace(')', ',0.08)'), tension: .45, pointRadius: 0 }] }, options: { responsive: true, maintainAspectRatio: false, animation: false, plugins: { legend: { display: false }, tooltip: { enabled: false } }, scales: { x: { display: false }, y: { display: false } } } });
  }

  /* ═══════════════════════════════════════════════════════
     LIVE FEED
  ═══════════════════════════════════════════════════════ */
  function addFeedItem(log) {
    if (feedPaused) return;
    feedCount++;
    if ($('fwFeedCount')) $('fwFeedCount').textContent = feedCount > 99 ? '99+' : feedCount;
    const cls = log.action === 'DROP' ? 'drop' : 'deny';
    const el = document.createElement('div');
    el.className = `fw-feed-item fw-feed-item--${cls}`;
    el.innerHTML = `<span class="fw-feed-time">${log.time}</span><span class="fw-feed-action fw-feed-action--${cls}">${log.action}</span><span class="fw-feed-msg">${log.src_ip} → ${log.dst_ip}:${log.dst_port}</span>`;
    const list = $('fwFeedList');
    if (list) { list.insertBefore(el, list.firstChild); while (list.children.length > 80) list.removeChild(list.lastChild); }
  }

  function initFeed() {
    const list = $('fwFeedList'); if (list) list.innerHTML = '';
    feedCount = 0;
    if (LOGS.length === 0) return;
    LOGS.filter(l => l.action !== 'ALLOW').slice(0, 15).reverse().forEach(l => addFeedItem(l));
  }

  if ($('fwFeedPauseBtn')) {
    $('fwFeedPauseBtn').addEventListener('click', () => {
      feedPaused = !feedPaused;
      $('fwFeedPauseLbl').textContent = feedPaused ? 'Retomar' : 'Pausar';
      $('fwFeedPauseIcon').className = feedPaused ? 'bi bi-play-fill' : 'bi bi-pause-fill';
    });
  }

  /* ═══════════════════════════════════════════════════════
     TOPBAR CONTROLS
  ═══════════════════════════════════════════════════════ */
  document.querySelectorAll('.fw-period__btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.fw-period__btn').forEach(b => b.classList.remove('fw-period__btn--active'));
      btn.classList.add('fw-period__btn--active');
      loadData(btn.dataset.p);
    });
  });

  if ($('fwRefreshBtn')) $('fwRefreshBtn').addEventListener('click', () => loadData());

  if ($('fwExportBtn')) {
    $('fwExportBtn').addEventListener('click', () => {
      const rows = LOGS;
      const csv = [
        ['Hora', 'Ação', 'Interface', 'Src IP', 'Dst IP', 'Porta', 'Proto', 'Regra', 'Bytes', 'Motivo'].join(','),
        ...rows.map(l => [l.time, l.action, l.iface, l.src_ip, l.dst_ip, l.dst_port, l.proto, l.rule_id, l.bytes, l.reason].join(','))
      ].join('\n');
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
      const a = Object.assign(document.createElement('a'), {
        href: URL.createObjectURL(blob),
        download: `moonshield-fw-${new Date().toISOString().slice(0, 10)}.csv`
      });
      a.click();
      URL.revokeObjectURL(a.href);
      showToast('CSV exportado 📥');
    });
  }

  if ($('qaResetCounters')) $('qaResetCounters').addEventListener('click', () => { showToast('Contadores resetados'); loadData(); });
  if ($('qaExportLogs')) $('qaExportLogs').addEventListener('click', () => $('fwExportBtn').click());

  /* ═══════════════════════════════════════════════════════
     TOAST
  ═══════════════════════════════════════════════════════ */
  let toastTimer;
  function showToast(msg, type = 'ok') {
    const t = $('fwToast');
    if (!t) return;
    t.textContent = msg;
    t.className = `fw-toast fw-toast--${type} show`;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove('show'), 2600);
  }

  if (!document.getElementById('fwKeyframes')) {
    const style = document.createElement('style');
    style.id = 'fwKeyframes';
    style.textContent = `@keyframes rowIn{from{opacity:0;transform:translateX(-5px)}to{opacity:1;transform:none}}`;
    document.head.appendChild(style);
  }

  // Init
  loadData();

});