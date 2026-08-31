/**
 * MOONSHIELD — AdGuard.JS  v6.0
 * NOC / DNS & Rede
 * ─────────────────────────────────────────────────────────────────────────
 * v6 (sobre v5):
 * • modo "prod_offline" → badge PROD vermelho + banner vermelho pulsando
 * • NUNCA exibe dados simulados em modo PROD (nem no feed, nem nas listas)
 * • updateModeBadge: prod_mock e prod_fallback removidos, prod_offline adicionado
 * • updateHealthCard: trata prod_offline como OFFLINE (vermelho)
 * • _ensureProdOfflineBanner / showProdOfflineBanner / hideProdOfflineBanner
 * • auto-refresh: também recarrega em prod_offline (para detectar quando voltar)
 * v5 (mantidos):
 * • getDeviceIcon → SVG inline por tipo de dispositivo
 * • Health rows   → SVG inline (sem emojis)
 * • Ações Rápidas (Modal dinâmico allow/block, flush cache, update)
 */

document.addEventListener('DOMContentLoaded', () => {

  /* ═══════════════════════════════════════════════════════
     UTILITÁRIOS
  ═══════════════════════════════════════════════════════ */
  const $ = id => document.getElementById(id);

  function fmtNum(n) {
    return n >= 1_000_000 ? (n / 1_000_000).toFixed(1) + 'M'
      : n >= 1_000 ? (n / 1_000).toFixed(1) + 'k'
        : String(n || 0);
  }

  function nowStr() {
    const d = new Date();
    return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`;
  }

  function _getCsrf() {
    return document.cookie.split(';')
      .find(c => c.trim().startsWith('csrftoken='))
      ?.split('=')[1] || '';
  }

  function escapeHtml(value) {
    return String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');
  }

  function setHealthValue(key, value, cls = 'ok') {
    const row = document.querySelector(`[data-health="${key}"]`);
    if (!row) return;
    const val = row.querySelector('.noc-health-row__val');
    if (!val) return;
    val.textContent = value;
    val.className = `noc-health-row__val noc-health-row__val--${cls}`;
  }

  /* ─────────────────────────────────────────────────────
     ÍCONES SVG POR TIPO DE DISPOSITIVO
  ───────────────────────────────────────────────────── */
  const DEVICE_ICONS = {
    laptop:  `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="2" y1="20" x2="22" y2="20"/></svg>`,
    desktop: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>`,
    tv:      `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="2" y="7" width="20" height="13" rx="2"/><polyline points="17 2 12 7 7 2"/></svg>`,
    router:  `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>`,
    printer: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>`,
    console: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><line x1="6" y1="12" x2="10" y2="12"/><line x1="8" y1="10" x2="8" y2="14"/><circle cx="15" cy="11" r="1" fill="currentColor"/><circle cx="17" cy="13" r="1" fill="currentColor"/><path d="M3 12a9 9 0 0 1 18 0 9 9 0 0 1-18 0z"/></svg>`,
    cpu:     `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/></svg>`,
    speaker: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="9" y="2" width="6" height="20" rx="3"/><line x1="9" y1="9" x2="1" y2="9"/><line x1="9" y1="12" x2="1" y2="12"/><line x1="9" y1="15" x2="1" y2="15"/><line x1="15" y1="9" x2="23" y2="9"/><line x1="15" y1="12" x2="23" y2="12"/><line x1="15" y1="15" x2="23" y2="15"/></svg>`,
    plug:    `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 22v-5"/><path d="M9 8V2"/><path d="M15 8V2"/><path d="M18 8H6a2 2 0 0 0-2 2v2a7 7 0 1 0 14 0v-2a2 2 0 0 0-2-2z"/></svg>`,
    mobile:  `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="5" y="2" width="14" height="20" rx="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>`,
  };

  function getDeviceIcon(name = '', type = '') {
    const n = (name + ' ' + type).toLowerCase();
    if (/macbook|notebook|laptop|chromebook|thinkpad/.test(n))                    return DEVICE_ICONS.laptop;
    if (/desktop|imac|pc\b|workstation/.test(n))                                  return DEVICE_ICONS.desktop;
    if (/tv|television|roku|appletv|chromecast|firetv|shield/.test(n))            return DEVICE_ICONS.tv;
    if (/router|roteador|gateway|access\s*point|ap\b|wifi|switch|unifi|mikrotik/.test(n)) return DEVICE_ICONS.router;
    if (/printer|impressora|laserjet|inkjet|epson|canon printer/.test(n))          return DEVICE_ICONS.printer;
    if (/playstation|ps[345]|xbox|nintendo|switch|gaming|console/.test(n))         return DEVICE_ICONS.console;
    if (/raspberry|rpi|pi\b|server|servidor|nas\b|synology|unraid|proxmox|cpu/.test(n)) return DEVICE_ICONS.cpu;
    if (/echo|alexa|homepod|google home|nest\s*hub|speaker|sonos/.test(n))         return DEVICE_ICONS.speaker;
    if (/plug|tomada|smart plug|shelly|tasmota|tuya/.test(n))                      return DEVICE_ICONS.plug;
    return DEVICE_ICONS.mobile;
  }

  /* ─────────────────────────────────────────────────────
     ÍCONES SVG PARA HEALTH ROWS
  ───────────────────────────────────────────────────── */
  const HEALTH_ROW_ICONS = {
    'dns-resolver':  `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="1.8"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>`,
    'adguard-api':   `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#a855f7" stroke-width="1.8"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
    'last-sync':     `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="1.8"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>`,
    'safe-browsing': `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#eab308" stroke-width="1.8"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`,
  };

  /* ═══════════════════════════════════════════════════════
     CHART.JS — defaults
  ═══════════════════════════════════════════════════════ */
  Chart.defaults.color                          = 'rgba(255,255,255,0.25)';
  Chart.defaults.font.family                    = "'JetBrains Mono', monospace";
  Chart.defaults.font.size                      = 10;
  Chart.defaults.plugins.legend.display         = false;
  Chart.defaults.plugins.tooltip.backgroundColor = '#0d1117';
  Chart.defaults.plugins.tooltip.borderColor    = 'rgba(255,255,255,0.10)';
  Chart.defaults.plugins.tooltip.borderWidth    = 1;
  Chart.defaults.plugins.tooltip.titleColor     = '#f0f0f0';
  Chart.defaults.plugins.tooltip.bodyColor      = 'rgba(255,255,255,0.55)';
  Chart.defaults.plugins.tooltip.padding        = 10;
  Chart.defaults.plugins.tooltip.cornerRadius   = 8;

  const GRID = 'rgba(255,255,255,0.04)';
  const TICK = 'rgba(255,255,255,0.20)';

  /* ═══════════════════════════════════════════════════════
     STATE PRINCIPAL
  ═══════════════════════════════════════════════════════ */
  let state = {
    mode: 'demo', period: '24h',
    metrics: {}, charts: {}, health: {},
    top_consultados: [], top_bloqueados: [],
    filter_count: 0, warning: null,
    generatedAt: null,
  };

  let clientState = {
    data: [], filtered: [],
    filter: 'all', search: '',
    sortCol: 'queries', sortDir: 'desc',
    page: 1, pageSize: 10,
  };

  let feedState = {
    entries: [],
    lastTime: null,
    feedCount: 0,
    paused: false,
    drawerIp: null,
    seenKeys: new Set(),
  };

  /* ═══════════════════════════════════════════════════════
     BANNERS
  ═══════════════════════════════════════════════════════ */

  // ── Banner amarelo — avisos genéricos (ex: fallback) ──────────────────────
  function _ensureWarningBanner() {
    let b = $('nocWarningBanner');
    if (!b) {
      b = document.createElement('div');
      b.id = 'nocWarningBanner';
      b.style.cssText = [
        'display:none', 'align-items:center', 'gap:10px',
        'padding:10px 16px', 'margin-bottom:12px',
        'background:rgba(234,179,8,.08)',
        'border:1px solid rgba(234,179,8,.25)',
        'border-radius:8px', 'font-size:12px', 'color:#eab308',
      ].join(';');
      b.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
        <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
      </svg><span id="nocWarningText"></span>`;
      const topbar = document.querySelector('.noc-topbar');
      if (topbar && topbar.parentNode) topbar.parentNode.insertBefore(b, topbar);
      else document.body.prepend(b);
    }
    return b;
  }
  function showWarningBanner(msg) {
    const b = _ensureWarningBanner();
    b.style.display = 'flex';
    const t = $('nocWarningText'); if (t) t.textContent = msg;
  }
  function hideWarningBanner() {
    const b = $('nocWarningBanner'); if (b) b.style.display = 'none';
  }

  // ── Banner vermelho — PROD com AdGuard offline / não configurado ──────────
  function _ensureProdOfflineBanner() {
    let b = $('nocProdOfflineBanner');
    if (!b) {
      b = document.createElement('div');
      b.id = 'nocProdOfflineBanner';
      b.style.cssText = [
        'display:none', 'align-items:center', 'gap:10px',
        'padding:10px 16px', 'margin-bottom:12px',
        'background:rgba(239,68,68,.07)',
        'border:1px solid rgba(239,68,68,.25)',
        'border-radius:8px', 'font-size:12px', 'color:var(--text-muted,#94a3b8)',
      ].join(';');
      b.innerHTML = `
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2"
             style="flex-shrink:0;animation:noc-pulse-red 2s ease-in-out infinite">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="8" x2="12" y2="12"/>
          <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
        <div style="display:flex;flex-direction:column;gap:2px;flex:1;min-width:0">
          <strong style="color:#ef4444">Modo Produção ativo — AdGuard inacessível</strong>
          <span id="nocProdOfflineMsg" style="font-size:11px"></span>
        </div>
        <a href="/configuracoes/" style="
          flex-shrink:0;padding:4px 12px;border-radius:5px;
          border:1px solid rgba(239,68,68,.3);color:#ef4444;
          font-size:11px;text-decoration:none;white-space:nowrap;
          transition:background .2s
        ">Configurações</a>`;

      const topbar = document.querySelector('.noc-topbar');
      if (topbar && topbar.parentNode) topbar.parentNode.insertBefore(b, topbar);
      else document.body.prepend(b);

      // Injeta keyframe uma única vez
      if (!document.getElementById('nocProdOfflineStyle')) {
        const s = document.createElement('style');
        s.id = 'nocProdOfflineStyle';
        s.textContent = `@keyframes noc-pulse-red { 0%,100%{opacity:1} 50%{opacity:.35} }`;
        document.head.appendChild(s);
      }
    }
    return b;
  }
  function showProdOfflineBanner(msg) {
    const b = _ensureProdOfflineBanner();
    b.style.display = 'flex';
    const m = $('nocProdOfflineMsg');
    if (m) m.textContent = msg || 'Verifique se o AdGuard Home está rodando e a URL está correta em Configurações.';
  }
  function hideProdOfflineBanner() {
    const b = $('nocProdOfflineBanner'); if (b) b.style.display = 'none';
  }

  /* ═══════════════════════════════════════════════════════
     BADGE DE MODO  (v6: prod_offline = PROD vermelho)
  ═══════════════════════════════════════════════════════ */
  function updateModeBadge(mode, warning) {
    const badge = $('nocModeBadge'); if (!badge) return;
    badge.style.display = 'inline-block';

    const BADGE_CFG = {
      demo:         { label: 'DEMO', color: '#eab308', bg: 'rgba(234,179,8,.1)',  border: 'rgba(234,179,8,.3)'  },
      prod:         { label: 'PROD', color: '#22c55e', bg: 'rgba(34,197,94,.1)',  border: 'rgba(34,197,94,.3)'  },
      prod_offline: { label: 'PROD', color: '#ef4444', bg: 'rgba(239,68,68,.1)',  border: 'rgba(239,68,68,.3)'  },
    };
    const cfg = BADGE_CFG[mode] || {
      label: (mode || '?').toUpperCase(),
      color: '#888', bg: 'rgba(255,255,255,.05)', border: 'rgba(255,255,255,.1)',
    };
    badge.textContent      = cfg.label;
    badge.style.color      = cfg.color;
    badge.style.background = cfg.bg;
    badge.style.border     = `1px solid ${cfg.border}`;

    // Banners: vermelho para prod_offline, amarelo para aviso genérico, nenhum para prod ok / demo
    if (mode === 'prod_offline') {
      showProdOfflineBanner(warning);
      hideWarningBanner();
    } else if (warning) {
      showWarningBanner(warning);
      hideProdOfflineBanner();
    } else {
      hideWarningBanner();
      hideProdOfflineBanner();
    }

    // Linha de health da API
    const apiRow = document.querySelector('[data-health="adguard-api"]');
    if (apiRow) {
      const valEl = apiRow.querySelector('.noc-health-row__val');
      if (valEl) {
        if (mode === 'prod') {
          valEl.textContent = 'OK';
          valEl.className   = 'noc-health-row__val noc-health-row__val--ok';
        } else if (mode === 'prod_offline') {
          valEl.textContent = 'Offline';
          valEl.className   = 'noc-health-row__val noc-health-row__val--error';
        } else {
          valEl.textContent = 'Demo';
          valEl.className   = 'noc-health-row__val noc-health-row__val--warn';
        }
      }
    }
  }

  /* ═══════════════════════════════════════════════════════
     API: DADOS PRINCIPAIS
  ═══════════════════════════════════════════════════════ */
  async function loadNocData() {
    try {
      const res = await fetch(`/dns/api/data/?period=${state.period}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();

      if (!data.ok && !data.metrics) {
        showWarningBanner(`Erro ao carregar dados: ${data.error || '—'}`);
        return;
      }

      state.mode            = data.mode || 'demo';
      state.metrics         = data.metrics || {};
      state.charts          = data.charts  || {};
      state.health          = data.health  || {};
      state.top_consultados = data.top_consultados || [];
      state.top_bloqueados  = data.top_bloqueados  || [];
      state.filter_count    = data.filter_count ?? state.filter_count;
      state.warning         = data.warning || null;
      state.generatedAt     = data.generated_at || null;
      clientState.data      = data.clientes || [];

      applyClientFilters();
      updateModeBadge(state.mode, state.warning);
      renderKPIs();
      renderCharts();
      renderTopLists();
      updateHealthCard(data);
      updateLiveTime();
    } catch (e) {
      console.error('[NOC] loadNocData:', e);
      showWarningBanner(`Falha de conexão: ${e.message}`);
    }
  }

  /* ═══════════════════════════════════════════════════════
     API: QUERYLOG — LIVE FEED
  ═══════════════════════════════════════════════════════ */
  function _feedKey(entry) {
    return [
      entry.time || '',
      entry.ip || '',
      entry.domain || '',
      entry.type || '',
      entry.blocked ? '1' : '0',
      entry.filter || '',
    ].join('|');
  }

  async function pollQuerylog() {
    try {
      const url = feedState.lastTime
        ? `/dns/api/querylog/?since=${encodeURIComponent(feedState.lastTime)}&limit=80`
        : `/dns/api/querylog/?limit=80`;

      const res = await fetch(url);
      if (!res.ok) return;

      const data = await res.json();
      if (!data.ok || !Array.isArray(data.entries) || data.entries.length === 0) return;

      const incoming = [...data.entries].sort((a, b) =>
        String(a.time || '').localeCompare(String(b.time || ''))
      );

      const newEntries = [];
      for (const entry of incoming) {
        const key = _feedKey(entry);
        if (feedState.seenKeys.has(key)) continue;
        feedState.seenKeys.add(key);
        newEntries.push(entry);
      }

      // Limita o Set para não crescer indefinidamente.
      if (feedState.seenKeys.size > 1500) {
        const keep = [...feedState.seenKeys].slice(-800);
        feedState.seenKeys = new Set(keep);
      }

      if (newEntries.length === 0) {
        const newest = incoming.at(-1)?.time;
        if (newest && (!feedState.lastTime || newest > feedState.lastTime)) {
          feedState.lastTime = newest;
        }
        return;
      }

      const newest = newEntries.at(-1)?.time;
      if (newest && (!feedState.lastTime || newest > feedState.lastTime)) {
        feedState.lastTime = newest;
      }

      // Estado interno fica newest-first; render do feed mantém essa ordem visual.
      const newestFirst = [...newEntries].reverse();
      feedState.entries = [...newestFirst, ...feedState.entries].slice(0, 500);

      if (!feedState.paused) newestFirst.forEach(entry => _addFeedRow(entry));
      newestFirst.filter(entry => entry.blocked).forEach(entry => _addBlockRow(entry));

      if (feedState.drawerIp) _renderDrawerFeed(feedState.drawerIp);
    } catch (e) {
      console.debug('[NOC] pollQuerylog:', e);
    }
  }

  function _addFeedRow(entry) {
    feedState.feedCount++;
    const countEl = $('feedCount');
    if (countEl) countEl.textContent = feedState.feedCount > 99 ? '99+' : feedState.feedCount;

    const cls  = entry.blocked ? 'block' : 'allow';
    const type = entry.blocked ? 'BLOCK' : 'ALLOW';
    const t    = entry.time_fmt || nowStr();

    const el = document.createElement('div');
    el.className = `noc-feed-item noc-feed-item--${cls}`;
    const filterTitle = entry.filter ? `Regra: ${entry.filter}` : (entry.cached ? 'Resposta em cache' : '');
    el.title = filterTitle;
    el.innerHTML = `
      <span class="noc-feed-time">${escapeHtml(t)}</span>
      <span class="noc-feed-type noc-feed-type--${cls}">${type}</span>
      <span class="noc-feed-ip mono">${escapeHtml(entry.ip)}</span>
      <span class="noc-feed-sep">·</span>
      <span class="noc-feed-msg">${escapeHtml(entry.domain || '—')}</span>
      <span class="noc-feed-qtype">${escapeHtml(entry.type || '—')}</span>
      ${entry.elapsed_ms != null ? `<span class="noc-feed-ms">${escapeHtml(entry.elapsed_ms)}ms</span>` : ''}
    `;
    const list = $('feedList'); if (!list) return;
    list.insertBefore(el, list.firstChild);
    while (list.children.length > 20) list.removeChild(list.lastChild);
  }

  function _addBlockRow(entry) {
    const el = $('listUltimosBloqueios'); if (!el) return;
    const row = document.createElement('div');
    row.className = 'noc-block-row noc-block-row--block';
    row.title = entry.filter ? `Regra: ${entry.filter}` : '';
    row.innerHTML = `
      <span class="noc-block-time">${escapeHtml(entry.time_fmt || nowStr())}</span>
      <span class="noc-block-ip mono">${escapeHtml(entry.ip)}</span>
      <span class="noc-block-domain">${escapeHtml(entry.domain || '—')}</span>
    `;
    el.insertBefore(row, el.firstChild);
    if (el.children.length > 15) el.removeChild(el.lastChild);
  }

  function _renderDrawerFeed(ip) {
    const el = $('dClientFeed'); if (!el) return;
    const entries = feedState.entries.filter(e => e.ip === ip).slice(0, 50);
    if (entries.length === 0) {
      el.innerHTML = `<div class="dFeed-empty">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
        </svg>
        Aguardando consultas de ${ip}…
      </div>`;
      return;
    }
    el.innerHTML = entries.map(e => {
      const cls = e.blocked ? 'block' : 'allow';
      return `
        <div class="dFeed-row dFeed-row--${cls}">
          <span class="dFeed-time">${escapeHtml(e.time_fmt || '—')}</span>
          <span class="dFeed-badge dFeed-badge--${cls}">${e.blocked ? 'BLOCK' : 'OK'}</span>
          <span class="dFeed-domain" title="${escapeHtml(e.filter || '')}">${escapeHtml(e.domain || '—')}</span>
          <span class="dFeed-type">${escapeHtml(e.type || '—')}</span>
          ${e.elapsed_ms != null ? `<span class="dFeed-ms">${escapeHtml(e.elapsed_ms)}ms</span>` : ''}
        </div>`;
    }).join('');
  }

  /* ═══════════════════════════════════════════════════════
     CARD DE SAÚDE  (v6: prod_offline = OFFLINE vermelho)
  ═══════════════════════════════════════════════════════ */
  function updateHealthCard(data) {
    const h = data.health || state.health || {};

    const fc = $('filterCount');
    if (fc) fc.textContent = data.filter_count ?? h.filters_enabled ?? '—';

    const ls = $('lastSync');
    if (ls) ls.textContent = nowStr();

    const versionEl = document.querySelector('[data-health="adguard-version"]');
    if (versionEl) versionEl.textContent = h.version || '—';

    if (state.mode === 'prod') {
      setHealthValue('dns-resolver', h.running === false ? 'Parado' : 'Online', h.running === false ? 'error' : 'ok');
      setHealthValue('adguard-api', h.api === 'offline' ? 'Offline' : 'OK', h.api === 'offline' ? 'error' : 'ok');
      setHealthValue('last-sync', 'agora', 'ok');
      if (h.safe_browsing === true) {
        setHealthValue('safe-browsing', 'Ativo', 'ok');
      } else if (h.safe_browsing === false) {
        setHealthValue('safe-browsing', 'Inativo', 'warn');
      } else {
        setHealthValue('safe-browsing', '—', 'warn');
      }
    } else if (state.mode === 'prod_offline') {
      setHealthValue('dns-resolver', 'Offline', 'error');
      setHealthValue('adguard-api', 'Offline', 'error');
      setHealthValue('last-sync', 'Falhou', 'error');
      setHealthValue('safe-browsing', '—', 'warn');
    } else {
      setHealthValue('dns-resolver', 'Demo', 'warn');
      setHealthValue('adguard-api', 'Demo', 'warn');
      setHealthValue('last-sync', 'agora', 'ok');
      setHealthValue('safe-browsing', 'Demo', 'warn');
    }

    const ov = $('healthOverall');
    if (ov) {
      if (state.mode === 'prod' && h.running !== false) {
        ov.textContent = 'ONLINE';
        ov.style.color = '#22c55e';
        ov.style.background = 'rgba(34,197,94,.1)';
        ov.style.borderColor = 'rgba(34,197,94,.25)';
      } else if (state.mode === 'prod_offline' || h.running === false) {
        ov.textContent = 'OFFLINE';
        ov.style.color = '#ef4444';
        ov.style.background = 'rgba(239,68,68,.1)';
        ov.style.borderColor = 'rgba(239,68,68,.25)';
      } else {
        ov.textContent = state.mode === 'demo' ? 'DEMO' : 'DEGRADADO';
        ov.style.color = '#f97316';
        ov.style.background = 'rgba(249,115,22,.1)';
        ov.style.borderColor = 'rgba(249,115,22,.25)';
      }
    }

    // CPU/RAM antigos eram randômicos. Em PROD, não exibimos dado fake.
    // Quando houver endpoint real de recursos, estes mesmos elementos podem ser alimentados.
    if (state.mode === 'prod') {
      if ($('resCpu')) $('resCpu').textContent = '—';
      if ($('resRam')) $('resRam').textContent = '—';
      if ($('resCpuBar')) $('resCpuBar').style.width = '0%';
      if ($('resRamBar')) $('resRamBar').style.width = '0%';
    }
  }

  /* ═══════════════════════════════════════════════════════
     KPIs e SPARKLINES
  ═══════════════════════════════════════════════════════ */
  let gaugeChart = null;

  function renderKPIs() {
    const m = state.metrics;
    if ($('kpiQueries'))   $('kpiQueries').textContent   = fmtNum(m.queries   || 0);
    if ($('kpiBloqueios')) $('kpiBloqueios').textContent = fmtNum(m.bloqueios || 0);
    if ($('kpiPctBloq'))   $('kpiPctBloq').textContent   = (m.pctBloq  || 0) + '%';
    if ($('kpiClientes'))  $('kpiClientes').textContent  = m.clientes  || 0;
    if ($('kpiLatencia'))  $('kpiLatencia').textContent  = (m.latencia || 0) + ' ms';
    if ($('kpiUptime'))    $('kpiUptime').textContent    = m.uptime    || '—';

    const qTrend = $('kpiQueriesTrend');
    const bTrend = $('kpiBloqueiosTrend');
    if (state.mode === 'prod') {
      if (qTrend) {
        qTrend.textContent = 'dados reais do período';
        qTrend.className = 'noc-kpi__trend';
        qTrend.style.color = 'var(--text-dim)';
      }
      if (bTrend) {
        bTrend.textContent = 'dados reais do período';
        bTrend.className = 'noc-kpi__trend';
        bTrend.style.color = 'var(--text-dim)';
      }
    }

    makeSparkline('sparkQueries',   state.charts.queries  || [], '#3b82f6');
    makeSparkline('sparkBloqueios', state.charts.bloqueios|| [], '#ef4444');
    makeSparkline('sparkLatencia',  state.charts.latency  || [], '#a855f7');

    const pct     = m.pctBloq || 0;
    const gaugeEl = $('gaugeKpi');
    if (gaugeEl) {
      if (gaugeChart) {
        gaugeChart.data.datasets[0].data = [pct, 100 - pct];
        gaugeChart.update();
      } else {
        gaugeChart = new Chart(gaugeEl, {
          type: 'doughnut',
          data: { datasets: [{ data: [pct, 100 - pct], backgroundColor: ['#eab308', 'rgba(255,255,255,0.05)'], borderColor: ['transparent', 'transparent'], borderWidth: 0 }] },
          options: { responsive: false, cutout: '72%', rotation: -90, circumference: 360, animation: { duration: 1200, easing: 'easeOutQuart' }, plugins: { tooltip: { enabled: false } } }
        });
      }
    }
  }

  const _sparkInstances = {};
  function makeSparkline(id, data, color) {
    const el = $(id); if (!el || !data.length) return;
    if (_sparkInstances[id]) {
      _sparkInstances[id].data.datasets[0].data = data;
      _sparkInstances[id].update('none'); return;
    }
    _sparkInstances[id] = new Chart(el, {
      type: 'line',
      data: { labels: Array(data.length).fill(''), datasets: [{ data, borderColor: color, borderWidth: 1.5, fill: true, backgroundColor: color.replace(')', ',.08)').replace('rgb', 'rgba'), tension: 0.45, pointRadius: 0 }] },
      options: { responsive: true, maintainAspectRatio: false, animation: false, plugins: { tooltip: { enabled: false } }, scales: { x: { display: false }, y: { display: false } } }
    });
  }

  /* ═══════════════════════════════════════════════════════
     GRÁFICOS PRINCIPAIS
  ═══════════════════════════════════════════════════════ */
  let chartQ = null, chartL = null;

  function renderCharts() {
    const hours = state.charts.hours || [];

    const ctxQ = $('chartQueryHour');
    if (ctxQ) {
      if (chartQ) {
        chartQ.data.labels = hours;
        chartQ.data.datasets[0].data = state.charts.queries   || [];
        chartQ.data.datasets[1].data = state.charts.bloqueios || [];
        chartQ.update('active');
      } else {
        const ctx   = ctxQ.getContext('2d');
        const gradB = ctx.createLinearGradient(0, 0, 0, 200);
        gradB.addColorStop(0, 'rgba(59,130,246,0.85)'); gradB.addColorStop(1, 'rgba(59,130,246,0.15)');
        const gradA = ctx.createLinearGradient(0, 0, 0, 200);
        gradA.addColorStop(0, 'rgba(239,68,68,0.25)');  gradA.addColorStop(1, 'rgba(239,68,68,0.00)');
        chartQ = new Chart(ctxQ, {
          type: 'bar',
          data: {
            labels: hours,
            datasets: [
              { label: 'Consultas', data: state.charts.queries,   backgroundColor: gradB, borderColor: '#3b82f6', borderWidth: 1, borderRadius: { topLeft: 4, topRight: 4 }, order: 2 },
              { label: 'Bloqueios', data: state.charts.bloqueios, type: 'line', borderColor: '#ef4444', backgroundColor: gradA, borderWidth: 2, fill: true, tension: 0.45, pointRadius: 0, pointHoverRadius: 5, pointHoverBackgroundColor: '#ef4444', order: 1 },
            ]
          },
          options: {
            responsive: true, maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            plugins: { tooltip: { callbacks: { label: i => `  ${i.dataset.label}: ${Number(i.raw).toLocaleString('pt-BR')}` } } },
            scales: { x: { grid: { color: GRID }, ticks: { maxTicksLimit: 8, color: TICK } }, y: { grid: { color: GRID }, ticks: { color: TICK }, min: 0 } },
            animation: { duration: 900 },
          }
        });
      }
    }

    const ctxL = $('chartLatency');
    if (ctxL) {
      if (chartL) {
        chartL.data.labels = hours;
        chartL.data.datasets[0].data = state.charts.latency_peak || [];
        chartL.data.datasets[1].data = state.charts.latency      || [];
        chartL.update('active');
      } else {
        const ctx   = ctxL.getContext('2d');
        const gradP = ctx.createLinearGradient(0, 0, 0, 160);
        gradP.addColorStop(0, 'rgba(168,85,247,0.55)'); gradP.addColorStop(1, 'rgba(168,85,247,0.00)');
        chartL = new Chart(ctxL, {
          type: 'line',
          data: {
            labels: hours,
            datasets: [
              { label: 'Pico',      data: state.charts.latency_peak, borderColor: 'rgba(255,255,255,0.10)', borderWidth: 1, fill: true, backgroundColor: 'rgba(255,255,255,0.03)', tension: 0.45, pointRadius: 0, order: 2 },
              { label: 'Média (ms)',data: state.charts.latency,      borderColor: '#a855f7', borderWidth: 2, fill: true, backgroundColor: gradP, tension: 0.45, pointRadius: 0, pointHoverRadius: 5, pointHoverBackgroundColor: '#a855f7', order: 1 },
            ]
          },
          options: {
            responsive: true, maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            scales: { x: { grid: { color: GRID }, ticks: { maxTicksLimit: 8, color: TICK } }, y: { grid: { color: GRID }, ticks: { color: TICK }, min: 0 } },
            animation: { duration: 900 },
          }
        });
      }
    }
  }

  /* ═══════════════════════════════════════════════════════
     LISTAS TOP
  ═══════════════════════════════════════════════════════ */
  function renderDomainList(elId, data, barColor) {
    const el = $(elId); if (!el) return;
    if (!data || data.length === 0) {
      el.innerHTML = "<p style='font-size:11px;color:var(--text-dim)'>Nenhum dado</p>"; return;
    }
    const max = data[0]?.n || 1;
    el.innerHTML = data.slice(0, 10).map((d, i) => `
      <div class="noc-domain-row">
        <span class="noc-domain-rank">${i + 1}</span>
        <span class="noc-domain-name">${d.domain}</span>
        <div class="noc-domain-bar-wrap">
          <div class="noc-domain-bar ${barColor}" style="width:${Math.round(d.n / max * 100)}%"></div>
        </div>
        <span class="noc-domain-count">${fmtNum(d.n)}</span>
      </div>`).join('');
  }

  function renderTopLists() {
    renderDomainList('listTopConsultados', state.top_consultados, '');
    renderDomainList('listTopBloqueados',  state.top_bloqueados,  'noc-domain-bar--red');

    const sorted = [...clientState.data].sort((a, b) => b.queries - a.queries).slice(0, 8);
    const maxCQ  = sorted[0]?.queries || 1;
    const listEl = $('listTopClientes');
    if (listEl) {
      listEl.innerHTML = sorted.length === 0
        ? "<p style='font-size:11px;color:var(--text-dim)'>Nenhum cliente</p>"
        : sorted.map((c, i) => `
          <div class="noc-domain-row" style="cursor:pointer" data-cid="${c.id}">
            <span class="noc-domain-rank">${i + 1}</span>
            <span class="noc-domain-icon" style="color:var(--text-dim)">${getDeviceIcon(c.name, c.type || '')}</span>
            <span class="noc-domain-name">${c.name}</span>
            <div class="noc-domain-bar-wrap">
              <div class="noc-domain-bar" style="width:${Math.round(c.queries / maxCQ * 100)}%;background:#22c55e"></div>
            </div>
            <span class="noc-domain-count">${fmtNum(c.queries)}</span>
          </div>`).join('');
      listEl.querySelectorAll('.noc-domain-row[data-cid]').forEach(row =>
        row.addEventListener('click', () => openDrawer(+row.dataset.cid))
      );
    }
  }

  /* ═══════════════════════════════════════════════════════
     HEALTH ROWS
  ═══════════════════════════════════════════════════════ */
  const HEALTH_ROWS_DEF = [
    { key: 'dns-resolver',  label: 'DNS Resolver',   val: 'Online', cls: 'ok'   },
    { key: 'adguard-api',   label: 'AdGuard API',    val: '—',      cls: 'warn' },
    { key: 'last-sync',     label: 'Última Sync',    val: 'agora',  cls: 'ok'   },
    { key: 'safe-browsing', label: 'Safe Browsing',  val: 'Ativo',  cls: 'ok'   },
  ];
  const healthRowsEl = $('healthRows');
  if (healthRowsEl) {
    healthRowsEl.innerHTML = HEALTH_ROWS_DEF.map(r => `
      <div class="noc-health-row" data-health="${r.key}">
        <span class="noc-health-row__icon">${HEALTH_ROW_ICONS[r.key] || ''}</span>
        <span class="noc-health-row__label">${r.label}</span>
        <span class="noc-health-row__val noc-health-row__val--${r.cls}">${r.val}</span>
      </div>`).join('');
  }

  /* ═══════════════════════════════════════════════════════
     RECURSOS — somente DEMO
     Em PROD não mostramos valores randômicos como se fossem reais.
  ═══════════════════════════════════════════════════════ */
  let demoCpu = 12, demoRam = 41;
  function updateDemoResources() {
    if (state.mode !== 'demo') return;
    demoCpu = Math.max(5, Math.min(85, demoCpu + (Math.floor(Math.random() * 9) - 4)));
    demoRam = Math.max(30, Math.min(75, demoRam + (Math.floor(Math.random() * 6) - 2)));
    if ($('resCpu')) $('resCpu').textContent = demoCpu + '%';
    if ($('resRam')) $('resRam').textContent = demoRam + '%';
    if ($('resCpuBar')) $('resCpuBar').style.width = demoCpu + '%';
    if ($('resRamBar')) $('resRamBar').style.width = demoRam + '%';
  }
  setInterval(updateDemoResources, 4000);

  /* ═══════════════════════════════════════════════════════
     TABELA CLIENTES
  ═══════════════════════════════════════════════════════ */
  let selectedClientRow = null;

  function applyClientFilters() {
    let d = [...clientState.data];
    if (clientState.filter !== 'all') d = d.filter(c => c.status === clientState.filter);
    if (clientState.search) {
      const q = clientState.search.toLowerCase();
      d = d.filter(c =>
        (c.name || '').toLowerCase().includes(q) ||
        (c.ip   || '').includes(q) ||
        (c.mac  || '').includes(q)
      );
    }
    d.sort((a, b) => {
      const av = a[clientState.sortCol] || 0, bv = b[clientState.sortCol] || 0;
      return clientState.sortDir === 'desc' ? bv - av : av - bv;
    });
    clientState.filtered = d;
    clientState.page = 1;
    renderClientsTable();
    renderClientsPagination();
    renderTopLists();
  }

  const STATUS_PILL = {
    online:   '<span class="status-pill status-pill--online"><span class="status-pill__dot"></span>Online</span>',
    offline:  '<span class="status-pill status-pill--offline"><span class="status-pill__dot"></span>Offline</span>',
    suspeito: '<span class="status-pill status-pill--suspeito"><span class="status-pill__dot"></span>Suspeito</span>',
  };

  function renderClientsTable() {
    const start = (clientState.page - 1) * clientState.pageSize;
    const rows  = clientState.filtered.slice(start, start + clientState.pageSize);
    if ($('clientsCount')) $('clientsCount').textContent = `${clientState.filtered.length} cliente${clientState.filtered.length !== 1 ? 's' : ''}`;

    const tbody = $('clientsTableBody'); if (!tbody) return;
    tbody.innerHTML = rows.map((c, i) => {
      const pctColor = c.pct > 25 ? '#ef4444' : c.pct > 10 ? '#eab308' : '#22c55e';
      const deviceSvg = getDeviceIcon(c.name, c.type || '');
      return `
      <tr data-cid="${c.id}" style="animation:rowIn .2s ${i * 20}ms both">
        <td>
          <div class="client-name-cell">
            <div class="client-avatar">${deviceSvg}</div>
            <div>
              <p class="client-name">${escapeHtml(c.name)}</p>
              <p class="client-mac">${escapeHtml(c.mac || "—")}</p>
            </div>
          </div>
        </td>
        <td><span class="client-ip mono">${escapeHtml(c.ip)}</span></td>
        <td>${STATUS_PILL[c.status] || ''}</td>
        <td><span class="mono" style="color:var(--text-primary);font-weight:600">${(c.queries   || 0).toLocaleString('pt-BR')}</span></td>
        <td><span class="mono" style="color:#ef4444">${(c.bloqueios || 0).toLocaleString('pt-BR')}</span></td>
        <td>
          <div class="client-pct-bar-wrap">
            <div class="client-pct-bar-track">
              <div class="client-pct-bar-fill" style="width:${Math.min(c.pct || 0, 100)}%;background:${pctColor}"></div>
            </div>
            <span class="client-pct-label">${c.pct || 0}%</span>
          </div>
        </td>
        <td><span class="mono" style="font-size:11px;color:var(--text-dim)">${escapeHtml(c.lastSeen || '—')}</span></td>
        <td>
          <div class="client-actions">
            <button class="client-action-btn" data-cid="${c.id}" data-act="view" title="Ver detalhes">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
            </button>
            <button class="client-action-btn" data-cid="${c.id}" data-act="copy" title="Copiar IP">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            </button>
            <button class="client-action-btn" data-cid="${c.id}" data-act="suspect" title="Marcar suspeito" style="${c.status === 'suspeito' ? 'color:#f97316' : ''}">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>
            </button>
          </div>
        </td>
      </tr>`;
    }).join('');

    tbody.querySelectorAll('tr[data-cid]').forEach(tr => {
      tr.addEventListener('click', e => {
        const btn = e.target.closest('[data-act]');
        if (!btn) { openDrawer(+tr.dataset.cid); return; }
        const id = +btn.dataset.cid, act = btn.dataset.act;
        if (act === 'view')    openDrawer(id);
        if (act === 'copy')    { navigator.clipboard?.writeText(clientState.data.find(c => c.id === id)?.ip || ''); showToast('IP copiado'); }
        if (act === 'suspect') toggleSuspect(id);
      });
    });
  }

  function renderClientsPagination() {
    const total = clientState.filtered.length;
    const pages = Math.max(1, Math.ceil(total / clientState.pageSize));
    const cur   = clientState.page;
    const start = total === 0 ? 0 : (cur - 1) * clientState.pageSize + 1;
    const end   = Math.min(cur * clientState.pageSize, total);
    if ($('clientsPagInfo')) $('clientsPagInfo').textContent = `${start}–${end} de ${total} clientes`;
    if ($('clientsPagPrev')) $('clientsPagPrev').disabled = cur <= 1;
    if ($('clientsPagNext')) $('clientsPagNext').disabled = cur >= pages;
    const numsEl = $('clientsPagNums'); if (!numsEl) return;
    const nums = pages <= 5
      ? Array.from({ length: pages }, (_, i) => i + 1)
      : [1, '…', cur, '…', pages].filter((v, i, a) => a.indexOf(v) === i);
    numsEl.innerHTML = nums.map(n =>
      n === '…'
        ? `<span style="padding:0 4px;font-family:var(--font-mono);font-size:11px;color:var(--text-dim)">…</span>`
        : `<button class="noc-pag-num${n === cur ? ' noc-pag-num--active' : ''}" data-p="${n}">${n}</button>`
    ).join('');
    numsEl.querySelectorAll('.noc-pag-num').forEach(btn =>
      btn.addEventListener('click', () => { clientState.page = +btn.dataset.p; renderClientsTable(); renderClientsPagination(); })
    );
  }

  $('clientsPagPrev')?.addEventListener('click', () => {
    if (clientState.page > 1) { clientState.page--; renderClientsTable(); renderClientsPagination(); }
  });
  $('clientsPagNext')?.addEventListener('click', () => {
    const pages = Math.ceil(clientState.filtered.length / clientState.pageSize);
    if (clientState.page < pages) { clientState.page++; renderClientsTable(); renderClientsPagination(); }
  });

  document.querySelectorAll('.noc-cf-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.noc-cf-btn').forEach(b => b.classList.remove('noc-cf-btn--active'));
      btn.classList.add('noc-cf-btn--active');
      clientState.filter = btn.dataset.cf;
      applyClientFilters();
    });
  });

  document.querySelectorAll('.noc-clients-table th[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
      const col = th.dataset.sort;
      clientState.sortDir = (clientState.sortCol === col && clientState.sortDir === 'desc') ? 'asc' : 'desc';
      clientState.sortCol = col;
      applyClientFilters();
    });
  });

  function toggleSuspect(id) {
    const c = clientState.data.find(x => x.id === id); if (!c) return;
    c.status = c.status === 'suspeito' ? 'online' : 'suspeito';
    applyClientFilters();
    showToast(c.status === 'suspeito' ? `${c.name} marcado como suspeito` : `${c.name} removido dos suspeitos`);
  }

  /* ═══════════════════════════════════════════════════════
     DRAWER CLIENTE
  ═══════════════════════════════════════════════════════ */
  let drawerChart = null;

  function openDrawer(id) {
    const c = clientState.data.find(x => x.id === id); if (!c) return;
    if (selectedClientRow) selectedClientRow.classList.remove('row-selected');
    selectedClientRow = $('clientsTableBody')?.querySelector(`tr[data-cid="${id}"]`);
    if (selectedClientRow) selectedClientRow.classList.add('row-selected');

    const avatarEl = $('drawerAvatar');
    if (avatarEl) avatarEl.innerHTML = getDeviceIcon(c.name, c.type || '');

    if ($('drawerName')) $('drawerName').textContent = c.name;
    if ($('drawerIp'))   $('drawerIp').textContent   = `${c.ip} · ${c.mac}`;
    if ($('drawerStatusBadge')) {
      const sb = $('drawerStatusBadge');
      sb.textContent         = c.status.charAt(0).toUpperCase() + c.status.slice(1);
      sb.style.background    = c.status === 'online' ? 'rgba(34,197,94,.12)' : c.status === 'suspeito' ? 'rgba(249,115,22,.12)' : 'rgba(255,255,255,.06)';
      sb.style.color         = c.status === 'online' ? '#22c55e'  : c.status === 'suspeito' ? '#f97316' : '#888';
      sb.style.borderColor   = c.status === 'online' ? 'rgba(34,197,94,.3)' : c.status === 'suspeito' ? 'rgba(249,115,22,.3)' : 'rgba(255,255,255,.12)';
    }

    if ($('dQueries'))   $('dQueries').textContent   = (c.queries   || 0).toLocaleString('pt-BR');
    if ($('dBloqueios')) $('dBloqueios').textContent = (c.bloqueios || 0).toLocaleString('pt-BR');
    if ($('dPct'))       $('dPct').textContent       = (c.pct       || 0) + '%';
    if ($('dReqMin'))    $('dReqMin').textContent    = c.reqMin || '—';

    if (drawerChart) { drawerChart.destroy(); drawerChart = null; }
    const dCtx = $('drawerChart');
    if (dCtx) {
      const data24 = Array.isArray(c.activity) && c.activity.length === 24
        ? c.activity
        : Array(24).fill(0);
      const ctx = dCtx.getContext('2d');
      const grad = ctx.createLinearGradient(0, 0, 0, 80);
      grad.addColorStop(0, 'rgba(59,130,246,0.55)');
      grad.addColorStop(1, 'rgba(59,130,246,0.00)');
      drawerChart = new Chart(dCtx, {
        type: 'line',
        data: {
          labels: state.charts.hours || Array(24).fill(''),
          datasets: [{
            data: data24,
            borderColor: '#3b82f6',
            borderWidth: 2,
            fill: true,
            backgroundColor: grad,
            tension: 0.45,
            pointRadius: 0,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: { duration: 400 },
          plugins: { legend: { display: false } },
          scales: { x: { display: false }, y: { display: false, beginAtZero: true } },
        },
      });
    }

    const renderDList = (elId, data) => {
      const el = $(elId); if (!el) return;
      if (!Array.isArray(data) || data.length === 0) {
        el.innerHTML = `<div style="font-size:11px;color:var(--text-dim);padding:6px 0">Sem dados neste recorte</div>`;
        return;
      }
      el.innerHTML = data.map(d => `
        <div class="noc-drawer__domain-row">
          <span class="noc-drawer__domain-name">${escapeHtml(d.domain || '—')}</span>
          <span class="noc-drawer__domain-count">${fmtNum(d.n || 0)}</span>
        </div>`).join('');
    };
    renderDList('dTopConsultados', c.topConsultados || []);
    renderDList('dTopBloqueados', c.topBloqueados || []);

    feedState.drawerIp = c.ip;
    _renderDrawerFeed(c.ip);
    const dFeedTitle = $('dFeedTitle');
    if (dFeedTitle) dFeedTitle.textContent = `Feed ao Vivo · ${c.ip}`;

    const btnFullFeed = $('dBtnFullFeed');
    if (btnFullFeed) btnFullFeed.href = `/dns/feed/?ip=${encodeURIComponent(c.ip)}`;

    $('dBtnTrust')?.addEventListener('click', () => {
      const cl = clientState.data.find(x => x.id === id);
      if (cl) cl.status = 'online';
      applyClientFilters(); closeDrawer();
      showToast(`${c.name} marcado como confiável`);
    });
    $('dBtnSuspect')?.addEventListener('click', () => { toggleSuspect(id); closeDrawer(); });
    $('dBtnExport')?.addEventListener('click', () => exportClientFeed(c));
    $('dBtnSoc')?.addEventListener('click', () => showToast('Abrindo no SOC…'));

    $('nocDrawer')?.classList.add('open');
    $('nocDrawerOverlay')?.classList.add('open');
  }

  function closeDrawer() {
    feedState.drawerIp = null;
    $('nocDrawer')?.classList.remove('open');
    $('nocDrawerOverlay')?.classList.remove('open');
    if (selectedClientRow) { selectedClientRow.classList.remove('row-selected'); selectedClientRow = null; }
  }

  $('nocDrawerClose')?.addEventListener('click', closeDrawer);
  $('nocDrawerOverlay')?.addEventListener('click', closeDrawer);
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeDrawer(); });

  function exportClientFeed(client) {
    const entries = feedState.entries.filter(e => e.ip === client.ip);
    if (!entries.length) { showToast('Nenhuma entrada para exportar'); return; }
    const headers = ['Hora', 'IP', 'Domínio', 'Tipo', 'Status', 'Latência(ms)', 'Filtro'];
    const rows    = entries.map(e => [e.time_fmt || e.time, e.ip, e.domain, e.type, e.status, e.elapsed_ms ?? '', e.filter].map(v => `"${v}"`).join(','));
    const blob    = new Blob([[headers.join(','), ...rows].join('\n')], { type: 'text/csv;charset=utf-8;' });
    const a = Object.assign(document.createElement('a'), {
      href: URL.createObjectURL(blob),
      download: `dns-${client.ip}-${new Date().toISOString().slice(0, 10)}.csv`
    });
    a.click(); URL.revokeObjectURL(a.href);
    showToast(`Feed de ${client.ip} exportado`);
  }

  /* ═══════════════════════════════════════════════════════
     AÇÕES RÁPIDAS / MODAL GENÉRICO
  ═══════════════════════════════════════════════════════ */
  function _ensureDomainModal() {
    if (document.getElementById('qaModal')) return;
    const m = document.createElement('div');
    m.id = 'qaModal';
    m.style.cssText = 'display:none;position:fixed;inset:0;z-index:9999;align-items:center;justify-content:center;background:rgba(0,0,0,.55);backdrop-filter:blur(4px)';
    m.innerHTML = `
      <div id="qaModalBox" style="background:#0d1117;border:1px solid rgba(255,255,255,.1);border-radius:12px;padding:24px;width:100%;max-width:440px;box-shadow:0 24px 64px rgba(0,0,0,.6);font-family:var(--font-mono,monospace)">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
          <p id="qaModalTitle" style="font-size:14px;font-weight:700;color:#f0f0f0;margin:0"></p>
          <button id="qaModalClose" style="background:none;border:none;cursor:pointer;color:#64748b;padding:4px;border-radius:4px;line-height:1;font-size:18px">✕</button>
        </div>
        <p id="qaModalDesc" style="font-size:11px;color:#64748b;margin-bottom:12px;line-height:1.5"></p>
        <textarea id="qaModalInput" placeholder="youtube.com.br&#10;uber.com.br&#10;ads.example.com" style="width:100%;height:100px;background:#0a0e14;border:1px solid rgba(255,255,255,.1);border-radius:8px;color:#e2e8f0;font-family:var(--font-mono,monospace);font-size:12px;padding:10px;resize:vertical;box-sizing:border-box;outline:none;transition:border-color .15s"></textarea>
        <div id="qaPreviewWrap" style="display:none;margin-top:10px">
          <p style="font-size:10px;color:#475569;margin-bottom:6px">Preview das regras:</p>
          <div id="qaPreviewList" style="background:#060a0f;border:1px solid rgba(255,255,255,.06);border-radius:6px;padding:8px;max-height:100px;overflow-y:auto;font-size:11px;color:#22c55e;line-height:1.7"></div>
        </div>
        <div style="display:flex;gap:8px;margin-top:16px;justify-content:flex-end">
          <button id="qaModalCancel" style="padding:7px 16px;background:transparent;border:1px solid rgba(255,255,255,.12);border-radius:6px;color:#94a3b8;font-size:12px;cursor:pointer">Cancelar</button>
          <button id="qaModalConfirm" style="padding:7px 20px;border:none;border-radius:6px;font-size:12px;font-weight:700;cursor:pointer;transition:opacity .15s">Confirmar</button>
        </div>
      </div>`;
    document.body.appendChild(m);
    m.addEventListener('click', e => { if (e.target === m) _closeModal(); });
    document.getElementById('qaModalClose').addEventListener('click', _closeModal);
    document.getElementById('qaModalCancel').addEventListener('click', _closeModal);
    document.getElementById('qaModalInput').addEventListener('input', _updatePreview);
  }

  let _modalMode = 'block';

  function _openModal(mode) {
    _ensureDomainModal();
    _modalMode = mode;
    const isBlock = mode === 'block';
    document.getElementById('qaModalTitle').textContent = isBlock ? 'Bloquear Domínios' : 'Whitelist — Permitir Domínios';
    document.getElementById('qaModalDesc').textContent  = 'Digite um domínio por linha. Você pode usar domínios simples (ex: ads.com) ou regras AdGuard completas (ex: ||ads.com^).';
    document.getElementById('qaModalInput').value = '';
    document.getElementById('qaModalInput').style.borderColor = isBlock ? 'rgba(239,68,68,.4)' : 'rgba(34,197,94,.4)';
    const btn = document.getElementById('qaModalConfirm');
    btn.style.background = isBlock ? '#ef4444' : '#22c55e';
    btn.style.color      = '#fff';
    btn.textContent      = isBlock ? 'Bloquear' : 'Permitir';
    btn.onclick          = _submitModal;
    document.getElementById('qaPreviewWrap').style.display = 'none';
    document.getElementById('qaPreviewList').innerHTML     = '';
    document.getElementById('qaModal').style.display = 'flex';
    setTimeout(() => document.getElementById('qaModalInput').focus(), 50);
  }

  function _closeModal() {
    const m = document.getElementById('qaModal'); if (m) m.style.display = 'none';
  }

  function _formatPreview(raw, mode) {
    const out = [];
    const seen = new Set();

    const push = rule => {
      if (!rule || seen.has(rule)) return;
      seen.add(rule);
      out.push(rule);
    };

    raw.split('\n').map(l => l.trim()).filter(Boolean).forEach(line => {
      if (line.startsWith('||') || line.startsWith('@@') || line.startsWith('!') ||
          line.startsWith('#') || line.startsWith('/') || line.startsWith('0.0.0.0') || line.startsWith('127.')) {
        push(line);
        return;
      }

      let domain = line.toLowerCase().trim();
      try {
        if (domain.includes('://')) domain = new URL(domain).hostname;
      } catch {}
      domain = domain.replace(/^www\./, '').replace(/\.$/, '');

      const domains = [domain];
      if (domain.endsWith('.com.br')) domains.push(domain.slice(0, -3));
      else if (domain.endsWith('.com')) domains.push(domain + '.br');

      domains.forEach(d => push(mode === 'allow' ? `@@||${d}^` : `||${d}^`));
    });

    return out;
  }

  function _updatePreview() {
    const raw   = document.getElementById('qaModalInput').value;
    const rules = _formatPreview(raw, _modalMode);
    const wrap  = document.getElementById('qaPreviewWrap');
    const list  = document.getElementById('qaPreviewList');
    if (rules.length === 0) { wrap.style.display = 'none'; return; }
    wrap.style.display = 'block';
    list.style.color   = _modalMode === 'allow' ? '#22c55e' : '#ef4444';
    list.innerHTML     = rules.map(r => `<div>${r}</div>`).join('');
  }

  async function _submitModal() {
    const raw = document.getElementById('qaModalInput').value.trim();
    if (!raw) { showToast('Digite ao menos um domínio'); return; }
    const finalRules = _formatPreview(raw, _modalMode).join('\n');
    const btn  = document.getElementById('qaModalConfirm');
    const orig = btn.textContent;
    btn.textContent = 'Enviando…'; btn.disabled = true;
    try {
      const res  = await fetch(_modalMode === 'block' ? '/dns/api/block/' : '/dns/api/allow/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': _getCsrf() },
        body: JSON.stringify({ domains: finalRules }),
      });
      const data = await res.json();
      if (data.ok) {
        const added = data.added?.length ?? 0;
        const skip = data.skipped?.length ?? 0;
        const conflicts = data.removed_conflicts?.length ?? 0;
        showToast(
          `✓ ${added} regra(s) adicionada(s)` +
          (conflicts ? ` · ${conflicts} conflito(s) removido(s)` : '') +
          (skip ? ` · ${skip} já existia(m)` : '')
        );
        _closeModal();
      } else {
        showToast(`Erro: ${data.error || 'Falha desconhecida'}`);
      }
    } catch (e) {
      showToast(`Erro de conexão: ${e.message}`);
    } finally {
      btn.textContent = orig; btn.disabled = false;
    }
  }

  async function _flushCache() {
    const btn = $('qaBtnFlush');
    if (btn) { btn.disabled = true; btn.style.opacity = '.5'; }
    try {
      const res  = await fetch('/dns/api/flush/', { method: 'POST', headers: { 'X-CSRFToken': _getCsrf() } });
      const data = await res.json();
      showToast(data.ok ? '✓ Cache DNS limpo' : `Erro: ${data.error}`);
    } catch (e) {
      showToast(`Erro: ${e.message}`);
    } finally {
      if (btn) { btn.disabled = false; btn.style.opacity = '1'; }
    }
  }

  async function _updateFilters() {
    const btn = $('qaBtnUpdate');
    if (btn) { btn.disabled = true; btn.style.opacity = '.5'; }
    showToast('Atualizando listas…');
    try {
      const res  = await fetch('/dns/api/update-filters/', { method: 'POST', headers: { 'X-CSRFToken': _getCsrf() } });
      const data = await res.json();
      showToast(data.ok ? `✓ ${data.msg}` : `Erro: ${data.error}`);
    } catch (e) {
      showToast(`Erro: ${e.message}`);
    } finally {
      if (btn) { btn.disabled = false; btn.style.opacity = '1'; }
    }
  }

  /* ═══════════════════════════════════════════════════════
     CONTROLES GERAIS
  ═══════════════════════════════════════════════════════ */
  document.querySelectorAll('.noc-period__btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.noc-period__btn').forEach(b => b.classList.remove('noc-period__btn--active'));
      btn.classList.add('noc-period__btn--active');
      state.period = btn.dataset.p;
      loadNocData();
      showToast(`Período: ${btn.dataset.p}`);
    });
  });

  const nocSearch      = $('nocSearch');
  const nocSearchClear = $('nocSearchClear');
  nocSearch?.addEventListener('input', () => {
    clientState.search = nocSearch.value.trim();
    nocSearchClear?.classList.toggle('visible', clientState.search.length > 0);
    applyClientFilters();
  });
  nocSearchClear?.addEventListener('click', () => {
    if (nocSearch) nocSearch.value = '';
    clientState.search = '';
    nocSearchClear?.classList.remove('visible');
    applyClientFilters();
  });

  $('nocRefreshBtn')?.addEventListener('click', () => {
    const btn = $('nocRefreshBtn');
    btn?.classList.add('spinning');
    feedState.lastTime = null;
    Promise.all([loadNocData(), pollQuerylog()]).finally(() => {
      btn?.classList.remove('spinning');
      showToast('Dados atualizados');
    });
  });

  $('nocExportBtn')?.addEventListener('click', () => {
    const headers = ['Nome', 'IP', 'MAC', 'Status', 'Queries', 'Bloqueios', '% Bloqueio', 'Última Atividade'];
    const rows    = clientState.filtered.map(c => [c.name, c.ip, c.mac, c.status, c.queries, c.bloqueios, c.pct, c.lastSeen].join(','));
    const blob    = new Blob([[headers.join(','), ...rows].join('\n')], { type: 'text/csv;charset=utf-8;' });
    const a = Object.assign(document.createElement('a'), {
      href: URL.createObjectURL(blob),
      download: `moonshield-dns-${new Date().toISOString().slice(0, 10)}.csv`
    });
    a.click(); URL.revokeObjectURL(a.href);
    showToast('CSV exportado');
  });

  $('nocClearFiltersBtn')?.addEventListener('click', () => {
    clientState.filter = 'all'; clientState.search = '';
    if (nocSearch) nocSearch.value = '';
    document.querySelectorAll('.noc-cf-btn').forEach(b => b.classList.remove('noc-cf-btn--active'));
    document.querySelector('.noc-cf-btn[data-cf="all"]')?.classList.add('noc-cf-btn--active');
    applyClientFilters();
    showToast('Filtros limpos');
  });

  $('feedPauseBtn')?.addEventListener('click', () => {
    feedState.paused = !feedState.paused;
    if ($('feedPauseLbl')) $('feedPauseLbl').textContent = feedState.paused ? 'Retomar' : 'Pausar';
    if ($('feedPauseIcon')) $('feedPauseIcon').innerHTML = feedState.paused
      ? '<polygon points="5 3 19 12 5 21 5 3"/>'
      : '<rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/>';
  });

  $('qaBtnBlock')?.addEventListener('click',  () => _openModal('block'));
  $('qaBtnAllow')?.addEventListener('click',  () => _openModal('allow'));
  $('qaBtnFlush')?.addEventListener('click',  _flushCache);
  $('qaBtnUpdate')?.addEventListener('click', _updateFilters);
  $('qaBtnSoc')?.addEventListener('click',    () => showToast('Abrindo módulo SOC…'));
  $('qaBtnReport')?.addEventListener('click', () => showToast('Relatório DNS gerado'));

  /* ═══════════════════════════════════════════════════════
     AUTO-REFRESH
     v6: recarrega também em prod_offline para detectar
         quando o AdGuard voltar a ficar disponível
  ═══════════════════════════════════════════════════════ */
  setInterval(() => {
    if (state.mode === 'prod' || state.mode === 'prod_offline') loadNocData();
  }, 30_000);
  setInterval(pollQuerylog, 4_000);

  /* ═══════════════════════════════════════════════════════
     TOAST & LIVE TIME
  ═══════════════════════════════════════════════════════ */
  let toastTimer;
  function showToast(msg) {
    const t = $('nocToast'); if (!t) return;
    t.textContent = msg; t.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove('show'), 2600);
  }
  function updateLiveTime() {
    const el = $('nocLastUpdate'); if (!el) return;
    const d  = new Date();
    el.textContent = `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
  }

  /* ═══════════════════════════════════════════════════════
     ESTILOS INJETADOS
  ═══════════════════════════════════════════════════════ */
  const s = document.createElement('style');
  s.textContent = `
    .noc-feed-item { display:flex; align-items:center; gap:6px; padding:5px 10px; border-radius:6px; font-size:11px; }
    .noc-feed-ip   { font-family:var(--font-mono,monospace); color:#64748b; font-size:10px; min-width:82px; }
    .noc-feed-sep  { color:#334155; }
    .noc-feed-qtype{ font-size:9px; color:#475569; background:rgba(255,255,255,.05); padding:1px 4px; border-radius:3px; margin-left:auto; }
    .noc-feed-ms   { font-size:9px; color:#22c55e; margin-left:4px; }

    #dClientFeed    { max-height:220px; overflow-y:auto; scrollbar-width:thin; scrollbar-color:rgba(255,255,255,.08) transparent; }
    .dFeed-row      { display:flex; align-items:center; gap:6px; padding:5px 8px; border-radius:5px; font-size:11px; border-bottom:1px solid rgba(255,255,255,.04); transition:background .15s; }
    .dFeed-row:hover{ background:rgba(255,255,255,.04); }
    .dFeed-row--block { border-left:2px solid rgba(239,68,68,.4); }
    .dFeed-row--allow { border-left:2px solid rgba(34,197,94,.3); }
    .dFeed-time     { font-family:var(--font-mono,monospace); font-size:10px; color:#475569; min-width:52px; }
    .dFeed-badge    { font-size:9px; font-weight:700; padding:1px 5px; border-radius:3px; letter-spacing:.03em; }
    .dFeed-badge--block { background:rgba(239,68,68,.15); color:#ef4444; }
    .dFeed-badge--allow { background:rgba(34,197,94,.12); color:#22c55e; }
    .dFeed-domain   { flex:1; color:var(--text-primary,#e2e8f0); font-size:11px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .dFeed-type     { font-size:9px; color:#475569; background:rgba(255,255,255,.05); padding:1px 4px; border-radius:3px; }
    .dFeed-ms       { font-size:9px; color:#22c55e; }
    .dFeed-empty    { display:flex; align-items:center; gap:6px; font-size:11px; color:#475569; padding:12px 0; }

    .noc-drawer__feed-header { display:flex; align-items:center; justify-content:space-between; margin-bottom:8px; }
    .noc-drawer__feed-title  { font-size:11px; font-weight:600; color:var(--text-secondary,#94a3b8); display:flex; align-items:center; gap:6px; }
  `;
  document.head.appendChild(s);

  /* ═══════════════════════════════════════════════════════
     INIT
  ═══════════════════════════════════════════════════════ */
  loadNocData();
  pollQuerylog();
});