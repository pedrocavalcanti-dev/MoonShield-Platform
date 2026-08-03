/**
 * MOONSHIELD — firewall/feed.js  v2
 * Melhorias:
 *  - Agrupamento de eventos repetidos com contador de hits
 *  - Top 3 origens bloqueadas com mini barra de intensidade
 *  - Geolocalização via ip-api.com (sem key, grátis)
 *  - Taxa de eventos/min calculada em tempo real
 *  - Destaque visual para novos eventos (flash azul)
 *  - Typo corrigido: fwfDetailIface
 *  - "Top Atacante" → "Top Origens Bloqueadas"
 */

document.addEventListener('DOMContentLoaded', () => {

  const $ = id => document.getElementById(id);
  const pad = n => String(n).padStart(2, '0');

  function fmtBytes(b) {
    return b >= 1048576 ? (b / 1048576).toFixed(1) + 'MB'
      : b >= 1024 ? (b / 1024).toFixed(0) + 'KB'
        : b + 'B';
  }
  function getCsrf() {
    return document.cookie.split(';').find(c => c.trim().startsWith('csrftoken='))?.split('=')[1] || '';
  }

  /* ── Estado ── */
  let allEvents = [];
  let paused = false;
  let autoScroll = true;
  let grouped = true;
  let filterAction = 'all';
  let filterIface = 'all';
  let filterProto = 'all';
  let searchQ = '';
  let lastTimestamp = null;
  let currentEvent = null;

  /* KPIs */
  let kpi = { drops: 0, denies: 0, allows: 0, total: 0 };
  const srcCount = {};
  const portCount = {};

  /* Taxa (eventos por minuto) */
  const rateWindow = [];   // timestamps dos últimos eventos
  function calcRate() {
    const now = Date.now();
    // Mantém só os últimos 60s
    while (rateWindow.length && rateWindow[0] < now - 60000) rateWindow.shift();
    return rateWindow.length;
  }

  /* Cache de geolocalização: ip → { country, org, flag, risk } */
  const geoCache = {};
  const geoPending = new Set();

  // Ícone BI por tipo de IP/país
  function _geoIcon(countryCode, isPrivate, isUnknown) {
    if (isPrivate) return '<i class="bi bi-hdd-network" title="Rede privada/local" style="color:var(--c-blue)"></i>';
    if (isUnknown) return '<i class="bi bi-question-circle" title="País desconhecido" style="color:var(--text-dim)"></i>';
    const highRisk = ['CN', 'RU', 'KP', 'IR', 'BY', 'SY', 'CU', 'VE', 'SD'];
    const medRisk = ['NG', 'PK', 'AF', 'IQ', 'LY', 'MM', 'YE', 'ZW'];
    if (highRisk.includes(countryCode))
      return '<i class="bi bi-exclamation-triangle-fill" title="País de alto risco" style="color:var(--c-red)"></i>';
    if (medRisk.includes(countryCode))
      return '<i class="bi bi-exclamation-circle" title="País de médio risco" style="color:var(--c-orange)"></i>';
    return '<i class="bi bi-globe2" title="IP externo" style="color:var(--text-dim)"></i>';
  }

  async function fetchGeo(ip) {
    if (!ip || geoCache[ip] || geoPending.has(ip)) return;
    // IPs privados/locais
    if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|::1$)/.test(ip)) {
      geoCache[ip] = {
        country: 'Rede local', org: 'IP privado',
        icon: _geoIcon(null, true, false), risk: 'low',
      };
      return;
    }
    geoPending.add(ip);
    try {
      const r = await fetch(
        `https://ip-api.com/json/${ip}?fields=country,org,countryCode,status`,
        { signal: AbortSignal.timeout(3000) }
      );
      const d = await r.json();
      if (d.status === 'success') {
        const highRisk = ['CN', 'RU', 'KP', 'IR', 'BY', 'SY', 'CU', 'VE', 'SD'];
        const medRisk = ['NG', 'PK', 'AF', 'IQ', 'LY', 'MM', 'YE', 'ZW'];
        const risk = highRisk.includes(d.countryCode) ? 'high'
          : medRisk.includes(d.countryCode) ? 'med' : 'low';
        geoCache[ip] = {
          country: d.country || '—',
          org: d.org || '—',
          icon: _geoIcon(d.countryCode, false, false),
          risk,
          countryCode: d.countryCode,
        };
      } else {
        geoCache[ip] = {
          country: '—', org: '—',
          icon: _geoIcon(null, false, true), risk: 'low',
        };
      }
    } catch {
      geoCache[ip] = {
        country: '—', org: '—',
        icon: _geoIcon(null, false, true), risk: 'low',
      };
    } finally {
      geoPending.delete(ip);
    }
  }

  /* ── Toast ── */
  let toastTimer;
  function showToast(msg) {
    const t = $('fwfToast'); if (!t) return;
    t.textContent = msg;
    t.className = 'fwf-toast show';
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove('show'), 2600);
  }

  /* ── Drawer ── */
  function openDrawer(ev) {
    currentEvent = ev;
    const badge = $('fwfDrawerBadge');
    badge.textContent = ev.action;
    badge.className = `fwf-action-badge fwf-action-badge--${(ev.action || '').toLowerCase()}`;

    $('fwfDetailSrc').textContent = ev.src_ip || '—';
    $('fwfDetailSrcMeta').textContent = ev.src_port ? `:${ev.src_port}` : '—';
    $('fwfDetailDst').textContent = ev.dst_ip || '—';
    $('fwfDetailDstMeta').textContent = ev.dst_port ? `${ev.iface || ''} · :${ev.dst_port}` : ev.iface || '—';
    $('fwfDetailProtoArrow').textContent = `${ev.proto || '?'} · :${ev.dst_port || '?'}`;
    $('fwfDetailTime').textContent = ev.time || '—';
    $('fwfDetailIface').textContent = ev.iface || '—';
    $('fwfDetailProto').textContent = ev.proto || '—';
    $('fwfDetailBytes').textContent = ev.bytes ? fmtBytes(ev.bytes) : '—';
    $('fwfDetailFlags').textContent = ev.flags || '—';
    $('fwfDetailChain').textContent = ev.chain || '—';
    $('fwfDetailRaw').textContent = JSON.stringify({
      time: ev.time, action: ev.action, iface: ev.iface,
      proto: ev.proto, src_ip: ev.src_ip, src_port: ev.src_port,
      dst_ip: ev.dst_ip, dst_port: ev.dst_port,
      bytes: ev.bytes, flags: ev.flags, chain: ev.chain,
    }, null, 2);

    // Hits (agrupamento)
    const hits = srcCount[ev.src_ip] || 1;
    const hitsBanner = $('fwfHitsBanner');
    if (hitsBanner) {
      if (hits > 1) {
        hitsBanner.style.display = 'flex';
        $('fwfHitsCount').textContent = hits;
      } else {
        hitsBanner.style.display = 'none';
      }
    }

    // Geo
    const geo = geoCache[ev.src_ip];
    const geoBanner = $('fwfGeoBanner');
    if (geoBanner) {
      if (geo) {
        geoBanner.style.display = 'flex';
        $('fwfGeoFlag').innerHTML = geo.icon;
        $('fwfGeoCountry').textContent = geo.country;
        $('fwfGeoOrg').textContent = geo.org;
        const riskEl = $('fwfGeoRisk');
        riskEl.textContent = geo.risk === 'high' ? '⚠ ALTO RISCO' : geo.risk === 'med' ? 'Médio' : 'Baixo';
        riskEl.className = `fwf-geo-risk fwf-geo-risk--${geo.risk}`;
      } else {
        geoBanner.style.display = 'none';
        // Busca em background e reabre
        if (ev.src_ip) fetchGeo(ev.src_ip).then(() => {
          if (currentEvent?.src_ip === ev.src_ip) openDrawer(ev);
        });
      }
    }

    $('fwfDrawer').classList.add('open');
    $('fwfDrawerOverlay').classList.add('open');
  }

  function closeDrawer() {
    $('fwfDrawer').classList.remove('open');
    $('fwfDrawerOverlay').classList.remove('open');
    currentEvent = null;
  }

  $('fwfDrawerClose')?.addEventListener('click', closeDrawer);
  $('fwfDrawerOverlay')?.addEventListener('click', closeDrawer);

  $('fwfDrawerBlock')?.addEventListener('click', () => {
    if (!currentEvent) return;
    bloqueioRapido(currentEvent.src_ip, currentEvent.iface, '', currentEvent.proto, '', 'Bloqueio via Feed');
    closeDrawer();
  });

  $('fwfDrawerAllow')?.addEventListener('click', () => {
    if (!currentEvent) return;
    fetch('/firewall/api/allowlist/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrf() },
      body: JSON.stringify({ ip: currentEvent.src_ip, reason: 'Liberação via Feed' }),
    }).then(() => showToast(`${currentEvent.src_ip} liberado ✓`));
    closeDrawer();
  });

  $('fwfDrawerRule')?.addEventListener('click', () => {
    if (!currentEvent) return;
    const p = new URLSearchParams({
      src: currentEvent.src_ip, port: currentEvent.dst_port || '',
      proto: currentEvent.proto || '', iface: currentEvent.iface || '',
    });
    window.location.href = `/firewall/regras/?nova_regra=1&${p}`;
  });

  $('fwfDrawerCopyIoc')?.addEventListener('click', () => {
    if (!currentEvent) return;
    const ioc = `${currentEvent.src_ip} | :${currentEvent.dst_port} | ${currentEvent.proto} | ${currentEvent.time}`;
    navigator.clipboard?.writeText(ioc);
    showToast('IOC copiado 📋');
  });

  /* ── Bloqueio rápido ── */
  async function bloqueioRapido(ip, iface, porta, proto, expires, motivo) {
    try {
      const r = await fetch('/firewall/api/bloqueio-rapido/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrf() },
        body: JSON.stringify({ ip, iface: iface || '', porta: porta || '', proto: proto || '', expires: expires || '', motivo: motivo || 'Bloqueio via Feed' }),
      });
      const d = await r.json();
      if (d.ok) showToast(`${ip} bloqueado ✓`);
      else showToast(`Erro: ${d.erro || 'falha'}`);
    } catch { showToast('Falha de rede'); }
  }

  /* ── Render de linha ── */
  function actionBadge(action) {
    const a = (action || '').toLowerCase();
    return `<span class="fwf-action-badge fwf-action-badge--${a}">${action}</span>`;
  }

  function geoCell(ip) {
    const geo = geoCache[ip];
    if (!geo) return '<i class="bi bi-hourglass" style="color:var(--text-dim);font-size:11px;opacity:.4"></i>';
    return `<span title="${geo.country} · ${geo.org}" style="font-size:13px">${geo.icon}</span>`;
  }

  function renderRow(ev, idx, isNew = false) {
    const hits = grouped ? (srcCount[ev.src_ip] || 1) : 1;
    const row = document.createElement('div');
    const action = (ev.action || '').toLowerCase();
    row.className = `fwf-row fwf-row--${action}${hits > 1 ? ' fwf-row--grouped' : ''}${isNew ? ' fwf-row--new' : ''}`;
    row.style.animationDelay = `${Math.min(idx, 20) * 10}ms`;

    const hitsBadge = hits > 1
      ? `<span class="fwf-hits-badge"><i class="bi bi-arrow-repeat" style="font-size:8px"></i>${hits}x</span>`
      : `<span class="fwf-hits-badge fwf-hits-badge--single">1x</span>`;

    row.innerHTML = `
      <div class="fwf-cell fwf-cell--time">${ev.time || '—'}</div>
      <div class="fwf-cell">${actionBadge(ev.action)}</div>
      <div class="fwf-cell"><span class="fwf-iface-badge">${ev.iface || '—'}</span></div>
      <div class="fwf-cell fwf-cell--ip">${ev.src_ip || '—'}</div>
      <div class="fwf-cell fwf-cell--geo">${geoCell(ev.src_ip)}</div>
      <div class="fwf-cell fwf-cell--arrow">
        <span style="color:var(--text-dim);font-size:9px">→</span>
        <span style="color:var(--text-primary)">${ev.dst_ip || '—'}</span>
        <span style="color:var(--c-red);font-weight:700">:${ev.dst_port || '—'}</span>
      </div>
      <div class="fwf-cell fwf-cell--proto">${ev.proto || '—'}</div>
      <div class="fwf-cell fwf-cell--hits">${hitsBadge}</div>
      <div class="fwf-cell">
        <div class="fwf-row-actions">
          <button class="fwf-row-btn fwf-row-btn--danger" title="Bloquear IP"><i class="bi bi-ban"></i></button>
          <button class="fwf-row-btn" title="Ver detalhes"><i class="bi bi-eye"></i></button>
          <button class="fwf-row-btn fwf-row-btn--ok" title="Liberar IP"><i class="bi bi-check2-circle"></i></button>
        </div>
      </div>`;

    row.addEventListener('click', e => { if (e.target.closest('.fwf-row-btn')) return; openDrawer(ev); });
    const [btnBlock, btnView, btnAllow] = row.querySelectorAll('.fwf-row-btn');
    btnBlock.addEventListener('click', e => { e.stopPropagation(); bloqueioRapido(ev.src_ip, ev.iface, '', ev.proto, '', 'Bloqueio via Feed'); });
    btnView.addEventListener('click', e => { e.stopPropagation(); openDrawer(ev); });
    btnAllow.addEventListener('click', e => {
      e.stopPropagation();
      fetch('/firewall/api/allowlist/', {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrf() },
        body: JSON.stringify({ ip: ev.src_ip, reason: 'Liberação via Feed' }),
      }).then(() => showToast(`${ev.src_ip} liberado ✓`));
    });

    return row;
  }

  /* ── Filtragem ── */
  function filteredEvents() {
    let events = allEvents;

    // Se agrupado, pega só o evento mais recente por src_ip+action+dst_port
    if (grouped) {
      const seen = new Map();
      events = [];
      for (const ev of allEvents) {
        const key = `${ev.src_ip}|${ev.action}|${ev.dst_port}`;
        if (!seen.has(key)) { seen.set(key, true); events.push(ev); }
      }
    }

    return events.filter(ev => {
      if (filterAction !== 'all' && ev.action !== filterAction) return false;
      if (filterIface !== 'all' && ev.iface !== filterIface) return false;
      if (filterProto !== 'all' && ev.proto !== filterProto) return false;
      if (searchQ) {
        const q = searchQ.toLowerCase();
        if (!ev.src_ip?.includes(q) && !ev.dst_ip?.includes(q) &&
          !String(ev.dst_port).includes(q) && !ev.proto?.toLowerCase().includes(q)) return false;
      }
      return true;
    });
  }

  /* ── Render completo ── */
  function renderAll(newCount = 0) {
    const body = $('fwfTableBody'); if (!body) return;
    const rows = filteredEvents();

    if (rows.length === 0) {
      body.innerHTML = `<div class="fwf-empty"><i class="bi bi-broadcast" style="font-size:28px;opacity:.3"></i><span>Nenhum evento${filterAction !== 'all' ? ' para este filtro' : ' ainda'}…</span></div>`;
      if ($('fwfFooterCount')) $('fwfFooterCount').textContent = '0 eventos visíveis';
      return;
    }

    body.innerHTML = '';
    rows.slice(0, 500).forEach((ev, i) => {
      body.appendChild(renderRow(ev, i, i < newCount));
    });
    if ($('fwfFooterCount')) $('fwfFooterCount').textContent = `${rows.length} evento${rows.length !== 1 ? 's' : ''} visíveis`;
    if (autoScroll) body.scrollTop = 0;
  }

  /* ── KPI Top Origens Bloqueadas (top 3) ── */
  function renderTopSrcs() {
    const el = $('kpiTopSrcs'); if (!el) return;

    // Só origens de DROP/DENY
    const blocked = Object.entries(srcCount)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3);

    if (!blocked.length) {
      el.innerHTML = '<span class="fwf-top-src-empty">—</span>';
      return;
    }

    const max = blocked[0][1];
    el.innerHTML = blocked.map(([ip, hits], i) => {
      const pct = Math.round((hits / max) * 100);
      const geo = geoCache[ip];
      const icon = geo ? geo.icon : '<i class="bi bi-hourglass" style="opacity:.3"></i>';
      return `
        <div class="fwf-top-src-item">
          <span class="fwf-top-src-rank">${i + 1}</span>
          <span class="fwf-top-src-ip" title="${ip}">${icon} ${ip.length > 15 ? ip.slice(0, 13) + '…' : ip}</span>
          <div class="fwf-top-src-bar-wrap">
            <div class="fwf-top-src-bar" style="width:${pct}%"></div>
          </div>
          <span class="fwf-top-src-hits">${hits}x</span>
        </div>`;
    }).join('');
  }

  /* ── Adicionar eventos ── */
  function addEvents(events) {
    if (!events.length) return;
    const now = Date.now();

    events.forEach(ev => {
      allEvents.unshift(ev);
      kpi.total++;
      rateWindow.push(now);
      const a = (ev.action || '').toUpperCase();
      if (a === 'DROP') kpi.drops++;
      else if (a === 'DENY') kpi.denies++;
      else if (a === 'ALLOW') kpi.allows++;

      // Conta só DROP/DENY pra top origens
      if ((a === 'DROP' || a === 'DENY') && ev.src_ip) {
        srcCount[ev.src_ip] = (srcCount[ev.src_ip] || 0) + 1;
      }
      if (ev.dst_port) portCount[ev.dst_port] = (portCount[ev.dst_port] || 0) + 1;

      // Prefetch geo em background
      if (ev.src_ip) fetchGeo(ev.src_ip);
    });

    if (allEvents.length > 2000) allEvents = allEvents.slice(0, 2000);

    // KPIs numéricos
    if ($('kpiDrops')) $('kpiDrops').textContent = kpi.drops.toLocaleString('pt-BR');
    if ($('kpiDenies')) $('kpiDenies').textContent = kpi.denies.toLocaleString('pt-BR');
    if ($('kpiAllows')) $('kpiAllows').textContent = kpi.allows.toLocaleString('pt-BR');
    if ($('kpiTotal')) $('kpiTotal').textContent = kpi.total.toLocaleString('pt-BR');
    if ($('fwfLiveCount')) $('fwfLiveCount').textContent = `${kpi.total} eventos`;

    // Top porta
    const topPort = Object.entries(portCount).sort((a, b) => b[1] - a[1])[0];
    if (topPort && $('kpiTopPort')) $('kpiTopPort').textContent = `:${topPort[0]}`;

    // Taxa
    if ($('kpiRate')) $('kpiRate').innerHTML = `${calcRate()}<span style="font-size:12px;opacity:.6">/m</span>`;

    // Top origens
    renderTopSrcs();

    if (!paused) renderAll(events.length);
  }

  /* ── Poll ── */
  async function poll() {
    try {
      const params = new URLSearchParams({ limit: 50 });
      if (lastTimestamp) params.set('since', lastTimestamp);

      const r = await fetch(`/firewall/api/feed/?${params}`);
      if (!r.ok) return;
      const d = await r.json();
      if (!d.ok) return;

      // Badge modo
      const badge = $('fwfModeBadge');
      if (badge && d.mode) {
        badge.style.display = 'inline-block';
        badge.textContent = d.mode.toUpperCase();
        badge.style.cssText += d.mode === 'prod'
          ? ';background:rgba(59,130,246,.18);color:#3b82f6;border:1px solid rgba(59,130,246,.3)'
          : ';background:rgba(234,179,8,.18);color:#eab308;border:1px solid rgba(234,179,8,.3)';
      }

      // Popula interfaces
      if (d.interfaces?.length) {
        const sel = $('fwfFilterIface');
        if (sel) {
          const cur = sel.value;
          sel.innerHTML = '<option value="all">Interface: Todas</option>';
          d.interfaces.forEach(iface => {
            const o = document.createElement('option');
            o.value = iface.nome || iface;
            o.textContent = iface.nome ? `${iface.nome} (${iface.ip || ''})` : iface;
            sel.appendChild(o);
          });
          if (cur !== 'all') sel.value = cur;
        }
      }

      if (d.eventos?.length) {
        addEvents(d.eventos);
        lastTimestamp = d.eventos[d.eventos.length - 1]?.time || null;
      }
    } catch (e) {
      console.error('[feed] poll error:', e);
    }
  }

  /* ── Controles ── */
  $('fwfPauseBtn')?.addEventListener('click', () => {
    paused = !paused;
    $('fwfPauseIcon').className = paused ? 'bi bi-play-fill' : 'bi bi-pause-fill';
    $('fwfPauseLabel').textContent = paused ? 'Retomar' : 'Pausar';
    $('fwfLiveDot').classList.toggle('paused', paused);
    if (!paused) renderAll();
  });

  $('fwfGroupToggle')?.addEventListener('change', e => {
    grouped = e.target.checked;
    renderAll();
  });

  $('fwfClearBtn')?.addEventListener('click', () => {
    allEvents = [];
    kpi = { drops: 0, denies: 0, allows: 0, total: 0 };
    Object.keys(srcCount).forEach(k => delete srcCount[k]);
    Object.keys(portCount).forEach(k => delete portCount[k]);
    rateWindow.length = 0;
    ['kpiDrops', 'kpiDenies', 'kpiAllows', 'kpiTotal'].forEach(id => { if ($(id)) $(id).textContent = '0'; });
    if ($('kpiTopPort')) $('kpiTopPort').textContent = '—';
    if ($('kpiRate')) $('kpiRate').innerHTML = '0<span style="font-size:12px;opacity:.6">/m</span>';
    if ($('fwfLiveCount')) $('fwfLiveCount').textContent = '0 eventos';
    renderTopSrcs();
    renderAll();
    showToast('Feed limpo');
  });

  $('fwfExportBtn')?.addEventListener('click', () => {
    const rows = filteredEvents();
    const csv = [
      ['Hora', 'Ação', 'Interface', 'Src IP', 'Src Porta', 'Dst IP', 'Dst Porta', 'Proto', 'Bytes', 'Flags', 'País'].join(','),
      ...rows.map(e => {
        const geo = geoCache[e.src_ip];
        return [e.time, e.action, e.iface, e.src_ip, e.src_port, e.dst_ip, e.dst_port, e.proto, e.bytes, e.flags, geo?.country || ''].join(',');
      })
    ].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const a = Object.assign(document.createElement('a'), {
      href: URL.createObjectURL(blob),
      download: `moonshield-fw-feed-${new Date().toISOString().slice(0, 10)}.csv`,
    });
    a.click(); URL.revokeObjectURL(a.href);
    showToast('CSV exportado 📥');
  });

  // Action chips
  document.querySelectorAll('.fwf-chip[data-action]').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.fwf-chip[data-action]').forEach(b => b.classList.remove('fwf-chip--active'));
      btn.classList.add('fwf-chip--active');
      filterAction = btn.dataset.action;
      renderAll();
    });
  });

  $('fwfFilterIface')?.addEventListener('change', e => { filterIface = e.target.value; renderAll(); });
  $('fwfFilterProto')?.addEventListener('change', e => { filterProto = e.target.value; renderAll(); });

  const searchEl = $('fwfSearch');
  const clearBtn = $('fwfSearchClear');
  searchEl?.addEventListener('input', () => {
    searchQ = searchEl.value.trim();
    clearBtn?.classList.toggle('visible', searchQ.length > 0);
    renderAll();
  });
  clearBtn?.addEventListener('click', () => {
    searchEl.value = ''; searchQ = '';
    clearBtn.classList.remove('visible');
    renderAll();
  });

  $('fwfAutoScroll')?.addEventListener('change', e => { autoScroll = e.target.checked; });

  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeDrawer(); });

  /* ── Taxa atualiza a cada segundo ── */
  setInterval(() => {
    if ($('kpiRate')) $('kpiRate').innerHTML = `${calcRate()}<span style="font-size:12px;opacity:.6">/m</span>`;
    // Atualiza geo nas linhas quando geo chegar
    renderTopSrcs();
  }, 5000);

  /* ── Init ── */
  setInterval(poll, 2000);
  poll();
});