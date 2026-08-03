/**
 * MOONSHIELD — feed.js
 * Live Feed DNS — tela completa
 * ─────────────────────────────────────────────────────────────────────────
 * Consome /dns/api/querylog/ a cada 3s via polling delta (since=).
 * Renderiza todas as queries em tabela com filtro tipo/search, KPIs ao vivo,
 * minigráfico de atividade, auto-scroll, exportação CSV.
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
        return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    }
    function pad(n) { return String(n).padStart(2, '0'); }

    /* ═══════════════════════════════════════════════════════
       STATE
    ═══════════════════════════════════════════════════════ */
    const state = {
        /* Buffer de todas as entradas recebidas nesta sessão */
        all: [],          // todas (máx 500)
        displayed: [],    // após filtros aplicados

        /* Filtros */
        typeFilter: 'all',  // 'all' | 'block' | 'allow'
        search: '',

        /* Polling */
        lastTime: null,   // ISO do cursor
        paused: false,
        autoScroll: true,

        /* KPIs de sessão */
        totalSessao: 0,
        blockedSessao: 0,
        allowedSessao: 0,
        uniqueIps: new Set(),

        /* Para req/min */
        rpmBucket: [],     // timestamps das últimas queries (sliding window 60s)

        /* Modo backend */
        mode: '—',
    };

    /* Minigráfico: conta queries por intervalo de 10s nos últimos 2 min */
    const MINI_BUCKETS = 24;  // 24 × 5s = 2 min de janela
    const MINI_INTERVAL = 5000;
    let miniChart = null;
    const miniBuckets = Array(MINI_BUCKETS).fill(0); // queries/bucket
    let lastBucketTime = Date.now();

    /* ═══════════════════════════════════════════════════════
       CHART.JS MINI
    ═══════════════════════════════════════════════════════ */
    Chart.defaults.color = 'rgba(255,255,255,0.20)';
    Chart.defaults.font.family = "'JetBrains Mono', monospace";
    Chart.defaults.plugins.legend.display = false;

    function initMiniChart() {
        const ctx = $('feedMiniChart');
        if (!ctx) return;
        const grad = ctx.getContext('2d').createLinearGradient(0, 0, 0, 40);
        grad.addColorStop(0, 'rgba(239,68,68,0.55)');
        grad.addColorStop(1, 'rgba(239,68,68,0.00)');
        miniChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: Array(MINI_BUCKETS).fill(''),
                datasets: [{
                    data: [...miniBuckets],
                    borderColor: '#ef4444',
                    borderWidth: 1.5,
                    fill: true,
                    backgroundColor: grad,
                    tension: 0.45,
                    pointRadius: 0,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                plugins: { tooltip: { enabled: false } },
                scales: { x: { display: false }, y: { display: false, min: 0 } },
            }
        });
    }

    function updateMiniChart(newCount) {
        const now = Date.now();
        /* Avança buckets se passaram intervalos desde o último */
        const elapsed = now - lastBucketTime;
        const steps = Math.floor(elapsed / MINI_INTERVAL);
        if (steps > 0) {
            for (let i = 0; i < Math.min(steps, MINI_BUCKETS); i++) {
                miniBuckets.shift();
                miniBuckets.push(0);
            }
            lastBucketTime += steps * MINI_INTERVAL;
        }
        /* Acumula no bucket atual */
        miniBuckets[miniBuckets.length - 1] += newCount;
        if (miniChart) {
            miniChart.data.datasets[0].data = [...miniBuckets];
            miniChart.update('none');
        }
    }

    /* ═══════════════════════════════════════════════════════
       POLLING
    ═══════════════════════════════════════════════════════ */
    async function poll() {
        try {
            const url = state.lastTime
                ? `/dns/api/querylog/?since=${encodeURIComponent(state.lastTime)}&limit=50`
                : `/dns/api/querylog/?limit=80`;

            const res = await fetch(url);
            if (!res.ok) return;
            const data = await res.json();
            if (!data.ok || !data.entries || data.entries.length === 0) return;

            /* Atualiza modo */
            if (data.mode) {
                state.mode = data.mode;
                renderModeBadge(data.mode);
            }

            const incoming = data.entries;
            const newEntries = state.lastTime
                ? incoming.filter(e => e.time > state.lastTime)
                : incoming;

            if (newEntries.length === 0) return;

            /* Atualiza cursor */
            state.lastTime = incoming[0].time;

            /* Acumula no buffer */
            state.all = [...newEntries, ...state.all].slice(0, 500);

            /* Atualiza KPIs de sessão */
            newEntries.forEach(e => {
                state.totalSessao++;
                if (e.blocked) state.blockedSessao++;
                else state.allowedSessao++;
                state.uniqueIps.add(e.ip);
                state.rpmBucket.push(Date.now());
            });

            /* Limpa rpmBucket (janela 60s) */
            const cutoff = Date.now() - 60_000;
            state.rpmBucket = state.rpmBucket.filter(t => t > cutoff);

            /* Minigráfico */
            updateMiniChart(newEntries.length);

            /* Renderiza KPIs */
            renderKPIs();

            /* Renderiza linhas novas se não pausado */
            if (!state.paused) {
                addRows(newEntries);
            }

            /* Timestamp atualização */
            const lu = $('feedLastUpdate');
            if (lu) lu.textContent = nowStr();

        } catch { /* silencioso */ }
    }

    /* ═══════════════════════════════════════════════════════
       RENDERIZAÇÃO DAS LINHAS
    ═══════════════════════════════════════════════════════ */
    function addRows(entries) {
        const tbody = $('feedTableBody');
        const emptyState = $('feedEmptyState');
        if (!tbody) return;

        /* Remove estado vazio na primeira entrada */
        if (emptyState && tbody.contains(emptyState)) {
            tbody.removeChild(emptyState);
        }

        /* Aplica filtros para decidir quais realmente renderizar */
        const toRender = entries.filter(matchesFilter);
        if (toRender.length === 0) return;

        const frag = document.createDocumentFragment();
        toRender.forEach(e => {
            const row = buildRow(e);
            frag.appendChild(row);
        });

        /* Insere no topo */
        tbody.insertBefore(frag, tbody.firstChild);

        /* Limita DOM a 300 nós visíveis */
        while (tbody.children.length > 300) {
            tbody.removeChild(tbody.lastChild);
        }

        /* Auto-scroll se ativado (scroll para o topo pois inserimos no início) */
        if (state.autoScroll) {
            tbody.scrollTop = 0;
        }

        /* Atualiza contador de linhas */
        updateRowCount();
    }

    function buildRow(e) {
        const cls = e.blocked ? 'block' : 'allow';
        const domainCls = e.blocked ? 'is-blocked' : '';
        const latencyHtml = buildLatency(e);
        const filterHtml = e.filter
            ? `<span class="feed-cell feed-cell--filter has-filter" title="${e.filter}">${truncate(e.filter, 22)}</span>`
            : `<span class="feed-cell feed-cell--filter">—</span>`;

        const row = document.createElement('div');
        row.className = `feed-row feed-row--${cls}`;
        row.dataset.time = e.time;
        row.dataset.ip = e.ip;
        row.dataset.domain = e.domain;
        row.dataset.blocked = e.blocked ? '1' : '0';
        row.innerHTML = `
      <span class="feed-cell feed-cell--time">${e.time_fmt || '—'}</span>
      <span class="feed-cell">
        <span class="feed-status-pill feed-status-pill--${cls}">
          <span class="feed-status-dot"></span>
          ${e.blocked ? 'BLOCK' : 'ALLOW'}
        </span>
      </span>
      <span class="feed-cell feed-cell--ip" title="${e.ip}">${e.ip}</span>
      <span class="feed-cell feed-cell--domain ${domainCls}" title="${e.domain}">${e.domain}</span>
      <span class="feed-cell">${buildTypeTag(e.type)}</span>
      ${latencyHtml}
      ${filterHtml}
    `;
        return row;
    }

    function buildTypeTag(type = 'A') {
        const t = type.toUpperCase();
        const cls = t === 'AAAA' ? 'aaaa' : t === 'CNAME' ? 'cname' : '';
        return `<span class="feed-cell feed-cell--type"><span class="feed-type-tag${cls ? ' feed-type-tag--' + cls : ''}">${t}</span></span>`;
    }

    function buildLatency(e) {
        if (e.blocked || e.elapsed_ms === null || e.elapsed_ms === undefined) {
            return `<span class="feed-cell feed-cell--latency"><span class="feed-lat--blocked">—</span></span>`;
        }
        const ms = e.elapsed_ms;
        const cls = ms < 5 ? 'fast' : ms < 20 ? 'medium' : 'slow';
        return `<span class="feed-cell feed-cell--latency"><span class="feed-lat--${cls}">${ms}ms</span></span>`;
    }

    function truncate(str, max) {
        return str.length > max ? str.slice(0, max) + '…' : str;
    }

    /* ═══════════════════════════════════════════════════════
       FILTROS
    ═══════════════════════════════════════════════════════ */
    function matchesFilter(e) {
        if (state.typeFilter === 'block' && !e.blocked) return false;
        if (state.typeFilter === 'allow' && e.blocked) return false;
        if (state.search) {
            const q = state.search.toLowerCase();
            return e.ip.includes(q) || e.domain.toLowerCase().includes(q);
        }
        return true;
    }

    /* Reaplica filtros ao buffer completo — limpa tabela e rerenderiza */
    function reapplyFilters() {
        const tbody = $('feedTableBody'); if (!tbody) return;
        tbody.innerHTML = '';

        const filtered = state.all.filter(matchesFilter).slice(0, 300);
        if (filtered.length === 0) {
            const empty = document.createElement('div');
            empty.className = 'feed-empty-state';
            empty.id = 'feedEmptyState';
            empty.innerHTML = `
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2" style="color:var(--text-dim)">
          <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
        </svg>
        <p>Nenhum resultado para os filtros atuais.</p>`;
            tbody.appendChild(empty);
            updateRowCount();
            return;
        }

        const frag = document.createDocumentFragment();
        filtered.forEach(e => {
            const row = buildRow(e);
            /* Desativa animação na rerenderização em massa */
            row.style.animation = 'none';
            frag.appendChild(row);
        });
        tbody.appendChild(frag);
        updateRowCount();
    }

    /* ═══════════════════════════════════════════════════════
       KPIs
    ═══════════════════════════════════════════════════════ */
    function renderKPIs() {
        const pct = state.totalSessao > 0
            ? Math.round((state.blockedSessao / state.totalSessao) * 100)
            : 0;
        const rpm = state.rpmBucket.length; // entradas nos últimos 60s

        if ($('fkTotal')) $('fkTotal').textContent = fmtNum(state.totalSessao);
        if ($('fkBlocked')) $('fkBlocked').textContent = fmtNum(state.blockedSessao);
        if ($('fkAllowed')) $('fkAllowed').textContent = fmtNum(state.allowedSessao);
        if ($('fkPct')) $('fkPct').textContent = pct + '%';
        if ($('fkRps')) $('fkRps').textContent = rpm;
        if ($('fkIps')) $('fkIps').textContent = state.uniqueIps.size;
    }

    /* ═══════════════════════════════════════════════════════
       MODE BADGE
    ═══════════════════════════════════════════════════════ */
    function renderModeBadge(mode) {
        const badge = $('feedModeBadge'); if (!badge) return;
        badge.style.display = 'inline-block';
        const cfg = {
            demo: { label: 'DEMO', color: '#eab308', bg: 'rgba(234,179,8,.1)', border: 'rgba(234,179,8,.3)' },
            prod: { label: 'PROD', color: '#22c55e', bg: 'rgba(34,197,94,.1)', border: 'rgba(34,197,94,.3)' },
            mock: { label: 'MOCK', color: '#eab308', bg: 'rgba(234,179,8,.1)', border: 'rgba(234,179,8,.3)' },
            fallback: { label: 'FALLBACK', color: '#f97316', bg: 'rgba(249,115,22,.1)', border: 'rgba(249,115,22,.3)' },
        }[mode] || { label: mode.toUpperCase(), color: '#888', bg: 'rgba(255,255,255,.05)', border: 'rgba(255,255,255,.1)' };
        badge.textContent = cfg.label;
        badge.style.color = cfg.color;
        badge.style.background = cfg.bg;
        badge.style.border = `1px solid ${cfg.border}`;
    }

    /* ═══════════════════════════════════════════════════════
       CONTADOR DE LINHAS
    ═══════════════════════════════════════════════════════ */
    function updateRowCount() {
        const tbody = $('feedTableBody');
        const count = tbody ? tbody.querySelectorAll('.feed-row').length : 0;
        const rc = $('feedRowCount');
        if (rc) rc.textContent = `${count} ${count === 1 ? 'entrada' : 'entradas'} exibidas`;
    }

    /* ═══════════════════════════════════════════════════════
       CONTROLES & EVENTOS
    ═══════════════════════════════════════════════════════ */
    
    /* Search elements */
    const searchEl = $('feedSearch');
    const searchClearEl = $('feedSearchClear');

    /* LÊ A URL E APLICA O IP AUTOMATICAMENTE */
    const urlParams = new URLSearchParams(window.location.search);
    const ipFiltrado = urlParams.get('ip');

    if (ipFiltrado) {
        state.search = ipFiltrado.trim();
        if (searchEl) searchEl.value = state.search;
        if (searchClearEl) searchClearEl.classList.add('visible');
        // Não precisamos chamar reapplyFilters() aqui porque a tabela ainda está vazia
        // O primeiro poll() já vai baixar os dados e aplicar esse state.search!
    }

    searchEl?.addEventListener('input', () => {
        state.search = searchEl.value.trim();
        searchClearEl?.classList.toggle('visible', state.search.length > 0);
        reapplyFilters();
    });

    searchClearEl?.addEventListener('click', () => {
        if (searchEl) searchEl.value = '';
        state.search = '';
        searchClearEl?.classList.remove('visible');
        
        // Se houver "ip" na URL, vamos removê-lo da barra de endereços para não confundir o usuário ao recarregar
        if (urlParams.has('ip')) {
            window.history.replaceState({}, document.title, window.location.pathname);
        }
        
        reapplyFilters();
    });

    /* Pausar / Retomar */
    $('feedPauseBtn')?.addEventListener('click', () => {
        state.paused = !state.paused;

        const dot = document.querySelector('.feed-live__dot');
        const lbl = $('feedPauseLbl');
        const icon = $('feedPauseIcon');

        if (dot) dot.classList.toggle('paused', state.paused);
        if (lbl) lbl.textContent = state.paused ? 'Retomar' : 'Pausar';
        if (icon) icon.innerHTML = state.paused
            ? '<polygon points="5 3 19 12 5 21 5 3"/>'
            : '<rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/>';

        if (!state.paused) {
            /* Retomou: renderiza tudo que ficou acumulado */
            reapplyFilters();
        }
    });

    /* Limpar log */
    $('feedClearBtn')?.addEventListener('click', () => {
        state.all = [];
        state.totalSessao = 0;
        state.blockedSessao = 0;
        state.allowedSessao = 0;
        state.uniqueIps = new Set();
        state.rpmBucket = [];
        miniBuckets.fill(0);
        if (miniChart) { miniChart.data.datasets[0].data = [...miniBuckets]; miniChart.update('none'); }
        renderKPIs();

        const tbody = $('feedTableBody'); if (!tbody) return;
        tbody.innerHTML = '';
        const empty = document.createElement('div');
        empty.className = 'feed-empty-state';
        empty.id = 'feedEmptyState';
        empty.innerHTML = `
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2" style="color:var(--text-dim)">
        <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
      </svg>
      <p>Log limpo. Aguardando novas consultas…</p>`;
        tbody.appendChild(empty);
        updateRowCount();
        showToast('Log limpo');
    });

    /* Exportar CSV */
    $('feedExportBtn')?.addEventListener('click', () => {
        const entries = state.all.filter(matchesFilter);
        if (!entries.length) { showToast('Nenhuma entrada para exportar'); return; }
        const headers = ['Hora', 'IP', 'Domínio', 'Tipo', 'Status', 'Latência(ms)', 'Filtro'];
        const rows = entries.map(e => [
            e.time_fmt || e.time,
            e.ip,
            e.domain,
            e.type,
            e.blocked ? 'BLOCK' : 'ALLOW',
            e.elapsed_ms ?? '',
            e.filter || '',
        ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(','));
        const blob = new Blob([[headers.join(','), ...rows].join('\n')], { type: 'text/csv;charset=utf-8;' });
        const a = Object.assign(document.createElement('a'), {
            href: URL.createObjectURL(blob),
            download: `feed-dns-${new Date().toISOString().slice(0, 10)}.csv`,
        });
        a.click(); URL.revokeObjectURL(a.href);
        showToast(`${entries.length} entradas exportadas`);
    });

    /* Filtro por tipo (chips) */
    document.querySelectorAll('.feed-chip').forEach(chip => {
        chip.addEventListener('click', () => {
            document.querySelectorAll('.feed-chip').forEach(c => c.classList.remove('feed-chip--active'));
            chip.classList.add('feed-chip--active');
            state.typeFilter = chip.dataset.type;
            reapplyFilters();
        });
    });

    /* Auto-scroll toggle */
    $('feedAutoScroll')?.addEventListener('change', e => {
        state.autoScroll = e.target.checked;
    });

    /* ═══════════════════════════════════════════════════════
       TOAST
    ═══════════════════════════════════════════════════════ */
    let toastTimer;
    function showToast(msg) {
        const t = $('feedToast'); if (!t) return;
        t.textContent = msg; t.classList.add('show');
        clearTimeout(toastTimer);
        toastTimer = setTimeout(() => t.classList.remove('show'), 2600);
    }

    /* ═══════════════════════════════════════════════════════
       INIT
    ═══════════════════════════════════════════════════════ */
    initMiniChart();
    poll();                              /* primeiro poll imediato */
    setInterval(poll, 3_000);           /* polling a cada 3s */
    setInterval(renderKPIs, 5_000);     /* atualiza req/min a cada 5s */

});