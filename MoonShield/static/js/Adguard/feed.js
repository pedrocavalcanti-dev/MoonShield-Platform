/**
 * MOONSHIELD — feed.js v2
 * Live Feed DNS — tela completa
 *
 * Melhorias:
 * - sem dependência do Chart.js/CDN;
 * - polling protegido contra chamadas concorrentes;
 * - deduplicação de eventos;
 * - filtros por status, tipo DNS, cache/upstream e busca;
 * - drawer com detalhes completos;
 * - ações rápidas BLOCK/ALLOW;
 * - tratamento visual de PROD offline;
 * - exportação CSV com campos adicionais;
 * - minigráfico em canvas nativo.
 */

document.addEventListener('DOMContentLoaded', () => {
    'use strict';

    const $ = (id) => document.getElementById(id);

    const MAX_BUFFER = 500;
    const MAX_DOM_ROWS = 300;
    const POLL_MS = 3000;
    const RPM_WINDOW = 60_000;
    const MINI_BUCKETS = 24;
    const MINI_INTERVAL = 5000;

    const state = {
        all: [],
        typeFilter: 'all',
        qtypeFilter: 'all',
        cacheFilter: 'all',
        search: '',
        lastTime: null,
        paused: false,
        autoScroll: true,
        mode: '—',
        polling: false,
        seen: new Set(),
        selected: null,
        rpmBucket: [],
        lastPollOk: false,
    };

    const miniBuckets = Array(MINI_BUCKETS).fill(0);
    let lastBucketTime = Date.now();
    let toastTimer = null;

    function fmtNum(n) {
        const value = Number(n || 0);
        if (value >= 1_000_000) return (value / 1_000_000).toFixed(1) + 'M';
        if (value >= 1_000) return (value / 1_000).toFixed(1) + 'k';
        return String(value);
    }

    function pad(n) {
        return String(n).padStart(2, '0');
    }

    function nowStr() {
        const d = new Date();
        return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    }

    function esc(value) {
        return String(value ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    function truncate(value, max = 30) {
        const s = String(value || '');
        return s.length > max ? s.slice(0, max) + '…' : s;
    }

    function getCsrf() {
        return document.cookie
            .split(';')
            .map((c) => c.trim())
            .find((c) => c.startsWith('csrftoken='))
            ?.split('=')[1] || '';
    }

    function eventKey(e) {
        return [
            e.time || '',
            e.ip || '',
            e.domain || '',
            e.type || '',
            e.blocked ? '1' : '0',
            e.filter || '',
        ].join('|');
    }

    function safeDomain(e) {
        return String(e?.domain || '—').replace(/\.$/, '');
    }

    function normalizedEntry(e) {
        return {
            time: String(e?.time || ''),
            time_fmt: String(e?.time_fmt || ''),
            ip: String(e?.ip || '—'),
            domain: safeDomain(e),
            type: String(e?.type || 'A').toUpperCase(),
            blocked: Boolean(e?.blocked),
            status: String(e?.status || (e?.blocked ? 'Bloqueado' : 'Processado')),
            elapsed_ms: e?.elapsed_ms === null || e?.elapsed_ms === undefined
                ? null
                : Number(e.elapsed_ms),
            filter: String(e?.filter || ''),
            reason: String(e?.reason || ''),
            upstream: String(e?.upstream || ''),
            cached: Boolean(e?.cached),
        };
    }

    function setLiveState(kind, message = '') {
        const dot = $('feedLiveDot');
        const root = $('feedLiveState');
        if (dot) {
            dot.classList.remove('is-ok', 'is-paused', 'is-error');
            dot.classList.add(kind === 'error' ? 'is-error' : kind === 'paused' ? 'is-paused' : 'is-ok');
        }
        if (root) root.title = message || (kind === 'error' ? 'Falha na coleta' : 'Coleta ativa');
    }

    function showWarning(message) {
        const box = $('feedWarning');
        const txt = $('feedWarningText');
        if (txt) txt.textContent = message || 'AdGuard indisponível.';
        if (box) box.hidden = false;
        setLiveState('error', message);
    }

    function hideWarning() {
        const box = $('feedWarning');
        if (box) box.hidden = true;
        if (!state.paused) setLiveState('ok');
    }

    function renderModeBadge(mode) {
        const badge = $('feedModeBadge');
        if (!badge) return;

        const cfg = {
            demo:         { label: 'DEMO', color: '#eab308', bg: 'rgba(234,179,8,.10)', border: 'rgba(234,179,8,.30)' },
            prod:         { label: 'PROD', color: '#22c55e', bg: 'rgba(34,197,94,.10)', border: 'rgba(34,197,94,.30)' },
            prod_offline: { label: 'PROD', color: '#ef4444', bg: 'rgba(239,68,68,.10)', border: 'rgba(239,68,68,.30)' },
        }[mode] || {
            label: String(mode || '?').toUpperCase(),
            color: '#94a3b8',
            bg: 'rgba(148,163,184,.08)',
            border: 'rgba(148,163,184,.20)',
        };

        badge.style.display = 'inline-block';
        badge.textContent = cfg.label;
        badge.style.color = cfg.color;
        badge.style.background = cfg.bg;
        badge.style.border = `1px solid ${cfg.border}`;
    }

    function advanceMiniBuckets(newCount) {
        const now = Date.now();
        const elapsed = now - lastBucketTime;
        const steps = Math.floor(elapsed / MINI_INTERVAL);

        if (steps > 0) {
            for (let i = 0; i < Math.min(steps, MINI_BUCKETS); i++) {
                miniBuckets.shift();
                miniBuckets.push(0);
            }
            lastBucketTime += steps * MINI_INTERVAL;
        }

        miniBuckets[miniBuckets.length - 1] += Number(newCount || 0);
        drawMiniChart();
    }

    function drawMiniChart() {
        const canvas = $('feedMiniChart');
        if (!canvas) return;

        const rect = canvas.getBoundingClientRect();
        const dpr = window.devicePixelRatio || 1;
        const width = Math.max(120, Math.floor(rect.width || canvas.width));
        const height = Math.max(32, Math.floor(rect.height || canvas.height));

        if (canvas.width !== Math.floor(width * dpr) || canvas.height !== Math.floor(height * dpr)) {
            canvas.width = Math.floor(width * dpr);
            canvas.height = Math.floor(height * dpr);
        }

        const ctx = canvas.getContext('2d');
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.clearRect(0, 0, width, height);

        const max = Math.max(1, ...miniBuckets);
        const step = width / Math.max(1, miniBuckets.length - 1);

        const pts = miniBuckets.map((v, i) => ({
            x: i * step,
            y: height - 5 - ((v / max) * (height - 10)),
        }));

        const gradient = ctx.createLinearGradient(0, 0, 0, height);
        gradient.addColorStop(0, 'rgba(239,68,68,.36)');
        gradient.addColorStop(1, 'rgba(239,68,68,0)');

        ctx.beginPath();
        ctx.moveTo(pts[0].x, height);
        pts.forEach((p) => ctx.lineTo(p.x, p.y));
        ctx.lineTo(pts[pts.length - 1].x, height);
        ctx.closePath();
        ctx.fillStyle = gradient;
        ctx.fill();

        ctx.beginPath();
        pts.forEach((p, i) => {
            if (i === 0) ctx.moveTo(p.x, p.y);
            else ctx.lineTo(p.x, p.y);
        });
        ctx.strokeStyle = '#ef4444';
        ctx.lineWidth = 1.5;
        ctx.stroke();
    }

    function pruneRpm() {
        const cutoff = Date.now() - RPM_WINDOW;
        state.rpmBucket = state.rpmBucket.filter((t) => t > cutoff);
    }

    function renderKPIs() {
        pruneRpm();

        const total = state.all.length;
        const blocked = state.all.filter((e) => e.blocked).length;
        const allowed = total - blocked;
        const pct = total ? Math.round((blocked / total) * 100) : 0;
        const ips = new Set(state.all.map((e) => e.ip).filter(Boolean));

        if ($('fkTotal')) $('fkTotal').textContent = fmtNum(total);
        if ($('fkBlocked')) $('fkBlocked').textContent = fmtNum(blocked);
        if ($('fkAllowed')) $('fkAllowed').textContent = fmtNum(allowed);
        if ($('fkPct')) $('fkPct').textContent = `${pct}%`;
        if ($('fkRps')) $('fkRps').textContent = fmtNum(state.rpmBucket.length);
        if ($('fkIps')) $('fkIps').textContent = fmtNum(ips.size);
        if ($('feedBufferInfo')) $('feedBufferInfo').textContent = `buffer ${total}/${MAX_BUFFER}`;
    }

    function matchesFilter(e) {
        if (state.typeFilter === 'block' && !e.blocked) return false;
        if (state.typeFilter === 'allow' && e.blocked) return false;

        if (state.qtypeFilter !== 'all' && String(e.type).toUpperCase() !== state.qtypeFilter) {
            return false;
        }

        if (state.cacheFilter === 'cache' && !e.cached) return false;
        if (state.cacheFilter === 'upstream' && e.cached) return false;

        if (state.search) {
            const q = state.search.toLowerCase();
            const haystack = [
                e.ip,
                e.domain,
                e.type,
                e.filter,
                e.reason,
                e.upstream,
                e.cached ? 'cache' : 'upstream',
            ].join(' ').toLowerCase();
            if (!haystack.includes(q)) return false;
        }

        return true;
    }

    function buildTypeTag(type = 'A') {
        const t = String(type || 'A').toUpperCase();
        const known = ['A', 'AAAA', 'HTTPS', 'CNAME', 'SRV', 'PTR', 'TXT', 'MX', 'NS'];
        const cls = known.includes(t) ? t.toLowerCase() : 'other';
        return `<span class="feed-type-tag feed-type-tag--${esc(cls)}">${esc(t)}</span>`;
    }

    function buildLatency(e) {
        if (e.blocked || e.elapsed_ms === null || Number.isNaN(e.elapsed_ms)) {
            return '<span class="feed-lat feed-lat--none">—</span>';
        }

        const ms = Number(e.elapsed_ms);
        const cls = ms < 5 ? 'fast' : ms < 25 ? 'medium' : 'slow';
        return `<span class="feed-lat feed-lat--${cls}">${esc(ms.toFixed(ms < 10 ? 2 : 1))} ms</span>`;
    }

    function buildSource(e) {
        if (e.blocked) return '<span class="feed-source feed-source--blocked">policy</span>';
        if (e.cached) return '<span class="feed-source feed-source--cache">cache</span>';
        return '<span class="feed-source feed-source--upstream">upstream</span>';
    }

    function buildRow(e) {
        const cls = e.blocked ? 'block' : 'allow';
        const row = document.createElement('div');
        row.className = `feed-row feed-row--${cls}`;
        row.dataset.key = eventKey(e);

        const filterTitle = e.filter || e.reason || '';
        const filterText = e.filter ? truncate(e.filter, 28) : e.reason ? truncate(e.reason, 28) : '—';

        row.innerHTML = `
            <span class="feed-cell feed-cell--time mono">${esc(e.time_fmt || '—')}</span>

            <span class="feed-cell feed-cell--status">
                <span class="feed-status-pill feed-status-pill--${cls}">
                    <span class="feed-status-dot"></span>
                    ${e.blocked ? 'BLOCK' : 'ALLOW'}
                </span>
            </span>

            <span class="feed-cell feed-cell--ip mono" title="${esc(e.ip)}">${esc(e.ip)}</span>

            <span class="feed-cell feed-cell--domain ${e.blocked ? 'is-blocked' : ''}" title="${esc(e.domain)}">
                ${esc(e.domain)}
            </span>

            <span class="feed-cell feed-cell--type">${buildTypeTag(e.type)}</span>

            <span class="feed-cell feed-cell--latency">${buildLatency(e)}</span>

            <span class="feed-cell feed-cell--source">${buildSource(e)}</span>

            <span class="feed-cell feed-cell--filter ${filterTitle ? 'has-filter' : ''}" title="${esc(filterTitle)}">
                ${esc(filterText)}
            </span>

            <span class="feed-cell feed-cell--actions">
                <button type="button" class="feed-row-btn" data-action="detail" title="Detalhes">Detalhes</button>
                <button type="button" class="feed-row-btn feed-row-btn--ghost" data-action="copy" title="Copiar domínio">Copiar</button>
            </span>
        `;

        row.querySelector('[data-action="detail"]')?.addEventListener('click', (ev) => {
            ev.stopPropagation();
            openDetail(e);
        });

        row.querySelector('[data-action="copy"]')?.addEventListener('click', async (ev) => {
            ev.stopPropagation();
            await copyText(e.domain);
        });

        row.addEventListener('dblclick', () => openDetail(e));
        return row;
    }

    function renderAll() {
        const body = $('feedTableBody');
        if (!body) return;

        const filtered = state.all.filter(matchesFilter).slice(0, MAX_DOM_ROWS);
        body.innerHTML = '';

        if (!filtered.length) {
            const empty = document.createElement('div');
            empty.className = 'feed-empty-state';
            empty.id = 'feedEmptyState';
            empty.innerHTML = `
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2">
                    <circle cx="12" cy="12" r="10"/>
                    <polyline points="12 6 12 12 16 14"/>
                </svg>
                <p>Nenhum resultado para os filtros atuais.</p>
                <span>Altere a busca ou os filtros para exibir consultas.</span>
            `;
            body.appendChild(empty);
        } else {
            const frag = document.createDocumentFragment();
            filtered.forEach((entry) => frag.appendChild(buildRow(entry)));
            body.appendChild(frag);
        }

        if (state.autoScroll) body.scrollTop = 0;
        updateRowCount(filtered.length);
    }

    function updateRowCount(count = null) {
        const visible = count ?? document.querySelectorAll('#feedTableBody .feed-row').length;
        const rc = $('feedRowCount');
        if (rc) {
            rc.textContent = `${visible} ${visible === 1 ? 'entrada exibida' : 'entradas exibidas'}`;
        }
    }

    function ingest(entries) {
        const fresh = [];

        for (const raw of entries || []) {
            const e = normalizedEntry(raw);
            const key = eventKey(e);
            if (state.seen.has(key)) continue;

            state.seen.add(key);
            fresh.push(e);

            const ts = e.time ? Date.parse(e.time) : NaN;
            state.rpmBucket.push(Number.isNaN(ts) ? Date.now() : ts);
        }

        if (!fresh.length) return 0;

        fresh.sort((a, b) => String(b.time).localeCompare(String(a.time)));
        state.all = [...fresh, ...state.all]
            .sort((a, b) => String(b.time).localeCompare(String(a.time)))
            .slice(0, MAX_BUFFER);

        if (state.seen.size > 2000) {
            state.seen = new Set(state.all.map(eventKey));
        }

        advanceMiniBuckets(fresh.length);
        renderKPIs();

        if (!state.paused) renderAll();
        return fresh.length;
    }

    async function poll() {
        if (state.polling) return;
        state.polling = true;

        try {
            const url = state.lastTime
                ? `/dns/api/querylog/?since=${encodeURIComponent(state.lastTime)}&limit=80`
                : '/dns/api/querylog/?limit=120';

            const res = await fetch(url, {
                method: 'GET',
                headers: { 'Accept': 'application/json' },
                cache: 'no-store',
            });

            if (!res.ok) {
                throw new Error(`HTTP ${res.status}`);
            }

            const data = await res.json();
            state.mode = data.mode || state.mode;
            renderModeBadge(state.mode);

            if (state.mode === 'prod_offline') {
                showWarning(data.warning || 'AdGuard indisponível ou não configurado.');
                return;
            }

            hideWarning();

            const incoming = Array.isArray(data.entries) ? data.entries : [];
            if (incoming.length) {
                const newest = incoming
                    .map((e) => e?.time)
                    .filter(Boolean)
                    .sort()
                    .at(-1);

                if (newest && (!state.lastTime || newest > state.lastTime)) {
                    state.lastTime = newest;
                }

                ingest(incoming);
            } else {
                renderKPIs();
            }

            state.lastPollOk = true;
            if ($('feedLastUpdate')) $('feedLastUpdate').textContent = nowStr();
            if (!state.paused) setLiveState('ok');

        } catch (err) {
            state.lastPollOk = false;
            showWarning(`Falha ao consultar o feed DNS: ${err.message}`);
        } finally {
            state.polling = false;
        }
    }

    function openDetail(entry) {
        state.selected = entry;

        const blocked = entry.blocked;
        const status = $('fdStatus');
        if (status) {
            status.className = `feed-status-pill feed-status-pill--${blocked ? 'block' : 'allow'}`;
            status.innerHTML = `<span class="feed-status-dot"></span>${blocked ? 'BLOCK' : 'ALLOW'}`;
        }

        if ($('fdDomain')) $('fdDomain').textContent = entry.domain || '—';
        if ($('fdType')) {
            $('fdType').className = `feed-type-tag feed-type-tag--${String(entry.type || 'A').toLowerCase()}`;
            $('fdType').textContent = entry.type || 'A';
        }
        if ($('fdTime')) $('fdTime').textContent = entry.time_fmt || entry.time || '—';
        if ($('fdIp')) $('fdIp').textContent = entry.ip || '—';
        if ($('fdLatency')) $('fdLatency').textContent =
            entry.blocked || entry.elapsed_ms === null ? '—' : `${entry.elapsed_ms} ms`;
        if ($('fdSource')) $('fdSource').textContent =
            entry.blocked ? 'Política / filtro' : entry.cached ? 'Cache local' : 'Upstream';
        if ($('fdUpstream')) $('fdUpstream').textContent = entry.upstream || '—';
        if ($('fdReason')) $('fdReason').textContent = entry.reason || '—';
        if ($('fdFilter')) $('fdFilter').textContent = entry.filter || '—';

        $('feedDetail')?.classList.add('is-open');
        $('feedDetailOverlay')?.classList.add('is-open');
        $('feedDetail')?.setAttribute('aria-hidden', 'false');
    }

    function closeDetail() {
        $('feedDetail')?.classList.remove('is-open');
        $('feedDetailOverlay')?.classList.remove('is-open');
        $('feedDetail')?.setAttribute('aria-hidden', 'true');
        state.selected = null;
    }

    async function postDomain(url, domain) {
        if (!domain || domain === '—') return;

        const res = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrf(),
                'Accept': 'application/json',
            },
            body: JSON.stringify({ domains: domain }),
        });

        const data = await res.json().catch(() => ({}));
        if (!res.ok || !data.ok) {
            throw new Error(data.error || `HTTP ${res.status}`);
        }
        return data;
    }

    async function blockSelected() {
        if (!state.selected) return;
        try {
            const result = await postDomain('/dns/api/block/', state.selected.domain);
            showToast(result?.added?.length ? 'Domínio bloqueado' : 'Regra já existente');
            closeDetail();
        } catch (err) {
            showToast(`Falha ao bloquear: ${err.message}`, 'error');
        }
    }

    async function allowSelected() {
        if (!state.selected) return;
        try {
            const result = await postDomain('/dns/api/allow/', state.selected.domain);
            showToast(result?.added?.length ? 'Whitelist adicionada' : 'Regra já existente');
            closeDetail();
        } catch (err) {
            showToast(`Falha na whitelist: ${err.message}`, 'error');
        }
    }

    async function copyText(text) {
        try {
            await navigator.clipboard.writeText(String(text || ''));
            showToast('Domínio copiado');
        } catch {
            const ta = document.createElement('textarea');
            ta.value = String(text || '');
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            ta.remove();
            showToast('Domínio copiado');
        }
    }

    function showToast(message, type = 'ok') {
        const t = $('feedToast');
        if (!t) return;
        t.textContent = message;
        t.dataset.type = type;
        t.classList.add('show');
        clearTimeout(toastTimer);
        toastTimer = setTimeout(() => t.classList.remove('show'), 2800);
    }

    function clearLocalFeed() {
        state.all = [];
        state.seen.clear();
        state.rpmBucket = [];
        miniBuckets.fill(0);
        drawMiniChart();
        renderKPIs();
        renderAll();
        showToast('Feed local limpo');
    }

    function exportCsv() {
        const entries = state.all.filter(matchesFilter);
        if (!entries.length) {
            showToast('Nenhuma entrada para exportar');
            return;
        }

        const headers = [
            'Data/Hora',
            'IP',
            'Dominio',
            'Tipo',
            'Status',
            'Latencia_ms',
            'Origem',
            'Upstream',
            'Motivo',
            'Filtro',
        ];

        const rows = entries.map((e) => [
            e.time || e.time_fmt,
            e.ip,
            e.domain,
            e.type,
            e.blocked ? 'BLOCK' : 'ALLOW',
            e.elapsed_ms ?? '',
            e.blocked ? 'policy' : e.cached ? 'cache' : 'upstream',
            e.upstream || '',
            e.reason || '',
            e.filter || '',
        ].map((v) => `"${String(v ?? '').replace(/"/g, '""')}"`).join(','));

        const blob = new Blob(
            ['\uFEFF' + [headers.join(','), ...rows].join('\n')],
            { type: 'text/csv;charset=utf-8;' }
        );

        const a = document.createElement('a');
        const href = URL.createObjectURL(blob);
        a.href = href;
        a.download = `moonshield-dns-feed-${new Date().toISOString().slice(0, 10)}.csv`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(href);

        showToast(`${entries.length} entradas exportadas`);
    }

    function applyUrlFilter() {
        const params = new URLSearchParams(window.location.search);
        const ip = params.get('ip');
        if (!ip) return;

        state.search = ip.trim();
        const input = $('feedSearch');
        if (input) input.value = state.search;
        $('feedSearchClear')?.classList.add('visible');
    }

    function bindEvents() {
        applyUrlFilter();

        $('feedSearch')?.addEventListener('input', (ev) => {
            state.search = ev.target.value.trim();
            $('feedSearchClear')?.classList.toggle('visible', Boolean(state.search));
            renderAll();
        });

        $('feedSearchClear')?.addEventListener('click', () => {
            const input = $('feedSearch');
            if (input) input.value = '';
            state.search = '';
            $('feedSearchClear')?.classList.remove('visible');

            const params = new URLSearchParams(window.location.search);
            if (params.has('ip')) {
                params.delete('ip');
                const suffix = params.toString() ? `?${params}` : '';
                window.history.replaceState({}, document.title, `${window.location.pathname}${suffix}`);
            }
            renderAll();
        });

        document.querySelectorAll('.feed-chip').forEach((chip) => {
            chip.addEventListener('click', () => {
                document.querySelectorAll('.feed-chip').forEach((c) => c.classList.remove('feed-chip--active'));
                chip.classList.add('feed-chip--active');
                state.typeFilter = chip.dataset.type || 'all';
                renderAll();
            });
        });

        $('feedQtypeFilter')?.addEventListener('change', (ev) => {
            state.qtypeFilter = ev.target.value;
            renderAll();
        });

        $('feedCacheFilter')?.addEventListener('change', (ev) => {
            state.cacheFilter = ev.target.value;
            renderAll();
        });

        $('feedPauseBtn')?.addEventListener('click', () => {
            state.paused = !state.paused;

            if ($('feedPauseLbl')) $('feedPauseLbl').textContent = state.paused ? 'Retomar' : 'Pausar';
            if ($('feedPauseIcon')) {
                $('feedPauseIcon').innerHTML = state.paused
                    ? '<polygon points="5 3 19 12 5 21 5 3"/>'
                    : '<rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/>';
            }

            setLiveState(state.paused ? 'paused' : state.lastPollOk ? 'ok' : 'error');

            if (!state.paused) renderAll();
        });

        $('feedClearBtn')?.addEventListener('click', clearLocalFeed);
        $('feedExportBtn')?.addEventListener('click', exportCsv);

        $('feedAutoScroll')?.addEventListener('change', (ev) => {
            state.autoScroll = Boolean(ev.target.checked);
        });

        $('feedRetryBtn')?.addEventListener('click', poll);

        $('feedDetailClose')?.addEventListener('click', closeDetail);
        $('feedDetailOverlay')?.addEventListener('click', closeDetail);

        $('fdCopyDomain')?.addEventListener('click', () => {
            if (state.selected) copyText(state.selected.domain);
        });
        $('fdBlockDomain')?.addEventListener('click', blockSelected);
        $('fdAllowDomain')?.addEventListener('click', allowSelected);

        document.addEventListener('keydown', (ev) => {
            if (ev.key === 'Escape') closeDetail();
        });

        window.addEventListener('resize', drawMiniChart);

        document.addEventListener('visibilitychange', () => {
            if (!document.hidden) poll();
        });
    }

    bindEvents();
    renderKPIs();
    drawMiniChart();
    poll();

    setInterval(poll, POLL_MS);
    setInterval(() => {
        renderKPIs();
        advanceMiniBuckets(0);
    }, MINI_INTERVAL);
});
