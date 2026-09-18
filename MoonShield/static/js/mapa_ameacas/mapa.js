(function () {
    'use strict';

    // State
    const STATE = {
        filters: { period: '24h', sev: 'all', source: 'all', category: '', country: '', query: '' },
        settings: { rotSpeed: 0.05, trailDuration: 15000, maxEvents: 200 },
        seenIds: new Set(),
        feedQueue: [], // stores event ids currently in the feed
        isPaused: false,
        selectedEventId: null,
        lastFetch: 0,
        pollingTimer: null,
        abortController: null,
        eventsCache: new Map() // ID -> event data
    };

    // Constants
    const MAX_FEED_ITEMS = 80;
    const MAX_SEEN_IDS = 1000;
    const POLL_INTERVAL = 5000;
    const SEV_ORDER = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

    // UI Elements
    const els = {
        mapContainer: document.getElementById('map'),
        feedContainer: document.getElementById('feed-container'),
        detailsPanel: document.getElementById('details-panel'),
        facetsContainer: document.getElementById('facets-container'),
        kpiRate: document.getElementById('kpi-rate'),
        kpiMatched: document.getElementById('kpi-matched'),
        kpiActive: document.getElementById('kpi-active'),
        kpiCritical: document.getElementById('kpi-critical'),

        filterPeriod: document.getElementById('filter-period'),
        filterSev: document.getElementById('filter-sev'),
        filterSource: document.getElementById('filter-source'),
        searchInput: document.getElementById('search-input'),

        btnPause: document.getElementById('btn-pause'),
        btnClear: document.getElementById('btn-clear'),
        btnSettings: document.getElementById('btn-settings'),

        healthIds: document.getElementById('health-ids'),
        healthFw: document.getElementById('health-firewall'),
        healthDns: document.getElementById('health-dns'),

        noLocationWarning: document.getElementById('no-location-warning'),

        activeFiltersBar: document.getElementById('active-filters-bar')
    };

    // Utils
    const escapeHTML = (str) => {
        if (str == null) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    };

    const debounce = (func, wait) => {
        let timeout;
        return function(...args) {
            clearTimeout(timeout);
            timeout = setTimeout(() => func.apply(this, args), wait);
        };
    };

    function updateActiveFiltersUI() {
        if (!els.activeFiltersBar) return;
        const active = [];
        if (STATE.filters.category) active.push({ key: 'category', val: STATE.filters.category, label: `Categoria: ${STATE.filters.category}` });
        if (STATE.filters.country) active.push({ key: 'country', val: STATE.filters.country, label: `País: ${STATE.filters.country}` });

        if (active.length > 0) {
            els.activeFiltersBar.style.display = 'flex';
            els.activeFiltersBar.innerHTML = '';
            active.forEach(f => {
                const tag = document.createElement('div');
                tag.className = 'filter-tag';
                const label = document.createElement('span');
                label.textContent = f.label;
                const closeBtn = document.createElement('button');
                closeBtn.innerHTML = '×';
                closeBtn.onclick = () => {
                    STATE.filters[f.key] = '';
                    fetchData();
                };
                tag.appendChild(label);
                tag.appendChild(closeBtn);
                els.activeFiltersBar.appendChild(tag);
            });
        } else {
            els.activeFiltersBar.style.display = 'none';
        }
    }

    // Polling & Data Fetch
    async function fetchData() {
        if (STATE.isPaused) return;

        if (STATE.abortController) {
            STATE.abortController.abort();
        }
        STATE.abortController = new AbortController();

        const params = new URLSearchParams();
        params.append('period', STATE.filters.period);
        params.append('sev', STATE.filters.sev);
        params.append('source', STATE.filters.source);
        if (STATE.filters.category) params.append('category', STATE.filters.category);
        if (STATE.filters.country) params.append('country', STATE.filters.country);
        if (STATE.filters.query) params.append('query', STATE.filters.query);
        params.append('limit', STATE.settings.maxEvents);

        try {
            const response = await fetch(`/mapa/api/overview/?${params.toString()}`, {
                signal: STATE.abortController.signal,
                headers: { 'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest' }
            });
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);

            const data = await response.json();
            if (data.ok) {
                processData(data);
            }
        } catch (e) {
            if (e.name !== 'AbortError') {
                console.error("Fetch API falhou", e);
            }
        } finally {
            STATE.abortController = null;
            if (!STATE.isPaused) {
                STATE.pollingTimer = setTimeout(fetchData, POLL_INTERVAL);
            }
        }
    }

    function processData(data) {
        if (data.config) {
            STATE.settings.trailDuration = data.config.trail_duration || 15000;
            STATE.settings.maxEvents = data.config.max_events || 200;
            STATE.settings.rotSpeed = data.config.rot_speed || 0.05;

            if (window.MoonShieldThreatMapRenderer) {
                window.MoonShieldThreatMapRenderer.setTrailDuration(STATE.settings.trailDuration);
                window.MoonShieldThreatMapRenderer.setRotationSpeed(STATE.settings.rotSpeed);
            }
        }

        if (data.node) {
            if (window.MoonShieldThreatMapRenderer) {
                window.MoonShieldThreatMapRenderer.setNode(data.node);
            }
            if (data.node.latitude == null || data.node.longitude == null) {
                if (els.noLocationWarning) els.noLocationWarning.classList.add('visible');
            } else {
                if (els.noLocationWarning) els.noLocationWarning.classList.remove('visible');
            }
        }

        updateKPIs(data.kpis);
        updateHealth(data.source_health);
        updateFacets(data.facets);
        updateActiveFiltersUI();

        const newEvents = [];
        const renderEvents = [];

        data.events.forEach(ev => {
            STATE.eventsCache.set(ev.id, ev);

            if (!STATE.seenIds.has(ev.id)) {
                newEvents.push(ev);
                STATE.seenIds.add(ev.id);
            }

            // Map rendering eligibility
            if (ev.geolocatable && (ev.direction === 'inbound' || ev.direction === 'outbound') && ev.external_geo && ev.external_geo.latitude != null) {
                let src_lat, src_lon, dest_lat, dest_lon;
                if (ev.direction === 'inbound') {
                    src_lat = ev.external_geo.latitude;
                    src_lon = ev.external_geo.longitude;
                    dest_lat = data.node.latitude;
                    dest_lon = data.node.longitude;
                } else {
                    src_lat = data.node.latitude;
                    src_lon = data.node.longitude;
                    dest_lat = ev.external_geo.latitude;
                    dest_lon = ev.external_geo.longitude;
                }

                if (src_lat != null && dest_lat != null) {
                    renderEvents.push({
                        id: ev.id,
                        severity: ev.severity,
                        count: ev.count,
                        src_lat, src_lon,
                        dest_lat, dest_lon,
                        external_lat: ev.external_geo.latitude,
                        external_lon: ev.external_geo.longitude
                    });
                }
            }
        });

        // FIFO para seenIds
        if (STATE.seenIds.size > MAX_SEEN_IDS) {
            const arr = Array.from(STATE.seenIds);
            const toRemove = arr.slice(0, arr.length - MAX_SEEN_IDS);
            toRemove.forEach(id => {
                STATE.seenIds.delete(id);
                STATE.eventsCache.delete(id);
            });
        }

        if (window.MoonShieldThreatMapRenderer) {
            window.MoonShieldThreatMapRenderer.setEvents(renderEvents);
        }

        if (newEvents.length > 0) {
            appendFeed(newEvents);
        }
    }

    function updateKPIs(kpis) {
        if (!kpis) return;
        if (els.kpiRate) els.kpiRate.textContent = kpis.rate + ' /m';
        if (els.kpiMatched) els.kpiMatched.textContent = kpis.matched_total;
        if (els.kpiActive) els.kpiActive.textContent = kpis.active;
        if (els.kpiCritical) els.kpiCritical.textContent = kpis.critical;
    }

    function updateHealth(health) {
        if (!health) return;
        const setH = (el, status) => {
            if (!el) return;
            el.className = 'health-indicator ' + status;
            el.title = status;
        };
        setH(els.healthIds, health.ids);
        setH(els.healthFw, health.firewall);
        setH(els.healthDns, health.dns);
    }

    function updateFacets(facets) {
        if (!facets || !els.facetsContainer) return;

        let html = '';

        const renderList = (title, items, type) => {
            let res = `<div class="facet-group"><h4>${title}</h4><ul>`;
            const sorted = Object.entries(items).sort((a, b) => b[1] - a[1]).slice(0, 5);
            if (sorted.length === 0) res += `<li><span class="text-muted">Nenhum dado</span></li>`;

            sorted.forEach(([k, v]) => {
                res += `<li class="facet-item" data-type="${type}" data-val="${escapeHTML(k)}">
                    <span class="facet-name">${escapeHTML(k)}</span>
                    <span class="facet-count">${v}</span>
                </li>`;
            });
            res += `</ul></div>`;
            return res;
        };

        html += renderList('Categorias', facets.categories, 'category');
        html += renderList('Países (Origem/Destino)', facets.countries, 'country');
        html += renderList('Fontes', facets.sources, 'source');

        els.facetsContainer.innerHTML = html;

        // Add click listeners
        els.facetsContainer.querySelectorAll('.facet-item').forEach(el => {
            el.addEventListener('click', () => {
                const type = el.getAttribute('data-type');
                const val = el.getAttribute('data-val');
                if (type === 'source') {
                    if(els.filterSource) els.filterSource.value = val;
                    STATE.filters.source = val;
                } else {
                    STATE.filters[type] = val;
                }
                fetchData();
            });
        });
    }

    const DIR_LABELS = {
        'inbound': 'ENTRADA',
        'outbound': 'SAÍDA',
        'internal': 'INTERNO',
        'unknown': 'INDEFINIDO'
    };

    function appendFeed(events) {
        if (!els.feedContainer) return;

        events.sort((a, b) => (SEV_ORDER[a.severity] || 0) - (SEV_ORDER[b.severity] || 0));

        const fragment = document.createDocumentFragment();

        events.forEach(ev => {
            const div = document.createElement('div');
            div.className = `feed-item sev-${ev.severity}`;
            div.setAttribute('data-id', ev.id);

            const timeStr = new Date(ev.timestamp).toLocaleTimeString();
            const sourceUpper = ev.source ? ev.source.toUpperCase() : 'UNK';

            let labelText = ev.signature || ev.action || ev.category || 'Alerta';
            if (labelText.length > 50) labelText = labelText.substring(0, 47) + '...';

            let html = `<div class="feed-item-header">
                <span class="feed-time">${timeStr}</span>
                <span class="feed-source">${sourceUpper}</span>
            </div>
            <div class="feed-title">${escapeHTML(labelText)}</div>
            <div class="feed-meta">`;

            if (ev.src_ip) {
                html += `<span class="feed-ip">${escapeHTML(ev.src_ip)}</span> → `;
            }
            if (ev.dst_ip) {
                html += `<span class="feed-ip">${escapeHTML(ev.dst_ip)}</span>`;
            }

            html += `</div>`;

            if (ev.count > 1) {
                html += `<div class="feed-badge count">×${ev.count}</div>`;
            }

            const dirLabel = DIR_LABELS[ev.direction] || DIR_LABELS.unknown;
            html += `<div class="feed-badge dir">${dirLabel}</div>`;

            div.innerHTML = html;
            fragment.insertBefore(div, fragment.firstChild);

            STATE.feedQueue.unshift(ev.id);
        });

        els.feedContainer.insertBefore(fragment, els.feedContainer.firstChild);

        while (STATE.feedQueue.length > MAX_FEED_ITEMS) {
            const idToRemove = STATE.feedQueue.pop();
            const el = els.feedContainer.querySelector(`[data-id="${idToRemove}"]`);
            if (el) el.remove();
        }
    }

    function showDetails(eventId) {
        if (!els.detailsPanel) return;
        const ev = STATE.eventsCache.get(eventId);
        if (!ev) return;

        STATE.selectedEventId = eventId;
        document.querySelectorAll('.feed-item').forEach(el => el.classList.remove('selected'));
        const fItem = els.feedContainer.querySelector(`[data-id="${eventId}"]`);
        if (fItem) fItem.classList.add('selected');

        let html = `<div class="details-header sev-${ev.severity}">
            <h3>${escapeHTML(ev.signature || ev.action || 'Detalhes do Evento')}</h3>
            <span class="badge ${ev.severity}">${(ev.severity || 'low').toUpperCase()}</span>
        </div>
        <div class="details-body">
            <table class="tech-table">
                <tr><td>Source</td><td>${escapeHTML(ev.source)}</td></tr>
                <tr><td>Timestamp</td><td class="font-mono">${new Date(ev.timestamp).toLocaleString()}</td></tr>
                <tr><td>Count</td><td class="font-mono">${ev.count}</td></tr>
                <tr><td>Direction</td><td>${DIR_LABELS[ev.direction] || DIR_LABELS.unknown}</td></tr>
                ${ev.protocol ? `<tr><td>Protocol</td><td class="font-mono">${escapeHTML(ev.protocol)}</td></tr>` : ''}
                ${ev.rule_id ? `<tr><td>Rule ID</td><td class="font-mono">${escapeHTML(ev.rule_id.toString())}</td></tr>` : ''}
                ${ev.category ? `<tr><td>Category</td><td>${escapeHTML(ev.category)}</td></tr>` : ''}
                ${ev.domain ? `<tr><td>Domain</td><td class="font-mono">${escapeHTML(ev.domain)}</td></tr>` : ''}
            </table>

            <h4>Origem</h4>
            <table class="tech-table">
                <tr><td>IP</td><td class="font-mono">${escapeHTML(ev.src_ip || '--')}</td></tr>
                ${ev.src_port ? `<tr><td>Port</td><td class="font-mono">${escapeHTML(ev.src_port.toString())}</td></tr>` : ''}
                ${ev.src_geo ? `<tr><td>Country</td><td>${escapeHTML(ev.src_geo.country_code || '--')}</td></tr>` : ''}
            </table>

            <h4>Destino</h4>
            <table class="tech-table">
                <tr><td>IP</td><td class="font-mono">${escapeHTML(ev.dst_ip || '--')}</td></tr>
                ${ev.dst_port ? `<tr><td>Port</td><td class="font-mono">${escapeHTML(ev.dst_port.toString())}</td></tr>` : ''}
                ${ev.dst_geo ? `<tr><td>Country</td><td>${escapeHTML(ev.dst_geo.country_code || '--')}</td></tr>` : ''}
            </table>
        </div>
        <div class="details-actions">`;

        if (ev.incident_id) {
            html += `<a href="/incidentes/${ev.incident_id}/" class="btn btn-primary btn-sm" target="_blank">Ver no SOC</a>`;
        }

        html += `<button class="btn btn-outline btn-sm" id="btn-focus-map">Focar no Mapa</button>
        </div>`;

        els.detailsPanel.innerHTML = html;
        els.detailsPanel.classList.add('visible');

        const btnFocus = document.getElementById('btn-focus-map');
        if (btnFocus && window.MoonShieldThreatMapRenderer) {
            btnFocus.onclick = () => {
                if (ev.geolocatable && ev.external_geo && ev.external_geo.latitude != null) {
                    window.MoonShieldThreatMapRenderer.focusEvent({
                        external_lon: ev.external_geo.longitude,
                        external_lat: ev.external_geo.latitude
                    });
                }
            };
        }
    }

    function setupListeners() {
        if (els.filterPeriod) els.filterPeriod.addEventListener('change', (e) => { STATE.filters.period = e.target.value; fetchData(); });
        if (els.filterSev) els.filterSev.addEventListener('change', (e) => { STATE.filters.sev = e.target.value; fetchData(); });
        if (els.filterSource) els.filterSource.addEventListener('change', (e) => { STATE.filters.source = e.target.value; fetchData(); });
        if (els.searchInput) els.searchInput.addEventListener('input', debounce((e) => { STATE.filters.query = e.target.value; fetchData(); }, 300));

        if (els.btnPause) {
            els.btnPause.addEventListener('click', () => {
                STATE.isPaused = !STATE.isPaused;
                els.btnPause.classList.toggle('active', STATE.isPaused);
                els.btnPause.innerHTML = STATE.isPaused ? '▶ Retomar' : '⏸ Pausar';
                if (window.MoonShieldThreatMapRenderer) window.MoonShieldThreatMapRenderer.setPaused(STATE.isPaused);
                if (!STATE.isPaused) fetchData();
            });
        }

        if (els.btnClear) {
            els.btnClear.addEventListener('click', () => {
                if (els.feedContainer) els.feedContainer.innerHTML = '';
                if (els.detailsPanel) els.detailsPanel.classList.remove('visible');
                STATE.feedQueue = [];
                if (window.MoonShieldThreatMapRenderer) window.MoonShieldThreatMapRenderer.clear();
            });
        }

        if (els.feedContainer) {
            els.feedContainer.addEventListener('click', (e) => {
                const item = e.target.closest('.feed-item');
                if (item) {
                    showDetails(item.getAttribute('data-id'));
                }
            });
        }

        // Theme changes observer
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (mutation.attributeName === 'data-theme') {
                    const newTheme = document.documentElement.getAttribute('data-theme') || 'dark';
                    if (window.MoonShieldThreatMapRenderer) {
                        window.MoonShieldThreatMapRenderer.setTheme(newTheme);
                    }
                }
            });
        });
        observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    }

    function boot() {
        setupListeners();

        const initialTheme = document.documentElement.getAttribute('data-theme') || 'dark';

        if (window.MoonShieldThreatMapRenderer && els.mapContainer) {
            const tokenEl = document.getElementById('mapbox-token');
            const token = tokenEl ? tokenEl.textContent.trim() : '';

            window.MoonShieldThreatMapRenderer.init({
                containerId: 'map',
                token: token,
                theme: initialTheme,
                onReady: () => {
                    fetchData();
                }
            });
        } else {
            fetchData();
        }
    }

    document.addEventListener('DOMContentLoaded', boot);

})();