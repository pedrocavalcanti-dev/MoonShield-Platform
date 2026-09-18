(function () {
    'use strict';

    // URL real gerada pelo Django em mapa.html via {% url %}
    const _tmCfgEl = document.getElementById('tm-config-data');
    const _tmCfg = _tmCfgEl ? JSON.parse(_tmCfgEl.textContent) : {};
    const LOCATION_ENDPOINT = _tmCfg.setLocationUrl || '/mapa/api/location/';

    // State
    const STATE = {
        filters: { period: '24h', sev: 'all', source: 'all', category: '', country: '', query: '' },
        settings: { rotSpeed: 0.05, trailDuration: 15000, maxEvents: 200 },
        seenIds: new Set(),
        feedQueue: [], // stores event ids currently in the feed
        isPaused: false,
        selectedEventId: null,
        lastFetch: 0,
        lastFetchOk: 0,
        pollingTimer: null,
        abortController: null,
        eventsCache: new Map(), // ID -> event data
        isGlobe: true,
        panelsHidden: false,
        cinemaMode: false,
        pendingBrowserLocation: null
    };

    // Constants
    const MAX_FEED_ITEMS = 80;
    const MAX_SEEN_IDS = 1000;
    const POLL_INTERVAL = 5000;
    const STALE_AFTER_MS = 30000;
    const SEV_ORDER = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

    const SOURCE_LABELS = {
        ids: 'IDS / Suricata',
        firewall: 'Firewall',
        dns: 'DNS / AdGuard'
    };

    const DIR_LABELS = {
        'inbound': 'ENTRADA',
        'outbound': 'SAÍDA',
        'internal': 'INTERNO',
        'unknown': 'INDEFINIDO'
    };

    // ---------------------------------------------------------------
    // UI Elements
    // ---------------------------------------------------------------
    const els = {
        mapContainer: document.getElementById('map'),
        feedContainer: document.getElementById('feed-container'),
        feedEmptyState: document.getElementById('feed-empty-state'),
        feedCount: document.getElementById('feed-count'),
        detailsPanel: document.getElementById('details-panel'),
        facetsContainer: document.getElementById('facets-container'),

        kpiEvents: document.getElementById('kpi-events'),
        kpiRate: document.getElementById('kpi-rate'),
        kpiCritical: document.getElementById('kpi-critical'),
        kpiGeo: document.getElementById('kpi-geo'),
        kpiTopCountry: document.getElementById('kpi-top-country'),

        filterPeriod: document.getElementById('filter-period'),
        filterSev: document.getElementById('filter-sev'),
        filterSource: document.getElementById('filter-source'),
        searchInput: document.getElementById('search-input'),

        btnPause: document.getElementById('btn-pause'),
        btnClear: document.getElementById('btn-clear'),
        btnSettings: document.getElementById('btn-settings'),
        settingsPopover: document.getElementById('settings-popover'),
        settingMaxEvents: document.getElementById('setting-max-events'),
        settingTrail: document.getElementById('setting-trail'),
        settingRot: document.getElementById('setting-rot'),

        btnProjection: document.getElementById('btn-projection'),
        projectionTag: document.getElementById('projection-tag'),
        btnTogglePanels: document.getElementById('btn-toggle-panels'),
        btnCinema: document.getElementById('btn-cinema'),
        btnExitCinema: document.getElementById('btn-exit-cinema'),

        mainGrid: document.getElementById('main-grid'),
        tmApp: document.getElementById('tm-app'),

        healthIds: document.getElementById('health-ids'),
        healthFw: document.getElementById('health-firewall'),
        healthDns: document.getElementById('health-dns'),

        noLocationWarning: document.getElementById('no-location-warning'),
        btnOpenLocationModal: document.getElementById('btn-open-location-modal'),

        bannerError: document.getElementById('banner-error'),
        bannerStale: document.getElementById('banner-stale'),

        activeFiltersBar: document.getElementById('active-filters-bar'),

        // Location modal
        locationModal: document.getElementById('location-modal'),
        btnCloseLocation: document.getElementById('btn-close-location'),
        btnCancelLocation: document.getElementById('btn-cancel-location'),
        btnSaveLocation: document.getElementById('btn-save-location'),
        btnUseBrowser: document.getElementById('btn-use-browser'),
        browserUnavailableMsg: document.getElementById('browser-unavailable-msg'),
        browserConfirmBox: document.getElementById('browser-confirm-box'),
        browserConfirmLat: document.getElementById('browser-confirm-lat'),
        browserConfirmLon: document.getElementById('browser-confirm-lon'),
        btnConfirmBrowserLocation: document.getElementById('btn-confirm-browser-location'),
        locLat: document.getElementById('loc-lat'),
        locLon: document.getElementById('loc-lon'),
        locError: document.getElementById('loc-error')
    };

    // ---------------------------------------------------------------
    // Utils
    // ---------------------------------------------------------------
    const escapeHTML = (str) => {
        if (str == null) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    };

    const debounce = (func, wait) => {
        let timeout;
        return function (...args) {
            clearTimeout(timeout);
            timeout = setTimeout(() => func.apply(this, args), wait);
        };
    };

    // Robust timestamp formatter.
    // Supports: ISO datetime, unix seconds, unix milliseconds,
    // numeric strings, and float unix-seconds strings.
    // Never returns "Invalid Date" and never falls back to "now".
    function parseTimestampToDate(value) {
        if (value === null || value === undefined || value === '') return null;

        let ms = null;

        if (typeof value === 'number' && !isNaN(value)) {
            ms = Math.abs(value) < 1e12 ? value * 1000 : value;
        } else if (typeof value === 'string') {
            const trimmed = value.trim();
            if (trimmed === '') return null;
            if (/^-?\d+(\.\d+)?$/.test(trimmed)) {
                const num = parseFloat(trimmed);
                ms = Math.abs(num) < 1e12 ? num * 1000 : num;
            } else {
                const parsed = Date.parse(trimmed);
                ms = isNaN(parsed) ? null : parsed;
            }
        }

        if (ms == null || isNaN(ms)) return null;
        const d = new Date(ms);
        return isNaN(d.getTime()) ? null : d;
    }

    function formatTimestamp(value, mode) {
        const d = parseTimestampToDate(value);
        if (!d) return '—';
        if (mode === 'full') {
            return d.toLocaleString('pt-BR');
        }
        return d.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }

    function getCookie(name) {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.substring(0, name.length + 1) === (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }

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
                closeBtn.textContent = '×';
                closeBtn.setAttribute('aria-label', 'Remover filtro');
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

    // ---------------------------------------------------------------
    // Polling & Data Fetch
    // ---------------------------------------------------------------
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
                STATE.lastFetchOk = Date.now();
                setErrorBanner(false);
                setStaleBanner(false);
            } else {
                setErrorBanner(false); // API 200 but ok:false — do not show a hard error banner
            }
        } catch (e) {
            if (e.name !== 'AbortError') {
                console.error('Fetch API falhou', e);
                if (Date.now() - STATE.lastFetchOk > STALE_AFTER_MS && !STATE.isPaused) {
                    setStaleBanner(true);
                }
            }
        } finally {
            STATE.abortController = null;
            if (!STATE.isPaused) {
                STATE.pollingTimer = setTimeout(fetchData, POLL_INTERVAL);
            }
        }
    }

    function setErrorBanner(show) {
        if (els.bannerError) els.bannerError.style.display = show ? 'block' : 'none';
    }
    function setStaleBanner(show) {
        if (els.bannerStale) els.bannerStale.style.display = show ? 'block' : 'none';
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

        const node = data.node || {};
        const nodeHasCoords = node.latitude != null && node.longitude != null;

        if (window.MoonShieldThreatMapRenderer) {
            window.MoonShieldThreatMapRenderer.setNode(node);
        }
        if (els.noLocationWarning) {
            els.noLocationWarning.classList.toggle('visible', !nodeHasCoords);
        }

        const newEvents = [];
        const renderEvents = [];

        (data.events || []).forEach(ev => {
            STATE.eventsCache.set(ev.id, ev);

            if (!STATE.seenIds.has(ev.id)) {
                newEvents.push(ev);
                STATE.seenIds.add(ev.id);
            }

            // Map rendering / geo-KPI eligibility:
            // geolocatable === true, direction inbound/outbound,
            // valid external_geo coords, valid node coords.
            const hasValidExternalGeo = ev.geolocatable === true
                && (ev.direction === 'inbound' || ev.direction === 'outbound')
                && ev.external_geo
                && ev.external_geo.latitude != null
                && ev.external_geo.longitude != null;

            if (hasValidExternalGeo && nodeHasCoords) {
                let src_lat, src_lon, dest_lat, dest_lon;
                if (ev.direction === 'inbound') {
                    src_lat = ev.external_geo.latitude;
                    src_lon = ev.external_geo.longitude;
                    dest_lat = node.latitude;
                    dest_lon = node.longitude;
                } else {
                    src_lat = node.latitude;
                    src_lon = node.longitude;
                    dest_lat = ev.external_geo.latitude;
                    dest_lon = ev.external_geo.longitude;
                }

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
        });

        // FIFO for seenIds
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

        updateKPIs(data.kpis, data.total, renderEvents.length);
        updateHealth(data.source_health);
        updateFacets(data.facets);
        updateActiveFiltersUI();

        if (newEvents.length > 0) {
            appendFeed(newEvents);
        }
        updateFeedEmptyState();
    }

    // ---------------------------------------------------------------
    // KPIs
    // ---------------------------------------------------------------
    function updateKPIs(kpis, total, geoCount) {
        kpis = kpis || {};

        const eventsVal = (kpis.matched_total != null) ? kpis.matched_total : (total != null ? total : 0);
        if (els.kpiEvents) els.kpiEvents.textContent = String(eventsVal);

        if (els.kpiRate) els.kpiRate.textContent = `${kpis.rate || 0} evt/min`;

        if (els.kpiCritical) els.kpiCritical.textContent = (kpis.critical != null) ? String(kpis.critical) : '0';

        // Geo KPI is computed client-side from actually-routable events.
        // A value of zero is valid and must render as "0", never "--".
        if (els.kpiGeo) els.kpiGeo.textContent = String(geoCount || 0);

        if (els.kpiTopCountry) {
            const tc = kpis.top_country;
            els.kpiTopCountry.textContent = (!tc || tc === '--') ? '—' : tc;
        }
    }

    function updateHealth(health) {
        if (!health) return;
        const setH = (el, status) => {
            if (!el) return;
            const s = status || 'unknown';
            el.className = 'health-indicator ' + s;
            el.title = el.title.split(' — ')[0] + ' — ' + s;
        };
        setH(els.healthIds, health.ids);
        setH(els.healthFw, health.firewall);
        setH(els.healthDns, health.dns);
    }

    // ---------------------------------------------------------------
    // Facets
    // ---------------------------------------------------------------
    function updateFacets(facets) {
        if (!facets || !els.facetsContainer) return;

        let html = '';

        const renderList = (title, items, type, emptyText, labelMap) => {
            let res = `<div class="facet-group"><h4>${title}</h4><ul>`;
            const entries = Object.entries(items || {});
            const sorted = entries.sort((a, b) => b[1] - a[1]).slice(0, 5);

            if (sorted.length === 0) {
                res += `<li><span class="text-muted">${escapeHTML(emptyText)}</span></li>`;
            }

            sorted.forEach(([k, v]) => {
                const label = (labelMap && labelMap[k]) ? labelMap[k] : k;
                res += `<li class="facet-item" data-type="${type}" data-val="${escapeHTML(k)}">
                    <span class="facet-name">${escapeHTML(label)}</span>
                    <span class="facet-count">${v}</span>
                </li>`;
            });
            res += `</ul></div>`;
            return res;
        };

        html += renderList('Categorias', facets.categories, 'category', 'Nenhum dado');
        // countries={} is a valid state (not a failure) when no event is geolocatable
        html += renderList('Países', facets.countries, 'country', 'Nenhum evento geolocalizável');
        html += renderList('Fontes', facets.sources, 'source', 'Nenhum dado', SOURCE_LABELS);

        els.facetsContainer.innerHTML = html;

        els.facetsContainer.querySelectorAll('.facet-item').forEach(el => {
            el.addEventListener('click', () => {
                const type = el.getAttribute('data-type');
                const val = el.getAttribute('data-val');
                if (type === 'source') {
                    if (els.filterSource) els.filterSource.value = val;
                    STATE.filters.source = val;
                } else {
                    STATE.filters[type] = val;
                }
                fetchData();
            });
        });
    }

    // ---------------------------------------------------------------
    // Feed
    // ---------------------------------------------------------------
    function updateFeedEmptyState() {
        const hasItems = STATE.feedQueue.length > 0;
        if (els.feedEmptyState) els.feedEmptyState.style.display = hasItems ? 'none' : 'block';
        if (els.feedCount) {
            const n = STATE.feedQueue.length;
            els.feedCount.textContent = n === 1 ? '1 evento' : `${n} eventos`;
        }
    }

    function appendFeed(events) {
        if (!els.feedContainer) return;

        events = events.slice().sort((a, b) => (SEV_ORDER[b.severity] || 0) - (SEV_ORDER[a.severity] || 0));

        const fragment = document.createDocumentFragment();

        events.forEach(ev => {
            const div = document.createElement('div');
            div.className = `feed-item sev-${ev.severity || 'low'}`;
            div.setAttribute('data-id', ev.id);
            div.setAttribute('tabindex', '0');
            div.setAttribute('role', 'button');

            const timeStr = formatTimestamp(ev.timestamp);
            const sourceLabel = SOURCE_LABELS[ev.source] || (ev.source ? ev.source.toUpperCase() : 'UNK');
            const sevLabel = (ev.severity || 'low').toUpperCase();

            let labelText = ev.signature || ev.action || ev.category || 'Alerta';
            if (labelText.length > 60) labelText = labelText.substring(0, 57) + '...';

            let html = `<div class="feed-item-header">
                <span class="feed-sev sev-text-${ev.severity || 'low'}">${sevLabel}</span>
                <span class="feed-source">${escapeHTML(sourceLabel)}</span>
                <span class="feed-time">${timeStr}</span>
            </div>`;

            if (ev.src_ip || ev.dst_ip || ev.domain) {
                const dest = ev.dst_ip ? escapeHTML(ev.dst_ip) : (ev.domain ? escapeHTML(ev.domain) : '');
                html += `<div class="feed-ips">`;
                if (ev.src_ip) html += `<span>${escapeHTML(ev.src_ip)}</span>`;
                if (ev.src_ip && dest) html += `<span class="feed-arrow">\u2192</span>`;
                if (dest) html += `<span>${dest}</span>`;
                html += `</div>`;
            }

            html += `<div class="feed-title">${escapeHTML(labelText)}</div>`;

            const dirLabel = DIR_LABELS[ev.direction] || DIR_LABELS.unknown;
            const geoLabel = ev.geolocatable === false ? 'SEM GEO' : '';
            html += `<div class="feed-meta"><span>${dirLabel}</span>`;
            if (geoLabel) html += `<span class="dot-sep">\u00b7</span><span>${geoLabel}</span>`;
            if (ev.count > 1) html += `<span class="feed-badge count">\u00d7${ev.count}</span>`;
            html += `</div>`;

            div.innerHTML = html;
            fragment.appendChild(div);

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

        const sev = ev.severity || 'low';
        let html = `<div class="details-header">
            <h3>${escapeHTML(ev.signature || ev.action || 'Detalhes do Evento')}</h3>
            <span class="badge ${sev}">${sev.toUpperCase()}</span>
        </div>
        <div class="details-body">
            <table class="tech-table">
                <tr><td>Source</td><td>${escapeHTML(SOURCE_LABELS[ev.source] || ev.source || '—')}</td></tr>
                <tr><td>Timestamp</td><td class="font-mono">${formatTimestamp(ev.timestamp, 'full')}</td></tr>
                <tr><td>Count</td><td class="font-mono">${ev.count != null ? ev.count : '—'}</td></tr>
                <tr><td>Direction</td><td>${DIR_LABELS[ev.direction] || DIR_LABELS.unknown}${ev.geolocatable === false ? ' · SEM GEO' : ''}</td></tr>
                ${ev.protocol ? `<tr><td>Protocol</td><td class="font-mono">${escapeHTML(ev.protocol)}</td></tr>` : ''}
                ${ev.rule_id ? `<tr><td>Rule ID</td><td class="font-mono">${escapeHTML(ev.rule_id.toString())}</td></tr>` : ''}
                ${ev.category ? `<tr><td>Category</td><td>${escapeHTML(ev.category)}</td></tr>` : ''}
                ${ev.domain ? `<tr><td>Domain</td><td class="font-mono">${escapeHTML(ev.domain)}</td></tr>` : ''}
            </table>

            <h4>Origem</h4>
            <table class="tech-table">
                <tr><td>IP</td><td class="font-mono">${escapeHTML(ev.src_ip || '—')}</td></tr>
                ${ev.src_port ? `<tr><td>Port</td><td class="font-mono">${escapeHTML(ev.src_port.toString())}</td></tr>` : ''}
                ${ev.src_geo ? `<tr><td>Country</td><td>${escapeHTML(ev.src_geo.country_code || '—')}</td></tr>` : ''}
            </table>

            <h4>Destino</h4>
            <table class="tech-table">
                <tr><td>IP</td><td class="font-mono">${escapeHTML(ev.dst_ip || '—')}</td></tr>
                ${ev.dst_port ? `<tr><td>Port</td><td class="font-mono">${escapeHTML(ev.dst_port.toString())}</td></tr>` : ''}
                ${ev.dst_geo ? `<tr><td>Country</td><td>${escapeHTML(ev.dst_geo.country_code || '—')}</td></tr>` : ''}
            </table>
        </div>
        <div class="details-actions">`;

        if (ev.incident_id) {
            html += `<a href="/incidentes/${encodeURIComponent(ev.incident_id)}/" class="btn btn-primary btn-sm" target="_blank" rel="noopener">Ver no SOC</a>`;
        }
        html += `<button class="btn btn-outline btn-sm" id="btn-copy-ioc">Copy IOC</button>`;
        html += `<button class="btn btn-outline btn-sm" id="btn-focus-map">Focar no Mapa</button>`;
        html += `</div>`;

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

        const btnCopy = document.getElementById('btn-copy-ioc');
        if (btnCopy) {
            btnCopy.onclick = () => {
                const ioc = ev.src_ip || ev.dst_ip || ev.domain || '';
                if (ioc && navigator.clipboard) {
                    navigator.clipboard.writeText(ioc).catch(() => {});
                }
            };
        }
    }

    // ---------------------------------------------------------------
    // Location modal / geolocation
    // ---------------------------------------------------------------
    function openLocationModal() {
        if (!els.locationModal) return;
        hideLocError();
        if (els.browserConfirmBox) els.browserConfirmBox.style.display = 'none';
        STATE.pendingBrowserLocation = null;

        const secure = !!(window.isSecureContext && 'geolocation' in navigator);
        if (els.btnUseBrowser) els.btnUseBrowser.disabled = !secure;
        if (els.browserUnavailableMsg) els.browserUnavailableMsg.style.display = secure ? 'none' : 'block';

        els.locationModal.style.display = 'flex';
    }

    function closeLocationModal() {
        if (!els.locationModal) return;
        els.locationModal.style.display = 'none';
        if (els.locLat) els.locLat.value = '';
        if (els.locLon) els.locLon.value = '';
        hideLocError();
        STATE.pendingBrowserLocation = null;
        if (els.browserConfirmBox) els.browserConfirmBox.style.display = 'none';
    }

    function showLocError(msg) {
        if (!els.locError) return;
        els.locError.textContent = msg;
        els.locError.style.display = 'block';
    }
    function hideLocError() {
        if (!els.locError) return;
        els.locError.style.display = 'none';
        els.locError.textContent = '';
    }

    function handleUseBrowserLocation() {
        hideLocError();
        // Geolocation is only ever requested after this explicit click —
        // never automatically on page load.
        if (!window.isSecureContext || !('geolocation' in navigator)) {
            if (els.browserUnavailableMsg) els.browserUnavailableMsg.style.display = 'block';
            return;
        }

        const originalLabel = els.btnUseBrowser.innerHTML;
        els.btnUseBrowser.disabled = true;

        navigator.geolocation.getCurrentPosition(
            (pos) => {
                els.btnUseBrowser.disabled = false;
                els.btnUseBrowser.innerHTML = originalLabel;
                STATE.pendingBrowserLocation = {
                    latitude: pos.coords.latitude,
                    longitude: pos.coords.longitude
                };
                if (els.browserConfirmLat) els.browserConfirmLat.textContent = pos.coords.latitude.toFixed(6);
                if (els.browserConfirmLon) els.browserConfirmLon.textContent = pos.coords.longitude.toFixed(6);
                if (els.browserConfirmBox) els.browserConfirmBox.style.display = 'flex';
            },
            () => {
                els.btnUseBrowser.disabled = false;
                els.btnUseBrowser.innerHTML = originalLabel;
                showLocError('Não foi possível obter a localização do navegador.');
            },
            { enableHighAccuracy: false, timeout: 10000, maximumAge: 0 }
        );
    }

    async function submitLocation(lat, lon, source) {
        source = source || 'manual';
        hideLocError();
        if (typeof lat !== 'number' || typeof lon !== 'number' || isNaN(lat) || isNaN(lon)) {
            showLocError('Coordenadas inválidas.');
            return;
        }
        if (lat < -90 || lat > 90) {
            showLocError('Latitude deve estar entre -90 e 90.');
            return;
        }
        if (lon < -180 || lon > 180) {
            showLocError('Longitude deve estar entre -180 e 180.');
            return;
        }

        const btnSave = els.btnSaveLocation;
        const originalLabel = btnSave ? btnSave.textContent : '';
        if (btnSave) {
            btnSave.disabled = true;
            btnSave.textContent = 'Salvando...';
        }

        try {
            const resp = await fetch(LOCATION_ENDPOINT, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCookie('csrftoken') || '',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify({ latitude: lat, longitude: lon, source: source })
            });

            let respData = {};
            try { respData = await resp.json(); } catch (_) {}

            if (!resp.ok) {
                const errMsg = respData.erro || `Erro ${resp.status} ao salvar.`;
                showLocError(errMsg);
                console.error('submitLocation falhou:', resp.status);
                return;
            }

            closeLocationModal();
            fetchData();
        } catch (e) {
            showLocError('Falha de rede ao salvar a localização. Tente novamente.');
            console.error('submitLocation network error:', e.message);
        } finally {
            if (btnSave) {
                btnSave.disabled = false;
                btnSave.textContent = originalLabel;
            }
        }
    }

    function saveManualLocation() {
        const lat = parseFloat(els.locLat ? els.locLat.value : '');
        const lon = parseFloat(els.locLon ? els.locLon.value : '');
        submitLocation(lat, lon, 'manual');
    }

    function confirmBrowserLocation() {
        if (!STATE.pendingBrowserLocation) return;
        submitLocation(STATE.pendingBrowserLocation.latitude, STATE.pendingBrowserLocation.longitude, 'browser');
    }

    // ---------------------------------------------------------------
    // Toolbar: projection / panels / cinema / settings
    // ---------------------------------------------------------------
    function toggleProjection() {
        STATE.isGlobe = !STATE.isGlobe;
        const mode = STATE.isGlobe ? 'globe' : 'mercator';
        if (window.MoonShieldThreatMapRenderer) window.MoonShieldThreatMapRenderer.setProjection(mode);
        if (els.projectionTag) els.projectionTag.textContent = STATE.isGlobe ? '3D' : '2D';
        if (els.btnProjection) els.btnProjection.classList.toggle('active', !STATE.isGlobe);
    }

    function _triggerResize() {
        // Dispara resize imediatamente (depois do rAF para layout calculado)
        // e novamente após a transição CSS (~300ms) para evitar canvas vazio.
        if (!window.MoonShieldThreatMapRenderer) return;
        requestAnimationFrame(() => {
            requestAnimationFrame(() => {
                window.MoonShieldThreatMapRenderer.resize();
                setTimeout(() => window.MoonShieldThreatMapRenderer.resize(), 320);
            });
        });
    }

    function togglePanels() {
        STATE.panelsHidden = !STATE.panelsHidden;
        if (els.mainGrid) els.mainGrid.classList.toggle('panels-hidden', STATE.panelsHidden);
        if (els.btnTogglePanels) els.btnTogglePanels.classList.toggle('active', STATE.panelsHidden);
        _triggerResize();
    }

    function enterCinemaMode() {
        if (!document.fullscreenElement && els.tmApp.requestFullscreen) {
            els.tmApp.requestFullscreen().catch(() => _fallbackEnterCinema());
        } else {
            _fallbackEnterCinema();
        }
    }

    function _fallbackEnterCinema() {
        STATE.cinemaMode = true;
        els.tmApp.classList.add('cinema-mode');
        if (els.btnCinema) {
            els.btnCinema.classList.add('active');
            els.btnCinema.setAttribute('aria-pressed', 'true');
        }
        if (els.btnExitCinema) els.btnExitCinema.style.display = 'flex';
        _triggerResize();
    }

    function exitCinemaMode() {
        if (document.fullscreenElement && document.exitFullscreen) {
            document.exitFullscreen();
        } else {
            _fallbackExitCinema();
        }
    }

    function _fallbackExitCinema() {
        STATE.cinemaMode = false;
        els.tmApp.classList.remove('cinema-mode');
        if (els.btnCinema) {
            els.btnCinema.classList.remove('active');
            els.btnCinema.setAttribute('aria-pressed', 'false');
        }
        if (els.btnExitCinema) els.btnExitCinema.style.display = 'none';
        _triggerResize();
    }

    function syncFullscreenState() {
        const isFS = !!document.fullscreenElement;
        if (isFS) {
            _fallbackEnterCinema();
        } else {
            _fallbackExitCinema();
        }
    }

    // ---------------------------------------------------------------
    // Persistence
    // ---------------------------------------------------------------
    const PREFS_KEY = 'moonshield.threatmap.preferences';

    function loadPreferences() {
        try {
            const stored = localStorage.getItem(PREFS_KEY);
            if (stored) {
                const prefs = JSON.parse(stored);
                // Validate period
                if (['1h', '24h', '7d', '30d'].includes(prefs.period)) {
                    STATE.filters.period = prefs.period;
                    if (els.filterPeriod) els.filterPeriod.value = prefs.period;
                }
                // Validate sev
                if (['all', 'critical', 'high', 'medium', 'low', 'info'].includes(prefs.sev)) {
                    STATE.filters.sev = prefs.sev;
                    if (els.filterSev) els.filterSev.value = prefs.sev;
                }
                // Validate source
                if (['all', 'ids', 'firewall', 'dns'].includes(prefs.source)) {
                    STATE.filters.source = prefs.source;
                    if (els.filterSource) els.filterSource.value = prefs.source;
                }
                // Settings
                if (prefs.maxEvents) {
                    STATE.settings.maxEvents = parseInt(prefs.maxEvents, 10);
                    if (els.settingMaxEvents) els.settingMaxEvents.value = prefs.maxEvents;
                }
                if (prefs.trailDuration) {
                    STATE.settings.trailDuration = parseInt(prefs.trailDuration, 10);
                    if (els.settingTrail) els.settingTrail.value = prefs.trailDuration;
                }
                if (prefs.rotSpeed !== undefined) {
                    STATE.settings.rotSpeed = parseFloat(prefs.rotSpeed);
                    if (els.settingRot) els.settingRot.value = prefs.rotSpeed;
                }
            }
        } catch (e) {
            console.warn('Failed to load Threat Map preferences:', e);
        }
    }

    function savePreferences() {
        try {
            const prefs = {
                period: STATE.filters.period,
                sev: STATE.filters.sev,
                source: STATE.filters.source,
                maxEvents: STATE.settings.maxEvents,
                trailDuration: STATE.settings.trailDuration,
                rotSpeed: STATE.settings.rotSpeed
            };
            localStorage.setItem(PREFS_KEY, JSON.stringify(prefs));
        } catch (e) {
            console.warn('Failed to save Threat Map preferences:', e);
        }
    }

    // ---------------------------------------------------------------
    // Listeners
    // ---------------------------------------------------------------
    function setupListeners() {
        if (els.filterPeriod) els.filterPeriod.addEventListener('change', (e) => { STATE.filters.period = e.target.value; savePreferences(); fetchData(); });
        if (els.filterSev) els.filterSev.addEventListener('change', (e) => { STATE.filters.sev = e.target.value; savePreferences(); fetchData(); });
        if (els.filterSource) els.filterSource.addEventListener('change', (e) => { STATE.filters.source = e.target.value; savePreferences(); fetchData(); });
        if (els.searchInput) els.searchInput.addEventListener('input', debounce((e) => { STATE.filters.query = e.target.value; fetchData(); }, 300));

        if (els.btnPause) {

            els.btnPause.addEventListener('click', () => {
                STATE.isPaused = !STATE.isPaused;
                els.btnPause.classList.toggle('status-live', !STATE.isPaused);
                els.btnPause.classList.toggle('status-paused', STATE.isPaused);
                els.btnPause.setAttribute('aria-pressed', String(STATE.isPaused));
                const label = els.btnPause.querySelector('.status-label');
                if (label) label.textContent = STATE.isPaused ? 'PAUSADO' : 'LIVE';
                if (window.MoonShieldThreatMapRenderer) window.MoonShieldThreatMapRenderer.setPaused(STATE.isPaused);
                if (!STATE.isPaused) fetchData();
            });
        }

        if (els.btnClear) {
            els.btnClear.addEventListener('click', () => {
                if (els.feedContainer) {
                    els.feedContainer.querySelectorAll('.feed-item').forEach(el => el.remove());
                }
                if (els.detailsPanel) els.detailsPanel.classList.remove('visible');
                STATE.feedQueue = [];
                updateFeedEmptyState();
                if (window.MoonShieldThreatMapRenderer) {
                    window.MoonShieldThreatMapRenderer.clear();
                    window.MoonShieldThreatMapRenderer.resetView();
                }
            });
        }

        if (els.feedContainer) {
            els.feedContainer.addEventListener('click', (e) => {
                const item = e.target.closest('.feed-item');
                if (item) showDetails(item.getAttribute('data-id'));
            });
            els.feedContainer.addEventListener('keydown', (e) => {
                if (e.key !== 'Enter' && e.key !== ' ') return;
                const item = e.target.closest('.feed-item');
                if (item) { e.preventDefault(); showDetails(item.getAttribute('data-id')); }
            });
        }

        // Toolbar
        if (els.btnProjection) els.btnProjection.addEventListener('click', toggleProjection);
        if (els.btnTogglePanels) els.btnTogglePanels.addEventListener('click', togglePanels);
        if (els.btnCinema) els.btnCinema.addEventListener('click', () => {
            if (STATE.cinemaMode) exitCinemaMode();
            else enterCinemaMode();
        });
        if (els.btnExitCinema) els.btnExitCinema.addEventListener('click', exitCinemaMode);

        document.addEventListener('fullscreenchange', syncFullscreenState);

        if (els.btnSettings) {
            els.btnSettings.addEventListener('click', (e) => {
                e.stopPropagation();
                els.settingsPopover.classList.toggle('visible');
            });
        }
        document.addEventListener('click', (e) => {
            if (els.settingsPopover && els.settingsPopover.classList.contains('visible')) {
                if (!els.settingsPopover.contains(e.target) && e.target !== els.btnSettings) {
                    els.settingsPopover.classList.remove('visible');
                }
            }
        });
        if (els.settingMaxEvents) els.settingMaxEvents.addEventListener('change', (e) => {
            STATE.settings.maxEvents = parseInt(e.target.value, 10) || 200;
            savePreferences();
            fetchData();
        });
        if (els.settingTrail) els.settingTrail.addEventListener('change', (e) => {
            STATE.settings.trailDuration = parseInt(e.target.value, 10) || 15000;
            savePreferences();
            if (window.MoonShieldThreatMapRenderer) window.MoonShieldThreatMapRenderer.setTrailDuration(STATE.settings.trailDuration);
        });
        if (els.settingRot) els.settingRot.addEventListener('change', (e) => {
            STATE.settings.rotSpeed = parseFloat(e.target.value) || 0;
            savePreferences();
            if (window.MoonShieldThreatMapRenderer) window.MoonShieldThreatMapRenderer.setRotationSpeed(STATE.settings.rotSpeed);
        });

        // Location modal
        if (els.btnOpenLocationModal) els.btnOpenLocationModal.addEventListener('click', openLocationModal);
        if (els.btnCloseLocation) els.btnCloseLocation.addEventListener('click', closeLocationModal);
        if (els.btnCancelLocation) els.btnCancelLocation.addEventListener('click', closeLocationModal);
        if (els.locationModal) els.locationModal.addEventListener('click', (e) => {
            if (e.target === els.locationModal) closeLocationModal();
        });
        if (els.btnUseBrowser) els.btnUseBrowser.addEventListener('click', handleUseBrowserLocation);
        if (els.btnConfirmBrowserLocation) els.btnConfirmBrowserLocation.addEventListener('click', confirmBrowserLocation);
        if (els.btnSaveLocation) els.btnSaveLocation.addEventListener('click', saveManualLocation);

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

        // Stale-data watchdog (only when not paused and API hasn't been ok in a while)
        setInterval(() => {
            if (!STATE.isPaused && STATE.lastFetchOk && (Date.now() - STATE.lastFetchOk > STALE_AFTER_MS)) {
                setStaleBanner(true);
            }
        }, 5000);
    }

    function boot() {
        setupListeners();
        updateFeedEmptyState();
        loadPreferences();

        // Iniciar polling independentemente do Mapbox
        fetchData();

        const initialTheme = document.documentElement.getAttribute('data-theme') || 'dark';

        if (window.MoonShieldThreatMapRenderer && els.mapContainer) {
            const tokenEl = document.getElementById('mapbox-token-data');
            let mapboxToken = '';

            try {
                mapboxToken = tokenEl ? JSON.parse(tokenEl.textContent) : '';
            } catch (error) {
                // Silencioso por design
            }

            if (!mapboxToken) {
                const mapFailureEl = document.getElementById('map-failure');
                if (mapFailureEl) mapFailureEl.style.display = 'flex';
                return;
            }

            window.MoonShieldThreatMapRenderer.init({
                containerId: 'map',
                token: mapboxToken,
                theme: initialTheme,
                onReady: () => {
                    // mapbox ready
                },
                onError: () => {
                    const mapFailureEl = document.getElementById('map-failure');
                    if (mapFailureEl) mapFailureEl.style.display = 'flex';
                }
            });
        }
    }

    document.addEventListener('DOMContentLoaded', boot);

})();