(function () {
    'use strict';

    const cfgEl = document.getElementById('tm-config-data');
    let CONFIG = {};
    try {
        CONFIG = cfgEl ? JSON.parse(cfgEl.textContent || '{}') : {};
    } catch (error) {
        console.error('[ThreatMap] Configuração JSON inválida.', error);
    }

    const ENDPOINTS = {
        overview: CONFIG.overviewUrl || '/mapa/api/overview/',
        feed: CONFIG.feedUrl || '/mapa/api/feed/',
        facets: CONFIG.facetsUrl || '/mapa/api/facets/',
        search: CONFIG.searchUrl || '/mapa/api/search/',
        location: CONFIG.setLocationUrl || '/mapa/api/location/',
        incidents: CONFIG.incidentsUrl || '/incidentes/',
        investigate: CONFIG.investigateIpUrl || '/incidentes/investigar/__IP__/'
    };

    const POLL_INTERVAL = 5000;
    const STALE_AFTER_MS = 30000;
    const FILTERS_STORAGE_KEY = 'moonshield.threatmap.v2.filtersCollapsed';
    const PREFS_STORAGE_KEY = 'moonshield.threatmap.v2.settings';
    const MAX_FEED_DOM = 80;

    const SOURCE_LABELS = {
        ids: 'IDS / Suricata',
        firewall: 'Firewall',
        dns: 'DNS / AdGuard'
    };

    const SEVERITY_LABELS = {
        critical: 'Crítico',
        high: 'Alto',
        medium: 'Médio',
        low: 'Baixo',
        info: 'Info'
    };

    const DIRECTION_LABELS = {
        inbound: 'Entrada',
        outbound: 'Saída',
        internal: 'Interno',
        external: 'Externo',
        unknown: 'Indefinido'
    };

    const ZONE_LABELS = {
        LAN: 'LAN',
        WAN: 'WAN',
        MGMT: 'MGMT',
        DMZ: 'DMZ',
        CUSTOM: 'CUSTOM'
    };

    const state = {
        live: true,
        isGlobe: true,
        panelsHidden: false,
        filtersCollapsed: false,
        mobileFiltersOpen: false,
        mobileEventsOpen: false,
        rightMode: 'events',
        filters: {
            period: '24h',
            sev: 'all',
            source: 'all',
            categories: [],
            countries: [],
            protocol: 'all',
            direction: 'all',
            zone: 'all'
        },
        draft: {
            categories: new Set(),
            countries: new Set()
        },
        settings: {
            maxEvents: 200,
            trailDuration: 15000,
            rotSpeed: 0.05
        },
        overview: null,
        feed: [],
        facets: {
            severities: {},
            sources: {},
            categories: {},
            countries: {},
            protocols: {},
            directions: {},
            zones: {}
        },
        node: null,
        selectedEvent: null,
        searchResult: null,
        pollTimer: null,
        staleTimer: null,
        lastSuccessAt: 0,
        refreshSeq: 0,
        searchController: null,
        toastTimer: null,
        settingsInitialized: false,
        currentPopover: null,
        popoverTrigger: null,
        resizeTimer: null,
        hasLoadedOnce: false
    };

    const $ = (id) => document.getElementById(id);

    const els = {
        app: $('tm-app'),
        mainGrid: $('main-grid'),
        map: $('map'),

        kpiEvents: $('kpi-events'),
        kpiRate: $('kpi-rate'),
        kpiCritical: $('kpi-critical'),
        kpiGeo: $('kpi-geo'),
        kpiTopCountry: $('kpi-top-country'),

        healthIds: $('health-ids'),
        healthFirewall: $('health-firewall'),
        healthDns: $('health-dns'),

        btnPause: $('btn-pause'),
        btnProjection: $('btn-projection'),
        btnTogglePanels: $('btn-toggle-panels'),
        btnCinema: $('btn-cinema'),
        btnClear: $('btn-clear'),
        btnSettings: $('btn-settings'),
        settingsPopover: $('settings-popover'),
        settingMaxEvents: $('setting-max-events'),
        settingTrail: $('setting-trail'),
        settingRot: $('setting-rot'),

        panelFilters: $('panel-filters'),
        btnCollapseFilters: $('btn-collapse-filters'),
        filterPeriod: $('filter-period'),
        filterSev: $('filter-sev'),
        filterSource: $('filter-source'),
        btnCategories: $('btn-categories'),
        categoriesLabel: $('categories-label'),
        categoriesPopover: $('categories-popover'),
        categoriesSearch: $('categories-search'),
        categoriesOptions: $('categories-options'),
        btnCountries: $('btn-countries'),
        countriesLabel: $('countries-label'),
        countriesPopover: $('countries-popover'),
        countriesSearch: $('countries-search'),
        countriesOptions: $('countries-options'),
        btnMoreFilters: $('btn-more-filters'),
        moreFiltersPopover: $('more-filters-popover'),
        filterProtocol: $('filter-protocol'),
        filterDirection: $('filter-direction'),
        filterZone: $('filter-zone'),
        activeFiltersBar: $('active-filters-bar'),
        btnResetFilters: $('btn-reset-filters'),

        panelEvents: $('panel-events'),
        eventsPanel: $('events-panel'),
        detailsPanel: $('details-panel'),
        feedCount: $('feed-count'),
        feedContainer: $('feed-container'),
        feedEmptyState: $('feed-empty-state'),

        searchForm: $('search-form'),
        searchInput: $('search-input'),

        btnMobileFilters: $('btn-mobile-filters'),
        btnMobileEvents: $('btn-mobile-events'),
        drawerBackdrop: $('drawer-backdrop'),

        bannerError: $('banner-error'),
        bannerStale: $('banner-stale'),
        mapFailure: $('map-failure'),
        noLocationWarning: $('no-location-warning'),

        btnOpenLocationModal: $('btn-open-location-modal'),
        locationModal: $('location-modal'),
        btnCloseLocation: $('btn-close-location'),
        btnCancelLocation: $('btn-cancel-location'),
        btnSaveLocation: $('btn-save-location'),
        btnUseBrowser: $('btn-use-browser'),
        browserUnavailableMsg: $('browser-unavailable-msg'),
        browserConfirmBox: $('browser-confirm-box'),
        browserConfirmLat: $('browser-confirm-lat'),
        browserConfirmLon: $('browser-confirm-lon'),
        btnConfirmBrowserLocation: $('btn-confirm-browser-location'),
        locLat: $('loc-lat'),
        locLon: $('loc-lon'),
        locError: $('loc-error'),

        locCep: $('loc-cep'),
        locEndereco: $('loc-endereco'),
        locCidade: $('loc-cidade'),
        locEstado: $('loc-estado'),
        locPais: $('loc-pais'),
        btnSearchAddress: $('btn-search-address'),
        locationConfirmDisplay: $('location-confirm-display'),

        toast: $('tm-toast')
    };

    function createEl(tag, className, text) {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined && text !== null) node.textContent = String(text);
        return node;
    }

    function hasFiniteNumber(value) {
        if (value === null || value === undefined || value === '') return false;
        const num = Number(value);
        return Number.isFinite(num);
    }

    function asNumber(value) {
        return hasFiniteNumber(value) ? Number(value) : null;
    }

    function textOrDash(value) {
        if (value === null || value === undefined || value === '') return '—';
        return String(value);
    }

    function parseTimestamp(value) {
        if (value === null || value === undefined || value === '') return null;

        if (typeof value === 'string') {
            const simpleTime = value.trim();
            if (/^\d{1,2}:\d{2}(:\d{2})?$/.test(simpleTime)) {
                return { simpleTime };
            }
        }

        let millis = null;
        if (typeof value === 'number' && Number.isFinite(value)) {
            millis = Math.abs(value) < 1e12 ? value * 1000 : value;
        } else if (typeof value === 'string') {
            const trimmed = value.trim();
            if (/^-?\d+(\.\d+)?$/.test(trimmed)) {
                const num = Number(trimmed);
                millis = Math.abs(num) < 1e12 ? num * 1000 : num;
            } else {
                const parsed = Date.parse(trimmed);
                if (!Number.isNaN(parsed)) millis = parsed;
            }
        }

        if (millis === null) return null;
        const date = new Date(millis);
        return Number.isNaN(date.getTime()) ? null : { date };
    }

    function formatTimestamp(value, full) {
        const parsed = parseTimestamp(value);
        if (!parsed) return '—';
        if (parsed.simpleTime) return parsed.simpleTime;
        if (full) return parsed.date.toLocaleString('pt-BR');
        return parsed.date.toLocaleTimeString('pt-BR', {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    }

    function getCookie(name) {
        if (!document.cookie) return null;
        const chunks = document.cookie.split(';');
        for (const chunk of chunks) {
            const cookie = chunk.trim();
            if (cookie.startsWith(`${name}=`)) {
                return decodeURIComponent(cookie.slice(name.length + 1));
            }
        }
        return null;
    }

    function normalizeFacet(raw) {
        if (!raw) return {};
        if (!Array.isArray(raw)) return raw;

        const out = {};
        raw.forEach((item) => {
            if (typeof item === 'string') {
                out[item] = 0;
                return;
            }
            if (!item || typeof item !== 'object') return;
            const key = item.value ?? item.code ?? item.name ?? item.label;
            if (key === null || key === undefined || key === '') return;
            out[String(key)] = Number(item.count ?? 0) || 0;
        });
        return out;
    }

    function getRenderer() {
        return window.MoonShieldThreatMapRenderer || null;
    }

    function rendererResize() {
        const renderer = getRenderer();
        if (!renderer || typeof renderer.resize !== 'function') return;

        window.clearTimeout(state.resizeTimer);
        requestAnimationFrame(() => {
            renderer.resize();
            state.resizeTimer = window.setTimeout(() => renderer.resize(), 280);
        });
    }

    function showToast(message, timeout) {
        if (!els.toast) return;
        window.clearTimeout(state.toastTimer);
        els.toast.textContent = message;
        els.toast.hidden = false;
        state.toastTimer = window.setTimeout(() => {
            els.toast.hidden = true;
        }, timeout || 2600);
    }

    function setBanner(el, show) {
        if (!el) return;
        el.hidden = !show;
    }

    function setApiHealthy(ok) {
        if (ok) {
            state.lastSuccessAt = Date.now();
            setBanner(els.bannerError, false);
            setBanner(els.bannerStale, false);
        }
    }

    function updateStaleBanner() {
        if (!state.live || !state.lastSuccessAt) {
            setBanner(els.bannerStale, false);
            return;
        }
        setBanner(els.bannerStale, Date.now() - state.lastSuccessAt > STALE_AFTER_MS);
    }

    function sourceLabel(key) {
        return SOURCE_LABELS[key] || String(key || '').toUpperCase() || '—';
    }

    function severityLabel(key) {
        return SEVERITY_LABELS[key] || textOrDash(key);
    }

    function directionLabel(key) {
        return DIRECTION_LABELS[key] || textOrDash(key);
    }

    function zoneLabel(key) {
        return ZONE_LABELS[key] || textOrDash(key);
    }

    function getExternalGeo(ev) {
        if (!ev || typeof ev !== 'object') return null;

        const ext = ev.external_geo || {};
        const lat = asNumber(ev.latitude ?? ext.latitude);
        const lon = asNumber(ev.longitude ?? ext.longitude);

        if (lat === null || lon === null || lat < -90 || lat > 90 || lon < -180 || lon > 180) {
            return null;
        }

        return {
            latitude: lat,
            longitude: lon,
            country: ev.country ?? ext.country ?? null,
            country_code: ev.country_code ?? ext.country_code ?? null,
            city: ev.city ?? ext.city ?? null,
            asn: ev.asn ?? ext.asn ?? null,
            org: ev.org ?? ext.org ?? null
        };
    }

    function eventHasGeo(ev) {
        if (!ev || typeof ev !== 'object') return false;
        if (ev.has_geo === false || ev.geolocatable === false) return false;
        return !!getExternalGeo(ev);
    }

    function nodeHasGeo(node) {
        if (!node) return false;
        const lat = asNumber(node.latitude);
        const lon = asNumber(node.longitude);
        return lat !== null && lon !== null && lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180;
    }

    function eventLocationLabel(ev) {
        const geo = getExternalGeo(ev);
        if (!geo) return 'Sem GEO';
        const chunks = [];
        if (geo.city) chunks.push(geo.city);
        if (geo.country || geo.country_code) chunks.push(geo.country || geo.country_code);
        return chunks.length ? chunks.join(' · ') : 'Geolocalizado';
    }

    function buildFilterParams(options) {
        const opts = options || {};
        const params = new URLSearchParams();

        params.set('period', state.filters.period || '24h');
        params.set('sev', state.filters.sev || 'all');
        params.set('source', state.filters.source || 'all');

        if (state.filters.protocol !== 'all') params.set('protocol', state.filters.protocol);
        if (state.filters.direction !== 'all') params.set('direction', state.filters.direction);
        if (state.filters.zone !== 'all') params.set('zone', state.filters.zone);

        state.filters.categories.forEach((value) => params.append('category', value));
        state.filters.countries.forEach((value) => params.append('country', value));

        if (opts.limit !== false) {
            params.set('limit', String(state.settings.maxEvents || 200));
        }

        return params;
    }

    function urlWithParams(baseUrl, params) {
        const query = params.toString();
        if (!query) return baseUrl;
        return `${baseUrl}${baseUrl.includes('?') ? '&' : '?'}${query}`;
    }

    async function fetchJson(url, options) {
        const response = await (window.MoonShieldLoading?.fetchCoalesced || fetch)(url, Object.assign({
            credentials: 'same-origin',
            headers: {
                Accept: 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            }
        }, options || {}));

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const contentType = response.headers.get('content-type') || '';
        if (!contentType.includes('application/json')) {
            throw new Error('Resposta não-JSON recebida.');
        }

        return response.json();
    }

    async function fetchOverview(seq) {
        const params = buildFilterParams();
        const data = await fetchJson(urlWithParams(ENDPOINTS.overview, params));
        if (seq !== state.refreshSeq) return null;
        if (!data || data.ok === false) throw new Error('Overview retornou ok=false.');
        applyOverview(data);
        return data;
    }

    async function fetchFeed(seq) {
        const params = buildFilterParams();
        const data = await fetchJson(urlWithParams(ENDPOINTS.feed, params));
        if (seq !== state.refreshSeq) return null;
        if (!data || data.ok === false) throw new Error('Feed retornou ok=false.');
        applyFeed(data);
        return data;
    }

    async function fetchFacets(seq) {
        const params = buildFilterParams({ limit: false });
        const data = await fetchJson(urlWithParams(ENDPOINTS.facets, params));
        if (seq !== state.refreshSeq) return null;
        if (!data || data.ok === false) throw new Error('Facets retornou ok=false.');
        applyFacets(data.facets || data.filter_facets || {});
        return data;
    }

    function getCacheKey() {
        const params = buildFilterParams();
        return `moonshield:mapa:${params.toString()}`;
    }

    async function refreshAll(options) {
        const opts = options || {};
        if (!opts.force && !state.live) return;
        if (!opts.force && window.MoonShieldLoading?.visibility?.isHidden()) {
            schedulePolling();
            return;
        }

        const firstLoad = !state.hasLoadedOnce;
        const cacheKey = getCacheKey();
        let hasSnapshot = false;

        if (firstLoad) {
            const cached = window.MoonShieldLoading?.cache?.get(cacheKey);
            if (cached) {
                if (cached.overview) applyOverview(cached.overview);
                if (cached.feed) applyFeed(cached.feed);
                if (cached.facets) applyFacets(cached.facets);
                state.hasLoadedOnce = true;
                hasSnapshot = true;
            }
        }

        const loadingTargets = [
            [els.app?.querySelector('.tm-v2__summary'), 'card'],
            [els.panelFilters, 'list'],
            [els.eventsPanel, 'table']
        ];

        if (!hasSnapshot) {
            loadingTargets.forEach(([target, variant]) => {
                if (firstLoad) window.MoonShieldLoading?.start(target, { variant });
                else window.MoonShieldLoading?.setRefreshing(target, true);
            });
        } else {
            loadingTargets.forEach(([target]) => {
                window.MoonShieldLoading?.setRefreshing(target, true);
            });
        }

        const seq = ++state.refreshSeq;
        const tasks = [
            fetchOverview(seq),
            fetchFeed(seq),
            fetchFacets(seq)
        ];

        const results = await Promise.allSettled(tasks);
        if (seq !== state.refreshSeq) return;

        const successCount = results.filter((item) => item.status === 'fulfilled').length;
        if (successCount > 0) setApiHealthy(true);

        if (successCount === 0 && !hasSnapshot) {
            setBanner(els.bannerError, true);
            loadingTargets.forEach(([target]) => window.MoonShieldLoading?.error(target, { message: 'Falha ao atualizar dados do mapa.' }));
        }

        const cachedData = {};
        results.forEach((item, i) => {
            if (item.status === 'rejected') {
                console.warn('[ThreatMap] Falha parcial de atualização:', item.reason);
            } else if (item.status === 'fulfilled' && item.value) {
                if (i === 0) cachedData.overview = item.value;
                if (i === 1) cachedData.feed = item.value;
                if (i === 2) cachedData.facets = item.value;
            }
        });

        if (successCount > 0) {
            window.MoonShieldLoading?.cache?.set(cacheKey, cachedData);
        }

        state.hasLoadedOnce = true;
        loadingTargets.forEach(([target]) => {
            if (firstLoad && !hasSnapshot) window.MoonShieldLoading?.finish(target);
            else window.MoonShieldLoading?.setRefreshing(target, false);
        });
        schedulePolling();
    }

    function schedulePolling() {
        window.clearTimeout(state.pollTimer);
        if (!state.live) return;
        state.pollTimer = window.setTimeout(() => {
            refreshAll().catch((error) => {
                console.error('[ThreatMap] Polling falhou.', error);
            });
        }, POLL_INTERVAL);
    }

    function applyOverview(data) {
        state.overview = data;
        state.node = data.node || state.node;

        const kpis = data.kpis || {};
        if (els.kpiEvents) {
            const total = kpis.events ?? kpis.matched_total ?? data.total ?? 0;
            els.kpiEvents.textContent = String(total);
        }
        if (els.kpiRate) {
            const rate = Number(kpis.rate ?? 0);
            els.kpiRate.textContent = `${Number.isFinite(rate) ? rate : 0} evt/min`;
        }
        if (els.kpiCritical) els.kpiCritical.textContent = String(kpis.critical ?? 0);
        if (els.kpiGeo) els.kpiGeo.textContent = String(kpis.geo_on_map ?? 0);
        if (els.kpiTopCountry) {
            const top = kpis.top_country;
            if (!top) {
                els.kpiTopCountry.textContent = '—';
            } else if (typeof top === 'object') {
                els.kpiTopCountry.textContent = textOrDash(top.name ?? top.country ?? top.code);
            } else {
                els.kpiTopCountry.textContent = String(top);
            }
        }

        updateHealth(data.source_health || {});

        if (data.config && !state.settingsInitialized) {
            const cfg = data.config;
            if (Number.isFinite(Number(cfg.max_events))) state.settings.maxEvents = Number(cfg.max_events);
            if (Number.isFinite(Number(cfg.trail_duration))) state.settings.trailDuration = Number(cfg.trail_duration);
            if (Number.isFinite(Number(cfg.rot_speed))) state.settings.rotSpeed = Number(cfg.rot_speed);
            loadLocalSettings();
            state.settingsInitialized = true;
            syncSettingsControls();
            applyRendererSettings();
        }

        const renderer = getRenderer();
        if (renderer && state.node) renderer.setNode(state.node);

        if (els.noLocationWarning) {
            els.noLocationWarning.classList.toggle('visible', !nodeHasGeo(state.node));
        }
    }

    function updateHealth(health) {
        updateHealthOne(els.healthIds, health.ids);
        updateHealthOne(els.healthFirewall, health.firewall);
        updateHealthOne(els.healthDns, health.dns);
    }

    function updateHealthOne(el, status) {
        if (!el) return;
        const normalized = ['online', 'degraded', 'offline'].includes(status) ? status : 'unknown';
        el.classList.remove('online', 'degraded', 'offline', 'unknown');
        el.classList.add(normalized);
        const base = el.id === 'health-ids' ? 'IDS / Suricata' : el.id === 'health-firewall' ? 'Firewall' : 'DNS / AdGuard';
        el.title = `${base} — ${normalized}`;
    }

    function getSeverityRank(sev) {
        const map = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
        return map[sev] || 0;
    }

    function buildGeoGroups(feed) {
        const groups = new Map();
        
        feed.forEach(ev => {
            const externalIp = ev.external_ip || ev.src_ip;
            const source = ev.source || 'unknown';
            const groupKey = `${source}|${externalIp}`;
            
            if (!groups.has(groupKey)) {
                groups.set(groupKey, {
                    groupKey: groupKey,
                    external_ip: externalIp,
                    source: source,
                    geo: getExternalGeo(ev),
                    latestTimestamp: ev.timestamp || ev.ts,
                    latestEvent: ev,
                    eventCount: 0,
                    totalOccurrences: 0,
                    signatures: new Set(),
                    highestSeverity: ev.severity || 'low',
                    direction: ev.direction,
                    _sevRank: getSeverityRank(ev.severity)
                });
            }
            
            const g = groups.get(groupKey);
            g.eventCount++;
            g.totalOccurrences += Number(ev.count || 1);
            if (ev.signature || ev.name || ev.title) g.signatures.add(ev.signature || ev.name || ev.title);
            
            const rank = getSeverityRank(ev.severity);
            if (rank > g._sevRank) {
                g._sevRank = rank;
                g.highestSeverity = ev.severity;
            }
            if (new Date(ev.timestamp || ev.ts) > new Date(g.latestTimestamp)) {
                g.latestTimestamp = ev.timestamp || ev.ts;
                g.latestEvent = ev;
            }
        });
        
        return Array.from(groups.values()).map(g => {
            return {
                ...g.latestEvent,
                groupKey: g.groupKey,
                isGroup: true,
                eventCount: g.eventCount,
                totalOccurrences: g.totalOccurrences,
                severity: g.highestSeverity,
                signaturesArray: Array.from(g.signatures),
                latestTimestamp: g.latestTimestamp
            };
        });
    }

    function applyFeed(data) {
        const rawEvents = Array.isArray(data.events) ? data.events : [];
        state.feed = rawEvents.filter(eventHasGeo).slice(0, MAX_FEED_DOM);
        state.feedGroups = buildGeoGroups(state.feed);

        renderFeed();
        updateRendererEvents();

        if (data.source_health) updateHealth(data.source_health);
    }

    function updateRendererEvents() {
        const renderer = getRenderer();
        if (!renderer) return;

        if (!nodeHasGeo(state.node)) {
            renderer.setEvents([]);
            return;
        }

        const nodeLat = Number(state.node.latitude);
        const nodeLon = Number(state.node.longitude);
        const renderEvents = [];

        (state.feedGroups || []).forEach((ev) => {
            const geo = getExternalGeo(ev);
            if (!geo) return;

            if (ev.direction === 'inbound') {
                renderEvents.push({
                    id: String(ev.id || ev.groupKey),
                    groupKey: ev.groupKey,
                    latestTimestamp: ev.latestTimestamp,
                    severity: ev.severity || 'low',
                    count: Number(ev.totalOccurrences || 1),
                    src_lat: geo.latitude,
                    src_lon: geo.longitude,
                    dest_lat: nodeLat,
                    dest_lon: nodeLon,
                    external_lat: geo.latitude,
                    external_lon: geo.longitude
                });
            } else if (ev.direction === 'outbound') {
                renderEvents.push({
                    id: String(ev.id || ev.groupKey),
                    groupKey: ev.groupKey,
                    latestTimestamp: ev.latestTimestamp,
                    severity: ev.severity || 'low',
                    count: Number(ev.totalOccurrences || 1),
                    src_lat: nodeLat,
                    src_lon: nodeLon,
                    dest_lat: geo.latitude,
                    dest_lon: geo.longitude,
                    external_lat: geo.latitude,
                    external_lon: geo.longitude
                });
            }
        });

        renderer.setEvents(renderEvents);
    }

    function renderFeed() {
        if (!els.feedContainer || !els.feedEmptyState || !els.feedCount) return;

        const groups = state.feedGroups || [];
        els.feedContainer.replaceChildren();
        els.feedCount.textContent = `${groups.length} ${groups.length === 1 ? 'origem' : 'origens'}`;

        if (!groups.length) {
            els.feedEmptyState.hidden = false;
            return;
        }

        els.feedEmptyState.hidden = true;
        const fragment = document.createDocumentFragment();

        groups.forEach((ev) => {
            const card = createEl('button', `tm-v2__event-card sev-${ev.severity || 'low'}`);
            card.type = 'button';
            card.dataset.eventId = String(ev.id || ev.groupKey || '');

            const head = createEl('div', 'tm-v2__event-head');
            const sev = createEl('span', `tm-v2__event-sev sev-${ev.severity || 'low'}`, severityLabel(ev.severity));
            const src = createEl('span', '', sourceLabel(ev.source));
            const time = createEl('time', '', formatTimestamp(ev.ts || ev.timestamp || ev.latestTimestamp));
            head.append(sev, src, time);

            const route = createEl('div', 'tm-v2__event-ip');
            const from = ev.external_ip || ev.src_ip || ev.domain || '—';
            const to = ev.dst_ip || (state.node && state.node.name) || 'MoonShield';
            route.textContent = `${from} → ${to}`;

            const titleText = ev.signature || ev.action || ev.category || 'Evento de segurança';
            const title = createEl('div', 'tm-v2__event-title', titleText);
            
            const locationText = eventLocationLabel(ev);
            let locString = locationText;
            if (ev.isGroup && ev.eventCount > 0) {
                locString += `\n${ev.eventCount} ${ev.eventCount === 1 ? 'evento' : 'eventos'} · ${ev.totalOccurrences} ${ev.totalOccurrences === 1 ? 'ocorrência' : 'ocorrências'}`;
            }
            const location = createEl('div', 'tm-v2__event-location');
            location.style.whiteSpace = 'pre-line';
            location.textContent = locString;

            card.append(head, route, title, location);
            card.addEventListener('click', () => {
                openContext(ev, { source: 'event' });
                const renderer = getRenderer();
                if (renderer) renderer.focusEvent({ external_lon: getExternalGeo(ev)?.longitude, external_lat: getExternalGeo(ev)?.latitude });
            });
            fragment.appendChild(card);
        });

        els.feedContainer.appendChild(fragment);
    }

    function applyFacets(facets) {
        state.facets = {
            severities: normalizeFacet(facets.severities),
            sources: normalizeFacet(facets.sources),
            categories: normalizeFacet(facets.categories),
            countries: normalizeFacet(facets.countries),
            protocols: normalizeFacet(facets.protocols),
            directions: normalizeFacet(facets.directions),
            zones: normalizeFacet(facets.zones)
        };

        populateSourceSelect();
        populateAdvancedSelects();
        renderMultiOptions('categories');
        renderMultiOptions('countries');
        updateMultiLabels();
    }

    function populateSelect(select, facet, allLabel, labelFn) {
        if (!select) return;
        const current = select.value;
        select.replaceChildren();

        const allOpt = createEl('option', '', allLabel);
        allOpt.value = 'all';
        select.appendChild(allOpt);

        Object.entries(facet || {})
            .sort((a, b) => Number(b[1]) - Number(a[1]) || String(a[0]).localeCompare(String(b[0])))
            .forEach(([key, count]) => {
                const option = createEl('option');
                option.value = key;
                const label = labelFn ? labelFn(key) : key;
                option.textContent = `${label}${Number(count) ? ` · ${count}` : ''}`;
                select.appendChild(option);
            });

        const exists = Array.from(select.options).some((option) => option.value === current);
        select.value = exists ? current : 'all';
    }

    function populateSourceSelect() {
        const desired = state.filters.source;
        populateSelect(els.filterSource, state.facets.sources, 'Todas as fontes', sourceLabel);
        const exists = Array.from(els.filterSource?.options || []).some((option) => option.value === desired);
        if (els.filterSource) els.filterSource.value = exists ? desired : 'all';
        if (!exists && desired !== 'all') state.filters.source = 'all';
    }

    function populateAdvancedSelects() {
        populateSelect(els.filterProtocol, state.facets.protocols, 'Todos', (v) => String(v).toUpperCase());
        populateSelect(els.filterDirection, state.facets.directions, 'Todas', directionLabel);
        populateSelect(els.filterZone, state.facets.zones, 'Todas', zoneLabel);

        restoreSelectValue(els.filterProtocol, state.filters.protocol, 'protocol');
        restoreSelectValue(els.filterDirection, state.filters.direction, 'direction');
        restoreSelectValue(els.filterZone, state.filters.zone, 'zone');
    }

    function restoreSelectValue(select, desired, filterKey) {
        if (!select) return;
        const exists = Array.from(select.options).some((option) => option.value === desired);
        if (exists) {
            select.value = desired;
        } else {
            select.value = 'all';
            if (desired !== 'all') state.filters[filterKey] = 'all';
        }
    }

    function facetEntries(kind) {
        const facet = state.facets[kind] || {};
        return Object.entries(facet).sort((a, b) => Number(b[1]) - Number(a[1]) || String(a[0]).localeCompare(String(b[0])));
    }

    function renderMultiOptions(kind, searchTerm) {
        const isCategories = kind === 'categories';
        const container = isCategories ? els.categoriesOptions : els.countriesOptions;
        if (!container) return;

        const term = String(searchTerm || '').trim().toLocaleLowerCase('pt-BR');
        const draftSet = state.draft[kind];
        container.replaceChildren();

        const entries = facetEntries(kind).filter(([key]) => String(key).toLocaleLowerCase('pt-BR').includes(term));

        if (!entries.length) {
            const empty = createEl(
                'div',
                'tm-v2__multi-empty',
                isCategories
                    ? 'Nenhuma categoria disponível para este recorte.'
                    : 'Nenhum país disponível neste período.'
            );
            container.appendChild(empty);
            return;
        }

        const fragment = document.createDocumentFragment();
        entries.forEach(([key, count]) => {
            const label = createEl('label', 'tm-v2__multi-option');
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.value = key;
            checkbox.checked = draftSet.has(key);
            checkbox.addEventListener('change', () => {
                if (checkbox.checked) draftSet.add(key);
                else draftSet.delete(key);
            });

            const name = createEl('span', '', key);
            const amount = createEl('small', '', count);
            label.append(checkbox, name, amount);
            fragment.appendChild(label);
        });
        container.appendChild(fragment);
    }

    function updateMultiLabels() {
        if (els.categoriesLabel) {
            els.categoriesLabel.textContent = selectionLabel(state.filters.categories, 'Todas as categorias');
        }
        if (els.countriesLabel) {
            els.countriesLabel.textContent = selectionLabel(state.filters.countries, 'Todos os países');
        }
    }

    function selectionLabel(values, fallback) {
        if (!values.length) return fallback;
        if (values.length === 1) return values[0];
        return `${values.length} selecionados`;
    }

    function syncDraft(kind) {
        state.draft[kind] = new Set(state.filters[kind]);
        if (kind === 'categories') {
            if (els.categoriesSearch) els.categoriesSearch.value = '';
            renderMultiOptions(kind);
        } else {
            if (els.countriesSearch) els.countriesSearch.value = '';
            renderMultiOptions(kind);
        }
    }

    function applyMulti(kind) {
        state.filters[kind] = Array.from(state.draft[kind]);
        updateMultiLabels();
        renderActiveFilters();
        closePopovers();
        refreshAll({ force: true }).catch(console.error);
    }

    function clearMultiDraft(kind) {
        state.draft[kind].clear();
        renderMultiOptions(kind);
    }

    function renderActiveFilters() {
        if (!els.activeFiltersBar) return;
        els.activeFiltersBar.replaceChildren();

        const chips = [];
        if (state.filters.sev !== 'all') chips.push({ kind: 'sev', value: state.filters.sev, label: severityLabel(state.filters.sev) });
        if (state.filters.source !== 'all') chips.push({ kind: 'source', value: state.filters.source, label: sourceLabel(state.filters.source) });
        if (state.filters.protocol !== 'all') chips.push({ kind: 'protocol', value: state.filters.protocol, label: String(state.filters.protocol).toUpperCase() });
        if (state.filters.direction !== 'all') chips.push({ kind: 'direction', value: state.filters.direction, label: directionLabel(state.filters.direction) });
        if (state.filters.zone !== 'all') chips.push({ kind: 'zone', value: state.filters.zone, label: zoneLabel(state.filters.zone) });
        state.filters.categories.forEach((value) => chips.push({ kind: 'categories', value, label: value }));
        state.filters.countries.forEach((value) => chips.push({ kind: 'countries', value, label: value }));

        if (!chips.length) {
            els.activeFiltersBar.appendChild(createEl('span', 'tm-v2__no-filters', 'Nenhum filtro adicional'));
            return;
        }

        chips.forEach((chip) => {
            const wrap = createEl('span', 'tm-v2__chip');
            const label = createEl('span', '', chip.label);
            const remove = createEl('button', '', '×');
            remove.type = 'button';
            remove.setAttribute('aria-label', `Remover filtro ${chip.label}`);
            remove.addEventListener('click', () => removeFilterChip(chip));
            wrap.append(label, remove);
            els.activeFiltersBar.appendChild(wrap);
        });
    }

    function removeFilterChip(chip) {
        if (chip.kind === 'categories' || chip.kind === 'countries') {
            state.filters[chip.kind] = state.filters[chip.kind].filter((value) => value !== chip.value);
            syncDraft(chip.kind);
            updateMultiLabels();
        } else {
            state.filters[chip.kind] = 'all';
            syncFilterControls();
        }
        renderActiveFilters();
        refreshAll({ force: true }).catch(console.error);
    }

    function resetFilters() {
        state.filters = {
            period: '24h',
            sev: 'all',
            source: 'all',
            categories: [],
            countries: [],
            protocol: 'all',
            direction: 'all',
            zone: 'all'
        };
        syncFilterControls();
        syncDraft('categories');
        syncDraft('countries');
        updateMultiLabels();
        renderActiveFilters();
        refreshAll({ force: true }).catch(console.error);
    }

    function syncFilterControls() {
        if (els.filterPeriod) els.filterPeriod.value = state.filters.period;
        if (els.filterSev) els.filterSev.value = state.filters.sev;
        if (els.filterSource) els.filterSource.value = state.filters.source;
        if (els.filterProtocol) els.filterProtocol.value = state.filters.protocol;
        if (els.filterDirection) els.filterDirection.value = state.filters.direction;
        if (els.filterZone) els.filterZone.value = state.filters.zone;
    }

    function openContext(data, options) {
        if (!els.eventsPanel || !els.detailsPanel) return;
        const opts = options || {};
        state.selectedEvent = opts.source === 'event' ? data : null;
        state.searchResult = opts.source === 'search' ? data : null;
        state.rightMode = 'context';

        els.eventsPanel.hidden = true;
        els.detailsPanel.hidden = false;
        renderContext(data, opts);
        ensureMobileEventsVisible();
    }

    function closeContext() {
        const renderer = getRenderer();
        if (renderer) renderer.contextFocused = false;

        state.selectedEvent = null;
        state.searchResult = null;
        state.rightMode = 'events';

        if (els.eventsPanel) els.eventsPanel.hidden = false;
        if (els.detailsPanel) {
            els.detailsPanel.hidden = true;
            els.detailsPanel.replaceChildren();
        }
    }

    function mergedContext(raw) {
        if (!raw || typeof raw !== 'object') return {};
        if (!raw.context || typeof raw.context !== 'object') return raw;
        return Object.assign({}, raw.context, raw);
    }

    function renderContext(raw, options) {
        const renderer = getRenderer();
        if (renderer) renderer.contextFocused = true;

        if (!els.detailsPanel) return;
        const data = mergedContext(raw);
        const opts = options || {};
        els.detailsPanel.replaceChildren();

        const inner = createEl('div', 'tm-v2__context-inner');

        const head = createEl('div', 'tm-v2__context-head');
        const back = createEl('button', 'tm-v2__back-btn', '←');
        back.type = 'button';
        back.setAttribute('aria-label', 'Voltar aos eventos');
        back.addEventListener('click', closeContext);

        const titleWrap = createEl('div');
        titleWrap.append(
            createEl('span', '', opts.source === 'search' ? 'Resultado da busca' : 'Evento selecionado'),
            createEl('h2', '', opts.source === 'search' ? textOrDash(data.value || data.ip || data.src_ip || data.external_ip) : 'Contexto')
        );

        head.append(back, titleWrap);
        if (data.severity) {
            head.appendChild(createEl('span', `tm-v2__severity-pill sev-${data.severity}`, severityLabel(data.severity)));
        }

        const body = createEl('div', 'tm-v2__context-body');
        const title = data.signature || data.title || data.action || data.category || (opts.source === 'search' ? textOrDash(data.value || data.ip) : 'Evento de segurança');
        body.appendChild(createEl('h3', 'tm-v2__context-title', title));

        const badges = createEl('div', 'tm-v2__context-badges');
        if (data.source) badges.appendChild(createEl('span', 'tm-v2__mini-badge', sourceLabel(data.source)));
        if (data.protocol) badges.appendChild(createEl('span', 'tm-v2__mini-badge', String(data.protocol).toUpperCase()));
        if (data.direction || data.flow_scope) badges.appendChild(createEl('span', 'tm-v2__mini-badge', directionLabel(data.direction || data.flow_scope)));
        if (data.role || data.src_role) badges.appendChild(createEl('span', 'tm-v2__mini-badge', data.role || data.src_role));
        if (badges.childElementCount) body.appendChild(badges);

        if (data.isGroup) {
            appendDetailSection(body, 'Resumo do IP', [
                ['Eventos agregados', data.eventCount],
                ['Ocorrências', data.totalOccurrences],
                ['Última atividade', formatTimestamp(data.ts || data.timestamp, true)]
            ]);
            if (data.signaturesArray && data.signaturesArray.length) {
                const sigs = data.signaturesArray.slice(0, 3).join(', ') + (data.signaturesArray.length > 3 ? '...' : '');
                appendDetailSection(body, 'Assinaturas', [
                    ['Observadas', sigs]
                ]);
            }
        } else {
            appendDetailSection(body, 'Evento', [
                ['Timestamp', formatTimestamp(data.ts || data.timestamp, true)],
                ['Ocorrências', data.count ?? '—'],
                ['Direção', directionLabel(data.direction || data.flow_scope)],
                ['Protocolo', data.protocol ? String(data.protocol).toUpperCase() : '—'],
                ['Rule ID', data.rule_id ?? data.sid ?? '—'],
                ['Categoria', data.category ?? '—']
            ]);
        }

        const srcGeo = data.src_geo || {};
        const externalGeo = data.external_geo || {};
        appendDetailSection(body, 'Origem', [
            ['IP', data.src_ip ?? data.external_ip ?? data.ip ?? data.value ?? '—'],
            ['País', data.country ?? srcGeo.country ?? srcGeo.country_code ?? externalGeo.country ?? externalGeo.country_code ?? '—'],
            ['Cidade', data.city ?? srcGeo.city ?? externalGeo.city ?? '—'],
            ['ASN', data.asn ?? srcGeo.asn ?? externalGeo.asn ?? '—'],
            ['Organização', data.org ?? data.organization ?? srcGeo.org ?? externalGeo.org ?? '—'],
            ['Scope', data.src_scope ?? data.scope ?? (data.has_geo === false ? 'internal' : '—')],
            ['Role', data.src_role ?? data.role ?? '—']
        ]);

        if (data.dst_ip || data.dst_port || data.dst_scope || data.dst_role) {
            appendDetailSection(body, 'Destino', [
                ['IP', data.dst_ip ?? '—'],
                ['Porta', data.dst_port ?? '—'],
                ['Scope', data.dst_scope ?? '—'],
                ['Role', data.dst_role ?? '—']
            ]);
        }

        const hasGeo = data.has_geo === true || data.geolocatable === true || !!getExternalGeo(data);
        if (!hasGeo) {
            const section = createEl('div', 'tm-v2__context-section');
            section.appendChild(createEl('h3', '', 'Geolocalização'));
            section.appendChild(createEl('div', 'tm-v2__mini-badge', 'Sem geolocalização pública'));
            body.appendChild(section);
        }

        const actions = createEl('div', 'tm-v2__context-actions');
        const incidentLink = createEl('a', 'tm-v2__context-action tm-v2__context-action--neutral', 'Ver no SOC');
        incidentLink.href = data.incident_id ? `${ENDPOINTS.incidents}${encodeURIComponent(data.incident_id)}/` : ENDPOINTS.incidents;
        actions.appendChild(incidentLink);

        const investigateIp = data.src_ip || data.external_ip || data.ip || data.value;
        if (investigateIp && looksLikeIp(String(investigateIp))) {
            const investigate = createEl('a', 'tm-v2__context-action tm-v2__context-action--primary', 'Investigar IP');
            investigate.href = ENDPOINTS.investigate.replace('__IP__', encodeURIComponent(String(investigateIp)));
            actions.appendChild(investigate);
        }

        const geo = getExternalGeo(data);
        if (geo && getRenderer()) {
            const focus = createEl('button', 'tm-v2__context-action tm-v2__context-action--neutral', 'Focar no mapa');
            focus.type = 'button';
            focus.addEventListener('click', () => {
                getRenderer().focusEvent({
                    external_lon: geo.longitude,
                    external_lat: geo.latitude
                });
            });
            actions.appendChild(focus);
        }

        body.appendChild(actions);
        inner.append(head, body);
        els.detailsPanel.appendChild(inner);
    }

    function appendDetailSection(parent, title, rows) {
        const usefulRows = rows.filter(([, value]) => value !== null && value !== undefined && value !== '');
        if (!usefulRows.length) return;

        const section = createEl('section', 'tm-v2__context-section');
        section.appendChild(createEl('h3', '', title));

        const dl = createEl('dl', 'tm-v2__detail-list');
        usefulRows.forEach(([label, value]) => {
            const row = createEl('div', 'tm-v2__detail-row');
            row.append(createEl('dt', '', label), createEl('dd', '', textOrDash(value)));
            dl.appendChild(row);
        });

        section.appendChild(dl);
        parent.appendChild(section);
    }

    function looksLikeIp(value) {
        const v = String(value || '').trim();
        return /^(\d{1,3}\.){3}\d{1,3}$/.test(v) || v.includes(':');
    }

    function extractSearchResult(data) {
        if (!data || data.ok === false) return null;

        let result = data.result ?? data.match ?? data.item ?? null;
        if (!result && Array.isArray(data.results)) result = data.results[0] || null;
        if (!result && Array.isArray(data.events)) result = data.events[0] || null;

        if (!result) {
            const hasRecognizableFields = ['has_geo', 'value', 'ip', 'src_ip', 'domain', 'signature', 'asn', 'context']
                .some((key) => Object.prototype.hasOwnProperty.call(data, key));
            if (hasRecognizableFields) result = data;
        }

        return result;
    }

    async function runSearch(query) {
        const q = String(query || '').trim();
        if (!q) return;

        if (state.feedGroups && looksLikeIp(q)) {
            const localGroup = state.feedGroups.find(g => g.external_ip === q);
            if (localGroup) {
                openContext(localGroup, { source: 'search' });
                const geo = getExternalGeo(localGroup);
                const renderer = getRenderer();
                if (renderer && geo) renderer.focusEvent({ external_lon: geo.longitude, external_lat: geo.latitude });
                return;
            }
        }

        if (state.searchController) state.searchController.abort();
        state.searchController = new AbortController();

        const params = new URLSearchParams();
        params.set('q', q);

        let submitBtn = null;
        if (els.searchForm) submitBtn = els.searchForm.querySelector('button[type="submit"]');

        if (submitBtn) {
            submitBtn.disabled = true;
            submitBtn.textContent = 'Buscando...';
        }
        window.MoonShieldLoading?.setRefreshing(els.detailsPanel || els.eventsPanel, true);

        try {
            const data = await fetchJson(urlWithParams(ENDPOINTS.search, params), {
                signal: state.searchController.signal
            });
            const result = extractSearchResult(data);

            if (!result) {
                showToast('Nenhum resultado encontrado.');
                return;
            }

            const merged = mergedContext(result);
            const geo = getExternalGeo(merged);
            const hasGeo = merged.has_geo === true || merged.geolocatable === true || !!geo;

            openContext(merged, { source: 'search' });

            if (hasGeo && geo && getRenderer()) {
                getRenderer().focusEvent({
                    external_lon: geo.longitude,
                    external_lat: geo.latitude
                });
            } else {
                const role = merged.role || merged.src_role || '';
                showToast(role ? `IP interno é ${role} - sem posição geográfica.` : 'Resultado sem posição geográfica pública.');
            }
        } catch (error) {
            if (error.name !== 'AbortError') {
                console.warn('[ThreatMap] Busca falhou.', error);
                showToast('Não foi possível concluir a busca.');
            }
        } finally {
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.textContent = 'Buscar';
            }
            window.MoonShieldLoading?.setRefreshing(els.detailsPanel || els.eventsPanel, false);
            state.searchController = null;
        }
    }

    function toggleLive() {
        state.live = !state.live;
        if (els.btnPause) {
            els.btnPause.classList.toggle('is-live', state.live);
            els.btnPause.classList.toggle('is-paused', !state.live);
            els.btnPause.setAttribute('aria-pressed', String(!state.live));
            const label = els.btnPause.querySelector('.status-label');
            if (label) label.textContent = state.live ? 'LIVE' : 'PAUSADO';
        }

        const renderer = getRenderer();
        if (renderer) renderer.setPaused(!state.live);

        window.clearTimeout(state.pollTimer);
        if (state.live) refreshAll({ force: true }).catch(console.error);
    }

    function toggleProjection() {
        state.isGlobe = !state.isGlobe;
        const renderer = getRenderer();
        if (renderer) renderer.setProjection(state.isGlobe ? 'globe' : 'mercator');
        if (els.btnProjection) {
            els.btnProjection.classList.toggle('is-active', !state.isGlobe);
            els.btnProjection.setAttribute('aria-pressed', String(state.isGlobe));
            els.btnProjection.title = state.isGlobe ? 'Usando globo 3D' : 'Usando mapa 2D';
        }
    }

    function togglePanels() {
        state.panelsHidden = !state.panelsHidden;
        if (els.app) els.app.classList.toggle('panels-hidden', state.panelsHidden);
        if (els.btnTogglePanels) {
            els.btnTogglePanels.classList.toggle('is-active', state.panelsHidden);
            els.btnTogglePanels.setAttribute('aria-pressed', String(state.panelsHidden));
        }
        rendererResize();
    }

    function toggleCinema() {
        if (!els.app) return;
        const active = !els.app.classList.contains('cinema-mode');
        els.app.classList.toggle('cinema-mode', active);
        if (els.btnCinema) {
            els.btnCinema.classList.toggle('is-active', active);
            els.btnCinema.setAttribute('aria-pressed', String(active));
        }
        rendererResize();
    }

    function clearVisualSelection() {
        closeContext();
        state.searchResult = null;
        if (els.searchInput) els.searchInput.value = '';
        const renderer = getRenderer();
        if (renderer) {
            renderer.clear();
            updateRendererEvents();
            renderer.resetView();
        }
    }

    function toggleFiltersCollapsed() {
        if (window.matchMedia('(max-width: 920px)').matches) {
            state.mobileFiltersOpen = !state.mobileFiltersOpen;
            state.mobileEventsOpen = false;
            updateMobileDrawers();
            return;
        }

        state.filtersCollapsed = !state.filtersCollapsed;
        updateFilterPanelState();
        saveFiltersCollapsed();
        rendererResize();
    }

    function updateFilterPanelState() {
        if (!els.app || !els.btnCollapseFilters) return;
        els.app.classList.toggle('filters-collapsed', state.filtersCollapsed);
        els.app.classList.toggle('filters-user-open', !state.filtersCollapsed);
        els.btnCollapseFilters.setAttribute('aria-expanded', String(!state.filtersCollapsed));
        els.btnCollapseFilters.setAttribute('aria-label', state.filtersCollapsed ? 'Expandir filtros' : 'Recolher filtros');
    }

    function loadFiltersCollapsed() {
        try {
            const stored = localStorage.getItem(FILTERS_STORAGE_KEY);
            if (stored === '1') state.filtersCollapsed = true;
            else if (stored === '0') state.filtersCollapsed = false;
            else state.filtersCollapsed = window.matchMedia('(max-width: 1180px)').matches;
        } catch (_) {
            state.filtersCollapsed = window.matchMedia('(max-width: 1180px)').matches;
        }
    }

    function saveFiltersCollapsed() {
        try {
            localStorage.setItem(FILTERS_STORAGE_KEY, state.filtersCollapsed ? '1' : '0');
        } catch (_) {
            // Storage indisponível não pode quebrar o mapa.
        }
    }

    function loadLocalSettings() {
        try {
            const raw = localStorage.getItem(PREFS_STORAGE_KEY);
            if (!raw) return;
            const saved = JSON.parse(raw);
            if ([50, 100, 150, 200].includes(Number(saved.maxEvents))) state.settings.maxEvents = Number(saved.maxEvents);
            if ([5000, 15000, 30000].includes(Number(saved.trailDuration))) state.settings.trailDuration = Number(saved.trailDuration);
            if ([0, 0.02, 0.05, 0.1].includes(Number(saved.rotSpeed))) state.settings.rotSpeed = Number(saved.rotSpeed);
        } catch (_) {
            // Preferências inválidas são ignoradas.
        }
    }

    function saveLocalSettings() {
        try {
            localStorage.setItem(PREFS_STORAGE_KEY, JSON.stringify(state.settings));
        } catch (_) {
            // Storage indisponível não pode quebrar o mapa.
        }
    }

    function syncSettingsControls() {
        if (els.settingMaxEvents) els.settingMaxEvents.value = String(state.settings.maxEvents);
        if (els.settingTrail) els.settingTrail.value = String(state.settings.trailDuration);
        if (els.settingRot) els.settingRot.value = String(state.settings.rotSpeed);
    }

    function applyRendererSettings() {
        const renderer = getRenderer();
        if (!renderer) return;
        renderer.setTrailDuration(state.settings.trailDuration);
        renderer.setRotationSpeed(state.settings.rotSpeed);
    }

    function toggleMobileFilters() {
        state.mobileFiltersOpen = !state.mobileFiltersOpen;
        state.mobileEventsOpen = false;
        updateMobileDrawers();
    }

    function toggleMobileEvents() {
        state.mobileEventsOpen = !state.mobileEventsOpen;
        state.mobileFiltersOpen = false;
        updateMobileDrawers();
    }

    function ensureMobileEventsVisible() {
        if (!window.matchMedia('(max-width: 920px)').matches) return;
        state.mobileEventsOpen = true;
        state.mobileFiltersOpen = false;
        updateMobileDrawers();
    }

    function closeMobileDrawers() {
        state.mobileFiltersOpen = false;
        state.mobileEventsOpen = false;
        updateMobileDrawers();
    }

    function updateMobileDrawers() {
        if (!els.app) return;
        els.app.classList.toggle('mobile-filters-open', state.mobileFiltersOpen);
        els.app.classList.toggle('mobile-events-open', state.mobileEventsOpen);

        if (els.btnMobileFilters) els.btnMobileFilters.setAttribute('aria-expanded', String(state.mobileFiltersOpen));
        if (els.btnMobileEvents) els.btnMobileEvents.setAttribute('aria-expanded', String(state.mobileEventsOpen));

        const anyOpen = state.mobileFiltersOpen || state.mobileEventsOpen;
        if (els.drawerBackdrop) els.drawerBackdrop.hidden = !anyOpen;
        rendererResize();
    }

    function positionPopover(popover, trigger) {
        if (!popover || !trigger || popover === els.settingsPopover) return;
        popover.hidden = false;

        requestAnimationFrame(() => {
            const triggerRect = trigger.getBoundingClientRect();
            const popRect = popover.getBoundingClientRect();
            const viewportW = document.documentElement.clientWidth;
            const viewportH = document.documentElement.clientHeight;
            const margin = 10;

            let left = triggerRect.right + 8;
            let top = triggerRect.top;

            if (left + popRect.width > viewportW - margin) {
                left = triggerRect.left - popRect.width - 8;
            }
            if (left < margin) left = Math.max(margin, triggerRect.left);
            if (top + popRect.height > viewportH - margin) {
                top = viewportH - popRect.height - margin;
            }
            if (top < margin) top = margin;

            popover.style.left = `${Math.round(left)}px`;
            popover.style.top = `${Math.round(top)}px`;
        });
    }

    function openPopover(popover, trigger, kind) {
        if (!popover || !trigger) return;

        if (state.currentPopover === popover && !popover.hidden) {
            closePopovers();
            return;
        }

        closePopovers(false);
        state.currentPopover = popover;
        state.popoverTrigger = trigger;

        if (kind === 'categories' || kind === 'countries') syncDraft(kind);

        popover.hidden = false;
        trigger.setAttribute('aria-expanded', 'true');

        if (popover === els.settingsPopover) {
            // Posicionamento é controlado pelo CSS dentro do wrapper.
        } else {
            positionPopover(popover, trigger);
        }
    }

    function closePopovers(returnFocus) {
        const shouldReturnFocus = returnFocus !== false;
        const popovers = [
            els.categoriesPopover,
            els.countriesPopover,
            els.moreFiltersPopover,
            els.settingsPopover
        ];

        popovers.forEach((popover) => {
            if (popover) {
                popover.hidden = true;
                if (popover !== els.settingsPopover) {
                    popover.style.left = '';
                    popover.style.top = '';
                }
            }
        });

        [els.btnCategories, els.btnCountries, els.btnMoreFilters, els.btnSettings].forEach((button) => {
            if (button) button.setAttribute('aria-expanded', 'false');
        });

        const previousTrigger = state.popoverTrigger;
        state.currentPopover = null;
        state.popoverTrigger = null;

        if (shouldReturnFocus && previousTrigger && document.contains(previousTrigger)) {
            previousTrigger.focus({ preventScroll: true });
        }
    }

    function isInsideOpenPopover(target) {
        return !!(state.currentPopover && !state.currentPopover.hidden && state.currentPopover.contains(target));
    }

    function openLocationModal() {
        if (!els.locationModal) return;

        hideLocationError();
        state.pendingBrowserLocation = null;
        if (els.browserConfirmBox) els.browserConfirmBox.hidden = true;

        const canBrowserGeo = !!(window.isSecureContext && navigator.geolocation);
        if (els.btnUseBrowser) els.btnUseBrowser.disabled = !canBrowserGeo;
        if (els.browserUnavailableMsg) els.browserUnavailableMsg.hidden = canBrowserGeo;

        els.locationModal.hidden = false;
        if (els.locLat) els.locLat.focus();
    }

    function closeLocationModal() {
        if (!els.locationModal) return;
        els.locationModal.hidden = true;
        state.pendingBrowserLocation = null;
        if (els.browserConfirmBox) els.browserConfirmBox.hidden = true;
        hideLocationError();
    }

    function showLocationError(message) {
        if (!els.locError) return;
        els.locError.textContent = message;
        els.locError.hidden = false;
    }

    function hideLocationError() {
        if (!els.locError) return;
        els.locError.textContent = '';
        els.locError.hidden = true;
    }

    async function searchAddress() {
        hideLocationError();
        const cep = (els.locCep ? els.locCep.value : '').trim();
        const address = (els.locEndereco ? els.locEndereco.value : '').trim();
        const city = (els.locCidade ? els.locCidade.value : '').trim();
        const stateStr = (els.locEstado ? els.locEstado.value : '').trim();
        const country = (els.locPais ? els.locPais.value : 'BR');

        if (!cep && !address && !city && !stateStr) {
            showLocationError('Preencha ao menos um campo para buscar.');
            return;
        }

        if (els.btnSearchAddress) els.btnSearchAddress.disabled = true;

        try {
            const geocodeUrl = ENDPOINTS.location + 'geocode/';
            const response = await fetch(geocodeUrl, {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    Accept: 'application/json',
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRFToken': getCookie('csrftoken') || ''
                },
                body: JSON.stringify({ cep, address, city, state: stateStr, country })
            });
            const data = await response.json();

            if (response.ok && data.ok && data.result) {
                state.pendingBrowserLocation = {
                    latitude: data.result.latitude,
                    longitude: data.result.longitude,
                    source: 'address',
                    extra: {
                        city: data.result.city || '',
                        region: data.result.region || '',
                        country_code: data.result.country_code || ''
                    }
                };
                if (els.locationConfirmDisplay) els.locationConfirmDisplay.textContent = data.result.display_name;
                if (els.browserConfirmLat) els.browserConfirmLat.textContent = data.result.latitude.toFixed(6);
                if (els.browserConfirmLon) els.browserConfirmLon.textContent = data.result.longitude.toFixed(6);
                if (els.browserConfirmBox) els.browserConfirmBox.hidden = false;
            } else {
                showLocationError(data.erro || 'Endereço não encontrado.');
                if (els.browserConfirmBox) els.browserConfirmBox.hidden = true;
                state.pendingBrowserLocation = null;
            }
        } catch (error) {
            showLocationError('Não foi possível consultar o endereço agora.');
            if (els.browserConfirmBox) els.browserConfirmBox.hidden = true;
            state.pendingBrowserLocation = null;
        } finally {
            if (els.btnSearchAddress) els.btnSearchAddress.disabled = false;
        }
    }

    function requestBrowserLocation() {
        hideLocationError();

        if (!window.isSecureContext || !navigator.geolocation) {
            if (els.browserUnavailableMsg) els.browserUnavailableMsg.hidden = false;
            return;
        }

        if (els.btnUseBrowser) els.btnUseBrowser.disabled = true;
        navigator.geolocation.getCurrentPosition(
            (position) => {
                if (els.btnUseBrowser) els.btnUseBrowser.disabled = false;
                state.pendingBrowserLocation = {
                    latitude: position.coords.latitude,
                    longitude: position.coords.longitude,
                    source: 'browser',
                    extra: {}
                };
                if (els.locationConfirmDisplay) els.locationConfirmDisplay.textContent = "Localização do navegador";
                if (els.browserConfirmLat) els.browserConfirmLat.textContent = position.coords.latitude.toFixed(6);
                if (els.browserConfirmLon) els.browserConfirmLon.textContent = position.coords.longitude.toFixed(6);
                if (els.browserConfirmBox) els.browserConfirmBox.hidden = false;
            },
            () => {
                if (els.btnUseBrowser) els.btnUseBrowser.disabled = false;
                showLocationError('Não foi possível obter a localização do navegador.');
            },
            { enableHighAccuracy: false, timeout: 10000, maximumAge: 0 }
        );
    }

    async function submitLocation(latitude, longitude, source, extra = {}) {
        const lat = Number(latitude);
        const lon = Number(longitude);

        if (!Number.isFinite(lat) || lat < -90 || lat > 90) {
            showLocationError('Latitude deve estar entre -90 e 90.');
            return;
        }
        if (!Number.isFinite(lon) || lon < -180 || lon > 180) {
            showLocationError('Longitude deve estar entre -180 e 180.');
            return;
        }

        hideLocationError();
        if (els.btnSaveLocation) els.btnSaveLocation.disabled = true;

        try {
            const payload = {
                latitude: lat,
                longitude: lon,
                source: source || 'manual'
            };
            if (extra) Object.assign(payload, extra);

            const response = await fetch(ENDPOINTS.location, {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    Accept: 'application/json',
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRFToken': getCookie('csrftoken') || ''
                },
                body: JSON.stringify(payload)
            });

            const data = await response.json().catch(() => ({}));
            if (!response.ok || data.ok === false) {
                throw new Error(data.erro || data.error || `HTTP ${response.status}`);
            }

            // Success
            state.node = state.node || {};
            state.node.latitude = lat;
            state.node.longitude = lon;
            
            if (els.noLocationWarning) {
                els.noLocationWarning.classList.remove('visible');
            }
            if (els.browserConfirmBox) {
                els.browserConfirmBox.hidden = true;
            }
            state.pendingBrowserLocation = null;

            const renderer = getRenderer();
            if (renderer && typeof renderer.setNode === 'function') {
                renderer.setNode({
                    ...(state.node || {}),
                    latitude: lat,
                    longitude: lon
                });
                if (typeof renderer.focusNode === 'function') {
                    renderer.focusNode();
                }
            }
            
            closeLocationModal();
            showToast('Localização do appliance atualizada.');
            
            if (state.live) {
                refreshAll({ force: true }).catch(console.error);
            }
        } catch (error) {
            console.warn('[ThreatMap] Falha ao salvar localização.', error);
            showLocationError(error.message || 'Falha ao salvar localização.');
        } finally {
            if (els.btnSaveLocation) els.btnSaveLocation.disabled = false;
        }
    }

    function handleResize() {
        if (!window.matchMedia('(max-width: 920px)').matches) {
            if (state.mobileFiltersOpen || state.mobileEventsOpen) {
                state.mobileFiltersOpen = false;
                state.mobileEventsOpen = false;
                updateMobileDrawers();
            }
        }
        rendererResize();
        if (state.currentPopover && state.popoverTrigger && state.currentPopover !== els.settingsPopover) {
            positionPopover(state.currentPopover, state.popoverTrigger);
        }
    }

    function bindListeners() {
        if (els.filterPeriod) {
            els.filterPeriod.addEventListener('change', () => {
                state.filters.period = els.filterPeriod.value;
                refreshAll({ force: true }).catch(console.error);
            });
        }

        if (els.filterSev) {
            els.filterSev.addEventListener('change', () => {
                state.filters.sev = els.filterSev.value;
                renderActiveFilters();
                refreshAll({ force: true }).catch(console.error);
            });
        }

        if (els.filterSource) {
            els.filterSource.addEventListener('change', () => {
                state.filters.source = els.filterSource.value;
                renderActiveFilters();
                refreshAll({ force: true }).catch(console.error);
            });
        }

        if (els.filterProtocol) {
            els.filterProtocol.addEventListener('change', () => {
                state.filters.protocol = els.filterProtocol.value;
                renderActiveFilters();
                refreshAll({ force: true }).catch(console.error);
            });
        }

        if (els.filterDirection) {
            els.filterDirection.addEventListener('change', () => {
                state.filters.direction = els.filterDirection.value;
                renderActiveFilters();
                refreshAll({ force: true }).catch(console.error);
            });
        }

        if (els.filterZone) {
            els.filterZone.addEventListener('change', () => {
                state.filters.zone = els.filterZone.value;
                renderActiveFilters();
                refreshAll({ force: true }).catch(console.error);
            });
        }

        if (els.btnCategories) {
            els.btnCategories.addEventListener('click', (event) => {
                event.stopPropagation();
                openPopover(els.categoriesPopover, els.btnCategories, 'categories');
            });
        }

        if (els.btnCountries) {
            els.btnCountries.addEventListener('click', (event) => {
                event.stopPropagation();
                openPopover(els.countriesPopover, els.btnCountries, 'countries');
            });
        }

        if (els.btnMoreFilters) {
            els.btnMoreFilters.addEventListener('click', (event) => {
                event.stopPropagation();
                openPopover(els.moreFiltersPopover, els.btnMoreFilters);
            });
        }

        if (els.btnSettings) {
            els.btnSettings.addEventListener('click', (event) => {
                event.stopPropagation();
                openPopover(els.settingsPopover, els.btnSettings);
            });
        }

        if (els.categoriesSearch) {
            els.categoriesSearch.addEventListener('input', () => renderMultiOptions('categories', els.categoriesSearch.value));
        }

        if (els.countriesSearch) {
            els.countriesSearch.addEventListener('input', () => renderMultiOptions('countries', els.countriesSearch.value));
        }

        document.querySelectorAll('[data-clear-multi]').forEach((button) => {
            button.addEventListener('click', () => clearMultiDraft(button.dataset.clearMulti));
        });

        document.querySelectorAll('[data-apply-multi]').forEach((button) => {
            button.addEventListener('click', () => applyMulti(button.dataset.applyMulti));
        });

        document.querySelectorAll('[data-close-popover]').forEach((button) => {
            button.addEventListener('click', () => closePopovers());
        });

        if (els.btnResetFilters) els.btnResetFilters.addEventListener('click', resetFilters);
        if (els.btnPause) els.btnPause.addEventListener('click', toggleLive);
        if (els.btnProjection) els.btnProjection.addEventListener('click', toggleProjection);
        if (els.btnTogglePanels) els.btnTogglePanels.addEventListener('click', togglePanels);
        if (els.btnCinema) els.btnCinema.addEventListener('click', toggleCinema);
        if (els.btnClear) els.btnClear.addEventListener('click', clearVisualSelection);
        if (els.btnCollapseFilters) els.btnCollapseFilters.addEventListener('click', toggleFiltersCollapsed);

        if (els.settingMaxEvents) {
            els.settingMaxEvents.addEventListener('change', () => {
                state.settings.maxEvents = Number(els.settingMaxEvents.value) || 200;
                saveLocalSettings();
                refreshAll({ force: true }).catch(console.error);
            });
        }

        if (els.settingTrail) {
            els.settingTrail.addEventListener('change', () => {
                state.settings.trailDuration = Number(els.settingTrail.value) || 15000;
                saveLocalSettings();
                applyRendererSettings();
            });
        }

        if (els.settingRot) {
            els.settingRot.addEventListener('change', () => {
                state.settings.rotSpeed = Number(els.settingRot.value) || 0;
                saveLocalSettings();
                applyRendererSettings();
            });
        }

        if (els.searchForm) {
            els.searchForm.addEventListener('submit', (event) => {
                event.preventDefault();
                runSearch(els.searchInput ? els.searchInput.value : '').catch(console.error);
            });
        }

        if (els.btnMobileFilters) els.btnMobileFilters.addEventListener('click', toggleMobileFilters);
        if (els.btnMobileEvents) els.btnMobileEvents.addEventListener('click', toggleMobileEvents);
        if (els.drawerBackdrop) els.drawerBackdrop.addEventListener('click', closeMobileDrawers);

        if (els.btnOpenLocationModal) els.btnOpenLocationModal.addEventListener('click', openLocationModal);
        if (els.btnCloseLocation) els.btnCloseLocation.addEventListener('click', closeLocationModal);
        if (els.btnCancelLocation) els.btnCancelLocation.addEventListener('click', closeLocationModal);
        if (els.locationModal) {
            els.locationModal.addEventListener('click', (event) => {
                if (event.target === els.locationModal) closeLocationModal();
            });
        }

        if (els.btnUseBrowser) els.btnUseBrowser.addEventListener('click', requestBrowserLocation);
        if (els.btnConfirmBrowserLocation) {
            els.btnConfirmBrowserLocation.addEventListener('click', () => {
                if (!state.pendingBrowserLocation) return;
                submitLocation(
                    state.pendingBrowserLocation.latitude,
                    state.pendingBrowserLocation.longitude,
                    state.pendingBrowserLocation.source || 'browser',
                    state.pendingBrowserLocation.extra
                ).catch(console.error);
            });
        }
        if (els.btnSearchAddress) {
            els.btnSearchAddress.addEventListener('click', searchAddress);
        }

        if (els.btnSaveLocation) {
            els.btnSaveLocation.addEventListener('click', () => {
                submitLocation(
                    els.locLat ? els.locLat.value : '',
                    els.locLon ? els.locLon.value : '',
                    'manual'
                ).catch(console.error);
            });
        }

        document.addEventListener('click', (event) => {
            if (!state.currentPopover) return;
            if (isInsideOpenPopover(event.target)) return;
            if (state.popoverTrigger && state.popoverTrigger.contains(event.target)) return;
            closePopovers(false);
        });

        document.addEventListener('keydown', (event) => {
            if (event.key !== 'Escape') return;

            if (state.currentPopover) {
                closePopovers();
                return;
            }

            if (els.locationModal && !els.locationModal.hidden) {
                closeLocationModal();
                return;
            }

            if (state.mobileFiltersOpen || state.mobileEventsOpen) {
                closeMobileDrawers();
                return;
            }

            if (els.app && els.app.classList.contains('cinema-mode')) {
                toggleCinema();
            }
        });

        window.addEventListener('resize', handleResize);

        const themeObserver = new MutationObserver((mutations) => {
            if (!mutations.some((mutation) => mutation.attributeName === 'data-theme')) return;
            const renderer = getRenderer();
            if (renderer) {
                renderer.setTheme(document.documentElement.getAttribute('data-theme') || 'light');
            }
        });
        themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

        if (window.ResizeObserver) {
            const observed = document.querySelector('main') || els.app?.parentElement;
            if (observed) {
                const resizeObserver = new ResizeObserver(() => rendererResize());
                resizeObserver.observe(observed);
            }
        }

        state.staleTimer = window.setInterval(updateStaleBanner, 5000);
    }

    function initRenderer() {
        const renderer = getRenderer();
        if (!renderer || !els.map) {
            if (els.mapFailure) els.mapFailure.hidden = false;
            return;
        }

        const tokenEl = $('mapbox-token-data');
        let token = '';
        try {
            token = tokenEl ? JSON.parse(tokenEl.textContent || '""') : '';
        } catch (_) {
            token = '';
        }

        if (!token) {
            if (els.mapFailure) els.mapFailure.hidden = false;
            return;
        }

    function handleRendererEventClick(groupKey) {
        if (!state.feedGroups) return;
        const group = state.feedGroups.find(g => g.groupKey === groupKey);
        if (group) {
            openContext(group, { source: 'event' });
            const renderer = getRenderer();
            if (renderer) renderer.focusEvent({ external_lon: getExternalGeo(group)?.longitude, external_lat: getExternalGeo(group)?.latitude });
        }
    }

        els.map.setAttribute('aria-busy', 'true');
        renderer.init({
            containerId: 'map',
            token,
            theme: document.documentElement.getAttribute('data-theme') || 'light',
            onEventClick: handleRendererEventClick,
            onReady: () => {
                els.map.setAttribute('aria-busy', 'false');
                if (els.mapFailure) els.mapFailure.hidden = true;
                applyRendererSettings();
                if (state.node) renderer.setNode(state.node);
                updateRendererEvents();
                rendererResize();
            },
            onError: (error) => {
                els.map.setAttribute('aria-busy', 'false');
                console.warn('[ThreatMap] Mapbox indisponível.', error);
                if (els.mapFailure) els.mapFailure.hidden = false;
            }
        });
    }

    function boot() {
        if (!els.app) return;

        loadFiltersCollapsed();
        updateFilterPanelState();
        syncFilterControls();
        syncDraft('categories');
        syncDraft('countries');
        updateMultiLabels();
        renderActiveFilters();
        bindListeners();
        initRenderer();

        refreshAll({ force: true }).catch((error) => {
            console.error('[ThreatMap] Falha na carga inicial.', error);
            setBanner(els.bannerError, true);
        });
    }

    document.addEventListener('DOMContentLoaded', boot);
})();
