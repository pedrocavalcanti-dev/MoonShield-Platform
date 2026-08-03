/**
 * MOONSHIELD — MAPA DE AMEAÇAS v8.0
 * Globo 3D · Rastros com glow aprimorado · Animações de impacto
 */

(function () {
    'use strict';

    /* ══════════════════════════════════════════════════════════
       1. CONSTANTES E ESTILO
    ══════════════════════════════════════════════════════════ */
    const SEV_COLORS = {
        critical: '#ff2d55',
        high: '#ff6b00',
        medium: '#ffd60a',
        low: '#0a84ff'
    };

    // Glow color com mais saturação para efeito neon
    const SEV_GLOW = {
        critical: 'rgba(255, 45,  85,  1)',
        high: 'rgba(255, 107, 0,   1)',
        medium: 'rgba(255, 214, 10,  1)',
        low: 'rgba(10,  132, 255, 1)'
    };

    const MAP_STYLES = {
        dark: 'mapbox://styles/mapbox/dark-v11',
        light: 'mapbox://styles/mapbox/light-v11'
    };

    const FOG_CONFIG = {
        dark: {
            'color': 'rgb(8, 8, 8)',
            'high-color': 'rgb(15, 15, 24)',
            'space-color': 'rgb(0, 0, 0)',
            'horizon-blend': 0.025,
            'star-intensity': 1.0
        },
        light: {
            'color': 'rgb(210, 228, 248)',
            'high-color': 'rgb(175, 210, 245)',
            'space-color': 'rgb(220, 238, 255)',
            'horizon-blend': 0.08,
            'star-intensity': 0.0
        }
    };

    const DEST_COLOR = { dark: '#22c55e', light: '#16a34a' };

    /* ══════════════════════════════════════════════════════════
       2. ESTADO
    ══════════════════════════════════════════════════════════ */
    let paused = false;
    let cinemaMode = false;
    let is2DMap = false;

    let feedCount = 0;
    let sessionTotal = 0;
    let currentPeriod = '24h';
    let sevFilter = 'all';
    let feedFilter = 'all';

    let trailDuration = 15000;
    let maxEvents = 200;
    let rotSpeed = 0.05;

    let activeEvents = [];
    let impactFlashes = []; // efeitos de impacto no destino
    let layersReady = false;
    let renderStarted = false;
    let seenIds = new Set();

    function getCurrentTheme() {
        return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
    }

    /* ══════════════════════════════════════════════════════════
       3. SLERP — interpolação esférica
    ══════════════════════════════════════════════════════════ */
    function slerp(lon1, lat1, lon2, lat2, t) {
        const rad = Math.PI / 180;
        const p1 = lat1 * rad, l1 = lon1 * rad, p2 = lat2 * rad, l2 = lon2 * rad;
        const x1 = Math.cos(p1) * Math.cos(l1), y1 = Math.cos(p1) * Math.sin(l1), z1 = Math.sin(p1);
        const x2 = Math.cos(p2) * Math.cos(l2), y2 = Math.cos(p2) * Math.sin(l2), z2 = Math.sin(p2);
        let dot = Math.max(-1, Math.min(1, x1 * x2 + y1 * y2 + z1 * z2));
        const omega = Math.acos(dot);
        if (omega < 1e-5) return [lon1 + (lon2 - lon1) * t, lat1 + (lat2 - lat1) * t];
        const s = Math.sin(omega);
        const a = Math.sin((1 - t) * omega) / s, b = Math.sin(t * omega) / s;
        return [
            Math.atan2(a * y1 + b * y2, a * x1 + b * x2) / rad,
            Math.asin(a * z1 + b * z2) / rad
        ];
    }

    function buildTrailCoords(ev, progress, n = 36) {
        const coords = [];
        for (let i = 0; i <= n; i++) {
            coords.push(slerp(ev.src_lon, ev.src_lat, ev.dest_lon, ev.dest_lat, (i / n) * progress));
        }
        return coords;
    }

    /* ══════════════════════════════════════════════════════════
       4. MAPBOX INIT
    ══════════════════════════════════════════════════════════ */
    mapboxgl.accessToken = MAPBOX_TOKEN;

    const map = new mapboxgl.Map({
        container: 'tg-canvas',
        style: MAP_STYLES[getCurrentTheme()],
        center: [-47.93 - 40, -15.78],
        zoom: 1.5,
        projection: 'globe',
        attributionControl: false,
    });

    map.addControl(
        new mapboxgl.NavigationControl({ showCompass: true, showZoom: true, visualizePitch: true }),
        'bottom-right'
    );

    let userInteracting = false;
    ['mousedown', 'mouseup', 'dragstart', 'dragend', 'touchstart', 'touchend'].forEach(ev => {
        map.on(ev, () => { userInteracting = ['mousedown', 'dragstart', 'touchstart'].includes(ev); });
    });

    /* ══════════════════════════════════════════════════════════
       5. LAYERS
    ══════════════════════════════════════════════════════════ */
    function initLayers() {
        const t = getCurrentTheme();
        map.setFog(FOG_CONFIG[t]);
        const dc = DEST_COLOR[t];

        const addSrc = (id, data) => {
            if (!map.getSource(id)) map.addSource(id, { type: 'geojson', data });
        };
        const emptyFC = { type: 'FeatureCollection', features: [] };

        addSrc('events-points', emptyFC);
        addSrc('events-lines', emptyFC);
        addSrc('events-glow', emptyFC);
        addSrc('events-glow2', emptyFC); // segundo passe de glow mais intenso
        addSrc('impact-points', emptyFC); // flashes de impacto no destino
        addSrc('dest-point', {
            type: 'Feature',
            geometry: { type: 'Point', coordinates: [-47.93, -15.78] }
        });

        // Destino — halo duplo
        if (!map.getLayer('dest-halo2')) map.addLayer({
            id: 'dest-halo2', type: 'circle', source: 'dest-point',
            paint: {
                'circle-radius': 28,
                'circle-color': dc,
                'circle-opacity': 0.10,
                'circle-blur': 0.8,
                'circle-pitch-alignment': 'map'
            }
        });
        if (!map.getLayer('dest-halo')) map.addLayer({
            id: 'dest-halo', type: 'circle', source: 'dest-point',
            paint: {
                'circle-radius': 16,
                'circle-color': dc,
                'circle-opacity': 0.32,
                'circle-blur': 0.35,
                'circle-stroke-width': 1,
                'circle-stroke-color': dc,
                'circle-pitch-alignment': 'map'
            }
        });
        if (!map.getLayer('dest-core')) map.addLayer({
            id: 'dest-core', type: 'circle', source: 'dest-point',
            paint: {
                'circle-radius': 4,
                'circle-color': dc,
                'circle-pitch-alignment': 'map'
            }
        });

        // Impactos no destino
        if (!map.getLayer('impact-flash')) map.addLayer({
            id: 'impact-flash', type: 'circle', source: 'impact-points',
            paint: {
                'circle-radius': ['get', 'radius'],
                'circle-color': ['get', 'color'],
                'circle-opacity': ['get', 'opacity'],
                'circle-blur': 0.5,
                'circle-pitch-alignment': 'map'
            }
        });

        // Linhas de rastro — 3 camadas de glow para efeito neon profundo
        if (!map.getLayer('attack-lines-glow2')) map.addLayer({
            id: 'attack-lines-glow2', type: 'line', source: 'events-glow2',
            paint: {
                'line-color': ['get', 'color'],
                'line-width': ['*', ['get', 'width'], 8],
                'line-blur': 14,
                'line-opacity': ['*', ['get', 'opacity'], 0.18]
            }
        });
        if (!map.getLayer('attack-lines-glow')) map.addLayer({
            id: 'attack-lines-glow', type: 'line', source: 'events-glow',
            paint: {
                'line-color': ['get', 'color'],
                'line-width': ['*', ['get', 'width'], 4],
                'line-blur': 7,
                'line-opacity': ['*', ['get', 'opacity'], 0.30]
            }
        });
        if (!map.getLayer('attack-lines')) map.addLayer({
            id: 'attack-lines', type: 'line', source: 'events-lines',
            paint: {
                'line-color': ['get', 'color'],
                'line-width': ['get', 'width'],
                'line-blur': 0.6,
                'line-opacity': ['get', 'opacity']
            }
        });

        // Pontos de ataque — halo + core
        if (!map.getLayer('attackers-halo')) map.addLayer({
            id: 'attackers-halo', type: 'circle', source: 'events-points',
            filter: ['!=', ['get', 'isHead'], true],
            paint: {
                'circle-radius': ['*', ['get', 'scale'], 20],
                'circle-color': ['get', 'color'],
                'circle-opacity': ['*', ['get', 'haloOpacity'], 0.50],
                'circle-blur': 0.85,
                'circle-pitch-alignment': 'map'
            }
        });
        if (!map.getLayer('attackers-halo2')) map.addLayer({
            id: 'attackers-halo2', type: 'circle', source: 'events-points',
            filter: ['!=', ['get', 'isHead'], true],
            paint: {
                'circle-radius': ['*', ['get', 'scale'], 10],
                'circle-color': ['get', 'color'],
                'circle-opacity': ['*', ['get', 'haloOpacity'], 0.35],
                'circle-blur': 0.4,
                'circle-pitch-alignment': 'map'
            }
        });
        if (!map.getLayer('attackers-core')) map.addLayer({
            id: 'attackers-core', type: 'circle', source: 'events-points',
            filter: ['!=', ['get', 'isHead'], true],
            paint: {
                'circle-radius': ['*', ['get', 'scale'], 3.8],
                'circle-color': '#ffffff',
                'circle-stroke-width': 1.8,
                'circle-stroke-color': ['get', 'color'],
                'circle-opacity': ['get', 'opacity'],
                'circle-pitch-alignment': 'map'
            }
        });

        // Cabeça do rastro (ponto que viaja ao longo da linha)
        if (!map.getLayer('trail-head-glow')) map.addLayer({
            id: 'trail-head-glow', type: 'circle', source: 'events-points',
            filter: ['==', ['get', 'isHead'], true],
            paint: {
                'circle-radius': ['*', ['get', 'scale'], 14],
                'circle-color': ['get', 'color'],
                'circle-opacity': ['*', ['get', 'haloOpacity'], 0.55],
                'circle-blur': 0.7,
                'circle-pitch-alignment': 'map'
            }
        });
        if (!map.getLayer('trail-head-core')) map.addLayer({
            id: 'trail-head-core', type: 'circle', source: 'events-points',
            filter: ['==', ['get', 'isHead'], true],
            paint: {
                'circle-radius': ['*', ['get', 'scale'], 4.2],
                'circle-color': '#ffffff',
                'circle-stroke-width': 2,
                'circle-stroke-color': ['get', 'color'],
                'circle-opacity': ['get', 'opacity'],
                'circle-pitch-alignment': 'map'
            }
        });

        layersReady = true;
        bindMapInteractions();
    }

    map.on('style.load', () => {
        initLayers();
        if (!renderStarted) { renderStarted = true; requestAnimationFrame(renderLoop); }
    });

    let lastTheme = getCurrentTheme();
    new MutationObserver(() => {
        const newTheme = getCurrentTheme();
        if (newTheme !== lastTheme) {
            lastTheme = newTheme;
            layersReady = false;
            map.setStyle(MAP_STYLES[newTheme]);
        }
    }).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

    /* ══════════════════════════════════════════════════════════
       6. RENDER LOOP
    ══════════════════════════════════════════════════════════ */
    function renderLoop(time) {
        if (!map.isStyleLoaded() || !layersReady) return requestAnimationFrame(renderLoop);

        // Rotação do globo
        if (!paused && !userInteracting && rotSpeed > 0 && map.getProjection().name === 'globe') {
            const c = map.getCenter();
            c.lng -= rotSpeed;
            map.jumpTo({ center: c });
        }

        const dc = DEST_COLOR[getCurrentTheme()];
        const t = time / 1000;
        const now = Date.now();

        // Pulso do destino
        const pulse = Math.sin(t * 2.8) * 0.5 + 0.5; // 0…1
        const pulse2 = Math.sin(t * 1.4) * 0.5 + 0.5;
        try {
            map.setPaintProperty('dest-halo', 'circle-opacity', 0.20 + pulse * 0.25);
            map.setPaintProperty('dest-halo', 'circle-radius', 14 + pulse * 7);
            map.setPaintProperty('dest-halo2', 'circle-opacity', 0.05 + pulse2 * 0.08);
            map.setPaintProperty('dest-halo2', 'circle-radius', 24 + pulse2 * 12);
            map.setPaintProperty('dest-halo', 'circle-color', dc);
            map.setPaintProperty('dest-halo2', 'circle-color', dc);
            map.setPaintProperty('dest-core', 'circle-color', dc);
        } catch (e) { }

        // Flashes de impacto
        impactFlashes = impactFlashes.filter(f => (now - f.born) < f.duration);

        // Gera features
        const pF = []; // pontos
        const lF = []; // linhas nítidas
        const gF = []; // glow normal
        const gF2 = []; // glow difuso
        const iF = []; // impactos

        // Flashes de impacto
        impactFlashes.forEach(f => {
            const life = (now - f.born) / f.duration;
            const radius = f.maxRadius * Math.sin(life * Math.PI);
            const opacity = Math.pow(1 - life, 1.5) * 0.7;
            iF.push({
                type: 'Feature',
                properties: { radius, color: f.color, opacity },
                geometry: { type: 'Point', coordinates: f.coords }
            });
        });

        activeEvents = activeEvents
            .filter(ev => (now - ev.born) < trailDuration)
            .slice(-maxEvents);

        const scaleM = { critical: 1.9, high: 1.5, medium: 1.2, low: 0.95 };
        const widthM = { critical: 2.8, high: 2.2, medium: 1.7, low: 1.3 };

        activeEvents.forEach(ev => {
            const elapsed = now - ev.born;
            const life = elapsed / trailDuration;
            // Fade in rápido, fade out suave no final
            const fadeIn = Math.min(1, life / 0.08);
            const fadeOut = life > 0.75 ? Math.pow(1 - ((life - 0.75) / 0.25), 1.5) : 1;
            const fade = fadeIn * fadeOut;

            const color = SEV_COLORS[ev.severity];
            const scale = scaleM[ev.severity] || 1;
            const width = widthM[ev.severity] || 2;

            // Ponto de origem (pulsante)
            const srcPulse = 0.8 + Math.sin(now / 300 + ev.id.charCodeAt(0)) * 0.2;
            pF.push({
                type: 'Feature',
                properties: {
                    id: ev.id,
                    color,
                    scale: scale * srcPulse,
                    opacity: fade,
                    haloOpacity: fade * 0.45,
                    isHead: false
                },
                geometry: { type: 'Point', coordinates: [ev.src_lon, ev.src_lat] }
            });

            // Progresso da linha: começa devagar, acelera
            const rawProgress = Math.min(1, life / 0.55);
            const fp = Math.pow(rawProgress, 0.7); // ease-out suave

            if (fp > 0.005) {
                const coords = buildTrailCoords(ev, fp, 40);

                // Linha nítida
                lF.push({
                    type: 'Feature',
                    properties: { color, opacity: fade * 0.90, width },
                    geometry: { type: 'LineString', coordinates: coords }
                });

                // Glow médio
                gF.push({
                    type: 'Feature',
                    properties: { color, opacity: fade * 0.75, width },
                    geometry: { type: 'LineString', coordinates: coords }
                });

                // Glow difuso (apenas para critical/high)
                if (ev.severity === 'critical' || ev.severity === 'high') {
                    gF2.push({
                        type: 'Feature',
                        properties: { color, opacity: fade * 0.6, width },
                        geometry: { type: 'LineString', coordinates: coords }
                    });
                }

                // Cabeça do rastro — ponto viajante
                if (fp < 0.99) {
                    const headCoord = coords[coords.length - 1];
                    const headPulse = 0.85 + Math.sin(now / 120) * 0.15;
                    pF.push({
                        type: 'Feature',
                        properties: {
                            id: ev.id + '_h',
                            color,
                            scale: scale * headPulse * 1.1,
                            opacity: fade,
                            haloOpacity: fade * 0.65,
                            isHead: true
                        },
                        geometry: { type: 'Point', coordinates: headCoord }
                    });
                } else if (!ev._impacted) {
                    // Disparar flash de impacto ao chegar
                    ev._impacted = true;
                    impactFlashes.push({
                        born: now,
                        duration: ev.severity === 'critical' ? 1200 : 800,
                        maxRadius: { critical: 32, high: 24, medium: 18, low: 14 }[ev.severity],
                        color,
                        coords: [ev.dest_lon, ev.dest_lat]
                    });
                }
            }
        });

        // Atualiza fontes
        try {
            map.getSource('events-points').setData({ type: 'FeatureCollection', features: pF });
            map.getSource('events-lines').setData({ type: 'FeatureCollection', features: lF });
            map.getSource('events-glow').setData({ type: 'FeatureCollection', features: gF });
            map.getSource('events-glow2').setData({ type: 'FeatureCollection', features: gF2 });
            map.getSource('impact-points').setData({ type: 'FeatureCollection', features: iF });
        } catch (e) { }

        requestAnimationFrame(renderLoop);
    }

    /* ══════════════════════════════════════════════════════════
       7. API POLLING
    ══════════════════════════════════════════════════════════ */
    async function loadMapOverview() {
        if (paused) return;
        try {
            const res = await fetch(`/mapa/api/overview/?period=${currentPeriod}&sev=${sevFilter}`);
            if (!res.ok) throw new Error('Erro ao buscar mapa');
            const data = await res.json();
            processApiData(data);
        } catch (e) { console.error('Falha na API Map Overview:', e); }
    }

    function processApiData(data) {
        const badge = document.getElementById('mapModeBadge');
        if (badge) {
            badge.style.display = 'inline-block';
            badge.textContent = data.mode === 'demo' ? 'DEMO' : 'PROD';
            badge.style.color = data.mode === 'demo' ? '#eab308' : '#22c55e';
            badge.style.border = `1px solid ${data.mode === 'demo' ? 'rgba(234,179,8,.3)' : 'rgba(34,197,94,.3)'}`;
            badge.style.backgroundColor = data.mode === 'demo' ? 'rgba(234,179,8,.1)' : 'rgba(34,197,94,.1)';
        }

        const events = data.events || [];
        events.forEach(ev => {
            if (!seenIds.has(ev.id)) {
                seenIds.add(ev.id);
                ev.born = Date.now();
                addToGlobe(ev);
                addToFeed(ev);
            }
        });

        if (seenIds.size > 1500) {
            seenIds = new Set(Array.from(seenIds).slice(-800));
        }

        const kpis = data.kpis || {};
        const elRate = document.getElementById('tg-kpi-rate');
        const elCrit = document.getElementById('tg-kpi-critical');
        const elTop = document.getElementById('tg-kpi-top-country');
        const elTotal = document.getElementById('tg-kpi-total');

        if (elRate) elRate.textContent = kpis.rate || 0;
        if (elTotal) elTotal.textContent = kpis.session_total || sessionTotal;
        if (elCrit) elCrit.textContent = document.querySelectorAll('.tg-fi-icon--critical').length || kpis.critical || 0;
        if (elTop && kpis.top_country !== '--') elTop.textContent = kpis.top_country;
    }

    function addToGlobe(ev) {
        if (sevFilter !== 'all' && ev.severity !== sevFilter) return;
        activeEvents.push(ev);
    }

    /* ══════════════════════════════════════════════════════════
       8. LIVE FEED
    ══════════════════════════════════════════════════════════ */
    const feedEl = document.getElementById('tg-live-feed');
    const feedCount_el = document.getElementById('tg-feed-count');
    const detailsEl = document.getElementById('tg-event-details');

    function sev2abbr(s) {
        return { critical: 'CRIT', high: 'ALTO', medium: 'MED', low: 'LOW' }[s] || s;
    }

    function addToFeed(ev) {
        if (feedFilter !== 'all' && ev.source !== feedFilter) return;
        feedCount++; sessionTotal++;
        feedCount_el.textContent = feedCount > 999 ? '999+' : feedCount;

        const el = document.createElement('div');
        el.className = `tg-feed-item tg-feed-item--${ev.severity}`;
        el.dataset.id = ev.id;
        el.innerHTML = `
            <div class="tg-fi-icon tg-fi-icon--${ev.severity}">${sev2abbr(ev.severity)}</div>
            <div class="tg-fi-body">
                <div class="tg-fi-top">
                    <span class="tg-fi-asn">${ev.asn}</span>
                    <span class="tg-fi-time">${ev.timestamp}</span>
                </div>
                <div class="tg-fi-ip">${ev.src_ip}</div>
                <div class="tg-fi-sig">${ev.signature}</div>
                <div class="tg-fi-meta">
                    <span class="tg-fi-flag">${ev.src_flag}</span>
                    <span class="tg-fi-country">${ev.src_city} · ${ev.src_country}</span>
                    <span class="tg-fi-src-badge tg-fi-src-badge--${ev.source}">${ev.source}</span>
                </div>
            </div>`;
        el.addEventListener('click', () => selectEvent(ev, el));
        feedEl.insertBefore(el, feedEl.firstChild);
        while (feedEl.children.length > 80) feedEl.removeChild(feedEl.lastChild);
    }

    function selectEvent(ev, el) {
        document.querySelectorAll('.tg-feed-item').forEach(e => e.classList.remove('tg-feed-item--active'));
        if (el) el.classList.add('tg-feed-item--active');

        document.getElementById('tg-det-sev-badge').textContent = ev.severity.toUpperCase();
        document.getElementById('tg-det-sev-badge').className = `tg-det-sev-badge tg-det-sev-badge--${ev.severity}`;
        document.getElementById('tg-det-source').textContent = ev.source;
        document.getElementById('tg-det-time').textContent = ev.timestamp;
        document.getElementById('tg-det-asn-hero').textContent = ev.asn;
        document.getElementById('tg-det-ip-big').textContent = ev.src_ip;
        document.getElementById('tg-det-country').textContent = `${ev.src_flag} ${ev.src_city} · ${ev.src_country}`;
        document.getElementById('tg-det-coords').textContent = `${ev.src_lat.toFixed(2)}°, ${ev.src_lon.toFixed(2)}°`;
        document.getElementById('tg-det-ip').textContent = ev.src_ip;
        document.getElementById('tg-det-asn').textContent = ev.asn;
        document.getElementById('tg-det-dest').textContent = `${ev.dest_ip} (sensor)`;
        document.getElementById('tg-det-port').textContent = `${ev.port} · ${ev.proto}`;
        document.getElementById('tg-det-sig').textContent = ev.signature;

        detailsEl.classList.add('visible');
        map.easeTo({ center: [ev.src_lon, ev.src_lat], zoom: 3.5, duration: 1500, essential: true });
    }

    /* ══════════════════════════════════════════════════════════
       9. INTERAÇÕES DE MAPA
    ══════════════════════════════════════════════════════════ */
    const tooltip = document.getElementById('tg-tooltip');

    function onHoverMove(e) {
        if (!e.features.length) return;
        map.getCanvas().style.cursor = 'pointer';
        const id = e.features[0].properties.id;
        const ev = activeEvents.find(a => a.id === id || (id && id.startsWith(a.id)));
        if (!ev) return;
        tooltip.style.display = 'block';
        tooltip.style.left = (e.point.x + 16) + 'px';
        tooltip.style.top = (e.point.y - 12) + 'px';
        tooltip.querySelector('.tg-gt__ip').textContent = ev.src_ip;
        tooltip.querySelector('.tg-gt__info').textContent = `${ev.src_flag} ${ev.src_city} · ${ev.src_country}`;
        const sevEl = tooltip.querySelector('.tg-gt__sev');
        sevEl.textContent = ev.severity.toUpperCase();
        sevEl.style.color = SEV_COLORS[ev.severity];
        sevEl.style.textShadow = `0 0 10px ${SEV_GLOW[ev.severity]}`;
    }

    function onHoverLeave() {
        map.getCanvas().style.cursor = '';
        tooltip.style.display = 'none';
    }

    function onClickAttacker(e) {
        if (!e.features.length) return;
        const id = e.features[0].properties.id;
        const ev = activeEvents.find(a => a.id === id);
        if (ev) selectEvent(ev, document.querySelector(`.tg-feed-item[data-id="${ev.id}"]`));
    }

    let interactionsBound = false;
    function bindMapInteractions() {
        if (interactionsBound) {
            ['attackers-core', 'trail-head-core'].forEach(layer => {
                map.off('mousemove', layer, onHoverMove);
                map.off('mouseleave', layer, onHoverLeave);
                map.off('click', layer, onClickAttacker);
            });
        }
        ['attackers-core', 'trail-head-core'].forEach(layer => {
            map.on('mousemove', layer, onHoverMove);
            map.on('mouseleave', layer, onHoverLeave);
            map.on('click', layer, onClickAttacker);
        });
        interactionsBound = true;
    }

    /* ══════════════════════════════════════════════════════════
       10. BOTÕES E FILTROS
    ══════════════════════════════════════════════════════════ */
    const tgBody = document.getElementById('tg-body');

    document.getElementById('tg-toggle-panels').addEventListener('click', function () {
        tgBody.classList.toggle('panels-hidden');
        const hidden = tgBody.classList.contains('panels-hidden');
        document.getElementById('tg-panels-label').textContent = hidden ? 'Mostrar Painéis' : 'Ocultar Painéis';
        this.classList.toggle('active', hidden);
        setTimeout(() => map.resize(), 400);
    });

    document.getElementById('tg-btn-projection').addEventListener('click', function () {
        is2DMap = !is2DMap;
        if (is2DMap) {
            map.setProjection('mercator');
            map.easeTo({ pitch: 0, bearing: 0, zoom: 1.5, duration: 1200 });
            document.getElementById('tg-proj-label').textContent = 'Globo 3D';
            document.getElementById('tg-proj-icon').innerHTML = `<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>`;
        } else {
            map.setProjection('globe');
            document.getElementById('tg-proj-label').textContent = 'Mapa 2D';
            document.getElementById('tg-proj-icon').innerHTML = `<rect x="2" y="6" width="20" height="12" rx="2"/><line x1="2" y1="12" x2="22" y2="12"/>`;
        }
    });

    const pauseBtn = document.getElementById('tg-btn-pause');
    pauseBtn.addEventListener('click', () => {
        paused = !paused;
        document.getElementById('tg-pause-label').textContent = paused ? 'Retomar' : 'Pausar';
        document.getElementById('tg-pause-icon').innerHTML = paused
            ? '<polygon points="5 3 19 12 5 21 5 3"/>'
            : '<rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/>';
        pauseBtn.style.color = paused ? '#ff2d55' : '';
    });

    document.getElementById('tg-btn-clear').addEventListener('click', () => {
        activeEvents = [];
        impactFlashes = [];
        feedEl.innerHTML = '';
        feedCount = 0;
        feedCount_el.textContent = '0';
        sessionTotal = 0;
    });

    document.getElementById('tg-btn-cinema').addEventListener('click', function () {
        cinemaMode = !cinemaMode;
        document.getElementById('tgWrapper').classList.toggle('modo-cinema', cinemaMode);
        this.classList.toggle('active', cinemaMode);
        this.innerHTML = cinemaMode
            ? `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3m0 18h3a2 2 0 0 0 2-2v-3M3 16v3a2 2 0 0 0 2 2h3"/></svg> Sair Cinema`
            : `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="7" width="20" height="15" rx="2"/><path d="M16 2l-4 5-4-5"/></svg> Modo Cinema`;
        setTimeout(() => map.resize(), 300);
    });

    document.getElementById('tg-filters-toggle').addEventListener('click', () => { tgBody.classList.add('left-collapsed'); setTimeout(() => map.resize(), 400); });
    document.getElementById('tg-open-filters').addEventListener('click', () => { tgBody.classList.remove('left-collapsed'); setTimeout(() => map.resize(), 400); });
    document.getElementById('tg-det-close').addEventListener('click', () => {
        detailsEl.classList.remove('visible');
        document.querySelectorAll('.tg-feed-item').forEach(e => e.classList.remove('tg-feed-item--active'));
    });

    // Chips de severidade
    document.querySelectorAll('.tg-chip').forEach(btn => btn.addEventListener('click', () => {
        document.querySelectorAll('.tg-chip').forEach(b => b.classList.remove('tg-chip--active'));
        btn.classList.add('tg-chip--active');
        sevFilter = btn.dataset.sev;
        loadMapOverview();
    }));

    // Range de tempo
    document.querySelectorAll('.tg-seg__btn').forEach(btn => btn.addEventListener('click', () => {
        document.querySelectorAll('.tg-seg__btn').forEach(b => b.classList.remove('tg-seg__btn--active'));
        btn.classList.add('tg-seg__btn--active');
        currentPeriod = btn.dataset.range;
        loadMapOverview();
    }));

    // Sliders
    document.getElementById('tg-filter-trail').addEventListener('input', e => {
        trailDuration = parseInt(e.target.value) * 1000;
        document.getElementById('tg-trail-val').textContent = e.target.value + 's';
    });
    document.getElementById('tg-filter-max-events').addEventListener('input', e => {
        maxEvents = parseInt(e.target.value);
        document.getElementById('tg-maxevt-val').textContent = e.target.value;
    });
    document.getElementById('tg-filter-rotation').addEventListener('input', e => {
        rotSpeed = (parseInt(e.target.value) / 10) * 0.1;
        document.getElementById('tg-rot-val').textContent = (parseInt(e.target.value) / 10).toFixed(1) + '×';
    });

    document.getElementById('tg-feed-src-filter').addEventListener('change', e => { feedFilter = e.target.value; });

    document.getElementById('tg-search').addEventListener('input', e => {
        const q = e.target.value.toLowerCase();
        document.querySelectorAll('.tg-feed-item').forEach(item => {
            item.style.display = item.textContent.toLowerCase().includes(q) ? '' : 'none';
        });
    });

    document.getElementById('tg-btn-copy-ioc')?.addEventListener('click', () => {
        const ip = document.getElementById('tg-det-ip')?.textContent;
        const lb = document.getElementById('tg-copy-label');
        if (ip && ip !== '—') {
            navigator.clipboard.writeText(ip).then(() => {
                lb.textContent = 'Copiado!';
                setTimeout(() => { lb.textContent = 'Copiar IOC'; }, 2000);
            });
        }
    });

    /* ══════════════════════════════════════════════════════════
       11. BOOT & POLLING
    ══════════════════════════════════════════════════════════ */
    loadMapOverview();
    setInterval(loadMapOverview, 4000);

})();