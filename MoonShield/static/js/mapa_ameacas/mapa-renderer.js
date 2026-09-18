(function () {
    'use strict';

    let map = null;
    let layersReady = false;
    let renderStarted = false;
    let lastTime = 0;

    let nodeCoords = null;
    let activeEvents = [];
    let impactFlashes = [];

    let rotSpeed = 0.05;
    let trailDuration = 15000;
    let isPaused = false;
    let currentTheme = 'dark';
    let isGlobe = true;
    let userInteracting = false;
    let prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

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
            'star-intensity': 0.12
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

    const SEV_COLORS = {
        critical: '#ff2d55',
        high: '#ff6b00',
        medium: '#ffd60a',
        low: '#0a84ff',
        info: '#64d2ff'
    };

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

    function buildTrailCoords(lon1, lat1, lon2, lat2, progress, n = 36) {
        const coords = [];
        for (let i = 0; i <= n; i++) {
            coords.push(slerp(lon1, lat1, lon2, lat2, (i / n) * progress));
        }
        return coords;
    }

    function initLayers() {
        if (!map) return;

        map.setFog(FOG_CONFIG[currentTheme]);
        const dc = DEST_COLOR[currentTheme];

        const addSrc = (id, data) => {
            if (!map.getSource(id)) map.addSource(id, { type: 'geojson', data });
        };
        const emptyFC = { type: 'FeatureCollection', features: [] };

        addSrc('events-points', emptyFC);
        addSrc('events-lines', emptyFC);
        addSrc('impact-points', emptyFC);
        addSrc('dest-point', emptyFC); // Initially empty

        if (!map.getLayer('dest-halo2')) map.addLayer({
            id: 'dest-halo2', type: 'circle', source: 'dest-point',
            paint: {
                'circle-radius': 28, 'circle-color': dc, 'circle-opacity': 0.10,
                'circle-blur': 0.8, 'circle-pitch-alignment': 'map'
            }
        });
        if (!map.getLayer('dest-halo')) map.addLayer({
            id: 'dest-halo', type: 'circle', source: 'dest-point',
            paint: {
                'circle-radius': 16, 'circle-color': dc, 'circle-opacity': 0.32,
                'circle-blur': 0.35, 'circle-stroke-width': 1, 'circle-stroke-color': dc,
                'circle-pitch-alignment': 'map'
            }
        });
        if (!map.getLayer('dest-core')) map.addLayer({
            id: 'dest-core', type: 'circle', source: 'dest-point',
            paint: {
                'circle-radius': 4, 'circle-color': dc, 'circle-pitch-alignment': 'map'
            }
        });

        if (!map.getLayer('impact-flash')) map.addLayer({
            id: 'impact-flash', type: 'circle', source: 'impact-points',
            paint: {
                'circle-radius': ['get', 'radius'], 'circle-color': ['get', 'color'],
                'circle-opacity': ['get', 'opacity'], 'circle-blur': 0.5, 'circle-pitch-alignment': 'map'
            }
        });

        if (!map.getLayer('attack-lines')) map.addLayer({
            id: 'attack-lines', type: 'line', source: 'events-lines',
            paint: {
                'line-color': ['get', 'color'], 'line-width': ['get', 'width'],
                'line-blur': 0.6, 'line-opacity': ['get', 'opacity']
            }
        });

        if (!map.getLayer('attackers-halo')) map.addLayer({
            id: 'attackers-halo', type: 'circle', source: 'events-points',
            filter: ['!=', ['get', 'isHead'], true],
            paint: {
                'circle-radius': ['*', ['get', 'scale'], 15], 'circle-color': ['get', 'color'],
                'circle-opacity': ['*', ['get', 'haloOpacity'], 0.50], 'circle-blur': 0.85, 'circle-pitch-alignment': 'map'
            }
        });
        if (!map.getLayer('attackers-core')) map.addLayer({
            id: 'attackers-core', type: 'circle', source: 'events-points',
            filter: ['!=', ['get', 'isHead'], true],
            paint: {
                'circle-radius': ['*', ['get', 'scale'], 3.5], 'circle-color': '#ffffff',
                'circle-stroke-width': 1.5, 'circle-stroke-color': ['get', 'color'],
                'circle-opacity': ['get', 'opacity'], 'circle-pitch-alignment': 'map'
            }
        });
        if (!map.getLayer('trail-head-core')) map.addLayer({
            id: 'trail-head-core', type: 'circle', source: 'events-points',
            filter: ['==', ['get', 'isHead'], true],
            paint: {
                'circle-radius': ['*', ['get', 'scale'], 4.0], 'circle-color': '#ffffff',
                'circle-stroke-width': 1.5, 'circle-stroke-color': ['get', 'color'],
                'circle-opacity': ['get', 'opacity'], 'circle-pitch-alignment': 'map'
            }
        });

        layersReady = true;
    }

    function renderLoop(time) {
        if (!renderStarted) return;
        requestAnimationFrame(renderLoop);

        const deltaTime = (time - lastTime) / 1000 || 0;
        lastTime = time;

        if (!map || !map.isStyleLoaded() || !layersReady) return;

        if (!isPaused && !userInteracting && isGlobe && rotSpeed > 0 && !prefersReducedMotion) {
            const c = map.getCenter();
            c.lng -= (rotSpeed * 10 * deltaTime);
            map.jumpTo({ center: c });
        }

        const now = Date.now();

        if (nodeCoords && !prefersReducedMotion) {
            const pulse = Math.sin(time / 400) * 0.5 + 0.5;
            const pulse2 = Math.sin(time / 800) * 0.5 + 0.5;
            try {
                map.setPaintProperty('dest-halo', 'circle-opacity', 0.20 + pulse * 0.25);
                map.setPaintProperty('dest-halo', 'circle-radius', 14 + pulse * 7);
                map.setPaintProperty('dest-halo2', 'circle-opacity', 0.05 + pulse2 * 0.08);
                map.setPaintProperty('dest-halo2', 'circle-radius', 24 + pulse2 * 12);
            } catch (e) {}
        }

        impactFlashes = impactFlashes.filter(f => (now - f.born) < f.duration);

        if (activeEvents.length === 0 && impactFlashes.length === 0) {
            try {
                map.getSource('events-points').setData({ type: 'FeatureCollection', features: [] });
                map.getSource('events-lines').setData({ type: 'FeatureCollection', features: [] });
                map.getSource('impact-points').setData({ type: 'FeatureCollection', features: [] });
            } catch(e) {}
            return;
        }

        const pF = [];
        const lF = [];
        const iF = [];

        impactFlashes.forEach(f => {
            const life = (now - f.born) / f.duration;
            const radius = f.maxRadius * Math.sin(life * Math.PI);
            const opacity = Math.pow(1 - life, 1.5) * 0.7;
            if (!prefersReducedMotion) {
                iF.push({
                    type: 'Feature', properties: { radius, color: f.color, opacity },
                    geometry: { type: 'Point', coordinates: f.coords }
                });
            }
        });

        activeEvents = activeEvents.filter(ev => (now - ev.born) < trailDuration);

        activeEvents.forEach(ev => {
            const life = (now - ev.born) / trailDuration;
            const fadeIn = Math.min(1, life / 0.08);
            const fadeOut = life > 0.75 ? Math.pow(1 - ((life - 0.75) / 0.25), 1.5) : 1;
            const fade = prefersReducedMotion ? (life < 1 ? 1 : 0) : (fadeIn * fadeOut);

            const color = SEV_COLORS[ev.severity] || SEV_COLORS.low;
            const baseScale = { critical: 1.6, high: 1.3, medium: 1.1, low: 0.9, info: 0.8 }[ev.severity] || 1;

            const countFactor = Math.min(Math.log2((ev.count || 1) + 1) * 0.15, 0.6);
            const scale = baseScale + countFactor;

            const baseWidth = { critical: 2.2, high: 1.8, medium: 1.4, low: 1.2, info: 1.0 }[ev.severity] || 1.5;
            const width = baseWidth + (countFactor * 2);

            const srcPulse = prefersReducedMotion ? 1 : 0.8 + Math.sin(now / 300 + ev.id.charCodeAt(0)) * 0.2;
            pF.push({
                type: 'Feature',
                properties: { id: ev.id, color, scale: scale * srcPulse, opacity: fade, haloOpacity: fade * 0.45, isHead: false },
                geometry: { type: 'Point', coordinates: [ev.src_lon, ev.src_lat] }
            });

            const rawProgress = Math.min(1, life / 0.55);
            const fp = prefersReducedMotion ? rawProgress : Math.pow(rawProgress, 0.7);

            if (fp > 0.005) {
                const coords = buildTrailCoords(ev.src_lon, ev.src_lat, ev.dest_lon, ev.dest_lat, fp, 40);

                lF.push({
                    type: 'Feature',
                    properties: { color, opacity: fade * 0.90, width },
                    geometry: { type: 'LineString', coordinates: coords }
                });

                if (fp < 0.99) {
                    const headCoord = coords[coords.length - 1];
                    const headPulse = prefersReducedMotion ? 1 : 0.85 + Math.sin(now / 120) * 0.15;
                    pF.push({
                        type: 'Feature',
                        properties: { id: ev.id + '_h', color, scale: scale * headPulse * 1.1, opacity: fade, haloOpacity: fade * 0.65, isHead: true },
                        geometry: { type: 'Point', coordinates: headCoord }
                    });
                } else if (!ev._impacted && !prefersReducedMotion) {
                    ev._impacted = true;
                    impactFlashes.push({
                        born: now,
                        duration: ev.severity === 'critical' ? 1000 : 700,
                        maxRadius: { critical: 24, high: 18, medium: 14, low: 10, info: 8 }[ev.severity] || 10,
                        color,
                        coords: [ev.dest_lon, ev.dest_lat]
                    });
                }
            }
        });

        try {
            map.getSource('events-points').setData({ type: 'FeatureCollection', features: pF });
            map.getSource('events-lines').setData({ type: 'FeatureCollection', features: lF });
            map.getSource('impact-points').setData({ type: 'FeatureCollection', features: iF });
        } catch (e) {}
    }

    const MoonShieldThreatMapRenderer = {
        init: function (options) {
            if (map) return;
            currentTheme = options.theme || 'dark';
            try {
                if (!options.token) {
                    if (options.onError) options.onError("Token não fornecido");
                    return;
                }
                mapboxgl.accessToken = options.token;
                map = new mapboxgl.Map({
                    container: options.containerId,
                    style: MAP_STYLES[currentTheme],
                    center: [0, 20],
                    zoom: 1.35,
                    projection: 'globe',
                    attributionControl: false,
                    failIfMajorPerformanceCaveat: false
                });

                map.on('error', event => {
                    if (options.onError) {
                        options.onError(event.error || event);
                    }
                });

                map.addControl(new mapboxgl.NavigationControl({ showCompass: true, showZoom: true, visualizePitch: true }), 'bottom-right');

                ['mousedown', 'dragstart', 'touchstart'].forEach(ev => {
                    map.on(ev, () => { userInteracting = true; });
                });
                ['mouseup', 'dragend', 'touchend'].forEach(ev => {
                    map.on(ev, () => { setTimeout(() => { userInteracting = false; }, 1000); });
                });

                map.on('style.load', () => {
                    initLayers();
                    if (nodeCoords) this.setNode(nodeCoords);
                    if (options.onReady) options.onReady();
                });

                lastTime = performance.now();
                renderStarted = true;
                requestAnimationFrame(renderLoop);

            } catch (e) {
                if (options.onError) options.onError(e);
            }
        },

        setNode: function (node) {
            if (!node || node.latitude == null || node.longitude == null) {
                this.hideNode();
                return;
            }
            nodeCoords = node;
            if (map && map.getSource('dest-point')) {
                map.getSource('dest-point').setData({
                    type: 'Feature',
                    geometry: { type: 'Point', coordinates: [node.longitude, node.latitude] }
                });
            }
        },

        hideNode: function () {
            nodeCoords = null;
            if (map && map.getSource('dest-point')) {
                map.getSource('dest-point').setData({ type: 'FeatureCollection', features: [] });
            }
        },

        setEvents: function (events) {
            const now = Date.now();
            events.forEach(ev => {
                if (!ev.born) ev.born = now;
            });
            activeEvents = events;
        },

        addArc: function (event) {
            if (!event.born) event.born = Date.now();
            activeEvents.push(event);
        },

        focusEvent: function (event) {
            if (event.external_lon != null && event.external_lat != null) {
                if (map) map.flyTo({ center: [event.external_lon, event.external_lat], zoom: 3.5, duration: prefersReducedMotion ? 0 : 1500 });
            }
        },

        focusNode: function () {
            if (nodeCoords && nodeCoords.longitude != null && nodeCoords.latitude != null) {
                if (map) map.flyTo({ center: [nodeCoords.longitude, nodeCoords.latitude], zoom: 2.5, duration: prefersReducedMotion ? 0 : 1500 });
            }
        },

        resetView: function () {
            if (map) map.flyTo({ center: [0, 20], zoom: 1.35, duration: prefersReducedMotion ? 0 : 1500 });
        },

        clear: function () {
            activeEvents = [];
            impactFlashes = [];
            if (map && layersReady) {
                try {
                    map.getSource('events-points').setData({ type: 'FeatureCollection', features: [] });
                    map.getSource('events-lines').setData({ type: 'FeatureCollection', features: [] });
                    map.getSource('impact-points').setData({ type: 'FeatureCollection', features: [] });
                } catch(e){}
            }
        },

        setProjection: function (mode) {
            if (!map) return;
            isGlobe = (mode === 'globe');
            map.setProjection(mode);
            if (!isGlobe) {
                map.easeTo({ pitch: 0, bearing: 0, duration: prefersReducedMotion ? 0 : 1200 });
            }
        },

        setRotationSpeed: function (speed) {
            rotSpeed = parseFloat(speed) || 0;
        },

        setTrailDuration: function (ms) {
            trailDuration = parseInt(ms, 10) || 15000;
        },

        setPaused: function (paused) {
            isPaused = !!paused;
        },

        setTheme: function (theme) {
            if (currentTheme === theme) return;
            currentTheme = theme;
            if (map) {
                layersReady = false;
                map.setStyle(MAP_STYLES[currentTheme]);
            }
        },

        resize: function () {
            if (map) map.resize();
        },

        isAvailable: function () {
            return !!map;
        },

        destroy: function () {
            renderStarted = false;
            if (map) {
                map.remove();
                map = null;
            }
        }
    };

    window.MoonShieldThreatMapRenderer = MoonShieldThreatMapRenderer;

    if (window.matchMedia) {
        window.matchMedia('(prefers-reduced-motion: reduce)').addEventListener('change', (e) => {
            prefersReducedMotion = e.matches;
        });
    }

})();