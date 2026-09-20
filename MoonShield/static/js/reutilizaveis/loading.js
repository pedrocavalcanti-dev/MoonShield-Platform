(() => {
  "use strict";

  const resolve = (target) => typeof target === "string" ? document.querySelector(target) : target;
  const rowsFor = (variant) => ({
    number: ["ms-skeleton-title", "ms-skeleton-number", "ms-skeleton-text"],
    chart: ["ms-skeleton-title", "ms-skeleton-chart"],
    table: ["ms-skeleton-table", "ms-skeleton-table", "ms-skeleton-table", "ms-skeleton-table"],
    list: ["ms-skeleton-list", "ms-skeleton-list", "ms-skeleton-list"],
    card: ["ms-skeleton-title", "ms-skeleton-number", "ms-skeleton-text"],
  }[variant] || ["ms-skeleton-title", "ms-skeleton-text", "ms-skeleton-text"]);

  function layerFor(element, options = {}) {
    let layer = element.querySelector(":scope > .ms-loading-layer");
    if (layer) return layer;
    layer = document.createElement("div");
    layer.className = "ms-loading-layer";
    layer.dataset.msLoading = options.variant || "default";
    layer.setAttribute("aria-hidden", "true");
    rowsFor(options.variant).forEach((className) => {
      const item = document.createElement("span");
      item.className = "ms-skeleton " + className;
      layer.appendChild(item);
    });
    element.appendChild(layer);
    return layer;
  }

  function start(target, options = {}) {
    const element = resolve(target);
    if (!element) return null;
    layerFor(element, options);
    element.classList.add("ms-loading-target", "ms-is-loading");
    element.classList.remove("ms-has-error");
    element.setAttribute("aria-busy", "true");
    return element;
  }

  function finish(target) {
    const element = resolve(target);
    if (!element) return null;
    element.classList.remove("ms-is-loading", "ms-is-refreshing");
    element.setAttribute("aria-busy", "false");
    return element;
  }

  function error(target, options = {}) {
    const element = finish(target);
    if (!element) return null;
    element.classList.add("ms-has-error");
    if (options.message) element.dataset.msLoadingError = options.message;
    return element;
  }

  function setPageLoading(value) {
    document.documentElement.classList.toggle("ms-page-loading", Boolean(value));
    document.getElementById("appContent")?.setAttribute("aria-busy", String(Boolean(value)));
  }

  function setRefreshing(target, value) {
    const element = resolve(target);
    if (!element) return null;
    element.classList.toggle("ms-is-refreshing", Boolean(value));
    element.setAttribute("aria-busy", String(Boolean(value)));
    return element;
  }

  const CACHE_TTL_MS = 120 * 1000;
    const memoryCache = new Map();
  const cache = {
      get(key) {
          try {
              let payload = null;
              try {
                  const str = sessionStorage.getItem(key);
                  if (str) payload = JSON.parse(str);
              } catch(e) {}

              if (!payload && memoryCache.has(key)) {
                  payload = memoryCache.get(key);
              }

              if (!payload || payload.version !== 1) return null;
              if (Date.now() - payload.savedAt > CACHE_TTL_MS) {
                payload.data._isStale = true;
            }
              return payload.data;
          } catch (e) {
              return null;
          }
      },
      set(key, data) {
          try {
              const payload = {
                  version: 1,
                  savedAt: Date.now(),
                  data: data
              };
              memoryCache.set(key, payload);
              try {
                  sessionStorage.setItem(key, JSON.stringify(payload));
              } catch (e) {}
          } catch (e) {}
      },
      remove(key) {
          try { memoryCache.delete(key); } catch (e) {}
          try { sessionStorage.removeItem(key); } catch (e) {}
      }
  };

  const pendingRequests = new Map();
  function fetchCoalesced(url, options = {}) {
      if (options.method && options.method.toUpperCase() !== 'GET') {
          return fetch(url, options);
      }
      if (pendingRequests.has(url)) {
          return pendingRequests.get(url).then(r => r.clone());
      }
      const p = fetch(url, options).finally(() => pendingRequests.delete(url));
      pendingRequests.set(url, p);
      return p.then(r => r.clone());
  }

  const visibility = {
      _callbacks: [],
      onVisible(cb) {
          if (this._callbacks.length === 0) {
              document.addEventListener('visibilitychange', () => {
                  if (document.visibilityState === 'visible') {
                      this._callbacks.forEach(fn => fn());
                  }
              });
          }
          this._callbacks.push(cb);
      },
      isHidden() {
          return document.visibilityState === 'hidden';
      }
  };

  window.MoonShieldLoading = { start, finish, error, setPageLoading, setRefreshing, cache, visibility, fetchCoalesced };
})();
