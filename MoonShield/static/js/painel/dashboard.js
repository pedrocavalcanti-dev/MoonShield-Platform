/**
 * MOONSHIELD — DASHBOARD.JS V12
 * Frontend do Dashboard Geral.
 * - Consome somente /painel/api/overview/
 * - Sem DEMO/MOCK/fallback sintético
 * - Skeleton global enquanto a API carrega
 * - Ataques: barras empilhadas
 * - DNS: linha/área
 * - Live Feed vertical
 * - SOC compacto e responsivo
 */

(() => {
  "use strict";

  document.addEventListener("DOMContentLoaded", () => {
    const shell = document.getElementById("dashboardShell");
    if (!shell) return;

    const SEV_TO_BACKEND = {
      all: "all",
      crit: "critico",
      high: "alto",
      med: "medio",
    };

    const COLORS = {
      red: "#ef4444",
      orange: "#f97316",
      yellow: "#eab308",
      green: "#22c55e",
      blue: "#3b82f6",
      purple: "#8b5cf6",
      cyan: "#06b6d4",
      pink: "#fb7185",
      slate: "#64748b",
    };

    const state = {
      period: "24h",
      sev: "all",
      paused: false,
      feedFilter: "all",
      lastData: null,
      lastFeed: [],
      cleared: false,
      loading: false,
      pollTimer: null,
    };

    const charts = {
      attacks: null,
      dns: null,
      timeline: null,
      categories: null,
      sensors: null,
      sparks: {},
    };

    function cssVar(name, fallback) {
      const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
      return value || fallback;
    }

    function chartTheme() {
      return {
        text: cssVar("--text-muted", "#6b7280"),
        dim: cssVar("--text-dim", "#9ca3af"),
        grid: cssVar("--border-soft", "#eef0f3"),
        card: cssVar("--bg-card", "#ffffff"),
        primary: cssVar("--text-primary", "#111827"),
      };
    }

    function configureChartDefaults() {
      if (!window.Chart) return;
      const t = chartTheme();
      Chart.defaults.color = t.dim;
      Chart.defaults.font.family = cssVar("--font-mono", "ui-monospace, SFMono-Regular, Menlo, monospace");
      Chart.defaults.font.size = 9;
      Chart.defaults.animation.duration = 280;
      Chart.defaults.plugins.legend.display = false;
      Chart.defaults.plugins.tooltip.backgroundColor = t.primary;
      Chart.defaults.plugins.tooltip.titleColor = t.card;
      Chart.defaults.plugins.tooltip.bodyColor = t.card;
      Chart.defaults.plugins.tooltip.borderWidth = 0;
      Chart.defaults.plugins.tooltip.cornerRadius = 7;
      Chart.defaults.plugins.tooltip.padding = 9;
    }

    configureChartDefaults();

    const el = (id) => document.getElementById(id);
    const setText = (id, value) => {
      const node = el(id);
      if (node) node.textContent = value;
    };

    function safeNumber(value, fallback = 0) {
      const n = Number(value);
      return Number.isFinite(n) ? n : fallback;
    }

    function formatNumber(value) {
      return safeNumber(value).toLocaleString("pt-BR");
    }

    function escapeHtml(value) {
      return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
    }

    function normalizeSeverity(value) {
      const v = String(value || "info").toLowerCase();
      if (["crit", "critical", "critico", "crítico"].includes(v)) return "crit";
      if (["high", "alto"].includes(v)) return "high";
      if (["med", "medium", "medio", "médio", "warn", "warning"].includes(v)) return "warn";
      return "info";
    }

    function severityLabel(value) {
      const sev = normalizeSeverity(value);
      return { crit: "CRÍTICO", high: "ALTO", warn: "MÉDIO", info: "INFO" }[sev];
    }

    function parseDate(value) {
      if (!value) return null;
      const d = new Date(value);
      return Number.isNaN(d.getTime()) ? null : d;
    }

    function formatClock(value) {
      const d = parseDate(value);
      if (!d) return "—";
      return d.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    }

    function formatUpdated(value) {
      const d = parseDate(value);
      if (!d) return "agora";
      return d.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" });
    }

    function setLoading(active) {
      state.loading = active;
      shell.classList.toggle("is-loading", active);
      window.MoonShieldLoading?.setPageLoading(active);
      const refresh = el("btnRefresh");
      if (refresh) refresh.disabled = active;
      el("refreshIcon")?.classList.toggle("is-spinning", active);
    }

    function showBanner(message) {
      const banner = el("dashBanner");
      const text = el("dashBannerMsg");
      if (!banner || !text) return;
      text.textContent = message;
      banner.hidden = false;
    }

    function hideBanner() {
      const banner = el("dashBanner");
      if (banner) banner.hidden = true;
    }

    async function fetchOverview() {
      const sev = SEV_TO_BACKEND[state.sev] || "all";
      const url = `/painel/api/overview/?period=${encodeURIComponent(state.period)}&sev=${encodeURIComponent(sev)}`;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10000);
      try {
        const response = await fetch(url, {
          headers: { Accept: "application/json", "X-Requested-With": "XMLHttpRequest" },
          credentials: "same-origin",
          signal: controller.signal,
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        if (data?.ok === false) throw new Error(data?.erro || data?.error || "Resposta inválida");
        return data;
      } finally {
        clearTimeout(timeout);
      }
    }

    async function renderDashboard({ silent = false } = {}) {
      if (!silent) setLoading(true);
      if (silent) window.MoonShieldLoading?.setRefreshing(shell, true);
      try {
        const data = await fetchOverview();
        state.lastData = data;
        hideBanner();

        renderHeader(data);
        renderKpis(data);
        renderMainCharts(data);
        renderFeed(data.feed || []);
        renderTopAttacks(data.intel?.top_ataques || []);
        renderTimeline(data.charts?.timeline || {});
        renderTopIPs(data.intel?.top_ips || []);
        renderCategories(data.intel?.categorias || []);
        renderHealth(data);
      } catch (error) {
        console.error("[MoonShield Dashboard] Falha ao carregar overview", error);
        showBanner(error?.name === "AbortError" ? "O Dashboard demorou mais que o esperado para responder." : "Alguns dados do Dashboard não puderam ser carregados agora.");
      } finally {
        if (!silent) setLoading(false);
        if (silent) window.MoonShieldLoading?.setRefreshing(shell, false);
      }
    }

    function renderHeader(data) {
      setText("dashNodeName", data.node?.name || "—");
      setText("dashNodeCidr", data.node?.cidr || "—");
      setText("lastUpdate", formatUpdated(data.last_update));

      const subtitle = el("attackChartSubtitle");
      if (subtitle) {
        subtitle.textContent = state.period === "24h"
          ? "Distribuição por severidade · 00h–23h"
          : `Distribuição por severidade · ${state.period}`;
      }
    }

    function animateCounter(node, target) {
      if (!node) return;
      const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches;
      if (reduce) {
        node.textContent = formatNumber(target);
        return;
      }
      const from = safeNumber(node.dataset.value, 0);
      const to = safeNumber(target, 0);
      const start = performance.now();
      const duration = 500;
      const step = (now) => {
        const p = Math.min(1, (now - start) / duration);
        const eased = 1 - Math.pow(1 - p, 3);
        node.textContent = formatNumber(Math.round(from + (to - from) * eased));
        if (p < 1) requestAnimationFrame(step);
      };
      node.dataset.value = String(to);
      requestAnimationFrame(step);
    }

    function renderKpis(data) {
      const kpi = data.kpis || {};
      animateCounter(el("kpiAmeacas"), kpi.ameacas_hoje || 0);
      animateCounter(el("kpiDns"), kpi.dns_queries || 0);
      animateCounter(el("kpiBloq"), kpi.dns_bloqueios || 0);
      setText("kpiBloqPct", `${safeNumber(kpi.bloqueio_pct).toFixed(1)}%`);

      const attacks = data.charts?.attacks || {};
      const attackTotals = combineSeries(attacks.crit, attacks.high, attacks.med);
      makeSparkline("sparkAmeacas", attackTotals, COLORS.red);
      makeSparkline("sparkDns", data.charts?.dns?.queries || [], COLORS.blue);
      makeSparkline("sparkBloq", data.charts?.dns?.blocked || [], COLORS.yellow);
      renderSensors(data);
    }

    function combineSeries(...series) {
      const size = Math.max(0, ...series.map(s => Array.isArray(s) ? s.length : 0));
      return Array.from({ length: size }, (_, i) => series.reduce((sum, s) => sum + safeNumber(s?.[i]), 0));
    }

    function makeSparkline(id, values, color) {
      const canvas = el(id);
      if (!canvas || !window.Chart) return;
      const data = Array.isArray(values) && values.length ? values.map(v => safeNumber(v)) : [0, 0, 0, 0, 0, 0];
      if (charts.sparks[id]) {
        charts.sparks[id].data.labels = data.map(() => "");
        charts.sparks[id].data.datasets[0].data = data;
        charts.sparks[id].update("none");
        return;
      }
      charts.sparks[id] = new Chart(canvas, {
        type: "line",
        data: {
          labels: data.map(() => ""),
          datasets: [{
            data,
            borderColor: color,
            borderWidth: 1.4,
            pointRadius: 0,
            tension: .38,
            fill: false,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: { intersect: false, mode: "index" },
          plugins: { legend: { display: false }, tooltip: { enabled: false } },
          scales: { x: { display: false }, y: { display: false } },
          animation: false,
        },
      });
    }

    function renderSensors(data) {
      const kpi = data.kpis || {};
      const online = safeNumber(kpi.sensores_online);
      const total = Math.max(1, safeNumber(kpi.sensores_total, 3));
      setText("radarLabel", `${online}/${total}`);

      const canvas = el("radarSensores");
      if (canvas && window.Chart) {
        const values = [online, Math.max(0, total - online)];
        if (!charts.sensors) {
          charts.sensors = new Chart(canvas, {
            type: "doughnut",
            data: {
              labels: ["Online", "Indisponível"],
              datasets: [{
                data: values,
                backgroundColor: [COLORS.green, cssVar("--border-soft", "#eef0f3")],
                borderWidth: 0,
                hoverOffset: 0,
              }],
            },
            options: {
              responsive: true,
              maintainAspectRatio: false,
              cutout: "76%",
              plugins: { tooltip: { enabled: false } },
              animation: { duration: 280 },
            },
          });
        } else {
          charts.sensors.data.datasets[0].data = values;
          charts.sensors.update("none");
        }
      }

      const list = el("sensoresList");
      if (!list) return;
      const sensors = Array.isArray(data.saude?.sensores) ? data.saude.sensores : [];
      if (!sensors.length) {
        list.innerHTML = `<div class="sensor-row"><span class="sensor-dot"></span><span>Sem telemetria disponível</span></div>`;
        return;
      }
      list.innerHTML = sensors.map(sensor => {
        const st = String(sensor.status || "err").toLowerCase();
        const cls = st === "ok" ? "sensor-dot--ok" : st === "warn" ? "sensor-dot--warn" : "sensor-dot--danger";
        const label = st === "ok" ? "Online" : st === "warn" ? "Atenção" : "Offline";
        return `<div class="sensor-row">
          <span class="sensor-dot ${cls}"></span>
          <span class="sensor-row__name">${escapeHtml(sensor.nome || "Sensor")}</span>
          <span class="sensor-row__status">${escapeHtml(label)}</span>
        </div>`;
      }).join("");
    }

    function normalize24Hours(labels, datasets) {
      const fixed = Array.from({ length: 24 }, (_, h) => `${String(h).padStart(2, "0")}h`);
      const output = datasets.map(() => Array(24).fill(0));
      if (!Array.isArray(labels)) return { labels: fixed, datasets: output };

      labels.forEach((label, index) => {
        const match = String(label).match(/(\d{1,2})/);
        if (!match) return;
        const hour = Number(match[1]);
        if (hour < 0 || hour > 23) return;
        datasets.forEach((series, sIndex) => {
          output[sIndex][hour] += safeNumber(series?.[index]);
        });
      });
      return { labels: fixed, datasets: output };
    }

    function renderMainCharts(data) {
      const theme = chartTheme();
      const hours = data.charts?.hours || [];
      const attacks = data.charts?.attacks || {};
      let attackLabels = hours;
      let attackSeries = [attacks.crit || [], attacks.high || [], attacks.med || []];

      if (state.period === "24h") {
        const normalized = normalize24Hours(hours, attackSeries);
        attackLabels = normalized.labels;
        attackSeries = normalized.datasets;
      }

      const attackCanvas = el("chartAtaques");
      if (attackCanvas && window.Chart) {
        const datasets = [
          { label: "Crítico", data: attackSeries[0], backgroundColor: COLORS.red, borderRadius: 3, borderSkipped: false, maxBarThickness: 18 },
          { label: "Alto", data: attackSeries[1], backgroundColor: COLORS.orange, borderRadius: 3, borderSkipped: false, maxBarThickness: 18 },
          { label: "Médio", data: attackSeries[2], backgroundColor: "#f3c94b", borderRadius: 3, borderSkipped: false, maxBarThickness: 18 },
        ];
        if (!charts.attacks) {
          charts.attacks = new Chart(attackCanvas, {
            type: "bar",
            data: { labels: attackLabels, datasets },
            options: {
              responsive: true,
              maintainAspectRatio: false,
              interaction: { intersect: false, mode: "index" },
              scales: {
                x: {
                  stacked: true,
                  grid: { display: false },
                  border: { display: false },
                  ticks: { color: theme.dim, maxRotation: 0, autoSkip: true, maxTicksLimit: 12, font: { size: 8 } },
                },
                y: {
                  stacked: true,
                  beginAtZero: true,
                  grid: { color: theme.grid, drawTicks: false },
                  border: { display: false },
                  ticks: { color: theme.dim, precision: 0, padding: 8, font: { size: 8 } },
                },
              },
              plugins: {
                tooltip: {
                  callbacks: {
                    footer(items) {
                      const total = items.reduce((sum, item) => sum + safeNumber(item.raw), 0);
                      return `Total: ${formatNumber(total)}`;
                    },
                  },
                },
              },
            },
          });
        } else {
          charts.attacks.data.labels = attackLabels;
          charts.attacks.data.datasets.forEach((ds, i) => { ds.data = attackSeries[i] || []; });
          charts.attacks.update("active");
        }
        setChartEmpty(attackCanvas, combineSeries(...attackSeries).every(v => v === 0), "Nenhum ataque no período");
      }

      const dns = data.charts?.dns || {};
      let dnsLabels = dns.hours || [];
      let dnsSeries = [dns.queries || [], dns.blocked || []];
      const normalizedDns = normalize24Hours(dnsLabels, dnsSeries);
      dnsLabels = normalizedDns.labels;
      dnsSeries = normalizedDns.datasets;

      const dnsCanvas = el("chartDns");
      if (dnsCanvas && window.Chart) {
        const gradient = dnsCanvas.getContext("2d").createLinearGradient(0, 0, 0, 220);
        gradient.addColorStop(0, "rgba(59,130,246,.18)");
        gradient.addColorStop(1, "rgba(59,130,246,0)");

        if (!charts.dns) {
          charts.dns = new Chart(dnsCanvas, {
            type: "line",
            data: {
              labels: dnsLabels,
              datasets: [
                {
                  label: "Consultas",
                  data: dnsSeries[0],
                  borderColor: COLORS.blue,
                  backgroundColor: gradient,
                  fill: true,
                  borderWidth: 1.8,
                  pointRadius: 0,
                  pointHoverRadius: 3,
                  tension: .34,
                },
                {
                  label: "Bloqueios",
                  data: dnsSeries[1],
                  borderColor: COLORS.pink,
                  backgroundColor: "transparent",
                  fill: false,
                  borderWidth: 1.4,
                  pointRadius: 0,
                  pointHoverRadius: 3,
                  tension: .34,
                  borderDash: [4, 4],
                },
              ],
            },
            options: {
              responsive: true,
              maintainAspectRatio: false,
              interaction: { intersect: false, mode: "index" },
              scales: {
                x: {
                  grid: { display: false },
                  border: { display: false },
                  ticks: { color: theme.dim, maxRotation: 0, autoSkip: true, maxTicksLimit: 12, font: { size: 8 } },
                },
                y: {
                  beginAtZero: true,
                  grid: { color: theme.grid, drawTicks: false },
                  border: { display: false },
                  ticks: { color: theme.dim, precision: 0, padding: 8, font: { size: 8 } },
                },
              },
            },
          });
        } else {
          charts.dns.data.labels = dnsLabels;
          charts.dns.data.datasets[0].data = dnsSeries[0];
          charts.dns.data.datasets[1].data = dnsSeries[1];
          charts.dns.update("active");
        }
        setChartEmpty(dnsCanvas, combineSeries(...dnsSeries).every(v => v === 0), "Nenhuma consulta DNS registrada");
      }
    }

    function setChartEmpty(canvas, show, message) {
      const wrap = canvas?.parentElement;
      if (!wrap) return;
      let empty = wrap.querySelector(".chart-empty");
      if (show) {
        if (!empty) {
          empty = document.createElement("div");
          empty.className = "chart-empty";
          empty.innerHTML = `<i class="bi bi-bar-chart-line"></i><span></span>`;
          wrap.appendChild(empty);
        }
        empty.querySelector("span").textContent = message;
      } else if (empty) {
        empty.remove();
      }
    }

    function renderFeed(feed) {
      if (state.paused) return;
      state.lastFeed = Array.isArray(feed) ? feed : [];
      if (!state.cleared) drawFeed();
    }

    function drawFeed() {
      const list = el("feedList");
      if (!list) return;
      const source = state.feedFilter === "all"
        ? state.lastFeed
        : state.lastFeed.filter(item => String(item.type || "").toUpperCase() === state.feedFilter);

      setText("feedCount", String(source.length));

      if (!source.length) {
        list.innerHTML = `<div class="feed-empty"><i class="bi bi-inbox"></i><strong>Nenhum evento no filtro atual</strong><span>Novos eventos aparecerão aqui automaticamente.</span></div>`;
        return;
      }

      list.innerHTML = source.map(item => {
        const sev = normalizeSeverity(item.sev);
        return `<div class="feed-item">
          <span class="feed-item__time">${escapeHtml(formatClock(item.ts))}</span>
          <span class="feed-item__source">${escapeHtml(item.type || "—")}</span>
          <div class="feed-item__body">
            <div class="feed-item__title">${escapeHtml(item.msg || "Evento detectado")}</div>
            <div class="feed-item__src">${escapeHtml(item.src || "—")}</div>
          </div>
          <span class="feed-item__severity feed-item__severity--${sev}">${severityLabel(sev)}</span>
        </div>`;
      }).join("");
    }

    function renderTopAttacks(items) {
      const container = el("intelAtaques");
      if (!container) return;
      const rows = Array.isArray(items) ? items.slice(0, 6) : [];
      if (!rows.length) {
        container.innerHTML = `<div class="panel-empty"><i class="bi bi-shield"></i><span>Sem ataques recorrentes no período.</span></div>`;
        return;
      }
      container.innerHTML = rows.map(item => {
        const sev = normalizeSeverity(item.sev);
        return `<div class="top-attack-row">
          <span class="top-attack-row__icon"><i class="bi bi-shield-exclamation"></i></span>
          <div class="top-attack-row__body">
            <div class="top-attack-row__title">${escapeHtml(item.nome || "Ataque")}</div>
            <div class="top-attack-row__meta">${severityLabel(sev)}</div>
          </div>
          <span class="top-attack-row__count">${formatNumber(item.count || 0)}×</span>
        </div>`;
      }).join("");
    }

    function renderTimeline(timeline) {
      const labels = Array.isArray(timeline.labels) ? timeline.labels : [];
      const crit = Array.isArray(timeline.crit) ? timeline.crit : Array(labels.length).fill(0);
      const high = Array.isArray(timeline.high) ? timeline.high : Array(labels.length).fill(0);
      const med = Array.isArray(timeline.med) ? timeline.med : Array(labels.length).fill(0);
      const canvas = el("chartTimeline");
      if (!canvas || !window.Chart) return;
      const theme = chartTheme();

      if (!charts.timeline) {
        charts.timeline = new Chart(canvas, {
          type: "line",
          data: {
            labels,
            datasets: [
              { label: "Médio", data: med, borderColor: COLORS.yellow, backgroundColor: "transparent", borderWidth: 1, pointRadius: 0, tension: .34 },
              { label: "Alto", data: high, borderColor: COLORS.orange, backgroundColor: "transparent", borderWidth: 1.3, pointRadius: 0, tension: .34 },
              { label: "Crítico", data: crit, borderColor: COLORS.red, backgroundColor: "rgba(239,68,68,.06)", borderWidth: 1.7, pointRadius: 0, tension: .34, fill: true },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { intersect: false, mode: "index" },
            scales: {
              x: { grid: { display: false }, border: { display: false }, ticks: { color: theme.dim, maxTicksLimit: 7, font: { size: 8 } } },
              y: { beginAtZero: true, grid: { color: theme.grid }, border: { display: false }, ticks: { color: theme.dim, precision: 0, font: { size: 8 } } },
            },
          },
        });
      } else {
        charts.timeline.data.labels = labels;
        charts.timeline.data.datasets[0].data = med;
        charts.timeline.data.datasets[1].data = high;
        charts.timeline.data.datasets[2].data = crit;
        charts.timeline.update("active");
      }
      setChartEmpty(canvas, combineSeries(crit, high, med).every(v => v === 0), "Nenhum incidente na última hora");
    }

    function renderTopIPs(items) {
      const container = el("socTopIPs");
      if (!container) return;
      const rows = Array.isArray(items) ? items.slice(0, 6) : [];
      if (!rows.length) {
        container.innerHTML = `<div class="panel-empty"><i class="bi bi-crosshair"></i><span>Sem origens ativas no período.</span></div>`;
        return;
      }
      const max = Math.max(1, ...rows.map(item => safeNumber(item.count)));
      container.innerHTML = rows.map((item, index) => {
        const pct = Math.max(3, Math.round((safeNumber(item.count) / max) * 100));
        return `<div class="soc-ip-row">
          <span class="soc-ip-row__rank">${index + 1}</span>
          <div class="soc-ip-row__body">
            <div class="soc-ip-row__ip">${escapeHtml(item.ip || "—")}</div>
            <div class="soc-ip-row__bar"><div class="soc-ip-row__fill" style="width:${pct}%"></div></div>
          </div>
          <span class="soc-ip-row__count">${formatNumber(item.count)}×</span>
        </div>`;
      }).join("");
    }

    function renderCategories(items) {
      const rows = Array.isArray(items) ? items.filter(i => safeNumber(i.count) > 0) : [];
      const total = rows.reduce((sum, item) => sum + safeNumber(item.count), 0);
      setText("catTotal", formatNumber(total));

      const canvas = el("chartCategorias");
      if (canvas && window.Chart) {
        const labels = rows.map(item => item.nome || "Categoria");
        const values = rows.map(item => safeNumber(item.count));
        const colors = rows.map((item, index) => item.color || [COLORS.blue, COLORS.red, COLORS.purple, COLORS.orange, COLORS.cyan, COLORS.yellow, COLORS.slate][index % 7]);
        const chartValues = values.length ? values : [1];
        const chartColors = colors.length ? colors : [cssVar("--border-soft", "#eef0f3")];

        if (!charts.categories) {
          charts.categories = new Chart(canvas, {
            type: "doughnut",
            data: { labels: labels.length ? labels : ["Sem dados"], datasets: [{ data: chartValues, backgroundColor: chartColors, borderWidth: 0, hoverOffset: 2 }] },
            options: { responsive: true, maintainAspectRatio: false, cutout: "73%", plugins: { tooltip: { enabled: values.length > 0 } } },
          });
        } else {
          charts.categories.data.labels = labels.length ? labels : ["Sem dados"];
          charts.categories.data.datasets[0].data = chartValues;
          charts.categories.data.datasets[0].backgroundColor = chartColors;
          charts.categories.options.plugins.tooltip.enabled = values.length > 0;
          charts.categories.update("active");
        }
      }

      const legend = el("catLegend");
      if (!legend) return;
      if (!rows.length) {
        legend.innerHTML = `<div class="panel-empty"><i class="bi bi-pie-chart"></i><span>Sem categorias no período.</span></div>`;
        return;
      }
      legend.innerHTML = rows.slice(0, 6).map((item, index) => {
        const count = safeNumber(item.count);
        const pct = total ? Math.round((count / total) * 100) : 0;
        const color = item.color || [COLORS.blue, COLORS.red, COLORS.purple, COLORS.orange, COLORS.cyan, COLORS.yellow][index % 6];
        return `<div class="soc-cat-row">
          <span class="soc-cat-row__dot" style="background:${escapeHtml(color)}"></span>
          <span class="soc-cat-row__name">${escapeHtml(item.nome || "Categoria")}</span>
          <span class="soc-cat-row__count">${formatNumber(count)}</span>
          <span class="soc-cat-row__pct">${pct}%</span>
        </div>`;
      }).join("");
    }

    function renderHealth(data) {
      const sensors = Array.isArray(data.saude?.sensores) ? data.saude.sensores : [];
      const grid = el("socHealthGrid");
      const overall = el("healthOverall");

      if (grid) {
        if (!sensors.length) {
          grid.innerHTML = `<div class="panel-empty"><i class="bi bi-heart-pulse"></i><span>Sem telemetria de saúde.</span></div>`;
        } else {
          grid.innerHTML = sensors.map(sensor => {
            const st = String(sensor.status || "err").toLowerCase();
            const statusClass = st === "ok" ? "is-ok" : st === "warn" ? "is-warn" : "is-error";
            const dotClass = st === "ok" ? "sensor-dot--ok" : st === "warn" ? "sensor-dot--warn" : "sensor-dot--danger";
            const label = st === "ok" ? "ONLINE" : st === "warn" ? "ATENÇÃO" : "OFFLINE";
            return `<div class="soc-health-item">
              <span class="soc-health-item__icon"><i class="bi ${escapeHtml(sensor.icon || "bi-activity")}"></i></span>
              <div class="soc-health-item__body">
                <div class="soc-health-item__name">${escapeHtml(sensor.nome || "Componente")}</div>
                <div class="soc-health-item__desc">${escapeHtml(sensor.desc || "Monitoramento operacional")}</div>
              </div>
              <span class="soc-health-item__status ${statusClass}"><span class="sensor-dot ${dotClass}"></span>${label}</span>
            </div>`;
          }).join("");
        }
      }

      if (overall) {
        const okCount = sensors.filter(s => String(s.status).toLowerCase() === "ok").length;
        const warnCount = sensors.filter(s => String(s.status).toLowerCase() === "warn").length;
        const allOk = sensors.length > 0 && okCount === sensors.length;
        overall.classList.remove("is-ok", "is-warn", "is-error");
        overall.classList.add(allOk ? "is-ok" : warnCount ? "is-warn" : "is-error");
        overall.innerHTML = `<span class="sensor-dot ${allOk ? "sensor-dot--ok" : warnCount ? "sensor-dot--warn" : "sensor-dot--danger"}"></span>${allOk ? "Operacional" : warnCount ? "Atenção" : "Degradado"}`;
      }

      const metrics = el("socMetrics");
      if (metrics) {
        const online = safeNumber(data.kpis?.sensores_online);
        const total = safeNumber(data.kpis?.sensores_total, sensors.length || 3);
        const incidentRate = calculateEventRate(data);
        metrics.innerHTML = `
          <div class="soc-metric"><strong>${incidentRate}</strong><span>eventos/min</span></div>
          <div class="soc-metric"><strong>${escapeHtml(state.period)}</strong><span>período</span></div>
          <div class="soc-metric"><strong>${online}/${total}</strong><span>sensores</span></div>`;
      }
    }

    function calculateEventRate(data) {
      const total = safeNumber(data.kpis?.ameacas_hoje);
      const minutes = { "1h": 60, "24h": 1440, "7d": 10080, "30d": 43200 }[state.period] || 1440;
      return (total / minutes).toFixed(total / minutes >= 10 ? 0 : 2);
    }

    function bindControls() {
      document.querySelectorAll("#dashPeriod [data-p]").forEach(button => {
        button.addEventListener("click", () => {
          const period = button.dataset.p;
          if (!period || period === state.period) return;
          state.period = period;
          document.querySelectorAll("#dashPeriod [data-p]").forEach(b => b.classList.toggle("is-active", b === button));
          state.cleared = false;
          renderDashboard();
        });
      });

      document.querySelectorAll("#dashSev [data-s]").forEach(button => {
        button.addEventListener("click", () => {
          const sev = button.dataset.s;
          if (!sev || sev === state.sev) return;
          state.sev = sev;
          document.querySelectorAll("#dashSev [data-s]").forEach(b => b.classList.toggle("is-active", b === button));
          state.cleared = false;
          renderDashboard();
        });
      });

      el("btnRefresh")?.addEventListener("click", () => {
        state.cleared = false;
        renderDashboard();
      });

      el("dashBannerClose")?.addEventListener("click", hideBanner);

      document.querySelectorAll("#feedFilters [data-ft]").forEach(button => {
        button.addEventListener("click", () => {
          state.feedFilter = button.dataset.ft || "all";
          state.cleared = false;
          document.querySelectorAll("#feedFilters [data-ft]").forEach(b => b.classList.toggle("is-active", b === button));
          drawFeed();
        });
      });

      el("feedPauseBtn")?.addEventListener("click", () => {
        state.paused = !state.paused;
        const icon = el("feedPauseIcon");
        if (icon) icon.className = state.paused ? "bi bi-play-fill" : "bi bi-pause-fill";
        const btn = el("feedPauseBtn");
        if (btn) btn.title = state.paused ? "Retomar feed" : "Pausar feed";
        if (!state.paused) drawFeed();
      });

      el("feedClearBtn")?.addEventListener("click", () => {
        state.cleared = true;
        const list = el("feedList");
        if (list) list.innerHTML = `<div class="feed-empty"><i class="bi bi-inbox"></i><strong>Visualização limpa</strong><span>Use Atualizar ou aguarde novos dados para repopular o feed.</span></div>`;
        setText("feedCount", "0");
      });

      el("btnExport")?.addEventListener("click", exportCsv);
    }

    function exportCsv() {
      const data = state.lastData;
      if (!data) return;
      const feed = Array.isArray(data.feed) ? data.feed : [];
      const rows = [
        ["timestamp", "fonte", "severidade", "origem", "evento"],
        ...feed.map(item => [item.ts || "", item.type || "", item.sev || "", item.src || "", item.msg || ""]),
      ];
      const csv = rows.map(row => row.map(cell => `"${String(cell).replaceAll('"', '""')}"`).join(",")).join("\r\n");
      const blob = new Blob(["\ufeff" + csv], { type: "text/csv;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `moonshield-dashboard-${new Date().toISOString().slice(0, 10)}.csv`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    }

    function startPolling() {
      if (state.pollTimer) clearInterval(state.pollTimer);
      state.pollTimer = setInterval(() => {
        if (document.hidden || state.loading) return;
        renderDashboard({ silent: true });
      }, 30000);
    }

    bindControls();
    renderDashboard();
    startPolling();
  });
})();
