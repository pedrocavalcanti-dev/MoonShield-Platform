/**
 * MOONSHIELD — DASHBOARD.JS  v11
 * ─────────────────────────────────────────────────────────────────────────
 * v11 — Dashboard 100% real:
 * • Dados exclusivamente do backend real (/painel/api/overview/)
 * • Sem DEMO, MOCK, LIVE_MSGS, dados sintéticos ou fallbacks falsos
 * • Empty states elegantes quando não há dados
 * • Loading state: "—" antes da API responder
 * • Filtros de período (1h/24h/7d/30d) e severidade passados ao backend
 * • Top Origens = IPs reais (GeoIP será integrado no Mapa de Ameaças)
 * • Polling 30s; atualização manual via botão
 * ─────────────────────────────────────────────────────────────────────────
 */

document.addEventListener("DOMContentLoaded", () => {

  /* ════════════════════════════════════════════════════════════
     CORES & TEMA
  ════════════════════════════════════════════════════════════ */
  const C = {
    red:    "#ef4444",
    orange: "#f97316",
    yellow: "#eab308",
    green:  "#22c55e",
    blue:   "#3b82f6",
    purple: "#a855f7",
    grid:   "rgba(255,255,255,0.04)",
    tick:   "rgba(255,255,255,0.20)",
  };

  Chart.defaults.color                              = "rgba(255,255,255,0.28)";
  Chart.defaults.font.family                        = "'JetBrains Mono', monospace";
  Chart.defaults.font.size                          = 10;
  Chart.defaults.plugins.legend.display            = false;
  Chart.defaults.plugins.tooltip.backgroundColor   = "#0d1117";
  Chart.defaults.plugins.tooltip.borderColor       = "rgba(255,255,255,0.10)";
  Chart.defaults.plugins.tooltip.borderWidth       = 1;
  Chart.defaults.plugins.tooltip.titleColor        = "#f0f0f0";
  Chart.defaults.plugins.tooltip.bodyColor         = "rgba(255,255,255,0.55)";
  Chart.defaults.plugins.tooltip.padding           = 10;
  Chart.defaults.plugins.tooltip.cornerRadius      = 8;

  /* ════════════════════════════════════════════════════════════
     PLUGIN — glow nas linhas
  ════════════════════════════════════════════════════════════ */
  const pluginLineGlow = {
    id: "lineGlow",
    beforeDatasetsDraw(chart) {
      const { ctx } = chart;
      chart.data.datasets.forEach((ds, i) => {
        if (!ds.borderColor || !ds.enableGlow) return;
        const meta = chart.getDatasetMeta(i);
        if (!meta.visible || !meta.dataset) return;
        ctx.save();
        ctx.shadowColor = ds.borderColor;
        ctx.shadowBlur  = 20;
        meta.dataset.draw(ctx);
        ctx.shadowBlur  = 8;
        meta.dataset.draw(ctx);
        ctx.restore();
      });
    }
  };
  Chart.register(pluginLineGlow);

  /* ════════════════════════════════════════════════════════════
     STATE
  ════════════════════════════════════════════════════════════ */
  let currentPeriod = "24h";
  let currentSev    = "all";
  let isPaused      = false;
  let feedCount     = 0;
  let feedFilter    = "all";
  let chartAtaques, chartDns, chartTimeline, chartCategorias;
  let lastData = null;
  let isLoading = false;

  /* ════════════════════════════════════════════════════════════
     LOADING STATE — exibe "—" nos KPIs enquanto carrega
  ════════════════════════════════════════════════════════════ */
  function setLoading(active) {
    isLoading = active;
    const kpiIds = ["kpiAmeacas", "kpiDns", "kpiBloq", "kpiBloqPct", "radarLabel"];
    kpiIds.forEach(id => {
      const el = document.getElementById(id);
      if (!el) return;
      if (active) {
        el.dataset.realValue = el.textContent;
        el.textContent = "—";
        el.style.opacity = "0.4";
      } else {
        el.style.opacity = "";
      }
    });

    const errBanner = document.getElementById("dashErrBanner");
    if (errBanner && active) errBanner.style.display = "none";
  }

  /* ════════════════════════════════════════════════════════════
     ERROR BANNER
  ════════════════════════════════════════════════════════════ */
  function showError(msg) {
    let banner = document.getElementById("dashErrBanner");
    if (!banner) {
      banner = document.createElement("div");
      banner.id = "dashErrBanner";
      banner.style.cssText = [
        "position:fixed", "top:64px", "left:50%", "transform:translateX(-50%)",
        "z-index:9999", "background:rgba(239,68,68,0.12)",
        "border:1px solid rgba(239,68,68,0.30)", "border-radius:8px",
        "padding:10px 20px", "color:#fca5a5", "font-size:13px",
        "display:flex", "align-items:center", "gap:8px"
      ].join(";");
      banner.innerHTML = `<i class="bi bi-exclamation-triangle"></i> <span id="dashErrMsg"></span>`;
      document.body.appendChild(banner);
    }
    document.getElementById("dashErrMsg").textContent = msg;
    banner.style.display = "flex";
    setTimeout(() => { banner.style.display = "none"; }, 8000);
  }

  /* ════════════════════════════════════════════════════════════
     API FETCH
  ════════════════════════════════════════════════════════════ */
  async function loadOverview(period = "24h", sev = "all") {
    const res = await fetch(
      `/painel/api/overview/?period=${period}&sev=${sev}`,
      { headers: { Accept: "application/json" }, signal: AbortSignal.timeout(8000) }
    );
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }

  /* ════════════════════════════════════════════════════════════
     RENDER PRINCIPAL
  ════════════════════════════════════════════════════════════ */
  async function render(period = currentPeriod, sev = currentSev) {
    setLoading(true);
    try {
      const data = await loadOverview(period, sev);
      lastData = data;
      renderKpis(data);
      renderSensors(data);
      renderCharts(data);
      renderFeed(data.feed || []);
      renderIntel(data.intel || {});
      renderInfra(data.infra || {});
      renderSOC(data);
      renderMode(data);
      updateTime(data.last_update);
    } catch (e) {
      console.error("Falha ao carregar overview:", e);
      showError("Alguns dados não puderam ser carregados.");
    } finally {
      setLoading(false);
    }
  }

  /* ════════════════════════════════════════════════════════════
     ANIMAÇÃO DE COUNTER (count-up)
  ════════════════════════════════════════════════════════════ */
  function animateCounter(el, target, duration = 1200, formatter = null) {
    if (!el) return;
    const start = 0;
    const startTime = performance.now();
    function step(now) {
      const elapsed  = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased    = 1 - Math.pow(1 - progress, 4);
      const current  = Math.round(start + (target - start) * eased);
      el.textContent = formatter ? formatter(current) : current.toLocaleString("pt-BR");
      if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  /* ════════════════════════════════════════════════════════════
     KPIs
  ════════════════════════════════════════════════════════════ */
  function renderKpis(data) {
    const kpi = data.kpis || {};

    animateCounter(document.getElementById("kpiAmeacas"), Number(kpi.ameacas_hoje ?? 0));
    animateCounter(document.getElementById("kpiDns"),     Number(kpi.dns_queries ?? 0), 1200, n => n.toLocaleString("pt-BR"));
    animateCounter(document.getElementById("kpiBloq"),    Number(kpi.dns_bloqueios ?? 0), 1200, n => n.toLocaleString("pt-BR"));

    const pct = Number(kpi.bloqueio_pct ?? 0);
    setEl("kpiBloqPct", `${pct.toFixed(1)}%`);

    // Sparklines — séries reais do backend
    const ch = data.charts || {};
    const attacks = ch.attacks || {};
    const dns     = ch.dns    || {};

    const total = (attacks.crit || []).map((v, i) =>
      v + (attacks.high?.[i] || 0) + (attacks.med?.[i] || 0)
    );
    makeSparkline("sparkAmeacas", total, C.red);
    makeSparkline("sparkDns",  dns.queries || [], C.blue);
    makeSparkline("sparkBloq", dns.blocked  || [], C.yellow);
  }

  /* ════════════════════════════════════════════════════════════
     SENSORES — card 4 (contagem e lista)
  ════════════════════════════════════════════════════════════ */
  function renderSensors(data) {
    const kpi = data.kpis || {};
    const sOn  = kpi.sensores_online ?? 0;
    const sAll = kpi.sensores_total  ?? 3;
    setEl("radarLabel", `${sOn}/${sAll}`);

    // Lista explícita dos 3 sensores abaixo do doughnut
    const saude    = data.saude || {};
    const sensores = saude.sensores || [];
    const lista    = document.getElementById("sensoresList");
    if (!lista || !sensores.length) return;

    const ST_COL  = { ok: C.green,  warn: C.yellow, err: C.red };
    const ST_LBL  = { ok: "Online", warn: "Alerta",  err: "Offline" };
    const ST_DOT  = { ok: "sensor-dot--ok", warn: "sensor-dot--danger", err: "sensor-dot--danger" };

    lista.innerHTML = sensores.map(s => {
      const col = ST_COL[s.status]  || "#6b7280";
      const lbl = ST_LBL[s.status] || s.status;
      const dot = ST_DOT[s.status] || "";
      return `
      <div class="sensor-row">
        <i class="bi ${s.icon}" style="color:${col}"></i>
        <span class="sensor-row__name">${s.nome}</span>
        <span class="sensor-row__status" style="color:${col}">
          <span class="sensor-dot ${dot}"></span>${lbl}
        </span>
      </div>`;
    }).join("");
  }

  /* ════════════════════════════════════════════════════════════
     SPARKLINES
  ════════════════════════════════════════════════════════════ */
  const _sparkInstances = {};
  function makeSparkline(id, data, color) {
    const el = document.getElementById(id);
    if (!el) return;

    // Empty state para sparkline sem dados
    const allZero = !data.length || data.every(v => v === 0);
    if (allZero) {
      if (_sparkInstances[id]) {
        _sparkInstances[id].data.datasets[0].data = Array(data.length || 12).fill(0);
        _sparkInstances[id].update("none");
      }
    }

    if (_sparkInstances[id]) {
      _sparkInstances[id].data.datasets[0].data = data;
      _sparkInstances[id].update("none");
      return;
    }
    _sparkInstances[id] = new Chart(el, {
      type: "line",
      data: {
        labels: Array(data.length).fill(""),
        datasets: [{
          data,
          borderColor: color,
          borderWidth: 1.5,
          fill: true,
          backgroundColor: color.replace(")", ",0.08)").replace("rgb", "rgba"),
          tension: 0.45,
          pointRadius: 0,
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false, animation: false,
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
        scales:  { x: { display: false }, y: { display: false } },
      }
    });
  }

  /* ════════════════════════════════════════════════════════════
     RADAR (doughnut — Sensores)
  ════════════════════════════════════════════════════════════ */
  let radarChart = null;
  function initRadar() {
    const el = document.getElementById("radarSensores");
    if (!el || radarChart) return;
    el.style.animation = "radarSpin 8s linear infinite";
    const style = document.createElement("style");
    style.textContent = `@keyframes radarSpin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} } #radarSensores{transform-origin:center}`;
    document.head.appendChild(style);
    radarChart = new Chart(el, {
      type: "doughnut",
      data: {
        datasets: [
          {
            data: [33, 33, 34],
            backgroundColor: ["rgba(34,197,94,0.70)", "rgba(34,197,94,0.35)", "rgba(34,197,94,0.15)"],
            borderColor:     ["rgba(34,197,94,0.9)",  "rgba(34,197,94,0.5)",  "rgba(34,197,94,0.2)"],
            borderWidth: 1,
          },
          {
            data: [25, 50, 25],
            backgroundColor: ["rgba(34,197,94,0.12)", "rgba(34,197,94,0.25)", "rgba(34,197,94,0.08)"],
            borderColor: "transparent", borderWidth: 0, weight: 0.4,
          }
        ]
      },
      options: {
        responsive: false, cutout: "58%",
        animation:  { duration: 1500, easing: "easeOutQuart" },
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
      }
    });
  }

  /* ════════════════════════════════════════════════════════════
     RING CHARTS
  ════════════════════════════════════════════════════════════ */
  const _ringInstances = {};
  function makeRing(id, value, color, trackColor) {
    const el = document.getElementById(id);
    if (!el) return;
    if (_ringInstances[id]) {
      _ringInstances[id].data.datasets[0].data = [value, 100 - value];
      _ringInstances[id].update("active");
      return;
    }
    _ringInstances[id] = new Chart(el, {
      type: "doughnut",
      data: {
        datasets: [{
          data: [value, 100 - value],
          backgroundColor: [color, trackColor || "rgba(255,255,255,0.05)"],
          borderColor:     ["transparent", "transparent"],
          borderWidth: 0,
          hoverBackgroundColor: [color, trackColor || "rgba(255,255,255,0.05)"],
        }]
      },
      options: {
        responsive: false, cutout: "74%", rotation: -90, circumference: 360,
        animation: { duration: 1400, easing: "easeOutQuart" },
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
      }
    });
  }

  /* ════════════════════════════════════════════════════════════
     EMPTY STATE para canvas
  ════════════════════════════════════════════════════════════ */
  function showChartEmpty(canvasId, msg = "Nenhum dado no período") {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const parent = canvas.parentElement;
    let placeholder = parent.querySelector(".chart-empty");
    if (!placeholder) {
      placeholder = document.createElement("div");
      placeholder.className = "chart-empty";
      placeholder.style.cssText = [
        "position:absolute", "inset:0", "display:flex", "flex-direction:column",
        "align-items:center", "justify-content:center",
        "color:rgba(255,255,255,0.25)", "font-size:12px", "gap:8px",
        "pointer-events:none"
      ].join(";");
      parent.style.position = "relative";
      parent.appendChild(placeholder);
    }
    placeholder.innerHTML = `<i class="bi bi-bar-chart" style="font-size:24px;opacity:.3"></i>${msg}`;
    placeholder.style.display = "flex";
    canvas.style.opacity = "0.15";
  }

  function hideChartEmpty(canvasId) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const parent = canvas.parentElement;
    const placeholder = parent.querySelector(".chart-empty");
    if (placeholder) placeholder.style.display = "none";
    canvas.style.opacity = "";
  }

  /* ════════════════════════════════════════════════════════════
     GRÁFICOS
  ════════════════════════════════════════════════════════════ */
  function renderCharts(data) {
    const ch      = data.charts || {};
    const hours   = ch.hours   || [];
    const attacks = ch.attacks || { crit: [], high: [], med: [] };
    // DNS usa sua própria série de horas (sempre 24h do AdGuard)
    const dnsData    = ch.dns || {};
    const dnsHours   = dnsData.hours   || hours;
    const dnsQueries = dnsData.queries || [];
    const dnsBlocked = dnsData.blocked || [];

    renderAttackChart(hours, attacks);
    renderDnsChart(dnsHours, dnsQueries, dnsBlocked);
  }

  function renderAttackChart(hours, attacks) {
    const ctxA = document.getElementById("chartAtaques");
    if (!ctxA) return;

    const hasData = (attacks.crit || []).some(v => v > 0)
                 || (attacks.high || []).some(v => v > 0)
                 || (attacks.med  || []).some(v => v > 0);

    if (!hasData) {
      showChartEmpty("chartAtaques", "Nenhum evento no período");
    } else {
      hideChartEmpty("chartAtaques");
    }

    const totalPerHour = (attacks.crit || []).map((v, i) =>
      v + (attacks.high?.[i] || 0) + (attacks.med?.[i] || 0)
    );
    const trend = totalPerHour.map((_, i) => {
      const slice = totalPerHour.slice(Math.max(0, i - 2), i + 1);
      return Math.round(slice.reduce((a, b) => a + b, 0) / slice.length);
    });

    if (chartAtaques) {
      chartAtaques.data.labels           = hours;
      chartAtaques.data.datasets[0].data = attacks.crit || [];
      chartAtaques.data.datasets[1].data = attacks.high || [];
      chartAtaques.data.datasets[2].data = attacks.med  || [];
      chartAtaques.data.datasets[3].data = trend;
      chartAtaques.update("active");
      return;
    }

    const aCtx  = ctxA.getContext("2d");
    const gradR = makeGrad(aCtx, "rgba(239,68,68,0.90)",  "rgba(239,68,68,0.35)");
    const gradO = makeGrad(aCtx, "rgba(249,115,22,0.85)", "rgba(249,115,22,0.28)");
    const gradM = makeGrad(aCtx, "rgba(234,179,8,0.70)",  "rgba(234,179,8,0.18)");

    chartAtaques = new Chart(ctxA, {
      type: "bar",
      data: {
        labels: hours,
        datasets: [
          { label: "Crítico",   data: attacks.crit || [], backgroundColor: gradR, borderColor: C.red,    borderWidth: 1, borderRadius: { topLeft: 3, topRight: 3 }, stack: "attacks" },
          { label: "Alto",      data: attacks.high || [], backgroundColor: gradO, borderColor: C.orange, borderWidth: 1, stack: "attacks" },
          { label: "Médio",     data: attacks.med  || [], backgroundColor: gradM, borderColor: C.yellow, borderWidth: 1, stack: "attacks" },
          { label: "Tendência", data: trend,              type: "line", borderColor: "rgba(255,255,255,0.30)", borderWidth: 1.5, borderDash: [4, 4], fill: false, tension: 0.5, pointRadius: 0, stack: "", enableGlow: false },
        ],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: { title: it => it[0].label, label: it => `  ${it.dataset.label}: ${it.raw}` } }
        },
        scales: {
          x: { stacked: true, grid: { color: C.grid, drawBorder: false }, ticks: { maxTicksLimit: 8, color: C.tick } },
          y: { stacked: true, grid: { color: C.grid, drawBorder: false }, ticks: { color: C.tick, stepSize: 5 }, min: 0 },
        },
        animation: { duration: 1000, easing: "easeOutQuart" },
      },
    });
  }

  function renderDnsChart(dnsHours, dnsQueries, dnsBlocked) {
    const ctxD = document.getElementById("chartDns");
    if (!ctxD) return;

    const hasData = dnsQueries.some(v => v > 0) || dnsBlocked.some(v => v > 0);
    if (!hasData) {
      showChartEmpty("chartDns", "Nenhuma consulta registrada");
    } else {
      hideChartEmpty("chartDns");
    }

    if (chartDns) {
      chartDns.data.labels           = dnsHours;
      chartDns.data.datasets[0].data = dnsQueries;
      chartDns.data.datasets[1].data = dnsBlocked;
      chartDns.update("active");
      return;
    }

    const dCtx  = ctxD.getContext("2d");
    const gradB = makeGrad(dCtx, "rgba(59,130,246,0.80)",  "rgba(59,130,246,0.18)");
    const gradRA= makeGrad(dCtx, "rgba(239,68,68,0.22)",   "rgba(239,68,68,0.00)");

    chartDns = new Chart(ctxD, {
      type: "bar",
      data: {
        labels: dnsHours,
        datasets: [
          { label: "Consultas", data: dnsQueries, backgroundColor: gradB,  borderColor: C.blue, borderWidth: 1, borderRadius: { topLeft: 3, topRight: 3 }, order: 2 },
          { label: "Bloqueios", data: dnsBlocked, type: "line", borderColor: C.red, backgroundColor: gradRA, borderWidth: 2.5, fill: true, tension: 0.45, pointRadius: 0, pointHoverRadius: 5, pointHoverBackgroundColor: C.red, order: 1, enableGlow: true },
        ],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: { label: it => `  ${it.dataset.label}: ${Number(it.raw).toLocaleString("pt-BR")}` } }
        },
        scales: {
          x: { grid: { display: false }, ticks: { maxTicksLimit: 8, color: C.tick } },
          y: { grid: { color: C.grid, drawBorder: false }, ticks: { color: C.tick }, min: 0 },
        },
        animation: { duration: 1000, easing: "easeOutQuart" },
      },
    });
  }

  function makeGrad(ctx, top, bot) {
    const g = ctx.createLinearGradient(0, 0, 0, 280);
    g.addColorStop(0, top); g.addColorStop(1, bot); return g;
  }

  /* ════════════════════════════════════════════════════════════
     LIVE FEED — somente eventos reais do backend
  ════════════════════════════════════════════════════════════ */
  const SEV_CLASS   = { crit: "feed-item--crit", high: "feed-item--high", warn: "feed-item--warn", info: "feed-item--info" };
  const BADGE_CLASS = { crit: "feed-item__badge--crit", high: "feed-item__badge--high", warn: "feed-item__badge--warn", info: "feed-item__badge--info" };
  const BADGE_LABEL = { crit: "CRIT", high: "ALTO", warn: "MED", info: "INFO" };

  function renderFeed(items) {
    const scroll = document.getElementById("feedList");
    if (!scroll) return;
    scroll.innerHTML = "";
    feedCount = 0;

    if (!items.length) {
      scroll.innerHTML = `
        <div class="feed-empty">
          <i class="bi bi-shield-check" style="font-size:24px;opacity:.3"></i>
          <span>Nenhum incidente no período</span>
        </div>`;
      setEl("feedCount", "0");
      return;
    }

    [...items].reverse().forEach(it => addFeedItem(it, true));
    setEl("feedCount", feedCount > 99 ? "99+" : feedCount);
  }

  function addFeedItem(tpl, silent = false) {
    const scroll = document.getElementById("feedList");
    if (!scroll) return;
    if (isPaused && !silent) return;
    if (feedFilter !== "all" && tpl.type !== feedFilter) return;
    feedCount++;
    if (!silent) setEl("feedCount", feedCount > 99 ? "99+" : feedCount);

    const d  = tpl.ts ? new Date(tpl.ts) : new Date();
    const ts = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    const el = document.createElement("div");
    el.className = `feed-item ${SEV_CLASS[tpl.sev] ?? ""}`;
    el.innerHTML = `
      <div class="feed-item__row">
        <span class="feed-item__time">${ts}</span>
        <span class="feed-item__badge ${BADGE_CLASS[tpl.sev] ?? ""}">${BADGE_LABEL[tpl.sev] ?? tpl.sev}</span>
      </div>
      <div class="feed-item__src">${tpl.type} / ${tpl.src}</div>
      <div class="feed-item__msg">${tpl.msg}</div>`;
    scroll.insertBefore(el, scroll.firstChild);
    while (scroll.children.length > 60) scroll.removeChild(scroll.lastChild);
  }

  document.getElementById("feedPauseBtn")?.addEventListener("click", () => {
    isPaused = !isPaused;
    const lbl  = document.getElementById("feedPauseLbl");
    const icon = document.getElementById("feedPauseIcon");
    if (lbl)  lbl.textContent  = isPaused ? "Retomar" : "Pausar";
    if (icon) icon.innerHTML   = isPaused
      ? '<polygon points="5 3 19 12 5 21 5 3"/>'
      : '<rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/>';
  });

  document.getElementById("feedClearBtn")?.addEventListener("click", () => {
    const sc = document.getElementById("feedList");
    if (!sc) return;
    sc.innerHTML = ""; feedCount = 0; setEl("feedCount", "0");
  });

  document.querySelectorAll(".feed-filter-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".feed-filter-btn").forEach(b => b.classList.remove("feed-filter-btn--active"));
      btn.classList.add("feed-filter-btn--active");
      feedFilter = btn.dataset.ft;
      // Re-renderiza o feed com o filtro atual
      if (lastData) renderFeed(
        feedFilter === "all"
          ? (lastData.feed || [])
          : (lastData.feed || []).filter(f => f.type === feedFilter)
      );
    });
  });

  /* ════════════════════════════════════════════════════════════
     INTEL — Top Origens (IPs reais) + Top Ataques
  ════════════════════════════════════════════════════════════ */
  const SEV_COLORS = { crit: "#ef4444", high: "#f97316", med: "#eab308", info: "#3b82f6" };
  const SEV_BADGE  = { crit: "sev-badge--crit", high: "sev-badge--high", med: "sev-badge--med" };

  function renderIntel(intel) {
    // Top Origens — IPs reais (sem GeoIP — sem flags/países inventados)
    const origensEl = document.getElementById("intelOrigens");
    if (origensEl) {
      const topIps = intel.top_ips || [];
      if (!topIps.length) {
        origensEl.innerHTML = `
          <div class="intel-empty">
            <i class="bi bi-geo-alt" style="opacity:.3"></i>
            <span>Sem origens no período</span>
          </div>`;
      } else {
        const maxCount = Math.max(...topIps.map(o => Number(o.count) || 1), 1);
        const rankColors = [C.red, C.orange, C.yellow, "#6b7280", "#6b7280", "#6b7280", "#6b7280"];
        origensEl.innerHTML = topIps.map((o, idx) => {
          const col  = rankColors[idx] || "#6b7280";
          const barW = Math.round((Number(o.count) / maxCount) * 100);
          return `
          <div class="intel-row">
            <span class="intel-rank" style="color:${col}">#${o.rank ?? idx + 1}</span>
            <span class="intel-name soc-ip-addr">${o.ip}</span>
            <div class="intel-bar-wrap">
              <div class="intel-bar intel-bar--anim" style="--bar-w:${barW}%;background:${col}"></div>
            </div>
            <span class="intel-count" style="color:${col}">${o.count}×</span>
          </div>`;
        }).join("");
      }
    }

    // Top Ataques (signatures reais)
    const ataquesEl = document.getElementById("intelAtaques");
    if (ataquesEl) {
      const topAtaques = intel.top_ataques || intel.ataques || [];
      if (!topAtaques.length) {
        ataquesEl.innerHTML = `
          <div class="intel-empty">
            <i class="bi bi-shield" style="opacity:.3"></i>
            <span>Sem assinaturas no período</span>
          </div>`;
      } else {
        ataquesEl.innerHTML = topAtaques.map(a => {
          const col = SEV_COLORS[a.sev] || "#6b7280";
          return `
          <div class="intel-attack-row">
            <div class="intel-attack-icon" style="background:${col}1a;border-color:${col}40;color:${col}">
              <i class="bi bi-shield-exclamation"></i>
            </div>
            <div class="intel-attack-body">
              <p class="intel-attack-name">${a.nome}</p>
            </div>
            <span class="sev-badge ${SEV_BADGE[a.sev] || ""}">${a.sev ? a.sev.toUpperCase() : ""}</span>
            <span class="intel-count" style="color:${col};font-size:14px">${a.count}×</span>
          </div>`;
        }).join("");
      }
    }
  }

  /* ════════════════════════════════════════════════════════════
     INFRA — 3 cards com rings
  ════════════════════════════════════════════════════════════ */
  function renderInfra(infra) {
    const dev = infra.dispositivos || {};
    const fw  = infra.firewall     || {};
    const dns = infra.dns_infra    || {};

    // Dispositivos
    const devPct = dev.pct ?? 0;
    setEl("infraDevOnline",  dev.online    ?? 0);
    setEl("infraDevOffline", dev.offline   ?? 0);
    setEl("infraDevNovo",    dev.novo_hoje ?? 0);
    setEl("infraDevPct",     `${devPct}%`);
    setEl("infraDevOnline2",  dev.online    ?? 0);
    setEl("infraDevOffline2", dev.offline   ?? 0);
    setEl("infraDevNovo2",    dev.novo_hoje ?? 0);
    makeRing("ringDispositivos", devPct, C.green, "rgba(34,197,94,0.08)");

    // Firewall — usar dados reais disponíveis (sem drops/blocks inventados)
    const fwStatus = fw.operacional ? "Operacional" : (fw.status_label || "Indisponível");
    const fwColor  = fw.operacional ? C.green : C.red;
    const fwAgent  = fw.agent_online ? "Online" : "Offline";
    const fwDrift  = fw.drift || "Nenhum";

    setEl("infraFwStatus",  fwStatus);
    setEl("infraFwAgent",   fwAgent);
    setEl("infraFwDrift",   fwDrift);
    // Manter compatibilidade com IDs antigos (drops/blocks = "—" quando indisponível)
    setEl("infraFwDrops",   fw.drops  ?? "—");
    setEl("infraFwBlocks",  fw.blocks ?? "—");
    setEl("infraFwPorta",   fw.top_porta ?? "—");
    setEl("infraFwDrops2",  fw.drops  ?? "—");
    setEl("infraFwBlocks2", fw.blocks ?? "—");
    setEl("infraFwPorta2",  fw.top_porta ? `:${fw.top_porta}` : "—");
    const fwPct = fw.pct ?? (fw.operacional ? 100 : 0);
    setEl("infraFwPct", `${fwPct}%`);
    makeRing("ringFirewall", fwPct, fwColor, `${fwColor.replace(")", ",0.08)").replace("#", "rgba(")}`);

    // DNS Infra
    const dnsPct = dns.bloqueio_pct ?? 0;
    setEl("infraDnsPct",      `${dnsPct.toFixed ? dnsPct.toFixed(1) : dnsPct}%`);
    setEl("infraDnsClientes", dns.clientes ?? 0);
    setEl("infraDnsRingPct",  `${dnsPct}%`);
    setEl("infraDnsBloq2",    Number(dns.bloqueios ?? 0).toLocaleString("pt-BR"));
    setEl("infraDnsPerm2",    Number(dns.permitidos ?? 0).toLocaleString("pt-BR"));
    setEl("infraDnsClientes2", dns.clientes ?? 0);
    makeRing("ringDns", Math.min(100, Math.round(dnsPct)), C.yellow, "rgba(234,179,8,0.08)");
  }

  /* ════════════════════════════════════════════════════════════
     SOC
  ════════════════════════════════════════════════════════════ */
  function renderSOC(data) {
    renderTimeline(data);
    renderTopIPs(data);
    renderCategorias(data);
    renderSaude(data);
  }

  /* SOC 1 — Timeline 60 min (dados reais do backend) */
  function renderTimeline(data) {
    const tl = data.charts?.timeline || {};
    // Se o backend não retornou timeline, exibe empty state
    const labels = tl.labels || [];
    const crit   = tl.crit   || Array(labels.length || 12).fill(0);
    const high   = tl.high   || Array(labels.length || 12).fill(0);
    const med    = tl.med    || Array(labels.length || 12).fill(0);

    const el = document.getElementById("chartTimeline");
    if (!el) return;

    const total = crit.map((v, i) => v + (high[i] || 0) + (med[i] || 0));
    const hasData = total.some(v => v > 0);

    if (!hasData) {
      showChartEmpty("chartTimeline", "Nenhum incidente na última hora");
    } else {
      hideChartEmpty("chartTimeline");
    }

    const peak = total.map((v, i) => {
      const w = total.slice(Math.max(0, i - 1), i + 2);
      return Math.round(Math.max(...w) * 1.35) || 0;
    });

    if (chartTimeline) {
      chartTimeline.data.labels           = labels;
      chartTimeline.data.datasets[0].data = peak;
      chartTimeline.data.datasets[1].data = total;
      chartTimeline.data.datasets[2].data = high;
      chartTimeline.data.datasets[3].data = crit;
      chartTimeline.update("active");
      return;
    }

    const ctx = el.getContext("2d");
    function tlGrad(r, g, b, aTop, aBot) {
      const h  = ctx.canvas.clientHeight || 220;
      const gr = ctx.createLinearGradient(0, 0, 0, h);
      gr.addColorStop(0,    `rgba(${r},${g},${b},${aTop})`);
      gr.addColorStop(0.65, `rgba(${r},${g},${b},${aTop * 0.35})`);
      gr.addColorStop(1,    `rgba(${r},${g},${b},${aBot})`);
      return gr;
    }

    chartTimeline = new Chart(el, {
      type: "line",
      data: {
        labels,
        datasets: [
          { label: "Pico",   data: peak,  borderColor: "rgba(255,255,255,0.08)", borderWidth: 1, fill: true, backgroundColor: tlGrad(255,255,255,0.06,0.00), tension: 0.5, pointRadius: 0, order: 4 },
          { label: "Total",  data: total, borderColor: C.red,    borderWidth: 2.5, fill: true, backgroundColor: tlGrad(239,68,68,0.55,0.02), tension: 0.45, pointRadius: 0, pointHoverRadius: 5, pointHoverBackgroundColor: C.red, pointHoverBorderColor: "#fff", pointHoverBorderWidth: 2, order: 3, enableGlow: true },
          { label: "Alto",   data: high,  borderColor: C.orange, borderWidth: 1.5, fill: true, backgroundColor: tlGrad(249,115,22,0.30,0.00), tension: 0.45, pointRadius: 0, order: 2, enableGlow: true },
          { label: "Crítico",data: crit,  borderColor: "#fbbf24", borderWidth: 1.2, fill: true, backgroundColor: tlGrad(251,191,36,0.18,0.00), tension: 0.45, pointRadius: 0, order: 1 },
        ],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: { title: it => `⏱ ${it[0].label}`, label: it => `  ${it.dataset.label}: ${it.raw}` } }
        },
        scales: {
          x: { grid: { color: C.grid, drawBorder: false }, ticks: { maxTicksLimit: 12, color: C.tick } },
          y: { grid: { color: C.grid, drawBorder: false }, ticks: { color: C.tick }, min: 0 },
        },
        animation: { duration: 900, easing: "easeOutQuart" },
      },
    });
  }

  /* SOC 2 — Top IPs Atacantes (IPs reais — sem países inventados) */
  function renderTopIPs(data) {
    const el = document.getElementById("socTopIPs");
    if (!el) return;

    const items = (data.intel?.top_ips || []).filter(it => it.ip);

    if (!items.length) {
      el.innerHTML = `
        <div class="soc-empty">
          <i class="bi bi-diagram-3" style="font-size:24px;opacity:.3"></i>
          <p>Sem IPs atacantes no período</p>
        </div>`;
      return;
    }

    const SEV_C  = { crit: C.red, high: C.orange, med: C.yellow, info: C.blue };
    const maxCount = Math.max(...items.map(it => Number(it.count) || 1), 1);

    el.innerHTML = items.slice(0, 7).map((it, idx) => {
      const col  = SEV_C[it.sev] || "#6b7280";
      const barW = Math.round((Number(it.count) / maxCount) * 100);
      return `
      <div class="soc-ip-row">
        <span class="soc-ip-rank" style="color:${col}">${it.rank ?? idx + 1}</span>
        <div class="soc-ip-body">
          <p class="soc-ip-addr">${it.ip}</p>
          <div class="soc-ip-bar-wrap">
            <div class="soc-ip-bar" style="width:${barW}%;background:${col}"></div>
          </div>
        </div>
        <div class="soc-ip-right">
          <span class="soc-ip-count" style="color:${col}">${it.count}×</span>
        </div>
      </div>`;
    }).join("");
  }

  /* SOC 3 — Categorias (dados reais — sem percentuais sintéticos) */
  function renderCategorias(data) {
    const cats = data.intel?.categorias || [];
    const total = cats.reduce((s, it) => s + (it.count || 0), 0);

    setEl("catTotal", total > 0 ? total.toLocaleString("pt-BR") : "—");

    const el = document.getElementById("chartCategorias");
    if (el) {
      if (!cats.length) {
        showChartEmpty("chartCategorias", "Sem categorias no período");
        if (chartCategorias) {
          chartCategorias.data.datasets[0].data = [1];
          chartCategorias.data.labels           = ["Sem dados"];
          chartCategorias.data.datasets[0].backgroundColor = ["rgba(107,114,128,0.3)"];
          chartCategorias.data.datasets[0].borderColor     = ["#6b7280"];
          chartCategorias.update("active");
        }
      } else {
        hideChartEmpty("chartCategorias");
        if (chartCategorias) {
          chartCategorias.data.labels                       = cats.map(it => it.nome);
          chartCategorias.data.datasets[0].data             = cats.map(it => it.count);
          chartCategorias.data.datasets[0].backgroundColor  = cats.map(it => (it.color || "#6b7280") + "cc");
          chartCategorias.data.datasets[0].borderColor      = cats.map(it => it.color || "#6b7280");
          chartCategorias.update("active");
        } else {
          chartCategorias = new Chart(el, {
            type: "doughnut",
            data: {
              labels: cats.map(it => it.nome),
              datasets: [{
                data:            cats.map(it => it.count),
                backgroundColor: cats.map(it => (it.color || "#6b7280") + "cc"),
                borderColor:     cats.map(it => it.color || "#6b7280"),
                borderWidth:     1.5,
                hoverOffset:     8,
              }]
            },
            options: {
              responsive: false, cutout: "64%",
              animation: { duration: 1200, easing: "easeOutQuart" },
              plugins: {
                legend: { display: false },
                tooltip: { callbacks: { label: it => `  ${it.label}: ${it.raw} (${total > 0 ? Math.round(it.raw / total * 100) : 0}%)` } }
              }
            }
          });
        }
      }
    }

    const legend = document.getElementById("catLegend");
    if (!legend) return;
    if (!cats.length) {
      legend.innerHTML = `<div class="soc-empty"><span style="color:rgba(255,255,255,.25)">Sem dados no período</span></div>`;
      return;
    }
    legend.innerHTML = cats.map(it => {
      const pct = total > 0 ? Math.round((it.count / total) * 100) : 0;
      return `
      <div class="soc-cat-item">
        <span class="soc-cat-dot" style="background:${it.color || '#6b7280'}"></span>
        <span class="soc-cat-name">${it.nome}</span>
        <span class="soc-cat-count">${it.count}</span>
        <span class="soc-cat-pct">${pct}%</span>
      </div>`;
    }).join("");
  }

  /* SOC 4 — Saúde do Sistema (dados reais — sem fallback hard-coded) */
  function renderSaude(data) {
    const saude    = data.saude || {};
    const sensores = saude.sensores || [];  // lista estruturada do backend

    const STATUS_COL = { ok: "#22c55e", warn: "#eab308", err: "#ef4444" };
    const STATUS_LBL = { ok: "ONLINE",  warn: "ALERTA",  err: "OFFLINE" };
    const STATUS_DOT = { ok: "sensor-dot--ok", warn: "sensor-dot--danger", err: "sensor-dot--danger" };

    if (sensores.length) {
      const allOk  = sensores.every(s => s.status === "ok");
      const hasWarn= sensores.some(s => s.status === "warn");
      const overall = document.getElementById("healthOverall");
      if (overall) {
        if (allOk) {
          overall.innerHTML  = '<span class="sensor-dot sensor-dot--ok"></span> Operacional';
          overall.style.cssText = "color:#22c55e;background:rgba(34,197,94,.06);border-color:rgba(34,197,94,.18)";
        } else if (hasWarn) {
          overall.innerHTML  = '<span class="sensor-dot sensor-dot--danger" style="background:#eab308;box-shadow:0 0 6px #eab308"></span> Com alertas';
          overall.style.cssText = "color:#eab308;background:rgba(234,179,8,.06);border-color:rgba(234,179,8,.18)";
        } else {
          overall.innerHTML  = '<span class="sensor-dot sensor-dot--danger"></span> Degradado';
          overall.style.cssText = "color:#ef4444;background:rgba(239,68,68,.06);border-color:rgba(239,68,68,.18)";
        }
      }

      const healthGrid = document.getElementById("socHealthGrid");
      if (healthGrid) {
        healthGrid.innerHTML = sensores.map(s => {
          const col = STATUS_COL[s.status] || "#6b7280";
          const lbl = STATUS_LBL[s.status] || s.status.toUpperCase();
          return `
          <div class="soc-health-item">
            <div class="soc-health-icon" style="background:${col}1a;border:1px solid ${col}40;color:${col}">
              <i class="bi ${s.icon}"></i>
            </div>
            <div class="soc-health-body">
              <p class="soc-health-name">${s.nome}</p>
              <p class="soc-health-desc">${s.desc}</p>
            </div>
            <div class="soc-health-status soc-health-status--${s.status}">
              <span class="sensor-dot ${STATUS_DOT[s.status]}"></span>
              ${lbl}
            </div>
          </div>`;
        }).join("");
      }
    }

    // Métricas operacionais reais
    const kpi   = data.kpis   || {};
    const metricsRow = document.getElementById("socMetrics");
    if (metricsRow) {
      const eventosMin = kpi.ameacas_hoje
        ? (kpi.ameacas_hoje / 1440).toFixed(2)
        : "0.00";
      metricsRow.innerHTML = [
        { lbl: "Eventos/min", val: eventosMin },
        { lbl: "Período",     val: currentPeriod },
        { lbl: "Sensores",    val: `${kpi.sensores_online ?? 0}/${kpi.sensores_total ?? 3}` },
      ].map(m => `
      <div class="soc-metric">
        <p class="soc-metric__val">${m.val}</p>
        <p class="soc-metric__lbl">${m.lbl}</p>
      </div>`).join("");
    }
  }

  /* ════════════════════════════════════════════════════════════
     MODE BADGE (oculto — appliance PROD-only)
  ════════════════════════════════════════════════════════════ */
  function renderMode(data) {
    const badge = document.getElementById("modeBadge");
    if (badge) badge.style.display = "none";
    if (data.node) {
      setEl("dashNodeName", data.node.name || "—");
    }
  }

  /* ════════════════════════════════════════════════════════════
     CONTROLES
  ════════════════════════════════════════════════════════════ */
  document.querySelectorAll(".dash-period__btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".dash-period__btn").forEach(b => b.classList.remove("dash-period__btn--active"));
      btn.classList.add("dash-period__btn--active");
      currentPeriod = btn.dataset.p;
      render(currentPeriod, currentSev);
    });
  });

  document.querySelectorAll(".dash-sev__btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".dash-sev__btn").forEach(b => b.classList.remove("dash-sev__btn--active"));
      btn.classList.add("dash-sev__btn--active");
      currentSev = btn.dataset.s;
      render(currentPeriod, currentSev);
    });
  });

  const refreshBtn = document.getElementById("btnRefresh");
  refreshBtn?.addEventListener("click", () => {
    const icon = document.getElementById("refreshIcon");
    if (icon) icon.style.animation = "spin 1s linear infinite";
    render(currentPeriod, currentSev).finally?.(() => {
      if (icon) icon.style.animation = "";
    });
  });

  // Exportar — feed real (dados do lastData.feed)
  document.getElementById("btnExport")?.addEventListener("click", () => {
    if (!lastData?.feed?.length) {
      alert("Nenhum evento disponível para exportar.");
      return;
    }
    const feed = lastData.feed;
    const rows = [
      ["Timestamp", "Tipo", "Severidade", "Origem", "Mensagem"],
      ...feed.map(f => [f.ts || "", f.type || "", f.sev || "", f.src || "", f.msg || ""]),
    ];
    const blob = new Blob([rows.map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(",")).join("\n")], { type: "text/csv" });
    const a = Object.assign(document.createElement("a"), {
      href:     URL.createObjectURL(blob),
      download: `moonshield-feed-${new Date().toISOString().slice(0, 10)}.csv`,
    });
    a.click();
    URL.revokeObjectURL(a.href);
  });

  /* ════════════════════════════════════════════════════════════
     POLLING — 30s (sem dados sintéticos)
  ════════════════════════════════════════════════════════════ */
  setInterval(async () => {
    if (isPaused) return;
    try {
      const data = await loadOverview(currentPeriod, currentSev);
      lastData = data;
      renderKpis(data);
      renderSensors(data);
      renderCharts(data);
      renderTimeline(data);
      updateTime(data.last_update);
    } catch (_) { /* silencioso — não quebrar a página */ }
  }, 30_000);

  /* ════════════════════════════════════════════════════════════
     UTILS
  ════════════════════════════════════════════════════════════ */
  function setEl(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  }

  function pad(n) { return String(n).padStart(2, "0"); }

  function updateTime(iso) {
    const el = document.getElementById("lastUpdate");
    if (!el) return;
    const d = iso ? new Date(iso) : new Date();
    el.textContent = `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  /* ════════════════════════════════════════════════════════════
     BOOT
  ════════════════════════════════════════════════════════════ */
  initRadar();
  render("24h", "all");

});
