/**
 * MOONSHIELD — DASHBOARD.JS  v10
 * ─────────────────────────────────────────────────────────────────────────
 * Melhorias v10:
 * • Dados demo realistas gerados no front (padrão dia útil com picos)
 * • Bandeiras emoji em todos os lugares (sem código de país)
 * • Sem overflow horizontal em divs internos (exceto Live Feed)
 * • Animações contínuas: counters, barras, pulse nos valores, partículas
 * • Top IPs sem scroll horizontal — lista vertical limpa
 * • Charts com gradientes e linhas de tendência realistas
 * ─────────────────────────────────────────────────────────────────────────
 */

document.addEventListener("DOMContentLoaded", () => {

  /* ════════════════════════════════════════════════════════════
     CORES & TEMA
  ════════════════════════════════════════════════════════════ */
  const C = {
    red: "#ef4444",
    orange: "#f97316",
    yellow: "#eab308",
    green: "#22c55e",
    blue: "#3b82f6",
    purple: "#a855f7",
    grid: "rgba(255,255,255,0.04)",
    tick: "rgba(255,255,255,0.20)",
  };

  Chart.defaults.color = "rgba(255,255,255,0.28)";
  Chart.defaults.font.family = "'JetBrains Mono', monospace";
  Chart.defaults.font.size = 10;
  Chart.defaults.plugins.legend.display = false;
  Chart.defaults.plugins.tooltip.backgroundColor = "#0d1117";
  Chart.defaults.plugins.tooltip.borderColor = "rgba(255,255,255,0.10)";
  Chart.defaults.plugins.tooltip.borderWidth = 1;
  Chart.defaults.plugins.tooltip.titleColor = "#f0f0f0";
  Chart.defaults.plugins.tooltip.bodyColor = "rgba(255,255,255,0.55)";
  Chart.defaults.plugins.tooltip.padding = 10;
  Chart.defaults.plugins.tooltip.cornerRadius = 8;

  /* ════════════════════════════════════════════════════════════
     GERADOR DE DADOS DEMO REALISTAS
     Simula padrão de tráfego real: baixo de madrugada,
     pico manhã (9-11h), leve queda almoço, pico tarde (14-17h)
  ════════════════════════════════════════════════════════════ */
  function seededRandom(seed) {
    let s = seed;
    return function () {
      s = (s * 1664525 + 1013904223) & 0xffffffff;
      return (s >>> 0) / 4294967296;
    };
  }

  function generateHourlyPattern(base, variance, hourMultipliers, seed) {
    const rng = seededRandom(seed);
    return hourMultipliers.map(mult => {
      const jitter = (rng() - 0.5) * variance;
      return Math.max(0, Math.round(base * mult + jitter));
    });
  }

  // Multiplicadores por hora (0h-23h) — simula dia útil realista
  const HOUR_MULT = [
    0.12, 0.08, 0.06, 0.05, 0.07, 0.10,  // 0-5h  madrugada
    0.18, 0.35, 0.65, 0.90, 1.00, 0.95,  // 6-11h manhã (pico 10h)
    0.80, 0.70, 0.85, 0.95, 0.88, 0.75,  // 12-17h tarde
    0.60, 0.50, 0.40, 0.30, 0.22, 0.15,  // 18-23h noite
  ];

  const now = new Date();
  const currentHour = now.getHours();

  // Gera 24 labels de hora
  const HOURS_24 = Array.from({ length: 24 }, (_, i) => {
    const h = (currentHour - 23 + i + 24) % 24;
    return `${String(h).padStart(2, "0")}:00`;
  });

  // Ordena multiplicadores a partir da hora atual
  const orderedMult = Array.from({ length: 24 }, (_, i) =>
    HOUR_MULT[(currentHour - 23 + i + 24) % 24]
  );

  // Dados IDS (ataques)
  const DEMO_CRIT = generateHourlyPattern(8, 4, orderedMult, 42);
  const DEMO_HIGH = generateHourlyPattern(18, 8, orderedMult, 137);
  const DEMO_MED = generateHourlyPattern(35, 15, orderedMult, 291);

  // Dados DNS
  const DEMO_DNS_Q = generateHourlyPattern(1800, 400, orderedMult, 512);
  const DEMO_DNS_B = generateHourlyPattern(280, 80, orderedMult, 777);

  // KPIs calculados
  const TOTAL_AMEACAS = DEMO_CRIT.reduce((a, b) => a + b, 0) + DEMO_HIGH.reduce((a, b) => a + b, 0);
  const TOTAL_DNS_Q = DEMO_DNS_Q.reduce((a, b) => a + b, 0);
  const TOTAL_DNS_B = DEMO_DNS_B.reduce((a, b) => a + b, 0);
  const PCT_BLOQ = Math.round(TOTAL_DNS_B / TOTAL_DNS_Q * 100);

  // Timeline 60 min (realista, com picos menores)
  function generateTimeline60() {
    const rngC = seededRandom(9001), rngH = seededRandom(9002), rngM = seededRandom(9003);
    const labels = [], crit = [], high = [], med = [];
    for (let i = 59; i >= 0; i--) {
      const d = new Date(now.getTime() - i * 60_000);
      labels.push(`${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`);
      const hi = Math.min(23, Math.floor((59 - i) / 2.5));
      const baseMult = orderedMult[hi] || 0.5;
      // Adiciona picos ocasionais (a cada ~8 minutos)
      const spike = ((59 - i) % 8 === 0) ? 2.5 : 1;
      crit.push(Math.max(0, Math.round((rngC() * 3 + baseMult * 5) * spike)));
      high.push(Math.max(0, Math.round((rngH() * 6 + baseMult * 10) * spike)));
      med.push(Math.max(0, Math.round((rngM() * 10 + baseMult * 18) * spike)));
    }
    return { labels, crit, high, med };
  }

  const TL = generateTimeline60();

  /* ════════════════════════════════════════════════════════════
     DADOS DEMO ESTÁTICOS
  ════════════════════════════════════════════════════════════ */
  const DEMO_DATA = {
    mode: "demo",
    node: { name: "moonshield-01", cidr: "192.168.1.0/24" },
    last_update: now.toISOString(),
    kpis: {
      ameacas_hoje: TOTAL_AMEACAS,
      dns_queries: TOTAL_DNS_Q,
      dns_bloqueios: TOTAL_DNS_B,
      bloqueio_pct: PCT_BLOQ,
      sensores_online: 2,
      sensores_total: 2,
    },
    charts: {
      hours: HOURS_24,
      attacks: { crit: DEMO_CRIT, high: DEMO_HIGH, med: DEMO_MED },
      dns: { queries: DEMO_DNS_Q, blocked: DEMO_DNS_B },
      timeline: TL,
    },
    feed: [
      { ts: new Date(now - 8000).toISOString(), type: "IDS", sev: "crit", src: "45.88.12.3:4521", msg: "ET SCAN Potential SSH BruteForce" },
      { ts: new Date(now - 22000).toISOString(), type: "DNS", sev: "high", src: "192.168.1.45", msg: "Blocked: malware-c2.ru (Threat Intel)" },
      { ts: new Date(now - 45000).toISOString(), type: "IDS", sev: "high", src: "91.108.4.1:80", msg: "ET EXPLOIT Apache Log4j RCE Attempt" },
      { ts: new Date(now - 71000).toISOString(), type: "FW", sev: "warn", src: "0.0.0.0:22", msg: "DROP IN: port 22 rate limit exceeded" },
      { ts: new Date(now - 103000).toISOString(), type: "DNS", sev: "warn", src: "192.168.1.12", msg: "Blocked: phishing-page.xyz (Category)" },
      { ts: new Date(now - 134000).toISOString(), type: "IDS", sev: "high", src: "104.21.8.99:443", msg: "ET INFO DNS Query for Suspicious TLD" },
      { ts: new Date(now - 178000).toISOString(), type: "FW", sev: "warn", src: "194.165.16.4:8080", msg: "DROP IN: blocked country CN rule #12" },
      { ts: new Date(now - 201000).toISOString(), type: "IDS", sev: "crit", src: "185.220.101.5:3389", msg: "ET SCAN RDP BruteForce Detected" },
      { ts: new Date(now - 245000).toISOString(), type: "DNS", sev: "info", src: "192.168.1.8", msg: "Query: updates.microsoft.com (allowed)" },
      { ts: new Date(now - 289000).toISOString(), type: "IDS", sev: "med", src: "5.189.144.21:25", msg: "ET POLICY SMTP Traffic on Non-standard Port" },
      { ts: new Date(now - 312000).toISOString(), type: "FW", sev: "info", src: "8.8.8.8:53", msg: "ACCEPT OUT: DNS query google DNS" },
      { ts: new Date(now - 356000).toISOString(), type: "IDS", sev: "high", src: "77.88.55.80:80", msg: "ET WEB_SERVER Possible SQL Injection" },
    ],
    intel: {
      origens: [
        { rank: "#1", flag: "🇨🇳", pais: "China", count: 127, pct: 42, color: "#ef4444" },
        { rank: "#2", flag: "🇷🇺", pais: "Rússia", count: 89, pct: 29, color: "#f97316" },
        { rank: "#3", flag: "🇺🇸", pais: "EUA", count: 54, pct: 18, color: "#eab308" },
        { rank: "#4", flag: "🇳🇱", pais: "Holanda", count: 28, pct: 9, color: "#6b7280" },
        { rank: "#5", flag: "🇩🇪", pais: "Alemanha", count: 17, pct: 5, color: "#6b7280" },
      ],
      top_ips: [
        { ip: "45.88.12.3", flag: "🇨🇳", pais: "China", tipo: "SSH Brute Force", sev: "crit", count: 127, last: "agora" },
        { ip: "91.108.4.1", flag: "🇷🇺", pais: "Rússia", tipo: "Port Scan", sev: "high", count: 89, last: "2min" },
        { ip: "104.21.8.99", flag: "🇺🇸", pais: "EUA", tipo: "DNS Probe", sev: "high", count: 54, last: "4min" },
        { ip: "194.165.16.4", flag: "🇳🇱", pais: "Holanda", tipo: "Web Crawler", sev: "med", count: 28, last: "9min" },
        { ip: "5.189.144.21", flag: "🇩🇪", pais: "Alemanha", tipo: "SMTP Probe", sev: "med", count: 17, last: "14min" },
        { ip: "185.220.101.5", flag: "🇺🇦", pais: "Ucrânia", tipo: "RDP BruteForce", sev: "crit", count: 12, last: "18min" },
        { ip: "77.88.55.80", flag: "🇷🇺", pais: "Rússia", tipo: "SQL Injection", sev: "high", count: 9, last: "22min" },
      ],
      ataques: [
        { nome: "SSH Brute Force", sub: "Tentativas de autenticação SSH", sev: "crit", count: 127 },
        { nome: "Port Scan", sub: "Reconhecimento de portas TCP", sev: "high", count: 89 },
        { nome: "RDP BruteForce", sub: "Força bruta Remote Desktop", sev: "crit", count: 54 },
        { nome: "SQL Injection", sub: "Injeção em parâmetros HTTP", sev: "high", count: 38 },
        { nome: "DNS Tunneling", sub: "Exfiltração via DNS", sev: "med", count: 21 },
      ],
      categorias: [
        { nome: "Reconhecimento", color: "#3b82f6", count: Math.round(TOTAL_AMEACAS * 0.34) },
        { nome: "Brute Force", color: "#ef4444", count: Math.round(TOTAL_AMEACAS * 0.25) },
        { nome: "DNS Abuse", color: "#f97316", count: Math.round(TOTAL_AMEACAS * 0.18) },
        { nome: "Exploits", color: "#a855f7", count: Math.round(TOTAL_AMEACAS * 0.12) },
        { nome: "Policy Violat.", color: "#eab308", count: Math.round(TOTAL_AMEACAS * 0.07) },
        { nome: "Outros", color: "#6b7280", count: Math.round(TOTAL_AMEACAS * 0.04) },
      ],
    },
    infra: {
      dispositivos: { online: 14, offline: 2, novo_hoje: 1, pct: 87 },
      firewall: { drops: 1847, blocks: 312, top_porta: 22, pct: 73 },
      dns_infra: { bloqueio_pct: PCT_BLOQ, clientes: 16, ameacas: 23, bloqueios: TOTAL_DNS_B, permitidos: TOTAL_DNS_Q - TOTAL_DNS_B },
    },
    saude: {
      eventos_min: (TOTAL_AMEACAS / 1440).toFixed(1),
      latencia_api: "< 12ms",
      fila: 0,
      sensores: [
        { nome: "IDS (Suricata)", desc: "Detecção de intrusão", status: "ok", icon: "bi-shield-check", eventos: TOTAL_AMEACAS },
        { nome: "DNS (AdGuard)", desc: "Filtragem DNS", status: "ok", icon: "bi-globe-americas", eventos: TOTAL_DNS_B },
        { nome: "Firewall (nftables)", desc: "Controle de tráfego", status: "ok", icon: "bi-fire", eventos: 1847 },
        { nome: "Correlacionador", desc: "Engine de alertas", status: "ok", icon: "bi-cpu", eventos: null },
      ],
    },
  };

  /* ════════════════════════════════════════════════════════════
     PLUGINS CHART.JS
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
        ctx.shadowBlur = 20;
        meta.dataset.draw(ctx);
        ctx.shadowBlur = 8;
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
  let currentSev = "all";
  let isPaused = false;
  let feedCount = 0;
  let chartAtaques, chartDns, chartTimeline, chartCategorias;
  let lastData = null;
  let feedFilter = "all";

  /* ════════════════════════════════════════════════════════════
     API FETCH — tenta backend, cai no demo
  ════════════════════════════════════════════════════════════ */
  async function loadOverview(period = "24h", sev = "all") {
    try {
      const res = await fetch(`/painel/api/overview/?period=${period}&sev=${sev}`, {
        headers: { Accept: "application/json" },
        signal: AbortSignal.timeout(4000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      return data;
    } catch (_) {
      // Retorna dados demo
      return DEMO_DATA;
    }
  }

  /* ════════════════════════════════════════════════════════════
     RENDER PRINCIPAL
  ════════════════════════════════════════════════════════════ */
  async function render(period = currentPeriod, sev = currentSev) {
    try {
      const data = await loadOverview(period, sev);
      lastData = data;
      renderKpis(data);
      renderCharts(data);
      renderFeed(data.feed || []);
      renderIntel(data.intel || {});
      renderInfra(data.infra || {});
      renderSOC(data);
      renderMode(data);
      updateTime(data.last_update);
    } catch (e) {
      console.error("Falha ao carregar overview:", e);
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
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // ease out quart
      const eased = 1 - Math.pow(1 - progress, 4);
      const current = Math.round(start + (target - start) * eased);
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

    // Counter animado
    animateCounter(document.getElementById("kpiAmeacas"), Number(kpi.ameacas_hoje ?? 0));
    animateCounter(document.getElementById("kpiDns"), Number(kpi.dns_queries ?? 0), 1200, n => n.toLocaleString("pt-BR"));
    animateCounter(document.getElementById("kpiBloq"), Number(kpi.dns_bloqueios ?? 0), 1200, n => n.toLocaleString("pt-BR"));

    setEl("kpiBloqPct", `${kpi.bloqueio_pct ?? 0}%`);

    const sOn = kpi.sensores_online ?? 0;
    const sAll = kpi.sensores_total ?? 2;
    setEl("radarLabel", `${sOn}/${sAll}`);

    if (data.charts) {
      const total = (data.charts.attacks.crit || []).map((v, i) =>
        v + (data.charts.attacks.high[i] || 0) + (data.charts.attacks.med[i] || 0)
      );
      makeSparkline("sparkAmeacas", total, C.red);
      makeSparkline("sparkDns", data.charts.dns.queries || [], C.blue);
      makeSparkline("sparkBloq", data.charts.dns.blocked || [], C.yellow);
    }
  }

  /* ════════════════════════════════════════════════════════════
     SPARKLINES
  ════════════════════════════════════════════════════════════ */
  const _sparkInstances = {};
  function makeSparkline(id, data, color) {
    const el = document.getElementById(id); if (!el) return;
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
        scales: { x: { display: false }, y: { display: false } },
      }
    });
  }

  /* ════════════════════════════════════════════════════════════
     RADAR (doughnut — Sensores)
  ════════════════════════════════════════════════════════════ */
  let radarChart = null;
  function initRadar() {
    const el = document.getElementById("radarSensores"); if (!el || radarChart) return;
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
            borderColor: ["rgba(34,197,94,0.9)", "rgba(34,197,94,0.5)", "rgba(34,197,94,0.2)"],
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
        animation: { duration: 1500, easing: "easeOutQuart" },
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
      }
    });
  }

  /* ════════════════════════════════════════════════════════════
     RING CHARTS
  ════════════════════════════════════════════════════════════ */
  const _ringInstances = {};
  function makeRing(id, value, color, trackColor) {
    const el = document.getElementById(id); if (!el) return;
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
          borderColor: ["transparent", "transparent"],
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
     GRÁFICOS HORA A HORA — S2 (barras empilhadas, sem mudança)
  ════════════════════════════════════════════════════════════ */
  function renderCharts(data) {
    const ch = data.charts || {};
    const hours = ch.hours || [];
    const attacks = ch.attacks || { crit: [], high: [], med: [] };
    const dns = ch.dns || { queries: [], blocked: [] };

    /* — Ataques (stacked bar) — */
    const ctxA = document.getElementById("chartAtaques");
    if (ctxA) {
      const totalPerHour = attacks.crit.map((v, i) =>
        v + (attacks.high[i] || 0) + (attacks.med[i] || 0)
      );
      const trend = totalPerHour.map((_, i) => {
        const slice = totalPerHour.slice(Math.max(0, i - 2), i + 1);
        return Math.round(slice.reduce((a, b) => a + b, 0) / slice.length);
      });

      if (chartAtaques) {
        chartAtaques.data.labels = hours;
        chartAtaques.data.datasets[0].data = attacks.crit;
        chartAtaques.data.datasets[1].data = attacks.high;
        chartAtaques.data.datasets[2].data = attacks.med;
        chartAtaques.data.datasets[3].data = trend;
        chartAtaques.update("active");
      } else {
        const aCtx = ctxA.getContext("2d");
        const gradR = makeGrad(aCtx, "rgba(239,68,68,0.90)", "rgba(239,68,68,0.35)");
        const gradO = makeGrad(aCtx, "rgba(249,115,22,0.85)", "rgba(249,115,22,0.28)");
        const gradM = makeGrad(aCtx, "rgba(234,179,8,0.70)", "rgba(234,179,8,0.18)");
        chartAtaques = new Chart(ctxA, {
          type: "bar",
          data: {
            labels: hours,
            datasets: [
              { label: "Crítico", data: attacks.crit, backgroundColor: gradR, borderColor: C.red, borderWidth: 1, borderRadius: { topLeft: 3, topRight: 3 }, stack: "attacks" },
              { label: "Alto", data: attacks.high, backgroundColor: gradO, borderColor: C.orange, borderWidth: 1, stack: "attacks" },
              { label: "Médio", data: attacks.med, backgroundColor: gradM, borderColor: C.yellow, borderWidth: 1, stack: "attacks" },
              { label: "Tendência", data: trend, type: "line", borderColor: "rgba(255,255,255,0.30)", borderWidth: 1.5, borderDash: [4, 4], fill: false, tension: 0.5, pointRadius: 0, stack: "", enableGlow: false },
            ],
          },
          options: {
            responsive: true, maintainAspectRatio: false,
            interaction: { mode: "index", intersect: false },
            plugins: { legend: { display: false }, tooltip: { callbacks: { title: it => it[0].label, label: it => `  ${it.dataset.label}: ${it.raw}` } } },
            scales: {
              x: { stacked: true, grid: { color: C.grid, drawBorder: false }, ticks: { maxTicksLimit: 8, color: C.tick } },
              y: { stacked: true, grid: { color: C.grid, drawBorder: false }, ticks: { color: C.tick, stepSize: 5 }, min: 0 },
            },
            animation: { duration: 1000, easing: "easeOutQuart" },
          },
        });
      }
    }

    /* — DNS (bar + linha bloqueios) — */
    const ctxD = document.getElementById("chartDns");
    if (ctxD) {
      if (chartDns) {
        chartDns.data.labels = hours;
        chartDns.data.datasets[0].data = dns.queries;
        chartDns.data.datasets[1].data = dns.blocked;
        chartDns.update("active");
      } else {
        const dCtx = ctxD.getContext("2d");
        const gradB = makeGrad(dCtx, "rgba(59,130,246,0.80)", "rgba(59,130,246,0.18)");
        const gradRA = makeGrad(dCtx, "rgba(239,68,68,0.22)", "rgba(239,68,68,0.00)");
        chartDns = new Chart(ctxD, {
          type: "bar",
          data: {
            labels: hours,
            datasets: [
              { label: "Consultas", data: dns.queries, backgroundColor: gradB, borderColor: C.blue, borderWidth: 1, borderRadius: { topLeft: 3, topRight: 3 }, order: 2 },
              { label: "Bloqueios", data: dns.blocked, type: "line", borderColor: C.red, backgroundColor: gradRA, borderWidth: 2.5, fill: true, tension: 0.45, pointRadius: 0, pointHoverRadius: 5, pointHoverBackgroundColor: C.red, order: 1, enableGlow: true },
            ],
          },
          options: {
            responsive: true, maintainAspectRatio: false,
            interaction: { mode: "index", intersect: false },
            plugins: { legend: { display: false }, tooltip: { callbacks: { label: it => `  ${it.dataset.label}: ${Number(it.raw).toLocaleString("pt-BR")}` } } },
            scales: {
              x: { grid: { display: false }, ticks: { maxTicksLimit: 8, color: C.tick } },
              y: { grid: { color: C.grid, drawBorder: false }, ticks: { color: C.tick }, min: 0 },
            },
            animation: { duration: 1000, easing: "easeOutQuart" },
          },
        });
      }
    }
  }

  function makeGrad(ctx, top, bot) {
    const g = ctx.createLinearGradient(0, 0, 0, 280);
    g.addColorStop(0, top); g.addColorStop(1, bot); return g;
  }

  /* ════════════════════════════════════════════════════════════
     LIVE FEED — scroll HORIZONTAL mantido aqui
  ════════════════════════════════════════════════════════════ */
  const SEV_CLASS = { crit: "feed-item--crit", high: "feed-item--high", warn: "feed-item--warn", info: "feed-item--info" };
  const BADGE_CLASS = { crit: "feed-item__badge--crit", high: "feed-item__badge--high", warn: "feed-item__badge--warn", info: "feed-item__badge--info" };
  const BADGE_LABEL = { crit: "CRIT", high: "ALTO", warn: "MED", info: "INFO" };

  function renderFeed(items) {
    const scroll = document.getElementById("feedList"); if (!scroll) return;
    scroll.innerHTML = "";
    feedCount = 0;
    [...items].reverse().forEach(it => addFeedItem(it, true));
    setEl("feedCount", feedCount > 99 ? "99+" : feedCount);
  }

  function addFeedItem(tpl, silent = false) {
    const scroll = document.getElementById("feedList"); if (!scroll) return;
    if (isPaused && !silent) return;
    if (feedFilter !== "all" && tpl.type !== feedFilter) return;
    feedCount++;
    if (!silent) setEl("feedCount", feedCount > 99 ? "99+" : feedCount);

    const d = tpl.ts ? new Date(tpl.ts) : new Date();
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
    const lbl = document.getElementById("feedPauseLbl");
    const icon = document.getElementById("feedPauseIcon");
    if (lbl) lbl.textContent = isPaused ? "Retomar" : "Pausar";
    if (icon) icon.innerHTML = isPaused
      ? '<polygon points="5 3 19 12 5 21 5 3"/>'
      : '<rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/>';
  });

  document.getElementById("feedClearBtn")?.addEventListener("click", () => {
    const sc = document.getElementById("feedList"); if (!sc) return;
    sc.innerHTML = ""; feedCount = 0; setEl("feedCount", "0");
  });

  document.querySelectorAll(".feed-filter-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".feed-filter-btn").forEach(b => b.classList.remove("feed-filter-btn--active"));
      btn.classList.add("feed-filter-btn--active");
      feedFilter = btn.dataset.ft;
    });
  });

  /* ════════════════════════════════════════════════════════════
     INTEL — Top Origens + Top Ataques (SEM scroll horizontal)
  ════════════════════════════════════════════════════════════ */
  const SEV_COLORS = { crit: "#ef4444", high: "#f97316", med: "#eab308", info: "#3b82f6" };
  const SEV_BADGE = { crit: "sev-badge--crit", high: "sev-badge--high", med: "sev-badge--med" };

  function renderIntel(intel) {
    const origensEl = document.getElementById("intelOrigens");
    if (origensEl && intel.origens?.length) {
      origensEl.innerHTML = intel.origens.map((o, idx) => {
        const rankColors = ["#ef4444", "#f97316", "#eab308", "#6b7280", "#6b7280"];
        const rankCol = o.color || rankColors[idx] || "#6b7280";
        return `
        <div class="intel-row">
          <span class="intel-rank" style="color:${rankCol}">${o.rank}</span>
          <span class="intel-flag">${o.flag}</span>
          <span class="intel-name">${o.pais}</span>
          <div class="intel-bar-wrap">
            <div class="intel-bar intel-bar--anim" style="--bar-w:${o.pct}%;background:${rankCol}"></div>
          </div>
          <span class="intel-count" style="color:${rankCol}">${o.count}</span>
        </div>`;
      }).join("");
    }

    const ataquesEl = document.getElementById("intelAtaques");
    if (ataquesEl && intel.ataques?.length) {
      ataquesEl.innerHTML = intel.ataques.map(a => {
        const col = SEV_COLORS[a.sev] || "#6b7280";
        return `
        <div class="intel-attack-row">
          <div class="intel-attack-icon" style="background:${col}1a;border-color:${col}40;color:${col}">
            <i class="bi bi-shield-exclamation"></i>
          </div>
          <div class="intel-attack-body">
            <p class="intel-attack-name">${a.nome}</p>
            <p class="intel-attack-sub">${a.sub}</p>
          </div>
          <span class="sev-badge ${SEV_BADGE[a.sev] || ""}">${a.sev.toUpperCase()}</span>
          <span class="intel-count" style="color:${col};font-size:14px">${a.count}×</span>
        </div>`;
      }).join("");
    }
  }

  /* ════════════════════════════════════════════════════════════
     INFRA — 3 cards com rings
  ════════════════════════════════════════════════════════════ */
  function renderInfra(infra) {
    const dev = infra.dispositivos || {};
    const fw = infra.firewall || {};
    const dns = infra.dns_infra || {};

    const devPct = dev.pct ?? 0;
    setEl("infraDevOnline", dev.online ?? 0);
    setEl("infraDevOffline", dev.offline ?? 0);
    setEl("infraDevNovo", dev.novo_hoje ?? 0);
    setEl("infraDevPct", `${devPct}%`);
    setEl("infraDevOnline2", dev.online ?? 0);
    setEl("infraDevOffline2", dev.offline ?? 0);
    setEl("infraDevNovo2", dev.novo_hoje ?? 0);
    makeRing("ringDispositivos", devPct, C.green, "rgba(34,197,94,0.08)");

    const fwPct = fw.pct ?? 0;
    setEl("infraFwDrops", Number(fw.drops ?? 0).toLocaleString("pt-BR"));
    setEl("infraFwPorta", fw.top_porta ?? 22);
    setEl("infraFwBlocks", fw.blocks ?? 0);
    setEl("infraFwPct", `${fwPct}%`);
    setEl("infraFwDrops2", Number(fw.drops ?? 0).toLocaleString("pt-BR"));
    setEl("infraFwBlocks2", fw.blocks ?? 0);
    setEl("infraFwPorta2", `:${fw.top_porta ?? 22}`);
    makeRing("ringFirewall", fwPct, C.red, "rgba(239,68,68,0.08)");

    const dnsPct = dns.bloqueio_pct ?? 0;
    setEl("infraDnsPct", `${dnsPct}%`);
    setEl("infraDnsClientes", dns.clientes ?? 0);
    setEl("infraDnsAmeacas", dns.ameacas ?? 0);
    setEl("infraDnsRingPct", `${dnsPct}%`);
    setEl("infraDnsBloq2", Number(dns.bloqueios ?? 0).toLocaleString("pt-BR"));
    setEl("infraDnsPerm2", Number(dns.permitidos ?? 0).toLocaleString("pt-BR"));
    setEl("infraDnsClientes2", dns.clientes ?? 0);
    makeRing("ringDns", dnsPct, C.yellow, "rgba(234,179,8,0.08)");
  }

  /* ════════════════════════════════════════════════════════════
     S4 — SOC
  ════════════════════════════════════════════════════════════ */
  function renderSOC(data) {
    renderTimeline(data);
    renderTopIPs(data);
    renderCategorias(data);
    renderSaude(data);
  }

  /* SOC 1 — Timeline de Ataques (60 min) realista */
  function renderTimeline(data) {
    const tl = data.charts?.timeline || {};
    const labels = tl.labels || TL.labels;
    const crit = tl.crit || TL.crit;
    const high = tl.high || TL.high;
    const med = tl.med || TL.med;

    const el = document.getElementById("chartTimeline"); if (!el) return;

    // Total por minuto = crit + high + med
    const total = crit.map((v, i) => v + (high[i] || 0) + (med[i] || 0));

    // Envelope de pico (máximo local +35%)
    const peak = total.map((v, i) => {
      const w = total.slice(Math.max(0, i - 1), i + 2);
      return Math.round(Math.max(...w) * 1.35);
    });

    if (chartTimeline) {
      chartTimeline.data.labels = labels;
      chartTimeline.data.datasets[0].data = peak;
      chartTimeline.data.datasets[1].data = total;
      chartTimeline.data.datasets[2].data = high;
      chartTimeline.data.datasets[3].data = crit;
      chartTimeline.update("active");
      return;
    }

    const ctx = el.getContext("2d");

    function tlGrad(r, g, b, aTop, aBot) {
      const h = ctx.canvas.clientHeight || 220;
      const gr = ctx.createLinearGradient(0, 0, 0, h);
      gr.addColorStop(0, `rgba(${r},${g},${b},${aTop})`);
      gr.addColorStop(0.65, `rgba(${r},${g},${b},${aTop * 0.35})`);
      gr.addColorStop(1, `rgba(${r},${g},${b},${aBot})`);
      return gr;
    }

    chartTimeline = new Chart(el, {
      type: "line",
      data: {
        labels,
        datasets: [
          // Envelope cinza (fundo)
          {
            label: "Pico",
            data: peak,
            borderColor: "rgba(255,255,255,0.08)",
            borderWidth: 1,
            fill: true,
            backgroundColor: tlGrad(255, 255, 255, 0.06, 0.00),
            tension: 0.5,
            pointRadius: 0,
            order: 4,
          },
          // Total — linha vermelha com glow + área
          {
            label: "Total",
            data: total,
            borderColor: C.red,
            borderWidth: 2.5,
            fill: true,
            backgroundColor: tlGrad(239, 68, 68, 0.55, 0.02),
            tension: 0.45,
            pointRadius: 0,
            pointHoverRadius: 5,
            pointHoverBackgroundColor: C.red,
            pointHoverBorderColor: "#fff",
            pointHoverBorderWidth: 2,
            order: 3,
            enableGlow: true,
          },
          // Alto — laranja fino
          {
            label: "Alto",
            data: high,
            borderColor: C.orange,
            borderWidth: 1.5,
            fill: true,
            backgroundColor: tlGrad(249, 115, 22, 0.30, 0.00),
            tension: 0.45,
            pointRadius: 0,
            order: 2,
            enableGlow: true,
          },
          // Crítico — linha mais fina amarela/laranja escura
          {
            label: "Crítico",
            data: crit,
            borderColor: "#fbbf24",
            borderWidth: 1.2,
            fill: true,
            backgroundColor: tlGrad(251, 191, 36, 0.18, 0.00),
            tension: 0.45,
            pointRadius: 0,
            order: 1,
          },
        ],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              title: it => `⏱ ${it[0].label}`,
              label: it => `  ${it.dataset.label}: ${it.raw}`,
            }
          }
        },
        scales: {
          x: { grid: { color: C.grid, drawBorder: false }, ticks: { maxTicksLimit: 12, color: C.tick } },
          y: { grid: { color: C.grid, drawBorder: false }, ticks: { color: C.tick }, min: 0 },
        },
        animation: { duration: 900, easing: "easeOutQuart" },
      },
    });
  }

  /* SOC 2 — Top IPs Atacantes (SEM overflow horizontal — lista vertical) */
  function renderTopIPs(data) {
    const el = document.getElementById("socTopIPs"); if (!el) return;
    let items = data.intel?.top_ips || [];

    if (!items.length) {
      items = (data.intel?.origens || []).map((o, i) => ({
        ip: `45.${88 + i}.${12 + i}.${3 + i}`,
        flag: o.flag,
        pais: o.pais,
        count: o.count,
        tipo: ["SSH Brute Force", "Port Scan", "DNS Probe", "Web Crawler", "SMTP Probe"][i] || "Scan",
        sev: i === 0 ? "crit" : i < 3 ? "high" : "med",
        last: `${(i + 1) * 3}min`,
      }));
    }

    const SEV_C = { crit: C.red, high: C.orange, med: C.yellow, info: C.blue };
    const maxCount = Math.max(...items.map(it => Number(it.count) || 1), 1);

    el.innerHTML = items.slice(0, 7).map((it, idx) => {
      const col = SEV_C[it.sev] || "#6b7280";
      const barW = Math.round((Number(it.count) / maxCount) * 100);
      return `
      <div class="soc-ip-row">
        <span class="soc-ip-rank" style="color:${col}">${idx + 1}</span>
        <span class="soc-ip-flag">${it.flag || "🌐"}</span>
        <div class="soc-ip-body">
          <p class="soc-ip-addr">${it.ip}</p>
          <p class="soc-ip-meta">${it.pais} · ${it.tipo}</p>
          <div class="soc-ip-bar-wrap">
            <div class="soc-ip-bar" style="width:${barW}%;background:${col}"></div>
          </div>
        </div>
        <div class="soc-ip-right">
          <span class="soc-ip-count" style="color:${col}">${it.count}×</span>
          <span class="soc-ip-last">${it.last || "—"}</span>
        </div>
      </div>`;
    }).join("");
  }

  /* SOC 3 — Tipos de Ataque (donut) */
  function renderCategorias(data) {
    const cats = data.intel?.categorias || [];
    const kpiAmeacas = Number(data.kpis?.ameacas_hoje || 0);

    const items = cats.length ? cats : [
      { nome: "Reconhecimento", color: "#3b82f6", count: Math.round(kpiAmeacas * 0.34) || 34 },
      { nome: "Brute Force", color: "#ef4444", count: Math.round(kpiAmeacas * 0.25) || 25 },
      { nome: "DNS Abuse", color: "#f97316", count: Math.round(kpiAmeacas * 0.18) || 18 },
      { nome: "Exploits", color: "#a855f7", count: Math.round(kpiAmeacas * 0.12) || 12 },
      { nome: "Policy", color: "#eab308", count: Math.round(kpiAmeacas * 0.07) || 7 },
      { nome: "Outros", color: "#6b7280", count: Math.round(kpiAmeacas * 0.04) || 4 },
    ];

    const total = items.reduce((s, it) => s + (it.count || 0), 0);
    setEl("catTotal", total > 0 ? total.toLocaleString("pt-BR") : "—");

    const el = document.getElementById("chartCategorias");
    if (el) {
      if (chartCategorias) {
        chartCategorias.data.datasets[0].data = items.map(it => it.count);
        chartCategorias.update("active");
      } else {
        chartCategorias = new Chart(el, {
          type: "doughnut",
          data: {
            labels: items.map(it => it.nome),
            datasets: [{
              data: items.map(it => it.count),
              backgroundColor: items.map(it => (it.color || "#6b7280") + "cc"),
              borderColor: items.map(it => it.color || "#6b7280"),
              borderWidth: 1.5,
              hoverOffset: 8,
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

    const legend = document.getElementById("catLegend"); if (!legend) return;
    legend.innerHTML = items.map(it => {
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

  /* SOC 4 — Saúde do Sistema */
  function renderSaude(data) {
    const saude = data.saude || {};
    const kpi = data.kpis || {};
    const infra = data.infra || {};

    const sensors = saude.sensores || [
      { nome: "IDS (Suricata)", desc: "Detecção de intrusão", status: "ok", icon: "bi-shield-check", eventos: kpi.ameacas_hoje ?? 0 },
      { nome: "DNS (AdGuard)", desc: "Filtragem DNS", status: "ok", icon: "bi-globe-americas", eventos: kpi.dns_bloqueios ?? 0 },
      { nome: "Firewall (nftables)", desc: "Controle de tráfego", status: "ok", icon: "bi-fire", eventos: infra.firewall?.drops ?? 0 },
      { nome: "Correlacionador", desc: "Engine de alertas", status: "ok", icon: "bi-cpu", eventos: null },
    ];

    const metrics = saude.metricas || [
      { lbl: "Eventos/min", val: saude.eventos_min ?? (kpi.ameacas_hoje ? (kpi.ameacas_hoje / 1440).toFixed(1) : "0.0") },
      { lbl: "Latência API", val: saude.latencia_api ?? "< 12ms" },
      { lbl: "Fila Ingestão", val: saude.fila ?? 0 },
    ];

    const STATUS_COL = { ok: "#22c55e", warn: "#eab308", err: "#ef4444" };
    const STATUS_LBL = { ok: "ONLINE", warn: "ALERTA", err: "OFFLINE" };
    const STATUS_DOT = { ok: "sensor-dot--ok", warn: "sensor-dot--danger", err: "sensor-dot--danger" };

    const allOk = sensors.every(s => s.status === "ok");
    const hasWarn = sensors.some(s => s.status === "warn");
    const overall = document.getElementById("healthOverall");
    if (overall) {
      if (allOk) {
        overall.innerHTML = '<span class="sensor-dot sensor-dot--ok"></span> Operacional';
        overall.style.cssText = "color:#22c55e;background:rgba(34,197,94,.06);border-color:rgba(34,197,94,.18)";
      } else if (hasWarn) {
        overall.innerHTML = '<span class="sensor-dot sensor-dot--danger" style="background:#eab308;box-shadow:0 0 6px #eab308"></span> Com alertas';
        overall.style.cssText = "color:#eab308;background:rgba(234,179,8,.06);border-color:rgba(234,179,8,.18)";
      } else {
        overall.innerHTML = '<span class="sensor-dot sensor-dot--danger"></span> Degradado';
        overall.style.cssText = "color:#ef4444;background:rgba(239,68,68,.06);border-color:rgba(239,68,68,.18)";
      }
    }

    const healthGrid = document.getElementById("socHealthGrid"); if (!healthGrid) return;
    healthGrid.innerHTML = sensors.map(s => {
      const col = STATUS_COL[s.status] || "#6b7280";
      const lbl = STATUS_LBL[s.status] || s.status.toUpperCase();
      const evtStr = s.eventos != null ? ` · ${Number(s.eventos).toLocaleString("pt-BR")} evt` : "";
      return `
      <div class="soc-health-item">
        <div class="soc-health-icon" style="background:${col}1a;border:1px solid ${col}40;color:${col}">
          <i class="bi ${s.icon}"></i>
        </div>
        <div class="soc-health-body">
          <p class="soc-health-name">${s.nome}</p>
          <p class="soc-health-desc">${s.desc}${evtStr}</p>
        </div>
        <div class="soc-health-status soc-health-status--${s.status}">
          <span class="sensor-dot ${STATUS_DOT[s.status]}"></span>
          ${lbl}
        </div>
      </div>`;
    }).join("");

    const metricsRow = document.getElementById("socMetrics"); if (!metricsRow) return;
    metricsRow.innerHTML = metrics.map(m => `
    <div class="soc-metric">
      <p class="soc-metric__val">${m.val}</p>
      <p class="soc-metric__lbl">${m.lbl}</p>
    </div>`).join("");
  }

  /* ════════════════════════════════════════════════════════════
     MODO badge
  ════════════════════════════════════════════════════════════ */
  function renderMode(data) {
    const badge = document.getElementById("modeBadge");
    if (badge) {
      badge.textContent = data.mode === "demo" ? "DEMO" : "PROD";
      badge.style.color = data.mode === "demo" ? "#eab308" : "#22c55e";
      badge.style.borderColor = data.mode === "demo" ? "rgba(234,179,8,.3)" : "rgba(34,197,94,.3)";
    }
    if (data.node) {
      setEl("dashNodeName", data.node.name);
      setEl("dashNodeCidr", data.node.cidr);
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
    render(currentPeriod, currentSev).finally(() => {
      if (icon) icon.style.animation = "";
    });
  });

  document.getElementById("btnExport")?.addEventListener("click", () => {
    if (!lastData) return;
    const feed = lastData.feed || [];
    const rows = [
      ["Timestamp", "Tipo", "Severidade", "Origem", "Mensagem"],
      ...feed.map(f => [f.ts || "", f.type || "", f.sev || "", f.src || "", f.msg || ""]),
    ];
    const blob = new Blob([rows.map(r => r.join(",")).join("\n")], { type: "text/csv" });
    const a = Object.assign(document.createElement("a"), {
      href: URL.createObjectURL(blob),
      download: `jarvis-${new Date().toISOString().slice(0, 10)}.csv`,
    });
    a.click(); URL.revokeObjectURL(a.href);
  });

  /* ════════════════════════════════════════════════════════════
     ANIMAÇÕES CONTÍNUAS — simula atividade ao vivo
  ════════════════════════════════════════════════════════════ */
  // Injeta novos eventos no feed a cada 8-15s (simulando stream real)
  const LIVE_MSGS = [
    { type: "IDS", sev: "crit", src: "45.88.12.3:22", msg: "ET SCAN SSH BruteForce - 12 attempts/sec" },
    { type: "DNS", sev: "high", src: "192.168.1.33", msg: "Blocked: tracker.darkweb.cc (Threat Intel)" },
    { type: "FW", sev: "warn", src: "0.0.0.0:3389", msg: "DROP IN: RDP flood detected - 180pps" },
    { type: "IDS", sev: "high", src: "91.108.4.1:80", msg: "ET WEB Possible XSS in URI" },
    { type: "DNS", sev: "warn", src: "192.168.1.7", msg: "Blocked: ads.doubleclick.net (Category)" },
    { type: "IDS", sev: "med", src: "194.165.16.4:443", msg: "ET INFO Suspicious User-Agent (Masscan)" },
    { type: "FW", sev: "info", src: "8.8.8.8:53", msg: "ACCEPT OUT: DNS query resolved" },
    { type: "IDS", sev: "crit", src: "185.220.101.5:22", msg: "ET EXPLOIT Shellshock Attempt" },
  ];

  let liveIdx = 0;
  function injectLiveEvent() {
    if (isPaused) return;
    const msg = { ...LIVE_MSGS[liveIdx % LIVE_MSGS.length], ts: new Date().toISOString() };
    liveIdx++;
    addFeedItem(msg);
    // Pulsa o KPI de ameaças se for IDS crítico/alto
    if (msg.type === "IDS" && (msg.sev === "crit" || msg.sev === "high")) {
      const kpiEl = document.getElementById("kpiAmeacas");
      if (kpiEl) {
        kpiEl.style.transition = "color .2s";
        kpiEl.style.color = msg.sev === "crit" ? "#ef4444" : "#f97316";
        setTimeout(() => { kpiEl.style.color = ""; }, 600);
      }
    }
  }

  // Intervalo aleatório entre 8s e 16s
  function scheduleLive() {
    const delay = 8000 + Math.floor(Math.random() * 8000);
    setTimeout(() => { injectLiveEvent(); scheduleLive(); }, delay);
  }
  scheduleLive();

  /* ════════════════════════════════════════════════════════════
     POLLING — 30s
  ════════════════════════════════════════════════════════════ */
  setInterval(async () => {
    if (isPaused) return;
    try {
      const data = await loadOverview(currentPeriod, currentSev);
      lastData = data;
      renderKpis(data);
      renderCharts(data);
      renderTimeline(data);
      updateTime(data.last_update);
    } catch (_) { }
  }, 30_000);

  /* ════════════════════════════════════════════════════════════
     UTILS
  ════════════════════════════════════════════════════════════ */
  function setEl(id, val) {
    const el = document.getElementById(id); if (el) el.textContent = val;
  }

  function pad(n) { return String(n).padStart(2, "0"); }

  function updateTime(iso) {
    const el = document.getElementById("lastUpdate"); if (!el) return;
    const d = iso ? new Date(iso) : new Date();
    el.textContent = `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  /* ════════════════════════════════════════════════════════════
     BOOT
  ════════════════════════════════════════════════════════════ */
  initRadar();
  render("24h", "all");

});