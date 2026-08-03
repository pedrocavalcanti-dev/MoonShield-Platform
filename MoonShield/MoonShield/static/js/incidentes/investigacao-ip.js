'use strict';
/* =================================================================
   MOONSHIELD — INVESTIGACAO-IP.JS  v4.2
   Correções v4.2:
   - Null guards em supDominioGroup / supDominioVal (fix bug modal domínio)
   - supDominio campos são opcionais no HTML; JS não quebra se ausentes
================================================================= */

const INV = {
  ip:      window.INV_IP   || '0.0.0.0',
  horas:   window.INV_HORAS || 24,
  sim:     false,
  dados:   null,
  timeline:null,
  filtroTl:'all',
  charts:  { score: null, dir: null, heatmap: null, sparks: {} },
};

const $ = id => document.getElementById(id);
const fmt = n => n >= 1000 ? (n / 1000).toFixed(1) + 'k' : String(n);

function toast(msg, tipo = '') {
  const el = $('invToast');
  el.textContent = msg;
  el.className   = 'inv-toast show' + (tipo ? ` inv-toast--${tipo}` : '');
  clearTimeout(el._t);
  el._t = setTimeout(() => { el.className = 'inv-toast'; }, 3000);
}

function fmtHora(iso) {
  return new Date(iso).toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}
function fmtDataHora(iso) {
  return new Date(iso).toLocaleString('pt-BR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
}

function riskCor(score) {
  if (score >= 80) return '#f43f5e';
  if (score >= 60) return '#fb923c';
  if (score >= 40) return '#fbbf24';
  if (score >= 20) return '#38bdf8';
  return '#34d399';
}
function riskLabel(score) {
  if (score >= 80) return 'CRÍTICO';
  if (score >= 60) return 'ALTO';
  if (score >= 40) return 'MÉDIO';
  if (score >= 20) return 'BAIXO';
  return 'NORMAL';
}
function riskBadgeClass(score) {
  if (score >= 80) return 'inv-risk-badge--critical';
  if (score >= 60) return 'inv-risk-badge--high';
  if (score >= 40) return 'inv-risk-badge--medium';
  return 'inv-risk-badge--low';
}
function sevDotClass(sev) {
  const m = { critico: '--critico', alto: '--alto', medio: '--medio', baixo: '--baixo' };
  return 'inv-sev-dot' + (m[sev] || '--info');
}
function statusClass(s) {
  const m = { novo: '--novo', investigando: '--investigando', resolvido: '--resolvido', falso: '--falso' };
  return 'inv-inc-item__status' + (m[s] || '--novo');
}
function statusLabel(s) {
  return { novo: 'NOVO', investigando: 'INVEST.', resolvido: 'OK', falso: 'FP' }[s] || String(s || '').toUpperCase();
}

function hideLoading(id) { const el = $(id); if (el) el.style.display = 'none'; }
function showContent(id) { const el = $(id); if (el) el.style.display = 'block'; }

function destroyChart(key) {
  if (INV.charts[key]) { try { INV.charts[key].destroy(); } catch (_) {} INV.charts[key] = null; }
}
function destroySpark(key) {
  if (INV.charts.sparks[key]) { try { INV.charts.sparks[key].destroy(); } catch (_) {} INV.charts.sparks[key] = null; }
}

/* ─── animação de contador ─── */
function animCount(id, target) {
  const el = $(id); if (!el) return;
  const start = parseInt(el.textContent.replace('k', '')) || 0;
  const dur = 600, step = 16;
  let elapsed = 0;
  const timer = setInterval(() => {
    elapsed += step;
    const p    = Math.min(elapsed / dur, 1);
    const ease = 1 - Math.pow(1 - p, 3);
    el.textContent = fmt(Math.round(start + (target - start) * ease));
    if (p >= 1) clearInterval(timer);
  }, step);
}

/* ─── animação de barras ─── */
function animateBars(container) {
  requestAnimationFrame(() => {
    setTimeout(() => {
      container.querySelectorAll('[data-target]').forEach(bar => {
        bar.style.transition = 'width 0.7s cubic-bezier(0.16,1,0.3,1)';
        bar.style.width = bar.dataset.target;
      });
    }, 60);
  });
}

/* ─── Chart defaults ─── */
function setupChartDefaults() {
  Chart.defaults.color             = 'rgba(148,163,184,0.75)';
  Chart.defaults.font.family       = 'var(--font-mono, monospace)';
  Chart.defaults.font.size         = 10;
  Chart.defaults.borderColor       = 'rgba(255,255,255,0.05)';
  Chart.defaults.plugins.legend.display = false;
  Chart.defaults.plugins.tooltip.backgroundColor = 'rgba(8,12,26,0.97)';
  Chart.defaults.plugins.tooltip.borderColor     = 'rgba(255,255,255,0.12)';
  Chart.defaults.plugins.tooltip.borderWidth     = 1;
  Chart.defaults.plugins.tooltip.padding         = 12;
  Chart.defaults.plugins.tooltip.titleColor      = '#f1f5f9';
  Chart.defaults.plugins.tooltip.bodyColor       = 'rgba(148,163,184,0.9)';
  Chart.defaults.plugins.tooltip.cornerRadius    = 8;
  Chart.defaults.plugins.tooltip.titleFont       = { weight: '700', size: 11 };
  Chart.defaults.animation = { duration: 600, easing: 'easeOutQuart' };
}

/* ─── Gerador de série temporal ─── */
function gerarSerie(eventos, horas) {
  const now   = new Date();
  const start = new Date(now - horas * 3600000);
  const bucketMin   = horas <= 2 ? 2 : horas <= 6 ? 5 : horas <= 24 ? 15 : 60;
  const totalBuckets = Math.ceil((horas * 60) / bucketMin) + 1;

  const scoreArr = new Array(totalBuckets).fill(0);
  const counts   = {
    alert: new Array(totalBuckets).fill(0),
    dns:   new Array(totalBuckets).fill(0),
    http:  new Array(totalBuckets).fill(0),
    tls:   new Array(totalBuckets).fill(0),
  };
  const sevWeight  = { critico: 30, alto: 14, medio: 6, baixo: 2 };
  const tipoWeight = { alert: 3, dns: 0.5, http: 1, tls: 0.8 };

  (eventos || []).forEach(ev => {
    const ts = new Date(ev.timestamp);
    if (ts < start) return;
    const idx  = Math.max(0, Math.min(totalBuckets - 1,
      Math.floor((ts - start) / 60000 / bucketMin)));
    const tipo = ev.tipo || 'alert';
    counts[tipo][idx] = (counts[tipo][idx] || 0) + 1;
    const sev = ev.severidade_jg || ev.severidade || 'medio';
    scoreArr[idx] += (sevWeight[sev] || 5) * (tipoWeight[tipo] || 1);
  });

  const w      = [0.06, 0.24, 0.40, 0.24, 0.06];
  const smooth = scoreArr.map((_, i) =>
    w.reduce((acc, wi, j) => acc + wi * (scoreArr[i - 2 + j] || 0), 0));
  const maxV     = Math.max(...smooth, 1);
  const scoreNorm = smooth.map(v => Math.min(100, Math.round((v / maxV) * 100)));

  const labels = [];
  let cur = new Date(start);
  for (let i = 0; i < totalBuckets; i++) {
    labels.push(cur.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' }));
    cur = new Date(cur.getTime() + bucketMin * 60000);
  }

  const hourBuckets = new Array(24).fill(0);
  (eventos || []).forEach(ev => { hourBuckets[new Date(ev.timestamp).getHours()]++; });

  return { labels, score: scoreNorm, series: counts, hourBuckets };
}

/* ─── Simulação ─── */
function gerarSimulacao(ip) {
  const now = new Date();
  const ctx = {
    total_alertas: 47, total_dns: 312, total_http: 89, total_tls: 54,
    criticos: 3, altos: 12, medios: 18, baixos: 14,
    geo: {
      pais: 'Rússia', pais_codigo: 'RU', cidade: 'Moscou',
      asn_number: 'AS12389', asn_org: 'PJSC Rostelecom',
      rdns: 'client.example.ru', latitude: 55.7558, longitude: 37.6173,
    },
    risk_score: {
      score: 74.5, total_alertas: 47, criticos: 3, altos: 12, medios: 18,
      ultimo_alerta: new Date(now - 1800000).toISOString(),
    },
    direction_counts:  { inbound: 34, outbound: 9, lateral: 4 },
    direction_dominant:'inbound',
    top_sids: [
      { sid: '2100498', signature: 'ET SCAN Potential SSH Scan',       total: 18 },
      { sid: '2023019', signature: 'ET MALWARE CobaltStrike Beacon',   total: 9  },
      { sid: '2010935', signature: 'ET DNS Query to .ru TLD',          total: 14 },
      { sid: '2001328', signature: 'ET POLICY RDP connection',         total: 6  },
      { sid: '2034700', signature: 'ET EXPLOIT Log4Shell Attempt',     total: 4  },
    ],
    top_dominios: [
      { query: 'update.microsoft.com',        total: 45 },
      { query: 'api.telegram.org',            total: 23 },
      { query: 'raw.githubusercontent.com',   total: 17 },
      { query: '185.220.101.47.nip.io',       total: 11 },
      { query: 'cdn.discordapp.com',          total: 8  },
    ],
    top_user_agents: [
      { ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', total: 34 },
      { ua: 'python-requests/2.28.1',                                        total: 18 },
      { ua: 'curl/7.84.0',                                                   total: 7  },
    ],
  };

  const tipos  = ['alert', 'dns', 'http', 'tls'];
  const eventos = [];
  for (let i = 0; i < 100; i++) {
    const dt   = new Date(now - Math.random() * 86400000 * (INV.horas / 24));
    const tipo = tipos[Math.floor(Math.random() * tipos.length)];
    const ev   = { tipo, timestamp: dt.toISOString() };
    if (tipo === 'alert') {
      const sigs = ctx.top_sids.map(s => s.signature);
      const sevs = ['critico', 'critico', 'alto', 'alto', 'medio', 'medio', 'baixo'];
      ev.titulo        = sigs[Math.floor(Math.random() * sigs.length)];
      ev.severidade_jg = sevs[Math.floor(Math.random() * sevs.length)];
      ev.detalhe       = `${ip}:${Math.floor(Math.random() * 60000 + 1024)} → 10.0.0.${Math.floor(Math.random() * 254 + 1)}:${[22,3389,80,443][Math.floor(Math.random() * 4)]}`;
      ev.sid           = ctx.top_sids[Math.floor(Math.random() * ctx.top_sids.length)].sid;
      ev.status        = ['novo', 'investigando', 'resolvido'][Math.floor(Math.random() * 3)];
      ev.id            = 1000 + i;
    } else if (tipo === 'dns') {
      ev.titulo  = ctx.top_dominios[Math.floor(Math.random() * ctx.top_dominios.length)].query;
      ev.detalhe = 'tipo=A rcode=NOERROR';
    } else if (tipo === 'http') {
      ev.titulo  = `GET ${['/api/v1/data','/wp-admin/','/uploads/shell.php','/login'][Math.floor(Math.random() * 4)]}`;
      ev.detalhe = `status=${[200,403,404,500][Math.floor(Math.random() * 4)]} • python-requests/2.28.1`;
    } else {
      ev.titulo  = ['api.telegram.org','raw.githubusercontent.com','cdn.discordapp.com'][Math.floor(Math.random() * 3)];
      ev.detalhe = 'TLS 1.3 • ja3=a0e9f5d64349fb13191bc781f81f42e1';
    }
    eventos.push(ev);
  }
  eventos.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  return { ctx, timeline: { ok: true, eventos, total: eventos.length } };
}

/* ─── Fetch ─── */
async function carregarTudo() {
  if (INV.sim) {
    const sim    = gerarSimulacao(INV.ip);
    INV.dados    = { ok: true, contexto: sim.ctx };
    INV.timeline = sim.timeline;
    renderTudo();
    return;
  }
  try {
    const [ctxRes, tlRes] = await Promise.all([
      fetch(`/incidentes/api/ip/${encodeURIComponent(INV.ip)}/contexto/?horas=${INV.horas}`),
      fetch(`/incidentes/api/ip/${encodeURIComponent(INV.ip)}/timeline/?horas=${INV.horas}`),
    ]);
    INV.dados    = await ctxRes.json();
    INV.timeline = await tlRes.json();
    renderTudo();
  } catch (e) {
    toast('Erro ao carregar dados. Tente o modo simulação.', 'danger');
    console.error(e);
  }
}

/* ─── Render principal ─── */
function renderTudo() {
  if (!INV.dados?.ok) return;
  const ctx = INV.dados.contexto;
  renderTopbar(ctx);
  renderKpis(ctx);
  renderGeo(ctx.geo);
  renderRisk(ctx.risk_score);
  renderDirecao(ctx.direction_counts, ctx.direction_dominant);
  renderTopSigs(ctx.top_sids);
  renderTopDoms(ctx.top_dominios);
  renderUserAgents(ctx.top_user_agents);
  renderIncidentesRelacionados();
  renderAnaliseJG(ctx);
  if (INV.timeline?.ok) {
    renderTimeline(INV.timeline.eventos);
    renderCharts(INV.timeline.eventos, ctx);
  }
}

function renderTopbar(ctx) {
  const geo  = ctx.geo || {};
  const code = (geo.pais_codigo || '').toLowerCase();
  $('ipFlag').innerHTML = code
    ? `<span class="fi fi-${code}" style="border-radius:3px;font-size:22px;line-height:1"></span>`
    : '🌐';
  $('ipMeta').textContent = [geo.pais, geo.cidade, geo.asn_org].filter(Boolean).join(' · ') || 'IP Brasil';
  const score = ctx.risk_score?.score || 0;
  const badge = $('ipRiskBadge');
  badge.className = `inv-risk-badge ${riskBadgeClass(score)}`;
  $('ipRiskVal').textContent = `Score ${Math.round(score)}`;
}

function renderKpis(ctx) {
  animCount('kpiAlertas', ctx.total_alertas || 0);
  animCount('kpiDns',     ctx.total_dns     || 0);
  animCount('kpiHttp',    ctx.total_http    || 0);
  animCount('kpiTls',     ctx.total_tls     || 0);
  const score   = ctx.risk_score?.score || 0;
  const scoreEl = $('kpiScore');
  if (scoreEl) { animCount('kpiScore', Math.round(score)); scoreEl.style.color = riskCor(score); }
  const chip = $('kpiScoreLbl');
  if (chip) {
    chip.textContent = riskLabel(score);
    chip.style.cssText = `background:${riskCor(score)}1a;color:${riskCor(score)};border-color:${riskCor(score)}44`;
  }
  const criticos = ctx.criticos || ctx.risk_score?.criticos || 0;
  const kpiCrit  = $('kpiCriticos');
  if (kpiCrit) {
    kpiCrit.textContent = `${criticos} CRÍTICO${criticos !== 1 ? 'S' : ''}`;
    kpiCrit.style.display = criticos > 0 ? '' : 'none';
  }
}

function renderGeo(geo) {
  hideLoading('geoLoading');
  const el = $('geoData');
  if (!geo || !Object.keys(geo).length) {
    el.innerHTML = '<p class="inv-empty-text">Dados geo não disponíveis.</p>';
    showContent('geoData'); return;
  }
  const code    = (geo.pais_codigo || '').toLowerCase();
  const flagHtml = code
    ? `<span class="fi fi-${code}" style="border-radius:2px;font-size:12px;vertical-align:middle"></span>`
    : '🌐';
  const rows = [
    ['País',    `${flagHtml} ${geo.pais || ''}`],
    ['Cidade',  geo.cidade],
    ['ASN',     geo.asn_number],
    ['Org',     geo.asn_org],
    ['rDNS',    geo.rdns],
    ['Lat/Lon', geo.latitude ? `${geo.latitude.toFixed(2)}, ${geo.longitude.toFixed(2)}` : null],
  ];
  el.innerHTML = rows.filter(([, v]) => v).map(([l, v]) => `
    <div class="inv-geo-item">
      <span class="inv-geo-item__lbl">${l}</span>
      <span class="inv-geo-item__val">${v}</span>
    </div>`).join('');
  showContent('geoData');
}

function renderRisk(risk) {
  hideLoading('riskLoading');
  const el = $('riskData');
  if (!risk) { el.innerHTML = '<p class="inv-empty-text">Risk Score não calculado.</p>'; showContent('riskData'); return; }
  const score = risk.score || 0, cor = riskCor(score);
  el.innerHTML = `
    <div class="inv-risk-num" style="color:${cor}">${Math.round(score)}<span class="inv-risk-denom">/100</span></div>
    <div class="inv-risk-track"><div class="inv-risk-fill" style="width:0%;background:${cor}" id="riskFill"></div></div>
    <div class="inv-risk-labels">
      <span style="color:${cor};font-weight:700">${riskLabel(score)}</span>
      <span style="color:var(--text-dim)">${risk.total_alertas || 0} alertas</span>
    </div>
    <div class="inv-risk-breakdown">
      ${[['Críticos',risk.criticos||0,'#f43f5e'],['Altos',risk.altos||0,'#fb923c'],['Médios',risk.medios||0,'#fbbf24']].map(([l,v,c]) => `
        <div class="inv-risk-row">
          <span class="inv-risk-row__label"><span class="inv-risk-dot" style="background:${c}"></span>${l}</span>
          <span style="color:${c};font-weight:700">${v}</span>
        </div>`).join('')}
      ${risk.ultimo_alerta ? `<div class="inv-risk-row inv-risk-row--last"><span class="inv-risk-row__label">Último alerta</span><span>${fmtDataHora(risk.ultimo_alerta)}</span></div>` : ''}
    </div>`;
  showContent('riskData');
  requestAnimationFrame(() => setTimeout(() => { const f = $('riskFill'); if (f) f.style.width = score + '%'; }, 80));
}

function renderDirecao(counts, dominant) {
  hideLoading('dirLoading'); showContent('dirData');
  const c = counts || {};
  const data = [
    { key: 'inbound',  label: 'Entrada', color: '#f43f5e' },
    { key: 'outbound', label: 'Saída',   color: '#fb923c' },
    { key: 'lateral',  label: 'Lateral', color: '#fbbf24' },
    { key: 'external', label: 'Externo', color: '#c084fc' },
  ].filter(d => (c[d.key] || 0) > 0);

  if (!data.length) { $('dirData').innerHTML = '<p class="inv-empty-text">Sem dados de direção.</p>'; return; }

  const canvas = $('dirDonutChart'); if (!canvas) return;
  destroyChart('dir');
  const total = data.reduce((s, d) => s + (c[d.key] || 0), 0);

  const centerLabelPlugin = {
    id: 'centerLabel',
    afterDraw(chart) {
      const { ctx, chartArea: { width, height, left, top } } = chart;
      const cx = left + width / 2, cy = top + height / 2;
      const activeIdx = chart._active?.[0]?.index ?? -1;
      let mainText, subText, color;
      if (activeIdx >= 0) {
        const d = data[activeIdx];
        mainText = c[d.key] || 0; subText = d.label; color = d.color;
      } else {
        mainText = total;
        subText  = dominant
          ? { inbound:'ENTRADA', outbound:'SAÍDA', lateral:'LATERAL', external:'EXTERNO' }[dominant] || dominant.toUpperCase()
          : 'TOTAL';
        color = dominant ? (data.find(d => d.key === dominant)?.color || '#94a3b8') : '#94a3b8';
      }
      ctx.save();
      ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
      ctx.font = '700 20px var(--font-mono,monospace)';
      ctx.fillStyle = color; ctx.fillText(mainText, cx, cy - 8);
      ctx.font = '600 9px var(--font-mono,monospace)';
      ctx.fillStyle = 'rgba(148,163,184,0.7)';
      ctx.fillText(subText, cx, cy + 10);
      ctx.restore();
    },
  };

  INV.charts.dir = new Chart(canvas, {
    type: 'doughnut',
    plugins: [centerLabelPlugin],
    data: {
      labels: data.map(d => d.label),
      datasets: [{
        data:                  data.map(d => c[d.key] || 0),
        backgroundColor:       data.map(d => d.color + 'aa'),
        borderColor:           data.map(d => d.color),
        borderWidth:           1.5,
        hoverBackgroundColor:  data.map(d => d.color + 'dd'),
        hoverBorderWidth:      2.5,
        hoverOffset:           8,
      }],
    },
    options: {
      cutout: '70%',
      plugins: {
        legend: { display: false },
        tooltip: { callbacks: { label: ctx => ` ${ctx.label}: ${ctx.raw} (${Math.round(ctx.raw / total * 100)}%)` } },
      },
      onHover: (_, active) => { canvas.style.cursor = active.length ? 'pointer' : 'default'; },
    },
  });

  const labelsEl = $('dirLabels'); if (!labelsEl) return;
  const domLabels = {
    inbound:  'Tráfego majoritariamente de entrada — possível ataque externo',
    outbound: 'Tráfego majoritariamente de saída — possível exfiltração',
    lateral:  'Tráfego lateral — possível movimento interno',
    external: 'Tráfego externo para externo',
  };
  labelsEl.innerHTML = `
    <div class="inv-dir-legend">
      ${data.map(d => `
        <div class="inv-dir-legend-item">
          <span class="inv-dir-legend-dot" style="background:${d.color}"></span>
          <span class="inv-dir-legend-lbl">${d.label}</span>
          <span class="inv-dir-legend-val" style="color:${d.color}">${c[d.key] || 0}</span>
        </div>`).join('')}
    </div>
    ${dominant ? `<div class="inv-dir-dominant">
      <i class="bi bi-info-circle" style="flex-shrink:0;margin-top:1px;color:${data.find(d => d.key === dominant)?.color || '#94a3b8'}"></i>
      <span>${domLabels[dominant] || dominant}</span>
    </div>` : ''}`;
}

function renderTopSigs(sigs) {
  hideLoading('sigsLoading');
  const el = $('sigsContent');
  if (!sigs?.length) { el.innerHTML = '<p class="inv-empty-text">Nenhuma assinatura encontrada.</p>'; showContent('sigsContent'); return; }
  $('topSigsCount').textContent = sigs.length;
  const max = Math.max(...sigs.map(s => s.total), 1);
  el.innerHTML = sigs.slice(0, 8).map((s, i) => `
    <div class="inv-list-item">
      <span class="inv-list-item__rank">#${i + 1}</span>
      <div class="inv-list-item__info">
        <div class="inv-list-item__name" title="${s.signature}">${s.signature || s.sid}</div>
        <div class="inv-list-item__sub">SID ${s.sid}</div>
      </div>
      <div class="inv-list-item__bar"><div class="inv-list-item__bar-fill inv-list-item__bar-fill--alert" style="width:0%" data-target="${(s.total / max * 100).toFixed(0)}%"></div></div>
      <span class="inv-list-item__count">${s.total}</span>
    </div>`).join('');
  showContent('sigsContent'); animateBars(el);
}

function renderTopDoms(doms) {
  hideLoading('domsLoading');
  const el = $('domsContent');
  if (!doms?.length) { el.innerHTML = '<p class="inv-empty-text">Nenhuma consulta DNS encontrada.</p>'; showContent('domsContent'); return; }
  $('topDomsCount').textContent = doms.length;
  const max = Math.max(...doms.map(d => d.total), 1);
  el.innerHTML = doms.slice(0, 8).map((d, i) => `
    <div class="inv-list-item">
      <span class="inv-list-item__rank">#${i + 1}</span>
      <span class="inv-list-item__name" title="${d.query}">${d.query}</span>
      <div class="inv-list-item__bar"><div class="inv-list-item__bar-fill inv-list-item__bar-fill--dns" style="width:0%" data-target="${(d.total / max * 100).toFixed(0)}%"></div></div>
      <span class="inv-list-item__count">${d.total}</span>
    </div>`).join('');
  showContent('domsContent'); animateBars(el);
}

function renderUserAgents(uas) {
  hideLoading('uaLoading');
  const el = $('uaContent');
  if (!uas?.length) { el.innerHTML = '<p class="inv-empty-text">Nenhum user agent encontrado.</p>'; showContent('uaContent'); return; }
  const max = Math.max(...uas.map(u => u.total), 1);
  el.innerHTML = uas.slice(0, 5).map((u, i) => `
    <div class="inv-list-item">
      <span class="inv-list-item__rank">#${i + 1}</span>
      <div class="inv-list-item__info">
        <div class="inv-list-item__name" title="${u.ua}">${u.ua.length > 44 ? u.ua.slice(0, 44) + '…' : u.ua}</div>
      </div>
      <div class="inv-list-item__bar"><div class="inv-list-item__bar-fill inv-list-item__bar-fill--ua" style="width:0%" data-target="${(u.total / max * 100).toFixed(0)}%"></div></div>
      <span class="inv-list-item__count">${u.total}</span>
    </div>`).join('');
  showContent('uaContent'); animateBars(el);
}

function renderIncidentesRelacionados() {
  hideLoading('relLoading');
  const el = $('relContent');
  try {
    const alertas = (INV.timeline?.eventos || []).filter(e => e.tipo === 'alert').slice(0, 6);
    if (!alertas.length) { el.innerHTML = '<p class="inv-empty-text">Nenhum incidente encontrado.</p>'; showContent('relContent'); return; }
    el.innerHTML = alertas.map(e => `
      <div class="inv-inc-item">
        <span class="inv-sev-dot ${sevDotClass(e.severidade_jg || e.severidade)}"></span>
        <div class="inv-inc-item__body">
          <div class="inv-inc-item__title">${e.titulo || 'Alerta'}</div>
          <div class="inv-inc-item__meta">${fmtDataHora(e.timestamp)}</div>
        </div>
        <span class="inv-inc-item__status ${statusClass(e.status)}">${statusLabel(e.status)}</span>
      </div>`).join('');
    showContent('relContent');
  } catch { el.innerHTML = '<p class="inv-empty-text">Erro ao carregar incidentes.</p>'; showContent('relContent'); }
}

function renderAnaliseJG(ctx) {
  hideLoading('analysisLoading');
  const el       = $('analysisData');
  const score    = ctx.risk_score?.score || 0;
  const criticos = ctx.criticos || ctx.risk_score?.criticos || 0;
  const doms     = ctx.top_dominios || [], sigs = ctx.top_sids || [];

  let verdict = 'Comportamento normal', icon = 'bi-check-circle-fill', cor = '#34d399';
  let desc    = 'Nenhum indicador de comprometimento detectado. Atividade dentro do esperado.';
  if (score >= 70) {
    verdict = 'Alto risco detectado'; icon = 'bi-exclamation-octagon-fill'; cor = '#f43f5e';
    desc    = `Risk score crítico (${Math.round(score)}/100) com ${criticos} alerta(s) crítico(s). Investigação urgente recomendada.`;
  } else if (score >= 40) {
    verdict = 'Atividade suspeita'; icon = 'bi-exclamation-triangle-fill'; cor = '#fb923c';
    desc    = `Score elevado (${Math.round(score)}/100). Múltiplos alertas detectados. Revisão manual recomendada.`;
  }

  const tags = [];
  if (sigs.some(s => s.signature?.toLowerCase().includes('scan')))    tags.push({ t:'RECON',         c:'#fb923c' });
  if (sigs.some(s => s.signature?.toLowerCase().includes('malware'))) tags.push({ t:'MALWARE',        c:'#f43f5e' });
  if (sigs.some(s => s.signature?.toLowerCase().includes('cobalt')))  tags.push({ t:'C2',             c:'#f43f5e' });
  if (sigs.some(s => s.signature?.toLowerCase().includes('exploit'))) tags.push({ t:'EXPLOIT',        c:'#f43f5e' });
  if (doms.some(d => d.query?.endsWith('.ru') || d.query?.endsWith('.cn'))) tags.push({ t:'GEO-SUSPEITO', c:'#fbbf24' });
  if ((ctx.top_user_agents || []).some(u => u.ua?.includes('python') || u.ua?.includes('curl'))) tags.push({ t:'AUTOMAÇÃO', c:'#c084fc' });
  if (criticos > 0) tags.push({ t:'CRÍTICO', c:'#f43f5e' });
  if (!tags.length) tags.push({ t:'OK', c:'#34d399' });

  el.innerHTML = `
    <div class="inv-analysis-verdict">
      <div class="inv-analysis-verdict__icon" style="background:${cor}18;border-color:${cor}40;color:${cor}">
        <i class="bi ${icon}"></i>
      </div>
      <div class="inv-analysis-verdict__text">
        <div class="inv-analysis-verdict__title" style="color:${cor}">${verdict}</div>
        ${desc}
      </div>
    </div>
    <div class="inv-analysis-tags">
      ${tags.map(tg => `<span class="inv-analysis-tag" style="color:${tg.c};background:${tg.c}18;border-color:${tg.c}44">${tg.t}</span>`).join('')}
    </div>`;
  showContent('analysisData');
}

/* ══════════════ CHARTS ══════════════ */
function renderCharts(eventos, ctx) {
  const serie = gerarSerie(eventos, INV.horas);
  renderSparklines(serie);
  renderScoreChart(serie, ctx);
  renderHeatmap(serie);
}

function renderSparklines(serie) {
  const defs = [
    { id: 'sparkAlert', valId: 'sparkValAlert', key: 'alert', color: '#f43f5e' },
    { id: 'sparkDns',   valId: 'sparkValDns',   key: 'dns',   color: '#38bdf8' },
    { id: 'sparkHttp',  valId: 'sparkValHttp',  key: 'http',  color: '#34d399' },
    { id: 'sparkTls',   valId: 'sparkValTls',   key: 'tls',   color: '#c084fc' },
  ];
  defs.forEach((sp, si) => {
    const canvas = $(sp.id); const valEl = $(sp.valId);
    if (!canvas) return;
    const data  = serie.series[sp.key];
    const total = data.reduce((a, b) => a + b, 0);
    if (valEl) animCount(sp.valId, total);
    destroySpark(sp.key);
    const ctx2 = canvas.getContext('2d');
    const grad = ctx2.createLinearGradient(0, 0, 0, 40);
    grad.addColorStop(0, sp.color + '55'); grad.addColorStop(1, sp.color + '00');
    INV.charts.sparks[sp.key] = new Chart(canvas, {
      type: 'line',
      data: {
        labels: serie.labels,
        datasets: [{
          data, borderColor: sp.color, borderWidth: 1.8,
          pointRadius: 0, pointHoverRadius: 4,
          pointHoverBackgroundColor: sp.color, pointHoverBorderColor: '#0a0f1e', pointHoverBorderWidth: 2,
          fill: true, backgroundColor: grad, tension: 0.45,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        animation: { delay: si * 80, duration: 700 },
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: {
            title: items => `${items[0].label}`,
            label: item  => ` ${sp.key.toUpperCase()}: ${item.raw}`,
          }},
        },
        interaction: { mode: 'index', intersect: false },
        scales: { x: { display: false }, y: { display: false, min: 0 } },
      },
    });
  });
}

function renderScoreChart(serie, ctx) {
  const canvas = $('scoreChart'); if (!canvas) return;
  destroyChart('score');
  const score   = ctx.risk_score?.score || 0;
  const mainCor = riskCor(score);
  const ctx2    = canvas.getContext('2d');
  const grad    = ctx2.createLinearGradient(0, 0, 0, 130);
  grad.addColorStop(0, mainCor + '44'); grad.addColorStop(0.6, mainCor + '11'); grad.addColorStop(1, mainCor + '00');
  const gradAlert = ctx2.createLinearGradient(0, 0, 0, 130);
  gradAlert.addColorStop(0, '#fb923c28'); gradAlert.addColorStop(1, '#fb923c00');

  const segmentColor = context => {
    const v = context.p1.parsed.y;
    if (v >= 80) return '#f43f5e';
    if (v >= 60) return '#fb923c';
    if (v >= 40) return '#fbbf24';
    if (v >= 20) return '#38bdf8';
    return '#34d399';
  };

  INV.charts.score = new Chart(canvas, {
    type: 'line',
    data: {
      labels: serie.labels,
      datasets: [
        {
          label: 'Risk Score', data: serie.score,
          segment: { borderColor: segmentColor },
          borderWidth: 2.5, pointRadius: 0, pointHoverRadius: 5,
          pointHoverBackgroundColor: mainCor, pointHoverBorderColor: '#0a0f1e', pointHoverBorderWidth: 2,
          fill: true, backgroundColor: grad, tension: 0.4, yAxisID: 'y',
        },
        {
          label: 'Alertas', data: serie.series.alert,
          borderColor: '#fb923c', borderWidth: 1.5, borderDash: [5, 4],
          pointRadius: 0, pointHoverRadius: 4, pointHoverBackgroundColor: '#fb923c',
          fill: true, backgroundColor: gradAlert, tension: 0.3, yAxisID: 'y2',
        },
      ],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { display: false },
        tooltip: { callbacks: {
          title: items => `🕐 ${items[0].label}`,
          label: item  => item.datasetIndex === 0
            ? ` Score: ${item.raw}  ${riskLabel(item.raw)}`
            : ` Alertas: ${item.raw}`,
          labelColor: item => ({
            borderColor:     item.datasetIndex === 0 ? riskCor(item.raw) : '#fb923c',
            backgroundColor: item.datasetIndex === 0 ? riskCor(item.raw) : '#fb923c',
            borderRadius: 3,
          }),
        }},
      },
      scales: {
        x: {
          grid: { color: 'rgba(255,255,255,0.04)' },
          ticks: { maxTicksLimit: 8, maxRotation: 0, font: { size: 9 } },
        },
        y: {
          position: 'left', min: 0, max: 100,
          grid: { color: 'rgba(255,255,255,0.04)' },
          ticks: { stepSize: 25, color: ctx => {
            const v = ctx.tick.value;
            if (v >= 80) return '#f43f5e88';
            if (v >= 60) return '#fb923c88';
            if (v >= 40) return '#fbbf2488';
            return 'rgba(148,163,184,0.4)';
          }},
        },
        y2: {
          position: 'right', min: 0,
          grid: { display: false },
          ticks: { stepSize: 1, font: { size: 9 }, color: '#fb923c66' },
        },
      },
    },
  });
}

function renderHeatmap(serie) {
  const canvas = $('heatmapChart'); if (!canvas) return;
  destroyChart('heatmap');
  const max    = Math.max(...serie.hourBuckets, 1);
  const colors = serie.hourBuckets.map(v => {
    const r = v / max;
    if (r > 0.75) return '#f43f5e';
    if (r > 0.5)  return '#fb923c';
    if (r > 0.25) return '#fbbf24';
    if (r > 0)    return '#38bdf8';
    return 'rgba(148,163,184,0.1)';
  });
  INV.charts.heatmap = new Chart(canvas, {
    type: 'bar',
    data: {
      labels: Array.from({ length: 24 }, (_, i) => `${String(i).padStart(2, '0')}h`),
      datasets: [{
        data: serie.hourBuckets,
        backgroundColor: colors,
        borderColor: colors.map(c => c === 'rgba(148,163,184,0.1)' ? 'rgba(148,163,184,0.08)' : c + 'cc'),
        borderWidth: 1, borderRadius: 3, borderSkipped: false,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      animation: { duration: 700, delay: ctx => ctx.dataIndex * 12 },
      plugins: {
        legend: { display: false },
        tooltip: { callbacks: {
          title: items => `Hora: ${items[0].label}`,
          label: item  => ` ${item.raw} evento${item.raw !== 1 ? 's' : ''}`,
        }},
      },
      scales: {
        x: { grid: { display: false }, ticks: { font: { size: 8 }, maxRotation: 0 } },
        y: { display: false, min: 0 },
      },
    },
  });
}

/* ══════════════ TIMELINE ══════════════ */
function renderTimeline(eventos) {
  hideLoading('tlLoading');
  if (!eventos?.length) { $('tlEmpty').style.display = 'flex'; return; }
  const counts = { alert: 0, dns: 0, http: 0, tls: 0 };
  eventos.forEach(e => { if (counts[e.tipo] !== undefined) counts[e.tipo]++; });
  animCount('tlCount', eventos.length);
  ['Alert', 'Dns', 'Http', 'Tls'].forEach(k => animCount('tlCount' + k, counts[k.toLowerCase()]));
  INV._allEventos = eventos;
  aplicarFiltroTimeline(INV.filtroTl);
}

function aplicarFiltroTimeline(filtro) {
  INV.filtroTl = filtro;
  const eventos = INV._allEventos || [];
  const filtrado = filtro === 'all' ? eventos : eventos.filter(e => e.tipo === filtro);
  const list = $('tlList');
  if (!filtrado.length) { list.style.display = 'none'; $('tlEmpty').style.display = 'flex'; return; }
  $('tlEmpty').style.display = 'none'; list.style.display = 'block';
  let html = [], diaAtual = null;
  filtrado.forEach(ev => {
    const diaStr = new Date(ev.timestamp).toLocaleDateString('pt-BR', { weekday: 'long', day: '2-digit', month: 'long' });
    if (diaStr !== diaAtual) {
      diaAtual = diaStr;
      html.push(`<div class="inv-tl-day-sep"><div class="inv-tl-day-sep__line"></div><span class="inv-tl-day-sep__label">${diaStr}</span><div class="inv-tl-day-sep__line"></div></div>`);
    }
    html.push(renderTlItem(ev));
  });
  list.innerHTML = html.join('');
  list.querySelectorAll('[data-inc-id]').forEach(el => {
    el.addEventListener('click', () => window.open(`/incidentes/?id=${el.dataset.incId}`, '_blank'));
  });
}

function iconeTipo(tipo) {
  return { alert:'bi-exclamation-triangle-fill', dns:'bi-globe2', http:'bi-arrow-left-right', tls:'bi-lock-fill' }[tipo] || 'bi-circle';
}

function renderTlItem(ev) {
  const attrs    = ev.id ? `data-inc-id="${ev.id}"` : '';
  const sevBadge = (ev.severidade_jg && ev.tipo === 'alert')
    ? `<span class="inv-sev-dot ${sevDotClass(ev.severidade_jg)}"></span>`
    : '';
  return `
    <div class="inv-tl-item inv-tl-item--${ev.tipo}" ${attrs}>
      <div class="inv-tl-dot"><i class="bi ${iconeTipo(ev.tipo)}"></i></div>
      <div class="inv-tl-content">
        <div class="inv-tl-row">${sevBadge}<div class="inv-tl-title-text">${ev.titulo || '—'}</div></div>
        <div class="inv-tl-meta">${ev.detalhe || ''}</div>
      </div>
      <div class="inv-tl-time">${fmtHora(ev.timestamp)}</div>
    </div>`;
}

/* ─── Modal de supressão ─── */
function abrirModalSupressao() { $('modalOverlay').classList.add('open'); $('acoesDropdown').classList.remove('open'); }
function fecharModalSupressao() { $('modalOverlay').classList.remove('open'); }

/* ─── Exportar JSON ─── */
function exportarJSON() {
  const payload = {
    ip:        INV.ip,
    horas:     INV.horas,
    gerado:    new Date().toISOString(),
    simulado:  INV.sim,
    contexto:  INV.dados?.contexto || null,
    timeline:  INV.timeline?.eventos || [],
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.download = `jg_investigacao_${INV.ip.replace(/[\.:]/g, '_')}_${Date.now()}.json`;
  a.href = url; a.click(); URL.revokeObjectURL(url);
  toast('JSON exportado com sucesso!', 'ok');
  $('acoesDropdown').classList.remove('open');
}

/* ─── Init ─── */
document.addEventListener('DOMContentLoaded', () => {
  setupChartDefaults();

  $('btnRefresh')?.addEventListener('click', () => {
    const btn = $('btnRefresh');
    btn.disabled = true;
    btn.querySelector('i')?.classList.add('spinning');
    carregarTudo().finally(() => {
      btn.disabled = false;
      btn.querySelector('i')?.classList.remove('spinning');
    });
  });

  document.querySelectorAll('.inv-period__btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.inv-period__btn').forEach(b => b.classList.remove('inv-period__btn--active'));
      btn.classList.add('inv-period__btn--active');
      INV.horas = parseInt(btn.dataset.h);
      carregarTudo();
    });
  });

  document.querySelectorAll('.inv-tl-filter').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.inv-tl-filter').forEach(b => b.classList.remove('inv-tl-filter--active'));
      btn.classList.add('inv-tl-filter--active');
      aplicarFiltroTimeline(btn.dataset.tipo);
    });
  });

  $('btnSimular')?.addEventListener('click', () => {
    INV.sim = !INV.sim;
    $('btnSimular').classList.toggle('active', INV.sim);
    const banner = $('simBanner');
    if (banner) banner.style.display = INV.sim ? 'flex' : 'none';
    toast(INV.sim ? 'Modo simulação ativado — dados fictícios' : 'Modo simulação desativado');
    carregarTudo();
  });
  $('simBannerClose')?.addEventListener('click', () => { $('simBanner').style.display = 'none'; });

  $('btnAcoes')?.addEventListener('click', e => { e.stopPropagation(); $('acoesDropdown').classList.toggle('open'); });
  document.addEventListener('click', e => { if (!e.target.closest('.inv-actions-wrap')) $('acoesDropdown')?.classList.remove('open'); });

  $('optSupressao')?.addEventListener('click', abrirModalSupressao);
  $('optExportar')?.addEventListener('click',  exportarJSON);
  $('optBloquear')?.addEventListener('click',  () => { toast('IP sinalizado como ameaça!', 'danger'); $('acoesDropdown').classList.remove('open'); });

  $('modalClose')?.addEventListener('click',  fecharModalSupressao);
  $('modalCancel')?.addEventListener('click', fecharModalSupressao);
  $('modalOverlay')?.addEventListener('click', e => { if (e.target === $('modalOverlay')) fecharModalSupressao(); });

  // FIX: null guards — os elementos supSidGroup / supDominioGroup são opcionais no HTML
  $('supTipo')?.addEventListener('change', e => {
    const val = e.target.value;
    const sidGrp = $('supSidGroup');
    const domGrp = $('supDominioGroup');
    if (sidGrp) sidGrp.style.display    = val === 'sid'     ? 'flex' : 'none';
    if (domGrp) domGrp.style.display    = val === 'dominio' ? 'flex' : 'none';
  });

  $('modalConfirm')?.addEventListener('click', () => {
    const tipo   = $('supTipo')?.value || 'ip_src';
    const motivo = $('supMotivo')?.value.trim() || '';
    if (!motivo) { toast('Informe o motivo da supressão.', 'danger'); return; }
    if (INV.sim)  { toast('Supressão criada (simulação)!', 'ok'); fecharModalSupressao(); return; }
    function getCookie(name) { const v = document.cookie.match(`(^|;)\\s*${name}\\s*=\\s*([^;]+)`); return v ? v.pop() : ''; }
    fetch('/incidentes/api/supressao/', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCookie('csrftoken') },
      body: JSON.stringify({
        tipo,
        ip:      tipo === 'ip_src'  ? INV.ip : null,
        // FIX: optional chaining — não quebra se o elemento não existir no HTML
        sid:     tipo === 'sid'     ? ($('supSidVal')?.value.trim()     || null) : null,
        dominio: tipo === 'dominio' ? ($('supDominioVal')?.value.trim() || null) : null,
        motivo,
        expira:  $('supExpira')?.value || null,
      }),
    }).then(r => r.json()).then(d => {
      if (d.ok || d.id) { toast('Supressão criada!', 'ok'); fecharModalSupressao(); }
      else throw new Error(d.erro || 'Erro');
    }).catch(err => toast('Erro ao criar supressão: ' + err.message, 'danger'));
  });

  document.addEventListener('keydown', e => { if (e.key === 'Escape') fecharModalSupressao(); });

  if (typeof ResizeObserver !== 'undefined') {
    let timer;
    const obs = new ResizeObserver(() => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        if (INV.timeline?.ok && INV.dados?.ok) {
          const serie = gerarSerie(INV.timeline.eventos, INV.horas);
          renderSparklines(serie);
          renderScoreChart(serie, INV.dados.contexto);
          renderHeatmap(serie);
        }
      }, 200);
    });
    const el = document.querySelector('.inv-score-chart-wrap');
    if (el) obs.observe(el);
  }

  carregarTudo();
});