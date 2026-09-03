'use strict';
/* MOONSHIELD — investigacao-ip.js v6
   Mantém endpoints e recursos existentes, melhora segurança/renderização
   e adiciona tooltips externos ricos para todos os gráficos Chart.js. */

const INV = {
  ip: window.INV_IP || '0.0.0.0', horas: window.INV_HORAS || 24, sim: false,
  dados: null, timeline: null, filtroTl: 'all', _allEventos: [],
  timelinePageSize: 16, timelineVisible: 16,
  charts: { score: null, dir: null, heatmap: null, sparks: {} },
};

const $ = id => document.getElementById(id);
const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[ch]));
const fmt = n => Number(n || 0) >= 1000 ? `${(Number(n) / 1000).toFixed(1)}k` : String(Number(n || 0));
const clamp = (n, min, max) => Math.min(max, Math.max(min, n));
const pct = (part, total) => total > 0 ? Math.round((part / total) * 100) : 0;

function toast(msg, tipo = '') {
  const el = $('invToast'); if (!el) return;
  el.textContent = msg; el.className = `inv-toast show${tipo ? ` inv-toast--${tipo}` : ''}`;
  clearTimeout(el._t); el._t = setTimeout(() => { el.className = 'inv-toast'; }, 3000);
}
function fmtHora(iso) {
  const d = new Date(iso); return Number.isNaN(d.getTime()) ? '—' : d.toLocaleTimeString('pt-BR', { hour:'2-digit', minute:'2-digit', second:'2-digit' });
}
function fmtDataHora(iso) {
  const d = new Date(iso); return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString('pt-BR', { day:'2-digit', month:'2-digit', hour:'2-digit', minute:'2-digit' });
}
function riskCor(score) {
  if (score >= 80) return '#f43f5e'; if (score >= 60) return '#fb923c';
  if (score >= 40) return '#fbbf24'; if (score >= 20) return '#38bdf8'; return '#34d399';
}
function riskLabel(score) {
  if (score >= 80) return 'CRÍTICO'; if (score >= 60) return 'ALTO';
  if (score >= 40) return 'MÉDIO'; if (score >= 20) return 'BAIXO'; return 'NORMAL';
}
function riskBadgeClass(score) {
  if (score >= 80) return 'inv-risk-badge--critical'; if (score >= 60) return 'inv-risk-badge--high';
  if (score >= 40) return 'inv-risk-badge--medium'; return 'inv-risk-badge--low';
}
function sevDotClass(sev) {
  return `inv-sev-dot${({ critico:'--critico', alto:'--alto', medio:'--medio', baixo:'--baixo' })[sev] || '--info'}`;
}
function statusClass(s) {
  return `inv-inc-item__status${({ novo:'--novo', investigando:'--investigando', resolvido:'--resolvido', falso:'--falso' })[s] || '--novo'}`;
}
function statusLabel(s) { return ({ novo:'NOVO', investigando:'INVEST.', resolvido:'OK', falso:'FP' })[s] || String(s || '').toUpperCase(); }
function hideLoading(id) { const el = $(id); if (el) el.style.display = 'none'; }
function showContent(id, display = 'block') { const el = $(id); if (el) el.style.display = display; }
function getCookie(name) {
  const match = document.cookie.match(new RegExp(`(?:^|;\\s*)${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : '';
}
async function fetchJson(url, options = {}) {
  const res = await fetch(url, { cache:'no-store', ...options });
  const ct = res.headers.get('content-type') || '';
  if (!ct.includes('application/json')) throw new Error(`Resposta inválida do servidor (HTTP ${res.status})`);
  const data = await res.json();
  if (!res.ok) throw new Error(data?.erro || data?.detail || data?.message || `HTTP ${res.status}`);
  return data;
}
function destroyChart(key) {
  if (!INV.charts[key]) return;
  try { INV.charts[key].destroy(); } catch (_) {}
  INV.charts[key] = null;
}
function destroySpark(key) {
  if (!INV.charts.sparks[key]) return;
  try { INV.charts.sparks[key].destroy(); } catch (_) {}
  INV.charts.sparks[key] = null;
}
function animCount(id, target) {
  const el = $(id); if (!el) return;
  const targetNum = Number(target || 0), start = Number(String(el.textContent).replace(/[^\d.-]/g, '')) || 0;
  const started = performance.now(), duration = 520;
  const frame = now => {
    const p = clamp((now - started) / duration, 0, 1), ease = 1 - Math.pow(1 - p, 3);
    el.textContent = fmt(Math.round(start + (targetNum - start) * ease));
    if (p < 1) requestAnimationFrame(frame);
  };
  requestAnimationFrame(frame);
}
function animateBars(container) {
  if (!container) return;
  requestAnimationFrame(() => setTimeout(() => container.querySelectorAll('[data-target]').forEach(bar => {
    bar.style.transition = 'width .65s cubic-bezier(.16,1,.3,1)'; bar.style.width = bar.dataset.target;
  }), 50));
}

/* ---------- Tooltips externos dos gráficos ---------- */
function tooltipEl() { return $('invChartTooltip'); }
function hideChartTooltip() {
  const el = tooltipEl(); if (!el) return;
  el.classList.remove('is-visible'); el.setAttribute('aria-hidden', 'true');
}
function positionTooltip(el, canvas, caretX, caretY) {
  const r = canvas.getBoundingClientRect(), margin = 12;
  el.style.left = '0px'; el.style.top = '0px';
  const w = el.offsetWidth || 230, h = el.offsetHeight || 110;
  let x = r.left + caretX + 14, y = r.top + caretY + 14;
  if (x + w + margin > window.innerWidth) x = r.left + caretX - w - 14;
  if (y + h + margin > window.innerHeight) y = r.top + caretY - h - 14;
  el.style.left = `${Math.max(margin, x)}px`; el.style.top = `${Math.max(margin, y)}px`;
}
function showChartTooltip(context, content) {
  const { chart, tooltip } = context, el = tooltipEl(); if (!el) return;
  if (!tooltip || tooltip.opacity === 0) { hideChartTooltip(); return; }
  el.innerHTML = content;
  el.classList.add('is-visible'); el.setAttribute('aria-hidden', 'false');
  positionTooltip(el, chart.canvas, tooltip.caretX, tooltip.caretY);
}
function tooltipHtml(title, rows, note = '') {
  return `<div class="inv-chart-tooltip__title">${esc(title)}</div>
    ${rows.map(r => `<div class="inv-chart-tooltip__row"><span class="inv-chart-tooltip__dot" style="background:${r.color || '#94a3b8'}"></span><span>${esc(r.label)}</span><strong${r.valueColor ? ` style="color:${r.valueColor}"` : ''}>${esc(r.value)}</strong></div>`).join('')}
    ${note ? `<div class="inv-chart-tooltip__note">${esc(note)}</div>` : ''}`;
}
function externalSparkTooltip(name, color, total) {
  return context => {
    const t = context.tooltip;
    if (!t || t.opacity === 0) return hideChartTooltip();
    const dp = t.dataPoints?.[0]; if (!dp) return hideChartTooltip();
    const value = Number(dp.raw || 0);
    showChartTooltip(context, tooltipHtml(dp.label || 'Período', [
      { label:name, value:String(value), color, valueColor:color },
      { label:'Participação', value:`${pct(value, total)}% do total`, color:'#64748b' },
    ], value ? 'Movimente o cursor pelo gráfico para acompanhar cada intervalo.' : 'Nenhum evento neste intervalo.'));
  };
}
function externalScoreTooltip(serie) {
  return context => {
    const t = context.tooltip;
    if (!t || t.opacity === 0) return hideChartTooltip();
    const idx = t.dataPoints?.[0]?.dataIndex; if (idx == null) return hideChartTooltip();
    const score = Number(serie.score[idx] || 0), alerts = Number(serie.series.alert[idx] || 0);
    showChartTooltip(context, tooltipHtml(serie.labels[idx] || 'Período', [
      { label:'Risk Score', value:`${score}/100 · ${riskLabel(score)}`, color:riskCor(score), valueColor:riskCor(score) },
      { label:'Alertas', value:String(alerts), color:'#fb923c' },
      { label:'DNS', value:String(serie.series.dns[idx] || 0), color:'#38bdf8' },
      { label:'HTTP', value:String(serie.series.http[idx] || 0), color:'#34d399' },
      { label:'TLS', value:String(serie.series.tls[idx] || 0), color:'#c084fc' },
    ], score >= 60 ? 'Faixa de risco elevada neste intervalo.' : 'Score calculado pela concentração e severidade dos eventos.'));
  };
}
function externalHeatTooltip(serie) {
  const total = serie.hourBuckets.reduce((a,b) => a + b, 0), max = Math.max(...serie.hourBuckets, 1);
  return context => {
    const t = context.tooltip;
    if (!t || t.opacity === 0) return hideChartTooltip();
    const dp = t.dataPoints?.[0]; if (!dp) return hideChartTooltip();
    const idx = dp.dataIndex, value = Number(dp.raw || 0), ratio = value / max;
    const level = ratio > .75 ? 'Muito alta' : ratio > .5 ? 'Alta' : ratio > .25 ? 'Média' : value > 0 ? 'Baixa' : 'Sem atividade';
    const color = ratio > .75 ? '#f43f5e' : ratio > .5 ? '#fb923c' : ratio > .25 ? '#fbbf24' : value > 0 ? '#38bdf8' : '#64748b';
    showChartTooltip(context, tooltipHtml(`Faixa ${String(idx).padStart(2,'0')}:00–${String((idx + 1) % 24).padStart(2,'0')}:00`, [
      { label:'Eventos', value:String(value), color, valueColor:color },
      { label:'Intensidade', value:level, color },
      { label:'Participação', value:`${pct(value, total)}%`, color:'#64748b' },
    ], 'A intensidade é relativa ao horário com maior volume dentro do período carregado.'));
  };
}
function externalDirectionTooltip(data, counts, total) {
  return context => {
    const t = context.tooltip;
    if (!t || t.opacity === 0) return hideChartTooltip();
    const dp = t.dataPoints?.[0]; if (!dp) return hideChartTooltip();
    const d = data[dp.dataIndex], value = Number(counts[d.key] || 0);
    showChartTooltip(context, tooltipHtml(`Direção: ${d.label}`, [
      { label:'Eventos', value:String(value), color:d.color, valueColor:d.color },
      { label:'Participação', value:`${pct(value, total)}%`, color:d.color },
    ], ({ inbound:'Tráfego recebido pelo ativo investigado.', outbound:'Tráfego originado pelo ativo investigado.', lateral:'Movimento entre ativos internos.', external:'Comunicação externa classificada.' })[d.key] || ''));
  };
}

/* Linha vertical no ponto sob o mouse. */
const hoverLinePlugin = {
  id:'msHoverLine',
  afterDatasetsDraw(chart) {
    const active = chart.tooltip?.getActiveElements?.() || []; if (!active.length || !chart.chartArea) return;
    const x = active[0].element.x, { ctx, chartArea:{ top, bottom } } = chart;
    ctx.save(); ctx.beginPath(); ctx.moveTo(x, top); ctx.lineTo(x, bottom);
    ctx.lineWidth = 1; ctx.strokeStyle = 'rgba(148,163,184,.22)'; ctx.setLineDash([3,3]); ctx.stroke(); ctx.restore();
  }
};

function setupChartDefaults() {
  if (typeof Chart === 'undefined') { toast('Chart.js não foi carregado.', 'danger'); return false; }
  Chart.defaults.color = 'rgba(148,163,184,.75)';
  Chart.defaults.font.family = '"JetBrains Mono", ui-monospace, SFMono-Regular, Consolas, monospace';
  Chart.defaults.font.size = 10; Chart.defaults.borderColor = 'rgba(255,255,255,.05)';
  Chart.defaults.plugins.legend.display = false;
  Chart.defaults.plugins.tooltip.enabled = false;
  Chart.defaults.animation = { duration:520, easing:'easeOutQuart' };
  return true;
}

/* ---------- Séries ---------- */
function gerarSerie(eventos, horas) {
  const now = new Date(), start = new Date(now.getTime() - horas * 3600000);
  const bucketMin = horas <= 2 ? 2 : horas <= 6 ? 5 : horas <= 24 ? 15 : 60;
  const totalBuckets = Math.ceil((horas * 60) / bucketMin) + 1;
  const scoreArr = new Array(totalBuckets).fill(0);
  const counts = { alert:new Array(totalBuckets).fill(0), dns:new Array(totalBuckets).fill(0), http:new Array(totalBuckets).fill(0), tls:new Array(totalBuckets).fill(0) };
  const sevWeight = { critico:30, alto:14, medio:6, baixo:2 }, tipoWeight = { alert:3, dns:.5, http:1, tls:.8 };

  (eventos || []).forEach(ev => {
    const ts = new Date(ev.timestamp); if (Number.isNaN(ts.getTime()) || ts < start) return;
    const idx = clamp(Math.floor((ts - start) / 60000 / bucketMin), 0, totalBuckets - 1);
    const tipo = counts[ev.tipo] ? ev.tipo : 'alert';
    counts[tipo][idx] += 1;
    const sev = ev.severidade_jg || ev.severidade || 'medio';
    scoreArr[idx] += (sevWeight[sev] || 5) * (tipoWeight[tipo] || 1);
  });

  const weights = [.06,.24,.40,.24,.06];
  const smooth = scoreArr.map((_, i) => weights.reduce((acc, w, j) => acc + w * (scoreArr[i - 2 + j] || 0), 0));
  const maxV = Math.max(...smooth, 1), score = smooth.map(v => Math.min(100, Math.round((v / maxV) * 100)));

  const labels = Array.from({ length:totalBuckets }, (_, i) => new Date(start.getTime() + i * bucketMin * 60000).toLocaleTimeString('pt-BR', { hour:'2-digit', minute:'2-digit' }));
  const hourBuckets = new Array(24).fill(0);
  (eventos || []).forEach(ev => { const d = new Date(ev.timestamp); if (!Number.isNaN(d.getTime())) hourBuckets[d.getHours()] += 1; });
  return { labels, score, series:counts, hourBuckets, bucketMin };
}

/* ---------- Simulação ---------- */
function gerarSimulacao(ip) {
  const now = new Date();
  const ctx = {
    total_alertas:47,total_dns:312,total_http:89,total_tls:54,criticos:3,altos:12,medios:18,baixos:14,
    geo:{pais:'Rússia',pais_codigo:'RU',cidade:'Moscou',asn_number:'AS12389',asn_org:'PJSC Rostelecom',rdns:'client.example.ru',latitude:55.7558,longitude:37.6173},
    risk_score:{score:74.5,total_alertas:47,criticos:3,altos:12,medios:18,ultimo_alerta:new Date(now-1800000).toISOString()},
    direction_counts:{inbound:34,outbound:9,lateral:4},direction_dominant:'inbound',
    top_sids:[
      {sid:'2100498',signature:'ET SCAN Potential SSH Scan',total:18},{sid:'2023019',signature:'ET MALWARE CobaltStrike Beacon',total:9},
      {sid:'2010935',signature:'ET DNS Query to .ru TLD',total:14},{sid:'2001328',signature:'ET POLICY RDP connection',total:6},
      {sid:'2034700',signature:'ET EXPLOIT Log4Shell Attempt',total:4}
    ],
    top_dominios:[
      {query:'update.microsoft.com',total:45},{query:'api.telegram.org',total:23},{query:'raw.githubusercontent.com',total:17},
      {query:'185.220.101.47.nip.io',total:11},{query:'cdn.discordapp.com',total:8}
    ],
    top_user_agents:[
      {ua:'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',total:34},
      {ua:'python-requests/2.28.1',total:18},{ua:'curl/7.84.0',total:7}
    ],
  };
  const tipos = ['alert','dns','http','tls'], eventos = [];
  for (let i=0;i<100;i++) {
    const tipo = tipos[Math.floor(Math.random()*tipos.length)], ev = { tipo, timestamp:new Date(now - Math.random()*86400000*(INV.horas/24)).toISOString() };
    if (tipo === 'alert') {
      const sig = ctx.top_sids[Math.floor(Math.random()*ctx.top_sids.length)], sevs = ['critico','critico','alto','alto','medio','medio','baixo'];
      ev.titulo=sig.signature; ev.severidade_jg=sevs[Math.floor(Math.random()*sevs.length)];
      ev.detalhe=`${ip}:${Math.floor(Math.random()*60000+1024)} → 10.0.0.${Math.floor(Math.random()*254+1)}:${[22,3389,80,443][Math.floor(Math.random()*4)]}`;
      ev.sid=sig.sid; ev.status=['novo','investigando','resolvido'][Math.floor(Math.random()*3)]; ev.id=1000+i;
    } else if (tipo === 'dns') { ev.titulo=ctx.top_dominios[Math.floor(Math.random()*ctx.top_dominios.length)].query; ev.detalhe='tipo=A rcode=NOERROR'; }
    else if (tipo === 'http') { ev.titulo=`GET ${['/api/v1/data','/wp-admin/','/uploads/shell.php','/login'][Math.floor(Math.random()*4)]}`; ev.detalhe=`status=${[200,403,404,500][Math.floor(Math.random()*4)]} • python-requests/2.28.1`; }
    else { ev.titulo=['api.telegram.org','raw.githubusercontent.com','cdn.discordapp.com'][Math.floor(Math.random()*3)]; ev.detalhe='TLS 1.3 • ja3=a0e9f5d64349fb13191bc781f81f42e1'; }
    eventos.push(ev);
  }
  eventos.sort((a,b) => new Date(b.timestamp)-new Date(a.timestamp));
  return { ctx, timeline:{ok:true,eventos,total:eventos.length} };
}

/* ---------- Carga ---------- */
async function carregarTudo() {
  hideChartTooltip();
  if (INV.sim) {
    const sim = gerarSimulacao(INV.ip); INV.dados={ok:true,contexto:sim.ctx}; INV.timeline=sim.timeline; renderTudo(); return;
  }
  try {
    const [ctxData, tlData] = await Promise.all([
      fetchJson(`/incidentes/api/ip/${encodeURIComponent(INV.ip)}/contexto/?horas=${INV.horas}`),
      fetchJson(`/incidentes/api/ip/${encodeURIComponent(INV.ip)}/timeline/?horas=${INV.horas}`)
    ]);
    INV.dados=ctxData; INV.timeline=tlData; renderTudo();
  } catch (e) {
    toast(`Erro ao carregar dados: ${e.message}`, 'danger'); console.error('investigacao-ip:', e);
  }
}
function renderTudo() {
  if (!INV.dados?.ok) { toast(INV.dados?.erro || 'Contexto do IP indisponível.', 'danger'); return; }
  const ctx = INV.dados.contexto || {};
  renderTopbar(ctx); renderKpis(ctx); renderGeo(ctx.geo); renderRisk(ctx.risk_score);
  renderDirecao(ctx.direction_counts, ctx.direction_dominant); renderTopSigs(ctx.top_sids);
  renderTopDoms(ctx.top_dominios); renderUserAgents(ctx.top_user_agents); renderIncidentesRelacionados();
  renderAnaliseMoonShield(ctx);
  if (INV.timeline?.ok) { renderTimeline(INV.timeline.eventos || []); renderCharts(INV.timeline.eventos || [], ctx); }
}

/* ---------- Renderizadores ---------- */
function renderTopbar(ctx) {
  const geo=ctx.geo||{}, code=String(geo.pais_codigo||'').toLowerCase(), flag=$('ipFlag');
  if (flag) flag.innerHTML=code?`<span class="fi fi-${esc(code)}" style="border-radius:3px;font-size:22px;line-height:1"></span>`:'🌐';
  if ($('ipMeta')) $('ipMeta').textContent=[geo.pais,geo.cidade,geo.asn_org].filter(Boolean).join(' · ')||'IP sem geolocalização';
  const score=Number(ctx.risk_score?.score||0), badge=$('ipRiskBadge');
  if (badge) badge.className=`inv-risk-badge ${riskBadgeClass(score)}`;
  if ($('ipRiskVal')) $('ipRiskVal').textContent=`Score ${Math.round(score)}`;
}
function renderKpis(ctx) {
  animCount('kpiAlertas',ctx.total_alertas||0); animCount('kpiDns',ctx.total_dns||0); animCount('kpiHttp',ctx.total_http||0); animCount('kpiTls',ctx.total_tls||0);
  const score=Number(ctx.risk_score?.score||0), scoreEl=$('kpiScore'); if (scoreEl){animCount('kpiScore',Math.round(score));scoreEl.style.color=riskCor(score);}
  const chip=$('kpiScoreLbl'); if(chip){chip.textContent=riskLabel(score);chip.style.cssText=`background:${riskCor(score)}1a;color:${riskCor(score)};border-color:${riskCor(score)}44`;}
  const criticos=Number(ctx.criticos||ctx.risk_score?.criticos||0), kpiCrit=$('kpiCriticos');
  if(kpiCrit){kpiCrit.textContent=`${criticos} CRÍTICO${criticos!==1?'S':''}`;kpiCrit.style.display=criticos>0?'':'none';}
}
function renderGeo(geo) {
  hideLoading('geoLoading'); const el=$('geoData'); if(!el)return;
  if(!geo||!Object.keys(geo).length){el.innerHTML='<p class="inv-empty-text">Dados GeoIP não disponíveis.</p>';showContent('geoData');return;}
  const code=String(geo.pais_codigo||'').toLowerCase(), flagHtml=code?`<span class="fi fi-${esc(code)}" style="border-radius:2px;font-size:12px;vertical-align:middle"></span>`:'🌐';
  const rows=[['País',`${flagHtml} ${esc(geo.pais||'')}`],['Cidade',esc(geo.cidade||'')],['ASN',esc(geo.asn_number||'')],['Org',esc(geo.asn_org||'')],['rDNS',esc(geo.rdns||'')],['Lat/Lon',geo.latitude!=null&&geo.longitude!=null?`${Number(geo.latitude).toFixed(2)}, ${Number(geo.longitude).toFixed(2)}`:'']];
  el.innerHTML=rows.filter(([,v])=>v).map(([l,v])=>`<div class="inv-geo-item"><span class="inv-geo-item__lbl">${l}</span><span class="inv-geo-item__val">${v}</span></div>`).join('');
  showContent('geoData');
}
function renderRisk(risk) {
  hideLoading('riskLoading'); const el=$('riskData'); if(!el)return;
  if(!risk){el.innerHTML='<p class="inv-empty-text">Risk Score não calculado.</p>';showContent('riskData');return;}
  const score=clamp(Number(risk.score||0),0,100), cor=riskCor(score);
  el.innerHTML=`<div class="inv-risk-num" style="color:${cor}">${Math.round(score)}<span class="inv-risk-denom">/100</span></div>
    <div class="inv-risk-track"><div class="inv-risk-fill" style="width:0%;background:${cor}" id="riskFill"></div></div>
    <div class="inv-risk-labels"><span style="color:${cor};font-weight:700">${riskLabel(score)}</span><span style="color:var(--text-dim)">${Number(risk.total_alertas||0)} alertas</span></div>
    <div class="inv-risk-breakdown">
      ${[['Críticos',risk.criticos||0,'#f43f5e'],['Altos',risk.altos||0,'#fb923c'],['Médios',risk.medios||0,'#fbbf24']].map(([l,v,c])=>`<div class="inv-risk-row"><span class="inv-risk-row__label"><span class="inv-risk-dot" style="background:${c}"></span>${l}</span><span style="color:${c};font-weight:700">${Number(v)}</span></div>`).join('')}
      ${risk.ultimo_alerta?`<div class="inv-risk-row inv-risk-row--last"><span class="inv-risk-row__label">Último alerta</span><span>${fmtDataHora(risk.ultimo_alerta)}</span></div>`:''}
    </div>`;
  showContent('riskData'); requestAnimationFrame(()=>setTimeout(()=>{const f=$('riskFill');if(f)f.style.width=`${score}%`;},60));
}
function renderDirecao(counts, dominant) {
  hideLoading('dirLoading'); showContent('dirData'); const c=counts||{};
  const data=[{key:'inbound',label:'Entrada',color:'#f43f5e'},{key:'outbound',label:'Saída',color:'#fb923c'},{key:'lateral',label:'Lateral',color:'#fbbf24'},{key:'external',label:'Externo',color:'#c084fc'}].filter(d=>Number(c[d.key]||0)>0);
  if(!data.length){$('dirData').innerHTML='<p class="inv-empty-text">Sem dados de direção.</p>';return;}
  const canvas=$('dirDonutChart'); if(!canvas)return; destroyChart('dir');
  const total=data.reduce((s,d)=>s+Number(c[d.key]||0),0);
  const centerLabelPlugin={id:'msCenterLabel',afterDraw(chart){
    const area=chart.chartArea;if(!area)return;const active=chart.tooltip?.getActiveElements?.()||[],idx=active[0]?.index??-1,d=idx>=0?data[idx]:null;
    const main=d?Number(c[d.key]||0):total,sub=d?d.label:(({inbound:'ENTRADA',outbound:'SAÍDA',lateral:'LATERAL',external:'EXTERNO'})[dominant]||'TOTAL'),color=d?d.color:(data.find(x=>x.key===dominant)?.color||'#94a3b8');
    const x=(area.left+area.right)/2,y=(area.top+area.bottom)/2,ctx=chart.ctx;ctx.save();ctx.textAlign='center';ctx.textBaseline='middle';ctx.font='700 20px "JetBrains Mono",monospace';ctx.fillStyle=color;ctx.fillText(String(main),x,y-8);ctx.font='600 9px "JetBrains Mono",monospace';ctx.fillStyle='rgba(148,163,184,.72)';ctx.fillText(String(sub).toUpperCase(),x,y+11);ctx.restore();
  }};
  INV.charts.dir=new Chart(canvas,{type:'doughnut',plugins:[centerLabelPlugin],data:{labels:data.map(d=>d.label),datasets:[{data:data.map(d=>c[d.key]||0),backgroundColor:data.map(d=>`${d.color}aa`),borderColor:data.map(d=>d.color),borderWidth:1.5,hoverBackgroundColor:data.map(d=>`${d.color}ee`),hoverBorderWidth:2.5,hoverOffset:7}]},options:{cutout:'70%',interaction:{mode:'nearest',intersect:true},plugins:{legend:{display:false},tooltip:{enabled:false,external:externalDirectionTooltip(data,c,total)}},onHover:(_,active)=>{canvas.style.cursor=active.length?'pointer':'default';}}});
  const labelsEl=$('dirLabels');if(!labelsEl)return;
  const notes={inbound:'Tráfego majoritariamente de entrada — possível origem externa.',outbound:'Tráfego majoritariamente de saída — revisar exfiltração.',lateral:'Tráfego lateral — revisar movimento interno.',external:'Tráfego classificado como externo.'};
  labelsEl.innerHTML=`<div class="inv-dir-legend">${data.map(d=>`<div class="inv-dir-legend-item"><span class="inv-dir-legend-dot" style="background:${d.color}"></span><span class="inv-dir-legend-lbl">${d.label}</span><span class="inv-dir-legend-val" style="color:${d.color}">${Number(c[d.key]||0)}</span></div>`).join('')}</div>${dominant?`<div class="inv-dir-dominant"><i class="bi bi-info-circle" style="flex-shrink:0;margin-top:1px;color:${data.find(d=>d.key===dominant)?.color||'#94a3b8'}"></i><span>${esc(notes[dominant]||dominant)}</span></div>`:''}`;
}
function renderTopSigs(sigs) {
  hideLoading('sigsLoading'); const el=$('sigsContent');if(!el)return;
  if(!sigs?.length){el.innerHTML='<p class="inv-empty-text">Nenhuma assinatura encontrada.</p>';showContent('sigsContent');return;}
  if($('topSigsCount'))$('topSigsCount').textContent=sigs.length;const max=Math.max(...sigs.map(s=>Number(s.total||0)),1);
  el.innerHTML=sigs.slice(0,8).map((s,i)=>`<div class="inv-list-item"><span class="inv-list-item__rank">#${i+1}</span><div class="inv-list-item__info"><div class="inv-list-item__name" title="${esc(s.signature||'')}">${esc(s.signature||s.sid||'—')}</div><div class="inv-list-item__sub">SID ${esc(s.sid||'—')}</div></div><div class="inv-list-item__bar"><div class="inv-list-item__bar-fill inv-list-item__bar-fill--alert" style="width:0%" data-target="${(Number(s.total||0)/max*100).toFixed(0)}%"></div></div><span class="inv-list-item__count">${Number(s.total||0)}</span></div>`).join('');
  showContent('sigsContent');animateBars(el);
}
function renderTopDoms(doms) {
  hideLoading('domsLoading');const el=$('domsContent');if(!el)return;
  if(!doms?.length){el.innerHTML='<p class="inv-empty-text">Nenhuma consulta DNS encontrada.</p>';showContent('domsContent');return;}
  if($('topDomsCount'))$('topDomsCount').textContent=doms.length;const max=Math.max(...doms.map(d=>Number(d.total||0)),1);
  el.innerHTML=doms.slice(0,8).map((d,i)=>`<div class="inv-list-item"><span class="inv-list-item__rank">#${i+1}</span><span class="inv-list-item__name" title="${esc(d.query||'')}">${esc(d.query||'—')}</span><div class="inv-list-item__bar"><div class="inv-list-item__bar-fill inv-list-item__bar-fill--dns" style="width:0%" data-target="${(Number(d.total||0)/max*100).toFixed(0)}%"></div></div><span class="inv-list-item__count">${Number(d.total||0)}</span></div>`).join('');
  showContent('domsContent');animateBars(el);
}
function renderUserAgents(uas) {
  hideLoading('uaLoading');const el=$('uaContent');if(!el)return;
  if(!uas?.length){el.innerHTML='<p class="inv-empty-text">Nenhum user agent encontrado.</p>';showContent('uaContent');return;}
  const max=Math.max(...uas.map(u=>Number(u.total||0)),1);
  el.innerHTML=uas.slice(0,5).map((u,i)=>{const ua=String(u.ua||'—');return `<div class="inv-list-item"><span class="inv-list-item__rank">#${i+1}</span><div class="inv-list-item__info"><div class="inv-list-item__name" title="${esc(ua)}">${esc(ua.length>50?`${ua.slice(0,50)}…`:ua)}</div></div><div class="inv-list-item__bar"><div class="inv-list-item__bar-fill inv-list-item__bar-fill--ua" style="width:0%" data-target="${(Number(u.total||0)/max*100).toFixed(0)}%"></div></div><span class="inv-list-item__count">${Number(u.total||0)}</span></div>`;}).join('');
  showContent('uaContent');animateBars(el);
}
function renderIncidentesRelacionados() {
  hideLoading('relLoading');const el=$('relContent');if(!el)return;
  try{
    const alertas=(INV.timeline?.eventos||[]).filter(e=>e.tipo==='alert').slice(0,6);
    if(!alertas.length){el.innerHTML='<p class="inv-empty-text">Nenhum incidente encontrado.</p>';showContent('relContent');return;}
    el.innerHTML=alertas.map(e=>`<div class="inv-inc-item"><span class="inv-sev-dot ${sevDotClass(e.severidade_jg||e.severidade)}"></span><div class="inv-inc-item__body"><div class="inv-inc-item__title">${esc(e.titulo||'Alerta')}</div><div class="inv-inc-item__meta">${fmtDataHora(e.timestamp)}</div></div><span class="inv-inc-item__status ${statusClass(e.status)}">${esc(statusLabel(e.status))}</span></div>`).join('');
    showContent('relContent');
  }catch{el.innerHTML='<p class="inv-empty-text">Erro ao carregar incidentes.</p>';showContent('relContent');}
}
function renderAnaliseMoonShield(ctx) {
  hideLoading('analysisLoading');const el=$('analysisData');if(!el)return;
  const score=Number(ctx.risk_score?.score||0),criticos=Number(ctx.criticos||ctx.risk_score?.criticos||0),doms=ctx.top_dominios||[],sigs=ctx.top_sids||[];
  let verdict='Comportamento normal',icon='bi-check-circle-fill',cor='#34d399',desc='Nenhum indicador relevante de comprometimento foi identificado no período.';
  if(score>=70){verdict='Alto risco detectado';icon='bi-exclamation-octagon-fill';cor='#f43f5e';desc=`Risk Score ${Math.round(score)}/100 com ${criticos} alerta(s) crítico(s). Priorize a investigação deste ativo.`;}
  else if(score>=40){verdict='Atividade suspeita';icon='bi-exclamation-triangle-fill';cor='#fb923c';desc=`Risk Score ${Math.round(score)}/100. Existem sinais suficientes para revisão manual e correlação dos eventos.`;}
  const tags=[];
  if(sigs.some(s=>String(s.signature||'').toLowerCase().includes('scan')))tags.push({t:'RECON',c:'#fb923c'});
  if(sigs.some(s=>String(s.signature||'').toLowerCase().includes('malware')))tags.push({t:'MALWARE',c:'#f43f5e'});
  if(sigs.some(s=>String(s.signature||'').toLowerCase().includes('cobalt')))tags.push({t:'C2',c:'#f43f5e'});
  if(sigs.some(s=>String(s.signature||'').toLowerCase().includes('exploit')))tags.push({t:'EXPLOIT',c:'#f43f5e'});
  if(doms.some(d=>/\.(ru|cn)$/i.test(String(d.query||''))))tags.push({t:'GEO-SUSPEITO',c:'#fbbf24'});
  if((ctx.top_user_agents||[]).some(u=>/(python|curl)/i.test(String(u.ua||''))))tags.push({t:'AUTOMAÇÃO',c:'#c084fc'});
  if(criticos>0)tags.push({t:'CRÍTICO',c:'#f43f5e'});if(!tags.length)tags.push({t:'OK',c:'#34d399'});
  el.innerHTML=`<div class="inv-analysis-verdict"><div class="inv-analysis-verdict__icon" style="background:${cor}18;border-color:${cor}40;color:${cor}"><i class="bi ${icon}"></i></div><div class="inv-analysis-verdict__text"><div class="inv-analysis-verdict__title" style="color:${cor}">${verdict}</div>${esc(desc)}</div></div><div class="inv-analysis-tags">${tags.map(t=>`<span class="inv-analysis-tag" style="color:${t.c};background:${t.c}18;border-color:${t.c}44">${t.t}</span>`).join('')}</div>`;
  showContent('analysisData');
}

/* ---------- Gráficos ---------- */
function renderCharts(eventos,ctx){if(typeof Chart==='undefined')return;const serie=gerarSerie(eventos,INV.horas);renderSparklines(serie);renderScoreChart(serie,ctx);renderHeatmap(serie);}
function renderSparklines(serie) {
  const defs=[
    {id:'sparkAlert',valId:'sparkValAlert',key:'alert',name:'Alertas',color:'#f43f5e'},
    {id:'sparkDns',valId:'sparkValDns',key:'dns',name:'DNS',color:'#38bdf8'},
    {id:'sparkHttp',valId:'sparkValHttp',key:'http',name:'HTTP',color:'#34d399'},
    {id:'sparkTls',valId:'sparkValTls',key:'tls',name:'TLS',color:'#c084fc'}
  ];
  defs.forEach((sp,si)=>{
    const canvas=$(sp.id);if(!canvas)return;const data=serie.series[sp.key],total=data.reduce((a,b)=>a+b,0);if($(sp.valId))animCount(sp.valId,total);destroySpark(sp.key);
    const c=canvas.getContext('2d'),grad=c.createLinearGradient(0,0,0,64);grad.addColorStop(0,`${sp.color}55`);grad.addColorStop(1,`${sp.color}00`);
    INV.charts.sparks[sp.key]=new Chart(canvas,{type:'line',plugins:[hoverLinePlugin],data:{labels:serie.labels,datasets:[{label:sp.name,data,borderColor:sp.color,borderWidth:1.8,pointRadius:0,pointHitRadius:16,pointHoverRadius:4,pointHoverBackgroundColor:sp.color,pointHoverBorderColor:'#0a0f1e',pointHoverBorderWidth:2,fill:true,backgroundColor:grad,tension:.38}]},options:{responsive:true,maintainAspectRatio:false,animation:{delay:si*60,duration:520},interaction:{mode:'index',intersect:false,axis:'x'},plugins:{legend:{display:false},tooltip:{enabled:false,external:externalSparkTooltip(sp.name,sp.color,total)}},scales:{x:{display:false},y:{display:false,beginAtZero:true}},onHover:(_,active)=>{canvas.style.cursor=active.length?'crosshair':'default';}}});
  });
}
function renderScoreChart(serie,ctx) {
  const canvas=$('scoreChart');if(!canvas)return;destroyChart('score');const score=Number(ctx.risk_score?.score||0),mainCor=riskCor(score),c=canvas.getContext('2d');
  const grad=c.createLinearGradient(0,0,0,220);grad.addColorStop(0,`${mainCor}40`);grad.addColorStop(.6,`${mainCor}10`);grad.addColorStop(1,`${mainCor}00`);
  const gradAlert=c.createLinearGradient(0,0,0,220);gradAlert.addColorStop(0,'#fb923c22');gradAlert.addColorStop(1,'#fb923c00');
  const segmentColor=context=>riskCor(Number(context.p1.parsed.y||0));
  INV.charts.score=new Chart(canvas,{type:'line',plugins:[hoverLinePlugin],data:{labels:serie.labels,datasets:[
    {label:'Risk Score',data:serie.score,segment:{borderColor:segmentColor},borderWidth:2.4,pointRadius:0,pointHitRadius:18,pointHoverRadius:5,pointHoverBackgroundColor:mainCor,pointHoverBorderColor:'#0a0f1e',pointHoverBorderWidth:2,fill:true,backgroundColor:grad,tension:.36,yAxisID:'y'},
    {label:'Alertas',data:serie.series.alert,borderColor:'#fb923c',borderWidth:1.4,borderDash:[5,4],pointRadius:0,pointHitRadius:18,pointHoverRadius:4,pointHoverBackgroundColor:'#fb923c',fill:true,backgroundColor:gradAlert,tension:.28,yAxisID:'y2'}
  ]},options:{responsive:true,maintainAspectRatio:false,interaction:{mode:'index',intersect:false,axis:'x'},plugins:{legend:{display:false},tooltip:{enabled:false,external:externalScoreTooltip(serie)}},onHover:(_,active)=>{canvas.style.cursor=active.length?'crosshair':'default';},scales:{
    x:{grid:{color:'rgba(255,255,255,.035)'},ticks:{maxTicksLimit:10,maxRotation:0,font:{size:9}}},
    y:{position:'left',min:0,max:100,grid:{color:'rgba(255,255,255,.035)'},ticks:{stepSize:20,font:{size:9},callback:v=>`${v}`}},
    y2:{position:'right',min:0,grid:{display:false},ticks:{precision:0,font:{size:9},color:'#fb923c88'}}
  }}});
}
function renderHeatmap(serie) {
  const canvas=$('heatmapChart');if(!canvas)return;destroyChart('heatmap');const max=Math.max(...serie.hourBuckets,1);
  const colors=serie.hourBuckets.map(v=>{const r=v/max;if(r>.75)return'#f43f5e';if(r>.5)return'#fb923c';if(r>.25)return'#fbbf24';if(r>0)return'#38bdf8';return'rgba(148,163,184,.10)';});
  INV.charts.heatmap=new Chart(canvas,{type:'bar',data:{labels:Array.from({length:24},(_,i)=>`${String(i).padStart(2,'0')}h`),datasets:[{label:'Eventos',data:serie.hourBuckets,backgroundColor:colors,borderColor:colors.map(c=>c.startsWith('rgba')?'rgba(148,163,184,.10)':c),borderWidth:1,borderRadius:4,borderSkipped:false,hoverBorderWidth:2}]},options:{responsive:true,maintainAspectRatio:false,interaction:{mode:'nearest',intersect:true},animation:{duration:520,delay:ctx=>ctx.dataIndex*8},plugins:{legend:{display:false},tooltip:{enabled:false,external:externalHeatTooltip(serie)}},onHover:(_,active)=>{canvas.style.cursor=active.length?'pointer':'default';},scales:{x:{grid:{display:false},ticks:{font:{size:8},maxRotation:0}},y:{beginAtZero:true,grid:{color:'rgba(255,255,255,.03)'},ticks:{precision:0,font:{size:8},maxTicksLimit:4}}}}});
}

/* ---------- Timeline ---------- */
function renderTimeline(eventos) {
  hideLoading('tlLoading');
  const empty=$('tlEmpty'),list=$('tlList');
  INV._allEventos=eventos||[];
  INV.timelineVisible=INV.timelinePageSize;

  if(!eventos?.length){
    if(list)list.style.display='none';
    if(empty)empty.style.display='flex';
    atualizarFooterTimeline(0,0);
    sincronizarAlturaTimeline();
    return;
  }

  const counts={alert:0,dns:0,http:0,tls:0};
  eventos.forEach(e=>{if(counts[e.tipo]!==undefined)counts[e.tipo]++;});
  animCount('tlCount',eventos.length);
  ['Alert','Dns','Http','Tls'].forEach(k=>animCount(`tlCount${k}`,counts[k.toLowerCase()]));
  aplicarFiltroTimeline(INV.filtroTl,true);
}

function eventosFiltradosTimeline() {
  const eventos=INV._allEventos||[];
  return INV.filtroTl==='all'?eventos:eventos.filter(e=>e.tipo===INV.filtroTl);
}

function atualizarFooterTimeline(visiveis,total) {
  const footer=$('tlFooter'),info=$('tlVisibleInfo'),btn=$('tlMoreBtn');
  if(!footer||!info||!btn)return;

  if(!total){
    footer.style.display='none';
    return;
  }

  footer.style.display='flex';
  info.textContent=`Mostrando ${visiveis} de ${total}`;
  const restantes=Math.max(0,total-visiveis);

  btn.disabled=restantes===0;
  btn.innerHTML=restantes>0
    ? `<span>Ver mais (${Math.min(INV.timelinePageSize,restantes)})</span><i class="bi bi-chevron-down"></i>`
    : `<span>Todos exibidos</span><i class="bi bi-check2"></i>`;
}

function sincronizarAlturaTimeline() {
  const card=document.querySelector('.inv-tl-card');
  const sidebar=document.querySelector('.inv-sidebar');
  if(!card||!sidebar)return;

  if(window.innerWidth<=1100){
    card.style.height='';
    return;
  }

  requestAnimationFrame(()=>{
    const h=Math.round(sidebar.getBoundingClientRect().height);
    if(h>0)card.style.height=`${h}px`;
  });
}

function aplicarFiltroTimeline(filtro,manterLimite=false) {
  INV.filtroTl=filtro;
  if(!manterLimite)INV.timelineVisible=INV.timelinePageSize;

  const filtrado=eventosFiltradosTimeline();
  const list=$('tlList'),empty=$('tlEmpty');
  if(!list||!empty)return;

  if(!filtrado.length){
    list.style.display='none';
    empty.style.display='flex';
    atualizarFooterTimeline(0,0);
    sincronizarAlturaTimeline();
    return;
  }

  empty.style.display='none';
  list.style.display='block';

  const visiveis=filtrado.slice(0,INV.timelineVisible);
  const out=[];
  let diaAtual=null;

  visiveis.forEach(ev=>{
    const d=new Date(ev.timestamp);
    const diaStr=Number.isNaN(d.getTime())
      ? 'Data desconhecida'
      : d.toLocaleDateString('pt-BR',{weekday:'long',day:'2-digit',month:'long'});

    if(diaStr!==diaAtual){
      diaAtual=diaStr;
      out.push(`<div class="inv-tl-day-sep"><div class="inv-tl-day-sep__line"></div><span class="inv-tl-day-sep__label">${esc(diaStr)}</span><div class="inv-tl-day-sep__line"></div></div>`);
    }

    out.push(renderTlItem(ev));
  });

  list.innerHTML=out.join('');
  list.querySelectorAll('[data-inc-id]').forEach(el=>el.addEventListener('click',()=>window.open(`/incidentes/?id=${encodeURIComponent(el.dataset.incId)}`,'_blank','noopener')));

  atualizarFooterTimeline(visiveis.length,filtrado.length);
  sincronizarAlturaTimeline();
}

function mostrarMaisTimeline() {
  const total=eventosFiltradosTimeline().length;
  if(INV.timelineVisible>=total)return;

  INV.timelineVisible=Math.min(total,INV.timelineVisible+INV.timelinePageSize);
  aplicarFiltroTimeline(INV.filtroTl,true);

  const body=document.querySelector('.inv-tl-body');
  if(body)body.scrollTo({top:body.scrollHeight,behavior:'smooth'});
}

function iconeTipo(tipo){return({alert:'bi-exclamation-triangle-fill',dns:'bi-globe2',http:'bi-arrow-left-right',tls:'bi-lock-fill'})[tipo]||'bi-circle';}
function renderTlItem(ev) {
  const attrs=ev.id?`data-inc-id="${esc(ev.id)}"`:'',sevBadge=ev.severidade_jg&&ev.tipo==='alert'?`<span class="inv-sev-dot ${sevDotClass(ev.severidade_jg)}"></span>`:'';
  return `<div class="inv-tl-item inv-tl-item--${esc(ev.tipo||'info')}" ${attrs}><div class="inv-tl-dot"><i class="bi ${iconeTipo(ev.tipo)}"></i></div><div class="inv-tl-content"><div class="inv-tl-row">${sevBadge}<div class="inv-tl-title-text">${esc(ev.titulo||'—')}</div></div><div class="inv-tl-meta">${esc(ev.detalhe||'')}</div></div><div class="inv-tl-time">${fmtHora(ev.timestamp)}</div></div>`;
}

/* ---------- Ações ---------- */
function abrirModalSupressao(){const modal=$('modalOverlay');if(modal){modal.classList.add('open');modal.setAttribute('aria-hidden','false');}$('acoesDropdown')?.classList.remove('open');setTimeout(()=>$('supMotivo')?.focus(),50);}
function fecharModalSupressao(){const modal=$('modalOverlay');if(modal){modal.classList.remove('open');modal.setAttribute('aria-hidden','true');}}
function exportarJSON() {
  const payload={ip:INV.ip,horas:INV.horas,gerado:new Date().toISOString(),simulado:INV.sim,contexto:INV.dados?.contexto||null,timeline:INV.timeline?.eventos||[]};
  const blob=new Blob([JSON.stringify(payload,null,2)],{type:'application/json'}),url=URL.createObjectURL(blob),a=document.createElement('a');
  a.download=`moonshield_investigacao_${INV.ip.replace(/[\.:]/g,'_')}_${Date.now()}.json`;a.href=url;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),0);
  toast('JSON exportado com sucesso!','ok');$('acoesDropdown')?.classList.remove('open');
}
async function criarSupressao() {
  const tipo=$('supTipo')?.value||'ip_src',motivo=$('supMotivo')?.value.trim()||'';
  if(!motivo)return toast('Informe o motivo da supressão.','danger');
  if(INV.sim){toast('Supressão criada (simulação)!','ok');fecharModalSupressao();return;}
  try{
    const data=await fetchJson('/incidentes/api/supressao/',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':getCookie('csrftoken')},body:JSON.stringify({tipo,ip:tipo==='ip_src'?INV.ip:null,sid:tipo==='sid'?($('supSidVal')?.value.trim()||null):null,dominio:tipo==='dominio'?($('supDominioVal')?.value.trim()||null):null,motivo,expira:$('supExpira')?.value||null})});
    if(data.ok||data.id){toast('Supressão criada!','ok');fecharModalSupressao();}else throw new Error(data.erro||'Erro ao criar supressão');
  }catch(e){toast(`Erro ao criar supressão: ${e.message}`,'danger');}
}
function resizeCharts(){[INV.charts.score,INV.charts.dir,INV.charts.heatmap,...Object.values(INV.charts.sparks)].forEach(chart=>{try{chart?.resize();}catch(_){}});}

/* ---------- Init ---------- */
document.addEventListener('DOMContentLoaded',()=>{
  if(!setupChartDefaults())return;
  $('modalOverlay')?.setAttribute('aria-hidden','true');

  $('btnRefresh')?.addEventListener('click',async()=>{
    const btn=$('btnRefresh');btn.disabled=true;btn.querySelector('i')?.classList.add('spinning');
    try{await carregarTudo();}finally{btn.disabled=false;btn.querySelector('i')?.classList.remove('spinning');}
  });
  document.querySelectorAll('.inv-period__btn').forEach(btn=>btn.addEventListener('click',()=>{
    document.querySelectorAll('.inv-period__btn').forEach(b=>b.classList.remove('inv-period__btn--active'));btn.classList.add('inv-period__btn--active');INV.horas=parseInt(btn.dataset.h,10)||24;carregarTudo();
  }));
  document.querySelectorAll('.inv-tl-filter').forEach(btn=>btn.addEventListener('click',()=>{
    document.querySelectorAll('.inv-tl-filter').forEach(b=>b.classList.remove('inv-tl-filter--active'));btn.classList.add('inv-tl-filter--active');aplicarFiltroTimeline(btn.dataset.tipo||'all');
  }));
  $('tlMoreBtn')?.addEventListener('click',mostrarMaisTimeline);
  $('btnSimular')?.addEventListener('click',()=>{
    INV.sim=!INV.sim;$('btnSimular').classList.toggle('active',INV.sim);if($('simBanner'))$('simBanner').style.display=INV.sim?'flex':'none';toast(INV.sim?'Modo simulação ativado — dados fictícios':'Modo simulação desativado');carregarTudo();
  });
  $('simBannerClose')?.addEventListener('click',()=>{if($('simBanner'))$('simBanner').style.display='none';});
  $('btnAcoes')?.addEventListener('click',e=>{e.stopPropagation();$('acoesDropdown')?.classList.toggle('open');});
  document.addEventListener('click',e=>{if(!e.target.closest('.inv-actions-wrap'))$('acoesDropdown')?.classList.remove('open');});
  $('optSupressao')?.addEventListener('click',abrirModalSupressao);$('optExportar')?.addEventListener('click',exportarJSON);
  $('optBloquear')?.addEventListener('click',()=>{toast('IP sinalizado como ameaça!','danger');$('acoesDropdown')?.classList.remove('open');});
  $('modalClose')?.addEventListener('click',fecharModalSupressao);$('modalCancel')?.addEventListener('click',fecharModalSupressao);
  $('modalOverlay')?.addEventListener('click',e=>{if(e.target===$('modalOverlay'))fecharModalSupressao();});
  $('supTipo')?.addEventListener('change',e=>{const val=e.target.value,sid=$('supSidGroup'),dom=$('supDominioGroup');if(sid)sid.style.display=val==='sid'?'flex':'none';if(dom)dom.style.display=val==='dominio'?'flex':'none';});
  $('modalConfirm')?.addEventListener('click',criarSupressao);
  document.addEventListener('keydown',e=>{if(e.key==='Escape'){fecharModalSupressao();hideChartTooltip();$('acoesDropdown')?.classList.remove('open');}});
  window.addEventListener('scroll',hideChartTooltip,{passive:true});
  window.addEventListener('blur',hideChartTooltip);

  if(typeof ResizeObserver!=='undefined'){
    let timer;const obs=new ResizeObserver(()=>{clearTimeout(timer);timer=setTimeout(()=>{resizeCharts();sincronizarAlturaTimeline();},120);});
    const sidebar=document.querySelector('.inv-sidebar');
    const root=document.querySelector('.ms-investigation');
    if(sidebar)obs.observe(sidebar);
    if(root)obs.observe(root);
  }
  window.addEventListener('resize',()=>{clearTimeout(window.__invTlResize);window.__invTlResize=setTimeout(sincronizarAlturaTimeline,120);});

  carregarTudo();
});
