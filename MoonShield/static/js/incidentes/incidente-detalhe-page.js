'use strict';
/* =================================================================
   MOONSHIELD — INCIDENTE-DETALHE-PAGE.JS  v2.0
   Melhorias:
   - Ring SVG animado com stroke-dashoffset
   - Acento colorido no hero por severidade
   - GeoIP com grid visual
   - Risk detail na sidebar com barra + breakdown
   - Relacionados com badge Novo
   - Status bar com botão "Novo" incluído
   - Botão copiar com feedback visual
================================================================= */

const INC_ID = window.INC_ID;
const $  = id  => document.getElementById(id);
const qs = sel => document.querySelector(sel);
const qa = sel => document.querySelectorAll(sel);

function esc(s) {
  return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function fmtDateTime(iso) {
  if (!iso) return '—';
  try { return new Date(iso).toLocaleString('pt-BR',{day:'2-digit',month:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit'}); }
  catch(_){ return '—'; }
}
function fmtTime(iso) {
  if (!iso) return '—';
  try { return new Date(iso).toLocaleTimeString('pt-BR',{hour:'2-digit',minute:'2-digit',second:'2-digit'}); }
  catch(_){ return '—'; }
}
function getCsrf() {
  return document.cookie.split(';').map(c=>c.trim()).find(c=>c.startsWith('csrftoken='))?.split('=')[1]||'';
}
function toast(msg, dur=2400) {
  const t=$('toast'); if(!t) return;
  t.textContent=msg; t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),dur);
}
function copyText(txt) {
  navigator.clipboard?.writeText(txt).then(()=>toast('Copiado: '+txt));
}

async function _fetch(url, opts={}) {
  const res = await fetch(url, opts);
  const ct  = res.headers.get('content-type')||'';
  if (!ct.includes('application/json')) {
    const text = await res.text();
    if (text.includes('<html')||text.includes('<!DOCTYPE'))
      throw new Error(`Sessão expirada (HTTP ${res.status})`);
    throw new Error(`Resposta inesperada (HTTP ${res.status})`);
  }
  const data = await res.json();
  if (!res.ok) throw new Error(data?.erro||data?.detail||`Erro HTTP ${res.status}`);
  return data;
}

/* ── Cores de risco ── */
function riskColor(s) {
  if (s <  30) return '#34d399';
  if (s <  50) return '#fbbf24';
  if (s <  70) return '#fb923c';
  return '#f43f5e';
}
function riskLabel(s) {
  if (s <  30) return 'BAIXO';
  if (s <  50) return 'MÉDIO';
  if (s <  70) return 'ALTO';
  return 'CRÍTICO';
}

/* ── Mapeamentos ── */
const SEV_CLASS = { critico:'crit', alto:'high', medio:'med', baixo:'low', informativo:'dim' };
const SEV_LABEL = { critico:'CRÍTICO', alto:'ALTO', medio:'MÉDIO', baixo:'BAIXO', informativo:'INFO' };
const SEV_ACCENT = { critico:'#f43f5e', alto:'#fb923c', medio:'#fbbf24', baixo:'#38bdf8', informativo:'#94a3b8' };
const CAT_ICON = {
  recon:'bi-binoculars-fill', auth:'bi-key-fill', lateral:'bi-arrows-angle-expand',
  dns:'bi-globe2', web:'bi-arrow-left-right', tls:'bi-lock-fill',
  malware:'bi-bug-fill', exfil:'bi-upload', p2p:'bi-share-fill',
  anomalia:'bi-question-diamond-fill', info:'bi-info-circle-fill',
};
const CAT_LABEL = {
  recon:'Reconhecimento', auth:'Brute Force / Auth', lateral:'Mov. Lateral',
  dns:'DNS / Policy', web:'Web / HTTP', tls:'TLS / QUIC',
  malware:'Malware / C2', exfil:'Exfiltração', p2p:'P2P',
  anomalia:'Anomalia', info:'Informativo',
};
const PORT_NAMES = {
  22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',110:'POP3',
  143:'IMAP',443:'HTTPS',445:'SMB',3306:'MySQL',3389:'RDP',
  5432:'PostgreSQL',6379:'Redis',8080:'HTTP-ALT',27017:'MongoDB',
  5800:'VNC-HTTP',5900:'VNC',1433:'MSSQL',1521:'Oracle',5432:'PostgreSQL',
};
const STATUS_LABEL = { novo:'Novo', investigando:'Investigando', resolvido:'Resolvido', falso:'Falso Positivo' };
const STATUS_DOT   = { novo:'new', investigando:'inv', resolvido:'ok', falso:'fp' };

let _ev    = null;
let _srcIp = null;

/* ═══════════════════════════════════════ INIT ═══════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', () => {
  if (!INC_ID) { toast('ID do incidente não encontrado.',5000); return; }
  initActions();
  initCorrTabs();
  initCollapsible('tecToggle','tecWrap');
  initCollapsible('rawToggle','rawWrap','id-collapsible--raw');
  initStatusButtons();
  initModal();
  loadIncidente();
});

/* ═══════════════════════════════════════ CARGA PRINCIPAL ═══════════════════════════════════════ */
async function loadIncidente() {
  try {
    const data = await _fetch(`/incidentes/api/${INC_ID}/`);
    _ev    = data.incidente;
    _srcIp = _ev?.srcIp || _ev?.tecnico?.src_ip || null;

    renderHero(_ev);
    renderStatusBar(_ev);
    renderFluxo(_ev);
    renderRecomendacoes(_ev);
    renderGeo(_ev);
    renderHistorico(_ev);
    renderCorrelacoes(data.correlacao || data);
    renderTecnico(_ev);
    setNota(_ev.nota || '');

    if (_srcIp) {
      loadRiskDetail(_srcIp);
      loadRelacionados(_srcIp, _ev.id);
      $('linkVerTodos')?.setAttribute('href', `/incidentes/investigar/${_srcIp}/`);
      $('btnInvestigarIp')?.setAttribute('href', `/incidentes/investigar/${_srcIp}/`);
    }
  } catch(e) {
    const el = $('heroLoading');
    if (el) el.innerHTML = `<span style="color:#f43f5e"><i class="bi bi-exclamation-circle"></i> ${esc(e.message)}</span>`;
    toast(`Erro: ${e.message}`, 5000);
  }
}

/* ═══════════════════════════════════════ HERO ═══════════════════════════════════════ */
function renderHero(ev) {
  $('heroLoading').style.display = 'none';
  $('heroContent').style.display = '';

  const sev    = ev.severidade_jg || 'informativo';
  const cat    = ev.categoria_jg  || 'info';
  const titulo = ev.titulo_jg || ev.sig?.name || '—';

  // breadcrumb
  const tb = $('topbarTitulo');
  if (tb) tb.textContent = titulo.length>55 ? titulo.slice(0,55)+'…' : titulo;

  // acento colorido
  const accent = $('heroAccent');
  if (accent) {
    const col = SEV_ACCENT[sev] || '#94a3b8';
    accent.style.background = `linear-gradient(90deg, ${col}, transparent)`;
  }

  // badges
  const badgeSev = $('heroBadgeSev');
  if (badgeSev) {
    badgeSev.className = `id-badge id-badge--${SEV_CLASS[sev]||'dim'}`;
    badgeSev.textContent = SEV_LABEL[sev] || sev.toUpperCase();
  }
  const badgeCat = $('heroBadgeCat');
  if (badgeCat) {
    badgeCat.className = `id-badge id-badge--cat id-badge--cat-${cat}`;
    badgeCat.innerHTML = `<i class="bi ${CAT_ICON[cat]||'bi-tag-fill'}"></i> ${esc(CAT_LABEL[cat]||cat)}`;
  }

  _updateStatusPill(ev.status || 'novo');

  const tituloEl = $('heroTitulo');
  if (tituloEl) tituloEl.textContent = titulo;

  const resumoEl = $('heroResumo');
  if (resumoEl) { resumoEl.textContent = ev.resumo_jg||''; resumoEl.style.display = ev.resumo_jg ? '' : 'none'; }

  const evidEl  = $('heroEvidencia');
  const evidTxt = $('heroEvidenciaText');
  if (ev.evidencia && evidEl && evidTxt) {
    evidTxt.textContent = ev.evidencia;
    evidEl.style.display = '';
  } else if (evidEl) {
    evidEl.style.display = 'none';
  }

  const sensorEl = $('heroSensor');
  if (sensorEl) sensorEl.innerHTML = `<i class="bi bi-hdd-rack-fill"></i> ${esc(ev.sensor||'sensor')}`;

  const timeEl = $('heroTime');
  if (timeEl) timeEl.innerHTML = `<i class="bi bi-clock"></i> ${fmtDateTime(ev.last_seen||ev.timestamp)}`;

  const oc = ev.ocorrencias || ev.group_count || 1;
  const ocEl = $('heroOcorrencias');
  if (oc > 1 && ocEl) {
    ocEl.style.display = '';
    const sp = ocEl.querySelector('span');
    if (sp) sp.textContent = oc;
  }

  const janelaEl = $('heroJanela');
  if (ev.first_seen && ev.last_seen && ev.first_seen !== ev.last_seen && janelaEl) {
    janelaEl.style.display = '';
    const sp = janelaEl.querySelector('span');
    if (sp) sp.textContent = `${fmtDateTime(ev.first_seen)} → ${fmtDateTime(ev.last_seen)}`;
  }

  renderRiskRing(ev.risk_score || 0);
}

function renderRiskRing(score) {
  const CIRC = 2 * Math.PI * 28;
  const pct  = Math.min(score, 100) / 100;
  const col  = riskColor(Math.min(score, 100));

  const arc = $('riskArc');
  if (arc) {
    arc.style.strokeDasharray  = String(CIRC);
    arc.style.strokeDashoffset = String(CIRC * (1 - pct));
    arc.style.stroke           = col;
  }
  const val = $('riskVal');
  if (val) { val.textContent = score >= 1000 ? '1k+' : String(Math.round(score)); val.style.color = col; }
  const tag = $('riskTag');
  if (tag) {
    tag.textContent       = riskLabel(Math.min(score,100));
    tag.style.color       = col;
    tag.style.borderColor = col+'44';
    tag.style.background  = col+'11';
  }
}

/* ═══════════════════════════════════════ STATUS BAR ═══════════════════════════════════════ */
function renderStatusBar(ev) {
  const bar = $('statusBar');
  if (bar) bar.style.display='';
  _updateStatusPill(ev.status||'novo');
  _highlightStatusBtn(ev.status||'novo');
}
function _updateStatusPill(status) {
  const pill=$('heroStatus'); if(!pill) return;
  pill.className=`id-status id-status--${status}`;
  $('heroStatusLabel').textContent=STATUS_LABEL[status]||status;
}
function _highlightStatusBtn(status) {
  qa('.id-status-btn[data-status]').forEach(b=>b.classList.toggle('id-status-btn--active',b.dataset.status===status));
}
function initStatusButtons() {
  qa('.id-status-btn[data-status]').forEach(btn=>btn.addEventListener('click',()=>updateStatus(btn.dataset.status)));
}
async function updateStatus(newStatus) {
  try {
    const data = await _fetch(`/incidentes/api/${INC_ID}/status/`,{
      method:'PATCH',
      headers:{'Content-Type':'application/json','X-CSRFToken':getCsrf()},
      body:JSON.stringify({status:newStatus}),
    });
    if (data.ok) {
      _updateStatusPill(newStatus);
      _highlightStatusBtn(newStatus);
      _appendHistorico(newStatus);
      toast(`Status → ${STATUS_LABEL[newStatus]||newStatus}`);
    }
  } catch(e) { toast(`⚠ ${e.message}`,4000); }
}

/* ═══════════════════════════════════════ FLUXO DE REDE ═══════════════════════════════════════ */
function renderFluxo(ev) {
  const card = $('cardFluxo'); if (!card) return;
  card.style.display = '';

  const proto = ev.tecnico?.protocolo || ev.sig?.proto || '—';
  const port  = ev.tecnico?.dest_porta || ev.sig?.port || 0;

  $('fluxoProto').textContent     = proto;
  $('fluxoProtoPill').textContent = proto;
  $('fluxoSrcIp').textContent     = ev.srcIp || '—';
  $('fluxoDstIp').textContent     = ev.dstIp || '—';

  // flag
  const code = (ev.pais_codigo||'').toLowerCase();
  const flagEl = $('fluxoSrcFlag');
  if (flagEl) {
    flagEl.innerHTML = code
      ? `<span class="fi fi-${code}" style="width:22px;height:16px;border-radius:3px;display:inline-block"></span>`
      : '<span style="font-size:18px"><span class="fi fi-br" style="width:20px;height:14px;border-radius:2px;display:inline-block;vertical-align:middle"></span></span>';
  }

  const srcCountryEl = $('fluxoSrcCountry');
  if (srcCountryEl) {
    if (ev.src_is_local) {
      srcCountryEl.innerHTML = '<span style="color:#34d399;font-size:11px"><i class="bi bi-house-fill"></i> Rede local</span>';
    } else {
      srcCountryEl.textContent = ev.country?.name || ev.pais || '';
    }
  }
  const srcAsnEl = $('fluxoSrcAsn');
  if (srcAsnEl) srcAsnEl.textContent = ev.asn_org ? `AS · ${ev.asn_org}` : '';
  const dstCountryEl = $('fluxoDstCountry');
  if (dstCountryEl) dstCountryEl.textContent = ev.dst_is_local ? '🏠 Rede local' : '';
  const dstPortEl = $('fluxoDstPort');
  if (dstPortEl) dstPortEl.textContent = port ? `Porta ${port} · ${PORT_NAMES[port]||proto}` : '';

  // direção
  const dir    = ev.direction||'';
  const dirBadge = $('fluxoDirBadge');
  const DIR_STYLE = {
    inbound:  {label:'INBOUND',  bg:'rgba(244,63,94,.1)',  col:'#f43f5e', bd:'rgba(244,63,94,.3)'},
    outbound: {label:'OUTBOUND', bg:'rgba(251,146,60,.1)', col:'#fb923c', bd:'rgba(251,146,60,.3)'},
    lateral:  {label:'LATERAL',  bg:'rgba(251,191,36,.1)', col:'#fbbf24', bd:'rgba(251,191,36,.3)'},
    external: {label:'EXTERNAL', bg:'rgba(192,132,252,.1)',col:'#c084fc', bd:'rgba(192,132,252,.3)'},
  };
  if (dirBadge && DIR_STYLE[dir]) {
    const d = DIR_STYLE[dir];
    dirBadge.textContent = d.label;
    dirBadge.style.cssText = `background:${d.bg};color:${d.col};border-color:${d.bd}`;
    dirBadge.style.display = '';
  }

  // copy
  $('copySrcIp')?.addEventListener('click', () => {
    copyText(ev.srcIp||'');
    const btn = $('copySrcIp');
    btn.classList.add('copied');
    setTimeout(()=>btn.classList.remove('copied'),1500);
  });
}

/* ═══════════════════════════════════════ RECOMENDAÇÕES ═══════════════════════════════════════ */
function renderRecomendacoes(ev) {
  const card  = $('cardRecom');
  const recom = ev.recomendacoes || [];
  const tags  = ev.tags_jg || [];
  if (!recom.length && !tags.length) return;
  card.style.display = '';

  const tagsEl = $('recomTags');
  if (tagsEl && tags.length) {
    tagsEl.innerHTML = tags.map(t=>`<span class="id-tag">${esc(t)}</span>`).join('');
  }
  $('recomList').innerHTML = recom.map((r,i)=>`
    <div class="id-recom-item">
      <span class="id-recom-num">${i+1}</span>
      <span class="id-recom-text">${esc(r)}</span>
    </div>`).join('');
}

/* ═══════════════════════════════════════ GEO ═══════════════════════════════════════ */
function renderGeo(ev) {
  const fields = [
    {l:'País',   v: ev.src_is_local ? 'Rede interna' : (ev.pais||ev.country?.name||'—')},
    {l:'Cidade', v: ev.cidade||'—'},
    {l:'ASN',    v: ev.asn_number||'—', mono:true},
    {l:'Org',    v: ev.asn_org||(ev.src_is_local?'LAN':'—')},
    {l:'rDNS',   v: ev.rdns||'—', mono:true},
    {l:'Direção',v: ev.direction||'—'},
  ];
  const cont = $('geoContent'); if (!cont) return;
  $('geoLoading')?.remove();
  cont.style.display = '';
  cont.innerHTML = `<div class="id-geo-grid">${
    fields.map(f=>`
      <div class="id-geo-item">
        <div class="id-geo-lbl">${esc(f.l)}</div>
        <div class="id-geo-val${f.mono?' id-tec-val--mono':''}" style="font-size:11px">${esc(String(f.v??'—'))}</div>
      </div>`).join('')
  }</div>`;
}

/* ═══════════════════════════════════════ HISTÓRICO ═══════════════════════════════════════ */
function renderHistorico(ev) {
  const el=$('histoCriado'); if(el) el.textContent=fmtDateTime(ev.criado_em||ev.first_seen);
}
function _appendHistorico(status) {
  const list=$('historicoList'); if(!list) return;
  const item=document.createElement('div');
  item.className='id-tl-mini-item';
  item.style.animation='id-slide-up .2s ease both';
  item.innerHTML=`
    <div class="id-tl-mini-dot id-tl-mini-dot--${STATUS_DOT[status]||'fp'}"></div>
    <div>
      <div class="id-tl-mini-title">Status → ${esc(STATUS_LABEL[status]||status)}</div>
      <div class="id-tl-mini-time">${fmtDateTime(new Date().toISOString())}</div>
    </div>`;
  list.appendChild(item);
}

/* ═══════════════════════════════════════ CORRELAÇÕES ═══════════════════════════════════════ */
function renderCorrelacoes(corr) {
  $('corrLoading')?.remove();
  const cont=$('corrContent'); if(cont) cont.style.display='';

  const dns  = corr.dns  || [];
  const http = corr.http || [];
  const tls  = corr.tls  || [];

  _setTabCount('corrDnsCount',  dns.length);
  _setTabCount('corrHttpCount', http.length);
  _setTabCount('corrTlsCount',  tls.length);

  $('corrPanelDns').innerHTML = dns.length
    ? dns.map(e=>`
        <div class="id-corr-item">
          <span class="id-corr-time">${fmtTime(e.timestamp)}</span>
          <span class="id-corr-val">${esc(e.query||'—')}</span>
          <span class="id-corr-sub">${esc(e.tipo||'')} ${esc(e.rcode||'')}</span>
        </div>`).join('')
    : '<p class="id-corr-empty">Sem consultas DNS nesta janela</p>';

  $('corrPanelHttp').innerHTML = http.length
    ? http.map(e=>`
        <div class="id-corr-item">
          <span class="id-corr-time">${fmtTime(e.timestamp)}</span>
          <span class="id-corr-val">${esc(e.metodo||'GET')} ${esc(e.hostname||'')}${esc(e.url||'')}</span>
          <span class="id-corr-sub">HTTP ${e.status_code||'?'}</span>
        </div>`).join('')
    : '<p class="id-corr-empty">Sem requisições HTTP nesta janela</p>';

  $('corrPanelTls').innerHTML = tls.length
    ? tls.map(e=>`
        <div class="id-corr-item">
          <span class="id-corr-time">${fmtTime(e.timestamp)}</span>
          <span class="id-corr-val">${esc(e.sni||'—')}</span>
          <span class="id-corr-sub">${esc(e.versao||'')}${e.ja3?' · JA3:'+e.ja3.slice(0,8):''}</span>
        </div>`).join('')
    : '<p class="id-corr-empty">Sem conexões TLS nesta janela</p>';
}

function _setTabCount(id, n) {
  const el=$(id); if(!el) return;
  el.textContent = n;
  if (n>0) el.classList.add('id-tab-badge--active');
}

function initCorrTabs() {
  qa('.id-tab-btn[data-tab]').forEach(tab=>{
    tab.addEventListener('click',()=>{
      qa('.id-tab-btn').forEach(t=>t.classList.remove('id-tab-btn--active'));
      tab.classList.add('id-tab-btn--active');
      const name = tab.dataset.tab;
      qa('.id-corr-panel').forEach(p=>p.style.display='none');
      const p=$(`corrPanel${name.charAt(0).toUpperCase()+name.slice(1)}`);
      if(p) p.style.display='';
    });
  });
}

/* ═══════════════════════════════════════ TÉCNICO ═══════════════════════════════════════ */
function renderTecnico(ev) {
  const tec = ev.tecnico || {};
  const fields = [
    {l:'Assinatura original', v: tec.signature||ev.sig?.name||'—', full:true},
    {l:'SID',                 v: tec.sid||ev.sig?.sid||'—',         mono:true},
    {l:'Categoria Suricata',  v: tec.categoria||ev.sig?.cat||'—'},
    {l:'Ação',                v: tec.acao||ev.sig?.action||'—'},
    {l:'Severidade Suricata', v: tec.severidade||ev.sig?.sev||'—'},
    {l:'Protocolo',           v: tec.protocolo||ev.sig?.proto||'—', mono:true},
    {l:'Porta destino',       v: tec.dest_porta||ev.sig?.port||'—', mono:true},
    {l:'Rev',                 v: ev.tecnico?.rev||ev.sig?.rev||'—',  mono:true},
  ];
  const grid=$('tecGrid'); if(!grid) return;
  grid.innerHTML = fields.map(f=>`
    <div class="id-tec-item${f.full?' id-tec-full':''}">
      <div class="id-tec-lbl">${esc(f.l)}</div>
      <div class="id-tec-val${f.mono?' id-tec-val--mono':''}" style="font-size:11px">${esc(String(f.v??'—'))}</div>
    </div>`).join('');

  const rawEl=$('rawJson');
  if(rawEl) rawEl.textContent = ev.raw_json ? JSON.stringify(ev.raw_json,null,2) : '(não disponível)';
}

/* ═══════════════════════════════════════ COLLAPSIBLE ═══════════════════════════════════════ */
function initCollapsible(btnId, wrapId, extraClass='') {
  const btn=$( btnId), wrap=$(wrapId); if(!btn||!wrap) return;
  btn.addEventListener('click',()=>{
    const open = wrap.classList.toggle('open');
    const icon = btn.querySelector('i');
    if(icon) icon.style.transform = open ? 'rotate(180deg)' : '';
    btn.childNodes.forEach(n=>{ if(n.nodeType===3) n.textContent=' '+(open?'Recolher':'Expandir'); });
  });
}

/* ═══════════════════════════════════════ RISK DETAIL (sidebar) ═══════════════════════════════════════ */
async function loadRiskDetail(ip) {
  try {
    const data = await _fetch(`/incidentes/api/ip/${ip}/contexto/?horas=24`);
    if (!data.ok || !data.contexto) return;
    const ctx  = data.contexto;
    const risk = ctx.risk_score || {};
    const score = risk.score || 0;
    const pct   = Math.min(score, 100);
    const col   = riskColor(pct);

    const card = $('riskDetailCard');
    const cont = $('riskDetailContent');
    if (!card || !cont) return;
    card.style.display = '';

    // atualiza ring com score real do IP
    renderRiskRing(score);

    cont.innerHTML = `
      <div style="padding:12px 14px 4px">
        <div class="id-risk-score-big" style="color:${col}">${Math.round(score)}</div>
        <div style="font-family:var(--font-mono);font-size:9px;letter-spacing:.1em;color:var(--text-dim);padding:2px 14px 8px;text-transform:uppercase">${riskLabel(pct)}</div>
      </div>
      <div class="id-risk-bar-wrap">
        <div class="id-risk-bar-track">
          <div class="id-risk-bar-fill" style="width:${pct}%;background:${col}"></div>
        </div>
      </div>
      <div class="id-risk-detail">
        <div class="id-risk-row"><span>Críticos</span><span style="color:#f43f5e;font-weight:700">${risk.criticos||0}</span></div>
        <div class="id-risk-row"><span>Altos</span><span style="color:#fb923c;font-weight:700">${risk.altos||0}</span></div>
        <div class="id-risk-row"><span>Médios</span><span style="color:#fbbf24;font-weight:700">${risk.medios||0}</span></div>
        <div class="id-risk-row"><span>Total alertas</span><span style="font-weight:700">${risk.total_alertas||0}</span></div>
        <div class="id-risk-row"><span>Alertas 24h</span><span style="font-weight:700">${ctx.total_alertas||0}</span></div>
        <div class="id-risk-row"><span>DNS 24h</span><span>${ctx.total_dns||0}</span></div>
        <div class="id-risk-row"><span>HTTP 24h</span><span>${ctx.total_http||0}</span></div>
      </div>`;
  } catch(_) { /* silencioso */ }
}

/* ═══════════════════════════════════════ RELACIONADOS ═══════════════════════════════════════ */
async function loadRelacionados(ip, selfId) {
  try {
    const data = await _fetch(`/incidentes/api/data/?count=20&horas=168&agrupado=0`);
    const lista = (data.eventos||[])
      .filter(e=>e.srcIp===ip && String(e.id)!==String(selfId))
      .slice(0,7);

    $('relLoading')?.remove();
    const el=$('relList'); if(!el) return;
    el.style.display='';

    if (!lista.length) {
      el.innerHTML='<p style="color:var(--text-dim);font-size:11px;padding:10px 14px;font-family:var(--font-mono)">Sem outros incidentes deste IP nos últimos 7d</p>';
      return;
    }
    el.innerHTML = lista.map(e=>{
      const sev   = e.severidade_jg||'informativo';
      const titulo = (e.titulo_jg||e.sig?.name||'—');
      const isNew  = (e.status||'novo') === 'novo';
      return `
        <a class="id-rel-item" href="/incidentes/${e.id}/">
          <span class="id-rel-dot id-rel-dot--${sev}"></span>
          <span class="id-rel-titulo" title="${esc(titulo)}">${esc(titulo)}</span>
          <div class="id-rel-right">
            <span class="id-rel-time">${fmtTime(e.timestamp)}</span>
            ${isNew?'<span class="id-rel-new">NOVO</span>':''}
          </div>
        </a>`;
    }).join('');
  } catch(_) { $('relLoading')?.remove(); }
}

/* ═══════════════════════════════════════ NOTA ═══════════════════════════════════════ */
function setNota(nota) { const ta=$('notaTextarea'); if(ta) ta.value=nota||''; }

document.addEventListener('DOMContentLoaded',()=>{
  $('btnSalvarNota')?.addEventListener('click',async()=>{
    const nota=$('notaTextarea')?.value||'';
    try {
      await _fetch(`/incidentes/api/${INC_ID}/status/`,{
        method:'PATCH',
        headers:{'Content-Type':'application/json','X-CSRFToken':getCsrf()},
        body:JSON.stringify({nota}),
      });
      toast('Nota salva');
    } catch(e){ toast(`⚠ ${e.message}`,4000); }
  });
});

/* ═══════════════════════════════════════ ACTIONS ═══════════════════════════════════════ */
function initActions() {
  const btn=$('btnAcoes'), dd=$('acoesDropdown');
  if(!btn||!dd) return;
  btn.addEventListener('click',e=>{e.stopPropagation();dd.classList.toggle('open');});
  document.addEventListener('click',()=>dd.classList.remove('open'));

  $('optInvestigar')?.addEventListener('click',()=>{
    if(_srcIp) window.open(`/incidentes/investigar/${_srcIp}/`,'_blank');
    dd.classList.remove('open');
  });
  $('optCopiarIp')?.addEventListener('click',()=>{
    if(_srcIp) copyText(_srcIp);
    dd.classList.remove('open');
  });
  $('optExportar')?.addEventListener('click',()=>{
    if(!_ev) return;
    const blob=new Blob([JSON.stringify(_ev,null,2)],{type:'application/json'});
    const a=document.createElement('a');
    a.href=URL.createObjectURL(blob);
    a.download=`incidente-${INC_ID}.json`;
    a.click();
    dd.classList.remove('open');
  });
  $('optSupressao')?.addEventListener('click',()=>{
    $('modalOverlay').classList.add('open');
    dd.classList.remove('open');
    if(_ev?.sig?.sid) $('supSidVal').value=_ev.sig.sid;
  });

  $('btnRefresh')?.addEventListener('click',()=>{
    const icon=$('refreshIcon');
    icon?.classList.add('spinning');
    loadIncidente().finally(()=>icon?.classList.remove('spinning'));
  });

  const style=document.createElement('style');
  style.textContent='.spinning{animation:id-spin .8s linear infinite}';
  document.head.appendChild(style);
}

/* ═══════════════════════════════════════ MODAL ═══════════════════════════════════════ */
function initModal() {
  $('modalClose')?.addEventListener('click',  ()=>$('modalOverlay').classList.remove('open'));
  $('modalCancel')?.addEventListener('click', ()=>$('modalOverlay').classList.remove('open'));
  $('modalOverlay')?.addEventListener('click',e=>{
    if(e.target===$('modalOverlay')) $('modalOverlay').classList.remove('open');
  });
  $('supTipo')?.addEventListener('change',()=>{
    $('supSidGroup').style.display=$('supTipo').value==='sid'?'':'none';
  });
  $('modalConfirm')?.addEventListener('click',async()=>{
    const tipo  =$('supTipo')?.value||'ip_src';
    const motivo=$('supMotivo')?.value||'';
    const expira=$('supExpira')?.value||null;
    if(!motivo.trim()){toast('⚠ Informe o motivo',3000);return;}
    try {
      const data=await _fetch('/incidentes/api/supressao/',{
        method:'POST',
        headers:{'Content-Type':'application/json','X-CSRFToken':getCsrf()},
        body:JSON.stringify({tipo,ip:_srcIp||'',sid:$('supSidVal')?.value||'',motivo,expira}),
      });
      if(data.ok){$('modalOverlay').classList.remove('open');toast(`Supressão criada: ${data.valor}`);}
    } catch(e){toast(`⚠ ${e.message}`,4000);}
  });
}