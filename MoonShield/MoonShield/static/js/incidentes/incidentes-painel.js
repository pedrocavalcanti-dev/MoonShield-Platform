'use strict';
/* =================================================================
   MOONSHIELD — INCIDENTES-PAINEL.JS  v3.6
   Correções v3.6:
   - fetch robusto: valida res.ok + content-type antes de res.json()
   - trata sessão expirada / erro 500 / resposta HTML inesperada
   - _calcHash inclui severidade_jg e categoria_jg
   - checagem defensiva de elementos DOM antes de usar
   - remove referências a KPIs inexistentes (kpiDns, kpiAltos, kpiNovos)
   - branding visível: MoonShield (nomes internos JG mantidos para não quebrar contrato)
   - código morto removido
================================================================= */

window.JGIncidentes = window.JGIncidentes || {};

const $ = id => document.getElementById(id);
const qs = sel => document.querySelector(sel);
const qa = sel => document.querySelectorAll(sel);

const PORT_NAMES = {
  22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
  143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 3306: 'MySQL', 3389: 'RDP',
  5432: 'PostgreSQL', 6379: 'Redis', 8080: 'HTTP-ALT', 8443: 'HTTPS-ALT',
  9001: 'Tor', 27017: 'MongoDB',
};
const SEV_CLASS = { critico: 'crit', alto: 'high', medio: 'med', baixo: 'low', informativo: 'dim' };
const SEV_LABEL = { critico: 'CRÍTICO', alto: 'ALTO', medio: 'MÉDIO', baixo: 'BAIXO', informativo: 'INFO' };
const CAT_ICON = {
  recon: 'bi-binoculars-fill', auth: 'bi-key-fill', lateral: 'bi-arrows-angle-expand',
  dns: 'bi-globe2', web: 'bi-arrow-left-right', tls: 'bi-lock-fill',
  malware: 'bi-bug-fill', exfil: 'bi-upload', p2p: 'bi-share-fill',
  anomalia: 'bi-question-diamond-fill', info: 'bi-info-circle-fill',
};
const CAT_LABEL = {
  recon: 'Reconhecimento', auth: 'Brute Force / Auth', lateral: 'Mov. Lateral',
  dns: 'DNS / Policy', web: 'Web / HTTP', tls: 'TLS / QUIC',
  malware: 'Malware / C2', exfil: 'Exfiltração', p2p: 'P2P / Mineração',
  anomalia: 'Anomalia', info: 'Informativo',
};
const PRESET_ICON = { casa: 'bi-house-fill', empresa: 'bi-building-fill', lab: 'bi-cpu-fill' };
const PRESET_NAME = { casa: 'Casa', empresa: 'Empresa', lab: 'Laboratório' };

// ─── localStorage ─────────────────────────────────────────────────────────────
const LS_KEY = 'ms_painel_filtros';

function _salvarFiltros() {
  try {
    localStorage.setItem(LS_KEY, JSON.stringify({
      preset: _state.presetAtivo,
      horas: _state.horas,
      sevFilter: _state.sevFilter,
      tabAtiva: _state.tabAtiva,
      pageSize: _state.pageSize,
      agrupado: _state.agrupado,
    }));
  } catch (_) { }
}

function _carregarFiltros() {
  try {
    // Suporta chave legada jg_painel_filtros e nova ms_painel_filtros
    const raw = localStorage.getItem(LS_KEY) || localStorage.getItem('jg_painel_filtros');
    if (!raw) return {};
    return JSON.parse(raw);
  } catch (_) { return {}; }
}

// ─── Utils ────────────────────────────────────────────────────────────────────
function isDemo(id) {
  if (!id) return true;
  return String(id).startsWith('demo-') || isNaN(parseInt(String(id)));
}
function fmtTime(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch (_) { return '—'; }
}
function fmtDateTime(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString('pt-BR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch (_) { return '—'; }
}
function esc(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function setEl(id, val) {
  const el = $(id);
  if (el) el.textContent = val;
}
function toast(msg, dur = 2200) {
  const t = $('toast'); if (!t) return;
  t.textContent = msg; t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), dur);
}
function copyText(txt) { navigator.clipboard?.writeText(txt).then(() => toast('Copiado: ' + txt)); }
function getCsrf() {
  return document.cookie.split(';').map(c => c.trim()).find(c => c.startsWith('csrftoken='))?.split('=')[1] || '';
}
function riskColor(s) {
  if (s < 30) return 'var(--c-ok)'; if (s < 50) return 'var(--c-med)';
  if (s < 70) return 'var(--c-high)'; return 'var(--c-crit)';
}
function riskLabel(s) {
  if (s < 30) return 'BAIXO'; if (s < 50) return 'MÉDIO'; if (s < 70) return 'ALTO'; return 'CRÍTICO';
}
function evTitulo(ev) { return ev.titulo_jg || ev.sig?.name || '—'; }
function evSev(ev) { return ev.severidade_jg || ev.sev || 'baixo'; }
function evPort(ev) { return ev.tecnico?.dest_porta || ev.sig?.port || 0; }
function evProto(ev) { return ev.tecnico?.protocolo || ev.sig?.proto || '—'; }

// ─── Fetch seguro ─────────────────────────────────────────────────────────────
/**
 * Faz fetch e retorna JSON de forma segura.
 * Lança erro descritivo se resposta não for JSON ou se status não for ok.
 */
async function _fetchJson(url, options = {}) {
  const res = await fetch(url, options);

  // Detecta resposta HTML inesperada (ex.: redirect de login, erro 500)
  const ct = res.headers.get('content-type') || '';
  if (!ct.includes('application/json')) {
    const text = await res.text();
    // Se parecer uma página de login, avisa claramente
    if (text.includes('<html') || text.includes('<!DOCTYPE')) {
      throw new Error(`Sessão expirada ou erro do servidor (HTTP ${res.status}). Faça login novamente.`);
    }
    throw new Error(`Resposta inesperada do servidor (HTTP ${res.status}, tipo: ${ct})`);
  }

  const data = await res.json();

  if (!res.ok) {
    const msg = data?.erro || data?.detail || data?.message || `Erro HTTP ${res.status}`;
    throw new Error(msg);
  }

  return data;
}

// ─── Badges ───────────────────────────────────────────────────────────────────
function sevBadge(sev) {
  const c = SEV_CLASS[sev] || 'dim';
  const l = SEV_LABEL[sev] || String(sev || '').toUpperCase() || '—';
  return `<span class="jg-badge jg-badge--${c}">${l}</span>`;
}
function fonteBadge(fonte) {
  const f = (fonte || 'IDS').toLowerCase();
  return `<span class="jg-badge jg-badge--fonte jg-badge--${f}">${esc(fonte || 'IDS')}</span>`;
}
function statusBadge(status) {
  const L = { novo: 'Novo', investigando: 'Investigando', resolvido: 'Resolvido', falso: 'Falso Positivo' };
  return `<span class="jg-status jg-status--${status || 'novo'}" data-status="${status || 'novo'}">
    <span class="jg-status__dot"></span>${L[status] || status || 'Novo'}
  </span>`;
}

// ─── Estado global ────────────────────────────────────────────────────────────
const _saved = _carregarFiltros();
const _state = {
  allEvents: [],
  filtered: [],
  evMap: new Map(),
  sortCol: 'timestamp',
  sortAsc: false,
  page: 1,
  pageSize: _saved.pageSize || 50,
  tabAtiva: _saved.tabAtiva || 'incidente',
  srcFilter: 'ALL',
  sevFilter: _saved.sevFilter || 'all',
  searchTerm: '',
  horas: _saved.horas || 24,
  agrupado: _saved.agrupado !== undefined ? _saved.agrupado : true,
  presetAtivo: _saved.preset || 'casa',
  modoDemo: false,
  modoProd: false,
  _lastHash: '',
  _renderPending: false,
};

window.JGIncidentes.state = _state;
window.JGIncidentes.utils = {
  esc, fmtTime, fmtDateTime, toast, getCsrf, isDemo,
  riskColor, riskLabel, evTitulo, evSev, evPort, evProto,
  sevBadge, statusBadge, fonteBadge,
  PORT_NAMES, SEV_CLASS, SEV_LABEL, CAT_ICON, CAT_LABEL,
};
window.JGIncidentes.renderTable = renderTable;

// ─── Fallback demo local ──────────────────────────────────────────────────────
function _gerarDemoLocal(horas) {
  const now = Date.now();
  const SIGS = [
    { name: 'ET SCAN Potential SSH Scan', sid: '2100498', sev: 'alto', cat: 'recon' },
    { name: 'ET MALWARE CobaltStrike Beacon', sid: '2023019', sev: 'critico', cat: 'malware' },
    { name: 'ET POLICY RDP Detected', sid: '2001328', sev: 'medio', cat: 'lateral' },
    { name: 'ET DNS Query to .ru TLD', sid: '2010935', sev: 'baixo', cat: 'dns' },
    { name: 'ET EXPLOIT Log4Shell Attempt', sid: '2034700', sev: 'critico', cat: 'web' },
    { name: 'ET SCAN Nmap Scripting Engine', sid: '2009358', sev: 'alto', cat: 'recon' },
    { name: 'ET TROJAN Metasploit Meterpreter', sid: '2019714', sev: 'critico', cat: 'malware' },
    { name: 'ET INFO TOR Known Exit Node', sid: '2522616', sev: 'medio', cat: 'p2p' },
    { name: 'ET WEB_SERVER SQL Injection', sid: '2006445', sev: 'alto', cat: 'web' },
    { name: 'ET POLICY DNS Query for TOR', sid: '2522610', sev: 'baixo', cat: 'dns' },
  ];
  const IPS = ['185.220.101.47', '91.92.251.103', '45.33.32.156', '104.21.44.87', '37.19.221.15'];
  const PAISES = [
    { name: 'Rússia', c: 'RU' }, { name: 'China', c: 'CN' },
    { name: 'Brasil', c: 'BR' }, { name: 'EUA', c: 'US' }, { name: 'Alemanha', c: 'DE' },
  ];
  const DSTS = ['192.168.1.1', '10.0.0.1', '10.0.0.5', '192.168.0.254'];
  const CLS = ['incidente', 'incidente', 'evento', 'evento', 'telemetria'];
  const r = a => a[Math.floor(Math.random() * a.length)];
  const evs = [];
  for (let i = 0; i < 80; i++) {
    const sig = r(SIGS), pais = r(PAISES), ip = r(IPS);
    const dt = new Date(now - Math.random() * horas * 3600000);
    evs.push({
      id: `demo-${i}`,
      timestamp: dt.toISOString(),
      last_seen: dt.toISOString(),
      first_seen: dt.toISOString(),
      severidade_jg: sig.sev,
      classificacao: r(CLS),
      categoria_jg: sig.cat,
      titulo_jg: sig.name,
      resumo_jg: `Atividade suspeita de ${ip} (${pais.name}).`,
      evidencia: `SID ${sig.sid} — ${sig.name}`,
      tags_jg: [sig.cat.toUpperCase(), sig.sev.toUpperCase()],
      recomendacoes: ['Bloquear IP de origem no firewall', 'Revisar logs do servidor alvo'],
      srcIp: ip,
      dstIp: r(DSTS),
      country: { name: pais.name, flag: '<span class="fi fi-br" style="width:20px;height:14px;border-radius:2px;display:inline-block;vertical-align:middle"></span>' },
      pais_codigo: pais.c,
      asn_org: 'AS' + (Math.floor(Math.random() * 60000) + 1000),
      fonte: r(['IDS', 'FW', 'DNS']),
      status: r(['novo', 'novo', 'investigando', 'resolvido']),
      group_count: Math.floor(Math.random() * 8) + 1,
      src_is_local: false,
      direction: r(['inbound', 'inbound', 'outbound', 'lateral']),
      sig: { name: sig.name, sid: sig.sid, cat: sig.cat },
      tecnico: {
        signature: sig.name, sid: sig.sid,
        protocolo: r(['TCP', 'UDP']),
        dest_porta: r([22, 80, 443, 3389, 8080]),
      },
    });
  }
  evs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  return evs;
}

// ─── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  window.JGIncidentes.renderTable = renderTable;

  initClock();
  initPeriod();
  initPreset();
  initSearch();
  initSort();
  initPagination();
  initTabs();
  initSrcFilters();
  initSevChips();
  initGroupToggle();
  _restaurarUI();

  if ($('alertTable')) {
    loadIncidentes();
    loadStats();
    setInterval(() => { loadIncidentes(); loadStats(); }, 15000);

    $('btnRefresh')?.addEventListener('click', () => {
      const icon = $('refreshIcon');
      icon?.classList.add('spinning');
      _state._lastHash = '';
      Promise.all([loadIncidentes(), loadStats()])
        .finally(() => icon?.classList.remove('spinning'));
    });
  }
});

// ─── Restaurar UI ─────────────────────────────────────────────────────────────
function _restaurarUI() {
  qa('.jg-period__btn').forEach(b => {
    b.classList.toggle('jg-period__btn--active', parseInt(b.dataset.h) === _state.horas);
  });
  const icon = $('presetBtn')?.querySelector('i.bi');
  if (icon) icon.className = `bi ${PRESET_ICON[_state.presetAtivo] || 'bi-house-fill'}`;
  setEl('presetLabel', PRESET_NAME[_state.presetAtivo] || 'Casa');
  qa('.jg-preset-opt').forEach(opt => {
    opt.style.background = opt.dataset.preset === _state.presetAtivo ? 'var(--bg-hover)' : '';
  });
  qa('.jg-sev-chip').forEach(c => {
    c.classList.toggle('jg-sev-chip--active', c.dataset.sev === _state.sevFilter);
  });
  qa('.jg-tab').forEach(t => {
    t.classList.toggle('jg-tab--active', t.dataset.tab === _state.tabAtiva);
  });
  const tog = $('toggleGroup');
  if (tog) tog.checked = _state.agrupado;
  const ps = $('pagSize');
  if (ps) ps.value = String(_state.pageSize);
}

// ─── Clock ────────────────────────────────────────────────────────────────────
function initClock() {
  const el = $('liveTime'); if (!el) return;
  const tick = () => { el.textContent = new Date().toLocaleTimeString('pt-BR'); };
  tick(); setInterval(tick, 1000);
}

// ─── Period ───────────────────────────────────────────────────────────────────
function initPeriod() {
  qa('.jg-period__btn').forEach(btn => btn.addEventListener('click', () => {
    qa('.jg-period__btn').forEach(b => b.classList.remove('jg-period__btn--active'));
    btn.classList.add('jg-period__btn--active');
    _state.horas = parseInt(btn.dataset.h);
    _state.page = 1;
    _state._lastHash = '';
    _salvarFiltros();
    loadIncidentes();
  }));
}

// ─── Preset ───────────────────────────────────────────────────────────────────
function initPreset() {
  const btn = $('presetBtn'), dd = $('presetDropdown');
  if (!btn || !dd) return;
  btn.addEventListener('click', e => { e.stopPropagation(); dd.classList.toggle('open'); });
  document.addEventListener('click', () => dd.classList.remove('open'));
  qa('.jg-preset-opt').forEach(opt => opt.addEventListener('click', () => {
    const p = opt.dataset.preset;
    setPreset(p);
    dd.classList.remove('open');
    // Persiste preset no backend sem bloquear
    fetch(`/incidentes/api/preset/salvar/?preset=${p}`).catch(() => { });
  }));
}

function setPreset(p) {
  _state.presetAtivo = p;
  const icon = $('presetBtn')?.querySelector('i.bi');
  if (icon) icon.className = `bi ${PRESET_ICON[p] || 'bi-house-fill'}`;
  setEl('presetLabel', PRESET_NAME[p] || p);
  qa('.jg-preset-opt').forEach(opt => {
    opt.style.background = opt.dataset.preset === p ? 'var(--bg-hover)' : '';
  });
  _state.page = 1;
  _state._lastHash = '';
  _salvarFiltros();
  loadIncidentes();
}

// ─── Abas ─────────────────────────────────────────────────────────────────────
function initTabs() {
  qa('.jg-tab').forEach(tab => tab.addEventListener('click', () => {
    qa('.jg-tab').forEach(t => t.classList.remove('jg-tab--active'));
    tab.classList.add('jg-tab--active');
    _state.tabAtiva = tab.dataset.tab;
    _state.page = 1;
    _salvarFiltros();
    applyFilters();
    updateInsights();
  }));
}

// ─── Source filters ───────────────────────────────────────────────────────────
function initSrcFilters() {
  qa('.jg-src-btn').forEach(btn => btn.addEventListener('click', () => {
    qa('.jg-src-btn').forEach(b => b.classList.remove('jg-src-btn--active'));
    btn.classList.add('jg-src-btn--active');
    _state.srcFilter = btn.dataset.src;
    _state.page = 1;
    applyFilters();
    updateInsights();
  }));
}

// ─── Severity chips ───────────────────────────────────────────────────────────
function initSevChips() {
  qa('.jg-sev-chip').forEach(chip => chip.addEventListener('click', () => {
    qa('.jg-sev-chip').forEach(c => c.classList.remove('jg-sev-chip--active'));
    chip.classList.add('jg-sev-chip--active');
    _state.sevFilter = chip.dataset.sev;
    _state.page = 1;
    _salvarFiltros();
    applyFilters();
    updateInsights();
  }));
}

// ─── Group toggle ─────────────────────────────────────────────────────────────
function initGroupToggle() {
  $('toggleGroup')?.addEventListener('change', e => {
    _state.agrupado = e.target.checked;
    _state.page = 1;
    _state._lastHash = '';
    _salvarFiltros();
    loadIncidentes();
  });
}

// ─── Search ───────────────────────────────────────────────────────────────────
function initSearch() {
  const inp = $('searchInput'), clr = $('searchClear');
  if (!inp) return;
  inp.addEventListener('input', () => {
    _state.searchTerm = inp.value.trim().toLowerCase();
    clr?.classList.toggle('visible', !!_state.searchTerm);
    _state.page = 1;
    applyFilters();
    updateInsights();
  });
  clr?.addEventListener('click', () => {
    inp.value = '';
    _state.searchTerm = '';
    clr.classList.remove('visible');
    _state.page = 1;
    applyFilters();
    updateInsights();
  });
}

// ─── Sort ─────────────────────────────────────────────────────────────────────
function initSort() {
  qa('.jg-table th[data-sort]').forEach(th => th.addEventListener('click', () => {
    const col = th.dataset.sort;
    if (_state.sortCol === col) _state.sortAsc = !_state.sortAsc;
    else { _state.sortCol = col; _state.sortAsc = false; }
    qa('.jg-table th').forEach(t => t.classList.remove('sorted', 'sorted-asc', 'sorted-desc'));
    th.classList.add('sorted', _state.sortAsc ? 'sorted-asc' : 'sorted-desc');
    _state.page = 1;
    applyFilters();
  }));
}

// ─── Hash robusto ─────────────────────────────────────────────────────────────
function _calcHash(eventos) {
  if (!eventos.length) return 'empty';
  return eventos.slice(0, 30).map(ev => [
    ev.id || '',
    ev.last_seen || ev.timestamp || '',
    ev.first_seen || '',
    ev.ocorrencias || ev.group_count || 1,
    ev.status || '',
    ev.classificacao || '',
    ev.severidade_jg || ev.sev || '',   // v3.6: inclui severidade
    ev.categoria_jg || '',              // v3.6: inclui categoria
  ].join('|')).join('||');
}

// ─── Carga de dados ───────────────────────────────────────────────────────────
async function loadIncidentes() {
  try {
    const agr = _state.agrupado ? 1 : 0;
    const url = `/incidentes/api/data/?count=100&horas=${_state.horas}&preset=${_state.presetAtivo}&agrupado=${agr}`;
    const data = await _fetchJson(url);

    if (!data.ok) {
      _ativarDemoEmergencia();
      return;
    }

    const eventos = (data.eventos || data.events || []).map(ev => ({
      ...ev,
      group_count: ev.group_count ?? ev.ocorrencias ?? 1,
      timestamp: ev.last_seen ?? ev.timestamp,
    }));

    const novoHash = _calcHash(eventos);
    const dadosMudaram = novoHash !== _state._lastHash;
    _state._lastHash = novoHash;

    _state.allEvents = eventos;
    _state.modoDemo = !!data.demo;
    _state.modoProd = !data.demo && eventos.length === 0;

    _atualizarBannerDemo(_state.modoDemo);
    _atualizarBannerProd(_state.modoProd);
    updateBadges();
    applyFilters();

    if (dadosMudaram) updateInsights();
    _updateKpiFromEvents();

  } catch (e) {
    console.warn('loadIncidentes falhou — fallback local:', e.message);
    // Mostra toast de erro apenas se não estiver em modo demo já
    if (!_state.modoDemo) {
      toast(`⚠ Erro ao carregar dados: ${e.message}`, 4000);
    }
    _ativarDemoEmergencia();
  }
}

function _ativarDemoEmergencia() {
  _state.allEvents = _gerarDemoLocal(_state.horas);
  _state.modoDemo = true;
  _state.modoProd = false;
  _atualizarBannerDemo(true);
  _atualizarBannerProd(false);
  updateBadges();
  applyFilters();
  updateInsights();
  _updateKpiFromEvents();
}

// ─── Banners ──────────────────────────────────────────────────────────────────
function _atualizarBannerDemo(ativo) {
  $('demoBanner')?.classList.toggle('jg-demo-banner--visible', ativo);
}
function _atualizarBannerProd(ativo) {
  $('prodLiveBanner')?.classList.toggle('jg-prod-banner--visible', ativo);
}

// ─── loadStats ────────────────────────────────────────────────────────────────
async function loadStats() {
  try {
    const data = await _fetchJson('/incidentes/api/stats/');
    if (!data.ultimas_24h) return;

    const u = data.ultimas_24h;
    const criticos = u.criticos_incidentes ?? u.criticos ?? '—';
    const novos = u.novos_incidentes ?? u.novos ?? '—';

    setEl('kpiCrit', criticos);

    const deltaEl = $('kpiCritDelta');
    if (deltaEl) {
      const delta = data.delta_criticos;
      if (delta !== undefined && delta !== null) {
        deltaEl.textContent = `${delta > 0 ? '+' : ''}${delta} vs 24h ant.`;
        deltaEl.style.color = delta > 0 ? 'var(--c-crit)' : delta < 0 ? 'var(--c-ok)' : 'var(--text-dim)';
        deltaEl.classList.add('show');
      } else {
        deltaEl.textContent = '— variação';
        deltaEl.classList.remove('show');
      }
    }

    const sub = $('kpiTotalSub');
    if (sub && u.investigando > 0) {
      sub.style.display = '';
      const span = sub.querySelector('span');
      if (span) span.textContent = `${u.investigando} investigando`;
    }

    if (data.resolvidos_hoje !== undefined) setEl('kpiResolvidos', data.resolvidos_hoje);

    // Nota: kpiDns, kpiAltos, kpiNovos foram removidos do HTML — não atualizar.
    // Se reintroduzidos no template, descomentar:
    // setEl('kpiNovos', novos);

  } catch (e) {
    // Stats são opcionais — falha silenciosa é aceitável
    console.warn('loadStats falhou:', e.message);
  }
}

// ─── KPIs locais ──────────────────────────────────────────────────────────────
function _updateKpiFromEvents() {
  if (!_state.allEvents.length) return;

  const topIp = _calcTopIp(_state.allEvents);
  setEl('kpiTopIp', topIp?.ip || '—');
  setEl('kpiTopIpSub', `${topIp?.count || 0} eventos`);
  setEl('kpiRate', _calcRate(_state.allEvents, _state.horas).toFixed(1));
  setEl('kpiTotal', _state.allEvents.length);
}

function _calcTopIp(events) {
  const counts = {};
  events.forEach(e => {
    if (!e.srcIp) return;
    counts[e.srcIp] = (counts[e.srcIp] || 0) + (e.group_count || 1);
  });
  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  if (!sorted.length) return null;
  return { ip: sorted[0][0], count: sorted[0][1] };
}

function _calcRate(events, horas) {
  const total = events.reduce((s, e) => s + (e.group_count || 1), 0);
  return horas > 0 ? total / (horas * 60) : 0;
}

// ─── Badges de aba ────────────────────────────────────────────────────────────
function updateBadges() {
  const inc = _state.allEvents.filter(e => (e.classificacao || 'telemetria') === 'incidente').length;
  const evt = _state.allEvents.filter(e => (e.classificacao || 'telemetria') === 'evento').length;
  const tel = _state.allEvents.filter(e => (e.classificacao || 'telemetria') === 'telemetria').length;
  setEl('badgeIncidente', inc);
  setEl('badgeEvento', evt);
  setEl('badgeTelemetria', tel);
}

// ─── Filtros ──────────────────────────────────────────────────────────────────
function applyFilters() {
  let evs = [..._state.allEvents];
  evs = evs.filter(e => (e.classificacao || 'telemetria') === _state.tabAtiva);
  if (_state.srcFilter !== 'ALL') evs = evs.filter(e => e.fonte === _state.srcFilter);
  if (_state.sevFilter !== 'all') evs = evs.filter(e => evSev(e) === _state.sevFilter);
  if (_state.searchTerm) {
    evs = evs.filter(e => {
      const hay = [
        e.srcIp, e.dstIp, e.titulo_jg, e.resumo_jg, e.categoria_jg, e.evidencia,
        e.sig?.name, e.sig?.sid, e.sig?.cat,
        (e.tags_jg || []).join(' '),
        e.country?.name, e.asn_org, e.rdns, e.direction,
      ].filter(Boolean).join(' ').toLowerCase();
      return hay.includes(_state.searchTerm);
    });
  }
  evs.sort((a, b) => {
    let va, vb;
    if (_state.sortCol === 'timestamp') { va = a.timestamp; vb = b.timestamp; }
    else if (_state.sortCol === 'sig') { va = evTitulo(a); vb = evTitulo(b); }
    else { va = ''; vb = ''; }
    if (va < vb) return _state.sortAsc ? -1 : 1;
    if (va > vb) return _state.sortAsc ? 1 : -1;
    return 0;
  });
  _state.filtered = evs;
  renderTable();
}

// ─── Render tabela ────────────────────────────────────────────────────────────
function renderTable() {
  if (_state._renderPending) return;
  _state._renderPending = true;
  requestAnimationFrame(() => {
    _state._renderPending = false;
    _renderTableImediato();
  });
}

function _renderTableImediato() {
  const tbody = $('alertTable'); if (!tbody) return;
  const total = _state.filtered.length;
  const maxPg = Math.max(1, Math.ceil(total / _state.pageSize));
  if (_state.page > maxPg) _state.page = maxPg;
  const start = (_state.page - 1) * _state.pageSize;
  const page = _state.filtered.slice(start, start + _state.pageSize);

  setEl('tableCount', `${total} evento${total !== 1 ? 's' : ''}`);
  setEl('pagInfo', `${start + 1}–${Math.min(start + _state.pageSize, total)} de ${total}`);
  setEl('pagTotal', `${maxPg} pág`);

  if (!page.length) {
    tbody.innerHTML = _emptyStateHTML();
    renderPagination(maxPg);
    return;
  }

  _state.evMap.clear();
  tbody.innerHTML = page.map((ev, i) => {
    _state.evMap.set(String(ev.id), ev);
    const sev = evSev(ev);
    const port = evPort(ev);
    const proto = evProto(ev);
    const titulo = evTitulo(ev);
    const code = ev.pais_codigo?.toLowerCase() || '';
    const flag = code
      ? `<span class="fi fi-${code}" style="width:20px;height:14px;border-radius:2px;display:inline-block;vertical-align:middle"></span>`
      : '<span class="fi fi-br" style="width:20px;height:14px;border-radius:2px;display:inline-block;vertical-align:middle"></span>';
    const cnt = _state.agrupado ? (ev.group_count || 1) : 1;
    const srcMeta = ev.src_is_local
      ? `<span class="cell-ip-sub">Rede local</span>`
      : `<span class="cell-ip-sub">${esc(ev.country?.name || '')}</span>`;

    return `<tr class="row-anim" style="animation-delay:${i * 14}ms" data-id="${esc(String(ev.id))}">
      <td class="cell-hora">${fmtTime(ev.timestamp)}</td>
      <td>${sevBadge(sev)}</td>
      <td>${fonteBadge(ev.fonte)}</td>
      <td class="cell-sig" title="${esc(titulo)}">${esc(titulo)}${cnt > 1 ? `<span class="jg-count-tag">${cnt}×</span>` : ''}</td>
      <td>
        <div class="cell-ip">
          <span class="cell-flag">${flag}</span>
          <div style="display:flex;flex-direction:column;min-width:0">
            <span class="cell-ip-text">${esc(ev.srcIp || '—')}</span>
            ${srcMeta}
          </div>
        </div>
      </td>
      <td><span class="jg-proto-tag">${esc(proto)}</span></td>
      <td><span style="font-family:var(--font-mono);font-size:11px">${esc(ev.dstIp || '—')}${port ? ':' + port : ''}</span></td>
      <td>${statusBadge(ev.status)}</td>
      <td class="cell-acoes">
        <button class="jg-row-action" title="Copiar IP" data-copy="${esc(ev.srcIp || '')}"><i class="bi bi-clipboard"></i></button>
        <button class="jg-row-action" title="Investigar IP" data-inv="${esc(ev.srcIp || '')}"><i class="bi bi-search"></i></button>
      </td>
    </tr>`;
  }).join('');

  // Event listeners nas linhas
  tbody.querySelectorAll('tr[data-id]').forEach(row => {
    row.addEventListener('click', e => {
      if (e.target.closest('.jg-row-action') || e.target.closest('.jg-status')) return;
      const ev = _state.evMap.get(row.dataset.id);
      if (ev) window.JGIncidentes.drawer?.openDrawer?.(ev);
    });
  });
  tbody.querySelectorAll('[data-copy]').forEach(btn => btn.addEventListener('click', e => {
    e.stopPropagation();
    if (btn.dataset.copy) {
      copyText(btn.dataset.copy);
      btn.classList.add('copied');
      setTimeout(() => btn.classList.remove('copied'), 1500);
    }
  }));
  tbody.querySelectorAll('[data-inv]').forEach(btn => btn.addEventListener('click', e => {
    e.stopPropagation();
    if (btn.dataset.inv) window.open(`/incidentes/investigar/${btn.dataset.inv}/`, '_blank');
  }));
  tbody.querySelectorAll('.jg-status').forEach(badge => badge.addEventListener('click', e => {
    e.stopPropagation();
    const row = badge.closest('tr[data-id]');
    const ev = row ? _state.evMap.get(row.dataset.id) : null;
    if (ev) cycleStatus(ev, badge);
  }));

  renderPagination(maxPg);
}

function _emptyStateHTML() {
  if (_state.modoProd) {
    return `<tr><td colspan="9" class="jg-empty jg-empty--prod">
      <div class="jg-empty__icon-wrap"><i class="bi bi-broadcast-pin jg-empty__icon jg-empty__icon--pulse"></i></div>
      <p class="jg-empty__title">Aguardando dados reais</p>
      <p class="jg-empty__sub">O modo <strong>Produção</strong> está ativo mas nenhum evento chegou ainda.<br>Verifique se o sensor MoonShield está online e enviando eventos.</p>
      <div class="jg-empty__steps">
        <div class="jg-empty__step"><span class="jg-empty__step-num">1</span><span>Sensor Linux com Suricata instalado e rodando</span></div>
        <div class="jg-empty__step"><span class="jg-empty__step-num">2</span><span>Execute o sensor MoonShield no servidor de coleta</span></div>
        <div class="jg-empty__step"><span class="jg-empty__step-num">3</span><span>Confira o status em <a href="/configuracoes/" class="jg-empty__link">Configurações → Integrações → IDS</a></span></div>
      </div>
    </td></tr>`;
  }
  return `<tr><td colspan="9" class="jg-empty">
    <i class="bi bi-inbox jg-empty__icon"></i>
    <p>Nenhum evento nesta categoria.</p>
  </td></tr>`;
}

// ─── Status cycle ─────────────────────────────────────────────────────────────
async function cycleStatus(ev, badge) {
  const cycle = ['novo', 'investigando', 'resolvido', 'falso'];
  const cur = badge.dataset.status || 'novo';
  const next = cycle[(cycle.indexOf(cur) + 1) % cycle.length];

  if (isDemo(ev.id)) {
    _aplicarStatusLocal(ev.id, next);
    _state._renderPending = false;
    renderTable();
    toast(`Status → ${next} (demo)`);
    return;
  }

  try {
    const data = await _fetchJson(`/incidentes/api/${ev.id}/status/`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrf() },
      body: JSON.stringify({ status: next }),
    });
    if (data.ok) {
      _aplicarStatusLocal(ev.id, next);
      _state._renderPending = false;
      renderTable();
      toast(`Status → ${next}`);
    }
  } catch (e) {
    toast(`⚠ Erro ao atualizar status: ${e.message}`, 4000);
    console.error('cycleStatus:', e);
  }
}

function _aplicarStatusLocal(id, status) {
  const ev = _state.allEvents.find(e => String(e.id) === String(id));
  if (ev) ev.status = status;
  window.JGIncidentes.drawer?.syncStatus?.(id, status);
}
window.JGIncidentes.aplicarStatusLocal = _aplicarStatusLocal;

// ─── Paginação ────────────────────────────────────────────────────────────────
function initPagination() {
  $('pagSize')?.addEventListener('change', e => {
    _state.pageSize = parseInt(e.target.value);
    _state.page = 1;
    _salvarFiltros();
    _state._renderPending = false;
    renderTable();
  });

  const nav = (action) => {
    const mp = Math.ceil(_state.filtered.length / _state.pageSize) || 1;
    if (action === 'first') _state.page = 1;
    else if (action === 'prev' && _state.page > 1) _state.page--;
    else if (action === 'next' && _state.page < mp) _state.page++;
    else if (action === 'last') _state.page = mp;
    _state._renderPending = false;
    renderTable();
  };

  $('pagFirst')?.addEventListener('click', () => nav('first'));
  $('pagPrev')?.addEventListener('click', () => nav('prev'));
  $('pagNext')?.addEventListener('click', () => nav('next'));
  $('pagLast')?.addEventListener('click', () => nav('last'));
}

function renderPagination(maxPg) {
  const first = $('pagFirst'), prev = $('pagPrev'), next = $('pagNext'), last = $('pagLast');
  if (first) first.disabled = prev.disabled = (_state.page === 1);
  if (next) next.disabled = last.disabled = (_state.page >= maxPg);
  const pages = $('pagPages'); if (!pages) return;
  pages.innerHTML = '';
  if (maxPg <= 7) {
    for (let p = 1; p <= maxPg; p++) addPagNum(pages, p);
    return;
  }
  const range = [];
  for (let p = Math.max(1, _state.page - 2); p <= Math.min(maxPg, _state.page + 2); p++) range.push(p);
  if (range[0] > 1) {
    addPagNum(pages, 1);
    if (range[0] > 2) pages.insertAdjacentHTML('beforeend', '<span class="jg-pag-ellipsis">…</span>');
  }
  range.forEach(p => addPagNum(pages, p));
  const last2 = range[range.length - 1];
  if (last2 < maxPg) {
    if (last2 < maxPg - 1) pages.insertAdjacentHTML('beforeend', '<span class="jg-pag-ellipsis">…</span>');
    addPagNum(pages, maxPg);
  }
}

function addPagNum(container, p) {
  const btn = document.createElement('button');
  btn.className = 'jg-pag-num' + (p === _state.page ? ' jg-pag-num--active' : '');
  btn.textContent = p;
  btn.addEventListener('click', () => { _state.page = p; _state._renderPending = false; renderTable(); });
  container.appendChild(btn);
}

// ─── Insights ─────────────────────────────────────────────────────────────────
function updateInsights() {
  if (!_state.filtered.length) {
    if (_state.modoProd) _renderInsightsProdVazio();
    return;
  }
  updateCountries();
  updateSevDist();
  updateSigs();
  updatePorts();
}

function _renderInsightsProdVazio() {
  const html = `<div class="jg-insight-empty"><i class="bi bi-radar jg-insight-empty__icon"></i><span class="jg-insight-empty__msg">Aguardando dados...</span></div>`;
  ['insightCountries', 'insightSevDist', 'insightSigs', 'insightPorts'].forEach(id => {
    const el = $(id); if (el) el.innerHTML = html;
  });
}

function updateCountries() {
  const el = $('insightCountries'); if (!el) return;
  const counts = {};
  _state.filtered.forEach(e => {
    if (e.src_is_local) return;
    const k = e.country?.name || 'Brasil';
    const fc = (e.pais_codigo || '').toLowerCase();
    const flag = fc ? `<span class="fi fi-${fc}" style="width:18px;height:13px;border-radius:2px;display:inline-block"></span>` : '<span class="fi fi-br" style="width:20px;height:14px;border-radius:2px;display:inline-block;vertical-align:middle"></span>';
    if (!counts[k]) counts[k] = { count: 0, flag };
    counts[k].count++;
  });
  const sorted = Object.entries(counts).sort((a, b) => b[1].count - a[1].count).slice(0, 7);
  const max = sorted[0]?.[1]?.count || 1;
  el.innerHTML = sorted.map(([name, d]) => `
    <div class="jg-country-row">
      <span class="jg-country-flag">${d.flag}</span>
      <span class="jg-country-name">${esc(name)}</span>
      <div class="jg-country-bar-wrap"><div class="jg-country-bar" style="width:${Math.round(d.count / max * 100)}%"></div></div>
      <span class="jg-country-count">${d.count}</span>
    </div>`).join('')
    || '<p style="color:var(--text-dim);font-size:11px;padding:4px 6px">Sem dados externos</p>';
}

function updateSevDist() {
  const el = $('insightSevDist'); if (!el) return;
  const counts = { critico: 0, alto: 0, medio: 0, baixo: 0, informativo: 0 };
  _state.filtered.forEach(e => { const s = evSev(e); if (s in counts) counts[s]++; });
  const total = _state.filtered.length || 1;
  el.innerHTML = [
    { k: 'critico', l: 'CRÍTICO', c: 'var(--c-crit)' },
    { k: 'alto', l: 'ALTO', c: 'var(--c-high)' },
    { k: 'medio', l: 'MÉDIO', c: 'var(--c-med)' },
    { k: 'baixo', l: 'BAIXO', c: 'var(--c-low)' },
    { k: 'informativo', l: 'INFO', c: 'var(--text-dim)' },
  ].map(r => `
    <div class="jg-sev-row">
      <div class="jg-sev-row-label">
        <span style="color:var(--text-muted)">${r.l}</span>
        <span style="color:var(--text-dim)">${counts[r.k]}</span>
      </div>
      <div class="jg-sev-track"><div class="jg-sev-fill" style="width:${Math.round(counts[r.k] / total * 100)}%;background:${r.c}"></div></div>
    </div>`).join('');
}

function updateSigs() {
  const el = $('insightSigs'); if (!el) return;
  const counts = {};
  _state.filtered.forEach(e => {
    const k = evTitulo(e), s = evSev(e);
    if (!counts[k]) counts[k] = { count: 0, sev: s };
    counts[k].count++;
  });
  const sorted = Object.entries(counts).sort((a, b) => b[1].count - a[1].count).slice(0, 6);
  el.innerHTML = sorted.map(([name, d]) => `
    <div class="jg-sig-row jg-sig-row--${SEV_CLASS[d.sev] || 'dim'}">
      <span class="jg-sig-name">${esc(name)}</span>
      <div class="jg-sig-meta"><span class="jg-sig-count">${d.count}×</span>${sevBadge(d.sev)}</div>
    </div>`).join('')
    || '<p style="color:var(--text-dim);font-size:11px;padding:4px 6px">—</p>';
}

function updatePorts() {
  const el = $('insightPorts'); if (!el) return;
  const counts = {};
  _state.filtered.forEach(e => { const p = evPort(e); if (p) counts[p] = (counts[p] || 0) + 1; });
  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 6);
  el.innerHTML = sorted.map(([port, cnt]) => `
    <div class="jg-port-row">
      <span class="jg-port-num">${port}</span>
      <span class="jg-port-name">${PORT_NAMES[port] || '—'}</span>
      <span class="jg-port-count">${cnt}</span>
    </div>`).join('')
    || '<p style="color:var(--text-dim);font-size:11px;padding:4px 6px">—</p>';
}