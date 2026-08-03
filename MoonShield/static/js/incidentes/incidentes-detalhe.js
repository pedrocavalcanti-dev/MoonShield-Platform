'use strict';
/* =================================================================
   MOONSHIELD — INCIDENTES-DETALHE.JS  v2.4
   Alterações v2.4:
   - botão "Detalhe" no drawer → abre /incidentes/<id>/ em nova aba
   - só visível para incidentes reais (oculto em modo demo)
================================================================= */

window.JGIncidentes = window.JGIncidentes || {};

const _$ = id => document.getElementById(id);
const _qs = sel => document.querySelector(sel);
const _qa = sel => document.querySelectorAll(sel);

function _u() { return window.JGIncidentes.utils || {}; }

const _drawer = {
  currentId: null,
  currentIp: null,
  currentEv: null,
  corrLoaded: false,
  ctxLoaded: false,
  tlLoaded: false,
};

window.JGIncidentes.drawer = { openDrawer, closeDrawer, syncStatus };

document.addEventListener('DOMContentLoaded', () => {
  initDrawer();
  initDrawerTabs();
});

// ─── Fetch seguro ─────────────────────────────────────────────────────────────
async function _fetchJsonDrawer(url, options = {}) {
  const res = await fetch(url, options);
  const ct = res.headers.get('content-type') || '';
  if (!ct.includes('application/json')) {
    const text = await res.text();
    if (text.includes('<html') || text.includes('<!DOCTYPE')) {
      throw new Error(`Sessão expirada ou erro do servidor (HTTP ${res.status})`);
    }
    throw new Error(`Resposta inesperada (HTTP ${res.status}, tipo: ${ct})`);
  }
  const data = await res.json();
  if (!res.ok) {
    const msg = data?.erro || data?.detail || data?.message || `Erro HTTP ${res.status}`;
    throw new Error(msg);
  }
  return data;
}

// ─── Erro amigável num painel ─────────────────────────────────────────────────
function _showPanelError(loadingId, msg) {
  const el = _$(loadingId);
  if (el) el.innerHTML = `<span style="color:var(--c-crit)"><i class="bi bi-exclamation-circle"></i> ${msg}</span>`;
}

// ─── Inicialização ────────────────────────────────────────────────────────────
function initDrawer() {
  _$('drawerOverlay')?.addEventListener('click', closeDrawer);
  _$('drawerClose')?.addEventListener('click', closeDrawer);
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeDrawer(); });

  _$('tecToggle')?.addEventListener('click', () => {
    const w = _$('tecWrap'); if (!w) return;
    const exp = w.classList.toggle('expanded');
    const tog = _$('tecToggle');
    if (tog) tog.textContent = exp ? 'Recolher' : 'Expandir';
  });

  _$('rawToggle')?.addEventListener('click', () => {
    const w = _$('rawWrap'); if (!w) return;
    const exp = w.classList.toggle('expanded');
    const tog = _$('rawToggle');
    if (tog) tog.textContent = exp ? 'Recolher' : 'Expandir';
  });

  _$('drawerInv')?.addEventListener('click', () => updateDrawerStatus('investigando'));
  _$('drawerOk')?.addEventListener('click',  () => updateDrawerStatus('resolvido'));
  _$('drawerFp')?.addEventListener('click',  () => updateDrawerStatus('falso'));
}

function initDrawerTabs() {
  _qa('.jg-drawer__tab').forEach(tab => tab.addEventListener('click', () => {
    _qa('.jg-drawer__tab').forEach(t => t.classList.remove('jg-drawer__tab--active'));
    tab.classList.add('jg-drawer__tab--active');

    const name = tab.dataset.tab;
    _qa('.jg-drawer__panel').forEach(p => p.classList.add('jg-drawer__panel--hidden'));

    const panelId = `panel${name.charAt(0).toUpperCase() + name.slice(1)}`;
    _$(panelId)?.classList.remove('jg-drawer__panel--hidden');

    if (name === 'correlacao' && !_drawer.corrLoaded) loadCorrelacao(_drawer.currentId);
    if (name === 'contexto'   && !_drawer.ctxLoaded)  loadContextoIp(_drawer.currentIp);
    if (name === 'timeline'   && !_drawer.tlLoaded)   loadTimeline(_drawer.currentIp);
  }));
}

// ─── Abrir Drawer ─────────────────────────────────────────────────────────────
function openDrawer(ev) {
  if (!ev) return;

  const u = _u();

  _drawer.currentId  = ev.id;
  _drawer.currentIp  = ev.srcIp;
  _drawer.currentEv  = ev;
  _drawer.corrLoaded = false;
  _drawer.ctxLoaded  = false;
  _drawer.tlLoaded   = false;

  // Reset tabs
  _qa('.jg-drawer__tab').forEach(t => t.classList.remove('jg-drawer__tab--active'));
  _qs('.jg-drawer__tab[data-tab="alerta"]')?.classList.add('jg-drawer__tab--active');
  _qa('.jg-drawer__panel').forEach(p => p.classList.add('jg-drawer__panel--hidden'));
  _$('panelAlerta')?.classList.remove('jg-drawer__panel--hidden');

  // Reset seções colapsáveis
  _$('tecWrap')?.classList.remove('expanded');
  const tecTog = _$('tecToggle');
  if (tecTog) tecTog.textContent = 'Expandir';
  _$('rawWrap')?.classList.remove('expanded');
  const rawTog = _$('rawToggle');
  if (rawTog) rawTog.textContent = 'Expandir';

  // Destaca linha na tabela
  _qa('.jg-table tr').forEach(r => r.classList.remove('row-selected'));
  _qs(`.jg-table tr[data-id="${CSS.escape(String(ev.id))}"]`)?.classList.add('row-selected');

  // Atalhos para utils
  const sev       = u.evSev?.(ev)   || 'baixo';
  const cat       = ev.categoria_jg || 'info';
  const titulo    = u.evTitulo?.(ev) || '—';
  const SEV_CLASS = u.SEV_CLASS  || {};
  const SEV_LABEL = u.SEV_LABEL  || {};
  const CAT_ICON  = u.CAT_ICON   || {};
  const CAT_LABEL = u.CAT_LABEL  || {};
  const esc         = u.esc         || (s => String(s ?? ''));
  const fmtDateTime = u.fmtDateTime || (iso => iso || '—');
  const evPort      = u.evPort      || (() => 0);
  const evProto     = u.evProto     || (() => '—');
  const PORT_NAMES  = u.PORT_NAMES  || {};
  const isDemo      = u.isDemo      || (id => !id || String(id).startsWith('demo-') || isNaN(parseInt(String(id))));

  // Badges no header
  const sevEl = _$('drawerSevBadge');
  if (sevEl) sevEl.outerHTML = `<span class="jg-badge jg-badge--${SEV_CLASS[sev] || 'dim'}" id="drawerSevBadge">${SEV_LABEL[sev] || sev.toUpperCase()}</span>`;

  const catBadgeEl = _$('drawerCatBadge');
  if (catBadgeEl) catBadgeEl.outerHTML = `<span class="jg-badge jg-badge--cat jg-badge--cat-${cat}" id="drawerCatBadge"><i class="bi ${CAT_ICON[cat] || 'bi-tag-fill'}"></i> ${esc(CAT_LABEL[cat] || cat)}</span>`;

  const drawerTime = _$('drawerTime');
  if (drawerTime) drawerTime.textContent = fmtDateTime(ev.timestamp);

  const drawerTitulo = _$('drawerTituloJg');
  if (drawerTitulo) drawerTitulo.textContent = titulo;

  // Janela do incidente
  const janelaEl = _$('drawerJanela');
  if (janelaEl) {
    if (ev.first_seen && ev.last_seen && ev.first_seen !== ev.last_seen) {
      janelaEl.textContent = `${fmtDateTime(ev.first_seen)} → ${fmtDateTime(ev.last_seen)}`;
      janelaEl.style.display = '';
    } else {
      janelaEl.style.display = 'none';
    }
  }

  // Ocorrências
  const ocEl = _$('drawerOcorrencias');
  if (ocEl) {
    const oc = ev.ocorrencias || ev.group_count || 1;
    if (oc > 1) {
      ocEl.textContent = `${oc} ocorrências`;
      ocEl.style.display = '';
    } else {
      ocEl.style.display = 'none';
    }
  }

  // Resumo
  const resumo   = ev.resumo_jg || '';
  const resumoEl = _$('drawerResumoJg');
  if (resumoEl) {
    resumoEl.textContent = resumo;
    resumoEl.style.display = resumo ? '' : 'none';
  }

  // Evidência
  const evidencia   = ev.evidencia || '';
  const evidenciaEl = _$('drawerEvidencia');
  if (evidenciaEl) {
    if (evidencia) {
      evidenciaEl.innerHTML = `<i class="bi bi-reception-4" style="margin-right:4px;color:var(--c-ok)"></i>${esc(evidencia)}`;
      evidenciaEl.style.display = '';
    } else {
      evidenciaEl.innerHTML = '';
      evidenciaEl.style.display = 'none';
    }
  }

  // Tags
  const tags     = ev.tags_jg || [];
  const tagsWrap = _$('drawerTagsWrap');
  if (tagsWrap) {
    if (tags.length) {
      const drawerTags = _$('drawerTags');
      if (drawerTags) drawerTags.innerHTML = tags.map(t => `<span class="jg-tag">${esc(t)}</span>`).join('');
      tagsWrap.style.display = '';
    } else {
      tagsWrap.style.display = 'none';
    }
  }

  // Recomendações
  const recom     = ev.recomendacoes || [];
  const recomWrap = _$('drawerRecomWrap');
  if (recomWrap) {
    if (recom.length) {
      const recomEl = _$('drawerRecomendacoes');
      if (recomEl) {
        recomEl.innerHTML = recom.map((r, i) => `
          <div class="jg-recom-item">
            <span class="jg-recom-num">${i + 1}</span>
            <span class="jg-recom-text">${esc(r)}</span>
          </div>`).join('');
      }
      recomWrap.style.display = '';
    } else {
      recomWrap.style.display = 'none';
    }
  }

  // Fluxo de rede
  const proto = evProto(ev);
  const port  = evPort(ev);

  const srcIpEl = _$('drawerSrcIp');
  if (srcIpEl) srcIpEl.textContent = ev.srcIp || '—';
  const dstIpEl = _$('drawerDstIp');
  if (dstIpEl) dstIpEl.textContent = ev.dstIp || '—';
  const protoEl = _$('drawerProto');
  if (protoEl) protoEl.textContent = proto;

  const srcMeta = _$('drawerSrcMeta');
  if (srcMeta) {
    if (ev.src_is_local) {
      srcMeta.innerHTML = '<span style="color:var(--c-ok);font-size:10px"><i class="bi bi-house-fill"></i> Rede local</span>';
    } else {
      const asn = ev.asn_org ? ` · ${esc(ev.asn_org)}` : '';
      srcMeta.innerHTML = `<span style="font-size:12px">${ev.country?.flag || '<span class="fi fi-br" style="width:20px;height:14px;border-radius:2px;display:inline-block;vertical-align:middle"></span>'}</span>
        <span style="font-size:10px;color:var(--text-dim)">${esc(ev.country?.name || '')}${asn}</span>`;
    }
  }

  const dstMeta = _$('drawerDstMeta');
  if (dstMeta) {
    dstMeta.textContent = port ? `Porta ${port} · ${PORT_NAMES[port] || proto}` : proto;
  }

  const dirEl = _$('drawerDirection');
  if (dirEl) {
    const dir = ev.direction;
    dirEl.innerHTML = (dir && dir !== 'unknown')
      ? `<span class="jg-dir jg-dir--${dir}">${dir.toUpperCase()}</span>`
      : '';
  }

  // GeoIP
  const geo = [
    { l: 'País',    v: ev.src_is_local ? 'Rede interna' : (ev.country?.name || '—') },
    { l: 'Cidade',  v: ev.cidade     || '—' },
    { l: 'ASN',     v: ev.asn_number || '—' },
    { l: 'Org',     v: ev.asn_org    || (ev.src_is_local ? 'LAN' : '—') },
    { l: 'rDNS',    v: ev.rdns       || '—' },
    { l: 'Direção', v: ev.direction  || '—' },
  ];
  const geoGrid = _$('drawerGeoGrid');
  if (geoGrid) {
    geoGrid.innerHTML = geo.map(g => `
      <div class="jg-info-item">
        <div class="jg-info-item__lbl">${g.l}</div>
        <div class="jg-info-item__val" style="font-size:11px">${esc(String(g.v ?? '—'))}</div>
      </div>`).join('');
  }

  // Técnico (Suricata)
  const tec        = ev.tecnico || {};
  const sigName    = _$('drawerSigName');
  if (sigName)    sigName.textContent    = tec.signature || ev.sig?.name   || '—';
  const sidEl2     = _$('drawerSid');
  if (sidEl2)     sidEl2.textContent     = tec.sid       || ev.sig?.sid    || '—';
  const catEl      = _$('drawerCat');
  if (catEl)      catEl.textContent      = tec.categoria || ev.sig?.cat    || '—';
  const acaoEl     = _$('drawerAcao');
  if (acaoEl)     acaoEl.textContent     = tec.acao      || ev.sig?.action || '—';
  const sevSurEl   = _$('drawerSevSuricata');
  if (sevSurEl)   sevSurEl.textContent   = tec.severidade|| ev.sig?.sev    || '—';

  // Raw JSON
  const rawEl = _$('drawerRaw');
  if (rawEl) {
    rawEl.textContent = ev.raw_json ? JSON.stringify(ev.raw_json, null, 2) : '(não disponível)';
  }

  // ── Links do footer ────────────────────────────────────────────────────────

  // Investigar IP → /incidentes/investigar/<ip>/
  const invLink = _$('drawerInvestigar');
  if (invLink && ev.srcIp) invLink.href = `/incidentes/investigar/${ev.srcIp}/`;

  // Detalhe → /incidentes/<id>/  (só para incidentes reais)
  const detLink = _$('drawerDetalhe');
  if (detLink) {
    if (ev.id && !isDemo(ev.id)) {
      detLink.href         = `/incidentes/${ev.id}/`;
      detLink.style.display = '';
    } else {
      detLink.style.display = 'none';
    }
  }

  // Abre drawer
  _$('drawerOverlay')?.classList.add('open');
  _$('drawer')?.classList.add('open');
}

// ─── Fechar Drawer ────────────────────────────────────────────────────────────
function closeDrawer() {
  _$('drawerOverlay')?.classList.remove('open');
  _$('drawer')?.classList.remove('open');
  _qa('.jg-table tr').forEach(r => r.classList.remove('row-selected'));
}

// ─── Sync status ──────────────────────────────────────────────────────────────
function syncStatus(id, status) {
  if (_drawer.currentEv && String(_drawer.currentEv.id) === String(id)) {
    _drawer.currentEv.status = status;
  }
}

// ─── Correlação ───────────────────────────────────────────────────────────────
async function loadCorrelacao(id) {
  const u       = _u();
  const isDemo  = u.isDemo  || (id => !id);
  const fmtTime = u.fmtTime || (iso => iso || '—');
  const esc     = u.esc     || (s => String(s ?? ''));

  if (isDemo(id)) {
    _$('corrLoading')?.remove();
    const cont = _$('corrContent');
    if (cont) cont.style.display = 'flex';
    ['corrDns', 'corrHttp', 'corrTls'].forEach(k => {
      const el = _$(k);
      if (el) el.innerHTML = '<p style="color:var(--text-dim);font-size:11px">Sem correlações (modo demo)</p>';
    });
    _drawer.corrLoaded = true;
    return;
  }

  try {
    const data = await _fetchJsonDrawer(`/incidentes/api/${id}/`);
    _$('corrLoading')?.remove();
    const cont = _$('corrContent');
    if (cont) cont.style.display = 'flex';

    _renderCorrList(_$('corrDns'), data.dns || [], ev => `
      <div class="jg-corr-item">
        <span class="jg-corr-time">${fmtTime(ev.timestamp)}</span>
        <span class="jg-corr-val">${esc(ev.query || '—')}</span>
        <span class="jg-corr-sub">${esc(ev.tipo || '')} ${esc(ev.rcode || '')}</span>
      </div>`);

    _renderCorrList(_$('corrHttp'), data.http || [], ev => `
      <div class="jg-corr-item">
        <span class="jg-corr-time">${fmtTime(ev.timestamp)}</span>
        <span class="jg-corr-val">${esc(ev.metodo || 'GET')} ${esc(ev.hostname || '')}${esc(ev.url || '')}</span>
        <span class="jg-corr-sub">HTTP ${ev.status_code || '?'}</span>
      </div>`);

    _renderCorrList(_$('corrTls'), data.tls || [], ev => `
      <div class="jg-corr-item">
        <span class="jg-corr-time">${fmtTime(ev.timestamp)}</span>
        <span class="jg-corr-val">${esc(ev.sni || '—')}</span>
        <span class="jg-corr-sub">${esc(ev.versao || '')}${ev.ja3 ? ' · JA3:' + ev.ja3.slice(0, 8) : ''}</span>
      </div>`);

    _drawer.corrLoaded = true;
  } catch (e) {
    _showPanelError('corrLoading', `Erro ao carregar correlações: ${e.message}`);
    console.error('loadCorrelacao:', e);
  }
}

function _renderCorrList(el, items, tplFn) {
  if (!el) return;
  el.innerHTML = items.length
    ? items.map(tplFn).join('')
    : '<p style="color:var(--text-dim);font-size:11px;padding:4px 0">Sem eventos nesta janela</p>';
}

// ─── Contexto IP ──────────────────────────────────────────────────────────────
async function loadContextoIp(ip) {
  if (!ip) return;
  const u         = _u();
  const esc       = u.esc       || (s => String(s ?? ''));
  const riskColor = u.riskColor || (() => '#94a3b8');
  const riskLabel = u.riskLabel || (() => '—');

  try {
    const data = await _fetchJsonDrawer(`/incidentes/api/ip/${ip}/contexto/?horas=24`);
    _$('ctxLoading')?.remove();
    const cont = _$('ctxContent');
    if (cont) cont.style.display = 'flex';

    if (!data.ok) {
      if (cont) cont.innerHTML = `<p style="color:var(--c-crit)">Erro: ${esc(data.erro || 'Brasil')}</p>`;
      return;
    }

    const ctx  = data.contexto || {};
    const risk = ctx.risk_score || {};
    const pct  = Math.min(100, risk.score || 0);

    const riskBar = _$('ctxRiskBar');
    if (riskBar) {
      riskBar.style.width      = pct + '%';
      riskBar.style.background = riskColor(risk.score || 0);
    }

    const riskVal = _$('ctxRiskVal');
    if (riskVal) riskVal.innerHTML = `<span style="color:${riskColor(risk.score || 0)};font-weight:700;font-size:16px">${(risk.score || 0).toFixed(1)}</span>`;

    const riskLbl = _$('ctxRiskLabel');
    if (riskLbl) riskLbl.innerHTML = `<span style="font-family:var(--font-mono);font-size:10px;color:var(--text-dim)">${riskLabel(risk.score || 0)}</span>`;

    const riskBreakdown = _$('ctxRiskBreakdown');
    if (riskBreakdown) {
      riskBreakdown.innerHTML = `
        <div class="jg-risk-row"><span>Críticos</span><span style="color:var(--c-crit)">${risk.criticos || 0}</span></div>
        <div class="jg-risk-row"><span>Altos</span><span style="color:var(--c-high)">${risk.altos || 0}</span></div>
        <div class="jg-risk-row"><span>Médios</span><span style="color:var(--c-med)">${risk.medios || 0}</span></div>
        <div class="jg-risk-row"><span>Total alertas</span><span>${risk.total_alertas || 0}</span></div>`;
    }

    const sids      = ctx.top_sids     || [];
    const ctxTopSids = _$('ctxTopSids');
    if (ctxTopSids) {
      ctxTopSids.innerHTML = sids.length
        ? sids.slice(0, 6).map(s => `
            <div class="jg-corr-item">
              <span class="jg-corr-val">${esc(s.signature || s.sid)}</span>
              <span class="jg-corr-sub">SID ${esc(String(s.sid))} · ${s.total}×</span>
            </div>`).join('')
        : '<p style="color:var(--text-dim);font-size:11px">Sem alertas</p>';
    }

    const doms       = ctx.top_dominios || [];
    const ctxTopDoms = _$('ctxTopDoms');
    if (ctxTopDoms) {
      ctxTopDoms.innerHTML = doms.length
        ? doms.slice(0, 6).map(d => `
            <div class="jg-corr-item">
              <span class="jg-corr-val">${esc(d.query)}</span>
              <span class="jg-corr-sub">${d.total}×</span>
            </div>`).join('')
        : '<p style="color:var(--text-dim);font-size:11px">Sem consultas DNS</p>';
    }

    const ctxCounts = _$('ctxCounts');
    if (ctxCounts) {
      ctxCounts.innerHTML = `
        <div class="jg-count-item"><span class="jg-count-val">${ctx.total_alertas || 0}</span><span class="jg-count-lbl">Alertas</span></div>
        <div class="jg-count-item"><span class="jg-count-val">${ctx.total_dns    || 0}</span><span class="jg-count-lbl">DNS</span></div>
        <div class="jg-count-item"><span class="jg-count-val">${ctx.total_http   || 0}</span><span class="jg-count-lbl">HTTP</span></div>
        <div class="jg-count-item"><span class="jg-count-val">${ctx.total_tls    || 0}</span><span class="jg-count-lbl">TLS</span></div>`;
    }

    _drawer.ctxLoaded = true;
  } catch (e) {
    _showPanelError('ctxLoading', `Erro ao carregar contexto: ${e.message}`);
    console.error('loadContextoIp:', e);
  }
}

// ─── Timeline ─────────────────────────────────────────────────────────────────
async function loadTimeline(ip) {
  if (!ip) return;
  const u       = _u();
  const fmtTime = u.fmtTime || (iso => iso || '—');
  const esc     = u.esc     || (s => String(s ?? ''));
  const ICON    = {
    alert: 'bi-exclamation-triangle-fill',
    dns:   'bi-globe2',
    http:  'bi-arrow-left-right',
    tls:   'bi-lock-fill',
  };

  try {
    const data = await _fetchJsonDrawer(`/incidentes/api/ip/${ip}/timeline/?horas=2`);
    _$('tlLoading')?.remove();
    const el = _$('tlContent'); if (!el) return;
    el.style.display = 'block';

    const evs = (data.eventos || []).slice(0, 30);
    if (!evs.length) {
      el.innerHTML = '<p style="color:var(--text-dim);font-size:11px">Sem eventos nas últimas 2h</p>';
      _drawer.tlLoaded = true;
      return;
    }

    el.innerHTML = evs.map(ev => `
      <div class="jg-tl-item jg-tl-item--${esc(ev.tipo || 'alert')}">
        <div class="jg-tl-dot"><i class="bi ${ICON[ev.tipo] || 'bi-dot'}"></i></div>
        <div style="min-width:0;flex:1">
          <div class="jg-tl-title">${esc(ev.titulo || '—')}</div>
          <div class="jg-tl-meta">${fmtTime(ev.timestamp)} · ${esc((ev.tipo || 'alert').toUpperCase())}</div>
        </div>
      </div>`).join('');

    _drawer.tlLoaded = true;
  } catch (e) {
    _showPanelError('tlLoading', `Erro ao carregar timeline: ${e.message}`);
    console.error('loadTimeline:', e);
  }
}

// ─── Atualizar status via drawer ──────────────────────────────────────────────
async function updateDrawerStatus(status) {
  const u       = _u();
  const isDemo  = u.isDemo   || (id => !id);
  const toast   = u.toast    || (() => { });
  const getCsrf = u.getCsrf  || (() => '');
  const id      = _drawer.currentId;

  if (isDemo(id)) {
    window.JGIncidentes.aplicarStatusLocal?.(id, status);
    window.JGIncidentes.renderTable?.();
    toast(`Status → ${status} (demo)`);
    return;
  }

  try {
    const data = await _fetchJsonDrawer(`/incidentes/api/${id}/status/`, {
      method:  'PATCH',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrf() },
      body:    JSON.stringify({ status }),
    });
    if (data.ok) {
      window.JGIncidentes.aplicarStatusLocal?.(id, status);
      window.JGIncidentes.renderTable?.();
      toast(`Status → ${status}`);
    }
  } catch (e) {
    toast(`⚠ Erro ao atualizar status: ${e.message}`, 4000);
    console.error('updateDrawerStatus:', e);
  }
}