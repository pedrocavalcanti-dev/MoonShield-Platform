/**
 * MOONSHIELD — firewall/regras.js  v5
 * v5: todos os alert/confirm/prompt nativos substituídos por modais JS
 */

document.addEventListener('DOMContentLoaded', () => {

  const $ = id => document.getElementById(id);

  function getCsrf() {
    return document.cookie.split(';').find(c => c.trim().startsWith('csrftoken='))?.split('=')[1] || '';
  }
  function getCsrfHeader() {
    return { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrf() };
  }

  /* ══ ESTADO ══ */
  let RULES = [], BLOCKLIST = [], ALLOWLIST = [], GEOBLOCK = [], NAT = [];
  let INTERFACES = [];
  let editingRuleId = null;
  let editingNatId = null;
  let filterAction = 'all';
  let filterIface = 'all';
  let searchRegras = '';
  let syncTimer = null;

  /* ══ ESTADO: BLOCK DETAIL MODAL ══ */
  let blockDetailIp = null;
  let blockDetailEntry = null;

  /* ══ TOAST ══ */
  let toastTimer;
  function showToast(msg, type = 'ok') {
    const t = $('fwrToast'); if (!t) return;
    t.innerHTML = msg;
    t.className = `fwr-toast fwr-toast--${type} show`;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove('show'), 3500);
  }

  function showApplyToast(agente_ok) {
    if (agente_ok) {
      showToast('<i class="bi bi-lightning-charge-fill" style="margin-right:5px"></i>Aplicado no Linux agora', 'ok');
    } else {
      showToast('<i class="bi bi-hourglass-split" style="margin-right:5px"></i>Salvo — aguardando sync (até 30s)', 'warn');
    }
  }

  /* ══ BOTÃO PUSH ══ */
  function setPushBtnState(state) {
    const btn = $('fwrPushBtn'); if (!btn) return;
    if (state === 'loading') {
      btn.innerHTML = '<i class="bi bi-hourglass-split"></i> Aplicando…';
      btn.disabled = true;
      btn.className = 'fwr-btn fwr-btn--orange';
    } else if (state === 'ok') {
      btn.innerHTML = '<i class="bi bi-lightning-charge-fill"></i> Aplicar no Linux';
      btn.disabled = false;
      btn.className = 'fwr-btn fwr-btn--orange';
    } else if (state === 'offline') {
      btn.innerHTML = '<i class="bi bi-lightning-charge-fill"></i> Aplicar no Linux';
      btn.disabled = false;
      btn.className = 'fwr-btn fwr-btn--orange';
      btn.title = 'Agente offline — será aplicado no próximo poll (30s)';
    }
  }

  /* ══ API ══ */
  async function apiFetch(url, method = 'GET', body = null) {
    const opts = { method, headers: getCsrfHeader() };
    if (body) opts.body = JSON.stringify(body);
    const r = await fetch(url, opts);
    return r.json();
  }

  /* ══════════════════════════════════════════════════════════
     SISTEMA DE MODAIS GENÉRICOS
     Substitui todos os alert / confirm / prompt nativos
  ══════════════════════════════════════════════════════════ */

  // Injeta o HTML dos modais uma única vez
  function _injectModalHtml() {
    if ($('msModalOverlay')) return;
    document.body.insertAdjacentHTML('beforeend', `
      <div id="msModalOverlay" style="
        display:none;position:fixed;inset:0;z-index:9999;
        background:rgba(0,0,0,.55);backdrop-filter:blur(3px);
        align-items:center;justify-content:center;
      ">
        <div id="msModalBox" style="
          background:var(--bg-card,#1a1f2e);border:1px solid var(--border,#2a2f3e);
          border-radius:10px;padding:28px 28px 22px;width:100%;max-width:420px;
          box-shadow:0 24px 60px rgba(0,0,0,.5);position:relative;
          animation:msModalIn .15s ease;
        ">
          <div style="display:flex;align-items:flex-start;gap:14px;margin-bottom:18px">
            <div id="msModalIcon" style="font-size:22px;flex-shrink:0;margin-top:1px"></div>
            <div style="flex:1">
              <p id="msModalTitle" style="font-size:14px;font-weight:700;color:var(--text,#e2e8f0);margin-bottom:5px"></p>
              <p id="msModalMsg" style="font-size:12px;color:var(--text-muted,#94a3b8);line-height:1.6"></p>
            </div>
          </div>

          <!-- campos de input (para prompt) -->
          <div id="msModalFields" style="margin-bottom:16px"></div>

          <div id="msModalBtns" style="display:flex;justify-content:flex-end;gap:8px"></div>
        </div>
      </div>
      <style>
        @keyframes msModalIn{from{opacity:0;transform:scale(.96) translateY(6px)}to{opacity:1;transform:none}}
        .ms-modal-input{
          width:100%;box-sizing:border-box;
          background:var(--bg-hover,#252b3b);
          border:1px solid var(--border,#2a2f3e);
          border-radius:6px;padding:8px 10px;
          color:var(--text,#e2e8f0);font-size:13px;
          margin-bottom:10px;outline:none;
          transition:border-color .15s;
        }
        .ms-modal-input:focus{border-color:#3b82f6}
        .ms-modal-input:last-child{margin-bottom:0}
        .ms-modal-label{
          font-size:11px;color:var(--text-dim,#64748b);
          margin-bottom:4px;display:block;font-weight:500;
        }
        .ms-modal-btn{
          padding:7px 16px;border-radius:6px;font-size:12px;
          font-weight:600;cursor:pointer;border:none;
          transition:opacity .15s,transform .1s;
        }
        .ms-modal-btn:hover{opacity:.85;transform:translateY(-1px)}
        .ms-modal-btn--cancel{background:var(--bg-hover,#252b3b);color:var(--text-muted,#94a3b8);border:1px solid var(--border,#2a2f3e)}
        .ms-modal-btn--confirm{background:#3b82f6;color:#fff}
        .ms-modal-btn--danger{background:#ef4444;color:#fff}
        .ms-modal-btn--ok{background:#22c55e;color:#fff}
      </style>
    `);

    // Fecha clicando fora
    $('msModalOverlay').addEventListener('click', e => {
      if (e.target === $('msModalOverlay')) _closeModal(null);
    });
  }

  let _modalResolve = null;

  function _closeModal(value) {
    const ov = $('msModalOverlay');
    if (ov) ov.style.display = 'none';
    if (_modalResolve) { _modalResolve(value); _modalResolve = null; }
  }

  function _openModal({ icon = '', title = '', msg = '', fields = [], buttons = [] }) {
    _injectModalHtml();
    $('msModalIcon').innerHTML = icon;
    $('msModalTitle').textContent = title;
    $('msModalMsg').innerHTML = msg;

    // Campos de input
    const fieldsDiv = $('msModalFields');
    fieldsDiv.innerHTML = '';
    fieldsDiv.style.display = fields.length ? 'block' : 'none';
    fields.forEach(f => {
      if (f.label) {
        const lbl = document.createElement('label');
        lbl.className = 'ms-modal-label';
        lbl.textContent = f.label;
        fieldsDiv.appendChild(lbl);
      }
      const inp = document.createElement('input');
      inp.className = 'ms-modal-input';
      inp.type = f.type || 'text';
      inp.placeholder = f.placeholder || '';
      inp.id = f.id || `msField_${Math.random()}`;
      if (f.value) inp.value = f.value;
      fieldsDiv.appendChild(inp);
    });

    // Botões
    const btnsDiv = $('msModalBtns');
    btnsDiv.innerHTML = '';
    buttons.forEach(b => {
      const btn = document.createElement('button');
      btn.className = `ms-modal-btn ms-modal-btn--${b.style || 'confirm'}`;
      btn.innerHTML = b.label;
      btn.addEventListener('click', () => {
        if (b.collect) {
          // Coleta valores dos inputs
          const vals = {};
          fields.forEach(f => { vals[f.id] = $(f.id)?.value?.trim() || ''; });
          _closeModal(b.collect(vals));
        } else {
          _closeModal(b.value !== undefined ? b.value : null);
        }
      });
      btnsDiv.appendChild(btn);
    });

    $('msModalOverlay').style.display = 'flex';

    return new Promise(res => { _modalResolve = res; });
  }

  /* ── confirm genérico ── */
  function msConfirm({ icon = '<i class="bi bi-exclamation-triangle-fill" style="color:#f97316"></i>', title, msg, confirmLabel = 'Confirmar', confirmStyle = 'danger' } = {}) {
    return _openModal({
      icon, title, msg,
      buttons: [
        { label: 'Cancelar', style: 'cancel', value: false },
        { label: confirmLabel, style: confirmStyle, value: true },
      ],
    });
  }

  /* ── prompt duplo: IP + motivo ── */
  function msPromptIpMotivo({ title, iconColor = '#ef4444', ipLabel = 'IP ou subnet', ipPlaceholder = 'ex: 1.2.3.4 ou 10.0.0.0/24', motivoLabel = 'Motivo (opcional)', motivoPlaceholder = '' } = {}) {
    return _openModal({
      icon: `<i class="bi bi-slash-circle" style="color:${iconColor}"></i>`,
      title,
      msg: '',
      fields: [
        { id: 'msIpField', label: ipLabel, placeholder: ipPlaceholder },
        { id: 'msMotivField', label: motivoLabel, placeholder: motivoPlaceholder },
      ],
      buttons: [
        { label: 'Cancelar', style: 'cancel', value: null },
        {
          label: 'Confirmar', style: 'danger',
          collect: vals => vals,
        },
      ],
    });
  }

  /* ── prompt simples: IP + motivo para allowlist ── */
  function msPromptAllow() {
    return _openModal({
      icon: '<i class="bi bi-check2-circle" style="color:#22c55e"></i>',
      title: 'Liberar IP / Domínio',
      msg: '',
      fields: [
        { id: 'msIpField', label: 'IP, subnet ou domínio', placeholder: 'ex: 8.8.8.8 ou partner.com' },
        { id: 'msMotivField', label: 'Motivo (opcional)', placeholder: 'ex: Parceiro confiável' },
      ],
      buttons: [
        { label: 'Cancelar', style: 'cancel', value: null },
        { label: '<i class="bi bi-plus-circle"></i> Liberar', style: 'ok', collect: vals => vals },
      ],
    });
  }

  /* ══ LOAD ══ */
  async function loadAll() {
    try {
      const d = await apiFetch('/firewall/api/data/');
      if (!d.ok) return;
      RULES = d.rules || [];
      BLOCKLIST = d.blocklist || [];
      ALLOWLIST = d.allowlist || [];
      GEOBLOCK = d.geoblock || [];
      NAT = d.nat || [];

      const badge = $('fwrModeBadge');
      if (badge) {
        badge.style.display = 'inline-block';
        badge.textContent = (d.mode || 'demo').toUpperCase();
        badge.style.cssText = d.mode === 'prod'
          ? 'display:inline-block;font-family:var(--font-mono);font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;background:rgba(59,130,246,.18);color:#3b82f6;border:1px solid rgba(59,130,246,.3)'
          : 'display:inline-block;font-family:var(--font-mono);font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;background:rgba(234,179,8,.18);color:#eab308;border:1px solid rgba(234,179,8,.3)';
      }
      if (d.sync) renderSyncBar(d.sync);
      renderAll();
    } catch (e) { console.error('[regras]', e); }
  }

  async function loadInterfaces() {
    try {
      const d = await apiFetch('/firewall/api/interfaces/');
      if (!d.ok || !d.interfaces) return;
      INTERFACES = d.interfaces;
      populateIfaceSelects();
      const status = $('fwrIfaceStatus');
      if (status && INTERFACES.length)
        status.textContent = `Interfaces detectadas: ${INTERFACES.map(i => `${i.nome} (${i.ip || '—'})`).join(' · ')}`;
    } catch (e) { console.warn('[regras] interfaces:', e); }
  }

  function populateIfaceSelects() {
    [$('qbIface'), $('fwrFilterIface')].forEach(sel => {
      if (!sel) return;
      const cur = sel.value, first = sel.options[0];
      sel.innerHTML = ''; sel.appendChild(first);
      (INTERFACES.length ? INTERFACES : [{ nome: 'WAN' }, { nome: 'LAN' }, { nome: 'VPN' }]).forEach(i => {
        const o = document.createElement('option');
        o.value = i.nome; o.textContent = i.ip ? `${i.nome}  (${i.ip})` : i.nome;
        sel.appendChild(o);
      });
      if (cur) sel.value = cur;
    });
    const rfIface = $('rfIface');
    if (rfIface) {
      const cur = rfIface.value; rfIface.innerHTML = '';
      (INTERFACES.length ? INTERFACES : [{ nome: 'WAN' }, { nome: 'LAN' }, { nome: 'VPN' }]).forEach(i => {
        const o = document.createElement('option');
        o.value = i.nome; o.textContent = i.ip ? `${i.nome}  (${i.ip})` : i.nome;
        rfIface.appendChild(o);
      });
      const any = document.createElement('option'); any.value = 'any'; any.textContent = 'Qualquer (any)';
      rfIface.appendChild(any);
      if (cur) rfIface.value = cur;
    }
  }

  /* ══ SYNC BAR ══ */
  function renderSyncBar(sync) {
    const bar = $('fwrSyncBar'); if (!bar) return;
    if (!sync || sync.pendentes === 0) {
      bar.classList.remove('visible');
      clearInterval(syncTimer);
      return;
    }
    bar.classList.add('visible');
    $('fwrSyncMsg').innerHTML =
      `<i class="bi bi-hourglass-split"></i> ${sync.pendentes} regra(s) pendente(s) de ${sync.total} — aguardando sincronização com o sensor Linux.`;
    clearInterval(syncTimer);
    let countdown = 30;
    syncTimer = setInterval(() => {
      countdown--;
      const msg = $('fwrSyncMsg');
      if (msg && countdown > 0)
        msg.innerHTML = `<i class="bi bi-hourglass-split"></i> ${sync.pendentes} regra(s) pendente(s) de ${sync.total} — próximo poll em ${countdown}s`;
      if (countdown <= 0) { clearInterval(syncTimer); loadAll(); }
    }, 1000);
  }

  function _currentSync() {
    return {
      pendentes: RULES.filter(r => r.pendente).length,
      total: RULES.length,
      aplicadas: RULES.filter(r => r.sincronizada).length,
    };
  }

  /* ══ RENDER ══ */
  function renderAll() { renderRules(); renderBlocklist(); renderAllowlist(); renderGeoblock(); renderNat(); updateCounts(); }

  function updateCounts() {
    $('tabCountRegras').textContent = RULES.filter(r => !r.deletado).length;
    $('tabCountBloqueados').textContent = BLOCKLIST.length;
    $('tabCountLiberados').textContent = ALLOWLIST.length;
    $('tabCountGeoblock').textContent = GEOBLOCK.length;
    $('tabCountNat').textContent = NAT.length;
  }

  /* ══ PREVIEW NFT ══ */
  function buildNftPreview() {
    const action = $('rfAction')?.value, iface = $('rfIface')?.value;
    const dir = $('rfDir')?.value, proto = $('rfProto')?.value;
    const src = $('rfSrc')?.value.trim() || 'any', dst = $('rfDst')?.value.trim() || 'any';
    const port = $('rfPort')?.value.trim() || 'any';
    const parts = [];
    if (iface && iface !== 'any') parts.push(`${dir === 'in' ? 'iifname' : 'oifname'} "${iface}"`);
    if (src && src !== 'any') parts.push(`ip saddr ${src}`);
    if (dst && dst !== 'any') parts.push(`ip daddr ${dst}`);
    if (proto && proto !== 'any') parts.push(proto.toLowerCase());
    if (port && port !== 'any' && (proto === 'TCP' || proto === 'UDP')) parts.push(`dport ${port}`);
    parts.push(action === 'allow' ? 'accept' : 'drop');
    const c = $('fwrNftPreviewCode'); if (c) c.textContent = parts.join(' ') || '—';
  }
  ['rfAction', 'rfIface', 'rfDir', 'rfProto', 'rfSrc', 'rfDst', 'rfPort'].forEach(id => {
    $(id)?.addEventListener('input', buildNftPreview);
    $(id)?.addEventListener('change', buildNftPreview);
  });

  /* ══ PREVIEW QB ══ */
  function updateQbPreview() {
    const ip = $('qbIp')?.value.trim(), iface = $('qbIface')?.value;
    const port = $('qbPort')?.value.trim(), proto = $('qbProto')?.value;
    const prev = $('qbPreview'); if (!prev) return;
    if (!ip) { prev.style.display = 'none'; return; }
    const parts = [];
    if (iface) parts.push(`iifname "${iface}"`);
    parts.push(`ip saddr ${ip}`);
    if (proto) parts.push(proto.toLowerCase());
    if (port) parts.push(`dport ${port}`);
    parts.push('drop');
    prev.style.display = 'block';
    prev.innerHTML = `<i class="bi bi-terminal" style="opacity:.5"></i> <code>${parts.join(' ')}</code>`;
  }
  $('qbIp')?.addEventListener('input', updateQbPreview);
  $('qbIface')?.addEventListener('change', updateQbPreview);
  $('qbPort')?.addEventListener('input', updateQbPreview);
  $('qbProto')?.addEventListener('change', updateQbPreview);

  /* ══ REGRAS ══ */
  function filteredRules() {
    return RULES.filter(r => {
      if (r.deletado) return false;
      if (filterAction !== 'all' && r.action !== filterAction) return false;
      if (filterIface !== 'all' && r.iface !== filterIface) return false;
      if (searchRegras) {
        const q = searchRegras.toLowerCase();
        if (!r.desc?.toLowerCase().includes(q) && !r.src?.includes(q) && !r.dst?.includes(q) && !String(r.port).includes(q)) return false;
      }
      return true;
    }).sort((a, b) => a.priority - b.priority);
  }

  function syncBadge(r) {
    if (r.pendente) return `<span class="fwr-sync-icon fwr-sync-icon--pending" title="Pendente — aguardando sync"><i class="bi bi-hourglass-split"></i></span>`;
    if (r.sincronizada) return `<span class="fwr-sync-icon fwr-sync-icon--ok" title="Aplicada no Linux"><i class="bi bi-check-circle-fill"></i></span>`;
    return `<span class="fwr-sync-icon" style="color:var(--text-dim)">—</span>`;
  }

  function buildNftInline(r) {
    const parts = [];
    if (r.iface && r.iface !== 'any') parts.push(`${r.dir === 'in' ? 'iifname' : 'oifname'} "${r.iface}"`);
    if (r.src && r.src !== 'any') parts.push(`saddr ${r.src}`);
    if (r.dst && r.dst !== 'any') parts.push(`daddr ${r.dst}`);
    if (r.proto && r.proto !== 'any') parts.push(r.proto.toLowerCase());
    if (r.port && r.port !== 'any') parts.push(`dport ${r.port}`);
    parts.push(r.action === 'allow' ? 'accept' : 'drop');
    return parts.join(' ');
  }

  function truncate(str, n) { return str?.length > n ? str.slice(0, n) + '…' : (str || '—'); }

  function renderRules() {
    const body = $('fwrRulesBody'); if (!body) return;
    const rows = filteredRules();
    if (!rows.length) {
      body.innerHTML = `<tr><td colspan="12"><div class="fwr-empty">
        <i class="bi bi-list-check" style="font-size:24px;opacity:.3"></i>
        <span>Nenhuma regra encontrada</span>
        <button class="fwr-btn fwr-btn--primary" onclick="document.getElementById('fwrNewRuleBtn').click()" style="margin-top:8px">
          <i class="bi bi-plus-circle"></i> Criar primeira regra
        </button>
      </div></td></tr>`;
      return;
    }
    body.innerHTML = rows.map((r, i) => `
      <tr style="animation:fwrRowIn .18s ${i * 12}ms both;opacity:${r.enabled ? 1 : .4}">
        <td style="font-family:var(--font-mono);font-size:12px">${r.priority}</td>
        <td><span class="fwr-action-badge fwr-action-badge--${r.action}">${r.action.toUpperCase()}</span></td>
        <td><span class="fwr-iface-badge">${r.iface}</span></td>
        <td style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted)">${r.proto}</td>
        <td style="font-family:var(--font-mono);font-size:11px" title="${r.src}">${truncate(r.src, 16)}</td>
        <td style="font-family:var(--font-mono);font-size:11px" title="${r.dst}">${truncate(r.dst, 16)}</td>
        <td style="font-family:var(--font-mono);font-size:11px">${r.port}</td>
        <td style="color:var(--text-muted);font-size:11px;max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${r.desc}">${r.desc || '—'}</td>
        <td style="max-width:150px;overflow:hidden">
          <code class="fwr-nft-inline" title="${buildNftInline(r)}">${truncate(buildNftInline(r), 20)}</code>
        </td>
        <td style="text-align:center">${syncBadge(r)}</td>
        <td>
          <label class="fwr-toggle" title="${r.enabled ? 'Desativar' : 'Ativar'}">
            <input type="checkbox" ${r.enabled ? 'checked' : ''} data-rid="${r.id}" class="rule-toggle"/>
            <span class="fwr-toggle-slider"></span>
          </label>
        </td>
        <td>
          <div class="fwr-row-actions">
            <button class="fwr-row-btn" data-rid="${r.id}" data-act="edit" title="Editar"><i class="bi bi-pencil"></i></button>
            <button class="fwr-row-btn" data-rid="${r.id}" data-act="dup"  title="Duplicar"><i class="bi bi-copy"></i></button>
            <button class="fwr-row-btn fwr-row-btn--danger" data-rid="${r.id}" data-act="del" title="Remover"><i class="bi bi-trash3"></i></button>
          </div>
        </td>
      </tr>`).join('');

    body.querySelectorAll('[data-act]').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        const id = +btn.dataset.rid, act = btn.dataset.act;
        if (act === 'edit') openRuleDrawer(id);
        if (act === 'dup') dupRule(id);
        if (act === 'del') deleteRule(id);
      });
    });
    body.querySelectorAll('.rule-toggle').forEach(chk => {
      chk.addEventListener('change', () => {
        const r = RULES.find(x => x.id === +chk.dataset.rid);
        if (r) { r.enabled = chk.checked; patchRule(r); }
      });
    });
  }

  /* ══ CRUD REGRAS ══ */
  function openRuleDrawer(id) {
    const r = id ? RULES.find(x => x.id === id) : null;
    editingRuleId = id || null;
    $('fwrRuleDrawerTitle').textContent = r ? 'Editar Regra' : 'Nova Regra';
    $('fwrRuleDrawerDup').style.display = r ? 'flex' : 'none';
    if (r) {
      $('rfDesc').value = r.desc || ''; $('rfAction').value = r.action || 'deny';
      $('rfIface').value = r.iface || 'any'; $('rfDir').value = r.dir || 'in';
      $('rfProto').value = r.proto || 'TCP'; $('rfSrc').value = r.src || 'any';
      $('rfDst').value = r.dst || 'any'; $('rfPort').value = r.port || 'any';
      $('rfPriority').value = r.priority || 100;
    } else { $('fwrRuleForm').reset(); }
    buildNftPreview();
    $('fwrRuleDrawer').classList.add('open');
    $('fwrRuleDrawerOverlay').classList.add('open');
    setTimeout(() => $('rfDesc')?.focus(), 200);
  }

  function closeRuleDrawer() {
    $('fwrRuleDrawer').classList.remove('open');
    $('fwrRuleDrawerOverlay').classList.remove('open');
    editingRuleId = null;
  }

  async function saveRule() {
    const saveBtn = $('fwrRuleSaveBtn');
    saveBtn.disabled = true;
    saveBtn.innerHTML = '<i class="bi bi-hourglass-split"></i> Salvando…';
    const payload = {
      desc: $('rfDesc').value.trim() || 'Sem descrição',
      action: $('rfAction').value,
      iface: $('rfIface').value,
      dir: $('rfDir').value,
      proto: $('rfProto').value,
      src: $('rfSrc').value.trim() || 'any',
      dst: $('rfDst').value.trim() || 'any',
      port: $('rfPort').value.trim() || 'any',
      priority: parseInt($('rfPriority').value) || 500,
    };
    try {
      if (editingRuleId) {
        const d = await apiFetch(`/firewall/api/rules/${editingRuleId}/`, 'PUT', payload);
        if (d.ok) {
          const idx = RULES.findIndex(r => r.id === editingRuleId);
          if (idx !== -1) RULES[idx] = d.rule;
          showApplyToast(d.agente_ok);
        } else {
          showToast(`<i class="bi bi-x-circle" style="margin-right:5px"></i>${d.erro || 'Erro ao salvar'}`, 'err');
        }
      } else {
        const d = await apiFetch('/firewall/api/rules/', 'POST', payload);
        if (d.ok) {
          RULES.push(d.rule);
          showApplyToast(d.agente_ok);
        } else {
          showToast(`<i class="bi bi-x-circle" style="margin-right:5px"></i>${d.erro || 'Erro ao salvar'}`, 'err');
        }
      }
      closeRuleDrawer();
      renderRules();
      updateCounts();
      renderSyncBar(_currentSync());
    } finally {
      saveBtn.disabled = false;
      saveBtn.innerHTML = '<i class="bi bi-floppy"></i> Salvar Regra';
    }
  }

  async function patchRule(r) {
    const d = await apiFetch(`/firewall/api/rules/${r.id}/`, 'PATCH', { enabled: r.enabled });
    if (d.ok) {
      if (d.rule) { const idx = RULES.findIndex(x => x.id === r.id); if (idx !== -1) RULES[idx] = d.rule; }
      else { r.pendente = true; r.sincronizada = false; }
      const label = r.enabled ? 'ativada' : 'desativada';
      if (d.agente_ok) {
        showToast(`<i class="bi bi-lightning-charge-fill" style="margin-right:5px"></i>Regra ${label} e aplicada no Linux`, 'ok');
      } else {
        showToast(`<i class="bi bi-hourglass-split" style="margin-right:5px"></i>Regra ${label} — aguardando sync`, 'warn');
      }
      renderRules();
      renderSyncBar(_currentSync());
    }
  }

  async function dupRule(id) {
    const r = RULES.find(x => x.id === id); if (!r) return;
    const d = await apiFetch('/firewall/api/rules/', 'POST', { ...r, id: undefined, desc: `${r.desc} (cópia)`, priority: r.priority + 1 });
    if (d.ok) {
      RULES.push(d.rule);
      renderRules();
      updateCounts();
      showApplyToast(d.agente_ok);
    }
  }

  async function deleteRule(id) {
    const r = RULES.find(x => x.id === id);
    const confirmed = await msConfirm({
      icon: '<i class="bi bi-trash3-fill" style="color:#ef4444"></i>',
      title: 'Remover regra',
      msg: `Tem certeza que deseja remover a regra <strong>${r?.desc || `#${id}`}</strong>? Esta ação não pode ser desfeita.`,
      confirmLabel: '<i class="bi bi-trash3"></i> Remover',
      confirmStyle: 'danger',
    });
    if (!confirmed) return;

    const d = await apiFetch(`/firewall/api/rules/${id}/`, 'DELETE');
    if (d.ok) {
      if (r) r.deletado = true;
      renderRules();
      updateCounts();
      if (d.agente_ok) {
        showToast('<i class="bi bi-trash3" style="margin-right:5px"></i>Regra removida do Linux', 'ok');
      } else {
        showToast('<i class="bi bi-hourglass-split" style="margin-right:5px"></i>Regra removida — aguardando sync', 'warn');
      }
      renderSyncBar(_currentSync());
    }
  }

  $('fwrNewRuleBtn')?.addEventListener('click', () => openRuleDrawer(null));
  $('fwrRuleSaveBtn')?.addEventListener('click', saveRule);
  $('fwrRuleDrawerCancel')?.addEventListener('click', closeRuleDrawer);
  $('fwrRuleDrawerClose')?.addEventListener('click', closeRuleDrawer);
  $('fwrRuleDrawerOverlay')?.addEventListener('click', closeRuleDrawer);
  $('fwrRuleDrawerDup')?.addEventListener('click', () => { if (editingRuleId) { dupRule(editingRuleId); closeRuleDrawer(); } });

  /* ══ BLOCKLIST ══ */
  function renderBlocklist() {
    const body = $('fwrBlockBody'); if (!body) return;
    const q = $('fwrSearchBlock')?.value.toLowerCase() || '';
    const rows = BLOCKLIST.filter(b => !q || b.ip?.includes(q) || b.reason?.toLowerCase().includes(q));
    if (!rows.length) {
      body.innerHTML = `<tr><td colspan="6"><div class="fwr-empty"><i class="bi bi-slash-circle" style="font-size:24px;opacity:.3"></i><span>${q ? 'Nenhum resultado' : 'Nenhum IP bloqueado'}</span></div></td></tr>`;
      return;
    }
    const sbadge = s => { const m = { Auto: 'orange', SOC: 'blue', Manual: 'gray' }; return `<span class="fwr-source-badge fwr-source-badge--${m[s] || 'gray'}">${s || 'Manual'}</span>`; };
    body.innerHTML = rows.map((b, i) => `
      <tr style="animation:fwrRowIn .15s ${i * 10}ms both">
        <td style="font-family:var(--font-mono);font-size:12px">${b.ip}</td>
        <td style="color:var(--text-muted);font-size:11px">${b.reason || '—'}</td>
        <td>${sbadge(b.source)}</td>
        <td style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted)">${b.date || '—'}</td>
        <td style="font-family:var(--font-mono);font-size:11px;color:${b.expires === '∞' ? 'var(--text-dim)' : '#f97316'}">${b.expires || '∞'}</td>
        <td>
          <button class="fwr-row-btn" data-bid-detail="${b.id}" title="Ver detalhes"><i class="bi bi-pencil"></i></button>
          <button class="fwr-row-btn fwr-row-btn--danger" data-bid="${b.id || b.ip}" title="Remover"><i class="bi bi-trash3"></i></button>
        </td>
      </tr>`).join('');
    body.querySelectorAll('[data-bid]').forEach(btn => btn.addEventListener('click', () => removeBlock(btn.dataset.bid)));
    body.querySelectorAll('[data-bid-detail]').forEach(btn => {
      btn.addEventListener('click', () => openBlockDetail(btn.dataset.bidDetail));
    });
  }

  async function removeBlock(idOrIp) {
    const e = BLOCKLIST.find(b => String(b.id) === String(idOrIp) || b.ip === idOrIp);
    if (!e?.id) return;

    const confirmed = await msConfirm({
      icon: '<i class="bi bi-slash-circle" style="color:#ef4444"></i>',
      title: 'Remover da blocklist',
      msg: `Remover <strong>${e.ip}</strong> da blocklist? O IP voltará a ter acesso.`,
      confirmLabel: '<i class="bi bi-trash3"></i> Remover',
      confirmStyle: 'danger',
    });
    if (!confirmed) return;

    const d = await apiFetch(`/firewall/api/blocklist/${e.id}/`, 'DELETE');
    if (d.ok) {
      BLOCKLIST = BLOCKLIST.filter(b => b.id !== e.id);
      renderBlocklist();
      updateCounts();
      showToast('<i class="bi bi-check-circle" style="margin-right:5px"></i>IP removido da blocklist');
    }
  }

  $('fwrSearchBlock')?.addEventListener('input', renderBlocklist);

  $('fwrAddBlockBtn')?.addEventListener('click', async () => {
    const result = await msPromptIpMotivo({
      title: 'Bloquear IP / Subnet',
      ipPlaceholder: 'ex: 1.2.3.4 ou 10.0.0.0/24',
      motivoPlaceholder: 'ex: Port scan, Brute force…',
    });
    if (!result || !result.msIpField) return;
    const ip = result.msIpField;
    const reason = result.msMotivField || 'Bloqueio manual';
    const d = await apiFetch('/firewall/api/blocklist/', 'POST', { ip, reason });
    if (d.ok) {
      BLOCKLIST.unshift(d.entry);
      renderBlocklist();
      updateCounts();
      showToast(`<i class="bi bi-slash-circle" style="margin-right:5px"></i>${ip} bloqueado`);
    }
  });

  /* ══ BLOCK DETAIL MODAL ══ */
  function openBlockDetail(blockId) {
    const entry = BLOCKLIST.find(b => String(b.id) === String(blockId));
    if (!entry) return;
    blockDetailEntry = entry;
    blockDetailIp = entry.ip;
    $('fwrBlockDetailTitle').textContent = `Detalhes: ${entry.ip}`;
    $('bdInfoSource').textContent = entry.source || '—';
    $('bdInfoDate').textContent = entry.date || '—';
    $('bdInfoExpires').textContent = entry.expires || '∞';
    $('bdInfoReason').textContent = entry.reason || '—';
    if ($('bdExcPort')) $('bdExcPort').value = '';
    if ($('bdExcPriority')) $('bdExcPriority').value = '10';
    if ($('bdExcAction')) $('bdExcAction').value = 'allow';
    if ($('bdExcProto')) $('bdExcProto').value = 'TCP';
    if ($('bdExcPreview')) $('bdExcPreview').innerHTML = '';
    renderBlockDetailRules();
    $('fwrBlockDetailOverlay').classList.add('open');
  }

  function renderBlockDetailRules() {
    const container = $('fwrBlockDetailRules'); if (!container) return;
    const regrasDoIp = RULES.filter(r => !r.deletado && (r.src === blockDetailIp || r.src === blockDetailEntry?.ip));
    if (!regrasDoIp.length) {
      container.innerHTML = `<p style="color:var(--text-dim);font-size:12px;padding:4px 0">Nenhuma regra encontrada para este IP.</p>`;
      return;
    }
    container.innerHTML = regrasDoIp.map(r => `
      <div style="display:flex;align-items:center;gap:8px;padding:6px 8px;margin-bottom:4px;background:var(--bg-hover);border-radius:5px;border:1px solid var(--border)">
        <span class="fwr-action-badge fwr-action-badge--${r.action}" style="font-size:10px;padding:1px 6px">${r.action.toUpperCase()}</span>
        <span style="font-family:var(--font-mono);font-size:11px;color:var(--text-dim)">${r.iface}</span>
        <span style="font-family:var(--font-mono);font-size:11px">${r.proto} port ${r.port}</span>
        <code style="font-size:10px;color:var(--text-dim);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${buildNftInline(r)}</code>
        <label class="fwr-toggle" style="transform:scale(.8)">
          <input type="checkbox" ${r.enabled ? 'checked' : ''} data-rid-bd="${r.id}" class="bd-rule-toggle"/>
          <span class="fwr-toggle-slider"></span>
        </label>
        <button class="fwr-row-btn fwr-row-btn--danger" data-rid-del="${r.id}" title="Remover" style="padding:3px 6px">
          <i class="bi bi-trash3"></i>
        </button>
      </div>`).join('');
    container.querySelectorAll('.bd-rule-toggle').forEach(chk => {
      chk.addEventListener('change', () => {
        const r = RULES.find(x => x.id === +chk.dataset.ridBd);
        if (r) { r.enabled = chk.checked; patchRule(r); }
      });
    });
    container.querySelectorAll('[data-rid-del]').forEach(btn => {
      btn.addEventListener('click', async () => { await deleteRule(+btn.dataset.ridDel); renderBlockDetailRules(); });
    });
  }

  function updateBdExcPreview() {
    const action = $('bdExcAction')?.value, proto = $('bdExcProto')?.value;
    const port = $('bdExcPort')?.value.trim() || 'any';
    const prev = $('bdExcPreview'); if (!prev || !blockDetailIp) return;
    const parts = [];
    if (proto !== 'any') parts.push(proto.toLowerCase());
    parts.push(`ip saddr ${blockDetailIp}`);
    if (port !== 'any') parts.push(`dport ${port}`);
    parts.push(action === 'allow' ? 'accept' : 'drop');
    prev.innerHTML = `<i class="bi bi-terminal" style="opacity:.5"></i> <code>${parts.join(' ')}</code>`;
  }
  ['bdExcAction', 'bdExcProto', 'bdExcPort'].forEach(id => {
    $(id)?.addEventListener('input', updateBdExcPreview);
    $(id)?.addEventListener('change', updateBdExcPreview);
  });

  $('bdExcAddBtn')?.addEventListener('click', async () => {
    if (!blockDetailIp) return;
    const payload = {
      action: $('bdExcAction').value, iface: blockDetailEntry?.iface || 'any', dir: 'in',
      proto: $('bdExcProto').value, src: blockDetailIp, dst: 'any',
      port: $('bdExcPort').value.trim() || 'any',
      priority: parseInt($('bdExcPriority').value) || 10,
      desc: `Exceção para ${blockDetailIp}`,
    };
    const d = await apiFetch('/firewall/api/rules/', 'POST', payload);
    if (d.ok) {
      RULES.push(d.rule);
      renderBlockDetailRules();
      renderRules();
      updateCounts();
      $('bdExcPort').value = '';
      showApplyToast(d.agente_ok);
    }
  });

  $('fwrBlockDetailClose')?.addEventListener('click', () => {
    $('fwrBlockDetailOverlay').classList.remove('open');
    blockDetailIp = null; blockDetailEntry = null;
  });
  $('fwrBlockDetailOverlay')?.addEventListener('click', e => {
    if (e.target === $('fwrBlockDetailOverlay')) {
      $('fwrBlockDetailOverlay').classList.remove('open');
      blockDetailIp = null; blockDetailEntry = null;
    }
  });

  /* ══ ALLOWLIST ══ */
  function renderAllowlist() {
    const body = $('fwrAllowBody'); if (!body) return;
    const q = $('fwrSearchAllow')?.value.toLowerCase() || '';
    const rows = ALLOWLIST.filter(a => !q || a.ip?.includes(q) || a.reason?.toLowerCase().includes(q));
    if (!rows.length) {
      body.innerHTML = `<tr><td colspan="4"><div class="fwr-empty"><i class="bi bi-check2-circle" style="font-size:24px;opacity:.3"></i><span>${q ? 'Nenhum resultado' : 'Nenhum IP liberado'}</span></div></td></tr>`;
      return;
    }
    body.innerHTML = rows.map((a, i) => `
      <tr style="animation:fwrRowIn .15s ${i * 10}ms both">
        <td style="font-family:var(--font-mono);font-size:12px">${a.ip}</td>
        <td style="color:var(--text-muted);font-size:11px">${a.reason || '—'}</td>
        <td style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted)">${a.date || '—'}</td>
        <td><button class="fwr-row-btn fwr-row-btn--danger" data-aid="${a.id || a.ip}" title="Remover"><i class="bi bi-trash3"></i></button></td>
      </tr>`).join('');
    body.querySelectorAll('[data-aid]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const e = ALLOWLIST.find(a => String(a.id) === btn.dataset.aid || a.ip === btn.dataset.aid);
        if (!e?.id) return;

        const confirmed = await msConfirm({
          icon: '<i class="bi bi-check2-circle" style="color:#22c55e"></i>',
          title: 'Remover da allowlist',
          msg: `Remover <strong>${e.ip}</strong> da allowlist? Ele ficará sujeito às regras normais de firewall.`,
          confirmLabel: '<i class="bi bi-trash3"></i> Remover',
          confirmStyle: 'danger',
        });
        if (!confirmed) return;

        const d = await apiFetch(`/firewall/api/allowlist/${e.id}/`, 'DELETE');
        if (d.ok) {
          ALLOWLIST = ALLOWLIST.filter(a => a.id !== e.id);
          renderAllowlist();
          updateCounts();
          showToast('<i class="bi bi-check-circle" style="margin-right:5px"></i>IP removido da allowlist');
        }
      });
    });
  }
  $('fwrSearchAllow')?.addEventListener('input', renderAllowlist);

  $('fwrAddAllowBtn')?.addEventListener('click', async () => {
    const result = await msPromptAllow();
    if (!result || !result.msIpField) return;
    const ip = result.msIpField;
    const reason = result.msMotivField || 'Liberação manual';
    const d = await apiFetch('/firewall/api/allowlist/', 'POST', { ip, reason });
    if (d.ok) {
      ALLOWLIST.push(d.entry);
      renderAllowlist();
      updateCounts();
      showToast(`<i class="bi bi-check2-circle" style="margin-right:5px"></i>${ip} liberado`);
    }
  });

  /* ══ GEOBLOCK ══ */
  function renderGeoblock() {
    const body = $('fwrGeoBody'); if (!body) return;
    const q = $('fwrSearchGeo')?.value.toLowerCase() || '';
    const rows = GEOBLOCK.filter(g => !q || g.country?.toLowerCase().includes(q) || g.code?.toLowerCase().includes(q));
    if (!rows.length) {
      body.innerHTML = `<tr><td colspan="5"><div class="fwr-empty"><i class="bi bi-globe2" style="font-size:24px;opacity:.3"></i><span>${q ? 'Nenhum resultado' : 'Nenhum país bloqueado'}</span></div></td></tr>`;
      return;
    }
    body.innerHTML = rows.map((g, i) => `
      <tr style="animation:fwrRowIn .15s ${i * 10}ms both">
        <td style="font-weight:500">${g.country}</td>
        <td><span style="font-family:var(--font-mono);font-size:11px;padding:2px 6px;background:var(--bg-hover);border-radius:3px">${g.code}</span></td>
        <td style="font-family:var(--font-mono);font-size:11px">${g.dir}</td>
        <td><label class="fwr-toggle"><input type="checkbox" ${g.enabled ? 'checked' : ''} data-gid="${g.id || g.code}" class="geo-toggle"/><span class="fwr-toggle-slider"></span></label></td>
        <td><button class="fwr-row-btn fwr-row-btn--danger" data-gid="${g.id || g.code}" data-act="del" title="Remover"><i class="bi bi-trash3"></i></button></td>
      </tr>`).join('');
    body.querySelectorAll('.geo-toggle').forEach(chk => {
      chk.addEventListener('change', async () => {
        const g = GEOBLOCK.find(x => String(x.id) === chk.dataset.gid || x.code === chk.dataset.gid);
        if (g?.id) {
          const d = await apiFetch(`/firewall/api/geoblock/${g.id}/`, 'PATCH', { enabled: chk.checked });
          if (d.ok) { g.enabled = chk.checked; showToast(`GeoBlock ${g.country}: ${g.enabled ? 'ativado' : 'desativado'}`); }
        }
      });
    });
    body.querySelectorAll('[data-act="del"]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const g = GEOBLOCK.find(x => String(x.id) === btn.dataset.gid || x.code === btn.dataset.gid);
        if (!g?.id) return;

        const confirmed = await msConfirm({
          icon: '<i class="bi bi-globe2" style="color:#a855f7"></i>',
          title: 'Remover GeoBlock',
          msg: `Remover bloqueio de <strong>${g.country}</strong>? Tráfego deste país voltará a ser permitido.`,
          confirmLabel: '<i class="bi bi-trash3"></i> Remover',
          confirmStyle: 'danger',
        });
        if (!confirmed) return;

        const d = await apiFetch(`/firewall/api/geoblock/${g.id}/`, 'DELETE');
        if (d.ok) { GEOBLOCK = GEOBLOCK.filter(x => x.id !== g.id); renderGeoblock(); updateCounts(); showToast('País removido'); }
      });
    });
  }
  $('fwrSearchGeo')?.addEventListener('input', renderGeoblock);
  $('fwrAddGeoBtn')?.addEventListener('click', () => { const p = $('fwrGeoAddPanel'); if (p) p.style.display = p.style.display === 'none' ? 'block' : 'none'; });
  $('geoAddCancelBtn')?.addEventListener('click', () => { if ($('fwrGeoAddPanel')) $('fwrGeoAddPanel').style.display = 'none'; });
  $('geoAddConfirmBtn')?.addEventListener('click', async () => {
    const sel = $('geoCountrySelect'), code = sel?.value;
    const country = sel?.options[sel.selectedIndex]?.text?.replace(/ \(\w+\)$/, '') || code;
    const dir = $('geoDirSelect')?.value || 'IN';
    if (!code) { showToast('Selecione um país', 'err'); return; }
    const d = await apiFetch('/firewall/api/geoblock/', 'POST', { code, country, dir, enabled: true });
    if (d.ok) { GEOBLOCK.push(d.entry); renderGeoblock(); updateCounts(); showToast(`${country} bloqueado`); if ($('fwrGeoAddPanel')) $('fwrGeoAddPanel').style.display = 'none'; }
  });

  /* ══ NAT ══ */
  function updateNatPreview() {
    const wan = $('natWanPort')?.value, ip = $('natLanIp')?.value, lan = $('natLanPort')?.value, proto = $('natProto')?.value || 'TCP';
    const c = $('fwrNatPreviewCode'); if (!c) return;
    c.textContent = (wan && ip && lan) ? `${proto} porta ${wan} da WAN → ${ip}:${lan}` : 'Tráfego chegando na porta WAN → redirecionado para servidor interno';
  }
  ['natWanPort', 'natLanIp', 'natLanPort', 'natProto'].forEach(id => { $(id)?.addEventListener('input', updateNatPreview); $(id)?.addEventListener('change', updateNatPreview); });

  function renderNat() {
    const body = $('fwrNatBody'); if (!body) return;
    if ($('natCount')) $('natCount').textContent = NAT.length;
    if (!NAT.length) {
      body.innerHTML = `<tr><td colspan="8"><div class="fwr-empty"><i class="bi bi-arrow-left-right" style="font-size:24px;opacity:.3"></i><span>Nenhum port forward</span><button class="fwr-btn fwr-btn--primary" onclick="document.getElementById('fwrNewNatBtn').click()" style="margin-top:8px"><i class="bi bi-plus-circle"></i> Adicionar</button></div></td></tr>`;
      return;
    }
    body.innerHTML = NAT.map((n, i) => `
      <tr style="animation:fwrRowIn .15s ${i * 10}ms both;opacity:${n.enabled ? 1 : .5}">
        <td style="font-weight:500">${n.name}</td>
        <td><span class="fwr-iface-badge">${n.iface}</span></td>
        <td style="font-family:var(--font-mono);font-size:12px">${n.wan_port}</td>
        <td style="font-family:var(--font-mono);font-size:12px">${n.lan_ip}</td>
        <td style="font-family:var(--font-mono);font-size:12px">${n.lan_port}</td>
        <td style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted)">${n.proto}</td>
        <td><label class="fwr-toggle"><input type="checkbox" ${n.enabled ? 'checked' : ''} data-nid="${n.id}" class="nat-toggle"/><span class="fwr-toggle-slider"></span></label></td>
        <td><div class="fwr-row-actions">
          <button class="fwr-row-btn" data-nid="${n.id}" data-act="edit" title="Editar"><i class="bi bi-pencil"></i></button>
          <button class="fwr-row-btn fwr-row-btn--danger" data-nid="${n.id}" data-act="del" title="Remover"><i class="bi bi-trash3"></i></button>
        </div></td>
      </tr>`).join('');
    body.querySelectorAll('.nat-toggle').forEach(chk => {
      chk.addEventListener('change', async () => {
        const n = NAT.find(x => x.id === +chk.dataset.nid);
        if (n?.id) { const d = await apiFetch(`/firewall/api/nat/${n.id}/`, 'PATCH', { enabled: chk.checked }); if (d.ok) { n.enabled = chk.checked; showToast(`Port forward ${n.enabled ? 'ativado' : 'desativado'}`); } }
      });
    });
    body.querySelectorAll('[data-act]').forEach(btn => {
      btn.addEventListener('click', async e => {
        e.stopPropagation();
        const id = +btn.dataset.nid, act = btn.dataset.act;
        if (act === 'edit') openNatDrawer(id);
        if (act === 'del') {
          const n = NAT.find(x => x.id === id);
          const confirmed = await msConfirm({
            icon: '<i class="bi bi-arrow-left-right" style="color:#f97316"></i>',
            title: 'Remover port forward',
            msg: `Remover o port forward <strong>${n?.name || `#${id}`}</strong>?`,
            confirmLabel: '<i class="bi bi-trash3"></i> Remover',
            confirmStyle: 'danger',
          });
          if (!confirmed) return;
          const d = await apiFetch(`/firewall/api/nat/${id}/`, 'DELETE');
          if (d.ok) { NAT = NAT.filter(n => n.id !== id); renderNat(); updateCounts(); showToast('Port forward removido'); }
        }
      });
    });
  }

  function openNatDrawer(id) {
    const n = id ? NAT.find(x => x.id === id) : null;
    editingNatId = id || null;
    $('fwrNatDrawerTitle').textContent = n ? 'Editar Port Forward' : 'Novo Port Forward';
    if (n) { $('natName').value = n.name || ''; $('natIface').value = n.iface || 'WAN'; $('natProto').value = n.proto || 'TCP'; $('natWanPort').value = n.wan_port || ''; $('natLanIp').value = n.lan_ip || ''; $('natLanPort').value = n.lan_port || ''; }
    else { $('fwrNatForm').reset(); }
    updateNatPreview();
    $('fwrNatDrawer').classList.add('open'); $('fwrNatDrawerOverlay').classList.add('open');
    setTimeout(() => $('natName')?.focus(), 200);
  }
  function closeNatDrawer() { $('fwrNatDrawer').classList.remove('open'); $('fwrNatDrawerOverlay').classList.remove('open'); editingNatId = null; }
  async function saveNat() {
    const name = $('natName')?.value.trim(), wan = $('natWanPort')?.value.trim(), ip = $('natLanIp')?.value.trim(), lan = $('natLanPort')?.value.trim();
    if (!name || !wan || !ip || !lan) { showToast('Preencha todos os campos', 'err'); return; }
    const payload = { name, iface: $('natIface')?.value || 'WAN', proto: $('natProto')?.value || 'TCP', wan_port: wan, lan_ip: ip, lan_port: lan, enabled: true };
    if (editingNatId) {
      const d = await apiFetch(`/firewall/api/nat/${editingNatId}/`, 'PUT', payload);
      if (d.ok) { const idx = NAT.findIndex(n => n.id === editingNatId); if (idx !== -1) NAT[idx] = d.nat; showToast('Port forward atualizado'); }
    } else {
      const d = await apiFetch('/firewall/api/nat/', 'POST', payload);
      if (d.ok) { NAT.push(d.nat); showToast('Port forward criado'); }
    }
    closeNatDrawer(); renderNat(); updateCounts();
  }
  $('fwrNewNatBtn')?.addEventListener('click', () => openNatDrawer(null));
  $('fwrNatSaveBtn')?.addEventListener('click', saveNat);
  $('fwrNatDrawerCancel')?.addEventListener('click', closeNatDrawer);
  $('fwrNatDrawerClose')?.addEventListener('click', closeNatDrawer);
  $('fwrNatDrawerOverlay')?.addEventListener('click', closeNatDrawer);

  /* ══ TABS ══ */
  document.querySelectorAll('.fwr-tab[data-tab]').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.fwr-tab').forEach(t => t.classList.remove('fwr-tab--active'));
      document.querySelectorAll('.fwr-panel').forEach(p => p.classList.remove('fwr-panel--active'));
      tab.classList.add('fwr-tab--active');
      $(`panel${tab.dataset.tab.charAt(0).toUpperCase() + tab.dataset.tab.slice(1)}`)?.classList.add('fwr-panel--active');
    });
  });

  /* ══ FILTROS ══ */
  $('fwrFilterAction')?.addEventListener('change', e => { filterAction = e.target.value; renderRules(); });
  $('fwrFilterIface')?.addEventListener('change', e => { filterIface = e.target.value; renderRules(); });
  $('fwrSearchRegras')?.addEventListener('input', e => { searchRegras = e.target.value.trim(); renderRules(); });

  /* ══ BLOQUEIO RÁPIDO ══ */
  $('qbSubmitBtn')?.addEventListener('click', async () => {
    const ip = $('qbIp')?.value.trim();
    if (!ip) { $('qbIp').focus(); showToast('<i class="bi bi-exclamation-triangle" style="margin-right:5px"></i>Informe um IP ou subnet', 'err'); return; }
    const btn = $('qbSubmitBtn');
    btn.disabled = true; btn.innerHTML = '<i class="bi bi-hourglass-split"></i> Bloqueando…';
    try {
      const d = await apiFetch('/firewall/api/bloqueio-rapido/', 'POST', {
        ip, iface: $('qbIface')?.value || '', porta: $('qbPort')?.value || '',
        proto: $('qbProto')?.value || '', expires: $('qbExpires')?.value || '',
        motivo: 'Bloqueio rápido pelo painel', source: 'Manual',
      });
      if (d.ok) {
        showApplyToast(d.agente_ok);
        $('qbIp').value = '';
        if ($('qbPreview')) $('qbPreview').style.display = 'none';
        await loadAll();
      } else {
        showToast(`<i class="bi bi-x-circle" style="margin-right:5px"></i>Erro: ${d.erro || 'falha'}`, 'err');
      }
    } catch (e) { showToast('<i class="bi bi-x-circle" style="margin-right:5px"></i>Falha de rede', 'err'); }
    finally { btn.disabled = false; btn.innerHTML = '<i class="bi bi-ban"></i> Bloquear'; }
  });

  /* ══ PUSH / EXPORT ══ */
  async function pushRules() {
    setPushBtnState('loading');
    try {
      const d = await apiFetch('/firewall/api/push-rules/', 'POST');
      if (d.ok) {
        showApplyToast(d.agente_ok);
        if (d.sync) renderSyncBar(d.sync);
        setPushBtnState(d.agente_ok ? 'ok' : 'offline');
      }
    } catch (e) {
      setPushBtnState('offline');
      showToast('<i class="bi bi-x-circle" style="margin-right:5px"></i>Falha de rede', 'err');
    }
  }
  $('fwrPushBtn')?.addEventListener('click', pushRules);
  $('fwrExportNftBtn')?.addEventListener('click', () => { showToast('Gerando arquivo .nft…'); window.location.href = '/firewall/api/export-nft/'; });

  /* ══ POLÍTICAS ══ */
  document.querySelectorAll('[data-pol]').forEach(el => {
    el.addEventListener('change', () => showToast(`Política "${el.dataset.pol}": ${el.type === 'checkbox' ? el.checked : el.value}`));
  });
  ['polDefaultIn', 'polDefaultOut', 'polDefaultFwd'].forEach(id => {
    $(id)?.addEventListener('change', function () { this.className = `fwr-policy-select fwr-policy-select--${this.value}`; showToast(`Política padrão: ${this.options[this.selectedIndex].text}`); });
  });

  /* ══ AJUDA ══ */
  const HELP = {
    regras: { title: 'Como funcionam as Regras', body: `<p>Regras definem o que o firewall <strong>bloqueia (DENY)</strong> ou <strong>permite (ALLOW)</strong>.</p><h4>Ordem de prioridade</h4><p>Regras com número menor são avaliadas primeiro. Se um pacote bate em uma regra, as outras são ignoradas.</p><h4>Exemplo prático</h4><p>Bloquear SSH da internet mas permitir da rede interna:</p><ul><li>Prioridade 10: ALLOW · LAN · TCP · :22</li><li>Prioridade 20: DENY · WAN · TCP · :22</li></ul><h4>Toggle (liga/desliga)</h4><p>Desativar uma regra a mantém salva mas para de aplicá-la. Útil para testes.</p><h4>Coluna "Comando nft"</h4><p>Mostra o comando exato que será executado no Linux quando a regra for aplicada.</p>` },
    blocklist: { title: 'Blocklist — IPs Bloqueados', body: `<p>IPs na blocklist são bloqueados automaticamente.</p><h4>Fontes</h4><ul><li><strong>Manual</strong> — adicionado pelo analista</li><li><strong>Auto</strong> — banido automaticamente pelo sensor (ex: brute force)</li><li><strong>SOC</strong> — marcado como ameaça no painel de Incidentes</li></ul><h4>Expiração</h4><p>"∞" = permanente. Você pode definir 1h, 24h, 7d ou 30d.</p>` },
    allowlist: { title: 'Allowlist — IPs Liberados', body: `<p>IPs na allowlist <strong>sempre passam</strong>, mesmo havendo regras de bloqueio.</p><p>Use para: servidores internos, parceiros confiáveis, rede de gerência.</p><p><strong>Cuidado:</strong> IPs na allowlist escapam de todas as regras, incluindo GeoBlock.</p>` },
    geoblock: { title: 'GeoBlock — Bloqueio por País', body: `<p>Bloqueia todo tráfego originado em países específicos.</p><h4>Direção</h4><ul><li><strong>IN</strong> — bloqueia tráfego vindo do país (mais comum)</li><li><strong>OUT</strong> — bloqueia tráfego saindo para o país</li><li><strong>BOTH</strong> — ambos os sentidos</li></ul><p><strong>Limitação:</strong> VPNs e proxies podem contornar o GeoBlock.</p>` },
    nat: { title: 'NAT / Port Forward', body: `<p>Redireciona tráfego que chega numa porta da WAN para um servidor interno.</p><h4>Exemplo</h4><ul><li>WAN Port: 80 → LAN IP: 10.0.0.10 : LAN Port: 80</li></ul><p>Tráfego na porta 80 da WAN vai para o servidor web interno.</p><h4>Porta diferente</h4><p>Você pode usar portas diferentes: WAN 2222 → LAN :22 para SSH na porta não padrão.</p>` },
    'bloqueio-rapido': { title: 'Bloqueio Rápido', body: `<p>Bloqueia um IP imediatamente, criando:</p><ul><li>Uma <strong>regra de firewall</strong> (prioridade 50)</li><li>Uma <strong>entrada na blocklist</strong></li></ul><p>O preview mostra o comando nft que será executado antes de confirmar.</p>` },
  };
  document.querySelectorAll('.fwr-help-btn[data-help]').forEach(btn => {
    btn.addEventListener('click', () => {
      const c = HELP[btn.dataset.help]; if (!c) return;
      $('fwrHelpTitle').textContent = c.title; $('fwrHelpBody').innerHTML = c.body;
      $('fwrHelpOverlay').classList.add('open');
    });
  });
  $('fwrHelpClose')?.addEventListener('click', () => $('fwrHelpOverlay').classList.remove('open'));
  $('fwrHelpOverlay')?.addEventListener('click', e => { if (e.target === $('fwrHelpOverlay')) $('fwrHelpOverlay').classList.remove('open'); });

  /* ══ KEYBOARD ══ */
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      _closeModal(null);
      closeRuleDrawer(); closeNatDrawer();
      $('fwrHelpOverlay')?.classList.remove('open');
      if ($('fwrBlockDetailOverlay')?.classList.contains('open')) {
        $('fwrBlockDetailOverlay').classList.remove('open');
        blockDetailIp = null; blockDetailEntry = null;
      }
    }
  });

  /* ══ URL PARAMS ══ */
  function checkUrlParams() {
    const p = new URLSearchParams(window.location.search);
    if (p.get('nova_regra')) {
      setTimeout(() => {
        openRuleDrawer(null);
        if (p.get('src')) $('rfSrc').value = p.get('src');
        if (p.get('port')) $('rfPort').value = p.get('port');
        if (p.get('proto')) $('rfProto').value = p.get('proto');
        if (p.get('iface')) $('rfIface').value = p.get('iface');
        window.history.replaceState({}, '', '/firewall/regras/');
      }, 500);
    }
  }

  /* ══ KEYFRAMES ══ */
  if (!document.getElementById('fwrKeyframes')) {
    const s = document.createElement('style'); s.id = 'fwrKeyframes';
    s.textContent = `@keyframes fwrRowIn{from{opacity:0;transform:translateX(-4px)}to{opacity:1;transform:none}}`;
    document.head.appendChild(s);
  }

  /* ══ INIT ══ */
  _injectModalHtml();
  loadInterfaces();
  loadAll();
  checkUrlParams();
  setInterval(loadAll, 30000);

});