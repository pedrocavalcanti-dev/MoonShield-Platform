/**
 * MOONSHIELD — NOTIFICACOES.JS v2
 * Fix: agora busca dados reais de /api/alertas/ (backend).
 * Mock removido — o backend já serve dados demo quando modo=demo.
 * Polling de /api/alertas/count/ é silencioso.
 */

document.addEventListener('DOMContentLoaded', () => {

  const panel      = document.getElementById('notifPanel');
  const overlay    = document.getElementById('notifOverlay');
  const closeBtn   = document.getElementById('notifPanelClose');
  const markAllBtn = document.getElementById('notifMarkAll');
  const notifList  = document.getElementById('notifList');
  const emptyState = document.getElementById('notifEmpty');
  const panelCount = document.getElementById('notifPanelCount');
  const notifBtn   = document.getElementById('topbarNotifBtn');
  const filterBtns = document.querySelectorAll('.notif-filter-btn');

  let allNotifs    = [];
  let activeFilter = 'all';

  // ── ABRIR / FECHAR ────────────────────────────────────────
  notifBtn?.addEventListener('click', openPanel);
  closeBtn?.addEventListener('click', closePanel);
  overlay?.addEventListener('click',  closePanel);
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && panel?.classList.contains('open')) closePanel();
  });

  function openPanel() {
    panel?.classList.add('open');
    panel?.setAttribute('aria-hidden', 'false');
    overlay?.classList.add('active');
    fetchNotifs();
  }

  function closePanel() {
    panel?.classList.remove('open');
    panel?.setAttribute('aria-hidden', 'true');
    overlay?.classList.remove('active');
  }

  // ── FILTROS ───────────────────────────────────────────────
  filterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      filterBtns.forEach(b => b.classList.remove('notif-filter-btn--active'));
      btn.classList.add('notif-filter-btn--active');
      activeFilter = btn.dataset.filter;
      renderNotifs();
    });
  });

  // ── BUSCAR NOTIFICAÇÕES — /api/alertas/ ───────────────────
  async function fetchNotifs() {
    try {
      const res = await fetch('/api/alertas/', {
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
        signal: AbortSignal.timeout(5000),
      });
      if (!res.ok) return;
      allNotifs = await res.json();
      renderNotifs();
      updateCount();
    } catch {
      // Sem conexão ou timeout — mantém lista anterior sem logar
    }
  }

  // ── RENDERIZAR ────────────────────────────────────────────
  function renderNotifs() {
    if (!notifList) return;

    const filtered = activeFilter === 'all'
      ? allNotifs
      : allNotifs.filter(n => n.severidade === activeFilter);

    notifList.querySelectorAll('.notif-item').forEach(el => el.remove());

    if (filtered.length === 0) {
      if (emptyState) emptyState.style.display = 'flex';
      return;
    }
    if (emptyState) emptyState.style.display = 'none';

    filtered.forEach((notif, i) => notifList.appendChild(createNotifItem(notif, i)));
  }

  function createNotifItem(notif, index) {
    const div = document.createElement('div');
    div.className = `notif-item notif-item--${notif.severidade}`;
    div.style.animationDelay = `${index * 40}ms`;
    div.dataset.id = notif.id;

    div.innerHTML = `
      <div class="notif-item__icon">${getIconSVG(notif.tipo)}</div>
      <div class="notif-item__body">
        <p class="notif-item__title">${escapeHTML(notif.titulo)}</p>
        <p class="notif-item__desc">${escapeHTML(notif.descricao)}</p>
        <p class="notif-item__time">${formatTime(notif.timestamp)}</p>
      </div>
      <button class="notif-item__dismiss" aria-label="Dispensar">
        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
        </svg>
      </button>`;

    div.querySelector('.notif-item__dismiss')?.addEventListener('click', e => {
      e.stopPropagation();
      dismissNotif(notif.id, div);
    });

    if (notif.url) div.addEventListener('click', () => { window.location.href = notif.url; });

    return div;
  }

  function dismissNotif(id, el) {
    allNotifs = allNotifs.filter(n => n.id !== id);
    Object.assign(el.style, { opacity: '0', transform: 'translateX(20px)', transition: 'opacity .2s, transform .2s' });
    setTimeout(() => { el.remove(); renderNotifs(); updateCount(); }, 200);
  }

  markAllBtn?.addEventListener('click', () => {
    allNotifs = [];
    renderNotifs();
    updateCount();
  });

  // ── CONTAGEM ──────────────────────────────────────────────
  function updateCount() {
    const count = allNotifs.length;
    if (panelCount) panelCount.textContent = count;
    document.dispatchEvent(new CustomEvent('notifCountUpdated', { detail: { count } }));
  }

  // ── POLLING /api/alertas/count/ ───────────────────────────
  setInterval(async () => {
    try {
      const res = await fetch('/api/alertas/count/', {
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
        signal: AbortSignal.timeout(4000),
      });
      if (!res.ok) return;
      const { count } = await res.json();
      document.dispatchEvent(new CustomEvent('notifCountUpdated', { detail: { count } }));
    } catch { /* silencioso */ }
  }, 60_000);

  // ── HELPERS ───────────────────────────────────────────────
  function escapeHTML(str = '') {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function formatTime(ts) {
    if (!ts) return '';
    const d = new Date(ts);
    const diffMin = Math.floor((Date.now() - d) / 60000);
    if (diffMin < 1)  return 'agora';
    if (diffMin < 60) return `${diffMin}m atrás`;
    const h = Math.floor(diffMin / 60);
    if (h < 24) return `${h}h atrás`;
    return d.toLocaleDateString('pt-BR');
  }

  function getIconSVG(tipo) {
    const icons = {
      ids:      `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
      scan:     `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>`,
      dns:      `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>`,
      firewall: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
    };
    return icons[tipo] ?? icons.ids;
  }

  // Carrega contagem inicial
  updateCount();
  fetchNotifs();

});