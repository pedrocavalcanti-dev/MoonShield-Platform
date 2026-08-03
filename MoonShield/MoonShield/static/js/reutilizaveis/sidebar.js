/**
 * MOONSHIELD — SIDEBAR.JS v7
 * - Estado inicial aplicado SEM transição (lê data-sidebar do <html>)
 * - Transições liberadas apenas após o primeiro frame
 * - Collapsed/expanded salvo no banco via POST /auth/api/ui/sidebar/
 */

// ── Aplica collapse IMEDIATAMENTE — antes do DOMContentLoaded ──────────────
// Neste ponto o <html data-sidebar="collapsed"> já existe no DOM.
// A classe .no-transition está ativa (adicionada pelo base.html),
// então nenhuma animação dispara.
(function applyInitialCollapse() {
  const collapsed = document.documentElement.dataset.sidebar === 'collapsed';
  const sidebar   = document.getElementById('sidebar');
  if (!sidebar) return;

  if (collapsed) {
    sidebar.classList.add('collapsed');
    document.documentElement.style.setProperty('--current-sidebar-w', 'var(--sidebar-collapsed)');
  } else {
    document.documentElement.style.setProperty('--current-sidebar-w', 'var(--sidebar-w)');
  }
})();

document.addEventListener('DOMContentLoaded', () => {

  // ── Remove .no-transition após o primeiro frame renderizado ────────────────
  // requestAnimationFrame garante que o browser já pintou o estado inicial.
  // A partir daqui todas as transições CSS voltam a funcionar normalmente.
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      document.documentElement.classList.remove('no-transition');
    });
  });

  /* ═══════════════════════════════════════════════════════
     COLLAPSE INTERATIVO
  ═══════════════════════════════════════════════════════ */
  const sidebar     = document.getElementById('sidebar');
  const collapseBtn = document.getElementById('sidebarCollapseBtn');

  function applyCollapse(collapsed) {
    if (!sidebar) return;
    sidebar.classList.toggle('collapsed', collapsed);
    document.documentElement.style.setProperty(
      '--current-sidebar-w',
      collapsed ? 'var(--sidebar-collapsed)' : 'var(--sidebar-w)'
    );
  }

  function getCSRF() {
    return document.cookie
      .split('; ')
      .find(r => r.startsWith('csrftoken='))
      ?.split('=')[1] ?? '';
  }

  async function saveCollapseState(collapsed) {
    try {
      await fetch('/auth/api/ui/sidebar/', {
        method:  'POST',
        headers: {
          'Content-Type':     'application/json',
          'X-CSRFToken':      getCSRF(),
          'X-Requested-With': 'XMLHttpRequest',
        },
        body:   JSON.stringify({ collapsed }),
        signal: AbortSignal.timeout(5000),
      });
    } catch { /* silencioso */ }
  }

  collapseBtn?.addEventListener('click', () => {
    if (!sidebar) return;
    const nowCollapsed = !sidebar.classList.contains('collapsed');
    applyCollapse(nowCollapsed);
    saveCollapseState(nowCollapsed);
  });

  /* ═══════════════════════════════════════════════════════
     MOBILE OVERLAY
  ═══════════════════════════════════════════════════════ */
  const overlay = document.getElementById('sidebarOverlay');

  function openMobileSidebar() {
    sidebar?.classList.add('mobile-open');
    overlay?.classList.add('open');
    document.body.style.overflow = 'hidden';
  }

  function closeMobileSidebar() {
    sidebar?.classList.remove('mobile-open');
    overlay?.classList.remove('open');
    document.body.style.overflow = '';
  }

  overlay?.addEventListener('click', closeMobileSidebar);
  document.addEventListener('openSidebar', openMobileSidebar);
  window.openMobileSidebar  = openMobileSidebar;
  window.closeMobileSidebar = closeMobileSidebar;

  /* ═══════════════════════════════════════════════════════
     BUSCA RÁPIDA — Ctrl+K
  ═══════════════════════════════════════════════════════ */
  const searchInput = document.getElementById('sidebarSearch');

  document.addEventListener('keydown', e => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      e.preventDefault();
      if (sidebar?.classList.contains('collapsed') && window.innerWidth > 900) {
        applyCollapse(false);
        saveCollapseState(false);
      }
      setTimeout(() => searchInput?.focus(), 100);
    }
    if (e.key === 'Escape' && document.activeElement === searchInput) {
      searchInput.blur();
    }
  });

  searchInput?.addEventListener('input', () => {
    const q = searchInput.value.toLowerCase().trim();
    document.querySelectorAll('.sidebar__item[data-label]').forEach(item => {
      item.style.display = (!q || (item.dataset.label?.toLowerCase() ?? '').includes(q)) ? '' : 'none';
    });
  });

  /* ═══════════════════════════════════════════════════════
     USER POPUP
  ═══════════════════════════════════════════════════════ */
  const userMenuBtn   = document.getElementById('userMenuBtn');
  const userMenuPopup = document.getElementById('userMenuPopup');

  userMenuBtn?.addEventListener('click', e => {
    e.stopPropagation();
    userMenuPopup?.classList.toggle('open');
  });

  document.addEventListener('click', e => {
    if (userMenuPopup?.classList.contains('open') &&
        !userMenuPopup.contains(e.target) &&
        e.target !== userMenuBtn) {
      userMenuPopup.classList.remove('open');
    }
  });

  /* ═══════════════════════════════════════════════════════
     ACTIVE ITEM
  ═══════════════════════════════════════════════════════ */
  const currentPath = window.location.pathname;
  document.querySelectorAll('.sidebar__item[href]').forEach(item => {
    if (item.getAttribute('href') === currentPath) {
      item.classList.add('sidebar__item--active');
    }
  });

  /* ═══════════════════════════════════════════════════════
     BADGES — /api/badges/
  ═══════════════════════════════════════════════════════ */
  const BADGE_IDS = {
    incidentes: 'badgeIncidentes',
    mapa:       'badgeMapa',
    firewall:   'badgeFirewall',
  };

  function updateBadge(id, count) {
    const el = document.getElementById(id);
    if (!el) return;
    if (count > 0) {
      el.textContent = count > 99 ? '99+' : count;
      el.style.display = 'inline-flex';
    } else {
      el.style.display = 'none';
    }
  }

  async function refreshBadges() {
    try {
      const res = await fetch('/api/badges/', {
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
        signal: AbortSignal.timeout(5000),
      });
      if (!res.ok) return;
      const data = await res.json();
      Object.entries(BADGE_IDS).forEach(([key, elId]) => {
        if (data[key] !== undefined) updateBadge(elId, data[key]);
      });
    } catch { /* silencioso */ }
  }

  refreshBadges();
  const badgeInterval = setInterval(refreshBadges, 30_000);
  window.addEventListener('beforeunload', () => clearInterval(badgeInterval));

});