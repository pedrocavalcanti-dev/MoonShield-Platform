/**
 * MOONSHIELD — TOPBAR.JS v2
 * Fix: removido localStorage (bloqueado pelo Edge Tracking Prevention).
 * O período ativo agora é controlado apenas via atributo CSS/DOM.
 */

document.addEventListener('DOMContentLoaded', () => {

  // ── FILTRO DE PERÍODO ─────────────────────────────────────
  const periodBtns = document.querySelectorAll('.topbar__period-btn');

  // Restaura o ativo pelo data-period="24h" como padrão (sem localStorage)
  const defaultPeriod = '24h';
  periodBtns.forEach(btn => {
    btn.classList.toggle('topbar__period-btn--active', btn.dataset.period === defaultPeriod);
  });

  periodBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      periodBtns.forEach(b => b.classList.remove('topbar__period-btn--active'));
      btn.classList.add('topbar__period-btn--active');
      document.dispatchEvent(new CustomEvent('periodChanged', { detail: { period: btn.dataset.period } }));
    });
  });

  // ── MOBILE — ABRIR SIDEBAR ────────────────────────────────
  const menuBtn = document.getElementById('topbarMenuBtn');
  menuBtn?.addEventListener('click', () => {
    document.dispatchEvent(new CustomEvent('openSidebar'));
  });

  // ── STATUS DOS SENSORES ───────────────────────────────────
  async function refreshSensors() {
    try {
      const res = await fetch('/api/sensores/', {
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
        signal: AbortSignal.timeout(5000),
      });
      if (!res.ok) return;
      const data = await res.json();
      updateSensor('ids', data.ids);
      updateSensor('dns', data.dns);
      updateSensor('fw', data.firewall);
    } catch {
      // silencioso — não polui o console
    }
  }

  function updateSensor(name, status) {
    const dot = document.querySelector(`.topbar__sensor[data-sensor="${name}"] .topbar__sensor-dot`);
    if (!dot) return;
    dot.className = 'topbar__sensor-dot dot--pulse';
    const map = { ok: 'topbar__sensor-dot--ok', warn: 'topbar__sensor-dot--warn', danger: 'topbar__sensor-dot--danger' };
    dot.classList.add(map[status] ?? 'topbar__sensor-dot--off');
  }

  refreshSensors();
  setInterval(refreshSensors, 20_000);

  // ── CONTADOR DE NOTIFICAÇÕES ──────────────────────────────
  document.addEventListener('notifCountUpdated', (e) => {
    const count = e.detail?.count ?? 0;
    const badge = document.getElementById('topbarNotifCount');
    const btn = document.getElementById('topbarNotifBtn');
    if (!badge || !btn) return;
    badge.textContent = count > 99 ? '99+' : count;
    badge.style.display = count > 0 ? 'flex' : 'none';
    btn.classList.toggle('has-notif', count > 0);
  });

  // ── USUÁRIO TOPBAR ────────────────────────────────────────
  const topbarUser = document.getElementById('topbarUser');
  topbarUser?.addEventListener('click', () => {
    document.getElementById('userMenuPopup')?.classList.toggle('open');
  });

});