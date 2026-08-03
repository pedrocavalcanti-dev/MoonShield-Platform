/**
 * MOONSHIELD — FOOTER.JS v2
 * Fix: fetchUptime agora é silencioso no catch — sem spam no console.
 */

document.addEventListener('DOMContentLoaded', () => {

  const timeEl   = document.getElementById('footerTime');
  const uptimeEl = document.getElementById('uptimeValue');

  // ── RELÓGIO ───────────────────────────────────────────────
  function updateClock() {
    if (!timeEl) return;
    timeEl.textContent = new Date().toLocaleTimeString('pt-BR', {
      hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
    });
  }

  updateClock();
  setInterval(updateClock, 1000);

  // ── UPTIME — /api/uptime/ ─────────────────────────────────
  async function fetchUptime() {
    try {
      const res = await fetch('/api/uptime/', {
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
        signal: AbortSignal.timeout(4000),
      });
      if (!res.ok) throw new Error();
      const { uptime_seconds } = await res.json();
      if (uptimeEl) uptimeEl.textContent = formatUptime(uptime_seconds);
    } catch {
      // Falha silenciosa — mostra texto neutro sem logar erro
      if (uptimeEl) uptimeEl.textContent = 'Sistema ativo';
    }
  }

  function formatUptime(seconds) {
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    if (d > 0) return `Uptime: ${d}d ${h}h ${m}m`;
    if (h > 0) return `Uptime: ${h}h ${m}m`;
    return `Uptime: ${m}m`;
  }

  fetchUptime();
  setInterval(fetchUptime, 60_000);

});