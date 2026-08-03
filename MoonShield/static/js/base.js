/**
 * MOONSHIELD — BASE.JS
 * Toggle de tema claro/escuro.
 * Fonte da verdade: data-theme no <html> (injetado pelo Django via profile.tema).
 * localStorage é apenas cache para evitar flash na próxima carga.
 */

(function () {
  'use strict';

  /* ══════════════════════════════════════════════════════
     TEMA — aplica IMEDIATAMENTE (antes do DOMContentLoaded)
     para evitar flash de tema errado.

     Prioridade:
       1. data-theme no <html>  ← Django/banco (mais confiável)
       2. localStorage jg_theme ← cache local (fallback)
       3. 'dark'                ← default final
  ══════════════════════════════════════════════════════ */
  const serverTheme = document.documentElement.getAttribute('data-theme');
  const localTheme = localStorage.getItem('jg_theme');

  // O servidor sempre ganha — sincroniza o cache local com o banco
  const activeTheme = serverTheme || localTheme || 'dark';

  document.documentElement.setAttribute('data-theme', activeTheme);

  // Mantém localStorage em sincronia com o banco
  if (activeTheme !== localTheme) {
    localStorage.setItem('jg_theme', activeTheme);
  }

  /* ══════════════════════════════════════════════════════
     TOGGLE DE TEMA (interação do usuário)
  ══════════════════════════════════════════════════════ */
  document.addEventListener('DOMContentLoaded', () => {

    const toggleBtns = document.querySelectorAll('.theme-toggle, [data-action="theme-toggle"]');

    function applyTheme(theme, { persist = true, syncServer = false } = {}) {
      document.documentElement.setAttribute('data-theme', theme);

      if (persist) {
        localStorage.setItem('jg_theme', theme);
      }

      // Atualiza aria nos botões
      toggleBtns.forEach(btn => {
        btn.setAttribute('aria-label', theme === 'dark' ? 'Ativar tema claro' : 'Ativar tema escuro');
        btn.setAttribute('title', theme === 'dark' ? 'Tema claro' : 'Tema escuro');
      });

      // Persiste no banco se pedido (ex: clique no toggle da topbar)
      if (syncServer) {
        const csrf = document.cookie.match(/csrftoken=([^;]+)/)?.[1] || '';
        fetch('/autenticacao/api/ui/tema/', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf },
          body: JSON.stringify({ tema: theme }),
        }).catch(() => { }); // silencioso — não bloqueia a UI
      }

      document.dispatchEvent(new CustomEvent('themeChanged', { detail: { theme } }));
    }

    function toggleTheme() {
      const current = document.documentElement.getAttribute('data-theme') || 'dark';
      applyTheme(current === 'dark' ? 'light' : 'dark', { persist: true, syncServer: true });
    }

    // Aplica tema atual e sincroniza aria dos botões
    applyTheme(activeTheme, { persist: true, syncServer: false });

    // Cliques nos botões de toggle
    toggleBtns.forEach(btn => {
      btn.addEventListener('click', toggleTheme);
    });

    // Atalho de teclado: Ctrl+Shift+L
    document.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'L') {
        e.preventDefault();
        toggleTheme();
      }
    });

    // Reage a mudanças de preferência do OS APENAS se o usuário não definiu preferência
    // (se há data-theme do servidor, o usuário definiu — não sobrescreve)
    if (!serverTheme) {
      window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
        applyTheme(e.matches ? 'dark' : 'light', { persist: true, syncServer: false });
      });
    }

    /* Remove a classe no-transition após o primeiro frame para
       reativar as animações CSS sem flash */
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        document.documentElement.classList.remove('no-transition');
      });
    });

  });

})();