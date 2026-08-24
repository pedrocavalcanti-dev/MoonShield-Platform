/**
 * MoonShield Network Panel
 * Barra lateral
 *
 * Responsabilidades:
 * - navegação entre seções;
 * - abertura/fechamento mobile;
 * - collapse/expand no desktop;
 * - persistência do estado recolhido;
 * - criação automática da alavanca quando necessário;
 * - backdrop;
 * - tecla ESC;
 * - sincronização do item ativo.
 */

'use strict';

import { $, $$ } from '../nucleo/dom.js';

const MOBILE_BREAKPOINT = 920;
const COLLAPSE_STORAGE_KEY = 'moonshield_network_sidebar_collapsed';

let inicializado = false;
let onNavigateCallback = null;

let sidebar = null;
let backdrop = null;
let openButton = null;
let closeButton = null;
let collapseButton = null;
let navItems = [];
let desktopCollapsed = false;


/* ==========================================================================
   INICIALIZAÇÃO
========================================================================== */

export function inicializarBarraLateral(opcoes = {}) {
    if (inicializado) {
        if (typeof opcoes.onNavigate === 'function') onNavigateCallback = opcoes.onNavigate;
        return;
    }

    sidebar = $('#networkSidebar');
    backdrop = $('#sidebarBackdrop');
    openButton = $('#sidebarOpen');
    closeButton = $('#sidebarClose');
    navItems = $$('.np-nav__item[data-section]');

    if (!sidebar) {
        console.warn('[MoonShield Network] Sidebar não encontrada.');
        return;
    }

    collapseButton = garantirBotaoCollapse();
    desktopCollapsed = lerPreferenciaCollapse();
    inicializado = true;
    onNavigateCallback = typeof opcoes.onNavigate === 'function' ? opcoes.onNavigate : null;

    registrarEventos();
    sincronizarEstadoResponsivo();
}


/* ==========================================================================
   ALAVANCA DESKTOP
========================================================================== */

function garantirBotaoCollapse() {
    let botao = $('#sidebarCollapse');
    if (botao) return botao;

    botao = document.createElement('button');
    botao.type = 'button';
    botao.className = 'np-sidebar__collapse';
    botao.id = 'sidebarCollapse';
    botao.setAttribute('aria-label', 'Recolher barra lateral');
    botao.setAttribute('aria-expanded', 'true');
    botao.setAttribute('title', 'Recolher barra lateral');
    botao.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 6L8 12L14 18"></path></svg>';

    sidebar.appendChild(botao);
    return botao;
}


/* ==========================================================================
   EVENTOS
========================================================================== */

function registrarEventos() {
    openButton?.addEventListener('click', abrirSidebarMobile);
    closeButton?.addEventListener('click', fecharSidebarMobile);
    backdrop?.addEventListener('click', fecharSidebarMobile);
    collapseButton?.addEventListener('click', alternarSidebarDesktop);

    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const secao = item.dataset.section;
            if (!secao) return;

            definirItemAtivo(secao);

            if (typeof onNavigateCallback === 'function') onNavigateCallback(secao);
            if (ehMobile()) fecharSidebarMobile();
        });
    });

    document.addEventListener('keydown', tratarTeclado);
    window.addEventListener('resize', sincronizarEstadoResponsivo, { passive: true });
}


/* ==========================================================================
   MOBILE — ABRIR / FECHAR
========================================================================== */

export function abrirSidebarMobile() {
    if (!sidebar || !ehMobile()) return;

    removerEstadoVisualCollapse();

    sidebar.classList.add('is-open');
    sidebar.setAttribute('aria-hidden', 'false');

    if (backdrop) {
        backdrop.hidden = false;
        backdrop.setAttribute('aria-hidden', 'false');
    }

    openButton?.setAttribute('aria-expanded', 'true');
    document.body.classList.add('np-sidebar-open');

    requestAnimationFrame(() => {
        const primeiro = sidebar.querySelector('.np-nav__item.is-active, .np-nav__item');
        primeiro?.focus({ preventScroll: true });
    });
}


export function fecharSidebarMobile() {
    if (!sidebar) return;

    const estavaAberta = sidebar.classList.contains('is-open');

    sidebar.classList.remove('is-open');

    if (ehMobile()) sidebar.setAttribute('aria-hidden', 'true');
    else sidebar.removeAttribute('aria-hidden');

    if (backdrop) {
        backdrop.hidden = true;
        backdrop.setAttribute('aria-hidden', 'true');
    }

    openButton?.setAttribute('aria-expanded', 'false');
    document.body.classList.remove('np-sidebar-open');

    if (estavaAberta && ehMobile()) openButton?.focus({ preventScroll: true });
}


export function alternarSidebarMobile() {
    if (!sidebar || !ehMobile()) return;
    sidebar.classList.contains('is-open') ? fecharSidebarMobile() : abrirSidebarMobile();
}


/* ==========================================================================
   DESKTOP — RECOLHER / EXPANDIR
========================================================================== */

export function colapsarSidebar() {
    if (!sidebar || ehMobile()) return false;

    desktopCollapsed = true;
    aplicarEstadoCollapse(true);
    salvarPreferenciaCollapse(true);
    return true;
}


export function expandirSidebar() {
    if (!sidebar || ehMobile()) return false;

    desktopCollapsed = false;
    aplicarEstadoCollapse(false);
    salvarPreferenciaCollapse(false);
    return true;
}


export function alternarSidebarDesktop() {
    if (!sidebar || ehMobile()) return false;
    return desktopCollapsed ? expandirSidebar() : colapsarSidebar();
}


function aplicarEstadoCollapse(colapsada) {
    if (!sidebar) return;

    sidebar.classList.toggle('is-collapsed', colapsada);
    document.documentElement.classList.toggle('np-sidebar-collapsed', colapsada);

    collapseButton?.setAttribute('aria-expanded', colapsada ? 'false' : 'true');
    collapseButton?.setAttribute('aria-label', colapsada ? 'Expandir barra lateral' : 'Recolher barra lateral');
    collapseButton?.setAttribute('title', colapsada ? 'Expandir barra lateral' : 'Recolher barra lateral');

    sidebar.dispatchEvent(new CustomEvent('moonshield:sidebar-collapse', {
        bubbles: true,
        detail: { collapsed: colapsada },
    }));
}


function removerEstadoVisualCollapse() {
    sidebar?.classList.remove('is-collapsed');
    document.documentElement.classList.remove('np-sidebar-collapsed');
}


/* ==========================================================================
   PERSISTÊNCIA
========================================================================== */

function lerPreferenciaCollapse() {
    try {
        return localStorage.getItem(COLLAPSE_STORAGE_KEY) === 'true';
    } catch (error) {
        console.warn('[MoonShield Network] Falha ao ler estado da sidebar:', error);
        return false;
    }
}


function salvarPreferenciaCollapse(colapsada) {
    try {
        localStorage.setItem(COLLAPSE_STORAGE_KEY, colapsada ? 'true' : 'false');
    } catch (error) {
        console.warn('[MoonShield Network] Falha ao salvar estado da sidebar:', error);
    }
}


/* ==========================================================================
   ITEM ATIVO
========================================================================== */

export function definirItemAtivo(secao) {
    navItems.forEach(item => {
        const ativo = item.dataset.section === secao;

        item.classList.toggle('is-active', ativo);

        if (ativo) item.setAttribute('aria-current', 'page');
        else item.removeAttribute('aria-current');
    });
}


export function obterItemAtivo() {
    return navItems.find(item => item.classList.contains('is-active')) || null;
}


/* ==========================================================================
   RESPONSIVIDADE
========================================================================== */

function sincronizarEstadoResponsivo() {
    if (!sidebar) return;

    if (ehMobile()) {
        removerEstadoVisualCollapse();

        if (!sidebar.classList.contains('is-open')) sidebar.setAttribute('aria-hidden', 'true');

        openButton?.setAttribute('aria-expanded', sidebar.classList.contains('is-open') ? 'true' : 'false');
        collapseButton?.setAttribute('aria-hidden', 'true');
        return;
    }

    sidebar.classList.remove('is-open');
    sidebar.removeAttribute('aria-hidden');

    if (backdrop) {
        backdrop.hidden = true;
        backdrop.setAttribute('aria-hidden', 'true');
    }

    openButton?.setAttribute('aria-expanded', 'false');
    document.body.classList.remove('np-sidebar-open');
    collapseButton?.removeAttribute('aria-hidden');
    aplicarEstadoCollapse(desktopCollapsed);
}


function ehMobile() {
    return window.innerWidth <= MOBILE_BREAKPOINT;
}


/* ==========================================================================
   TECLADO
========================================================================== */

function tratarTeclado(event) {
    if (event.key !== 'Escape') return;

    if (ehMobile() && sidebar?.classList.contains('is-open')) {
        event.preventDefault();
        fecharSidebarMobile();
    }
}


/* ==========================================================================
   ESTADO
========================================================================== */

export function sidebarAberta() {
    return Boolean(sidebar?.classList.contains('is-open'));
}


export function sidebarEhMobile() {
    return ehMobile();
}


export function sidebarColapsada() {
    return !ehMobile() && desktopCollapsed;
}


/* ==========================================================================
   EXPORT DEFAULT
========================================================================== */

export default {
    inicializarBarraLateral,
    abrirSidebarMobile,
    fecharSidebarMobile,
    alternarSidebarMobile,
    colapsarSidebar,
    expandirSidebar,
    alternarSidebarDesktop,
    definirItemAtivo,
    obterItemAtivo,
    sidebarAberta,
    sidebarEhMobile,
    sidebarColapsada,
};
