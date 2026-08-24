/**
 * MoonShield Network Panel
 * Barra lateral
 *
 * Responsabilidades:
 * - navegação entre seções;
 * - abertura/fechamento mobile;
 * - backdrop;
 * - tecla ESC;
 * - sincronização do item ativo.
 *
 * O tema continua sendo controlado pelo script global do painel através
 * do mesmo #themeToggle, agora localizado no rodapé da sidebar.
 */

'use strict';

import { $, $$ } from '../nucleo/dom.js';

const MOBILE_BREAKPOINT = 920;

let inicializado = false;
let onNavigateCallback = null;
let sidebar = null;
let backdrop = null;
let openButton = null;
let closeButton = null;
let navItems = [];

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

    inicializado = true;
    onNavigateCallback = typeof opcoes.onNavigate === 'function' ? opcoes.onNavigate : null;
    registrarEventos();
    sincronizarEstadoResponsivo();
}

function registrarEventos() {
    openButton?.addEventListener('click', abrirSidebarMobile);
    closeButton?.addEventListener('click', fecharSidebarMobile);
    backdrop?.addEventListener('click', fecharSidebarMobile);

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

export function abrirSidebarMobile() {
    if (!sidebar || !ehMobile()) return;

    sidebar.classList.add('is-open');
    sidebar.setAttribute('aria-hidden', 'false');

    if (backdrop) {
        backdrop.hidden = false;
        backdrop.setAttribute('aria-hidden', 'false');
    }

    openButton?.setAttribute('aria-expanded', 'true');
    document.body.classList.add('np-sidebar-open');

    requestAnimationFrame(() => {
        sidebar.querySelector('.np-nav__item.is-active, .np-nav__item')?.focus({ preventScroll: true });
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

function sincronizarEstadoResponsivo() {
    if (!sidebar) return;

    if (ehMobile()) {
        if (!sidebar.classList.contains('is-open')) sidebar.setAttribute('aria-hidden', 'true');
        openButton?.setAttribute('aria-expanded', sidebar.classList.contains('is-open') ? 'true' : 'false');
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
}

function ehMobile() {
    return window.innerWidth <= MOBILE_BREAKPOINT;
}

function tratarTeclado(event) {
    if (event.key !== 'Escape' || !sidebar?.classList.contains('is-open')) return;
    event.preventDefault();
    fecharSidebarMobile();
}

export function sidebarAberta() {
    return Boolean(sidebar?.classList.contains('is-open'));
}

export function sidebarEhMobile() {
    return ehMobile();
}

export default {
    inicializarBarraLateral,
    abrirSidebarMobile,
    fecharSidebarMobile,
    alternarSidebarMobile,
    definirItemAtivo,
    obterItemAtivo,
    sidebarAberta,
    sidebarEhMobile,
};
