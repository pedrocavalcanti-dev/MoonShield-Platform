/**
 * MoonShield Network Panel
 * Drawer
 *
 * Controla os painéis laterais/modais de configuração e detalhes.
 */

'use strict';

import { $, $$ } from '../nucleo/dom.js';

const FOCUSABLE_SELECTOR = [
    'a[href]',
    'button:not([disabled])',
    'input:not([disabled]):not([type="hidden"])',
    'select:not([disabled])',
    'textarea:not([disabled])',
    '[tabindex]:not([tabindex="-1"])',
].join(',');

let inicializado = false;
let drawerAtual = null;
let elementoFocoAnterior = null;

/* ========================================================================== 
   INICIALIZAÇÃO
========================================================================== */

export function inicializarDrawers() {
    if (inicializado) return;
    inicializado = true;

    $$('.np-drawer').forEach(drawer => prepararDrawer(drawer));

    document.addEventListener('click', tratarCliqueGlobal);
    document.addEventListener('keydown', tratarTeclado);
}

/* ========================================================================== 
   PREPARAÇÃO
========================================================================== */

function prepararDrawer(drawer) {
    if (!drawer.id) {
        console.warn('[MoonShield Network] Drawer sem ID encontrado:', drawer);
        return;
    }

    drawer.setAttribute('aria-hidden', drawer.classList.contains('is-open') ? 'false' : 'true');
    if (!drawer.classList.contains('is-open')) drawer.hidden = false;

    const painel = $('.np-drawer__panel', drawer);
    if (painel && !painel.hasAttribute('tabindex')) painel.setAttribute('tabindex', '-1');
}

/* ========================================================================== 
   ABRIR
========================================================================== */

export function abrirDrawer(drawerOuId, opcoes = {}) {
    const drawer = resolverDrawer(drawerOuId);

    if (!drawer) {
        console.warn('[MoonShield Network] Drawer não encontrado:', drawerOuId);
        return false;
    }

    if (drawerAtual && drawerAtual !== drawer) fecharDrawer(drawerAtual, { restaurarFoco: false });

    elementoFocoAnterior = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    drawerAtual = drawer;

    drawer.classList.add('is-open');
    drawer.setAttribute('aria-hidden', 'false');
    drawer.dataset.drawerOpen = 'true';

    atualizarBloqueioPagina();

    requestAnimationFrame(() => {
        const foco = opcoes.foco ? resolverElemento(opcoes.foco, drawer) : obterPrimeiroFocavel(drawer) || $('.np-drawer__panel', drawer);
        foco?.focus({ preventScroll: true });
    });

    drawer.dispatchEvent(new CustomEvent('moonshield:drawer-open', {
        bubbles: true,
        detail: { id: drawer.id },
    }));

    return true;
}

/* ========================================================================== 
   FECHAR
========================================================================== */

export function fecharDrawer(drawerOuId = drawerAtual, opcoes = {}) {
    const { restaurarFoco = true } = opcoes;
    const drawer = resolverDrawer(drawerOuId);

    if (!drawer || !drawer.classList.contains('is-open')) return false;

    drawer.classList.remove('is-open');
    drawer.setAttribute('aria-hidden', 'true');
    delete drawer.dataset.drawerOpen;

    if (drawerAtual === drawer) drawerAtual = null;

    atualizarBloqueioPagina();

    drawer.dispatchEvent(new CustomEvent('moonshield:drawer-close', {
        bubbles: true,
        detail: { id: drawer.id },
    }));

    if (restaurarFoco && elementoFocoAnterior?.isConnected) {
        requestAnimationFrame(() => elementoFocoAnterior?.focus({ preventScroll: true }));
    }

    elementoFocoAnterior = null;
    return true;
}

export function fecharTodosDrawers(opcoes = {}) {
    const abertos = $$('.np-drawer.is-open');

    abertos.forEach((drawer, indice) => {
        fecharDrawer(drawer, {
            restaurarFoco: Boolean(opcoes.restaurarFoco && indice === abertos.length - 1),
        });
    });

    drawerAtual = null;
    atualizarBloqueioPagina();
}

/* ========================================================================== 
   TOGGLE
========================================================================== */

export function alternarDrawer(drawerOuId) {
    const drawer = resolverDrawer(drawerOuId);
    if (!drawer) return false;
    return drawer.classList.contains('is-open') ? fecharDrawer(drawer) : abrirDrawer(drawer);
}

/* ========================================================================== 
   CLICK GLOBAL
========================================================================== */

function tratarCliqueGlobal(event) {
    const alvo = event.target;
    if (!(alvo instanceof Element)) return;

    const fechamento = alvo.closest([
        '[data-close-interface-drawer]',
        '[data-close-route-drawer]',
        '[data-close-nat-drawer]',
        '[data-close-change-drawer]',
        '[data-close-drawer]',
        '.np-drawer__backdrop',
    ].join(','));

    if (!fechamento) return;

    const drawer = fechamento.closest('.np-drawer');
    if (!drawer) return;

    const clicouBackdrop = fechamento.classList.contains('np-drawer__backdrop');
    if (clicouBackdrop && fechamentoExplicito(drawer)) return;

    event.preventDefault();
    fecharDrawer(drawer);
}

/* ========================================================================== 
   TECLADO
========================================================================== */

function tratarTeclado(event) {
    if (!drawerAtual?.classList.contains('is-open')) return;

    if (event.key === 'Escape') {
        if (fechamentoExplicito(drawerAtual)) {
            event.preventDefault();
            return;
        }

        event.preventDefault();
        fecharDrawer(drawerAtual);
        return;
    }

    if (event.key === 'Tab') controlarTab(event, drawerAtual);
}

/* ========================================================================== 
   FOCUS TRAP
========================================================================== */

function controlarTab(event, drawer) {
    const focaveis = obterFocaveis(drawer);

    if (!focaveis.length) {
        event.preventDefault();
        $('.np-drawer__panel', drawer)?.focus();
        return;
    }

    const primeiro = focaveis[0];
    const ultimo = focaveis.at(-1);

    if (event.shiftKey && document.activeElement === primeiro) {
        event.preventDefault();
        ultimo.focus();
        return;
    }

    if (!event.shiftKey && document.activeElement === ultimo) {
        event.preventDefault();
        primeiro.focus();
    }
}

/* ========================================================================== 
   HELPERS
========================================================================== */

function fechamentoExplicito(drawer) {
    return drawer?.dataset.closePolicy === 'explicit';
}

function resolverDrawer(drawerOuId) {
    if (!drawerOuId) return null;

    if (drawerOuId instanceof HTMLElement) {
        if (drawerOuId.classList.contains('np-drawer')) return drawerOuId;
        return drawerOuId.closest('.np-drawer');
    }

    if (typeof drawerOuId !== 'string') return null;
    if (drawerOuId.startsWith('#')) return $(drawerOuId);

    return document.getElementById(drawerOuId) || $(drawerOuId);
}

function resolverElemento(elementoOuSeletor, raiz = document) {
    if (!elementoOuSeletor) return null;
    if (elementoOuSeletor instanceof HTMLElement) return elementoOuSeletor;
    if (typeof elementoOuSeletor === 'string') return $(elementoOuSeletor, raiz);
    return null;
}

function obterFocaveis(drawer) {
    return $$(FOCUSABLE_SELECTOR, drawer).filter(elemento => {
        if (!(elemento instanceof HTMLElement)) return false;
        if (elemento.hidden) return false;

        const style = window.getComputedStyle(elemento);
        return style.display !== 'none' && style.visibility !== 'hidden';
    });
}

function obterPrimeiroFocavel(drawer) {
    return obterFocaveis(drawer)[0] || null;
}

/* ========================================================================== 
   BLOQUEIO DO BODY
========================================================================== */

function atualizarBloqueioPagina() {
    const existeDrawerAberto = Boolean($('.np-drawer.is-open'));

    document.body.classList.toggle('np-drawer-open', existeDrawerAberto);

    if (existeDrawerAberto) {
        document.body.style.overflow = 'hidden';
        return;
    }

    if (!$('.np-modal.is-open')) document.body.style.removeProperty('overflow');
}

/* ========================================================================== 
   ESTADO
========================================================================== */

export function obterDrawerAberto() {
    return drawerAtual || $('.np-drawer.is-open');
}

export function drawerAberto(drawerOuId = null) {
    if (!drawerOuId) return Boolean($('.np-drawer.is-open'));

    const drawer = resolverDrawer(drawerOuId);
    return Boolean(drawer?.classList.contains('is-open'));
}

/* ========================================================================== 
   DRAWERS CONHECIDOS
========================================================================== */

export const drawers = Object.freeze({
    interface: 'interfaceDrawer',
    rota: 'routeDrawer',
    nat: 'natDrawer',
    alteracao: 'changeDrawer',
});

export default {
    inicializarDrawers,
    abrirDrawer,
    fecharDrawer,
    fecharTodosDrawers,
    alternarDrawer,
    obterDrawerAberto,
    drawerAberto,
    drawers,
};
