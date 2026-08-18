import { $ } from '../nucleo/dom.js';

export function initBarraLateral() {
    $('btnOpenSidebar')?.addEventListener('click', openSidebar);
    $('btnCloseSidebar')?.addEventListener('click', closeSidebar);
    $('sidebarBackdrop')?.addEventListener('click', closeSidebar);
}

export function openSidebar() {
    $('panelSidebar')?.classList.add('is-open');
    $('sidebarBackdrop')?.classList.add('is-open');
    document.body.style.overflow = 'hidden';
}

export function closeSidebar() {
    $('panelSidebar')?.classList.remove('is-open');
    $('sidebarBackdrop')?.classList.remove('is-open');
    document.body.style.overflow = '';
}