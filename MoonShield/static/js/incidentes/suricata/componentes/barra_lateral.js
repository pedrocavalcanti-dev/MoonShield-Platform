import { $ } from '../nucleo/dom.js';

export function initBarraLateral() {
    // Recupera a preferência do usuário (se ele já havia ocultado antes)
    const isCollapsed = localStorage.getItem('moonshield_sidebar_collapsed') === 'true';
    if (isCollapsed && window.innerWidth > 860) {
        document.body.classList.add('is-sidebar-collapsed');
    }

    $('btnOpenSidebar')?.addEventListener('click', toggleSidebar);
    $('btnCloseSidebar')?.addEventListener('click', closeSidebar);
    $('sidebarBackdrop')?.addEventListener('click', closeSidebar);
}

export function toggleSidebar() {
    const isMobile = window.innerWidth <= 860;
    
    if (isMobile) {
        // No celular, o botão de menu sempre "abre" a barra lateral
        openSidebar();
    } else {
        // No computador (desktop), ele alterna entre ocultar e mostrar
        const isCollapsed = document.body.classList.toggle('is-sidebar-collapsed');
        // Salva a preferência no navegador
        localStorage.setItem('moonshield_sidebar_collapsed', isCollapsed);
    }
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