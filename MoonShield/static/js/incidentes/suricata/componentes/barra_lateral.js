import {
    $,
} from '../nucleo/dom.js';


const SIDEBAR_STORAGE_KEY = (
    'moonshield_sidebar_collapsed'
);

const MOBILE_BREAKPOINT = 860;

let resizeTimer = null;


/* ==========================================================================
   INICIALIZAÇÃO
   ========================================================================== */

export function initBarraLateral() {
    restoreSidebarPreference();

    $('btnOpenSidebar')
        ?.addEventListener(
            'click',
            toggleSidebar,
        );

    $('btnCloseSidebar')
        ?.addEventListener(
            'click',
            closeSidebar,
        );

    $('sidebarBackdrop')
        ?.addEventListener(
            'click',
            closeSidebar,
        );

    /*
     * Se o usuário redimensionar desktop → mobile ou mobile → desktop,
     * normalizamos o estado sem perder a preferência salva do desktop.
     */
    window.addEventListener(
        'resize',
        handleResize,
    );

    window.addEventListener(
        'beforeunload',
        cleanupSidebar,
        {
            once: true,
        },
    );
}


/* ==========================================================================
   TOGGLE
   ========================================================================== */

export function toggleSidebar() {
    if (isMobileViewport()) {
        /*
         * No mobile o botão de menu abre/fecha o drawer.
         * O estado mobile não substitui a preferência de sidebar do desktop.
         */
        const sidebar = $(
            'panelSidebar',
        );

        if (
            sidebar?.classList.contains(
                'is-open',
            )
        ) {
            closeSidebar();
        } else {
            openSidebar();
        }

        return;
    }

    const isCollapsed = (
        document.body.classList.toggle(
            'is-sidebar-collapsed',
        )
    );

    persistCollapsedPreference(
        isCollapsed,
    );

    closeMobileSidebarOnly();
}


/* ==========================================================================
   MOBILE
   ========================================================================== */

export function openSidebar() {
    if (!isMobileViewport()) {
        /*
         * Em desktop "abrir" significa garantir que ela não esteja recolhida.
         */
        document.body.classList.remove(
            'is-sidebar-collapsed',
        );

        persistCollapsedPreference(
            false,
        );

        return;
    }

    $('panelSidebar')
        ?.classList.add(
            'is-open',
        );

    $('sidebarBackdrop')
        ?.classList.add(
            'is-open',
        );

    document.body.classList.add(
        'is-sidebar-mobile-open',
    );

    document.body.style.overflow = (
        'hidden'
    );
}


export function closeSidebar() {
    closeMobileSidebarOnly();
}


function closeMobileSidebarOnly() {
    $('panelSidebar')
        ?.classList.remove(
            'is-open',
        );

    $('sidebarBackdrop')
        ?.classList.remove(
            'is-open',
        );

    document.body.classList.remove(
        'is-sidebar-mobile-open',
    );

    document.body.style.overflow = '';
}


/* ==========================================================================
   PERSISTÊNCIA
   ========================================================================== */

function restoreSidebarPreference() {
    const collapsed = (
        readCollapsedPreference()
    );

    if (isMobileViewport()) {
        /*
         * Mobile sempre inicia fechado. A preferência desktop continua salva
         * e será reaplicada quando a janela voltar a ficar maior.
         */
        document.body.classList.remove(
            'is-sidebar-collapsed',
        );

        closeMobileSidebarOnly();

        return;
    }

    document.body.classList.toggle(
        'is-sidebar-collapsed',
        collapsed,
    );

    closeMobileSidebarOnly();
}


function readCollapsedPreference() {
    try {
        return (
            window.localStorage.getItem(
                SIDEBAR_STORAGE_KEY,
            )
            === 'true'
        );
    } catch (error) {
        console.warn(
            '[MoonShield] Não foi possível ler a preferência da sidebar:',
            error,
        );

        return false;
    }
}


function persistCollapsedPreference(
    collapsed,
) {
    try {
        window.localStorage.setItem(
            SIDEBAR_STORAGE_KEY,
            collapsed
                ? 'true'
                : 'false',
        );
    } catch (error) {
        console.warn(
            '[MoonShield] Não foi possível salvar a preferência da sidebar:',
            error,
        );
    }
}


/* ==========================================================================
   RESPONSIVIDADE
   ========================================================================== */

function isMobileViewport() {
    return (
        window.innerWidth
        <= MOBILE_BREAKPOINT
    );
}


function handleResize() {
    if (resizeTimer) {
        window.clearTimeout(
            resizeTimer,
        );
    }

    resizeTimer = window.setTimeout(
        () => {
            resizeTimer = null;

            if (isMobileViewport()) {
                document.body.classList.remove(
                    'is-sidebar-collapsed',
                );

                closeMobileSidebarOnly();

                return;
            }

            /*
             * Voltou ao desktop: recupera a preferência que o usuário tinha.
             */
            document.body.classList.toggle(
                'is-sidebar-collapsed',
                readCollapsedPreference(),
            );

            closeMobileSidebarOnly();
        },
        120,
    );
}


/* ==========================================================================
   LIMPEZA
   ========================================================================== */

function cleanupSidebar() {
    if (resizeTimer) {
        window.clearTimeout(
            resizeTimer,
        );

        resizeTimer = null;
    }

    window.removeEventListener(
        'resize',
        handleResize,
    );
}
