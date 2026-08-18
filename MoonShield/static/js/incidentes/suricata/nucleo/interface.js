import {
    STATUS_CLASS_MAP,
    STATUS_LABELS
} from './estado.js';

import {
    capitalize,
    textValue
} from './utilitarios.js';

import {
    $,
    updateClassByPrefix
} from './dom.js';

import {
    showToast
} from '../componentes/notificacoes.js';


/* ==========================================================================
   STATUS
   ========================================================================== */

export function normalizeStatus(
    status,
    fallback = 'pending'
) {
    /*
     * Booleanos.
     */
    if (
        typeof status === 'boolean'
    ) {
        return status
            ? 'ok'
            : 'error';
    }


    const normalized =
        String(status || '')
            .trim()
            .toLowerCase();


    if (!normalized) {
        return fallback;
    }


    /*
     * Usa primeiro o mapa definido no estado global.
     */
    if (
        STATUS_CLASS_MAP?.[normalized]
    ) {
        return STATUS_CLASS_MAP[
            normalized
        ];
    }


    /*
     * Compatibilidade defensiva.
     */
    const aliases = {
        healthy: 'ok',
        saudavel: 'ok',
        'saudável': 'ok',
        success: 'ok',
        sucesso: 'ok',
        ativo: 'ok',
        active: 'ok',

        aviso: 'warning',
        warning: 'warning',
        degradado: 'warning',
        degraded: 'warning',

        pending: 'pending',
        pendente: 'pending',
        executando: 'pending',
        running: 'pending',
        verificando: 'pending',
        desconhecido: 'pending',

        erro: 'error',
        error: 'error',
        offline: 'error',
        inativo: 'error',
        inactive: 'error',
        cancelado: 'error'
    };


    return (
        aliases[normalized] ||
        fallback
    );
}


/* ==========================================================================
   LABEL DO STATUS
   ========================================================================== */

export function statusLabel(
    status,
    fallback = 'Verificando'
) {
    const normalized =
        String(status || '')
            .trim()
            .toLowerCase();


    if (!normalized) {
        return fallback;
    }


    if (
        STATUS_LABELS?.[normalized]
    ) {
        return STATUS_LABELS[
            normalized
        ];
    }


    const aliases = {
        healthy: 'Saudável',
        saudavel: 'Saudável',
        'saudável': 'Saudável',

        success: 'Sucesso',
        sucesso: 'Sucesso',

        ativo: 'Ativo',
        active: 'Ativo',

        aviso: 'Aviso',
        warning: 'Aviso',

        degradado: 'Degradado',
        degraded: 'Degradado',

        pending: 'Pendente',
        pendente: 'Pendente',

        executando: 'Executando',
        running: 'Executando',

        verificando: 'Verificando',

        desconhecido: 'Desconhecido',

        erro: 'Erro',
        error: 'Erro',

        offline: 'Offline',

        inativo: 'Inativo',
        inactive: 'Inativo',

        cancelado: 'Cancelado'
    };


    return (
        aliases[normalized] ||
        capitalize(normalized) ||
        fallback
    );
}


/* ==========================================================================
   CHIP
   ========================================================================== */

export function applyChip(
    id,
    status,
    label = null
) {
    const element =
        $(id);

    if (!element) {
        return;
    }

    const normalized =
        normalizeStatus(status);

    updateClassByPrefix(
        element,
        'sp-chip--',
        normalized
    );

    element.textContent =
        label ||
        statusLabel(status);
}


/* ==========================================================================
   STATUS PILL
   ========================================================================== */

export function applyPill(
    id,
    status,
    label = null
) {
    const element =
        $(id);

    if (!element) {
        return;
    }

    const normalized =
        normalizeStatus(status);

    updateClassByPrefix(
        element,
        'sp-status-pill--',
        normalized
    );

    element.textContent =
        label ||
        statusLabel(status);
}


/* ==========================================================================
   STATUS DOT
   ========================================================================== */

export function applyStatusDot(
    id,
    status
) {
    const element =
        $(id);

    if (!element) {
        return;
    }

    const normalized =
        normalizeStatus(status);

    updateClassByPrefix(
        element,
        'sp-status-dot--',
        normalized
    );
}


/* ==========================================================================
   ÍCONES SVG
   ========================================================================== */

export function iconSVG(
    name,
    size = 16
) {
    const paths = {
        pulse:
            '<path d="M3 12h4l2-5 4 10 2-5h6"/>',

        download:
            '<path d="M12 3v12M7 10l5 5 5-5"/><path d="M5 21h14"/>',

        settings:
            '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06A1.65 1.65 0 0 0 15 19.4a1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.6 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06A2 2 0 1 1 7.04 4.3l.06.06A1.65 1.65 0 0 0 9 4.6a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9c.12.6.65 1 1.26 1H21a2 2 0 1 1 0 4h-.09c-.61 0-1.14.4-1.51 1Z"/>',

        refresh:
            '<path d="M20 11a8.1 8.1 0 1 0 2 5.3"/><path d="M20 4v7h-7"/>',

        check:
            '<path d="m5 12 4 4L19 6"/>',

        restart:
            '<path d="M20 11a8.1 8.1 0 1 0 2 5.3"/><path d="M20 4v7h-7"/>',

        activity:
            '<path d="M3 12h4l2-5 4 10 2-5h6"/>',

        task:
            '<path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>'
    };


    const numericSize =
        Number(size) > 0
            ? Number(size)
            : 16;

    const path =
        paths[name] ||
        paths.task;


    return `
        <svg
            width="${numericSize}"
            height="${numericSize}"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="1.8"
            stroke-linecap="round"
            stroke-linejoin="round"
            aria-hidden="true"
        >
            ${path}
        </svg>
    `;
}


/* ==========================================================================
   CLIPBOARD
   ========================================================================== */

export async function copyToClipboard(
    text,
    successMessage = 'Conteúdo copiado.'
) {
    const content =
        textValue(
            text,
            ''
        );

    if (!content) {
        showToast(
            'Não há conteúdo para copiar.',
            'warning'
        );

        return false;
    }


    /*
     * API moderna.
     */
    if (
        navigator.clipboard &&
        window.isSecureContext
    ) {
        try {
            await navigator.clipboard.writeText(
                content
            );

            showToast(
                successMessage,
                'ok'
            );

            return true;

        } catch (error) {
            console.warn(
                '[MoonShield] Clipboard API indisponível, tentando fallback.',
                error
            );
        }
    }


    /*
     * Fallback para HTTP/rede local.
     *
     * Útil enquanto o MoonShield estiver acessado por:
     * http://10.x.x.x:8000
     */
    const textarea =
        document.createElement(
            'textarea'
        );

    textarea.value =
        content;

    textarea.setAttribute(
        'readonly',
        ''
    );

    textarea.style.position =
        'fixed';

    textarea.style.left =
        '-9999px';

    textarea.style.top =
        '0';

    textarea.style.opacity =
        '0';


    document.body.appendChild(
        textarea
    );

    textarea.focus();
    textarea.select();


    try {
        const copied =
            document.execCommand(
                'copy'
            );

        if (!copied) {
            throw new Error(
                'O navegador recusou a operação de cópia.'
            );
        }

        showToast(
            successMessage,
            'ok'
        );

        return true;

    } catch (error) {
        console.error(
            '[MoonShield] Falha ao copiar conteúdo:',
            error
        );

        showToast(
            'Não foi possível copiar.',
            'error'
        );

        return false;

    } finally {
        textarea.remove();
    }
}


/* ==========================================================================
   TRATAMENTO CENTRAL DE ERROS DA INTERFACE
   ========================================================================== */

export function handleError(
    error,
    options = {}
) {
    console.error(
        '[MoonShield]',
        error
    );


    const message =
        error?.payload?.mensagem ||
        error?.payload?.erro ||
        error?.payload?.detail ||
        error?.message ||
        'Ocorreu um erro inesperado.';


    const title =
        options.title ||
        'Erro';


    const duration =
        Number.isFinite(
            Number(options.duration)
        )
            ? Number(options.duration)
            : 5000;


    showToast(
        message,
        'error',
        title,
        duration
    );


    return {
        message,
        error
    };
}