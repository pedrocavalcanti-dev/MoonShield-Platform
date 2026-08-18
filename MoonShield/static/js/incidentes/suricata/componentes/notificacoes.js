import { $ } from '../nucleo/dom.js';
import { escapeHTML } from '../nucleo/utilitarios.js';

export function showToast(message, type = 'info', title = null, duration = 5000) {
    const container = $('toastContainer');
    if (!container) return;

    const toastType = type === 'success' ? 'ok' : type === 'warn' ? 'warning' : type === 'danger' ? 'error' : type;

    const iconMap = {
        ok: '<path d="m5 12 4 4L19 6"/>',
        warning: '<path d="M10.3 2.9 1.8 17a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 2.9a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4M12 17h.01"/>',
        error: '<circle cx="12" cy="12" r="9"/><path d="m9 9 6 6M15 9l-6 6"/>',
        info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>',
    };

    const titleMap = {
        ok: 'Concluído',
        warning: 'Atenção',
        error: 'Erro',
        info: 'Informação',
    };

    const toast = document.createElement('div');
    toast.className = `sp-toast sp-toast--${toastType}`;
    toast.innerHTML = `
        <span class="sp-toast__icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                ${iconMap[toastType] || iconMap.info}
            </svg>
        </span>
        <span class="sp-toast__copy">
            <strong>${escapeHTML(title || titleMap[toastType] || titleMap.info)}</strong>
            <span>${escapeHTML(message)}</span>
        </span>
        <button class="sp-copy-btn" type="button" aria-label="Fechar">Fechar</button>
    `;

    const closeButton = toast.querySelector('button');
    const close = () => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(15px)';
        window.setTimeout(() => toast.remove(), 180);
    };

    closeButton?.addEventListener('click', close);
    container.appendChild(toast);

    if (duration > 0) {
        window.setTimeout(close, duration);
    }
}