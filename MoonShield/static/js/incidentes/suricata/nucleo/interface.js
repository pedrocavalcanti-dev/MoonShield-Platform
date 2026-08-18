import { STATUS_CLASS_MAP, STATUS_LABELS } from './estado.js';
import { capitalize } from './utilitarios.js';
import { $, updateClassByPrefix } from './dom.js';
import { showToast } from '../componentes/notificacoes.js';

export function normalizeStatus(status, fallback = 'pending') {
    if (typeof status === 'boolean') return status ? 'ok' : 'error';
    const normalized = String(status || '').trim().toLowerCase();
    return STATUS_CLASS_MAP[normalized] || fallback;
}

export function statusLabel(status, fallback = 'Verificando') {
    const normalized = String(status || '').trim().toLowerCase();
    return STATUS_LABELS[normalized] || capitalize(normalized) || fallback;
}

export function applyChip(id, status, label = null) {
    const element = $(id);
    if (!element) return;
    const normalized = normalizeStatus(status);
    updateClassByPrefix(element, 'sp-chip--', normalized);
    element.textContent = label || statusLabel(status);
}

export function applyPill(id, status, label = null) {
    const element = $(id);
    if (!element) return;
    const normalized = normalizeStatus(status);
    updateClassByPrefix(element, 'sp-status-pill--', normalized);
    element.textContent = label || statusLabel(status);
}

export function applyStatusDot(id, status) {
    const element = $(id);
    if (!element) return;
    const normalized = normalizeStatus(status);
    updateClassByPrefix(element, 'sp-status-dot--', normalized);
}

export function iconSVG(name, size = 16) {
    const paths = {
        pulse: '<path d="M3 12h4l2-5 4 10 2-5h6"/>',
        download: '<path d="M12 3v12M7 10l5 5 5-5"/><path d="M5 21h14"/>',
        settings: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06A1.65 1.65 0 0 0 15 19.4a1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.6 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06A2 2 0 1 1 7.04 4.3l.06.06A1.65 1.65 0 0 0 9 4.6a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9c.12.6.65 1 1.26 1H21a2 2 0 1 1 0 4h-.09c-.61 0-1.14.4-1.51 1Z"/>',
        refresh: '<path d="M20 11a8.1 8.1 0 1 0 2 5.3"/><path d="M20 4v7h-7"/>',
        check: '<path d="m5 12 4 4L19 6"/>',
        restart: '<path d="M20 11a8.1 8.1 0 1 0 2 5.3"/><path d="M20 4v7h-7"/>',
        activity: '<path d="M3 12h4l2-5 4 10 2-5h6"/>',
        task: '<path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>',
    };

    return `
        <svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
            ${paths[name] || paths.task}
        </svg>
    `;
}

export async function copyToClipboard(text, successMessage) {
    if (!text) {
        showToast('Não há conteúdo para copiar.', 'warning');
        return;
    }

    try {
        await navigator.clipboard.writeText(text);
        showToast(successMessage, 'ok');
    } catch (error) {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();

        try {
            document.execCommand('copy');
            showToast(successMessage, 'ok');
        } catch (copyError) {
            showToast('Não foi possível copiar.', 'error');
        } finally {
            textarea.remove();
        }
    }
}