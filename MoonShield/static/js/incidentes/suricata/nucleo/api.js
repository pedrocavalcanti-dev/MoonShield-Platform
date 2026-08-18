import { URLS, REQUIRED_URLS } from './estado.js';
import { csrfToken } from './utilitarios.js';
import { showToast } from '../componentes/notificacoes.js';

export function apiUrl(name) {
    const value = URLS?.[name];
    if (typeof value !== 'string' || !value.trim() || value === 'undefined') {
        throw new Error(`URL da API não configurada: ${name}.`);
    }
    return value;
}

export function validatePanelContract() {
    const missing = REQUIRED_URLS.filter((name) => {
        const value = URLS?.[name];
        return typeof value !== 'string' || !value.trim() || value === 'undefined';
    });

    if (missing.length) {
        throw new Error(`Contrato do painel incompleto. URLs ausentes: ${missing.join(', ')}.`);
    }
    return true;
}

export async function fetchJSON(url, options = {}) {
    if (!url) throw new Error('URL da API não configurada.');

    const method = String(options.method || 'GET').toUpperCase();
    const headers = new Headers(options.headers || {});
    headers.set('Accept', 'application/json');

    if (options.body !== undefined && !(options.body instanceof FormData) && !headers.has('Content-Type')) {
        headers.set('Content-Type', 'application/json');
    }

    if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
        headers.set('X-CSRFToken', csrfToken());
    }

    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), options.timeout || 30000);

    let body = options.body;
    if (body !== undefined && body !== null && !(body instanceof FormData) && typeof body !== 'string') {
        body = JSON.stringify(body);
    }

    try {
        const response = await fetch(url, {
            ...options, method, headers, body, credentials: 'same-origin', signal: controller.signal,
        });

        const contentType = response.headers.get('content-type') || '';
        let payload;

        if (contentType.includes('application/json')) {
            payload = await response.json();
        } else {
            const text = await response.text();
            payload = { ok: response.ok, mensagem: text || response.statusText };
        }

        if (!response.ok) {
            const message = payload?.mensagem || payload?.erro || payload?.detail || `Erro HTTP ${response.status}.`;
            const error = new Error(message);
            error.status = response.status;
            error.payload = payload;
            throw error;
        }

        return payload;
    } catch (error) {
        if (error.name === 'AbortError') throw new Error('A solicitação excedeu o tempo limite.');
        throw error;
    } finally {
        window.clearTimeout(timeout);
    }
}

export function unwrapPayload(payload) {
    if (!payload || typeof payload !== 'object') return {};
    if (payload.dados && typeof payload.dados === 'object' && !Array.isArray(payload.dados)) return payload.dados;
    if (payload.data && typeof payload.data === 'object' && !Array.isArray(payload.data)) return payload.data;
    return payload;
}

export function handleError(error) {
    console.error(error);
    const message = error?.payload?.mensagem || error?.payload?.erro || error?.message || 'Ocorreu um erro inesperado.';
    showToast(message, 'error');
}