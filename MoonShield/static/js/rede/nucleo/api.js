/**
 * MoonShield Network Panel
 * Núcleo HTTP
 *
 * Toda comunicação com a API Django deve passar por este módulo.
 */

'use strict';

const painelConfig = window.MS_NETWORK_PANEL || {};
const DEFAULT_TIMEOUT = 20000;
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE']);

export class ApiError extends Error {
    constructor(message, options = {}) {
        super(message || 'Erro na comunicação com o servidor.');
        this.name = 'ApiError';
        this.codigo = options.codigo || 'api_error';
        this.status = Number(options.status || 0);
        this.detalhes = options.detalhes ?? null;
        this.resposta = options.resposta ?? null;
        this.url = options.url || null;
        this.metodo = options.metodo || null;
        this.causa = options.causa || null;
    }

    get naoAutenticado() {
        return this.status === 401;
    }

    get proibido() {
        return this.status === 403;
    }

    get naoEncontrado() {
        return this.status === 404;
    }

    get conflito() {
        return this.status === 409;
    }

    get indisponivel() {
        return this.status === 503 || this.codigo === 'agent_indisponivel';
    }

    get timeout() {
        return this.status === 504 || this.codigo === 'request_timeout';
    }
}


/* ==========================================================================
   CONFIGURAÇÃO
========================================================================== */

const urls = Object.freeze({ ...(painelConfig.urls || {}) });

function obterCsrfToken() {
    if (painelConfig.csrfToken && painelConfig.csrfToken !== 'NOTPROVIDED') return painelConfig.csrfToken;

    const cookie = document.cookie.split(';').map(item => item.trim()).find(item => item.startsWith('csrftoken='));
    if (!cookie) return '';

    try {
        return decodeURIComponent(cookie.substring('csrftoken='.length));
    } catch {
        return cookie.substring('csrftoken='.length);
    }
}


/* ==========================================================================
   URL
========================================================================== */

function construirUrl(url, params = null) {
    if (!url) throw new ApiError('URL da API não configurada.', { codigo: 'api_url_ausente' });
    if (!params || typeof params !== 'object') return url;

    const base = new URL(url, window.location.origin);

    Object.entries(params).forEach(([chave, valor]) => {
        if (valor === undefined || valor === null || valor === '') return;

        if (Array.isArray(valor)) {
            valor.forEach(item => base.searchParams.append(chave, String(item)));
            return;
        }

        if (typeof valor === 'boolean') {
            base.searchParams.set(chave, valor ? 'true' : 'false');
            return;
        }

        base.searchParams.set(chave, String(valor));
    });

    return base.origin === window.location.origin ? `${base.pathname}${base.search}${base.hash}` : base.toString();
}


function preencherUrl(template, parametros = {}) {
    if (!template) throw new ApiError('Template de URL não configurado.', { codigo: 'api_url_template_ausente' });

    return Object.entries(parametros).reduce((url, [chave, valor]) => {
        const encoded = encodeURIComponent(String(valor));
        return url.replaceAll(`__${chave.toUpperCase()}__`, encoded).replaceAll(`{${chave}}`, encoded);
    }, template);
}


/* ==========================================================================
   BODY
========================================================================== */

function prepararBody(dados, headers) {
    if (dados === undefined || dados === null) return undefined;

    if (dados instanceof FormData || dados instanceof Blob || dados instanceof ArrayBuffer || dados instanceof URLSearchParams) {
        return dados;
    }

    if (typeof dados === 'string') {
        if (!headers.has('Content-Type')) headers.set('Content-Type', 'text/plain;charset=UTF-8');
        return dados;
    }

    if (!headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
    return JSON.stringify(dados);
}


/* ==========================================================================
   RESPOSTA
========================================================================== */

async function lerResposta(response) {
    if (response.status === 204) return null;

    const contentType = response.headers.get('content-type') || '';
    const texto = await response.text();

    if (!texto) return null;

    if (contentType.includes('application/json')) {
        try {
            return JSON.parse(texto);
        } catch (error) {
            throw new ApiError('O servidor retornou um JSON inválido.', {
                codigo: 'api_json_invalido',
                status: response.status,
                url: response.url,
                causa: error,
            });
        }
    }

    return texto;
}


function criarErroResposta(response, payload, metodo, url) {
    const erroServidor = payload && typeof payload === 'object' ? payload.erro : null;

    let mensagem = erroServidor?.mensagem || payload?.mensagem || null;
    let codigo = erroServidor?.codigo || payload?.codigo || `http_${response.status}`;
    let detalhes = erroServidor?.detalhes ?? payload?.detalhes ?? null;

    if (!mensagem) {
        const mensagens = {
            400: 'A solicitação enviada é inválida.',
            401: 'Sua sessão não está autenticada.',
            403: 'Você não possui permissão para executar esta operação.',
            404: 'O recurso solicitado não foi encontrado.',
            405: 'Método HTTP não permitido.',
            409: 'A operação entrou em conflito com o estado atual.',
            422: 'Não foi possível validar os dados enviados.',
            429: 'Muitas solicitações foram realizadas. Tente novamente em instantes.',
            500: 'O servidor encontrou um erro interno.',
            502: 'Falha na comunicação com um serviço interno.',
            503: 'O serviço necessário está indisponível.',
            504: 'A operação excedeu o tempo limite.',
        };

        mensagem = mensagens[response.status] || `Erro HTTP ${response.status}.`;
    }

    return new ApiError(mensagem, {
        codigo,
        status: response.status,
        detalhes,
        resposta: payload,
        metodo,
        url,
    });
}


/* ==========================================================================
   REQUEST
========================================================================== */

async function request(url, options = {}) {
    const metodo = String(options.method || 'GET').toUpperCase();
    const endpoint = construirUrl(url, options.params);
    const headers = new Headers(options.headers || {});
    const timeout = Number(options.timeout ?? DEFAULT_TIMEOUT);
    const controller = new AbortController();

    if (!headers.has('Accept')) headers.set('Accept', 'application/json');
    if (!headers.has('X-Requested-With')) headers.set('X-Requested-With', 'XMLHttpRequest');

    if (!SAFE_METHODS.has(metodo)) {
        const csrfToken = obterCsrfToken();
        if (csrfToken && !headers.has('X-CSRFToken')) headers.set('X-CSRFToken', csrfToken);
    }

    const body = SAFE_METHODS.has(metodo) ? undefined : prepararBody(options.body, headers);
    const timeoutId = timeout > 0 ? window.setTimeout(() => controller.abort(), timeout) : null;

    let response;

    try {
        response = await fetch(endpoint, {
            method: metodo,
            headers,
            body,
            credentials: 'same-origin',
            cache: options.cache || 'no-store',
            redirect: options.redirect || 'follow',
            signal: controller.signal,
        });
    } catch (error) {
        if (error?.name === 'AbortError') {
            throw new ApiError('A comunicação com o servidor excedeu o tempo limite.', {
                codigo: 'request_timeout',
                status: 504,
                metodo,
                url: endpoint,
                causa: error,
            });
        }

        throw new ApiError('Não foi possível comunicar com o servidor MoonShield.', {
            codigo: 'network_error',
            status: 0,
            metodo,
            url: endpoint,
            causa: error,
        });
    } finally {
        if (timeoutId) window.clearTimeout(timeoutId);
    }

    const payload = await lerResposta(response);

    if (!response.ok) throw criarErroResposta(response, payload, metodo, endpoint);

    if (payload && typeof payload === 'object' && payload.ok === false) {
        const erro = payload.erro || {};

        throw new ApiError(erro.mensagem || 'A operação não pôde ser concluída.', {
            codigo: erro.codigo || 'api_operation_error',
            status: response.status,
            detalhes: erro.detalhes ?? null,
            resposta: payload,
            metodo,
            url: endpoint,
        });
    }

    return payload;
}


/* ==========================================================================
   MÉTODOS
========================================================================== */

function get(url, params = null, options = {}) {
    return request(url, { ...options, method: 'GET', params });
}


function post(url, dados = {}, options = {}) {
    return request(url, { ...options, method: 'POST', body: dados });
}


function put(url, dados = {}, options = {}) {
    return request(url, { ...options, method: 'PUT', body: dados });
}


function patch(url, dados = {}, options = {}) {
    return request(url, { ...options, method: 'PATCH', body: dados });
}


function del(url, dados = undefined, options = {}) {
    return request(url, { ...options, method: 'DELETE', body: dados });
}


/* ==========================================================================
   HELPERS
========================================================================== */

function possuiUrl(nome) {
    return typeof urls[nome] === 'string' && urls[nome].length > 0;
}


function url(nome, parametros = null) {
    const endpoint = urls[nome];

    if (!endpoint) {
        throw new ApiError(`A URL "${nome}" não está configurada no painel.`, {
            codigo: 'api_url_nao_configurada',
        });
    }

    return parametros ? preencherUrl(endpoint, parametros) : endpoint;
}


/* ==========================================================================
   EXPORT
========================================================================== */

export const api = Object.freeze({
    urls,
    request,
    get,
    post,
    put,
    patch,
    delete: del,
    del,
    url,
    possuiUrl,
    preencherUrl,
    construirUrl,
    obterCsrfToken,
});

export default api;