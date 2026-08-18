import {
    URLS,
    REQUIRED_URLS
} from './estado.js';

import {
    csrfToken
} from './utilitarios.js';


/* ==========================================================================
   URLS
   ========================================================================== */

export function apiUrl(name) {
    const value = URLS?.[name];

    if (
        typeof value !== 'string' ||
        !value.trim() ||
        value === 'undefined'
    ) {
        throw new Error(
            `URL da API não configurada: ${name}.`
        );
    }

    return value;
}


/* ==========================================================================
   CONTRATO DO PAINEL
   ========================================================================== */

export function validatePanelContract() {
    const missing = REQUIRED_URLS.filter(
        (name) => {
            const value = URLS?.[name];

            return (
                typeof value !== 'string' ||
                !value.trim() ||
                value === 'undefined'
            );
        }
    );

    if (missing.length) {
        throw new Error(
            `Contrato do painel incompleto. URLs ausentes: ${missing.join(', ')}.`
        );
    }

    return true;
}


/* ==========================================================================
   CLIENTE HTTP
   ========================================================================== */

export async function fetchJSON(
    url,
    options = {}
) {
    if (!url) {
        throw new Error(
            'URL da API não configurada.'
        );
    }

    const method = String(
        options.method || 'GET'
    ).toUpperCase();

    const headers = new Headers(
        options.headers || {}
    );

    headers.set(
        'Accept',
        'application/json'
    );


    /*
     * Content-Type somente quando o corpo não é FormData.
     */
    if (
        options.body !== undefined &&
        options.body !== null &&
        !(options.body instanceof FormData) &&
        !headers.has('Content-Type')
    ) {
        headers.set(
            'Content-Type',
            'application/json'
        );
    }


    /*
     * CSRF em operações que alteram estado.
     */
    if (
        ![
            'GET',
            'HEAD',
            'OPTIONS'
        ].includes(method)
    ) {
        const token = csrfToken();

        if (token) {
            headers.set(
                'X-CSRFToken',
                token
            );
        }
    }


    /*
     * Timeout da requisição.
     */
    const controller =
        new AbortController();

    const timeoutMs =
        Number(options.timeout) > 0
            ? Number(options.timeout)
            : 30000;

    const timeout =
        window.setTimeout(
            () => controller.abort(),
            timeoutMs
        );


    /*
     * Serialização do body.
     */
    let body =
        options.body;

    if (
        body !== undefined &&
        body !== null &&
        !(body instanceof FormData) &&
        typeof body !== 'string'
    ) {
        body =
            JSON.stringify(body);
    }


    try {
        const response =
            await fetch(
                url,
                {
                    ...options,

                    method,
                    headers,
                    body,

                    credentials:
                        'same-origin',

                    signal:
                        controller.signal
                }
            );


        const contentType =
            response.headers.get(
                'content-type'
            ) || '';

        let payload;


        /*
         * JSON
         */
        if (
            contentType.includes(
                'application/json'
            )
        ) {
            try {
                payload =
                    await response.json();

            } catch (error) {
                payload = {
                    ok: false,
                    mensagem:
                        'A API retornou JSON inválido.'
                };
            }

        } else {
            /*
             * Resposta HTML/texto.
             *
             * Isso também ajuda a identificar redirects para login
             * ou páginas de erro do Django.
             */
            const text =
                await response.text();

            payload = {
                ok:
                    response.ok,

                mensagem:
                    text ||
                    response.statusText ||
                    `HTTP ${response.status}`
            };
        }


        /*
         * Erros HTTP.
         */
        if (!response.ok) {
            const message =
                payload?.mensagem ||
                payload?.erro ||
                payload?.detail ||
                `Erro HTTP ${response.status}.`;

            const error =
                new Error(message);

            error.status =
                response.status;

            error.payload =
                payload;

            error.url =
                response.url;

            throw error;
        }


        return payload;

    } catch (error) {
        /*
         * Timeout.
         */
        if (
            error?.name ===
            'AbortError'
        ) {
            const timeoutError =
                new Error(
                    'A solicitação excedeu o tempo limite.'
                );

            timeoutError.code =
                'REQUEST_TIMEOUT';

            throw timeoutError;
        }


        throw error;

    } finally {
        window.clearTimeout(
            timeout
        );
    }
}


/* ==========================================================================
   NORMALIZAÇÃO DO PAYLOAD
   ========================================================================== */

export function unwrapPayload(
    payload
) {
    if (
        !payload ||
        typeof payload !== 'object'
    ) {
        return {};
    }


    /*
     * Contrato atual do Django:
     *
     * {
     *     ok: true,
     *     mensagem: "...",
     *     dados: {...}
     * }
     */
    if (
        payload.dados &&
        typeof payload.dados === 'object' &&
        !Array.isArray(payload.dados)
    ) {
        return payload.dados;
    }


    /*
     * Compatibilidade com respostas usando "data".
     */
    if (
        payload.data &&
        typeof payload.data === 'object' &&
        !Array.isArray(payload.data)
    ) {
        return payload.data;
    }


    return payload;
}


/* ==========================================================================
   COMPATIBILIDADE

   handleError pertence conceitualmente a interface.js.

   Este re-export existe somente para não quebrar módulos que ainda tenham:

   import { handleError } from './api.js';

   Novos módulos devem importar diretamente de interface.js.
   ========================================================================== */

export {
    handleError
} from './interface.js';