import {
    APP
} from './estado.js';


/* ==========================================================================
   PAYLOAD INICIAL
   ========================================================================== */

export function normalizeInitialPayload(
    value
) {
    if (!value) {
        return {};
    }

    if (
        typeof value === 'object'
    ) {
        return value;
    }

    if (
        typeof value !== 'string'
    ) {
        return {};
    }

    try {
        return JSON.parse(
            value
        );

    } catch (error) {
        console.error(
            '[MoonShield] Não foi possível interpretar payload inicial:',
            error
        );

        return {};
    }
}


/* ==========================================================================
   TIPOS SEGUROS
   ========================================================================== */

export function safeObject(
    value
) {
    return (
        value &&
        typeof value === 'object' &&
        !Array.isArray(value)
    )
        ? value
        : {};
}


export function safeArray(
    value
) {
    return Array.isArray(value)
        ? value
        : [];
}


/* ==========================================================================
   LEITURA DEFENSIVA
   ========================================================================== */

export function readPath(
    source,
    paths,
    fallback = undefined
) {
    for (const path of paths) {
        const segments =
            String(path)
                .split('.');

        let value =
            source;

        for (
            const segment
            of segments
        ) {
            if (
                value === null ||
                value === undefined ||
                typeof value !== 'object' ||
                !(segment in value)
            ) {
                value =
                    undefined;

                break;
            }

            value =
                value[segment];
        }

        if (
            value !== undefined &&
            value !== null
        ) {
            return value;
        }
    }

    return fallback;
}


/* ==========================================================================
   CONVERSÕES
   ========================================================================== */

export function boolValue(
    value,
    fallback = false
) {
    if (
        typeof value === 'boolean'
    ) {
        return value;
    }

    if (
        typeof value === 'number'
    ) {
        return value !== 0;
    }

    if (
        typeof value === 'string'
    ) {
        const normalized =
            value
                .trim()
                .toLowerCase();

        if (
            [
                'true',
                '1',
                'sim',
                'yes',
                'ativo',
                'ok',
                'saudavel',
                'saudável'
            ].includes(normalized)
        ) {
            return true;
        }

        if (
            [
                'false',
                '0',
                'não',
                'nao',
                'no',
                'inativo',
                'erro',
                'error'
            ].includes(normalized)
        ) {
            return false;
        }
    }

    return fallback;
}


export function numberValue(
    value,
    fallback = 0
) {
    const parsed =
        Number(value);

    return Number.isFinite(parsed)
        ? parsed
        : fallback;
}


export function textValue(
    value,
    fallback = '—'
) {
    if (
        value === null ||
        value === undefined ||
        value === ''
    ) {
        return fallback;
    }

    if (
        typeof value === 'boolean'
    ) {
        return value
            ? 'Sim'
            : 'Não';
    }

    return String(value);
}


/* ==========================================================================
   TEXTO
   ========================================================================== */

export function capitalize(
    value
) {
    const text =
        String(value || '')
            .trim();

    if (!text) {
        return '';
    }

    return (
        text
            .charAt(0)
            .toUpperCase() +
        text.slice(1)
    );
}


/* ==========================================================================
   SEGURANÇA HTML
   ========================================================================== */

export function escapeHTML(
    value
) {
    const div =
        document.createElement(
            'div'
        );

    div.textContent =
        textValue(
            value,
            ''
        );

    return div.innerHTML;
}


/* ==========================================================================
   DATA
   ========================================================================== */

export function formatDate(
    value,
    options = {}
) {
    if (!value) {
        return '—';
    }

    const date =
        value instanceof Date
            ? value
            : new Date(value);

    if (
        Number.isNaN(
            date.getTime()
        )
    ) {
        return textValue(
            value
        );
    }

    try {
        return new Intl.DateTimeFormat(
            'pt-BR',
            {
                dateStyle:
                    options.dateStyle ||
                    'short',

                timeStyle:
                    options.timeStyle ||
                    'medium'
            }
        ).format(date);

    } catch (error) {
        return date.toLocaleString(
            'pt-BR'
        );
    }
}


/* ==========================================================================
   TEMPO RELATIVO
   ========================================================================== */

export function formatRelativeTime(
    value
) {
    if (!value) {
        return 'agora';
    }

    const date =
        value instanceof Date
            ? value
            : new Date(value);

    if (
        Number.isNaN(
            date.getTime()
        )
    ) {
        return 'agora';
    }

    const diffSeconds =
        Math.round(
            (
                date.getTime() -
                Date.now()
            ) / 1000
        );

    const absolute =
        Math.abs(
            diffSeconds
        );

    let unit =
        'second';

    let divisor =
        1;


    if (
        absolute >= 86400
    ) {
        unit =
            'day';

        divisor =
            86400;

    } else if (
        absolute >= 3600
    ) {
        unit =
            'hour';

        divisor =
            3600;

    } else if (
        absolute >= 60
    ) {
        unit =
            'minute';

        divisor =
            60;
    }


    try {
        return new Intl.RelativeTimeFormat(
            'pt-BR',
            {
                numeric:
                    'auto'
            }
        ).format(
            Math.round(
                diffSeconds /
                divisor
            ),
            unit
        );

    } catch (error) {
        return formatDate(
            date
        );
    }
}


/* ==========================================================================
   DURAÇÃO
   ========================================================================== */

export function formatDuration(
    seconds
) {
    const value =
        numberValue(
            seconds,
            -1
        );

    if (
        value < 0
    ) {
        return '—';
    }

    if (
        value < 60
    ) {
        return `${Math.round(value)}s`;
    }

    const minutes =
        Math.floor(
            value / 60
        );

    const remainingSeconds =
        Math.round(
            value % 60
        );

    if (
        minutes < 60
    ) {
        return (
            `${minutes}m ` +
            `${remainingSeconds}s`
        );
    }

    const hours =
        Math.floor(
            minutes / 60
        );

    const remainingMinutes =
        minutes % 60;

    return (
        `${hours}h ` +
        `${remainingMinutes}m`
    );
}


/* ==========================================================================
   BYTES
   ========================================================================== */

export function formatBytes(
    bytes
) {
    const value =
        numberValue(
            bytes,
            -1
        );

    if (
        value < 0
    ) {
        return '—';
    }

    if (
        value === 0
    ) {
        return '0 B';
    }

    const units = [
        'B',
        'KB',
        'MB',
        'GB',
        'TB'
    ];

    const index =
        Math.min(
            Math.floor(
                Math.log(value) /
                Math.log(1024)
            ),
            units.length - 1
        );

    const result =
        value /
        Math.pow(
            1024,
            index
        );

    const decimals =
        index === 0
            ? 0
            : result >= 10
                ? 1
                : 2;

    return (
        `${result.toFixed(decimals)} ` +
        `${units[index]}`
    );
}


/* ==========================================================================
   BOOLEAN
   ========================================================================== */

export function formatBoolean(
    value,
    yes = 'Sim',
    no = 'Não'
) {
    if (
        value === null ||
        value === undefined
    ) {
        return '—';
    }

    return boolValue(value)
        ? yes
        : no;
}


/* ==========================================================================
   CAPTURA
   ========================================================================== */

export function formatCaptureMode(
    value
) {
    const labels = {
        lan:
            'Somente LAN',

        lan_wan:
            'LAN + WAN',

        personalizado:
            'Personalizado',

        af_packet:
            'AF_PACKET',

        afpacket:
            'AF_PACKET'
    };

    const key =
        String(
            value ||
            ''
        )
            .trim()
            .toLowerCase();

    return (
        labels[key] ||
        textValue(value)
    );
}


/* ==========================================================================
   URL DINÂMICA
   ========================================================================== */

export function sanitizeUrl(
    template,
    id
) {
    if (!template) {
        return '';
    }

    return String(template)
        .replace(
            '__ID__',
            encodeURIComponent(
                String(id || '')
            )
        );
}


/* ==========================================================================
   COOKIE
   ========================================================================== */

export function getCookie(
    name
) {
    const cookies =
        document.cookie
            ? document.cookie.split(';')
            : [];

    for (
        const cookie
        of cookies
    ) {
        const [
            key,
            ...rest
        ] =
            cookie
                .trim()
                .split('=');

        if (
            key === name
        ) {
            return decodeURIComponent(
                rest.join('=')
            );
        }
    }

    return null;
}


/* ==========================================================================
   CSRF
   ========================================================================== */

export function csrfToken() {
    return (
        APP.csrfToken ||
        getCookie(
            'csrftoken'
        ) ||
        ''
    );
}