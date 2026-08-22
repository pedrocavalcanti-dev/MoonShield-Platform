/**
 * MoonShield Network Panel
 * Utilitários
 *
 * Funções puras compartilhadas pelo frontend.
 */

'use strict';


/* ==========================================================================
   VALORES
========================================================================== */

export function valorOuTraco(valor, fallback = '—') {
    return valor === undefined || valor === null || valor === '' ? fallback : valor;
}


export function paraNumero(valor, fallback = 0) {
    if (valor === undefined || valor === null || valor === '') return fallback;

    const numero = Number(valor);
    return Number.isFinite(numero) ? numero : fallback;
}


export function paraInteiro(valor, fallback = 0) {
    const numero = paraNumero(valor, NaN);
    return Number.isFinite(numero) ? Math.trunc(numero) : fallback;
}


export function limitarNumero(valor, minimo, maximo) {
    const numero = Number(valor);
    if (!Number.isFinite(numero)) return minimo;

    return Math.min(Math.max(numero, minimo), maximo);
}


export function paraBooleano(valor, fallback = false) {
    if (typeof valor === 'boolean') return valor;
    if (typeof valor === 'number') return valor !== 0;
    if (valor === undefined || valor === null || valor === '') return fallback;

    const texto = String(valor).trim().toLowerCase();

    if (['true', '1', 'yes', 'sim', 'on', 'enabled', 'ativo'].includes(texto)) return true;
    if (['false', '0', 'no', 'nao', 'não', 'off', 'disabled', 'inativo'].includes(texto)) return false;

    return fallback;
}


/* ==========================================================================
   DATA
========================================================================== */

export function paraData(valor) {
    if (!valor) return null;

    if (valor instanceof Date) return Number.isNaN(valor.getTime()) ? null : valor;

    const data = new Date(valor);
    return Number.isNaN(data.getTime()) ? null : data;
}


export function formatarHorario(valor = new Date()) {
    const data = paraData(valor);
    if (!data) return '—';

    return new Intl.DateTimeFormat('pt-BR', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
    }).format(data);
}


export function formatarHorarioCurto(valor = new Date()) {
    const data = paraData(valor);
    if (!data) return '—';

    return new Intl.DateTimeFormat('pt-BR', {
        hour: '2-digit',
        minute: '2-digit',
    }).format(data);
}


export function formatarData(valor) {
    const data = paraData(valor);
    if (!data) return '—';

    return new Intl.DateTimeFormat('pt-BR', {
        day: '2-digit',
        month: '2-digit',
        year: 'numeric',
    }).format(data);
}


export function formatarDataHora(valor) {
    const data = paraData(valor);
    if (!data) return '—';

    return new Intl.DateTimeFormat('pt-BR', {
        day: '2-digit',
        month: '2-digit',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
    }).format(data);
}


export function formatarDataHoraCurta(valor) {
    const data = paraData(valor);
    if (!data) return '—';

    return new Intl.DateTimeFormat('pt-BR', {
        day: '2-digit',
        month: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
    }).format(data);
}


/* ==========================================================================
   TEMPO
========================================================================== */

export function formatarDuracaoSegundos(segundos) {
    segundos = Math.max(0, paraInteiro(segundos, 0));

    const horas = Math.floor(segundos / 3600);
    const minutos = Math.floor((segundos % 3600) / 60);
    const restante = segundos % 60;

    if (horas > 0) return `${horas}h ${String(minutos).padStart(2, '0')}m ${String(restante).padStart(2, '0')}s`;
    if (minutos > 0) return `${minutos}m ${String(restante).padStart(2, '0')}s`;

    return `${restante}s`;
}


export function formatarContagemRegressiva(segundos) {
    segundos = Math.max(0, Math.ceil(paraNumero(segundos, 0)));

    const horas = Math.floor(segundos / 3600);
    const minutos = Math.floor((segundos % 3600) / 60);
    const restante = segundos % 60;

    if (horas > 0) {
        return `${String(horas).padStart(2, '0')}:${String(minutos).padStart(2, '0')}:${String(restante).padStart(2, '0')}`;
    }

    return `${String(minutos).padStart(2, '0')}:${String(restante).padStart(2, '0')}`;
}


export function segundosAte(valor) {
    const data = paraData(valor);
    if (!data) return 0;

    return Math.max(0, Math.ceil((data.getTime() - Date.now()) / 1000));
}


/* ==========================================================================
   TEXTO
========================================================================== */

export function textoSeguro(valor, fallback = '') {
    return valor === undefined || valor === null ? fallback : String(valor);
}


export function capitalizar(valor) {
    const texto = textoSeguro(valor).trim();
    return texto ? texto.charAt(0).toUpperCase() + texto.slice(1) : '';
}


export function truncarTexto(valor, limite = 80, sufixo = '…') {
    const texto = textoSeguro(valor);

    if (texto.length <= limite) return texto;
    return `${texto.slice(0, Math.max(0, limite - sufixo.length))}${sufixo}`;
}


export function escaparHtml(valor) {
    return textoSeguro(valor)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#039;');
}


/* ==========================================================================
   JSON
========================================================================== */

export function formatarJson(valor, fallback = '{}') {
    if (valor === undefined || valor === null) return fallback;
    if (typeof valor === 'string') return valor;

    try {
        return JSON.stringify(valor, null, 2);
    } catch {
        return fallback;
    }
}


/* ==========================================================================
   IPv4 / CIDR — APRESENTAÇÃO
========================================================================== */

export function formatarIpv4(endereco, prefixo = null) {
    if (!endereco) return '—';
    return prefixo === undefined || prefixo === null || prefixo === '' ? String(endereco) : `${endereco}/${prefixo}`;
}


export function separarCidr(cidr) {
    const texto = textoSeguro(cidr).trim();

    if (!texto.includes('/')) {
        return {
            endereco: texto || null,
            prefixo: null,
        };
    }

    const [endereco, prefixo] = texto.split('/', 2);

    return {
        endereco: endereco || null,
        prefixo: prefixo !== undefined ? paraInteiro(prefixo, null) : null,
    };
}


/* ==========================================================================
   RÓTULOS — INTERFACES
========================================================================== */

const ROTULOS_PAPEL = {
    unassigned: 'Não atribuída',
    wan: 'WAN',
    lan: 'LAN',
    mgmt: 'Gerenciamento',
    dmz: 'DMZ',
    custom: 'Personalizada',
};


const ROTULOS_IPV4 = {
    dhcp: 'DHCP',
    static: 'Estático',
    disabled: 'Desativado',
};


const ROTULOS_BACKEND = {
    unknown: 'Desconhecido',
    networkmanager: 'NetworkManager',
    networkd: 'systemd-networkd',
    ifupdown: 'ifupdown',
    runtime: 'Runtime',
};


export function rotuloPapel(valor) {
    return ROTULOS_PAPEL[valor] || capitalizar(valor || 'Não atribuída');
}


export function rotuloModoIpv4(valor) {
    return ROTULOS_IPV4[valor] || capitalizar(valor || 'Desconhecido');
}


export function rotuloBackend(valor) {
    return ROTULOS_BACKEND[valor] || valorOuTraco(valor);
}


/* ==========================================================================
   RÓTULOS — ALTERAÇÕES
========================================================================== */

const ROTULOS_STATUS_ALTERACAO = {
    created: 'Criada',
    validating: 'Validando',
    applying: 'Aplicando',
    waiting_confirmation: 'Aguardando confirmação',
    confirmed: 'Confirmada',
    rollback: 'Rollback',
    reverted: 'Revertida',
    failed: 'Falhou',
    cancelled: 'Cancelada',
};


const ROTULOS_TIPO_ALTERACAO = {
    interface: 'Interface',
    routing: 'Roteamento',
    nat: 'NAT',
    route: 'Rota',
    general: 'Geral',
};


export function rotuloStatusAlteracao(valor) {
    return ROTULOS_STATUS_ALTERACAO[valor] || capitalizar(valor || 'Desconhecido');
}


export function rotuloTipoAlteracao(valor) {
    return ROTULOS_TIPO_ALTERACAO[valor] || capitalizar(valor || 'Desconhecido');
}


/* ==========================================================================
   STATUS VISUAL
========================================================================== */

export function nivelVisualStatus(valor) {
    const status = textoSeguro(valor).toLowerCase();

    if (['ok', 'online', 'up', 'success', 'healthy', 'confirmed', 'synced', 'sincronizado'].includes(status)) return 'ok';

    if ([
        'warning',
        'pending',
        'waiting_confirmation',
        'rollback',
        'reverted',
        'degraded',
        'pendente',
    ].includes(status)) return 'warning';

    if (['error', 'failed', 'offline', 'down', 'unhealthy', 'falhou'].includes(status)) return 'error';

    return 'pending';
}


/* ==========================================================================
   ALTERAÇÃO
========================================================================== */

export function alteracaoAguardaConfirmacao(alteracao) {
    return Boolean(alteracao && alteracao.status === 'waiting_confirmation');
}


export function alteracaoFinalizada(alteracao) {
    if (!alteracao) return true;
    return ['confirmed', 'reverted', 'failed', 'cancelled'].includes(alteracao.status);
}


/* ==========================================================================
   ERROS
========================================================================== */

export function normalizarErro(error, fallback = 'Não foi possível concluir a operação.') {
    if (!error) {
        return {
            titulo: 'Erro de rede',
            codigo: 'unknown_error',
            mensagem: fallback,
            status: 0,
            detalhes: null,
        };
    }

    if (typeof error === 'string') {
        return {
            titulo: 'Erro de rede',
            codigo: 'error',
            mensagem: error,
            status: 0,
            detalhes: null,
        };
    }

    const servidor = error.resposta?.erro || error.response?.erro || error.erro || {};

    const codigo = error.codigo || servidor.codigo || 'network_error';
    const status = Number(error.status || 0);
    const mensagem = error.mensagem || servidor.mensagem || error.message || fallback;
    const detalhes = error.detalhes ?? servidor.detalhes ?? null;

    let titulo = 'Erro de rede';

    if (status === 401) titulo = 'Sessão expirada';
    else if (status === 403) titulo = 'Operação não permitida';
    else if (status === 404) titulo = 'Recurso não encontrado';
    else if (status === 409) titulo = 'Conflito de configuração';
    else if (status === 503 || codigo.includes('indisponivel')) titulo = 'Agent indisponível';
    else if (status === 504 || codigo.includes('timeout')) titulo = 'Tempo limite excedido';
    else if (codigo.includes('valid')) titulo = 'Configuração inválida';

    return {
        titulo,
        codigo,
        mensagem,
        status,
        detalhes,
        original: error,
    };
}


/* ==========================================================================
   ASYNC
========================================================================== */

export function esperar(ms = 0) {
    return new Promise(resolve => window.setTimeout(resolve, Math.max(0, Number(ms) || 0)));
}


export function debounce(funcao, atraso = 250) {
    let timer = null;

    return function debounced(...args) {
        window.clearTimeout(timer);
        timer = window.setTimeout(() => funcao.apply(this, args), atraso);
    };
}


export function throttle(funcao, intervalo = 250) {
    let ultimaExecucao = 0;
    let timer = null;

    return function throttled(...args) {
        const agora = Date.now();
        const restante = intervalo - (agora - ultimaExecucao);

        if (restante <= 0) {
            window.clearTimeout(timer);
            timer = null;
            ultimaExecucao = agora;
            funcao.apply(this, args);
            return;
        }

        if (timer) return;

        timer = window.setTimeout(() => {
            timer = null;
            ultimaExecucao = Date.now();
            funcao.apply(this, args);
        }, restante);
    };
}


/* ==========================================================================
   CLIPBOARD
========================================================================== */

export async function copiarTexto(texto) {
    const valor = textoSeguro(texto);

    if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(valor);
        return true;
    }

    const textarea = document.createElement('textarea');
    textarea.value = valor;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';

    document.body.appendChild(textarea);
    textarea.select();

    const sucesso = document.execCommand('copy');
    textarea.remove();

    return sucesso;
}


/* ==========================================================================
   IDENTIFICADORES
========================================================================== */

export function idCurto(valor, tamanho = 8) {
    const texto = textoSeguro(valor);
    return texto.length <= tamanho ? texto : texto.slice(0, tamanho);
}


/* ==========================================================================
   ARRAYS
========================================================================== */

export function garantirArray(valor) {
    if (Array.isArray(valor)) return valor;
    if (valor === undefined || valor === null) return [];
    return [valor];
}


export function ordenarPor(lista, campo, direcao = 'asc') {
    const multiplicador = direcao === 'desc' ? -1 : 1;

    return [...garantirArray(lista)].sort((a, b) => {
        const va = a?.[campo];
        const vb = b?.[campo];

        if (va === vb) return 0;
        if (va === undefined || va === null) return 1;
        if (vb === undefined || vb === null) return -1;

        return String(va).localeCompare(String(vb), 'pt-BR', {
            numeric: true,
            sensitivity: 'base',
        }) * multiplicador;
    });
}


/* ==========================================================================
   EXPORT DEFAULT
========================================================================== */

export default {
    valorOuTraco,
    paraNumero,
    paraInteiro,
    limitarNumero,
    paraBooleano,
    paraData,
    formatarHorario,
    formatarHorarioCurto,
    formatarData,
    formatarDataHora,
    formatarDataHoraCurta,
    formatarDuracaoSegundos,
    formatarContagemRegressiva,
    segundosAte,
    textoSeguro,
    capitalizar,
    truncarTexto,
    escaparHtml,
    formatarJson,
    formatarIpv4,
    separarCidr,
    rotuloPapel,
    rotuloModoIpv4,
    rotuloBackend,
    rotuloStatusAlteracao,
    rotuloTipoAlteracao,
    nivelVisualStatus,
    alteracaoAguardaConfirmacao,
    alteracaoFinalizada,
    normalizarErro,
    esperar,
    debounce,
    throttle,
    copiarTexto,
    idCurto,
    garantirArray,
    ordenarPor,
};