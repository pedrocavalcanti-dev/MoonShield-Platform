/**
 * MoonShield Network Panel
 * Sistema de notificações / toasts
 */

'use strict';

import { $, criar } from '../nucleo/dom.js';

const CONFIG = Object.freeze({
    maximo: 5,
    duracoes: Object.freeze({ sucesso: 3500, info: 4000, aviso: 5000, erro: 7000 }),
});

const ICONES = Object.freeze({
    sucesso: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"></circle><path d="M8 12.5L10.7 15L16 9.5"></path></svg>',
    info: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"></circle><path d="M12 11V16"></path><path d="M12 8H12.01"></path></svg>',
    aviso: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.9L2.4 17.5A2 2 0 0 0 4.1 20.5H19.9A2 2 0 0 0 21.6 17.5L13.7 3.9A2 2 0 0 0 10.3 3.9Z"></path><path d="M12 9V13"></path><path d="M12 17H12.01"></path></svg>',
    erro: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"></circle><path d="M15 9L9 15"></path><path d="M9 9L15 15"></path></svg>',
});

let contador = 0;

function mostrar(tipo, titulo, mensagem = '', opcoes = {}) {
    const tipoNormalizado = normalizarTipo(tipo);
    const container = obterContainer();
    if (!container) return null;

    limitarQuantidade(container);

    const id = `np-toast-${++contador}`;
    const toast = criar('div', {
        className: `np-toast np-toast--${tipoNormalizado}`,
        attrs: {
            id,
            role: tipoNormalizado === 'erro' ? 'alert' : 'status',
            'aria-live': tipoNormalizado === 'erro' ? 'assertive' : 'polite',
            'data-toast-type': tipoNormalizado,
        },
    });

    const icone = criar('div', { className: 'np-toast__icon', attrs: { 'aria-hidden': 'true' } });
    icone.innerHTML = ICONES[tipoNormalizado] || ICONES.info;

    const copy = criar('div', { className: 'np-toast__copy' });
    const strong = criar('strong', { text: titulo || tituloPadrao(tipoNormalizado) });
    const span = criar('span', { text: mensagem || '' });
    copy.append(strong);
    if (mensagem) copy.append(span);

    const fechar = criar('button', {
        className: 'np-icon-btn np-icon-btn--small np-toast__close',
        attrs: { type: 'button', 'aria-label': 'Fechar notificação', title: 'Fechar' },
        html: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M6 6L18 18"></path><path d="M18 6L6 18"></path></svg>',
    });

    toast.append(icone, copy, fechar);
    container.appendChild(toast);

    const duracao = Number(opcoes.duracao ?? CONFIG.duracoes[tipoNormalizado] ?? 4000);
    let timer = null;
    let restante = duracao;
    let iniciadoEm = Date.now();

    const iniciarTimer = () => {
        if (opcoes.persistente || restante <= 0 || timer) return;
        iniciadoEm = Date.now();
        timer = window.setTimeout(() => removerToast(toast), restante);
    };

    const pausarTimer = () => {
        if (!timer) return;
        window.clearTimeout(timer);
        timer = null;
        restante = Math.max(0, restante - (Date.now() - iniciadoEm));
    };

    fechar.addEventListener('click', () => removerToast(toast));
    toast.addEventListener('mouseenter', pausarTimer);
    toast.addEventListener('mouseleave', iniciarTimer);
    iniciarTimer();

    return { id, elemento: toast, fechar: () => removerToast(toast) };
}

function removerToast(toast) {
    if (!(toast instanceof HTMLElement) || !toast.isConnected || toast.dataset.removendo === 'true') return;
    toast.dataset.removendo = 'true';
    toast.classList.add('is-removing');
    window.setTimeout(() => toast.remove(), 190);
}

function limitarQuantidade(container) {
    const toasts = Array.from(container.querySelectorAll('.np-toast'));
    const excesso = Math.max(0, toasts.length - CONFIG.maximo + 1);
    toasts.slice(0, excesso).forEach(removerToast);
}

export function limparNotificacoes() {
    const container = obterContainer();
    if (!container) return;
    container.querySelectorAll('.np-toast').forEach(removerToast);
}

function obterContainer() {
    let container = $('#toastContainer');
    if (container) return container;

    container = criar('div', {
        className: 'np-toasts',
        attrs: { id: 'toastContainer', 'aria-live': 'polite', 'aria-atomic': 'false' },
    });
    document.body.appendChild(container);
    return container;
}

function normalizarTipo(tipo) {
    const valor = String(tipo || 'info').trim().toLowerCase();
    const aliases = { ok: 'sucesso', success: 'sucesso', warning: 'aviso', warn: 'aviso', error: 'erro' };
    const normalizado = aliases[valor] || valor;
    return Object.prototype.hasOwnProperty.call(ICONES, normalizado) ? normalizado : 'info';
}

function tituloPadrao(tipo) {
    return ({ sucesso: 'Concluído', info: 'Informação', aviso: 'Atenção', erro: 'Erro' })[tipo] || 'MoonShield';
}

export const notificacao = Object.freeze({
    sucesso(titulo, mensagem = '', opcoes = {}) { return mostrar('sucesso', titulo, mensagem, opcoes); },
    info(titulo, mensagem = '', opcoes = {}) { return mostrar('info', titulo, mensagem, opcoes); },
    aviso(titulo, mensagem = '', opcoes = {}) { return mostrar('aviso', titulo, mensagem, opcoes); },
    erro(titulo, mensagem = '', opcoes = {}) { return mostrar('erro', titulo, mensagem, opcoes); },
    mostrar,
    limpar: limparNotificacoes,
});

export default notificacao;
