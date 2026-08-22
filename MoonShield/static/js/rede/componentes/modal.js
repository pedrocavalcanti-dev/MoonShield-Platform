/**
 * MoonShield Network Panel
 * Modais globais
 */

'use strict';

import { $, $$, setText, setHidden } from '../nucleo/dom.js';

const FOCUSABLE_SELECTOR = [
    'a[href]',
    'button:not([disabled])',
    'input:not([disabled]):not([type="hidden"])',
    'select:not([disabled])',
    'textarea:not([disabled])',
    '[tabindex]:not([tabindex="-1"])',
].join(',');

let inicializado = false;
let modalAtual = null;
let focoAnterior = null;
let confirmacaoAtual = null;


/* ==========================================================================
   INICIALIZAÇÃO
========================================================================== */

export function inicializarModal() {
    if (inicializado) return;
    inicializado = true;

    $$('.np-modal').forEach(modal => {
        modal.setAttribute('aria-hidden', modal.classList.contains('is-open') ? 'false' : 'true');
        const dialog = $('.np-modal__dialog', modal);
        if (dialog && !dialog.hasAttribute('tabindex')) dialog.setAttribute('tabindex', '-1');
    });

    document.addEventListener('click', tratarCliqueGlobal);
    document.addEventListener('keydown', tratarTeclado);
}

export const inicializarModais = inicializarModal;


/* ==========================================================================
   ABRIR
========================================================================== */

export function abrirModal(modalOuId, opcoes = {}) {
    const modal = resolverModal(modalOuId);
    if (!modal) {
        console.warn('[MoonShield Network] Modal não encontrado:', modalOuId);
        return false;
    }

    if (modalAtual && modalAtual !== modal && opcoes.fecharOutros !== false) {
        fecharModal(modalAtual, { restaurarFoco: false });
    }

    focoAnterior = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    modalAtual = modal;

    modal.classList.add('is-open');
    modal.setAttribute('aria-hidden', 'false');
    modal.dataset.modalOpen = 'true';

    atualizarBloqueioPagina();

    requestAnimationFrame(() => {
        const foco = opcoes.foco ? resolverElemento(opcoes.foco, modal) : obterPrimeiroFocavel(modal) || $('.np-modal__dialog', modal);
        foco?.focus({ preventScroll: true });
    });

    modal.dispatchEvent(new CustomEvent('moonshield:modal-open', {
        bubbles: true,
        detail: { id: modal.id },
    }));

    return true;
}


/* ==========================================================================
   FECHAR
========================================================================== */

export function fecharModal(modalOuId = modalAtual, opcoes = {}) {
    const { restaurarFoco = true } = opcoes;
    const modal = resolverModal(modalOuId);

    if (!modal || !modal.classList.contains('is-open')) return false;

    modal.classList.remove('is-open');
    modal.setAttribute('aria-hidden', 'true');
    delete modal.dataset.modalOpen;

    if (modalAtual === modal) modalAtual = null;

    atualizarBloqueioPagina();

    modal.dispatchEvent(new CustomEvent('moonshield:modal-close', {
        bubbles: true,
        detail: { id: modal.id },
    }));

    if (restaurarFoco && focoAnterior?.isConnected) {
        requestAnimationFrame(() => focoAnterior?.focus({ preventScroll: true }));
    }

    focoAnterior = null;
    return true;
}


export function fecharTodosModais(opcoes = {}) {
    const abertos = $$('.np-modal.is-open');

    abertos.forEach((modal, indice) => {
        fecharModal(modal, {
            restaurarFoco: Boolean(opcoes.restaurarFoco && indice === abertos.length - 1),
        });
    });

    modalAtual = null;
    atualizarBloqueioPagina();
}


/* ==========================================================================
   CONFIRMAÇÃO
========================================================================== */

export function confirmarModal(opcoes = {}) {
    inicializarModal();

    if (confirmacaoAtual) {
        confirmacaoAtual.resolve(false);
        confirmacaoAtual = null;
    }

    const modal = $('#confirmModal');
    const titulo = $('#confirmModalTitle');
    const mensagem = $('#confirmModalMessage');
    const detalhes = $('#confirmModalDetails');
    const confirmar = $('#confirmModalConfirmButton');
    const cancelar = $('#confirmModalCancelButton');

    if (!modal || !confirmar || !cancelar) return Promise.resolve(false);

    setText(titulo, opcoes.titulo || 'Confirmar operação');
    setText(mensagem, opcoes.mensagem || 'Deseja realmente continuar?');

    if (opcoes.detalhes) {
        setText(detalhes, opcoes.detalhes);
        setHidden(detalhes, false);
    } else {
        setText(detalhes, '');
        setHidden(detalhes, true);
    }

    confirmar.textContent = opcoes.textoConfirmar || 'Confirmar';
    cancelar.textContent = opcoes.textoCancelar || 'Cancelar';

    confirmar.classList.remove('np-btn--danger', 'np-btn--primary');
    confirmar.classList.add(opcoes.perigoso === false ? 'np-btn--primary' : 'np-btn--danger');

    abrirModal(modal, { foco: confirmar });

    return new Promise(resolve => {
        let concluido = false;

        const finalizar = resultado => {
            if (concluido) return;
            concluido = true;

            confirmar.removeEventListener('click', confirmarHandler);
            cancelar.removeEventListener('click', cancelarHandler);
            modal.removeEventListener('moonshield:modal-close', fecharHandler);

            confirmacaoAtual = null;
            fecharModal(modal);
            resolve(Boolean(resultado));
        };

        const confirmarHandler = () => finalizar(true);
        const cancelarHandler = () => finalizar(false);

        const fecharHandler = () => {
            if (!concluido) finalizar(false);
        };

        confirmar.addEventListener('click', confirmarHandler);
        cancelar.addEventListener('click', cancelarHandler);
        modal.addEventListener('moonshield:modal-close', fecharHandler, { once: true });

        confirmacaoAtual = { resolve: finalizar };
    });
}


/* ==========================================================================
   ERRO
========================================================================== */

export function mostrarErroModal(opcoes = {}) {
    const modal = $('#networkErrorModal');

    if (!modal) return false;

    setText($('#networkErrorTitle'), opcoes.titulo || 'Não foi possível concluir a operação');
    setText($('#networkErrorMessage'), opcoes.mensagem || 'Ocorreu um erro inesperado.');

    const detalhes = $('#networkErrorDetails');

    if (opcoes.detalhes) {
        setText(detalhes, typeof opcoes.detalhes === 'string' ? opcoes.detalhes : JSON.stringify(opcoes.detalhes, null, 2));
        setHidden(detalhes, false);
    } else {
        setHidden(detalhes, true);
    }

    return abrirModal(modal);
}


/* ==========================================================================
   CLICK GLOBAL
========================================================================== */

function tratarCliqueGlobal(event) {
    const alvo = event.target;
    if (!(alvo instanceof Element)) return;

    const fecharErro = alvo.closest('[data-close-error-modal]');
    if (fecharErro) {
        event.preventDefault();
        fecharModal(fecharErro.closest('.np-modal'));
        return;
    }

    const cancelarConfirmacao = alvo.closest('[data-confirm-modal-cancel]');
    if (cancelarConfirmacao) {
        event.preventDefault();

        if (confirmacaoAtual) {
            confirmacaoAtual.resolve(false);
            return;
        }

        fecharModal(cancelarConfirmacao.closest('.np-modal'));
    }
}


/* ==========================================================================
   TECLADO
========================================================================== */

function tratarTeclado(event) {
    if (!modalAtual?.classList.contains('is-open')) return;

    if (event.key === 'Escape') {
        if (modalAtual.id === 'networkOperationModal' || modalAtual.id === 'safeApplyModal') return;

        event.preventDefault();

        if (modalAtual.id === 'confirmModal' && confirmacaoAtual) {
            confirmacaoAtual.resolve(false);
            return;
        }

        fecharModal(modalAtual);
        return;
    }

    if (event.key === 'Tab') controlarTab(event, modalAtual);
}


/* ==========================================================================
   FOCUS TRAP
========================================================================== */

function controlarTab(event, modal) {
    const focaveis = obterFocaveis(modal);

    if (!focaveis.length) {
        event.preventDefault();
        $('.np-modal__dialog', modal)?.focus();
        return;
    }

    const primeiro = focaveis[0];
    const ultimo = focaveis.at(-1);

    if (event.shiftKey && document.activeElement === primeiro) {
        event.preventDefault();
        ultimo.focus();
    } else if (!event.shiftKey && document.activeElement === ultimo) {
        event.preventDefault();
        primeiro.focus();
    }
}


/* ==========================================================================
   HELPERS
========================================================================== */

function resolverModal(modalOuId) {
    if (!modalOuId) return null;

    if (modalOuId instanceof HTMLElement) {
        if (modalOuId.classList.contains('np-modal')) return modalOuId;
        return modalOuId.closest('.np-modal');
    }

    if (typeof modalOuId !== 'string') return null;
    if (modalOuId.startsWith('#')) return $(modalOuId);

    return document.getElementById(modalOuId) || $(modalOuId);
}


function resolverElemento(elementoOuSeletor, raiz = document) {
    if (!elementoOuSeletor) return null;
    if (elementoOuSeletor instanceof HTMLElement) return elementoOuSeletor;
    return typeof elementoOuSeletor === 'string' ? $(elementoOuSeletor, raiz) : null;
}


function obterFocaveis(modal) {
    return $$(FOCUSABLE_SELECTOR, modal).filter(elemento => {
        if (!(elemento instanceof HTMLElement) || elemento.hidden) return false;

        const style = window.getComputedStyle(elemento);
        return style.display !== 'none' && style.visibility !== 'hidden';
    });
}


function obterPrimeiroFocavel(modal) {
    return obterFocaveis(modal)[0] || null;
}


function atualizarBloqueioPagina() {
    const existeModal = Boolean($('.np-modal.is-open'));
    document.body.classList.toggle('np-modal-open', existeModal);

    if (existeModal) {
        document.body.style.overflow = 'hidden';
        return;
    }

    if (!$('.np-drawer.is-open')) document.body.style.removeProperty('overflow');
}


/* ==========================================================================
   ESTADO
========================================================================== */

export function obterModalAberto() {
    return modalAtual || $('.np-modal.is-open');
}


export function modalAberto(modalOuId = null) {
    if (!modalOuId) return Boolean($('.np-modal.is-open'));

    const modal = resolverModal(modalOuId);
    return Boolean(modal?.classList.contains('is-open'));
}


/* ==========================================================================
   EXPORT
========================================================================== */

export default {
    inicializarModal,
    inicializarModais,
    abrirModal,
    fecharModal,
    fecharTodosModais,
    confirmarModal,
    mostrarErroModal,
    obterModalAberto,
    modalAberto,
};