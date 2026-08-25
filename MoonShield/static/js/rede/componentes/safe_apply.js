/**
 * MoonShield Network Panel
 * Safe Apply
 *
 * O contador é apenas visual.
 * O navegador NÃO controla o rollback real.
 * O MoonShield Agent é a autoridade do timer, confirmação e rollback.
 */

'use strict';

import { api } from '../nucleo/api.js';
import { estado } from '../nucleo/estado.js';
import { $, setText, setHidden } from '../nucleo/dom.js';
import {
    formatarContagemRegressiva,
    normalizarErro,
    rotuloTipoAlteracao,
    segundosAte,
    paraNumero,
} from '../nucleo/utilitarios.js';

import { abrirModal, fecharModal, confirmarModal } from './modal.js';
import { notificacao } from './notificacoes.js';

const POLL_INTERVAL = 4000;
const CRITICAL_SECONDS = 15;
const RECONCILIATION_RETRY = 2500;

const STATUS_ATIVOS = new Set([
    'created',
    'validating',
    'applying',
    'waiting_confirmation',
    'rollback',
]);

const STATUS_FINAIS = new Set([
    'confirmed',
    'reverted',
    'failed',
    'cancelled',
]);

let inicializado = false;
let alteracaoAtiva = null;
let reservaLocal = null;
let countdownTimer = null;
let pollTimer = null;
let processando = false;
let reconciliando = false;
let totalSegundos = 60;
let rollbackConfirmando = false;
let rollbackConfirmTimer = null;
let reconciliationTimer = null;

const elementos = {
    modal: null,
    modalTitle: null,
    changeTitle: null,
    changeType: null,
    changeId: null,
    countdown: null,
    progress: null,
    confirmButton: null,
    rollbackButton: null,

    activeCard: null,
    activeTitle: null,
    activeDescription: null,
    activeTimer: null,
    activeConfirmButton: null,
    activeRollbackButton: null,

    operationModal: null,
    operationTitle: null,
    operationDescription: null,
};


/* ==========================================================================
   INICIALIZAÇÃO
========================================================================== */

function inicializar() {
    if (inicializado) return;
    inicializado = true;

    cachearElementos();
    registrarEventos();

    const ativa = estado.get('alteracoes.ativa');
    if (ativa && alteracaoEmAndamento(ativa)) sincronizar(ativa);
    else atualizarLockGlobal();
}


function cachearElementos() {
    elementos.modal = $('#safeApplyModal');
    elementos.modalTitle = $('#safeApplyModalTitle');
    elementos.changeTitle = $('#safeApplyChangeTitle');
    elementos.changeType = $('#safeApplyChangeType');
    elementos.changeId = $('#safeApplyChangeId');
    elementos.countdown = $('#safeApplyCountdown');
    elementos.progress = $('#safeApplyProgressBar');
    elementos.confirmButton = $('#safeApplyConfirmButton');
    elementos.rollbackButton = $('#safeApplyRollbackButton');

    elementos.activeCard = $('#activeSafeChangeCard');
    elementos.activeTitle = $('#activeSafeChangeTitle');
    elementos.activeDescription = $('#activeSafeChangeDescription');
    elementos.activeTimer = $('#activeSafeChangeTimer');
    elementos.activeConfirmButton = $('#activeSafeChangeConfirmButton');
    elementos.activeRollbackButton = $('#activeSafeChangeRollbackButton');

    elementos.operationModal = $('#networkOperationModal');
    elementos.operationTitle = $('#networkOperationTitle');
    elementos.operationDescription = $('#networkOperationDescription');
}


function registrarEventos() {
    elementos.confirmButton?.addEventListener('click', confirmarAlteracao);
    elementos.activeConfirmButton?.addEventListener('click', confirmarAlteracao);
    elementos.rollbackButton?.addEventListener('click', solicitarRollback);
    elementos.activeRollbackButton?.addEventListener('click', solicitarRollback);
}


/* ==========================================================================
   LOCK / RESERVA LOCAL
========================================================================== */

function reservado() {
    return Boolean(reservaLocal);
}


function reservarOperacao(origem = 'network-operation') {
    if (ocupado()) return false;

    reservaLocal = {
        origem: String(origem || 'network-operation'),
        criadaEm: Date.now(),
    };

    estado.set('alteracoes.reservaLocal', reservaLocal);
    atualizarLockGlobal();
    emitirEvento('lock', alteracaoAtiva);

    return true;
}


function liberarReserva() {
    if (!reservaLocal) return;

    reservaLocal = null;
    estado.set('alteracoes.reservaLocal', null);
    atualizarLockGlobal();
    emitirEvento('unlock', alteracaoAtiva);
}


function ocupado() {
    return reservado() || alteracaoEmAndamento(alteracaoAtiva);
}


function atualizarLockGlobal() {
    const bloqueado = ocupado();

    estado.set('alteracoes.bloqueada', bloqueado);
    document.documentElement.classList.toggle('network-safe-apply-active', bloqueado);
    document.documentElement.dataset.networkMutationLocked = bloqueado ? 'true' : 'false';

    document.dispatchEvent(new CustomEvent('moonshield:network-lock-change', {
        detail: {
            bloqueado,
            reserva: reservaLocal,
            alteracao: alteracaoAtiva,
        },
    }));
}


/* ==========================================================================
   ABRIR / SINCRONIZAR
========================================================================== */

function abrir(alteracao, opcoes = {}) {
    if (!alteracao) return false;

    sincronizar(alteracao);

    if (!alteracaoAguardaConfirmacao(alteracao)) return false;

    if (opcoes.mostrarModal !== false && elementos.modal) {
        abrirModal(elementos.modal, { foco: elementos.confirmButton });
    }

    return true;
}


function sincronizar(alteracao) {
    if (!alteracao) {
        if (!reservado()) fechar();
        return;
    }

    const idAnterior = obterId(alteracaoAtiva);
    const idNovo = obterId(alteracao);
    const trocouAlteracao = idAnterior !== idNovo;

    alteracaoAtiva = alteracao;
    reservaLocal = null;

    estado.set('alteracoes.reservaLocal', null);
    estado.set('alteracoes.ativa', alteracao);
    atualizarLockGlobal();

    if (STATUS_FINAIS.has(statusAlteracao(alteracao))) {
        tratarAlteracaoFinalizada(alteracao);
        return;
    }

    if (!alteracaoEmAndamento(alteracao)) {
        tratarAlteracaoFinalizada(alteracao);
        return;
    }

    if (alteracaoAguardaConfirmacao(alteracao)) {
        if (trocouAlteracao || !countdownTimer) prepararTempo(alteracao);
        atualizarInterface(alteracao);
        setHidden(elementos.activeCard, false);
        iniciarCountdown();
    } else {
        pararCountdown();
        setHidden(elementos.activeCard, true);
    }

    iniciarPolling();
}


/* ==========================================================================
   UI
========================================================================== */

function atualizarInterface(alteracao) {
    const titulo = alteracao.titulo || 'Configuração de rede';
    const tipo = rotuloTipoAlteracao(alteracao.tipo);
    const id = obterId(alteracao) || '—';
    const descricao = alteracao.descricao || 'Confirme que o acesso ao MoonShield continua funcionando.';

    setText(elementos.modalTitle, 'Configuração de rede aplicada');
    setText(elementos.changeTitle, titulo);
    setText(elementos.changeType, tipo);
    setText(elementos.changeId, id);

    setText(elementos.activeTitle, titulo);
    setText(elementos.activeDescription, descricao);

    atualizarCountdownVisual();
}


/* ==========================================================================
   TEMPO
========================================================================== */

function prepararTempo(alteracao) {
    const restantes = obterSegundosRestantes(alteracao);
    const configurado = paraNumero(
        alteracao.tempo_confirmacao ??
        alteracao.timeout_confirmacao ??
        alteracao.configuracao_solicitada?.tempo_confirmacao,
        60
    );

    totalSegundos = Math.max(1, configurado, restantes);
}


function obterSegundosRestantes(alteracao) {
    if (!alteracao || !alteracaoAguardaConfirmacao(alteracao)) return 0;

    if (alteracao.segundos_restantes !== undefined && alteracao.segundos_restantes !== null) {
        return Math.max(0, Math.ceil(paraNumero(alteracao.segundos_restantes, 0)));
    }

    if (alteracao.expira_em) return segundosAte(alteracao.expira_em);

    const timeout = paraNumero(
        alteracao.tempo_confirmacao ??
        alteracao.configuracao_solicitada?.tempo_confirmacao,
        60
    );

    if (alteracao.aplicada_em) {
        const aplicada = new Date(alteracao.aplicada_em);

        if (!Number.isNaN(aplicada.getTime())) {
            const expira = new Date(aplicada.getTime() + timeout * 1000);
            return segundosAte(expira);
        }
    }

    return timeout;
}


function iniciarCountdown() {
    if (countdownTimer || !alteracaoAguardaConfirmacao(alteracaoAtiva)) return;

    atualizarCountdownVisual();

    countdownTimer = window.setInterval(() => {
        atualizarCountdownVisual();

        if (obterSegundosRestantes(alteracaoAtiva) <= 0) {
            pararCountdown();
            marcarPrazoExpirado();
            reconciliarAposExpiracao();
        }
    }, 1000);
}


function pararCountdown() {
    if (!countdownTimer) return;
    window.clearInterval(countdownTimer);
    countdownTimer = null;
}


function atualizarCountdownVisual() {
    const segundos = obterSegundosRestantes(alteracaoAtiva);
    const texto = formatarContagemRegressiva(segundos);

    setText(elementos.countdown, texto);
    setText(elementos.activeTimer, texto);

    const percentual = Math.max(
        0,
        Math.min(100, (segundos / Math.max(totalSegundos, 1)) * 100)
    );

    if (elementos.progress) elementos.progress.style.width = `${percentual}%`;

    const critico = segundos > 0 && segundos <= CRITICAL_SECONDS;
    elementos.activeCard?.classList.toggle('is-critical', critico);

    const podeConfirmar = Boolean(
        alteracaoAguardaConfirmacao(alteracaoAtiva) &&
        segundos > 0 &&
        !processando &&
        !reconciliando
    );

    if (elementos.confirmButton) elementos.confirmButton.disabled = !podeConfirmar;
    if (elementos.activeConfirmButton) elementos.activeConfirmButton.disabled = !podeConfirmar;

    const podeRollback = Boolean(
        alteracaoEmAndamento(alteracaoAtiva) &&
        !processando &&
        !reconciliando
    );

    if (elementos.rollbackButton) elementos.rollbackButton.disabled = !podeRollback;
    if (elementos.activeRollbackButton) elementos.activeRollbackButton.disabled = !podeRollback;
}


function marcarPrazoExpirado() {
    setText(elementos.countdown, '00:00');
    setText(elementos.activeTimer, '00:00');
    setText(
        elementos.activeDescription,
        'Prazo encerrado. Verificando o resultado do rollback com o MoonShield Agent.'
    );

    if (elementos.progress) elementos.progress.style.width = '0%';
    elementos.activeCard?.classList.remove('is-critical');

    if (elementos.confirmButton) elementos.confirmButton.disabled = true;
    if (elementos.activeConfirmButton) elementos.activeConfirmButton.disabled = true;
}


async function reconciliarAposExpiracao() {
    if (!alteracaoAtiva || reconciliando) return null;

    reconciliando = true;
    atualizarCountdownVisual();

    try {
        const url = urlReconciliar();
        if (url) {
            try {
                await api.post(url, {});
            } catch (error) {
                console.warn('[MoonShield Network] Reconciliação automática não respondeu:', error);
            }
        }

        const atualizada = await consultarEstadoAtual({ silencioso: true });

        if (atualizada && alteracaoEmAndamento(atualizada)) {
            agendarNovaReconciliacao();
        }

        return atualizada;
    } finally {
        reconciliando = false;
        atualizarCountdownVisual();
    }
}


function agendarNovaReconciliacao() {
    if (reconciliationTimer) return;

    reconciliationTimer = window.setTimeout(() => {
        reconciliationTimer = null;

        if (alteracaoAtiva && alteracaoEmAndamento(alteracaoAtiva)) {
            reconciliarAposExpiracao();
        }
    }, RECONCILIATION_RETRY);
}


/* ==========================================================================
   CONFIRMAR
========================================================================== */

async function confirmarAlteracao() {
    if (!alteracaoAtiva || processando || reconciliando) return false;

    const id = obterId(alteracaoAtiva);
    if (!id) {
        notificacao.erro('Alteração inválida', 'O identificador da alteração não está disponível.');
        return false;
    }

    processando = true;
    definirBotoesCarregando(true);

    try {
        const resposta = await api.post(urlAlteracao(id, 'confirmar'), {});
        const alteracao = extrairAlteracao(resposta) || { ...alteracaoAtiva, status: 'confirmed' };

        tratarAlteracaoFinalizada(alteracao);

        notificacao.sucesso(
            'Configuração confirmada',
            'A nova configuração de rede foi confirmada e o rollback foi desarmado.'
        );

        emitirEvento('confirmed', alteracao);
        await atualizarPainel();

        return true;
    } catch (error) {
        const existente = extrairAlteracaoDeErro(error);

        if (existente) {
            sincronizar(existente);

            if (statusAlteracao(existente) === 'confirmed') {
                notificacao.sucesso('Configuração confirmada', 'A alteração já estava confirmada.');
                return true;
            }

            if (STATUS_FINAIS.has(statusAlteracao(existente))) return false;
        }

        const erro = normalizarErro(error);
        notificacao.erro(erro.titulo, erro.mensagem);

        return false;
    } finally {
        processando = false;
        definirBotoesCarregando(false);
    }
}


/* ==========================================================================
   ROLLBACK
========================================================================== */

async function solicitarRollback() {
    if (!alteracaoAtiva || processando || reconciliando) return false;

    if (!rollbackConfirmando) {
        rollbackConfirmando = true;

        if (rollbackConfirmTimer) window.clearTimeout(rollbackConfirmTimer);

        [elementos.rollbackButton, elementos.activeRollbackButton].forEach(botao => {
            if (!botao) return;
            botao.classList.add('is-confirming');
            botao.textContent = 'Confirmar reversão';
        });

        setText(elementos.modalTitle, 'Confirmar reversão da configuração');
        setText(
            elementos.activeDescription,
            'Clique novamente em Confirmar reversão para restaurar o snapshot anterior.'
        );

        rollbackConfirmTimer = window.setTimeout(() => resetarConfirmacaoRollback(), 8000);
        return false;
    }

    resetarConfirmacaoRollback(false);

    return executarRollback('Rollback solicitado manualmente pelo administrador.');
}


function resetarConfirmacaoRollback(restaurarInterface = true) {
    rollbackConfirmando = false;

    if (rollbackConfirmTimer) {
        window.clearTimeout(rollbackConfirmTimer);
        rollbackConfirmTimer = null;
    }

    [elementos.rollbackButton, elementos.activeRollbackButton].forEach(botao => {
        if (!botao) return;
        botao.classList.remove('is-confirming');
        botao.textContent = 'Reverter agora';
    });

    if (restaurarInterface && alteracaoAtiva && alteracaoAguardaConfirmacao(alteracaoAtiva)) {
        atualizarInterface(alteracaoAtiva);
    }
}


async function executarRollback(motivo = 'Rollback solicitado pelo painel.') {
    if (!alteracaoAtiva || processando || reconciliando) return false;

    const id = obterId(alteracaoAtiva);
    if (!id) {
        notificacao.erro('Alteração inválida', 'O identificador da alteração não está disponível.');
        return false;
    }

    processando = true;
    definirBotoesCarregando(true);

    mostrarOperacao({
        titulo: 'Revertendo configuração',
        descricao: 'Solicitando restauração do snapshot anterior ao MoonShield Agent.',
    });

    try {
        const dados = new URLSearchParams();
        dados.set('motivo', motivo);

        const resposta = await api.post(urlAlteracao(id, 'rollback'), dados);
        const alteracao = extrairAlteracao(resposta) || { ...alteracaoAtiva, status: 'reverted' };

        ocultarOperacao();
        tratarAlteracaoFinalizada(alteracao);

        notificacao.aviso('Rollback executado', 'A configuração anterior foi restaurada.');

        emitirEvento('rollback', alteracao);
        await atualizarPainel();

        return true;
    } catch (error) {
        ocultarOperacao();

        const existente = extrairAlteracaoDeErro(error);
        if (existente) {
            sincronizar(existente);

            if (statusAlteracao(existente) === 'reverted') {
                notificacao.aviso('Configuração revertida', 'A alteração já havia sido revertida.');
                return true;
            }
        }

        const erro = normalizarErro(error);
        notificacao.erro(erro.titulo, erro.mensagem);

        if (alteracaoAtiva && alteracaoAguardaConfirmacao(alteracaoAtiva)) {
            abrirModal(elementos.modal);
        }

        return false;
    } finally {
        processando = false;
        definirBotoesCarregando(false);
    }
}


/* ==========================================================================
   POLLING
========================================================================== */

function iniciarPolling() {
    if (pollTimer || !alteracaoAtiva) return;

    pollTimer = window.setInterval(() => {
        if (document.hidden || processando || reconciliando) return;
        consultarEstadoAtual({ silencioso: true });
    }, POLL_INTERVAL);
}


function pararPolling() {
    if (!pollTimer) return;
    window.clearInterval(pollTimer);
    pollTimer = null;
}


async function consultarEstadoAtual({ silencioso = false } = {}) {
    const id = obterId(alteracaoAtiva);
    if (!id) return null;

    try {
        const resposta = await api.get(urlAlteracao(id));
        const alteracao = extrairAlteracao(resposta);

        if (!alteracao) return null;

        if (alteracaoEmAndamento(alteracao)) {
            sincronizar(alteracao);
            return alteracao;
        }

        tratarAlteracaoFinalizada(alteracao);
        return alteracao;
    } catch (error) {
        if (!silencioso) {
            const erro = normalizarErro(error);
            notificacao.erro(erro.titulo, erro.mensagem);
        } else {
            console.warn('[MoonShield Network] Falha ao consultar Safe Apply:', error);
        }

        return null;
    }
}


/* ==========================================================================
   FINALIZAÇÃO / FECHAR
========================================================================== */

function tratarAlteracaoFinalizada(alteracao) {
    const anterior = alteracaoAtiva;
    const estavaAtiva = Boolean(anterior);

    alteracaoAtiva = null;
    reservaLocal = null;

    estado.set('alteracoes.ativa', null);
    estado.set('alteracoes.reservaLocal', null);

    pararTimers();
    fecharModal(elementos.modal, { restaurarFoco: false });
    setHidden(elementos.activeCard, true);
    atualizarLockGlobal();

    if (!estavaAtiva) return;

    const status = statusAlteracao(alteracao);

    if (status === 'confirmed') {
        notificacao.sucesso('Configuração confirmada', 'A alteração de rede foi confirmada.');
    } else if (status === 'reverted') {
        notificacao.aviso('Configuração revertida', 'O MoonShield restaurou a configuração anterior.');
    } else if (status === 'failed') {
        notificacao.erro(
            'Alteração falhou',
            alteracao?.erro || 'Não foi possível aplicar a configuração de rede.'
        );
    }

    emitirEvento('finished', alteracao);
}


function fechar() {
    alteracaoAtiva = null;
    reservaLocal = null;

    estado.set('alteracoes.ativa', null);
    estado.set('alteracoes.reservaLocal', null);

    pararTimers();

    if (elementos.modal?.classList.contains('is-open')) {
        fecharModal(elementos.modal, { restaurarFoco: false });
    }

    setHidden(elementos.activeCard, true);
    atualizarLockGlobal();
}


function fecharSeInativo() {
    const ativa = estado.get('alteracoes.ativa');

    if (!ativa || !alteracaoEmAndamento(ativa)) {
        if (!reservado()) fechar();
        return true;
    }

    sincronizar(ativa);
    return false;
}


/* ==========================================================================
   MODAL DE OPERAÇÃO
========================================================================== */

function mostrarOperacao(opcoes = {}) {
    if (!elementos.operationModal) return false;

    setText(elementos.operationTitle, opcoes.titulo || 'Aplicando configuração');
    setText(
        elementos.operationDescription,
        opcoes.descricao || 'Aguarde enquanto o MoonShield processa a alteração.'
    );

    resetarEtapasOperacao();
    definirEtapaOperacao('validate', 'active');

    return abrirModal(elementos.operationModal);
}


function ocultarOperacao() {
    if (!elementos.operationModal?.classList.contains('is-open')) return;

    fecharModal(elementos.operationModal, { restaurarFoco: false });
}


function resetarEtapasOperacao() {
    ['Validate', 'Snapshot', 'Rollback', 'Apply', 'Verify'].forEach(nome => {
        const elemento = $(`#operationStep${nome}`);
        elemento?.classList.remove('is-active', 'is-done', 'is-error');
    });
}


function definirEtapaOperacao(etapa, status = 'active') {
    const ids = {
        validate: 'operationStepValidate',
        snapshot: 'operationStepSnapshot',
        rollback: 'operationStepRollback',
        apply: 'operationStepApply',
        verify: 'operationStepVerify',
    };

    const elemento = $(`#${ids[etapa] || ''}`);
    if (!elemento) return;

    elemento.classList.remove('is-active', 'is-done', 'is-error');

    if (status === 'done') elemento.classList.add('is-done');
    else if (status === 'error') elemento.classList.add('is-error');
    else elemento.classList.add('is-active');
}


function confirmarOperacao(opcoes = {}) {
    return confirmarModal(opcoes);
}


/* ==========================================================================
   HELPERS
========================================================================== */

function definirBotoesCarregando(ativo) {
    [
        elementos.confirmButton,
        elementos.rollbackButton,
        elementos.activeConfirmButton,
        elementos.activeRollbackButton,
    ].forEach(botao => {
        if (!botao) return;
        botao.disabled = Boolean(ativo);
        botao.classList.toggle('is-loading', Boolean(ativo));
    });
}


function urlAlteracao(id, acao = '') {
    const base = api.urls.alteracoes;
    if (!base) throw new Error('URL de alterações não configurada.');

    const normalizada = base.endsWith('/') ? base : `${base}/`;
    const recurso = `${normalizada}${encodeURIComponent(String(id))}/`;

    return acao ? `${recurso}${acao}/` : recurso;
}


function urlReconciliar() {
    if (api.urls.reconciliarAlteracoes) return api.urls.reconciliarAlteracoes;
    if (api.urls.reconciliar) return api.urls.reconciliar;

    const base = api.urls.alteracoes;
    if (!base) return null;

    return `${base.endsWith('/') ? base : `${base}/`}reconciliar/`;
}


function extrairAlteracao(resposta) {
    if (!resposta) return null;

    const candidata =
        resposta.dados?.alteracao ||
        resposta.dados?.ativa ||
        resposta.dados?.resultado?.alteracao ||
        resposta.alteracao ||
        null;

    if (candidata && typeof candidata === 'object' && obterId(candidata)) return candidata;

    const direta = resposta.dados;
    if (direta && typeof direta === 'object' && obterId(direta)) return direta;

    return null;
}


function extrairAlteracaoDeErro(error) {
    const candidatos = [
        error?.dados?.erro?.detalhes?.alteracao,
        error?.erro?.detalhes?.alteracao,
        error?.detalhes?.alteracao,
        error?.response?.dados?.erro?.detalhes?.alteracao,
        error?.response?.data?.erro?.detalhes?.alteracao,
        error?.data?.erro?.detalhes?.alteracao,
    ];

    return candidatos.find(item => item && typeof item === 'object' && obterId(item)) || null;
}


function obterId(alteracao) {
    return alteracao?.id || alteracao?.uuid || alteracao?.alteracao_id || null;
}


function statusAlteracao(alteracao) {
    return String(alteracao?.status || '').trim().toLowerCase();
}


function alteracaoAguardaConfirmacao(alteracao) {
    return statusAlteracao(alteracao) === 'waiting_confirmation';
}


function alteracaoEmAndamento(alteracao) {
    if (!alteracao) return false;
    if (alteracao.em_andamento === true) return true;
    if (alteracao.finalizada === true) return false;
    return STATUS_ATIVOS.has(statusAlteracao(alteracao));
}


async function atualizarPainel() {
    try {
        if (typeof window.MoonShieldNetwork?.atualizarDepoisDeAlteracao === 'function') {
            await window.MoonShieldNetwork.atualizarDepoisDeAlteracao();
        } else if (typeof window.MoonShieldNetwork?.atualizar === 'function') {
            await window.MoonShieldNetwork.atualizar();
        }
    } catch (error) {
        console.warn('[MoonShield Network] Atualização pós Safe Apply incompleta:', error);
    }
}


function emitirEvento(tipo, alteracao) {
    document.dispatchEvent(new CustomEvent(
        `moonshield:safe-apply-${tipo}`,
        { detail: { alteracao, reserva: reservaLocal } }
    ));
}


function pararTimers() {
    pararCountdown();
    pararPolling();
    resetarConfirmacaoRollback(false);

    if (reconciliationTimer) {
        window.clearTimeout(reconciliationTimer);
        reconciliationTimer = null;
    }
}


function ativo() {
    return alteracaoEmAndamento(alteracaoAtiva);
}


function obterAlteracaoAtiva() {
    return alteracaoAtiva;
}


function destruir() {
    pararTimers();

    alteracaoAtiva = null;
    reservaLocal = null;
    processando = false;
    reconciliando = false;
    inicializado = false;

    estado.set('alteracoes.reservaLocal', null);
    atualizarLockGlobal();
}


/* ==========================================================================
   EXPORT
========================================================================== */

export const safeApply = Object.freeze({
    inicializar,
    destruir,
    abrir,
    fechar,
    sincronizar,
    fecharSeInativo,

    ativo,
    ocupado,
    reservado,
    reservarOperacao,
    liberarReserva,
    obterAlteracaoAtiva,

    confirmarAlteracao,
    executarRollback,
    consultarEstadoAtual,

    confirmarOperacao,
    mostrarOperacao,
    ocultarOperacao,
    definirEtapaOperacao,

    extrairAlteracaoDeErro,
});

export default safeApply;
