/**
 * MoonShield Network Panel
 * Safe Apply
 *
 * IMPORTANTE:
 * O contador deste módulo é apenas visual.
 *
 * O navegador NÃO controla o rollback real.
 * O MoonShield Agent deve armar o rollback antes de modificar a rede e
 * executá-lo sozinho caso a confirmação não chegue.
 */

'use strict';

import { api } from '../nucleo/api.js';
import { estado } from '../nucleo/estado.js';
import { $, setText, setHidden, setStatusPill } from '../nucleo/dom.js';
import {
    alteracaoAguardaConfirmacao,
    formatarContagemRegressiva,
    normalizarErro,
    rotuloTipoAlteracao,
    segundosAte,
    paraNumero,
} from '../nucleo/utilitarios.js';
import { abrirModal, fecharModal, confirmarModal } from '../componentes/modal.js';
import { notificacao } from '../componentes/notificacoes.js';

const POLL_INTERVAL = 5000;
const CRITICAL_SECONDS = 15;

let inicializado = false;
let alteracaoAtiva = null;
let countdownTimer = null;
let pollTimer = null;
let processando = false;
let totalSegundos = 60;


/* ==========================================================================
   ELEMENTOS
========================================================================== */

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
    if (ativa && alteracaoAguardaConfirmacao(ativa)) sincronizar(ativa);
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
   ABRIR
========================================================================== */

function abrir(alteracao, opcoes = {}) {
    if (!alteracao) return false;

    if (!alteracaoAguardaConfirmacao(alteracao)) {
        sincronizar(alteracao);
        return false;
    }

    alteracaoAtiva = alteracao;
    estado.set('alteracoes.ativa', alteracao);

    prepararTempo(alteracao);
    atualizarInterface(alteracao);
    iniciarCountdown();
    iniciarPolling();

    setHidden(elementos.activeCard, false);

    if (opcoes.mostrarModal !== false && elementos.modal) abrirModal(elementos.modal, { foco: elementos.confirmButton });

    return true;
}


/* ==========================================================================
   SINCRONIZAR
========================================================================== */

function sincronizar(alteracao) {
    if (!alteracao) {
        fechar();
        return;
    }

    if (!alteracaoAguardaConfirmacao(alteracao)) {
        tratarAlteracaoFinalizada(alteracao);
        return;
    }

    const trocouAlteracao = obterId(alteracaoAtiva) !== obterId(alteracao);

    alteracaoAtiva = alteracao;
    estado.set('alteracoes.ativa', alteracao);

    if (trocouAlteracao || !countdownTimer) prepararTempo(alteracao);

    atualizarInterface(alteracao);
    setHidden(elementos.activeCard, false);

    iniciarCountdown();
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
    if (!alteracao) return 0;

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
    if (countdownTimer) return;

    atualizarCountdownVisual();

    countdownTimer = window.setInterval(() => {
        atualizarCountdownVisual();

        if (obterSegundosRestantes(alteracaoAtiva) <= 0) {
            pararCountdown();
            marcarPrazoExpirado();
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

    const percentual = Math.max(0, Math.min(100, (segundos / Math.max(totalSegundos, 1)) * 100));

    if (elementos.progress) elementos.progress.style.width = `${percentual}%`;

    const critico = segundos > 0 && segundos <= CRITICAL_SECONDS;
    elementos.activeCard?.classList.toggle('is-critical', critico);

    if (elementos.confirmButton) elementos.confirmButton.disabled = processando || segundos <= 0;
    if (elementos.activeConfirmButton) elementos.activeConfirmButton.disabled = processando || segundos <= 0;
}


function marcarPrazoExpirado() {
    setText(elementos.countdown, '00:00');
    setText(elementos.activeTimer, '00:00');
    setText(elementos.activeDescription, 'Prazo encerrado. Aguardando o estado informado pelo MoonShield Agent.');

    if (elementos.progress) elementos.progress.style.width = '0%';

    elementos.activeCard?.classList.remove('is-critical');

    if (elementos.confirmButton) elementos.confirmButton.disabled = true;
    if (elementos.activeConfirmButton) elementos.activeConfirmButton.disabled = true;

    /*
     * Não fazemos rollback daqui.
     *
     * O Agent é o responsável pelo timer e pelo rollback real.
     */
}


/* ==========================================================================
   CONFIRMAR
========================================================================== */

async function confirmarAlteracao() {
    if (!alteracaoAtiva || processando) return false;

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

        estado.set('alteracoes.ativa', null);
        alteracaoAtiva = null;

        pararTimers();
        fecharModal(elementos.modal, { restaurarFoco: false });
        setHidden(elementos.activeCard, true);

        notificacao.sucesso('Configuração confirmada', 'A nova configuração de rede foi confirmada e o rollback foi desarmado.');

        emitirEvento('confirmed', alteracao);
        await atualizarPainel();

        return true;
    } catch (error) {
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
    if (!alteracaoAtiva || processando) return false;

    if (elementos.modal?.classList.contains('is-open')) {
        fecharModal(elementos.modal, { restaurarFoco: false });
    }

    const confirmado = await confirmarModal({
        titulo: 'Reverter configuração de rede?',
        mensagem: 'O MoonShield Agent tentará restaurar o snapshot anterior desta alteração.',
        detalhes: 'Use esta opção se perdeu conectividade, acesso administrativo ou identificou uma configuração incorreta.',
        textoConfirmar: 'Reverter agora',
        textoCancelar: 'Manter configuração',
        perigoso: true,
    });

    if (!confirmado) {
        if (alteracaoAtiva && alteracaoAguardaConfirmacao(alteracaoAtiva)) abrirModal(elementos.modal);
        return false;
    }

    return executarRollback('Rollback solicitado manualmente pelo administrador.');
}


async function executarRollback(motivo = 'Rollback solicitado pelo painel.') {
    if (!alteracaoAtiva || processando) return false;

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
        /*
         * O endpoint atual de rollback lê request.POST.
         * Portanto usamos URLSearchParams, e não JSON.
         */
        const dados = new URLSearchParams();
        dados.set('motivo', motivo);

        const resposta = await api.post(urlAlteracao(id, 'rollback'), dados);
        const alteracao = extrairAlteracao(resposta) || { ...alteracaoAtiva, status: 'reverted' };

        estado.set('alteracoes.ativa', null);
        alteracaoAtiva = null;

        pararTimers();
        ocultarOperacao();
        fecharModal(elementos.modal, { restaurarFoco: false });
        setHidden(elementos.activeCard, true);

        notificacao.aviso('Rollback executado', 'A restauração da configuração anterior foi solicitada.');

        emitirEvento('rollback', alteracao);
        await atualizarPainel();

        return true;
    } catch (error) {
        ocultarOperacao();

        const erro = normalizarErro(error);
        notificacao.erro(erro.titulo, erro.mensagem);

        if (alteracaoAtiva && alteracaoAguardaConfirmacao(alteracaoAtiva)) abrirModal(elementos.modal);

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
        if (document.hidden || processando) return;
        consultarEstadoAtual();
    }, POLL_INTERVAL);
}


function pararPolling() {
    if (!pollTimer) return;
    window.clearInterval(pollTimer);
    pollTimer = null;
}


async function consultarEstadoAtual() {
    const id = obterId(alteracaoAtiva);
    if (!id) return null;

    try {
        const resposta = await api.get(urlAlteracao(id));
        const alteracao = extrairAlteracao(resposta);

        if (!alteracao) return null;

        if (alteracaoAguardaConfirmacao(alteracao)) {
            alteracaoAtiva = alteracao;
            estado.set('alteracoes.ativa', alteracao);
            atualizarInterface(alteracao);
            return alteracao;
        }

        tratarAlteracaoFinalizada(alteracao);
        return alteracao;
    } catch (error) {
        console.warn('[MoonShield Network] Falha ao consultar Safe Apply:', error);
        return null;
    }
}


/* ==========================================================================
   FINALIZAÇÃO EXTERNA
========================================================================== */

function tratarAlteracaoFinalizada(alteracao) {
    const anterior = alteracaoAtiva;
    const estavaAtiva = Boolean(anterior);

    alteracaoAtiva = null;
    estado.set('alteracoes.ativa', null);

    pararTimers();
    fecharModal(elementos.modal, { restaurarFoco: false });
    setHidden(elementos.activeCard, true);

    if (!estavaAtiva) return;

    if (alteracao?.status === 'confirmed') {
        notificacao.sucesso('Configuração confirmada', 'A alteração de rede foi confirmada.');
    } else if (alteracao?.status === 'reverted') {
        notificacao.aviso('Configuração revertida', 'O MoonShield restaurou a configuração anterior.');
    } else if (alteracao?.status === 'failed') {
        notificacao.erro('Alteração falhou', alteracao.erro || 'Não foi possível aplicar a configuração de rede.');
    }

    emitirEvento('finished', alteracao);
}


/* ==========================================================================
   FECHAR
========================================================================== */

function fechar() {
    alteracaoAtiva = null;
    estado.set('alteracoes.ativa', null);

    pararTimers();

    if (elementos.modal?.classList.contains('is-open')) fecharModal(elementos.modal, { restaurarFoco: false });

    setHidden(elementos.activeCard, true);
}


function fecharSeInativo() {
    const ativa = estado.get('alteracoes.ativa');

    if (!ativa || !alteracaoAguardaConfirmacao(ativa)) {
        fechar();
        return true;
    }

    sincronizar(ativa);
    return false;
}


/* ==========================================================================
   OPERAÇÃO
========================================================================== */

function mostrarOperacao(opcoes = {}) {
    if (!elementos.operationModal) return false;

    setText(elementos.operationTitle, opcoes.titulo || 'Aplicando configuração');
    setText(elementos.operationDescription, opcoes.descricao || 'Aguarde enquanto o MoonShield processa a alteração.');

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


/* ==========================================================================
   CONFIRMAÇÃO GENÉRICA
========================================================================== */

function confirmarOperacao(opcoes = {}) {
    return confirmarModal(opcoes);
}


/* ==========================================================================
   BOTÕES
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


/* ==========================================================================
   URL
========================================================================== */

function urlAlteracao(id, acao = '') {
    const base = api.urls.alteracoes;

    if (!base) throw new Error('URL de alterações não configurada.');

    const normalizada = base.endsWith('/') ? base : `${base}/`;
    const recurso = `${normalizada}${encodeURIComponent(String(id))}/`;

    return acao ? `${recurso}${acao}/` : recurso;
}


/* ==========================================================================
   DADOS
========================================================================== */

function extrairAlteracao(resposta) {
    if (!resposta) return null;

    return resposta.dados?.alteracao ||
        resposta.dados?.resultado?.alteracao ||
        resposta.dados ||
        resposta.alteracao ||
        null;
}


function obterId(alteracao) {
    return alteracao?.id || alteracao?.uuid || alteracao?.alteracao_id || null;
}


/* ==========================================================================
   ATUALIZAR PAINEL
========================================================================== */

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


/* ==========================================================================
   EVENTOS
========================================================================== */

function emitirEvento(tipo, alteracao) {
    document.dispatchEvent(new CustomEvent(`moonshield:safe-apply-${tipo}`, {
        detail: { alteracao },
    }));
}


/* ==========================================================================
   TIMERS
========================================================================== */

function pararTimers() {
    pararCountdown();
    pararPolling();
}


/* ==========================================================================
   ESTADO
========================================================================== */

function ativo() {
    return Boolean(alteracaoAtiva && alteracaoAguardaConfirmacao(alteracaoAtiva));
}


function obterAlteracaoAtiva() {
    return alteracaoAtiva;
}


/* ==========================================================================
   DESTRUIR
========================================================================== */

function destruir() {
    pararTimers();
    alteracaoAtiva = null;
    inicializado = false;
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
    obterAlteracaoAtiva,
    confirmarAlteracao,
    executarRollback,
    confirmarOperacao,
    mostrarOperacao,
    ocultarOperacao,
    definirEtapaOperacao,
});

export default safeApply;