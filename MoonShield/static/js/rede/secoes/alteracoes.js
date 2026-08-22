/**
 * MoonShield Network Panel
 * Seção: Alterações
 */

'use strict';

import { api } from '../nucleo/api.js';
import { estado } from '../nucleo/estado.js';
import {
    $, $$, setText, setHidden, setStatusPill, setJson, criar,
} from '../nucleo/dom.js';
import {
    formatarData, formatarHorarioCurto, formatarDataHora, idCurto,
    rotuloStatusAlteracao, rotuloTipoAlteracao, alteracaoAguardaConfirmacao,
    normalizarErro, segundosAte, formatarContagemRegressiva,
} from '../nucleo/utilitarios.js';
import { abrirDrawer, fecharDrawer, drawers } from '../componentes/drawer.js';
import { notificacao } from '../componentes/notificacoes.js';
import { safeApply } from '../componentes/safe_apply.js';

const STATUS_ATIVOS = new Set(['created', 'validating', 'applying', 'waiting_confirmation', 'rollback']);

let inicializado = false;
let carregando = false;
let alteracaoDetalhe = null;
let detailTimer = null;

const elementos = {
    refreshButton: null,
    reconcileButton: null,
    clearFiltersButton: null,
    statusFilter: null,
    typeFilter: null,

    total: null,
    pending: null,
    confirmed: null,
    reverted: null,
    failed: null,

    body: null,
    empty: null,
    template: null,

    drawer: null,
    status: null,
    type: null,
    id: null,
    title: null,
    user: null,
    createdAt: null,
    appliedAt: null,
    confirmedAt: null,
    rollbackAt: null,
    timerContainer: null,
    timer: null,
    configuration: null,
    agentResult: null,
    log: null,
    error: null,
    errorMessage: null,
    rollbackButton: null,
    confirmButton: null,
};


/* ==========================================================================
   INICIALIZAÇÃO
========================================================================== */

function inicializar() {
    if (inicializado) return;
    inicializado = true;

    cachearElementos();
    registrarEventos();

    document.addEventListener('moonshield:safe-apply-confirmed', tratarSafeApplyFinalizado);
    document.addEventListener('moonshield:safe-apply-rollback', tratarSafeApplyFinalizado);
    document.addEventListener('moonshield:safe-apply-finished', tratarSafeApplyFinalizado);
}


function cachearElementos() {
    elementos.refreshButton = $('#refreshChangesButton');
    elementos.reconcileButton = $('#reconcileChangesButton');
    elementos.clearFiltersButton = $('#clearChangesFiltersButton');
    elementos.statusFilter = $('#changesStatusFilter');
    elementos.typeFilter = $('#changesTypeFilter');

    elementos.total = $('#changesTotal');
    elementos.pending = $('#changesPending');
    elementos.confirmed = $('#changesConfirmed');
    elementos.reverted = $('#changesReverted');
    elementos.failed = $('#changesFailed');

    elementos.body = $('#changesTableBody');
    elementos.empty = $('#changesEmptyRow');
    elementos.template = $('#changeRowTemplate');

    elementos.drawer = $('#changeDrawer');
    elementos.status = $('#changeDetailStatus');
    elementos.type = $('#changeDetailType');
    elementos.id = $('#changeDetailId');
    elementos.title = $('#changeDetailTitle');
    elementos.user = $('#changeDetailUser');
    elementos.createdAt = $('#changeDetailCreatedAt');
    elementos.appliedAt = $('#changeDetailAppliedAt');
    elementos.confirmedAt = $('#changeDetailConfirmedAt');
    elementos.rollbackAt = $('#changeDetailRollbackAt');
    elementos.timerContainer = $('#changeDetailTimerContainer');
    elementos.timer = $('#changeDetailTimer');
    elementos.configuration = $('#changeDetailConfiguration');
    elementos.agentResult = $('#changeDetailAgentResult');
    elementos.log = $('#changeDetailLog');
    elementos.error = $('#changeDetailError');
    elementos.errorMessage = $('#changeDetailErrorMessage');
    elementos.rollbackButton = $('#changeRollbackButton');
    elementos.confirmButton = $('#changeConfirmButton');
}


/* ==========================================================================
   EVENTOS
========================================================================== */

function registrarEventos() {
    elementos.refreshButton?.addEventListener('click', () => carregar());
    elementos.reconcileButton?.addEventListener('click', reconciliar);

    elementos.statusFilter?.addEventListener('change', aplicarFiltros);
    elementos.typeFilter?.addEventListener('change', aplicarFiltros);

    elementos.clearFiltersButton?.addEventListener('click', () => {
        elementos.statusFilter.value = '';
        elementos.typeFilter.value = '';

        estado.set('alteracoes.filtros', {
            status: '',
            tipo: '',
        });

        carregar();
    });

    elementos.body?.addEventListener('click', event => {
        const alvo = event.target instanceof Element ? event.target : null;
        const botao = alvo?.closest('[data-change-view]');
        if (!botao) return;

        const row = botao.closest('[data-change-row]');
        if (!row) return;

        abrirDetalhe(row.dataset.changeId);
    });

    elementos.confirmButton?.addEventListener('click', confirmarDetalhe);
    elementos.rollbackButton?.addEventListener('click', rollbackDetalhe);

    elementos.drawer?.addEventListener('moonshield:drawer-close', pararDetailTimer);
}


/* ==========================================================================
   CARREGAR
========================================================================== */

async function carregar(opcoes = {}) {
    if (carregando) return estado.get('alteracoes.lista', []);

    carregando = true;
    definirCarregando(true);

    const filtros = {
        ...estado.get('alteracoes.filtros', {}),
        ...opcoes.filtros,
    };

    try {
        const params = {
            status: filtros.status || undefined,
            tipo: filtros.tipo || undefined,
            limite: opcoes.limite || 100,
        };

        const resposta = await api.get(api.urls.alteracoes, params);
        const lista = extrairLista(resposta);

        estado.set('alteracoes.lista', lista);
        estado.set('alteracoes.carregado', true);

        renderizar(lista);

        const ativa = encontrarAtiva(lista);
        estado.set('alteracoes.ativa', ativa);

        if (ativa) safeApply.sincronizar(ativa);
        else safeApply.fecharSeInativo();

        return lista;
    } catch (error) {
        if (!opcoes.silencioso) {
            const erro = normalizarErro(error);
            notificacao.erro(erro.titulo, erro.mensagem);
        }

        throw error;
    } finally {
        carregando = false;
        definirCarregando(false);
    }
}


/* ==========================================================================
   RENDER
========================================================================== */

function renderizar(lista = estado.get('alteracoes.lista', [])) {
    renderizarResumo(lista);
    renderizarTabela(lista);
    atualizarBadge(lista);
}


function sincronizar() {
    renderizar();
}


function renderizarResumo(lista) {
    const total = lista.length;
    const pendentes = lista.filter(item => STATUS_ATIVOS.has(item.status)).length;
    const confirmadas = lista.filter(item => item.status === 'confirmed').length;
    const revertidas = lista.filter(item => ['reverted', 'rollback'].includes(item.status)).length;
    const falhas = lista.filter(item => item.status === 'failed').length;

    setText(elementos.total, total, '0');
    setText(elementos.pending, pendentes, '0');
    setText(elementos.confirmed, confirmadas, '0');
    setText(elementos.reverted, revertidas, '0');
    setText(elementos.failed, falhas, '0');
}


function renderizarTabela(lista) {
    if (!elementos.body) return;

    $$('[data-change-row-rendered]', elementos.body).forEach(row => row.remove());
    setHidden(elementos.empty, lista.length > 0);

    lista.forEach(alteracao => {
        const row = criarLinha(alteracao);
        if (row) elementos.body.appendChild(row);
    });
}


function criarLinha(alteracao) {
    const template = elementos.template;

    if (!template) return criarLinhaManual(alteracao);

    const fragmento = template.content.cloneNode(true);
    const row = fragmento.querySelector('[data-change-row]');

    if (!row) return null;

    preencherLinha(row, alteracao);

    row.dataset.changeRowRendered = 'true';
    return row;
}


function criarLinhaManual(alteracao) {
    const row = criar('tr', {
        attrs: {
            'data-change-row': '',
            'data-change-row-rendered': 'true',
        },
    });

    for (let i = 0; i < 6; i++) row.appendChild(criar('td'));

    preencherLinha(row, alteracao);
    return row;
}


function preencherLinha(row, alteracao) {
    const id = obterId(alteracao);
    const criadoEm = alteracao.criado_em || alteracao.created_at || alteracao.created;
    const usuario = obterUsuario(alteracao);

    row.dataset.changeId = String(id || '');

    setText($('[data-change-date]', row), formatarData(criadoEm));
    setText($('[data-change-time]', row), formatarHorarioCurto(criadoEm));

    setText($('[data-change-title]', row), alteracao.titulo || 'Alteração de rede');
    setText($('[data-change-id]', row), id ? idCurto(id, 12) : '—');

    const tipo = $('[data-change-type]', row);

    if (tipo) {
        tipo.dataset.type = alteracao.tipo || 'general';
        setText(tipo, rotuloTipoAlteracao(alteracao.tipo));
    }

    const status = $('[data-change-status]', row);

    if (status) {
        status.dataset.status = alteracao.status || '';
        setStatusPill(status, nivelStatus(alteracao.status), rotuloStatusAlteracao(alteracao.status));
        status.dataset.status = alteracao.status || '';
    }

    setText($('[data-change-user]', row), usuario);
}


/* ==========================================================================
   FILTROS
========================================================================== */

function aplicarFiltros() {
    const filtros = {
        status: elementos.statusFilter?.value || '',
        tipo: elementos.typeFilter?.value || '',
    };

    estado.set('alteracoes.filtros', filtros);

    carregar({
        filtros,
        silencioso: true,
    }).catch(error => {
        const erro = normalizarErro(error);
        notificacao.erro(erro.titulo, erro.mensagem);
    });
}


/* ==========================================================================
   DETALHE
========================================================================== */

async function abrirDetalhe(id) {
    if (!id) return;

    let alteracao = estado.get('alteracoes.lista', []).find(item => String(obterId(item)) === String(id));

    try {
        const resposta = await api.get(urlAlteracao(id));
        alteracao = extrairAlteracao(resposta) || alteracao;
    } catch (error) {
        if (!alteracao) {
            const erro = normalizarErro(error);
            notificacao.erro(erro.titulo, erro.mensagem);
            return;
        }
    }

    if (!alteracao) return;

    alteracaoDetalhe = alteracao;

    preencherDetalhe(alteracao);
    abrirDrawer(drawers.alteracao);

    if (alteracaoAguardaConfirmacao(alteracao)) iniciarDetailTimer();
}


/* ==========================================================================
   PREENCHER DETALHE
========================================================================== */

function preencherDetalhe(alteracao) {
    const id = obterId(alteracao);
    const status = alteracao.status || '';
    const tipo = alteracao.tipo || 'general';

    setStatusPill(elementos.status, nivelStatus(status), rotuloStatusAlteracao(status));
    if (elementos.status) elementos.status.dataset.status = status;

    setText(elementos.type, rotuloTipoAlteracao(tipo));
    if (elementos.type) elementos.type.dataset.type = tipo;

    setText(elementos.id, id || '—');
    setText(elementos.title, alteracao.titulo || 'Alteração de rede');
    setText(elementos.user, obterUsuario(alteracao));

    setText(elementos.createdAt, formatarDataHora(alteracao.criado_em || alteracao.created_at));
    setText(elementos.appliedAt, formatarDataHora(alteracao.aplicada_em));
    setText(elementos.confirmedAt, formatarDataHora(alteracao.confirmada_em));
    setText(elementos.rollbackAt, formatarDataHora(alteracao.rollback_em));

    setJson(elementos.configuration, alteracao.configuracao_solicitada || {});
    setJson(elementos.agentResult, alteracao.resultado_agent || {});
    setText(elementos.log, formatarLog(alteracao.log), '—');

    if (alteracao.erro) {
        setText(elementos.errorMessage, typeof alteracao.erro === 'string' ? alteracao.erro : JSON.stringify(alteracao.erro, null, 2));
        setHidden(elementos.error, false);
    } else {
        setHidden(elementos.error, true);
    }

    const aguardando = alteracaoAguardaConfirmacao(alteracao);

    setHidden(elementos.timerContainer, !aguardando);
    setHidden(elementos.confirmButton, !aguardando);
    setHidden(elementos.rollbackButton, !aguardando);

    if (aguardando) atualizarDetailTimer();
}


/* ==========================================================================
   TIMER DETALHE
========================================================================== */

function iniciarDetailTimer() {
    pararDetailTimer();
    atualizarDetailTimer();

    detailTimer = window.setInterval(atualizarDetailTimer, 1000);
}


function pararDetailTimer() {
    if (!detailTimer) return;

    window.clearInterval(detailTimer);
    detailTimer = null;
}


function atualizarDetailTimer() {
    if (!alteracaoDetalhe || !alteracaoAguardaConfirmacao(alteracaoDetalhe)) {
        pararDetailTimer();
        return;
    }

    const segundos = segundosRestantes(alteracaoDetalhe);

    setText(elementos.timer, formatarContagemRegressiva(segundos));

    if (segundos <= 0) {
        elementos.confirmButton && (elementos.confirmButton.disabled = true);
        pararDetailTimer();
    }
}


/* ==========================================================================
   CONFIRMAR DETALHE
========================================================================== */

async function confirmarDetalhe() {
    if (!alteracaoDetalhe || !alteracaoAguardaConfirmacao(alteracaoDetalhe)) return;

    const id = obterId(alteracaoDetalhe);
    if (!id) return;

    definirBotoesDetalhe(true);

    try {
        const resposta = await api.post(urlAlteracao(id, 'confirmar'), {});
        const atualizada = extrairAlteracao(resposta) || { ...alteracaoDetalhe, status: 'confirmed' };

        atualizarAlteracao(atualizada);
        estado.set('alteracoes.ativa', null);

        safeApply.fecharSeInativo();
        preencherDetalhe(atualizada);

        notificacao.sucesso('Configuração confirmada', 'A alteração foi confirmada com sucesso.');

        await carregar({ silencioso: true });
    } catch (error) {
        const erro = normalizarErro(error);
        notificacao.erro(erro.titulo, erro.mensagem);
    } finally {
        definirBotoesDetalhe(false);
    }
}


/* ==========================================================================
   ROLLBACK DETALHE
========================================================================== */

async function rollbackDetalhe() {
    if (!alteracaoDetalhe || !alteracaoAguardaConfirmacao(alteracaoDetalhe)) return;

    estado.set('alteracoes.ativa', alteracaoDetalhe);
    safeApply.sincronizar(alteracaoDetalhe);

    const sucesso = await safeApply.executarRollback('Rollback solicitado pelo painel de Alterações.');

    if (sucesso) {
        fecharDrawer(drawers.alteracao);
        await carregar({ silencioso: true });
    }
}


/* ==========================================================================
   RECONCILIAR
========================================================================== */

async function reconciliar() {
    if (!api.urls.reconciliar) return;

    elementos.reconcileButton.disabled = true;
    elementos.reconcileButton.classList.add('is-loading');

    try {
        const resposta = await api.post(api.urls.reconciliar, {});
        const dados = resposta?.dados ?? resposta ?? {};

        notificacao.sucesso(
            'Alterações reconciliadas',
            dados.mensagem || 'O estado das alterações pendentes foi reconciliado.'
        );

        await carregar({ silencioso: true });
    } catch (error) {
        const erro = normalizarErro(error);
        notificacao.erro(erro.titulo, erro.mensagem);
    } finally {
        elementos.reconcileButton.disabled = false;
        elementos.reconcileButton.classList.remove('is-loading');
    }
}


/* ==========================================================================
   ALTERAÇÃO ATIVA
========================================================================== */

async function buscarAlteracaoAtiva() {
    const atual = estado.get('alteracoes.ativa');

    if (atual && alteracaoAguardaConfirmacao(atual)) {
        try {
            const resposta = await api.get(urlAlteracao(obterId(atual)));
            const atualizada = extrairAlteracao(resposta);

            if (atualizada && alteracaoAguardaConfirmacao(atualizada)) {
                estado.set('alteracoes.ativa', atualizada);
                atualizarAlteracao(atualizada);
                return atualizada;
            }

            estado.set('alteracoes.ativa', null);
            return null;
        } catch {
            return atual;
        }
    }

    const listaAtual = estado.get('alteracoes.lista', []);
    const encontrada = encontrarAtiva(listaAtual);

    if (encontrada) {
        estado.set('alteracoes.ativa', encontrada);
        return encontrada;
    }

    try {
        const resposta = await api.get(api.urls.alteracoes, {
            status: 'waiting_confirmation',
            limite: 10,
        });

        const lista = extrairLista(resposta);
        const ativa = encontrarAtiva(lista);

        estado.set('alteracoes.ativa', ativa);
        return ativa;
    } catch {
        return null;
    }
}


/* ==========================================================================
   ATUALIZAR ALTERAÇÃO
========================================================================== */

function atualizarAlteracao(alteracao) {
    if (!alteracao) return;

    const id = obterId(alteracao);

    estado.update('alteracoes.lista', lista => {
        const novaLista = [...(lista || [])];
        const indice = novaLista.findIndex(item => String(obterId(item)) === String(id));

        if (indice >= 0) novaLista[indice] = alteracao;
        else novaLista.unshift(alteracao);

        return novaLista;
    });

    if (alteracaoAguardaConfirmacao(alteracao)) estado.set('alteracoes.ativa', alteracao);

    renderizar();

    if (alteracaoDetalhe && String(obterId(alteracaoDetalhe)) === String(id)) {
        alteracaoDetalhe = alteracao;
        preencherDetalhe(alteracao);
    }
}


/* ==========================================================================
   BADGE
========================================================================== */

function atualizarBadge(lista = estado.get('alteracoes.lista', [])) {
    const pendentes = lista.filter(item => STATUS_ATIVOS.has(item.status)).length;
    const badge = $('#sidebarChangesBadge');

    setText(badge, pendentes, '0');
    setHidden(badge, pendentes <= 0);
}


/* ==========================================================================
   LOADING
========================================================================== */

function definirCarregando(ativo) {
    if (elementos.refreshButton) {
        elementos.refreshButton.disabled = Boolean(ativo);
        elementos.refreshButton.classList.toggle('is-loading', Boolean(ativo));
    }
}


function definirBotoesDetalhe(ativo) {
    if (elementos.confirmButton) elementos.confirmButton.disabled = Boolean(ativo);
    if (elementos.rollbackButton) elementos.rollbackButton.disabled = Boolean(ativo);
}


/* ==========================================================================
   SAFE APPLY EVENT
========================================================================== */

function tratarSafeApplyFinalizado() {
    carregar({ silencioso: true }).catch(() => {});
}


/* ==========================================================================
   HELPERS
========================================================================== */

function encontrarAtiva(lista) {
    return lista.find(item => item.status === 'waiting_confirmation') || null;
}


function obterId(alteracao) {
    return alteracao?.id || alteracao?.uuid || alteracao?.alteracao_id || null;
}


function obterUsuario(alteracao) {
    const usuario = alteracao?.solicitado_por || alteracao?.usuario || alteracao?.requested_by;

    if (!usuario) return 'Sistema';
    if (typeof usuario === 'string') return usuario;

    return usuario.nome || usuario.full_name || usuario.username || usuario.email || 'Sistema';
}


function nivelStatus(status) {
    if (status === 'confirmed') return 'ok';
    if (['waiting_confirmation', 'rollback', 'reverted'].includes(status)) return 'warning';
    if (status === 'failed') return 'error';
    if (status === 'applying') return 'ok';

    return 'pending';
}


function segundosRestantes(alteracao) {
    if (alteracao.segundos_restantes !== undefined && alteracao.segundos_restantes !== null) {
        return Math.max(0, Math.ceil(Number(alteracao.segundos_restantes) || 0));
    }

    if (alteracao.expira_em) return segundosAte(alteracao.expira_em);

    return 0;
}


function formatarLog(log) {
    if (!log) return '—';
    if (typeof log === 'string') return log;

    if (Array.isArray(log)) {
        return log.map(item => {
            if (typeof item === 'string') return item;

            const data = item.data || item.timestamp || item.criado_em || '';
            const mensagem = item.mensagem || item.message || JSON.stringify(item);

            return `${data ? `[${data}] ` : ''}${mensagem}`;
        }).join('\n');
    }

    try {
        return JSON.stringify(log, null, 2);
    } catch {
        return String(log);
    }
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
   EXTRAÇÃO
========================================================================== */

function extrairLista(resposta) {
    const dados = resposta?.dados ?? resposta ?? {};

    if (Array.isArray(dados)) return dados;
    if (Array.isArray(dados.alteracoes)) return dados.alteracoes;
    if (Array.isArray(dados.resultados)) return dados.resultados;
    if (Array.isArray(dados.lista)) return dados.lista;

    return [];
}


function extrairAlteracao(resposta) {
    return resposta?.dados?.alteracao ||
        resposta?.dados?.resultado?.alteracao ||
        resposta?.alteracao ||
        null;
}


/* ==========================================================================
   ATIVAÇÃO
========================================================================== */

async function aoAtivar() {
    if (!estado.get('alteracoes.carregado')) {
        try {
            await carregar({ silencioso: true });
        } catch {
            // Mantém a página funcional mesmo se o Agent estiver offline.
        }
    } else {
        renderizar();
    }
}


/* ==========================================================================
   EXPORT
========================================================================== */

export const alteracoes = Object.freeze({
    inicializar,
    aoAtivar,
    carregar,
    renderizar,
    sincronizar,
    atualizarAlteracao,
    buscarAlteracaoAtiva,
    abrirDetalhe,
    reconciliar,
});

export default alteracoes;