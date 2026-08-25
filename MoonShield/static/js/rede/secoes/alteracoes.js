/**
 * MoonShield Network Panel
 * Seção: Alterações
 */

'use strict';

import { api } from '../nucleo/api.js';
import { estado } from '../nucleo/estado.js';
import { $, $$, setText, setHidden, setStatusPill, setJson, criar } from '../nucleo/dom.js';
import {
    formatarData,
    formatarHorarioCurto,
    formatarDataHora,
    idCurto,
    rotuloStatusAlteracao,
    rotuloTipoAlteracao,
    normalizarErro,
    segundosAte,
    formatarContagemRegressiva,
} from '../nucleo/utilitarios.js';
import { abrirDrawer, fecharDrawer, drawers } from '../componentes/drawer.js';
import { notificacao } from '../componentes/notificacoes.js';
import { safeApply } from '../componentes/safe_apply.js';

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
let carregando = false;
let reconciliando = false;
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
    document.addEventListener('moonshield:network-lock-change', atualizarEstadoBotoes);
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


function registrarEventos() {
    elementos.refreshButton?.addEventListener('click', () => carregar());
    elementos.reconcileButton?.addEventListener('click', reconciliar);

    elementos.statusFilter?.addEventListener('change', aplicarFiltros);
    elementos.typeFilter?.addEventListener('change', aplicarFiltros);

    elementos.clearFiltersButton?.addEventListener('click', () => {
        if (elementos.statusFilter) elementos.statusFilter.value = '';
        if (elementos.typeFilter) elementos.typeFilter.value = '';

        estado.set('alteracoes.filtros', { status: '', tipo: '' });
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
        ...(opcoes.filtros || {}),
    };

    try {
        const params = {
            status: filtros.status || undefined,
            tipo: filtros.tipo || undefined,
            limite: opcoes.limite || 100,
        };

        const resposta = await api.get(api.urls.alteracoes, params);
        const lista = extrairLista(resposta);
        const ativaApi = extrairAtiva(resposta);

        estado.set('alteracoes.lista', lista);
        estado.set('alteracoes.carregado', true);

        renderizar(lista);

        const ativasLista = encontrarAtivas(lista);
        const ativa = ativaApi || ativasLista[0] || null;

        if (ativasLista.length > 1) {
            console.warn(
                '[MoonShield Network] Mais de uma alteração ativa encontrada no histórico:',
                ativasLista.map(item => obterId(item))
            );
        }

        estado.set('alteracoes.ativa', ativa);

        if (ativa) safeApply.sincronizar?.(ativa);
        else safeApply.fecharSeInativo?.();

        atualizarEstadoBotoes();
        return lista;
    } catch (error) {
        estado.set('alteracoes.carregado', false);

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
    atualizarEstadoBotoes();
}


function sincronizar() {
    renderizar();
}


function renderizarResumo(lista) {
    const total = lista.length;
    const pendentes = lista.filter(item => STATUS_ATIVOS.has(statusAlteracao(item))).length;
    const confirmadas = lista.filter(item => statusAlteracao(item) === 'confirmed').length;
    const revertidas = lista.filter(item => statusAlteracao(item) === 'reverted').length;
    const falhas = lista.filter(item => statusAlteracao(item) === 'failed').length;

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
    const statusAtual = statusAlteracao(alteracao);

    row.dataset.changeId = String(id || '');
    row.classList.toggle('is-active-change', STATUS_ATIVOS.has(statusAtual));

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
        status.dataset.status = statusAtual;
        setStatusPill(status, nivelStatus(statusAtual), rotuloStatusAlteracao(statusAtual));
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

    carregar({ filtros, silencioso: true }).catch(error => {
        const erro = normalizarErro(error);
        notificacao.erro(erro.titulo, erro.mensagem);
    });
}


/* ==========================================================================
   DETALHE
========================================================================== */

async function abrirDetalhe(id) {
    if (!id) return;

    let alteracao = estado
        .get('alteracoes.lista', [])
        .find(item => String(obterId(item)) === String(id));

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
    atualizarAlteracao(alteracao);

    preencherDetalhe(alteracao);
    abrirDrawer(drawers.alteracao);

    if (statusAlteracao(alteracao) === 'waiting_confirmation') iniciarDetailTimer();
}


function preencherDetalhe(alteracao) {
    const id = obterId(alteracao);
    const status = statusAlteracao(alteracao);
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
        setText(
            elementos.errorMessage,
            typeof alteracao.erro === 'string'
                ? alteracao.erro
                : JSON.stringify(alteracao.erro, null, 2)
        );
        setHidden(elementos.error, false);
    } else {
        setHidden(elementos.error, true);
    }

    const aguardando = status === 'waiting_confirmation';
    const podeRollback = ['applying', 'waiting_confirmation', 'rollback'].includes(status);

    setHidden(elementos.timerContainer, !aguardando);
    setHidden(elementos.confirmButton, !aguardando);
    setHidden(elementos.rollbackButton, !podeRollback);

    if (elementos.confirmButton) {
        elementos.confirmButton.disabled =
            !aguardando ||
            segundosRestantes(alteracao) <= 0;
    }

    if (elementos.rollbackButton) {
        elementos.rollbackButton.disabled = !podeRollback;
    }

    if (aguardando) atualizarDetailTimer();
    else pararDetailTimer();
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


async function atualizarDetailTimer() {
    if (!alteracaoDetalhe || statusAlteracao(alteracaoDetalhe) !== 'waiting_confirmation') {
        pararDetailTimer();
        return;
    }

    const segundos = segundosRestantes(alteracaoDetalhe);
    setText(elementos.timer, formatarContagemRegressiva(segundos));

    if (segundos > 0) return;

    if (elementos.confirmButton) elementos.confirmButton.disabled = true;
    pararDetailTimer();

    // O Agent é a autoridade do timeout. O detalhe apenas solicita reconciliação.
    try {
        await reconciliar({ silencioso: true });
        const id = obterId(alteracaoDetalhe);
        const resposta = await api.get(urlAlteracao(id));
        const atualizada = extrairAlteracao(resposta);

        if (atualizada) {
            alteracaoDetalhe = atualizada;
            atualizarAlteracao(atualizada);
            preencherDetalhe(atualizada);
        }
    } catch {
        // O polling global continuará tentando.
    }
}


/* ==========================================================================
   CONFIRMAR / ROLLBACK
========================================================================== */

async function confirmarDetalhe() {
    if (!alteracaoDetalhe || statusAlteracao(alteracaoDetalhe) !== 'waiting_confirmation') return;

    estado.set('alteracoes.ativa', alteracaoDetalhe);
    safeApply.sincronizar?.(alteracaoDetalhe);

    const sucesso = await safeApply.confirmarAlteracao?.();

    if (sucesso) {
        await carregar({ silencioso: true });

        const id = obterId(alteracaoDetalhe);
        const atualizada = estado
            .get('alteracoes.lista', [])
            .find(item => String(obterId(item)) === String(id));

        if (atualizada) {
            alteracaoDetalhe = atualizada;
            preencherDetalhe(atualizada);
        }
    }
}


async function rollbackDetalhe() {
    if (!alteracaoDetalhe || !STATUS_ATIVOS.has(statusAlteracao(alteracaoDetalhe))) return;

    estado.set('alteracoes.ativa', alteracaoDetalhe);
    safeApply.sincronizar?.(alteracaoDetalhe);

    const sucesso = await safeApply.executarRollback?.(
        'Rollback solicitado pelo painel de Alterações.'
    );

    if (sucesso) {
        fecharDrawer(drawers.alteracao);
        await carregar({ silencioso: true });
    }
}


/* ==========================================================================
   RECONCILIAR
========================================================================== */

async function reconciliar(opcoes = {}) {
    if (reconciliando) return false;

    const url =
        api.urls.reconciliarAlteracoes ||
        api.urls.reconciliar ||
        `${api.urls.alteracoes.endsWith('/') ? api.urls.alteracoes : `${api.urls.alteracoes}/`}reconciliar/`;

    if (!url) return false;

    reconciliando = true;
    atualizarEstadoBotoes();

    if (elementos.reconcileButton) {
        elementos.reconcileButton.classList.add('is-loading');
    }

    try {
        const resposta = await api.post(url, {});
        const dados = resposta?.dados ?? resposta ?? {};
        const ativa = dados.ativa || null;

        if (ativa) {
            estado.set('alteracoes.ativa', ativa);
            safeApply.sincronizar?.(ativa);
        }

        if (!opcoes.silencioso) {
            notificacao.sucesso(
                'Alterações reconciliadas',
                dados.mensagem || 'O estado das alterações foi reconciliado.'
            );
        }

        await carregar({ silencioso: true });
        return true;
    } catch (error) {
        if (!opcoes.silencioso) {
            const erro = normalizarErro(error);
            notificacao.erro(erro.titulo, erro.mensagem);
        }

        return false;
    } finally {
        reconciliando = false;

        if (elementos.reconcileButton) {
            elementos.reconcileButton.classList.remove('is-loading');
        }

        atualizarEstadoBotoes();
    }
}


/* ==========================================================================
   ALTERAÇÃO ATIVA
========================================================================== */

async function buscarAlteracaoAtiva() {
    const atual = estado.get('alteracoes.ativa');

    if (atual && STATUS_ATIVOS.has(statusAlteracao(atual))) {
        try {
            const resposta = await api.get(urlAlteracao(obterId(atual)));
            const atualizada = extrairAlteracao(resposta);

            if (atualizada && STATUS_ATIVOS.has(statusAlteracao(atualizada))) {
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

    try {
        const resposta = await api.get(api.urls.alteracoes, { limite: 100 });
        const ativaApi = extrairAtiva(resposta);

        if (ativaApi) {
            estado.set('alteracoes.ativa', ativaApi);
            atualizarAlteracao(ativaApi);
            return ativaApi;
        }

        const lista = extrairLista(resposta);
        const ativas = encontrarAtivas(lista);

        if (ativas.length > 1) {
            console.warn(
                '[MoonShield Network] Estado inconsistente: múltiplas alterações ativas.',
                ativas.map(item => obterId(item))
            );
        }

        const ativa = ativas[0] || null;
        estado.set('alteracoes.ativa', ativa);

        return ativa;
    } catch {
        return null;
    }
}


/* ==========================================================================
   ATUALIZAR ALTERAÇÃO / BADGE / CONTROLES
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

    if (STATUS_ATIVOS.has(statusAlteracao(alteracao))) {
        estado.set('alteracoes.ativa', alteracao);
    } else {
        const ativa = estado.get('alteracoes.ativa');

        if (ativa && String(obterId(ativa)) === String(id)) {
            estado.set('alteracoes.ativa', null);
        }
    }

    renderizar();

    if (
        alteracaoDetalhe &&
        String(obterId(alteracaoDetalhe)) === String(id)
    ) {
        alteracaoDetalhe = alteracao;
        preencherDetalhe(alteracao);
    }
}


function atualizarBadge(lista = estado.get('alteracoes.lista', [])) {
    const pendentes = lista.filter(item => STATUS_ATIVOS.has(statusAlteracao(item))).length;
    const badge = $('#sidebarChangesBadge');

    setText(badge, pendentes, '0');
    setHidden(badge, pendentes <= 0);
}


function definirCarregando(ativo) {
    if (elementos.refreshButton) {
        elementos.refreshButton.disabled = Boolean(ativo);
        elementos.refreshButton.classList.toggle('is-loading', Boolean(ativo));
    }
}


function atualizarEstadoBotoes() {
    if (elementos.reconcileButton) {
        elementos.reconcileButton.disabled = reconciliando;
    }

    if (alteracaoDetalhe) preencherDetalhe(alteracaoDetalhe);
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

function encontrarAtivas(lista) {
    return (lista || [])
        .filter(item => STATUS_ATIVOS.has(statusAlteracao(item)))
        .sort((a, b) => {
            const da = new Date(a.iniciada_em || a.criado_em || 0).getTime();
            const db = new Date(b.iniciada_em || b.criado_em || 0).getTime();
            return db - da;
        });
}


function statusAlteracao(alteracao) {
    return String(alteracao?.status || '').trim().toLowerCase();
}


function obterId(alteracao) {
    return alteracao?.id || alteracao?.uuid || alteracao?.alteracao_id || null;
}


function obterUsuario(alteracao) {
    const usuario =
        alteracao?.solicitado_por ||
        alteracao?.usuario ||
        alteracao?.requested_by;

    if (!usuario) return 'Sistema';
    if (typeof usuario === 'string') return usuario;

    return usuario.nome || usuario.full_name || usuario.username || usuario.email || 'Sistema';
}


function nivelStatus(status) {
    if (status === 'confirmed') return 'ok';
    if (status === 'reverted') return 'warning';
    if (status === 'failed') return 'error';
    if (['applying', 'validating'].includes(status)) return 'pending';
    if (['waiting_confirmation', 'rollback'].includes(status)) return 'warning';

    return 'pending';
}


function segundosRestantes(alteracao) {
    if (alteracao?.segundos_restantes !== undefined && alteracao?.segundos_restantes !== null) {
        return Math.max(0, Math.ceil(Number(alteracao.segundos_restantes) || 0));
    }

    if (alteracao?.expira_em) return segundosAte(alteracao.expira_em);

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


function urlAlteracao(id, acao = '') {
    const base = api.urls.alteracoes;
    if (!base) throw new Error('URL de alterações não configurada.');

    const normalizada = base.endsWith('/') ? base : `${base}/`;
    const recurso = `${normalizada}${encodeURIComponent(String(id))}/`;

    return acao ? `${recurso}${acao}/` : recurso;
}


function extrairLista(resposta) {
    const dados = resposta?.dados ?? resposta ?? {};

    if (Array.isArray(dados)) return dados;
    if (Array.isArray(dados.alteracoes)) return dados.alteracoes;
    if (Array.isArray(dados.resultados)) return dados.resultados;
    if (Array.isArray(dados.lista)) return dados.lista;

    return [];
}


function extrairAtiva(resposta) {
    const dados = resposta?.dados ?? resposta ?? {};
    const ativa = dados.ativa || dados.alteracao_ativa || null;

    return ativa && typeof ativa === 'object' ? ativa : null;
}


function extrairAlteracao(resposta) {
    const dados = resposta?.dados ?? resposta ?? {};

    return (
        dados.alteracao ||
        dados.resultado?.alteracao ||
        (dados.id ? dados : null) ||
        resposta?.alteracao ||
        null
    );
}


/* ==========================================================================
   ATIVAÇÃO / EXPORT
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
