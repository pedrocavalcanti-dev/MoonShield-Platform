/**
 * MoonShield Network Panel
 * ========================
 *
 * Orquestrador principal do frontend da Rede.
 *
 * Responsabilidades:
 * - inicializar o painel;
 * - controlar navegação;
 * - carregar estado inicial;
 * - sincronizar status global;
 * - controlar sidebar mobile;
 * - disparar atualização global;
 * - detectar interfaces;
 * - aplicar configuração completa;
 * - integrar módulos de seção;
 * - restaurar seção pela URL;
 * - acompanhar Safe Apply pendente.
 *
 * Nenhum fetch direto deve ser adicionado aqui.
 * Comunicação HTTP pertence a nucleo/api.js.
 */

'use strict';

import { api } from './nucleo/api.js';
import { estado } from './nucleo/estado.js';
import { $, $$, setText, setHidden } from './nucleo/dom.js';
import { formatarHorario, normalizarErro } from './nucleo/utilitarios.js';

import { inicializarBarraLateral, fecharSidebarMobile } from './componentes/barra_lateral.js';
import { notificacao } from './componentes/notificacoes.js';
import { inicializarModal } from './componentes/modal.js';
import { inicializarDrawers } from './componentes/drawer.js';
import { safeApply } from './componentes/safe_apply.js';

import { visaoGeral } from './secoes/visao_geral.js';
import { interfaces } from './secoes/interfaces.js';
import { roteamentoNat } from './secoes/roteamento_nat.js';
import { diagnostico } from './secoes/diagnostico.js';
import { alteracoes } from './secoes/alteracoes.js';


/* ==========================================================================
   CONFIGURAÇÃO
========================================================================== */

const CONFIG = {
    secaoInicial: 'visao-geral',
    intervaloStatus: 30000,
    intervaloAlteracaoAtiva: 5000,
    hashPrefix: '#',
};

const SECOES = new Set([
    'visao-geral',
    'interfaces',
    'roteamento-nat',
    'diagnostico',
    'alteracoes',
]);

const MODULOS = {
    'visao-geral': visaoGeral,
    'interfaces': interfaces,
    'roteamento-nat': roteamentoNat,
    'diagnostico': diagnostico,
    'alteracoes': alteracoes,
};

let inicializado = false;
let carregando = false;
let statusTimer = null;


/* ==========================================================================
   ELEMENTOS
========================================================================== */

const elementos = {
    pageTitle: null,
    pageEyebrow: null,
    lastUpdateTime: null,
    topbarAgentStatus: null,
    refreshButton: null,
    detectButton: null,
    applyAllButton: null,
    overviewRefreshButton: null,
    interfacesDetectButton: null,
};


/* ==========================================================================
   BOOT
========================================================================== */

async function iniciarPainel() {
    if (inicializado) return;
    inicializado = true;

    cachearElementos();
    registrarErrosGlobais();
    inicializarInfraestrutura();
    registrarEventosGlobais();
    inicializarModulos();

    const secaoInicial = obterSecaoInicial();
    ativarSecao(secaoInicial, { atualizarHash: false });

    await carregarEstadoInicial();
    iniciarAtualizacaoPeriodica();

    document.documentElement.classList.add('network-panel-ready');
}


/* ==========================================================================
   INFRAESTRUTURA
========================================================================== */

function inicializarInfraestrutura() {
    inicializarBarraLateral({ onNavigate: ativarSecao });
    inicializarModal();
    inicializarDrawers();
    safeApply.inicializar();
}


/* ==========================================================================
   MÓDULOS
========================================================================== */

function inicializarModulos() {
    Object.entries(MODULOS).forEach(([nome, modulo]) => {
        if (!modulo || typeof modulo.inicializar !== 'function') {
            console.warn(`[MoonShield Network] Módulo "${nome}" não possui inicializar().`);
            return;
        }

        try {
            modulo.inicializar();
        } catch (error) {
            console.error(`[MoonShield Network] Falha ao inicializar "${nome}":`, error);
        }
    });
}


/* ==========================================================================
   CACHE
========================================================================== */

function cachearElementos() {
    elementos.pageTitle = $('#pageTitle');
    elementos.pageEyebrow = $('#pageEyebrow');
    elementos.lastUpdateTime = $('#lastUpdateTime');
    elementos.topbarAgentStatus = $('#topbarAgentStatus');

    elementos.refreshButton = $('#refreshNetworkButton');
    elementos.detectButton = $('#detectInterfacesButton');
    elementos.applyAllButton = $('#applyAllButton');

    elementos.overviewRefreshButton = $('#overviewRefreshButton');
    elementos.interfacesDetectButton = $('#interfacesDetectButton');
}


/* ==========================================================================
   EVENTOS
========================================================================== */

function registrarEventosGlobais() {
    elementos.refreshButton?.addEventListener('click', atualizarTudo);
    elementos.overviewRefreshButton?.addEventListener('click', atualizarTudo);

    elementos.detectButton?.addEventListener('click', detectarInterfaces);
    elementos.interfacesDetectButton?.addEventListener('click', detectarInterfaces);

    elementos.applyAllButton?.addEventListener('click', aplicarTudo);

    window.addEventListener('hashchange', () => {
        const secao = obterSecaoHash();
        if (secao) ativarSecao(secao, { atualizarHash: false });
    });

    window.addEventListener('focus', () => {
        if (!document.hidden) atualizarStatusSilencioso();
    });

    document.addEventListener('visibilitychange', () => {
        if (!document.hidden) atualizarStatusSilencioso();
    });

    window.addEventListener('beforeunload', () => {
        pararAtualizacaoPeriodica();
        safeApply.destruir?.();
    });
}


/* ==========================================================================
   NAVEGAÇÃO
========================================================================== */

function ativarSecao(nome, opcoes = {}) {
    const { atualizarHash = true } = opcoes;
    if (!SECOES.has(nome)) nome = CONFIG.secaoInicial;

    $$('[data-section-panel]').forEach(section => {
        section.classList.toggle('is-active', section.dataset.sectionPanel === nome);
    });

    $$('.np-nav__item[data-section]').forEach(item => {
        const ativo = item.dataset.section === nome;
        item.classList.toggle('is-active', ativo);
        item.setAttribute('aria-current', ativo ? 'page' : 'false');
    });

    const item = $(`.np-nav__item[data-section="${nome}"]`);
    const titulo = item?.dataset.title || tituloSecao(nome);
    const eyebrow = item?.dataset.eyebrow || 'Rede';

    setText(elementos.pageTitle, titulo);
    setText(elementos.pageEyebrow, eyebrow);

    estado.set('ui.secaoAtual', nome);
    fecharSidebarMobile();

    if (atualizarHash) {
        const hash = `${CONFIG.hashPrefix}${nome}`;
        if (window.location.hash !== hash) history.replaceState(null, '', hash);
    }

    const modulo = MODULOS[nome];
    if (modulo && typeof modulo.aoAtivar === 'function') {
        Promise.resolve(modulo.aoAtivar()).catch(error => {
            console.error(`[MoonShield Network] Falha ao ativar seção "${nome}":`, error);
        });
    }
}


function obterSecaoInicial() {
    return obterSecaoHash() || estado.get('ui.secaoAtual') || CONFIG.secaoInicial;
}


function obterSecaoHash() {
    const nome = window.location.hash.replace(/^#/, '').trim();
    return SECOES.has(nome) ? nome : null;
}


function tituloSecao(nome) {
    const titulos = {
        'visao-geral': 'Visão Geral',
        'interfaces': 'Interfaces',
        'roteamento-nat': 'Roteamento & NAT',
        'diagnostico': 'Diagnóstico',
        'alteracoes': 'Alterações',
    };

    return titulos[nome] || 'Rede';
}


/* ==========================================================================
   CARGA INICIAL
========================================================================== */

async function carregarEstadoInicial() {
    if (carregando) return;
    carregando = true;

    definirCarregamentoGlobal(true);

    try {
        const resultados = await Promise.allSettled([
            carregarStatus(),
            interfaces.carregar?.(),
            roteamentoNat.carregar?.(),
            alteracoes.carregar?.(),
        ]);

        resultados.forEach((resultado, indice) => {
            if (resultado.status === 'rejected') {
                console.warn(`[MoonShield Network] Carga inicial ${indice} falhou:`, resultado.reason);
            }
        });

        sincronizarModulos();
        atualizarHorario();
    } finally {
        carregando = false;
        definirCarregamentoGlobal(false);
    }
}


/* ==========================================================================
   STATUS
========================================================================== */

async function carregarStatus({ silencioso = false } = {}) {
    try {
        const resposta = await api.get(api.urls.status);
        const dados = resposta?.dados || {};

        estado.set('status', dados);
        estado.set('agent', dados.agent || {});

        atualizarStatusAgent(dados.agent || {});
        atualizarBadgesGlobais(dados);

        visaoGeral.atualizarStatus?.(dados);

        return dados;
    } catch (error) {
        const erro = normalizarErro(error);

        estado.set('agent', {
            online: false,
            status: {},
            erro,
        });

        atualizarStatusAgent({ online: false, erro });

        if (!silencioso) {
            notificacao.erro('Agent indisponível', erro.mensagem || 'Não foi possível consultar o MoonShield Agent.');
        }

        throw error;
    }
}


async function atualizarStatusSilencioso() {
    try {
        await carregarStatus({ silencioso: true });
        await verificarAlteracaoAtiva();
        atualizarHorario();
    } catch {
        // Atualização silenciosa não deve gerar erro visual recorrente.
    }
}


/* ==========================================================================
   AGENT
========================================================================== */

function atualizarStatusAgent(agent = {}) {
    const online = Boolean(agent.online);
    const status = elementos.topbarAgentStatus;

    if (status) {
        status.classList.remove('np-status-pill--ok', 'np-status-pill--warning', 'np-status-pill--error', 'np-status-pill--pending');
        status.classList.add(online ? 'np-status-pill--ok' : 'np-status-pill--error');
        status.dataset.status = online ? 'online' : 'offline';

        const texto = online ? 'Agent Online' : 'Agent Offline';
        status.innerHTML = `<span class="np-status-dot"></span>${texto}`;
    }

    atualizarStatusSidebarAgent(agent);

    document.documentElement.dataset.agent = online ? 'online' : 'offline';
}


function atualizarStatusSidebarAgent(agent = {}) {
    const online = Boolean(agent.online);
    const indicator = $('#sidebarAgentIndicator');
    const label = $('#sidebarAgentLabel');
    const backend = $('#sidebarAgentBackend');

    indicator?.classList.remove('is-online', 'is-offline', 'is-pending');
    indicator?.classList.add(online ? 'is-online' : 'is-offline');

    setText(label, online ? 'Online' : 'Offline');

    const backendNome =
        agent.status?.backend ||
        estado.get('status.agent.status.backend') ||
        estado.get('status.backend') ||
        '—';

    setText(backend, backendNome);
}


/* ==========================================================================
   BADGES
========================================================================== */

function atualizarBadgesGlobais(dados = {}) {
    const totalInterfaces = Number(dados.interfaces?.total || 0);
    const pendentes = Number(dados.alteracoes?.pendentes || 0);

    const interfaceBadge = $('#sidebarInterfacesBadge');
    const changesBadge = $('#sidebarChangesBadge');

    setText(interfaceBadge, totalInterfaces);
    setHidden(interfaceBadge, totalInterfaces <= 0);

    setText(changesBadge, pendentes);
    setHidden(changesBadge, pendentes <= 0);
}


/* ==========================================================================
   ATUALIZAÇÃO GLOBAL
========================================================================== */

async function atualizarTudo() {
    if (carregando) return;

    carregando = true;
    definirCarregamentoGlobal(true);

    try {
        const resultados = await Promise.allSettled([
            carregarStatus({ silencioso: true }),
            interfaces.carregar?.({ silencioso: true }),
            roteamentoNat.carregar?.({ silencioso: true }),
            alteracoes.carregar?.({ silencioso: true }),
        ]);

        const falhas = resultados.filter(item => item.status === 'rejected');

        sincronizarModulos();
        atualizarHorario();

        if (falhas.length) {
            notificacao.aviso('Atualização parcial', `${falhas.length} módulo(s) não puderam ser atualizados.`);
        } else {
            notificacao.sucesso('Rede atualizada', 'Os dados do painel foram atualizados.');
        }
    } catch (error) {
        exibirErroOperacao(error, 'Não foi possível atualizar o painel.');
    } finally {
        carregando = false;
        definirCarregamentoGlobal(false);
    }
}


/* ==========================================================================
   DETECTAR INTERFACES
========================================================================== */

async function detectarInterfaces() {
    if (carregando) return;

    const botoes = [elementos.detectButton, elementos.interfacesDetectButton].filter(Boolean);
    botoes.forEach(botao => definirBotaoCarregando(botao, true));

    try {
        const resposta = await api.post(api.urls.detectarInterfaces, {});
        const dados = resposta?.dados || {};

        estado.set('interfaces.lista', Array.isArray(dados.interfaces) ? dados.interfaces : []);
        estado.set('interfaces.backend', dados.backend || null);

        interfaces.renderizar?.();
        visaoGeral.atualizarInterfaces?.();
        atualizarResumoBackend();

        notificacao.sucesso(
            'Interfaces detectadas',
            `${Number(dados.total || dados.interfaces?.length || 0)} interface(s) encontrada(s).`
        );

        await carregarStatus({ silencioso: true });
        atualizarHorario();
    } catch (error) {
        exibirErroOperacao(error, 'Não foi possível detectar as interfaces do sistema.');
    } finally {
        botoes.forEach(botao => definirBotaoCarregando(botao, false));
    }
}


/* ==========================================================================
   APLICAR TUDO
========================================================================== */

async function aplicarTudo() {
    if (safeApply.ativo?.()) {
        notificacao.aviso('Alteração pendente', 'Confirme ou reverta a alteração atual antes de aplicar outra.');
        return;
    }

    const confirmado = await safeApply.confirmarOperacao?.({
        titulo: 'Aplicar configuração completa?',
        mensagem: 'Interfaces, roteamento e NAT serão enviados ao MoonShield Agent.',
        detalhes: 'Um snapshot será criado e o rollback automático ficará armado até a confirmação.',
        perigoso: false,
    });

    if (confirmado === false) return;

    definirBotaoCarregando(elementos.applyAllButton, true);

    try {
        safeApply.mostrarOperacao?.({
            titulo: 'Aplicando configuração de rede',
            descricao: 'O MoonShield está preparando uma alteração segura.',
        });

        const resposta = await api.post(api.urls.aplicarTudo, {});
        const alteracao = resposta?.dados?.alteracao;

        safeApply.ocultarOperacao?.();

        if (!alteracao) throw new Error('A API não retornou os dados da alteração.');

        estado.set('alteracoes.ativa', alteracao);

        alteracoes.atualizarAlteracao?.(alteracao);
        safeApply.abrir?.(alteracao);

        await atualizarDepoisDeAlteracao();

        notificacao.aviso(
            'Confirmação necessária',
            'A configuração foi aplicada. Confirme o acesso antes do término do rollback.'
        );
    } catch (error) {
        safeApply.ocultarOperacao?.();
        exibirErroOperacao(error, 'Não foi possível aplicar a configuração completa.');
    } finally {
        definirBotaoCarregando(elementos.applyAllButton, false);
    }
}


/* ==========================================================================
   ALTERAÇÃO ATIVA
========================================================================== */

async function verificarAlteracaoAtiva() {
    try {
        const alteracao = await alteracoes.buscarAlteracaoAtiva?.();

        if (!alteracao) {
            estado.set('alteracoes.ativa', null);
            safeApply.fecharSeInativo?.();
            return null;
        }

        estado.set('alteracoes.ativa', alteracao);
        safeApply.sincronizar?.(alteracao);

        return alteracao;
    } catch (error) {
        console.warn('[MoonShield Network] Não foi possível reconciliar alteração ativa:', error);
        return null;
    }
}


async function atualizarDepoisDeAlteracao() {
    const resultados = await Promise.allSettled([
        carregarStatus({ silencioso: true }),
        interfaces.carregar?.({ silencioso: true }),
        roteamentoNat.carregar?.({ silencioso: true }),
        alteracoes.carregar?.({ silencioso: true }),
    ]);

    resultados.forEach(resultado => {
        if (resultado.status === 'rejected') {
            console.warn('[MoonShield Network] Atualização pós-alteração incompleta:', resultado.reason);
        }
    });

    sincronizarModulos();
    atualizarHorario();
}


/* ==========================================================================
   SINCRONIZAÇÃO ENTRE MÓDULOS
========================================================================== */

function sincronizarModulos() {
    atualizarResumoBackend();

    visaoGeral.sincronizar?.();
    interfaces.sincronizar?.();
    roteamentoNat.sincronizar?.();
    alteracoes.sincronizar?.();

    const ativa = estado.get('alteracoes.ativa');
    if (ativa) safeApply.sincronizar?.(ativa);
}


function atualizarResumoBackend() {
    const status = estado.get('status') || {};
    const lista = estado.get('interfaces.lista') || [];

    const backend =
        status.agent?.status?.backend ||
        estado.get('interfaces.backend') ||
        'NetworkManager';

    setText($('#sidebarBackendName'), backend || 'Backend desconhecido');
    setText($('#sidebarInterfaceSummary'), `${lista.length} interface(s) detectada(s)`);
}


/* ==========================================================================
   LOADING GLOBAL
========================================================================== */

function definirCarregamentoGlobal(ativo) {
    document.documentElement.classList.toggle('network-loading', Boolean(ativo));
    elementos.refreshButton?.classList.toggle('is-loading', Boolean(ativo));

    if (elementos.refreshButton) elementos.refreshButton.disabled = Boolean(ativo);
}


/* ==========================================================================
   LOADING DE BOTÃO
========================================================================== */

function definirBotaoCarregando(botao, ativo) {
    if (!botao) return;

    if (ativo) {
        if (!botao.dataset.originalHtml) botao.dataset.originalHtml = botao.innerHTML;
        botao.disabled = true;
        botao.classList.add('is-loading');
        botao.innerHTML = '<span class="np-spinner"></span>';
        return;
    }

    botao.disabled = false;
    botao.classList.remove('is-loading');

    if (botao.dataset.originalHtml) {
        botao.innerHTML = botao.dataset.originalHtml;
        delete botao.dataset.originalHtml;
    }
}


/* ==========================================================================
   HORÁRIO
========================================================================== */

function atualizarHorario() {
    const agora = new Date();
    estado.set('ui.ultimaAtualizacao', agora.toISOString());
    setText(elementos.lastUpdateTime, formatarHorario(agora));
}


/* ==========================================================================
   TIMERS
========================================================================== */

function iniciarAtualizacaoPeriodica() {
    pararAtualizacaoPeriodica();

    statusTimer = window.setInterval(() => {
        if (document.hidden) return;
        atualizarStatusSilencioso();
    }, CONFIG.intervaloStatus);

    verificarAlteracaoAtiva();
}


function pararAtualizacaoPeriodica() {
    if (!statusTimer) return;
    window.clearInterval(statusTimer);
    statusTimer = null;
}


/* ==========================================================================
   ERROS
========================================================================== */

function exibirErroOperacao(error, fallback) {
    const erro = normalizarErro(error);

    console.error('[MoonShield Network]', error);

    notificacao.erro(
        erro.titulo || 'Erro de rede',
        erro.mensagem || fallback || 'Não foi possível concluir a operação.'
    );
}


function registrarErrosGlobais() {
    window.addEventListener('error', evento => {
        console.error('[MoonShield Network] Erro global:', evento.error || evento.message);
    });

    window.addEventListener('unhandledrejection', evento => {
        console.error('[MoonShield Network] Promise rejeitada:', evento.reason);
    });
}


/* ==========================================================================
   API PÚBLICA
========================================================================== */

window.MoonShieldNetwork = {
    atualizar: atualizarTudo,
    detectarInterfaces,
    aplicarTudo,
    ativarSecao,
    carregarStatus,
    verificarAlteracaoAtiva,
    atualizarDepoisDeAlteracao,
    estado,
};


/* ==========================================================================
   INICIALIZAÇÃO
========================================================================== */

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', iniciarPainel, { once: true });
} else {
    iniciarPainel();
}