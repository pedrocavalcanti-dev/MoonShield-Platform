/**
 * MoonShield Network Panel
 * ========================
 *
 * Orquestrador principal do frontend da Rede.
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
let aplicandoTudo = false;
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

    // A operação ativa precisa ser conhecida antes de liberar qualquer mutação.
    await verificarAlteracaoAtiva();

    iniciarAtualizacaoPeriodica();
    atualizarEstadoControles();

    document.documentElement.classList.add('network-panel-ready');
}


/* ==========================================================================
   INFRAESTRUTURA / MÓDULOS
========================================================================== */

function inicializarInfraestrutura() {
    inicializarBarraLateral({ onNavigate: ativarSecao });
    inicializarModal();
    inicializarDrawers();
    safeApply.inicializar();
}


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
   CACHE / EVENTOS
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
        if (!document.hidden) atualizarStatusSilencioso({ verificarAtiva: true });
    });

    document.addEventListener('visibilitychange', () => {
        if (!document.hidden) atualizarStatusSilencioso({ verificarAtiva: true });
    });

    document.addEventListener('moonshield:network-lock-change', atualizarEstadoControles);
    document.addEventListener('moonshield:safe-apply-finished', atualizarEstadoControles);
    document.addEventListener('moonshield:safe-apply-confirmed', atualizarEstadoControles);
    document.addEventListener('moonshield:safe-apply-rollback', atualizarEstadoControles);

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
            notificacao.erro(
                'Agent indisponível',
                erro.mensagem || 'Não foi possível consultar o MoonShield Agent.'
            );
        }

        throw error;
    }
}


async function atualizarStatusSilencioso({ verificarAtiva = false } = {}) {
    try {
        await carregarStatus({ silencioso: true });

        // O Safe Apply possui polling próprio enquanto há operação conhecida.
        // Só procuramos uma operação global quando necessário.
        if (verificarAtiva || !safeApply.ativo?.()) {
            await verificarAlteracaoAtiva();
        }

        atualizarHorario();
    } catch {
        // Atualização silenciosa não deve gerar erro visual recorrente.
    }
}


/* ==========================================================================
   AGENT / BADGES
========================================================================== */

function atualizarStatusAgent(agent = {}) {
    const online = Boolean(agent.online);
    const status = elementos.topbarAgentStatus;

    if (status) {
        status.classList.remove(
            'np-status-pill--ok',
            'np-status-pill--warning',
            'np-status-pill--error',
            'np-status-pill--pending'
        );
        status.classList.add(online ? 'np-status-pill--ok' : 'np-status-pill--error');
        status.dataset.status = online ? 'online' : 'offline';
        status.innerHTML = `<span class="np-status-dot"></span>${online ? 'Agent Online' : 'Agent Offline'}`;
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
   CONTROLES / LOCK GLOBAL
========================================================================== */

function atualizarEstadoControles() {
    const bloqueado = Boolean(safeApply.ocupado?.());
    const agentOnline = Boolean(estado.get('agent.online'));

    estado.set('ui.redeBloqueada', bloqueado);

    if (elementos.applyAllButton) {
        elementos.applyAllButton.disabled = bloqueado || aplicandoTudo || carregando || !agentOnline;
        elementos.applyAllButton.setAttribute('aria-disabled', elementos.applyAllButton.disabled ? 'true' : 'false');

        if (bloqueado) {
            elementos.applyAllButton.title = 'Existe uma alteração de rede em andamento.';
        } else {
            elementos.applyAllButton.removeAttribute('title');
        }
    }

    document.documentElement.classList.toggle('network-mutation-locked', bloqueado);
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
        await verificarAlteracaoAtiva();
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
        atualizarEstadoControles();
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

        const ativa = dados.alteracao_ativa;
        if (ativa) {
            estado.set('alteracoes.ativa', ativa);
            safeApply.sincronizar?.(ativa);
        }

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
        atualizarEstadoControles();
    }
}


/* ==========================================================================
   APLICAR TUDO
========================================================================== */

async function aplicarTudo() {
    if (aplicandoTudo || safeApply.ocupado?.()) {
        const ativa = safeApply.obterAlteracaoAtiva?.();

        notificacao.aviso(
            'Alteração em andamento',
            ativa?.titulo
                ? `${ativa.titulo}. Confirme ou reverta antes de iniciar outra operação.`
                : 'Confirme ou reverta a alteração atual antes de aplicar outra.'
        );

        return false;
    }

    const confirmado = await safeApply.confirmarOperacao?.({
        titulo: 'Aplicar configuração completa?',
        mensagem: 'Interfaces, roteamento e NAT serão enviados ao MoonShield Agent.',
        detalhes: 'Um snapshot será criado e o rollback automático ficará armado até a confirmação.',
        perigoso: false,
    });

    if (confirmado === false) return false;

    // Lock local ANTES do POST. Isso fecha a janela de duplo clique/request.
    if (!safeApply.reservarOperacao?.('apply-all')) {
        notificacao.aviso(
            'Alteração em andamento',
            'Outra operação de rede foi iniciada. Aguarde a conclusão.'
        );
        return false;
    }

    aplicandoTudo = true;
    atualizarEstadoControles();
    definirBotaoCarregando(elementos.applyAllButton, true);

    safeApply.mostrarOperacao?.({
        titulo: 'Aplicando configuração de rede',
        descricao: 'Validando o estado desejado, preparando snapshot e armando o rollback.',
    });

    try {
        const resposta = await api.post(api.urls.aplicarTudo, {});
        const alteracao = resposta?.dados?.alteracao || resposta?.dados?.ativa;

        if (!alteracao) {
            throw new Error('A API não retornou os dados da alteração.');
        }

        estado.set('alteracoes.ativa', alteracao);
        alteracoes.atualizarAlteracao?.(alteracao);

        safeApply.ocultarOperacao?.();
        safeApply.sincronizar?.(alteracao);

        if (String(alteracao.status || '') === 'waiting_confirmation') {
            safeApply.abrir?.(alteracao);

            notificacao.aviso(
                'Confirmação necessária',
                'A configuração foi aplicada. Confirme o acesso antes do término do Safe Apply.'
            );
        }

        await atualizarDepoisDeAlteracao();

        return true;
    } catch (error) {
        safeApply.ocultarOperacao?.();

        const existente = safeApply.extrairAlteracaoDeErro?.(error);

        if (existente) {
            estado.set('alteracoes.ativa', existente);
            safeApply.sincronizar?.(existente);

            notificacao.aviso(
                'Alteração já em andamento',
                existente.titulo
                    ? `${existente.titulo} precisa ser concluída antes de iniciar outra.`
                    : 'Existe uma alteração de rede que precisa ser concluída.'
            );

            await atualizarDepoisDeAlteracao();
            return false;
        }

        safeApply.liberarReserva?.();
        exibirErroOperacao(error, 'Não foi possível aplicar a configuração completa.');

        return false;
    } finally {
        aplicandoTudo = false;
        definirBotaoCarregando(elementos.applyAllButton, false);
        atualizarEstadoControles();
    }
}


/* ==========================================================================
   ALTERAÇÃO ATIVA
========================================================================== */

async function verificarAlteracaoAtiva() {
    // Se já conhecemos uma alteração ativa, o polling do Safe Apply é a fonte
    // primária. Evita requests duplicados no mesmo intervalo.
    if (safeApply.ativo?.()) {
        return safeApply.obterAlteracaoAtiva?.() || null;
    }

    try {
        const alteracao = await alteracoes.buscarAlteracaoAtiva?.();

        if (!alteracao) {
            if (!safeApply.reservado?.()) {
                estado.set('alteracoes.ativa', null);
                safeApply.fecharSeInativo?.();
            }

            atualizarEstadoControles();
            return null;
        }

        estado.set('alteracoes.ativa', alteracao);
        safeApply.sincronizar?.(alteracao);
        atualizarEstadoControles();

        return alteracao;
    } catch (error) {
        console.warn('[MoonShield Network] Não foi possível verificar alteração ativa:', error);
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

    const ativa = estado.get('alteracoes.ativa');
    if (ativa) safeApply.sincronizar?.(ativa);
    else await verificarAlteracaoAtiva();

    atualizarHorario();
    atualizarEstadoControles();
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

    atualizarEstadoControles();
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
   LOADING
========================================================================== */

function definirCarregamentoGlobal(ativo) {
    document.documentElement.classList.toggle('network-loading', Boolean(ativo));
    elementos.refreshButton?.classList.toggle('is-loading', Boolean(ativo));

    if (elementos.refreshButton) elementos.refreshButton.disabled = Boolean(ativo);

    atualizarEstadoControles();
}


function definirBotaoCarregando(botao, ativo) {
    if (!botao) return;

    if (ativo) {
        if (!botao.dataset.originalHtml) botao.dataset.originalHtml = botao.innerHTML;
        botao.disabled = true;
        botao.classList.add('is-loading');
        botao.innerHTML = '<span class="np-spinner"></span>';
        return;
    }

    botao.classList.remove('is-loading');

    if (botao.dataset.originalHtml) {
        botao.innerHTML = botao.dataset.originalHtml;
        delete botao.dataset.originalHtml;
    }

    if (botao !== elementos.applyAllButton) botao.disabled = false;
}


/* ==========================================================================
   HORÁRIO / TIMERS
========================================================================== */

function atualizarHorario() {
    const agora = new Date();
    estado.set('ui.ultimaAtualizacao', agora.toISOString());
    setText(elementos.lastUpdateTime, formatarHorario(agora));
}


function iniciarAtualizacaoPeriodica() {
    pararAtualizacaoPeriodica();

    statusTimer = window.setInterval(() => {
        if (document.hidden) return;
        atualizarStatusSilencioso({ verificarAtiva: false });
    }, CONFIG.intervaloStatus);
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
    atualizarEstadoControles,
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
