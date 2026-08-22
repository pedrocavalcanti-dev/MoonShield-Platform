/**
 * MoonShield Network Panel
 * Seção: Diagnóstico
 */

'use strict';

import { api } from '../nucleo/api.js';
import { estado } from '../nucleo/estado.js';
import {
    $, $$, setText, setHidden, clonarTemplate, setStatusPill, limpar,
} from '../nucleo/dom.js';
import {
    formatarDataHora, normalizarErro, garantirArray, paraBooleano,
} from '../nucleo/utilitarios.js';
import { notificacao } from '../componentes/notificacoes.js';

let inicializado = false;
let executando = false;

const elementos = {
    button: null,
    total: null,
    success: null,
    warnings: null,
    errors: null,
    healthPanel: null,
    healthTitle: null,
    healthDescription: null,
    healthStatus: null,
    lastExecution: null,
    container: null,
    empty: null,
    template: null,
    metaPanel: null,
    backend: null,
    overallResult: null,
    executedAt: null,
};


/* ==========================================================================
   INICIALIZAÇÃO
========================================================================== */

function inicializar() {
    if (inicializado) return;
    inicializado = true;

    cachearElementos();
    registrarEventos();

    const resultado = estado.get('diagnostico.resultado');
    if (resultado) renderizar(resultado);
}


function cachearElementos() {
    elementos.button = $('#runDiagnosticsButton');

    elementos.total = $('#diagnosticTotal');
    elementos.success = $('#diagnosticSuccess');
    elementos.warnings = $('#diagnosticWarnings');
    elementos.errors = $('#diagnosticErrors');

    elementos.healthPanel = $('#diagnosticHealthPanel');
    elementos.healthTitle = $('#diagnosticHealthTitle');
    elementos.healthDescription = $('#diagnosticHealthDescription');
    elementos.healthStatus = $('#diagnosticHealthStatus');

    elementos.lastExecution = $('#diagnosticLastExecution');

    elementos.container = $('#diagnosticChecksContainer');
    elementos.empty = $('#diagnosticEmptyState');
    elementos.template = $('#diagnosticCheckTemplate');

    elementos.metaPanel = $('#diagnosticMetaPanel');
    elementos.backend = $('#diagnosticBackend');
    elementos.overallResult = $('#diagnosticOverallResult');
    elementos.executedAt = $('#diagnosticExecutedAt');
}


function registrarEventos() {
    elementos.button?.addEventListener('click', executar);

    elementos.container?.addEventListener('click', event => {
        const alvo = event.target instanceof Element ? event.target : null;
        const botao = alvo?.closest('[data-diagnostic-expand]');
        if (!botao) return;

        const check = botao.closest('[data-diagnostic-check]');
        const detalhes = $('[data-diagnostic-details]', check);
        if (!detalhes) return;

        const aberto = !detalhes.hidden;
        detalhes.hidden = aberto;
        botao.classList.toggle('is-open', !aberto);
        botao.setAttribute('aria-expanded', aberto ? 'false' : 'true');
    });
}


/* ==========================================================================
   EXECUTAR
========================================================================== */

async function executar() {
    if (executando) return;

    executando = true;
    estado.set('diagnostico.executando', true);

    definirCarregando(true);

    try {
        const resposta = await api.get(api.urls.diagnostico);
        const dados = resposta?.dados ?? resposta ?? {};

        estado.set('diagnostico.resultado', dados);
        estado.set('diagnostico.ultimaExecucao', new Date().toISOString());

        renderizar(dados);

        const resumo = resumir(dados);

        if (resumo.erros > 0) {
            notificacao.erro('Diagnóstico concluído', `${resumo.erros} problema(s) foram encontrados.`);
        } else if (resumo.avisos > 0) {
            notificacao.aviso('Diagnóstico concluído', `${resumo.avisos} aviso(s) requerem atenção.`);
        } else {
            notificacao.sucesso('Diagnóstico concluído', 'As verificações de rede foram concluídas sem falhas.');
        }
    } catch (error) {
        const erro = normalizarErro(error);
        renderizarErro(erro);
        notificacao.erro(erro.titulo, erro.mensagem);
    } finally {
        executando = false;
        estado.set('diagnostico.executando', false);
        definirCarregando(false);
    }
}


/* ==========================================================================
   RENDER
========================================================================== */

function renderizar(dados) {
    const checks = extrairChecks(dados);
    const resumo = resumir(dados, checks);
    const saudavel = determinarSaudavel(dados, resumo);

    renderizarResumo(resumo);
    renderizarSaude(dados, saudavel, resumo);
    renderizarChecks(checks);
    renderizarMeta(dados, saudavel);
}


function renderizarResumo(resumo) {
    setText(elementos.total, resumo.total, '0');
    setText(elementos.success, resumo.sucessos, '0');
    setText(elementos.warnings, resumo.avisos, '0');
    setText(elementos.errors, resumo.erros, '0');
}


/* ==========================================================================
   HEALTH
========================================================================== */

function renderizarSaude(dados, saudavel, resumo) {
    elementos.healthPanel?.classList.remove('is-ok', 'is-warning', 'is-error');

    let nivel = 'ok';
    let titulo = 'Rede operacional';
    let descricao = 'As verificações executadas não encontraram falhas críticas.';

    if (resumo.erros > 0 || saudavel === false) {
        nivel = 'error';
        titulo = 'Problemas de rede detectados';
        descricao = `${resumo.erros || 1} verificação(ões) apresentaram falha. Consulte os detalhes abaixo.`;
    } else if (resumo.avisos > 0) {
        nivel = 'warning';
        titulo = 'Rede operacional com avisos';
        descricao = `${resumo.avisos} verificação(ões) requerem atenção.`;
    }

    elementos.healthPanel?.classList.add(`is-${nivel}`);

    setText(elementos.healthTitle, dados.titulo || titulo);
    setText(elementos.healthDescription, dados.mensagem || dados.descricao || descricao);
    setStatusPill(elementos.healthStatus, nivel, nivel === 'ok' ? 'Saudável' : nivel === 'warning' ? 'Atenção' : 'Falha');
}


/* ==========================================================================
   CHECKS
========================================================================== */

function renderizarChecks(checks) {
    if (!elementos.container) return;

    $$('[data-diagnostic-check-rendered]', elementos.container).forEach(item => item.remove());

    setHidden(elementos.empty, checks.length > 0);

    checks.forEach(check => {
        const elemento = criarCheck(check);
        if (elemento) elementos.container.appendChild(elemento);
    });
}


function criarCheck(check) {
    const elemento = clonarTemplate(elementos.template, '[data-diagnostic-check]');
    if (!elemento) return null;

    const nivel = normalizarNivel(check);
    const detalhes = check.detalhes ?? check.details ?? check.dados ?? null;

    elemento.dataset.diagnosticCheckRendered = 'true';
    elemento.classList.add(`is-${nivel}`);

    const icon = $('[data-diagnostic-status-icon]', elemento);
    icon?.classList.remove('is-pending', 'is-ok', 'is-warning', 'is-error');
    icon?.classList.add(`is-${nivel}`);

    setText($('[data-diagnostic-name]', elemento), check.nome || check.titulo || check.name || 'Verificação');
    setText($('[data-diagnostic-code]', elemento), check.codigo || check.code || 'check');
    setText($('[data-diagnostic-message]', elemento), check.mensagem || check.message || check.descricao || '—');

    setStatusPill(
        $('[data-diagnostic-status]', elemento),
        nivel,
        nivel === 'ok' ? 'OK' : nivel === 'warning' ? 'Aviso' : nivel === 'error' ? 'Falha' : 'Pendente'
    );

    const detailsContainer = $('[data-diagnostic-details]', elemento);
    const detailsContent = $('[data-diagnostic-details-content]', elemento);
    const expand = $('[data-diagnostic-expand]', elemento);

    if (detalhes === null || detalhes === undefined || detalhes === '') {
        setHidden(detailsContainer, true);
        setHidden(expand, true);
    } else {
        setHidden(expand, false);
        setHidden(detailsContainer, true);

        try {
            detailsContent.textContent = typeof detalhes === 'string' ? detalhes : JSON.stringify(detalhes, null, 2);
        } catch {
            detailsContent.textContent = String(detalhes);
        }
    }

    return elemento;
}


/* ==========================================================================
   META
========================================================================== */

function renderizarMeta(dados, saudavel) {
    const executadoEm =
        dados.executado_em ||
        dados.executed_at ||
        estado.get('diagnostico.ultimaExecucao') ||
        new Date().toISOString();

    const backend =
        dados.backend ||
        dados.rede?.backend ||
        estado.get('interfaces.backend') ||
        estado.get('agent.status.backend') ||
        '—';

    setText(elementos.backend, backend);
    setText(elementos.overallResult, saudavel ? 'Saudável' : 'Com problemas');
    setText(elementos.executedAt, formatarDataHora(executadoEm));
    setText(elementos.lastExecution, `Executado em ${formatarDataHora(executadoEm)}`);

    setHidden(elementos.metaPanel, false);
}


/* ==========================================================================
   ERRO
========================================================================== */

function renderizarErro(erro) {
    elementos.healthPanel?.classList.remove('is-ok', 'is-warning');
    elementos.healthPanel?.classList.add('is-error');

    setText(elementos.healthTitle, erro.titulo || 'Falha no diagnóstico');
    setText(elementos.healthDescription, erro.mensagem || 'Não foi possível executar as verificações.');
    setStatusPill(elementos.healthStatus, 'error', 'Falha');

    setText(elementos.total, '—');
    setText(elementos.success, '—');
    setText(elementos.warnings, '—');
    setText(elementos.errors, '—');
}


/* ==========================================================================
   LOADING
========================================================================== */

function definirCarregando(ativo) {
    elementos.container?.classList.toggle('is-loading', Boolean(ativo));

    if (elementos.button) {
        elementos.button.disabled = Boolean(ativo);
        elementos.button.classList.toggle('is-loading', Boolean(ativo));
    }

    if (ativo) {
        setHidden(elementos.empty, true);
        $$('[data-diagnostic-check-rendered]', elementos.container).forEach(item => item.remove());
    }
}


/* ==========================================================================
   EXTRAÇÃO
========================================================================== */

function extrairChecks(dados) {
    const candidatos = [
        dados.checks,
        dados.verificacoes,
        dados.testes,
        dados.resultados,
        dados.diagnosticos,
        dados.resultado?.checks,
        dados.resultado?.verificacoes,
    ];

    for (const candidato of candidatos) {
        if (Array.isArray(candidato)) return candidato;
    }

    if (dados.resultados && typeof dados.resultados === 'object' && !Array.isArray(dados.resultados)) {
        return Object.entries(dados.resultados).map(([codigo, valor]) => {
            if (valor && typeof valor === 'object') return { codigo, ...valor };

            return {
                codigo,
                nome: codigo,
                ok: paraBooleano(valor),
                mensagem: String(valor),
            };
        });
    }

    return [];
}


/* ==========================================================================
   RESUMO
========================================================================== */

function resumir(dados, checks = null) {
    checks = checks || extrairChecks(dados);

    let sucessos = 0;
    let avisos = 0;
    let erros = 0;

    checks.forEach(check => {
        const nivel = normalizarNivel(check);

        if (nivel === 'ok') sucessos++;
        else if (nivel === 'warning') avisos++;
        else if (nivel === 'error') erros++;
    });

    return {
        total: checks.length,
        sucessos,
        avisos,
        erros,
    };
}


function normalizarNivel(check) {
    const bruto = String(
        check.nivel ??
        check.status ??
        check.estado ??
        check.resultado ??
        ''
    ).toLowerCase();

    if (['success', 'ok', 'healthy', 'pass', 'passed', 'online', 'up'].includes(bruto)) return 'ok';
    if (['warning', 'warn', 'degraded', 'attention', 'aviso'].includes(bruto)) return 'warning';
    if (['error', 'failed', 'fail', 'unhealthy', 'offline', 'down', 'erro'].includes(bruto)) return 'error';

    if (check.ok !== undefined) return paraBooleano(check.ok) ? 'ok' : 'error';
    if (check.sucesso !== undefined) return paraBooleano(check.sucesso) ? 'ok' : 'error';
    if (check.saudavel !== undefined) return paraBooleano(check.saudavel) ? 'ok' : 'error';

    return 'pending';
}


function determinarSaudavel(dados, resumo) {
    const valor =
        dados.saudavel ??
        dados.healthy ??
        dados.ok ??
        dados.resultado?.saudavel ??
        dados.resultado?.ok;

    if (valor !== undefined) return paraBooleano(valor);

    return resumo.erros === 0;
}


/* ==========================================================================
   ATIVAÇÃO
========================================================================== */

function aoAtivar() {
    const resultado = estado.get('diagnostico.resultado');
    if (resultado) renderizar(resultado);
}


/* ==========================================================================
   EXPORT
========================================================================== */

export const diagnostico = Object.freeze({
    inicializar,
    aoAtivar,
    executar,
    renderizar,
});

export default diagnostico;