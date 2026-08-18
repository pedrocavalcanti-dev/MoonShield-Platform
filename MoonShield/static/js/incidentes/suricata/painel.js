import { APP, CONFIG, state } from './nucleo/estado.js';
import { normalizeInitialPayload } from './nucleo/utilitarios.js';
import { validatePanelContract, unwrapPayload, fetchJSON, apiUrl } from './nucleo/api.js';
import { $, $all, setButtonLoading } from './nucleo/dom.js';

import { initBarraLateral, closeSidebar } from './componentes/barra_lateral.js';
import { initModal, confirmOperation } from './componentes/modal.js';
import { initGaveta, openTaskDrawer } from './componentes/gaveta.js';
import { startStatusPolling, stopStatusPolling, bindVisibility } from './componentes/atualizacao_automatica.js';

import { initStars, renderGlobalStatus, updateLastRefresh } from './secoes/visao_geral.js';
import { renderSuricata, renderMonitor, renderEve, renderCursor, renderRules, renderStackChecks } from './secoes/saude_stack.js';
import { renderConfiguration, renderTopology } from './secoes/configuracao.js';
import { initRegras, renderRulesSection } from './secoes/regras.js';
import { initDiagnostico, renderDiagnostic } from './secoes/diagnostico.js';
import { initTarefas, loadTasks, confirmTask, requestTaskCancellation, loadTaskDetail } from './secoes/tarefas.js';

async function refreshStatus(showSuccessToast = false) {
    if (state.isFetchingStatus) return state.statusData;
    state.isFetchingStatus = true;
    setButtonLoading($('btnRefreshStatus'), true);

    try {
        const payload = await fetchJSON(apiUrl('status'));
        const data = unwrapPayload(payload);
        state.statusData = data;
        state.lastStatusFetchAt = new Date();

        renderAllStatus(data);
        if (showSuccessToast) showToast('Status atualizado com sucesso.', 'ok');
        return data;
    } catch (error) {
        renderStatusError(error);
        throw error;
    } finally {
        state.isFetchingStatus = false;
        setButtonLoading($('btnRefreshStatus'), false);
    }
}

function renderAllStatus(data) {
    const stack = data.stack || data.dados?.stack || data.novo_status || data.status_stack || data;
    const suricata = stack.suricata || stack.status_suricata || data.suricata || {};
    const monitor = stack.monitor || stack.monitor_local || data.monitor || {};
    const services = stack.servicos || data.servicos || {};
    const environment = stack.ambiente || data.ambiente || {};

    const statusGeneral = stack.status || data.status || 'desconhecido';
    const healthy = stack.saudavel || statusGeneral === 'ok' || statusGeneral === 'sucesso';
    const active = stack.stack_ativa || (suricata.ativo && monitor.ativo);
    const message = stack.mensagem || data.mensagem || (healthy ? 'A stack Suricata está funcionando normalmente.' : 'Existem pontos que precisam de atenção.');

    renderGlobalStatus({ status: statusGeneral, healthy, active, message });
    renderSuricata(suricata, services, environment);
    renderMonitor(monitor, services);
    renderEve(suricata, monitor);
    renderCursor(monitor);
    renderRules(suricata, stack);
    renderConfiguration(APP.configuracao || data.configuracao || CONFIG);
    renderTopology(suricata.topologia || stack.topologia || {}, APP.configuracao || CONFIG);
    renderStackChecks(stack, data);
    renderRulesSection(suricata, stack);
    updateLastRefresh();
}

function renderStatusError(error) {
    renderGlobalStatus({ status: 'error', healthy: false, active: false, message: error.message });
}

function navigateToSection(sectionName) {
    const target = document.querySelector(`.sp-section[data-section="${CSS.escape(sectionName)}"]`);
    if (!target) return;

    $all('.sp-section').forEach((s) => s.classList.toggle('is-active', s.dataset.section === sectionName));
    $all('[data-section-target]').forEach((btn) => btn.classList.toggle('is-active', btn.dataset.sectionTarget === sectionName));

    state.currentSection = sectionName;
    window.scrollTo({ top: 0, behavior: 'smooth' });
    closeSidebar();

    if (sectionName === 'tasks') loadTasks().catch(console.error);
    if (sectionName === 'diagnostic' && state.diagnosticData) renderDiagnostic(state.diagnosticData);
}

const handleTaskComplete = async () => {
    await loadTasks();
    await refreshStatus();
};

const handleOpenDrawer = (taskId) => {
    openTaskDrawer(taskId, loadTaskDetail, handleTaskComplete).catch(console.error);
};

const handleConfirmTask = (config) => {
    confirmOperation({
        title: config.title,
        text: config.text,
        details: config.details || '',
        confirmLabel: 'Criar tarefa',
        onConfirm: () => confirmTask(config, handleOpenDrawer),
    });
};

function initEventDelegation() {
    document.addEventListener('click', (event) => {
        const sectionTarget = event.target.closest('[data-section-target]');
        if (sectionTarget) navigateToSection(sectionTarget.dataset.sectionTarget);

        const sectionLink = event.target.closest('[data-section-link]');
        if (sectionLink) navigateToSection(sectionLink.dataset.sectionLink);

        const taskOpen = event.target.closest('[data-task-open]');
        if (taskOpen) handleOpenDrawer(taskOpen.dataset.taskOpen);

        const restartSuricata = event.target.closest('[data-action="restart-suricata"]');
        if (restartSuricata) {
            handleConfirmTask({ tipo: 'reinicio_suricata', title: 'Reiniciar o Suricata?', text: 'A captura pode ficar indisponível por alguns segundos.', details: 'O comando será enviado como tarefa privilegiada.' });
        }

        const restartMonitor = event.target.closest('[data-action="restart-monitor"]');
        if (restartMonitor) {
            handleConfirmTask({ tipo: 'reinicio_monitor', title: 'Reiniciar o monitor?', text: 'A leitura do eve.json será reiniciada.', details: 'Eventos já persistidos não serão removidos.' });
        }
    });

    $('btnOpenConfiguration')?.addEventListener('click', () => navigateToSection('configuration'));
    $('btnRefreshStatus')?.addEventListener('click', () => refreshStatus(true).catch(console.error));
    $('btnRefreshHealth')?.addEventListener('click', () => refreshStatus(true).catch(console.error));
    $('btnRefreshTopology')?.addEventListener('click', () => refreshStatus(true).catch(console.error));

    document.addEventListener('keydown', (event) => {
        if (event.key !== 'Escape') return;
        if ($('confirmationModal')?.classList.contains('is-open')) return;
        if ($('taskDrawer')?.classList.contains('is-open')) return;
        closeSidebar();
    });
}

async function bootstrap() {
    validatePanelContract();

    state.statusData = normalizeInitialPayload(APP.statusInicial);
    state.cardsData = normalizeInitialPayload(APP.cardsIniciais);

    initStars();
    initBarraLateral();
    initModal();
    initGaveta(requestTaskCancellation);
    initTarefas();
    initDiagnostico(() => navigateToSection('diagnostic'));
    initRegras(handleConfirmTask);
    initEventDelegation();
    bindVisibility(refreshStatus, loadTaskDetail);

    if (Object.keys(state.statusData).length) {
        try { renderAllStatus(state.statusData); } catch (e) { console.error(e); }
    } else {
        renderConfiguration(CONFIG);
    }

    await Promise.allSettled([
        loadTasks().catch(console.error),
        refreshStatus().catch(console.error)
    ]);

    startStatusPolling(refreshStatus);
}

window.addEventListener('beforeunload', () => {
    state.destroyed = true;
    stopStatusPolling();
}, { once: true });

bootstrap().catch(console.error);