import { fetchJSON, unwrapPayload, apiUrl, handleError } from '../nucleo/api.js';
import { state, TASK_LABELS, TASK_ICONS } from '../nucleo/estado.js';
import { safeArray, readPath, numberValue, textValue, capitalize, escapeHTML, formatDate, formatDuration, sanitizeUrl } from '../nucleo/utilitarios.js';
import { $, setText, setButtonLoading } from '../nucleo/dom.js';
import { normalizeStatus, statusLabel, iconSVG } from '../nucleo/interface.js';
import { renderOverviewTasks } from './visao_geral.js';
import { showToast } from '../componentes/notificacoes.js';

export function initTarefas() {
    $('taskStatusFilter')?.addEventListener('change', () => { state.taskOffset = 0; loadTasks().catch(handleError); });
    $('taskTypeFilter')?.addEventListener('change', () => { state.taskOffset = 0; loadTasks().catch(handleError); });

    $('btnClearTaskFilters')?.addEventListener('click', () => {
        if ($('taskStatusFilter')) $('taskStatusFilter').value = '';
        if ($('taskTypeFilter')) $('taskTypeFilter').value = '';
        state.taskOffset = 0;
        loadTasks().catch(handleError);
    });

    $('btnTaskPrev')?.addEventListener('click', () => {
        state.taskOffset = Math.max(0, state.taskOffset - state.taskLimit);
        loadTasks().catch(handleError);
    });

    $('btnTaskNext')?.addEventListener('click', () => {
        if (state.taskOffset + state.taskLimit >= state.taskTotal) return;
        state.taskOffset += state.taskLimit;
        loadTasks().catch(handleError);
    });

    $('btnRefreshTasks')?.addEventListener('click', async () => {
        const button = $('btnRefreshTasks');
        setButtonLoading(button, true);
        try {
            await loadTasks();
            showToast('Lista de tarefas atualizada.', 'ok');
        } catch (error) {
            handleError(error);
        } finally {
            setButtonLoading(button, false);
        }
    });
}

export async function createTask(tipo, parametros = {}) {
    const payload = await fetchJSON(apiUrl('criarTarefa'), {
        method: 'POST',
        body: { tipo, parametros },
    });

    const data = unwrapPayload(payload);
    const task = readPath(data, ['tarefa'], null) || readPath(payload, ['tarefa'], null) || data;

    if (!task || typeof task !== 'object') throw new Error('A API não retornou a tarefa criada.');
    return task;
}

export async function confirmTask(config, onCreated) {
    const task = await createTask(config.tipo, config.parametros || {});
    showToast('Tarefa criada com sucesso.', 'ok');
    await loadTasks();
    if (onCreated) onCreated(task.id || task.pk);
}

export async function loadTasks() {
    const query = new URLSearchParams();
    const status = $('taskStatusFilter')?.value || '';
    const type = $('taskTypeFilter')?.value || '';

    query.set('offset', String(state.taskOffset));
    query.set('limite', String(state.taskLimit));
    if (status) query.set('status', status);
    if (type) query.set('tipo', type);

    const payload = await fetchJSON(`${apiUrl('listarTarefas')}?${query}`);
    const data = unwrapPayload(payload);
    const tasks = safeArray(readPath(data, ['tarefas', 'results'], readPath(payload, ['tarefas'], [])));
    const total = numberValue(readPath(data, ['total', 'count'], tasks.length), tasks.length);

    state.tasks = tasks;
    state.taskTotal = total;
    state.taskPage = Math.floor(state.taskOffset / state.taskLimit) + 1;

    renderTaskTable(tasks);
    renderOverviewTasks(tasks.slice(0, 5));
    renderTaskPagination();

    return tasks;
}

export function renderTaskTable(tasks) {
    const body = $('taskTableBody');
    if (!body) return;

    body.innerHTML = '';
    if (!tasks.length) {
        body.innerHTML = `<tr><td colspan="7"><div class="sp-empty-state"><span class="sp-empty-state__icon">${iconSVG('task', 22)}</span><div><strong>Nenhuma tarefa encontrada</strong><span>Altere os filtros ou crie uma nova operação.</span></div></div></td></tr>`;
        return;
    }

    for (const task of tasks) {
        const id = task.id || task.pk || '';
        const status = textValue(task.status, 'pendente').toLowerCase();
        const normalizedStatus = normalizeStatus(status);
        const progress = Math.max(0, Math.min(100, numberValue(task.progresso, 0)));
        const row = document.createElement('tr');

        row.innerHTML = `
            <td><div class="sp-task-cell"><span class="sp-task-cell__icon">${iconSVG(TASK_ICONS[task.tipo] || 'task', 15)}</span><span class="sp-task-cell__copy"><strong>${escapeHTML(TASK_LABELS[task.tipo] || capitalize(task.tipo))}</strong><span>${escapeHTML(id)}</span></span></div></td>
            <td><span class="sp-status-pill sp-status-pill--${normalizedStatus}">${escapeHTML(statusLabel(status))}</span></td>
            <td><div class="sp-progress-mini"><div class="sp-progress-mini__bar"><span style="width:${progress}%"></span></div><span class="sp-progress-mini__text">${progress}%</span></div></td>
            <td>${escapeHTML(task.etapa_atual || '—')}</td>
            <td>${escapeHTML(formatDate(task.iniciado_em || task.criado_em))}</td>
            <td>${escapeHTML(formatDuration(task.duracao_segundos))}</td>
            <td><button class="sp-icon-btn sp-icon-btn--small" type="button" aria-label="Abrir tarefa" data-task-open="${escapeHTML(id)}"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg></button></td>
        `;
        body.appendChild(row);
    }
}

export function renderTaskPagination() {
    const start = state.taskTotal ? state.taskOffset + 1 : 0;
    const end = Math.min(state.taskOffset + state.taskLimit, state.taskTotal);
    const totalPages = Math.max(1, Math.ceil(state.taskTotal / state.taskLimit));

    setText('taskPaginationText', `${start}–${end} de ${state.taskTotal} tarefa(s)`);
    setText('taskPageText', `Página ${state.taskPage} de ${totalPages}`);

    if ($('btnTaskPrev')) $('btnTaskPrev').disabled = state.taskOffset <= 0;
    if ($('btnTaskNext')) $('btnTaskNext').disabled = state.taskOffset + state.taskLimit >= state.taskTotal;
}

export async function loadTaskDetail(taskId) {
    const detailUrl = sanitizeUrl(apiUrl('detalheTarefaTemplate'), taskId);
    const payload = await fetchJSON(detailUrl);
    const data = unwrapPayload(payload);
    return readPath(data, ['tarefa'], null) || readPath(payload, ['tarefa'], null) || data;
}

export async function requestTaskCancellation(taskId) {
    const url = sanitizeUrl(apiUrl('cancelarTarefaTemplate'), taskId);
    await fetchJSON(url, { method: 'POST', body: {} });
    showToast('Cancelamento solicitado.', 'warning');
}