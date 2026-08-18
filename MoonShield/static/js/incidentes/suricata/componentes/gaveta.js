import { $, setText, setHidden, $all } from '../nucleo/dom.js';
import { state, TASK_LABELS, FINAL_TASK_STATUSES, RUNNING_TASK_STATUSES } from '../nucleo/estado.js';
import { applyPill, normalizeStatus, statusLabel } from '../nucleo/interface.js';
import { formatDate, formatDuration, numberValue, escapeHTML, textValue, sanitizeUrl } from '../nucleo/utilitarios.js';
import { apiUrl, fetchJSON, unwrapPayload } from '../nucleo/api.js';
import { copyToClipboard } from '../nucleo/interface.js';
import { confirmOperation } from './modal.js';

export function initGaveta(onRequestCancel) {
    $('btnCloseTaskDrawer')?.addEventListener('click', closeTaskDrawer);
    $('btnCloseTaskDrawerFooter')?.addEventListener('click', closeTaskDrawer);
    
    $all('[data-close-task-drawer]').forEach((element) => {
        element.addEventListener('click', closeTaskDrawer);
    });

    $('btnCancelTask')?.addEventListener('click', () => {
        if (!state.currentTaskId) return;
        confirmOperation({
            title: 'Solicitar cancelamento?',
            text: 'O cancelamento é cooperativo e ocorrerá entre as etapas da tarefa.',
            details: `Tarefa: ${state.currentTaskId}`,
            confirmLabel: 'Solicitar cancelamento',
            confirmClass: 'sp-btn--danger',
            onConfirm: () => onRequestCancel(state.currentTaskId),
        });
    });

    $('btnCopyTaskLogs')?.addEventListener('click', () => {
        const text = $('drawerTaskLogs')?.innerText || '';
        copyToClipboard(text, 'Logs copiados.');
    });
}

export async function openTaskDrawer(taskId, loadDetailFn, onCompleteCb) {
    if (!taskId) return;
    state.currentTaskId = taskId;

    const drawer = $('taskDrawer');
    if (drawer) {
        drawer.classList.add('is-open');
        drawer.setAttribute('aria-hidden', 'false');
        document.body.style.overflow = 'hidden';
    }

    renderTaskDrawerLoading(taskId);

    try {
        const task = await loadDetailFn(taskId);
        renderTaskDrawer(task);
        await loadTaskLogs(taskId);

        if (RUNNING_TASK_STATUSES.has(String(task.status || '').toLowerCase())) {
            startTaskPolling(taskId, loadDetailFn, onCompleteCb);
        } else {
            stopTaskPolling();
        }
    } catch (error) {
        throw error;
    }
}

export function closeTaskDrawer() {
    stopTaskPolling();
    const drawer = $('taskDrawer');
    if (drawer) {
        drawer.classList.remove('is-open');
        drawer.setAttribute('aria-hidden', 'true');
    }
    state.currentTaskId = null;
    state.currentTask = null;
    document.body.style.overflow = '';
}

export function renderTaskDrawerLoading(taskId) {
    setText('taskDrawerTitle', 'Carregando tarefa');
    setText('drawerTaskType', '—');
    setText('drawerTaskId', taskId);
    setText('drawerTaskStage', 'Consultando');
    setText('drawerTaskPercent', '0%');
    setText('drawerTaskMessage', 'Buscando dados da tarefa...');
    applyPill('drawerTaskStatus', 'pending', 'Carregando');

    const bar = $('drawerTaskProgressBar');
    if (bar) bar.style.width = '0%';

    setText('drawerTaskCreated', '—');
    setText('drawerTaskStarted', '—');
    setText('drawerTaskFinished', '—');
    setText('drawerTaskDuration', '—');
    setHidden('drawerTaskError', true);
    setHidden('btnCancelTask', true);

    const logs = $('drawerTaskLogs');
    if (logs) logs.innerHTML = '<div class="sp-terminal__empty">Carregando logs...</div>';
    setText('drawerTaskResult', 'Carregando...');
}

export function renderTaskDrawer(task) {
    const id = task.id || task.pk || state.currentTaskId || '—';
    const status = String(task.status || 'pendente').toLowerCase();
    const progress = Math.max(0, Math.min(100, numberValue(task.progresso, 0)));

    setText('taskDrawerTitle', TASK_LABELS[task.tipo] || task.tipo || 'Tarefa Suricata');
    setText('drawerTaskType', TASK_LABELS[task.tipo] || task.tipo);
    setText('drawerTaskId', id);
    applyPill('drawerTaskStatus', normalizeStatus(status), statusLabel(status));
    setText('drawerTaskStage', task.etapa_atual || 'Aguardando início');
    setText('drawerTaskPercent', `${progress}%`);
    setText('drawerTaskMessage', task.mensagem || 'Nenhuma atualização disponível.');
    setText('drawerTaskCreated', formatDate(task.criado_em));
    setText('drawerTaskStarted', formatDate(task.iniciado_em));
    setText('drawerTaskFinished', formatDate(task.finalizado_em));
    setText('drawerTaskDuration', formatDuration(task.duracao_segundos));

    const bar = $('drawerTaskProgressBar');
    if (bar) bar.style.width = `${progress}%`;

    const hasError = Boolean(task.erro);
    setHidden('drawerTaskError', !hasError);
    setText('drawerTaskErrorText', task.erro || '');

    const canCancel = boolValue(task.pode_cancelar) || RUNNING_TASK_STATUSES.has(status);
    setHidden('btnCancelTask', !canCancel);

    const result = task.resultado || {};
    setText('drawerTaskResult', Object.keys(result).length ? JSON.stringify(result, null, 2) : 'Nenhum resultado disponível.');
}

export async function loadTaskLogs(taskId) {
    const url = new URL(sanitizeUrl(apiUrl('logsTarefaTemplate'), taskId), window.location.origin);
    url.searchParams.set('offset', '0');
    url.searchParams.set('limite', '500');

    const payload = await fetchJSON(url.toString());
    const data = unwrapPayload(payload);
    const logs = Array.isArray(data.logs) ? data.logs : (Array.isArray(payload.logs) ? payload.logs : []);
    
    renderTaskLogs(logs);
}

export function renderTaskLogs(logs) {
    const container = $('drawerTaskLogs');
    if (!container) return;

    container.innerHTML = '';

    if (!logs.length) {
        container.innerHTML = '<div class="sp-terminal__empty">Nenhum log registrado.</div>';
        return;
    }

    for (const log of logs) {
        const line = document.createElement('div');
        line.className = 'sp-terminal-line';

        const level = textValue(log.nivel, 'info').toUpperCase();
        const time = log.criado_em ? new Date(log.criado_em).toLocaleTimeString('pt-BR') : '--:--:--';

        line.innerHTML = `
            <span class="sp-terminal-line__time">${escapeHTML(time)}</span>
            <span class="sp-terminal-line__level">[${escapeHTML(level)}]</span>
            <span class="sp-terminal-line__message">${escapeHTML(log.etapa ? `${log.etapa}: ${log.mensagem}` : log.mensagem)}</span>
        `;
        container.appendChild(line);
    }
    container.scrollTop = container.scrollHeight;
}

export function startTaskPolling(taskId, loadDetailFn, onCompleteCb) {
    stopTaskPolling();

    state.taskPollTimer = window.setInterval(async () => {
        if (state.destroyed || state.currentTaskId !== taskId || document.hidden) return;

        try {
            const task = await loadDetailFn(taskId);
            renderTaskDrawer(task);
            await loadTaskLogs(taskId);

            if (FINAL_TASK_STATUSES.has(String(task.status || '').toLowerCase())) {
                stopTaskPolling();
                if (onCompleteCb) await onCompleteCb(task);
            }
        } catch (error) {
            console.error('Erro no polling da tarefa:', error);
        }
    }, 2500);
}

export function stopTaskPolling() {
    if (state.taskPollTimer) {
        window.clearInterval(state.taskPollTimer);
        state.taskPollTimer = null;
    }
}