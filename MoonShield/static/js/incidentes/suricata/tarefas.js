import {
    fetchJSON,
    unwrapPayload,
    apiUrl,
    handleError,
} from '../nucleo/api.js';

import {
    state,
    TASK_LABELS,
    TASK_ICONS,
} from '../nucleo/estado.js';

import {
    safeArray,
    safeObject,
    readPath,
    numberValue,
    textValue,
    capitalize,
    escapeHTML,
    formatDate,
    formatDuration,
    sanitizeUrl,
} from '../nucleo/utilitarios.js';

import {
    $,
    setText,
    setButtonLoading,
} from '../nucleo/dom.js';

import {
    normalizeStatus,
    statusLabel,
    iconSVG,
} from '../nucleo/interface.js';

import {
    renderOverviewTasks,
} from './visao_geral.js';

import {
    showToast,
} from '../componentes/notificacoes.js';

import {
    confirmOperation,
} from '../componentes/modal.js';

import {
    initOperacaoLonga,
    getLongOperationProfile,
    trackLongOperationTask,
    applyTaskToLongOperation,
    failLongOperation,
    getTrackedLongOperationTaskId,
} from '../componentes/operacao_longa.js';


const FINAL_TASK_STATUSES = new Set([
    'sucesso',
    'erro',
    'cancelado',
    'ignorado',
]);

const RUNNING_TASK_STATUSES = new Set([
    'pendente',
    'executando',
]);

const LONG_OPERATION_TASKS = new Set([
    'instalacao',
    'configuracao',
    'atualizacao_regras',
    'validacao',
    'reinicio_suricata',
    'reinicio_monitor',
    'reparo',
]);

const TASK_DETAIL_POLL_INTERVAL = 2500;

let drawerPollTimer = null;
let drawerPollInFlight = false;
let operationResumeAttempted = false;


/* ==========================================================================
   INICIALIZAÇÃO
   ========================================================================== */

export function initTarefas() {
    initOperacaoLonga();

    $('taskStatusFilter')
        ?.addEventListener(
            'change',
            () => {
                state.taskOffset = 0;

                loadTasks()
                    .catch(
                        handleError,
                    );
            },
        );

    $('taskTypeFilter')
        ?.addEventListener(
            'change',
            () => {
                state.taskOffset = 0;

                loadTasks()
                    .catch(
                        handleError,
                    );
            },
        );

    $('btnClearTaskFilters')
        ?.addEventListener(
            'click',
            () => {
                if ($('taskStatusFilter')) {
                    $('taskStatusFilter').value = '';
                }

                if ($('taskTypeFilter')) {
                    $('taskTypeFilter').value = '';
                }

                state.taskOffset = 0;

                loadTasks()
                    .catch(
                        handleError,
                    );
            },
        );

    $('btnRefreshTasks')
        ?.addEventListener(
            'click',
            () => {
                state.taskOffset = 0;

                loadTasks()
                    .catch(
                        handleError,
                    );
            },
        );

    $('btnTaskPrev')
        ?.addEventListener(
            'click',
            () => {
                state.taskOffset = Math.max(
                    0,
                    state.taskOffset
                    - state.taskLimit,
                );

                loadTasks()
                    .catch(
                        handleError,
                    );
            },
        );

    $('btnTaskNext')
        ?.addEventListener(
            'click',
            () => {
                if (
                    state.taskOffset
                    + state.taskLimit
                    >= state.taskTotal
                ) {
                    return;
                }

                state.taskOffset += (
                    state.taskLimit
                );

                loadTasks()
                    .catch(
                        handleError,
                    );
            },
        );

    $('btnUpdateAllRules')
        ?.addEventListener(
            'click',
            () => {
                confirmOperation({
                    title: 'Atualizar regras do Suricata?',
                    text: (
                        'O MoonShield atualizará ET Open e '
                        + 'reaplicará as regras MoonShield configuradas.'
                    ),
                    details: (
                        'A operação será executada pelo worker automático '
                        + 'e poderá levar alguns minutos.'
                    ),
                    confirmLabel: 'Atualizar regras',
                    confirmClass: 'sp-btn--primary',
                    onConfirm: () =>
                        confirmTask({
                            tipo: 'atualizacao_regras',
                            parametros: {
                                atualizar_et: true,
                                atualizar_moonshield: true,
                                validar_depois: true,
                            },
                        }),
                });
            },
        );

    window.addEventListener(
        'beforeunload',
        cleanupTasks,
        {
            once: true,
        },
    );
}


/* ==========================================================================
   LISTAGEM
   ========================================================================== */

export async function loadTasks() {
    const params = new URLSearchParams();

    params.set(
        'limite',
        String(
            state.taskLimit,
        ),
    );

    params.set(
        'offset',
        String(
            state.taskOffset,
        ),
    );

    const statusFilter = (
        $('taskStatusFilter')
            ?.value
        || ''
    );

    const typeFilter = (
        $('taskTypeFilter')
            ?.value
        || ''
    );

    if (statusFilter) {
        params.set(
            'status',
            statusFilter,
        );
    }

    if (typeFilter) {
        params.set(
            'tipo',
            typeFilter,
        );
    }

    const payload = await fetchJSON(
        `${apiUrl('listarTarefas')}?${params.toString()}`,
    );

    const data = safeObject(
        unwrapPayload(
            payload,
        ),
    );

    const tasks = safeArray(
        readPath(
            data,
            [
                'tarefas',
                'results',
            ],
            [],
        ),
    );

    const total = numberValue(
        readPath(
            data,
            [
                'total',
                'count',
            ],
            tasks.length,
        ),
        tasks.length,
    );

    state.tasks = tasks;
    state.taskTotal = total;
    state.taskPage = Math.floor(
        state.taskOffset
        / Math.max(
            1,
            state.taskLimit,
        ),
    ) + 1;

    renderTaskTable(
        tasks,
    );

    renderOverviewTasks(
        tasks.slice(
            0,
            5,
        ),
    );

    renderTaskPagination();

    updateTaskBadge(
        tasks,
    );

    resumeRunningLongOperation(
        tasks,
    );

    return tasks;
}


/* ==========================================================================
   CRIAÇÃO / CONFIRMAÇÃO
   ========================================================================== */

export async function confirmTask(
    config,
    handleOpenDrawer = null,
) {
    const taskType = textValue(
        config?.tipo,
        '',
    );

    if (!taskType) {
        throw new Error(
            'Tipo de tarefa não informado.',
        );
    }

    const parameters = (
        config?.parametros
        && typeof config.parametros === 'object'
            ? config.parametros
            : {}
    );

    const profile = getLongOperationProfile(
        taskType,
        parameters,
    );

    /*
     * O diagnóstico é tratado pelo módulo diagnostico.js e não passa por
     * este loader geral.
     */
    const shouldUseGlobalLoader = (
        profile !== null
        && LONG_OPERATION_TASKS.has(
            taskType,
        )
    );

    let task = null;

    try {
        const payload = await fetchJSON(
            apiUrl('criarTarefa'),
            {
                method: 'POST',
                body: {
                    tipo: taskType,
                    parametros: parameters,
                },
            },
        );

        const data = safeObject(
            unwrapPayload(
                payload,
            ),
        );

        task = safeObject(
            readPath(
                data,
                [
                    'tarefa',
                ],
                data,
            ),
        );

        const taskId = getTaskId(
            task,
        );

        if (!taskId) {
            throw new Error(
                'A API criou a operação, mas não retornou o ID da tarefa.',
            );
        }

        showToast(
            'Tarefa criada com sucesso.',
            'ok',
        );

        if (shouldUseGlobalLoader) {
            startGlobalTaskTracking(
                task,
                parameters,
            );
        }

        await loadTasks();

        if (
            typeof handleOpenDrawer
            === 'function'
        ) {
            handleOpenDrawer(
                taskId,
            );
        }

        return task;

    } catch (error) {
        if (shouldUseGlobalLoader) {
            failLongOperation(
                error?.payload?.mensagem
                || error?.payload?.erro
                || error?.message
                || 'Não foi possível iniciar a operação.',
            );
        }

        throw error;
    }
}


/* ==========================================================================
   LOADER GLOBAL
   ========================================================================== */

function startGlobalTaskTracking(
    task,
    parameters = {},
) {
    const taskId = getTaskId(
        task,
    );

    const taskType = textValue(
        task?.tipo,
        '',
    );

    if (
        !taskId
        || !LONG_OPERATION_TASKS.has(
            taskType,
        )
    ) {
        return false;
    }

    return trackLongOperationTask({
        task,
        taskId,
        taskType,
        parameters,
        fetchTask: fetchTaskById,
        pollInterval: 1600,

        onUpdate: async (
            freshTask,
        ) => {
            /*
             * Se a gaveta estiver aberta na mesma tarefa, atualizamos a gaveta
             * usando o mesmo resultado do polling do loader.
             */
            if (
                state.currentTaskId
                && String(
                    state.currentTaskId,
                ) === String(
                    getTaskId(
                        freshTask,
                    ),
                )
            ) {
                state.currentTask = freshTask;

                renderTaskDrawer(
                    freshTask,
                );
            }
        },

        onFinish: async (
            freshTask,
        ) => {
            state.currentTask = (
                freshTask
            );

            if (
                state.currentTaskId
                && String(
                    state.currentTaskId,
                ) === String(
                    getTaskId(
                        freshTask,
                    ),
                )
            ) {
                renderTaskDrawer(
                    freshTask,
                );

                await loadTaskLogs(
                    getTaskId(
                        freshTask,
                    ),
                ).catch(
                    () => {},
                );
            }

            await loadTasks()
                .catch(
                    () => {},
                );

            const finalStatus = normalizeStatus(
                freshTask.status
                || freshTask.estado,
            );

            showToast(
                finalStatus === 'ok'
                || finalStatus === 'sucesso'
                    ? 'Operação concluída.'
                    : finalStatus === 'warning'
                        ? 'Operação encerrada com atenção.'
                        : 'Operação finalizada.',
                finalStatus === 'ok'
                || finalStatus === 'sucesso'
                    ? 'ok'
                    : finalStatus === 'warning'
                        ? 'warning'
                        : 'error',
            );
        },
    });
}


function resumeRunningLongOperation(
    tasks,
) {
    if (
        operationResumeAttempted
        && getTrackedLongOperationTaskId()
    ) {
        return;
    }

    const running = tasks.find(
        (task) => {
            const status = normalizeTaskStatus(
                task.status
                || task.estado,
            );

            const type = textValue(
                task.tipo,
                '',
            );

            return (
                RUNNING_TASK_STATUSES.has(
                    status,
                )
                && LONG_OPERATION_TASKS.has(
                    type,
                )
            );
        },
    );

    operationResumeAttempted = true;

    if (!running) {
        return;
    }

    if (
        getTrackedLongOperationTaskId()
    ) {
        return;
    }

    startGlobalTaskTracking(
        running,
        safeObject(
            running.parametros
            || {},
        ),
    );
}


/* ==========================================================================
   TABELA / PAGINAÇÃO
   ========================================================================== */

function renderTaskTable(
    tasks,
) {
    const container = $(
        'taskTableBody',
    );

    if (!container) {
        return;
    }

    container.innerHTML = '';

    if (!tasks.length) {
        container.innerHTML = `
            <tr>
                <td
                    colspan="7"
                    class="sp-task-table__empty"
                >
                    Nenhuma tarefa encontrada.
                </td>
            </tr>
        `;

        return;
    }

    for (const task of tasks) {
        const status = normalizeStatus(
            task.status
            || task.estado,
        );

        const taskType = textValue(
            task.tipo,
            'tarefa',
        );

        const taskId = getTaskId(
            task,
        );

        const progress = clampProgress(
            task.progresso,
        );

        const row = document.createElement(
            'tr',
        );

        row.dataset.taskId = (
            taskId
        );

        row.innerHTML = `
            <td>
                <span class="sp-task-type">
                    <span class="sp-task-type__icon">
                        ${iconSVG(
                            TASK_ICONS[taskType]
                            || 'task',
                            15,
                        )}
                    </span>

                    <span>
                        <strong>
                            ${escapeHTML(
                                TASK_LABELS[taskType]
                                || capitalize(
                                    taskType,
                                ),
                            )}
                        </strong>

                        <small>
                            ${escapeHTML(
                                task.mensagem
                                || 'Sem detalhes',
                            )}
                        </small>
                    </span>
                </span>
            </td>

            <td>
                <span class="sp-status-pill sp-status-pill--${status}">
                    ${escapeHTML(
                        statusLabel(
                            task.status
                            || task.estado,
                        ),
                    )}
                </span>
            </td>

            <td>
                <span class="sp-task-progress-text">
                    ${progress}%
                </span>
            </td>

            <td>
                <small>
                    ${escapeHTML(
                        task.etapa_atual
                        || task.etapa
                        || '—',
                    )}
                </small>
            </td>

            <td>
                <small>
                    ${escapeHTML(
                        safeFormatDate(
                            task.criado_em
                            || task.criada_em,
                        ),
                    )}
                </small>
            </td>

            <td>
                <small>
                    ${escapeHTML(
                        safeFormatDuration(
                            task.duracao_segundos,
                        ),
                    )}
                </small>
            </td>

            <td>
                <button
                    class="sp-mini-action"
                    type="button"
                    data-task-open="${escapeHTML(taskId)}"
                >
                    Detalhes
                </button>
            </td>
        `;

        container.appendChild(
            row,
        );
    }
}


function renderTaskPagination() {
    const start = state.taskTotal
        ? state.taskOffset + 1
        : 0;

    const end = Math.min(
        state.taskOffset
        + state.taskLimit,
        state.taskTotal,
    );

    const totalPages = Math.max(
        1,
        Math.ceil(
            state.taskTotal
            / Math.max(
                1,
                state.taskLimit,
            ),
        ),
    );

    setText(
        'taskPaginationText',
        `${start}–${end} de ${state.taskTotal} tarefa(s)`,
    );

    setText(
        'taskPageText',
        `Página ${state.taskPage} de ${totalPages}`,
    );

    if ($('btnTaskPrev')) {
        $('btnTaskPrev').disabled = (
            state.taskOffset <= 0
        );
    }

    if ($('btnTaskNext')) {
        $('btnTaskNext').disabled = (
            state.taskOffset
            + state.taskLimit
            >= state.taskTotal
        );
    }
}


function updateTaskBadge(
    tasks,
) {
    const running = tasks.filter(
        (task) =>
            RUNNING_TASK_STATUSES.has(
                normalizeTaskStatus(
                    task.status
                    || task.estado,
                ),
            ),
    ).length;

    const badge = $(
        'navTaskBadge',
    );

    if (!badge) {
        return;
    }

    badge.hidden = (
        running === 0
    );

    badge.textContent = String(
        running,
    );
}


/* ==========================================================================
   DETALHE / GAVETA
   ========================================================================== */

export async function loadTaskDetail(
    taskId,
) {
    if (!taskId) {
        return null;
    }

    state.currentTaskId = (
        String(taskId)
    );

    const task = await fetchTaskById(
        taskId,
    );

    state.currentTask = task;

    renderTaskDrawer(
        task,
    );

    await loadTaskLogs(
        taskId,
    ).catch(
        (error) => {
            console.error(
                '[MoonShield] Não foi possível carregar logs da tarefa:',
                error,
            );
        },
    );

    startDrawerPolling(
        taskId,
    );

    return task;
}


async function fetchTaskById(
    taskId,
) {
    const detailUrl = sanitizeUrl(
        apiUrl(
            'detalheTarefaTemplate',
        ),
        taskId,
    );

    const payload = await fetchJSON(
        detailUrl,
    );

    const data = safeObject(
        unwrapPayload(
            payload,
        ),
    );

    return safeObject(
        readPath(
            data,
            [
                'tarefa',
            ],
            data,
        ),
    );
}


function renderTaskDrawer(
    task,
) {
    const statusRaw = (
        task.status
        || task.estado
        || 'pendente'
    );

    const status = normalizeStatus(
        statusRaw,
    );

    const taskId = getTaskId(
        task,
    );

    const taskType = textValue(
        task.tipo,
        'tarefa',
    );

    const progress = clampProgress(
        task.progresso,
    );

    setText(
        'taskDrawerTitle',
        TASK_LABELS[taskType]
        || capitalize(
            taskType,
        ),
    );

    setText(
        'drawerTaskType',
        TASK_LABELS[taskType]
        || capitalize(
            taskType,
        ),
    );

    setText(
        'drawerTaskId',
        taskId,
    );

    setText(
        'drawerTaskStage',
        task.etapa_atual
        || task.etapa
        || '—',
    );

    setText(
        'drawerTaskPercent',
        `${progress}%`,
    );

    setText(
        'drawerTaskMessage',
        task.mensagem
        || 'Sem atualizações.',
    );

    setText(
        'drawerTaskCreated',
        safeFormatDate(
            task.criado_em
            || task.criada_em,
        ),
    );

    setText(
        'drawerTaskStarted',
        safeFormatDate(
            task.iniciado_em
            || task.iniciada_em,
        ),
    );

    setText(
        'drawerTaskFinished',
        safeFormatDate(
            task.finalizado_em
            || task.finalizada_em,
        ),
    );

    setText(
        'drawerTaskDuration',
        safeFormatDuration(
            task.duracao_segundos,
        ),
    );

    const statusElement = $(
        'drawerTaskStatus',
    );

    if (statusElement) {
        statusElement.textContent = (
            statusLabel(
                statusRaw,
            )
        );

        statusElement.className = (
            `sp-status-pill sp-status-pill--${status}`
        );
    }

    const bar = $(
        'drawerTaskProgressBar',
    );

    if (bar) {
        bar.style.width = (
            `${progress}%`
        );
    }

    const errorBox = $(
        'drawerTaskError',
    );

    if (errorBox) {
        const errorText = (
            task.erro
            || ''
        );

        errorBox.hidden = (
            !errorText
        );

        setText(
            'drawerTaskErrorText',
            errorText,
        );
    }

    const result = $(
        'drawerTaskResult',
    );

    if (result) {
        result.textContent = formatTaskResult(
            task.resultado,
        );
    }

    const cancelButton = $(
        'btnCancelTask',
    );

    if (cancelButton) {
        cancelButton.hidden = (
            !RUNNING_TASK_STATUSES.has(
                normalizeTaskStatus(
                    statusRaw,
                ),
            )
        );
    }
}


async function loadTaskLogs(
    taskId,
) {
    const container = $(
        'drawerTaskLogs',
    );

    if (!container) {
        return [];
    }

    const url = sanitizeUrl(
        apiUrl(
            'logsTarefaTemplate',
        ),
        taskId,
    );

    const payload = await fetchJSON(
        url,
    );

    const data = safeObject(
        unwrapPayload(
            payload,
        ),
    );

    const logs = safeArray(
        readPath(
            data,
            [
                'logs',
            ],
            [],
        ),
    );

    renderTaskLogs(
        logs,
    );

    return logs;
}


function renderTaskLogs(
    logs,
) {
    const container = $(
        'drawerTaskLogs',
    );

    if (!container) {
        return;
    }

    container.innerHTML = '';

    if (!logs.length) {
        container.innerHTML = `
            <div class="sp-terminal__empty">
                Nenhum log disponível.
            </div>
        `;

        return;
    }

    for (const log of logs) {
        const line = document.createElement(
            'div',
        );

        line.className = (
            'sp-terminal-line'
        );

        const level = textValue(
            log.nivel,
            'info',
        ).toUpperCase();

        const time = (
            log.criado_em
            ? new Date(
                log.criado_em,
            ).toLocaleTimeString(
                'pt-BR',
            )
            : '--:--:--'
        );

        line.innerHTML = `
            <span class="sp-terminal-line__time">
                ${escapeHTML(time)}
            </span>

            <span class="sp-terminal-line__level">
                [${escapeHTML(level)}]
            </span>

            <span class="sp-terminal-line__message">
                ${escapeHTML(
                    log.etapa
                        ? `${log.etapa}: ${log.mensagem}`
                        : log.mensagem
                        || '',
                )}
            </span>
        `;

        container.appendChild(
            line,
        );
    }

    container.scrollTop = (
        container.scrollHeight
    );
}


/* ==========================================================================
   POLLING DA GAVETA
   ========================================================================== */

function startDrawerPolling(
    taskId,
) {
    stopDrawerPolling();

    drawerPollTimer = window.setInterval(
        async () => {
            if (
                drawerPollInFlight
                || document.hidden
                || !state.currentTaskId
                || String(
                    state.currentTaskId,
                ) !== String(
                    taskId,
                )
            ) {
                return;
            }

            drawerPollInFlight = true;

            try {
                const task = await fetchTaskById(
                    taskId,
                );

                state.currentTask = task;

                renderTaskDrawer(
                    task,
                );

                if (
                    getTrackedLongOperationTaskId()
                    && String(
                        getTrackedLongOperationTaskId(),
                    ) === String(
                        taskId,
                    )
                ) {
                    applyTaskToLongOperation(
                        task,
                    );
                }

                const status = normalizeTaskStatus(
                    task.status
                    || task.estado,
                );

                if (
                    FINAL_TASK_STATUSES.has(
                        status,
                    )
                ) {
                    stopDrawerPolling();

                    await loadTaskLogs(
                        taskId,
                    ).catch(
                        () => {},
                    );
                }
            } catch (error) {
                console.error(
                    '[MoonShield] Erro no polling da gaveta:',
                    error,
                );
            } finally {
                drawerPollInFlight = false;
            }
        },
        TASK_DETAIL_POLL_INTERVAL,
    );
}


function stopDrawerPolling() {
    if (drawerPollTimer) {
        window.clearInterval(
            drawerPollTimer,
        );

        drawerPollTimer = null;
    }

    drawerPollInFlight = false;
}


/* ==========================================================================
   CANCELAMENTO
   ========================================================================== */

export async function requestTaskCancellation(
    taskId,
) {
    if (!taskId) {
        return;
    }

    const url = sanitizeUrl(
        apiUrl(
            'cancelarTarefaTemplate',
        ),
        taskId,
    );

    await fetchJSON(
        url,
        {
            method: 'POST',
            body: {},
        },
    );

    showToast(
        'Cancelamento solicitado.',
        'warning',
    );

    await loadTaskDetail(
        taskId,
    );
}


/* ==========================================================================
   HELPERS
   ========================================================================== */

function getTaskId(
    task,
) {
    return textValue(
        task?.id
        || task?.pk
        || task?.tarefa_id
        || '',
        '',
    );
}


function normalizeTaskStatus(
    value,
) {
    const status = String(
        value || '',
    )
        .trim()
        .toLowerCase();

    if (
        status === 'running'
        || status === 'processando'
    ) {
        return 'executando';
    }

    if (
        status === 'pending'
        || status === 'aguardando'
    ) {
        return 'pendente';
    }

    if (
        status === 'ok'
        || status === 'concluido'
        || status === 'concluida'
    ) {
        return 'sucesso';
    }

    if (
        status === 'error'
        || status === 'falha'
        || status === 'failed'
    ) {
        return 'erro';
    }

    return (
        status
        || 'pendente'
    );
}


function clampProgress(
    value,
) {
    return Math.max(
        0,
        Math.min(
            100,
            Math.round(
                numberValue(
                    value,
                    0,
                ),
            ),
        ),
    );
}


function safeFormatDate(
    value,
) {
    if (!value) {
        return '—';
    }

    try {
        return formatDate(
            value,
        );
    } catch {
        try {
            return new Date(
                value,
            ).toLocaleString(
                'pt-BR',
            );
        } catch {
            return '—';
        }
    }
}


function safeFormatDuration(
    value,
) {
    const seconds = numberValue(
        value,
        0,
    );

    if (!seconds) {
        return '—';
    }

    try {
        return formatDuration(
            seconds,
        );
    } catch {
        const minutes = Math.floor(
            seconds / 60,
        );

        const remaining = (
            seconds % 60
        );

        return minutes > 0
            ? `${minutes}m ${remaining}s`
            : `${remaining}s`;
    }
}


function formatTaskResult(
    result,
) {
    if (
        result === null
        || result === undefined
        || result === ''
    ) {
        return 'Sem resultado disponível.';
    }

    if (
        typeof result === 'string'
    ) {
        return result;
    }

    try {
        return JSON.stringify(
            result,
            null,
            2,
        );
    } catch {
        return String(
            result,
        );
    }
}


function cleanupTasks() {
    stopDrawerPolling();
}
