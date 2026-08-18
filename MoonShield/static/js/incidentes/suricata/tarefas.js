import {
    fetchJSON,
    unwrapPayload,
    apiUrl
} from '../nucleo/api.js';

import {
    state,
    TASK_LABELS,
    TASK_ICONS
} from '../nucleo/estado.js';

import {
    safeArray,
    readPath,
    numberValue,
    textValue,
    capitalize,
    escapeHTML,
    formatDate,
    formatDuration,
    sanitizeUrl
} from '../nucleo/utilitarios.js';

import {
    $,
    setText,
    setButtonLoading
} from '../nucleo/dom.js';

import {
    normalizeStatus,
    statusLabel,
    iconSVG,
    handleError
} from '../nucleo/interface.js';

import {
    renderOverviewTasks
} from './visao_geral.js';

import {
    showToast
} from '../componentes/notificacoes.js';


/* ==========================================================================
   INICIALIZAÇÃO
   ========================================================================== */

export function initTarefas() {
    /*
     * Filtro por status
     */
    $('taskStatusFilter')?.addEventListener(
        'change',
        () => {
            state.taskOffset = 0;

            loadTasks().catch(
                handleError
            );
        }
    );


    /*
     * Filtro por tipo
     */
    $('taskTypeFilter')?.addEventListener(
        'change',
        () => {
            state.taskOffset = 0;

            loadTasks().catch(
                handleError
            );
        }
    );


    /*
     * Limpar filtros
     */
    $('btnClearTaskFilters')?.addEventListener(
        'click',
        () => {
            const statusFilter =
                $('taskStatusFilter');

            const typeFilter =
                $('taskTypeFilter');

            if (statusFilter) {
                statusFilter.value = '';
            }

            if (typeFilter) {
                typeFilter.value = '';
            }

            state.taskOffset = 0;

            loadTasks().catch(
                handleError
            );
        }
    );


    /*
     * Página anterior
     */
    $('btnTaskPrev')?.addEventListener(
        'click',
        () => {
            state.taskOffset = Math.max(
                0,
                state.taskOffset - state.taskLimit
            );

            loadTasks().catch(
                handleError
            );
        }
    );


    /*
     * Próxima página
     */
    $('btnTaskNext')?.addEventListener(
        'click',
        () => {
            if (
                state.taskOffset +
                state.taskLimit >=
                state.taskTotal
            ) {
                return;
            }

            state.taskOffset +=
                state.taskLimit;

            loadTasks().catch(
                handleError
            );
        }
    );


    /*
     * Atualização manual
     */
    $('btnRefreshTasks')?.addEventListener(
        'click',
        async () => {
            const button =
                $('btnRefreshTasks');

            setButtonLoading(
                button,
                true
            );

            try {
                await loadTasks();

                showToast(
                    'Lista de tarefas atualizada.',
                    'ok'
                );

            } catch (error) {
                handleError(error);

            } finally {
                setButtonLoading(
                    button,
                    false
                );
            }
        }
    );
}


/* ==========================================================================
   CRIAÇÃO DE TAREFA
   ========================================================================== */

export async function createTask(
    tipo,
    parametros = {}
) {
    if (!tipo) {
        throw new Error(
            'O tipo da tarefa não foi informado.'
        );
    }

    const payload = await fetchJSON(
        apiUrl('criarTarefa'),
        {
            method: 'POST',

            body: {
                tipo,
                parametros
            }
        }
    );

    const data =
        unwrapPayload(payload);

    const task =
        readPath(
            data,
            ['tarefa'],
            null
        ) ||
        readPath(
            payload,
            ['tarefa'],
            null
        ) ||
        data;

    if (
        !task ||
        typeof task !== 'object'
    ) {
        throw new Error(
            'A API não retornou a tarefa criada.'
        );
    }

    return task;
}


/* ==========================================================================
   CONFIRMAÇÃO / CRIAÇÃO
   ========================================================================== */

export async function confirmTask(
    config,
    onCreated = null
) {
    if (!config?.tipo) {
        throw new Error(
            'Configuração da tarefa inválida.'
        );
    }

    const task = await createTask(
        config.tipo,
        config.parametros || {}
    );

    showToast(
        'Tarefa criada com sucesso.',
        'ok'
    );

    await loadTasks();

    const taskId =
        task.id ||
        task.pk ||
        null;

    if (
        taskId &&
        typeof onCreated === 'function'
    ) {
        await onCreated(taskId);
    }

    return task;
}


/* ==========================================================================
   LISTAGEM
   ========================================================================== */

export async function loadTasks() {
    const query =
        new URLSearchParams();

    const status =
        $('taskStatusFilter')?.value ||
        '';

    const type =
        $('taskTypeFilter')?.value ||
        '';

    query.set(
        'offset',
        String(state.taskOffset)
    );

    query.set(
        'limite',
        String(state.taskLimit)
    );

    if (status) {
        query.set(
            'status',
            status
        );
    }

    if (type) {
        query.set(
            'tipo',
            type
        );
    }

    const payload =
        await fetchJSON(
            `${apiUrl('listarTarefas')}?${query.toString()}`
        );

    const data =
        unwrapPayload(payload);

    const tasks =
        safeArray(
            readPath(
                data,
                [
                    'tarefas',
                    'results'
                ],
                readPath(
                    payload,
                    ['tarefas'],
                    []
                )
            )
        );

    const total =
        numberValue(
            readPath(
                data,
                [
                    'total',
                    'count'
                ],
                tasks.length
            ),
            tasks.length
        );

    /*
     * Estado global
     */
    state.tasks =
        tasks;

    state.taskTotal =
        total;

    state.taskPage =
        Math.floor(
            state.taskOffset /
            state.taskLimit
        ) + 1;


    /*
     * Renderizações
     */
    renderTaskTable(
        tasks
    );

    renderOverviewTasks(
        tasks.slice(
            0,
            5
        )
    );

    renderTaskPagination();

    updateTaskBadge(
        tasks
    );

    return tasks;
}


/* ==========================================================================
   TABELA
   ========================================================================== */

export function renderTaskTable(
    tasks
) {
    const body =
        $('taskTableBody');

    if (!body) {
        return;
    }

    body.innerHTML = '';


    /*
     * Estado vazio
     */
    if (!tasks.length) {
        body.innerHTML = `
            <tr>
                <td colspan="7">
                    <div class="sp-empty-state">

                        <span class="sp-empty-state__icon">
                            ${iconSVG('task', 22)}
                        </span>

                        <div>
                            <strong>
                                Nenhuma tarefa encontrada
                            </strong>

                            <span>
                                Altere os filtros ou crie uma nova operação.
                            </span>
                        </div>

                    </div>
                </td>
            </tr>
        `;

        return;
    }


    /*
     * Linhas
     */
    for (const task of tasks) {
        const id =
            task.id ||
            task.pk ||
            '';

        const type =
            textValue(
                task.tipo,
                ''
            );

        const status =
            textValue(
                task.status,
                'pendente'
            ).toLowerCase();

        const normalizedStatus =
            normalizeStatus(
                status
            );

        const progress =
            Math.max(
                0,
                Math.min(
                    100,
                    numberValue(
                        task.progresso,
                        0
                    )
                )
            );

        const label =
            TASK_LABELS[type] ||
            capitalize(type) ||
            'Tarefa';

        const icon =
            TASK_ICONS[type] ||
            'task';

        const etapa =
            task.etapa_atual ||
            '—';

        const inicio =
            task.iniciado_em ||
            task.criado_em ||
            null;

        const duration =
            task.duracao_segundos;

        const row =
            document.createElement(
                'tr'
            );


        row.innerHTML = `
            <td>
                <div class="sp-task-cell">

                    <span class="sp-task-cell__icon">
                        ${iconSVG(icon, 15)}
                    </span>

                    <span class="sp-task-cell__copy">

                        <strong>
                            ${escapeHTML(label)}
                        </strong>

                        <span>
                            ${escapeHTML(id)}
                        </span>

                    </span>

                </div>
            </td>


            <td>
                <span
                    class="sp-status-pill sp-status-pill--${escapeHTML(normalizedStatus)}"
                >
                    ${escapeHTML(statusLabel(status))}
                </span>
            </td>


            <td>
                <div class="sp-progress-mini">

                    <div class="sp-progress-mini__bar">
                        <span
                            style="width:${progress}%"
                        ></span>
                    </div>

                    <span class="sp-progress-mini__text">
                        ${progress}%
                    </span>

                </div>
            </td>


            <td>
                ${escapeHTML(etapa)}
            </td>


            <td>
                ${escapeHTML(formatDate(inicio))}
            </td>


            <td>
                ${escapeHTML(formatDuration(duration))}
            </td>


            <td>
                <button
                    class="sp-icon-btn sp-icon-btn--small"
                    type="button"
                    aria-label="Abrir tarefa"
                    title="Abrir tarefa"
                    data-task-open="${escapeHTML(id)}"
                >
                    <svg
                        width="15"
                        height="15"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        stroke-width="2"
                        aria-hidden="true"
                    >
                        <path d="M5 12h14" />
                        <path d="M12 5l7 7-7 7" />
                    </svg>
                </button>
            </td>
        `;

        body.appendChild(
            row
        );
    }
}


/* ==========================================================================
   PAGINAÇÃO
   ========================================================================== */

export function renderTaskPagination() {
    const start =
        state.taskTotal
            ? state.taskOffset + 1
            : 0;

    const end =
        Math.min(
            state.taskOffset +
                state.taskLimit,
            state.taskTotal
        );

    const totalPages =
        Math.max(
            1,
            Math.ceil(
                state.taskTotal /
                state.taskLimit
            )
        );

    setText(
        'taskPaginationText',
        `${start}–${end} de ${state.taskTotal} tarefa(s)`
    );

    setText(
        'taskPageText',
        `Página ${state.taskPage} de ${totalPages}`
    );


    const prev =
        $('btnTaskPrev');

    const next =
        $('btnTaskNext');


    if (prev) {
        prev.disabled =
            state.taskOffset <= 0;
    }

    if (next) {
        next.disabled =
            state.taskOffset +
            state.taskLimit >=
            state.taskTotal;
    }
}


/* ==========================================================================
   BADGE DA SIDEBAR
   ========================================================================== */

export function updateTaskBadge(
    tasks = []
) {
    const badge =
        $('navTaskBadge');

    if (!badge) {
        return;
    }

    const runningStatuses =
        new Set([
            'pendente',
            'executando'
        ]);

    const runningCount =
        safeArray(tasks)
            .filter((task) => {
                const status =
                    String(
                        task?.status ||
                        ''
                    )
                        .trim()
                        .toLowerCase();

                return runningStatuses.has(
                    status
                );
            })
            .length;


    if (runningCount <= 0) {
        badge.hidden = true;
        badge.textContent = '0';

        return;
    }

    badge.textContent =
        String(runningCount);

    badge.hidden = false;
}


/* ==========================================================================
   DETALHE
   ========================================================================== */

export async function loadTaskDetail(
    taskId
) {
    if (!taskId) {
        throw new Error(
            'ID da tarefa não informado.'
        );
    }

    const detailUrl =
        sanitizeUrl(
            apiUrl(
                'detalheTarefaTemplate'
            ),
            taskId
        );

    const payload =
        await fetchJSON(
            detailUrl
        );

    const data =
        unwrapPayload(
            payload
        );

    const task =
        readPath(
            data,
            ['tarefa'],
            null
        ) ||
        readPath(
            payload,
            ['tarefa'],
            null
        ) ||
        data;


    if (
        !task ||
        typeof task !== 'object'
    ) {
        throw new Error(
            'Não foi possível carregar os detalhes da tarefa.'
        );
    }

    return task;
}


/* ==========================================================================
   CANCELAMENTO
   ========================================================================== */

export async function requestTaskCancellation(
    taskId
) {
    if (!taskId) {
        throw new Error(
            'ID da tarefa não informado.'
        );
    }

    const url =
        sanitizeUrl(
            apiUrl(
                'cancelarTarefaTemplate'
            ),
            taskId
        );

    const payload =
        await fetchJSON(
            url,
            {
                method: 'POST',
                body: {}
            }
        );

    showToast(
        'Cancelamento solicitado.',
        'warning'
    );

    return unwrapPayload(
        payload
    );
}