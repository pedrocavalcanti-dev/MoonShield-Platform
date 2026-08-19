import {
    $,
    $all,
    setText,
    setHidden,
} from '../nucleo/dom.js';

import {
    state,
    TASK_LABELS,
    FINAL_TASK_STATUSES,
    RUNNING_TASK_STATUSES,
} from '../nucleo/estado.js';

import {
    applyPill,
    normalizeStatus,
    statusLabel,
    copyToClipboard,
} from '../nucleo/interface.js';

import {
    formatDate,
    formatDuration,
    numberValue,
    boolValue,
    escapeHTML,
    textValue,
    sanitizeUrl,
} from '../nucleo/utilitarios.js';

import {
    apiUrl,
    fetchJSON,
    unwrapPayload,
} from '../nucleo/api.js';

import {
    confirmOperation,
} from './modal.js';


/* ==========================================================================
   ESTADO LOCAL
   ========================================================================== */

let lastFocusedElement = null;


/* ==========================================================================
   INICIALIZAÇÃO
   ========================================================================== */

export function initGaveta(onRequestCancel) {
    $('btnCloseTaskDrawer')
        ?.addEventListener(
            'click',
            closeTaskDrawer
        );

    $('btnCloseTaskDrawerFooter')
        ?.addEventListener(
            'click',
            closeTaskDrawer
        );

    $all('[data-close-task-drawer]')
        .forEach((element) => {
            element.addEventListener(
                'click',
                closeTaskDrawer
            );
        });

    $('btnCancelTask')
        ?.addEventListener(
            'click',
            () => {
                if (!state.currentTaskId) {
                    return;
                }

                confirmOperation({
                    title:
                        'Solicitar cancelamento?',

                    text:
                        'O cancelamento é cooperativo e ocorrerá entre as etapas da tarefa.',

                    details:
                        `Tarefa: ${state.currentTaskId}`,

                    confirmLabel:
                        'Solicitar cancelamento',

                    confirmClass:
                        'sp-btn--danger',

                    onConfirm:
                        () => {
                            if (
                                typeof onRequestCancel === 'function'
                            ) {
                                return onRequestCancel(
                                    state.currentTaskId
                                );
                            }
                        },
                });
            }
        );

    $('btnCopyTaskLogs')
        ?.addEventListener(
            'click',
            () => {
                const text =
                    $('drawerTaskLogs')
                        ?.innerText ||
                    '';

                copyToClipboard(
                    text,
                    'Logs copiados.'
                );
            }
        );

    document.addEventListener(
        'keydown',
        handleDrawerKeydown
    );
}


/* ==========================================================================
   ABERTURA
   ========================================================================== */

export async function openTaskDrawer(
    taskId,
    loadDetailFn,
    onCompleteCb
) {
    if (!taskId) {
        return;
    }

    if (
        typeof loadDetailFn !== 'function'
    ) {
        throw new Error(
            'Função de carregamento da tarefa não informada.'
        );
    }

    state.currentTaskId =
        taskId;

    lastFocusedElement =
        document.activeElement instanceof HTMLElement
            ? document.activeElement
            : null;

    const drawer =
        $('taskDrawer');

    if (drawer) {
        drawer.classList.add(
            'is-open'
        );

        drawer.setAttribute(
            'aria-hidden',
            'false'
        );

        if (
            'inert' in drawer
        ) {
            drawer.inert =
                false;
        }

        document.body.style.overflow =
            'hidden';
    }

    renderTaskDrawerLoading(
        taskId
    );

    window.requestAnimationFrame(
        () => {
            const closeButton =
                $('btnCloseTaskDrawer');

            if (
                closeButton instanceof HTMLElement
            ) {
                closeButton.focus({
                    preventScroll: true,
                });
            }
        }
    );

    const task =
        await loadDetailFn(
            taskId
        );

    if (
        state.currentTaskId !== taskId
    ) {
        return;
    }

    state.currentTask =
        task;

    renderTaskDrawer(
        task
    );

    await loadTaskLogs(
        taskId
    );

    const status =
        String(
            task?.status ||
            ''
        )
            .trim()
            .toLowerCase();

    if (
        RUNNING_TASK_STATUSES.has(
            status
        )
    ) {
        startTaskPolling(
            taskId,
            loadDetailFn,
            onCompleteCb
        );
    } else {
        stopTaskPolling();
    }

    return task;
}


/* ==========================================================================
   FECHAMENTO
   ========================================================================== */

export function closeTaskDrawer() {
    stopTaskPolling();

    const drawer =
        $('taskDrawer');

    /*
     * Remove o foco de dentro do drawer antes de marcá-lo
     * como aria-hidden. Isso evita warning de acessibilidade.
     */
    if (
        drawer &&
        drawer.contains(
            document.activeElement
        ) &&
        document.activeElement instanceof HTMLElement
    ) {
        document.activeElement.blur();
    }

    if (drawer) {
        drawer.classList.remove(
            'is-open'
        );

        drawer.setAttribute(
            'aria-hidden',
            'true'
        );

        if (
            'inert' in drawer
        ) {
            drawer.inert =
                true;
        }
    }

    state.currentTaskId =
        null;

    state.currentTask =
        null;

    document.body.style.overflow =
        '';

    if (
        lastFocusedElement instanceof HTMLElement &&
        document.contains(
            lastFocusedElement
        )
    ) {
        window.requestAnimationFrame(
            () => {
                lastFocusedElement.focus({
                    preventScroll: true,
                });
            }
        );
    }

    lastFocusedElement =
        null;
}


/* ==========================================================================
   ESC
   ========================================================================== */

function handleDrawerKeydown(
    event
) {
    if (
        event.key !== 'Escape'
    ) {
        return;
    }

    const drawer =
        $('taskDrawer');

    if (
        !drawer ||
        !drawer.classList.contains(
            'is-open'
        )
    ) {
        return;
    }

    event.preventDefault();

    closeTaskDrawer();
}


/* ==========================================================================
   LOADING
   ========================================================================== */

export function renderTaskDrawerLoading(
    taskId
) {
    setText(
        'taskDrawerTitle',
        'Carregando tarefa'
    );

    setText(
        'drawerTaskType',
        '—'
    );

    setText(
        'drawerTaskId',
        taskId
    );

    setText(
        'drawerTaskStage',
        'Consultando'
    );

    setText(
        'drawerTaskPercent',
        '0%'
    );

    setText(
        'drawerTaskMessage',
        'Buscando dados da tarefa...'
    );

    applyPill(
        'drawerTaskStatus',
        'pending',
        'Carregando'
    );

    const bar =
        $('drawerTaskProgressBar');

    if (bar) {
        bar.style.width =
            '0%';
    }

    setText(
        'drawerTaskCreated',
        '—'
    );

    setText(
        'drawerTaskStarted',
        '—'
    );

    setText(
        'drawerTaskFinished',
        '—'
    );

    setText(
        'drawerTaskDuration',
        '—'
    );

    setHidden(
        'drawerTaskError',
        true
    );

    setHidden(
        'btnCancelTask',
        true
    );

    const logs =
        $('drawerTaskLogs');

    if (logs) {
        logs.innerHTML =
            '<div class="sp-terminal__empty">Carregando logs...</div>';
    }

    setText(
        'drawerTaskResult',
        'Carregando...'
    );
}


/* ==========================================================================
   RENDER DA TAREFA
   ========================================================================== */

export function renderTaskDrawer(
    task
) {
    if (
        !task ||
        typeof task !== 'object'
    ) {
        throw new Error(
            'Dados inválidos ao renderizar tarefa.'
        );
    }

    const id =
        task.id ||
        task.pk ||
        state.currentTaskId ||
        '—';

    const status =
        String(
            task.status ||
            'pendente'
        )
            .trim()
            .toLowerCase();

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

    const taskLabel =
        TASK_LABELS[
            task.tipo
        ] ||
        textValue(
            task.tipo,
            'Tarefa Suricata'
        );

    setText(
        'taskDrawerTitle',
        taskLabel
    );

    setText(
        'drawerTaskType',
        taskLabel
    );

    setText(
        'drawerTaskId',
        id
    );

    applyPill(
        'drawerTaskStatus',
        normalizeStatus(
            status
        ),
        statusLabel(
            status
        )
    );

    setText(
        'drawerTaskStage',
        task.etapa_atual ||
        'Aguardando início'
    );

    setText(
        'drawerTaskPercent',
        `${progress}%`
    );

    setText(
        'drawerTaskMessage',
        task.mensagem ||
        'Nenhuma atualização disponível.'
    );

    setText(
        'drawerTaskCreated',
        formatDate(
            task.criado_em
        )
    );

    setText(
        'drawerTaskStarted',
        formatDate(
            task.iniciado_em
        )
    );

    setText(
        'drawerTaskFinished',
        formatDate(
            task.finalizado_em
        )
    );

    setText(
        'drawerTaskDuration',
        formatDuration(
            task.duracao_segundos
        )
    );

    const bar =
        $('drawerTaskProgressBar');

    if (bar) {
        bar.style.width =
            `${progress}%`;
    }

    const hasError =
        Boolean(
            task.erro
        );

    setHidden(
        'drawerTaskError',
        !hasError
    );

    setText(
        'drawerTaskErrorText',
        task.erro ||
        ''
    );

    /*
     * ESTA ERA A LINHA QUE QUEBRAVA.
     *
     * boolValue agora está importado corretamente de utilitarios.js.
     */
    const canCancel =
        boolValue(
            task.pode_cancelar,
            false
        ) ||
        RUNNING_TASK_STATUSES.has(
            status
        );

    setHidden(
        'btnCancelTask',
        !canCancel
    );

    const result =
        task.resultado &&
        typeof task.resultado === 'object'
            ? task.resultado
            : {};

    const hasResult =
        Object.keys(
            result
        ).length > 0;

    setText(
        'drawerTaskResult',
        hasResult
            ? JSON.stringify(
                result,
                null,
                2
            )
            : 'Nenhum resultado disponível.'
    );

    state.currentTask =
        task;
}


/* ==========================================================================
   LOGS
   ========================================================================== */

export async function loadTaskLogs(
    taskId
) {
    if (!taskId) {
        renderTaskLogs(
            []
        );

        return [];
    }

    const template =
        apiUrl(
            'logsTarefaTemplate'
        );

    if (!template) {
        throw new Error(
            'URL de logs da tarefa não configurada.'
        );
    }

    const dynamicUrl =
        sanitizeUrl(
            template,
            taskId
        );

    const url =
        new URL(
            dynamicUrl,
            window.location.origin
        );

    url.searchParams.set(
        'offset',
        '0'
    );

    url.searchParams.set(
        'limite',
        '500'
    );

    const payload =
        await fetchJSON(
            url.toString()
        );

    const data =
        unwrapPayload(
            payload
        ) || {};

    const logs =
        Array.isArray(
            data.logs
        )
            ? data.logs
            : Array.isArray(
                payload?.logs
            )
                ? payload.logs
                : [];

    renderTaskLogs(
        logs
    );

    return logs;
}


/* ==========================================================================
   RENDER DOS LOGS
   ========================================================================== */

export function renderTaskLogs(
    logs
) {
    const container =
        $('drawerTaskLogs');

    if (!container) {
        return;
    }

    container.innerHTML =
        '';

    if (
        !Array.isArray(logs) ||
        !logs.length
    ) {
        container.innerHTML =
            '<div class="sp-terminal__empty">Nenhum log registrado.</div>';

        return;
    }

    for (
        const log
        of logs
    ) {
        const line =
            document.createElement(
                'div'
            );

        line.className =
            'sp-terminal-line';

        const level =
            textValue(
                log?.nivel,
                'info'
            )
                .toUpperCase();

        let time =
            '--:--:--';

        if (
            log?.criado_em
        ) {
            const date =
                new Date(
                    log.criado_em
                );

            if (
                !Number.isNaN(
                    date.getTime()
                )
            ) {
                time =
                    date.toLocaleTimeString(
                        'pt-BR'
                    );
            }
        }

        const message =
            log?.etapa
                ? `${textValue(log.etapa, '')}: ${textValue(log.mensagem, '')}`
                : textValue(
                    log?.mensagem,
                    ''
                );

        line.innerHTML = `
            <span class="sp-terminal-line__time">${escapeHTML(time)}</span>
            <span class="sp-terminal-line__level">[${escapeHTML(level)}]</span>
            <span class="sp-terminal-line__message">${escapeHTML(message)}</span>
        `;

        container.appendChild(
            line
        );
    }

    container.scrollTop =
        container.scrollHeight;
}


/* ==========================================================================
   POLLING
   ========================================================================== */

export function startTaskPolling(
    taskId,
    loadDetailFn,
    onCompleteCb
) {
    stopTaskPolling();

    if (
        !taskId ||
        typeof loadDetailFn !== 'function'
    ) {
        return;
    }

    state.taskPollTimer =
        window.setInterval(
            async () => {
                if (
                    state.destroyed ||
                    state.currentTaskId !== taskId ||
                    document.hidden
                ) {
                    return;
                }

                try {
                    const task =
                        await loadDetailFn(
                            taskId
                        );

                    if (
                        state.currentTaskId !== taskId
                    ) {
                        return;
                    }

                    state.currentTask =
                        task;

                    renderTaskDrawer(
                        task
                    );

                    await loadTaskLogs(
                        taskId
                    );

                    const status =
                        String(
                            task?.status ||
                            ''
                        )
                            .trim()
                            .toLowerCase();

                    if (
                        FINAL_TASK_STATUSES.has(
                            status
                        )
                    ) {
                        stopTaskPolling();

                        if (
                            typeof onCompleteCb === 'function'
                        ) {
                            await onCompleteCb(
                                task
                            );
                        }
                    }

                } catch (error) {
                    console.error(
                        '[MoonShield] Erro no polling da tarefa:',
                        error
                    );
                }
            },
            2500
        );
}


/* ==========================================================================
   STOP POLLING
   ========================================================================== */

export function stopTaskPolling() {
    if (
        !state.taskPollTimer
    ) {
        return;
    }

    window.clearInterval(
        state.taskPollTimer
    );

    state.taskPollTimer =
        null;
}