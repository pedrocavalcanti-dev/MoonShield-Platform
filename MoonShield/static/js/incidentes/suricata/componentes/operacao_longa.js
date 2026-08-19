import {
    $,
    setText,
} from '../nucleo/dom.js';

import {
    numberValue,
    textValue,
} from '../nucleo/utilitarios.js';


const FINAL_STATUSES = new Set([
    'sucesso',
    'erro',
    'cancelado',
    'ignorado',
]);

const RUNNING_STATUSES = new Set([
    'pendente',
    'executando',
]);

const DEFAULT_POLL_INTERVAL = 1600;

const OPERATION_PROFILES = Object.freeze({
    validacao: {
        title: 'Validando configuração do Suricata',
        description: 'O Suricata está carregando o YAML e as assinaturas configuradas.',
        estimate: 'Esta operação pode levar cerca de 40–60 segundos.',
    },

    atualizacao_regras: {
        title: 'Atualizando regras do Suricata',
        description: 'O MoonShield está sincronizando ET Open e as regras locais configuradas.',
        estimate: 'Esta operação pode levar alguns minutos, dependendo da atualização disponível.',
    },

    instalacao_regras_moonshield: {
        title: 'Instalando MoonShield Rules',
        description: 'As regras locais estão sendo instaladas e referenciadas na configuração do Suricata.',
        estimate: 'Esta etapa normalmente leva alguns segundos.',
    },

    configuracao: {
        title: 'Aplicando configuração do Suricata',
        description: 'O MoonShield está aplicando interfaces, HOME_NET, EVE e referências de regras.',
        estimate: 'A aplicação e validação podem levar cerca de 40–90 segundos.',
    },

    reinicio_suricata: {
        title: 'Reiniciando o Suricata',
        description: 'O serviço do motor IDS está sendo reiniciado de forma controlada.',
        estimate: 'A captura pode ficar indisponível por alguns segundos.',
    },

    reinicio_monitor: {
        title: 'Reiniciando o monitor MoonShield',
        description: 'O leitor do eve.json está sendo reiniciado e retomará o cursor persistido.',
        estimate: 'Esta operação normalmente leva poucos segundos.',
    },

    instalacao: {
        title: 'Instalando ambiente Suricata',
        description: 'O MoonShield está preparando pacotes, configuração, serviços e regras.',
        estimate: 'A instalação pode levar alguns minutos.',
    },

    reparo: {
        title: 'Reparando ambiente Suricata',
        description: 'O MoonShield está verificando e corrigindo componentes necessários da stack.',
        estimate: 'O tempo varia conforme os componentes que precisarem de correção.',
    },
});


let elapsedTimer = null;
let pollTimer = null;
let currentTaskId = null;
let currentTaskType = null;
let currentStartedAt = null;
let currentFetchTask = null;
let currentOnUpdate = null;
let currentOnFinish = null;
let pollInFlight = false;


/* ==========================================================================
   INICIALIZAÇÃO
   ========================================================================== */

export function initOperacaoLonga() {
    setOverlayVisible(false);

    window.addEventListener(
        'beforeunload',
        cleanupLongOperation,
        {
            once: true,
        },
    );
}


/* ==========================================================================
   PERFIS
   ========================================================================== */

export function getLongOperationProfile(
    taskType,
    parameters = {},
) {
    const type = normalizeText(taskType);

    /*
     * O diagnóstico já possui UX própria e não é interceptado pelo
     * componente global.
     */
    if (
        !type
        || type === 'diagnostico'
    ) {
        return null;
    }

    if (
        type === 'atualizacao_regras'
    ) {
        const updateEt = parameters?.atualizar_et;
        const updateMoon = parameters?.atualizar_moonshield;

        if (
            updateEt === false
            && updateMoon !== false
        ) {
            return {
                ...OPERATION_PROFILES.instalacao_regras_moonshield,
            };
        }

        if (
            updateEt !== false
            && updateMoon === false
        ) {
            return {
                title: 'Atualizando ET Open',
                description: 'O Suricata Update está sincronizando o conjunto comunitário de assinaturas ET Open.',
                estimate: 'Esta operação pode levar alguns minutos.',
            };
        }
    }

    const profile = OPERATION_PROFILES[type];

    if (profile) {
        return {
            ...profile,
        };
    }

    return {
        title: 'Executando operação do Suricata',
        description: 'O MoonShield está processando a tarefa solicitada no worker automático.',
        estimate: 'Aguarde a conclusão da operação.',
    };
}


/* ==========================================================================
   ABERTURA / ATUALIZAÇÃO
   ========================================================================== */

export function openLongOperation({
    taskId = null,
    taskType = '',
    parameters = {},
    title = '',
    description = '',
    estimate = '',
    progress = 0,
    stage = 'Preparando',
    message = 'Aguardando o worker iniciar a operação.',
    startedAt = null,
} = {}) {
    const profile = (
        getLongOperationProfile(
            taskType,
            parameters,
        )
        || {}
    );

    currentTaskId = taskId
        ? String(taskId)
        : currentTaskId;

    currentTaskType = (
        taskType
        || currentTaskType
        || ''
    );

    currentStartedAt = resolveStartedAt(
        startedAt,
    );

    setText(
        'longOperationEyebrow',
        'Operação em andamento',
    );

    setText(
        'longOperationTitle',
        title
        || profile.title
        || 'Executando operação',
    );

    setText(
        'longOperationDescription',
        description
        || profile.description
        || 'O MoonShield está processando a solicitação.',
    );

    setText(
        'longOperationEstimate',
        estimate
        || profile.estimate
        || 'Aguarde a conclusão da operação.',
    );

    setText(
        'longOperationTaskId',
        currentTaskId
            ? `Tarefa ${currentTaskId}`
            : 'Preparando tarefa',
    );

    updateLongOperation({
        status: 'executando',
        progress,
        stage,
        message,
        startedAt: currentStartedAt,
    });

    setOverlayState(
        'running',
    );

    setOverlayVisible(true);

    startElapsedTimer(
        currentStartedAt,
    );
}


export function updateLongOperation({
    status = 'executando',
    progress = 0,
    stage = '',
    message = '',
    startedAt = null,
    finishedAt = null,
    durationSeconds = null,
} = {}) {
    const normalizedStatus = normalizeStatus(
        status,
    );

    const safeProgress = clampProgress(
        progress,
    );

    if (startedAt) {
        currentStartedAt = resolveStartedAt(
            startedAt,
        );
    }

    setText(
        'longOperationProgressText',
        `${safeProgress}%`,
    );

    const bar = $(
        'longOperationProgressBar',
    );

    if (bar) {
        bar.style.width = (
            `${safeProgress}%`
        );

        bar.setAttribute(
            'aria-valuenow',
            String(safeProgress),
        );
    }

    setText(
        'longOperationStage',
        formatStage(
            stage
            || (
                normalizedStatus === 'pendente'
                    ? 'Aguardando worker'
                    : 'Processando'
            ),
        ),
    );

    setText(
        'longOperationMessage',
        message
        || defaultMessageForStatus(
            normalizedStatus,
        ),
    );

    if (
        durationSeconds !== null
        && durationSeconds !== undefined
        && FINAL_STATUSES.has(
            normalizedStatus,
        )
    ) {
        setText(
            'longOperationElapsed',
            formatElapsed(
                numberValue(
                    durationSeconds,
                    0,
                ),
            ),
        );
    } else if (finishedAt) {
        const started = (
            currentStartedAt
            || Date.now()
        );

        const finished = new Date(
            finishedAt,
        ).getTime();

        if (
            Number.isFinite(finished)
        ) {
            setText(
                'longOperationElapsed',
                formatElapsed(
                    Math.max(
                        0,
                        Math.floor(
                            (
                                finished
                                - started
                            )
                            / 1000,
                        ),
                    ),
                ),
            );
        }
    }

    setOverlayState(
        visualStateFromStatus(
            normalizedStatus,
        ),
    );
}


/* ==========================================================================
   ACOMPANHAMENTO DE TAREFA
   ========================================================================== */

export function trackLongOperationTask({
    task,
    taskId = null,
    taskType = '',
    parameters = {},
    fetchTask,
    onUpdate = null,
    onFinish = null,
    pollInterval = DEFAULT_POLL_INTERVAL,
} = {}) {
    stopLongOperationPolling();

    const initialTask = (
        task
        && typeof task === 'object'
            ? task
            : {}
    );

    currentTaskId = String(
        taskId
        || initialTask.id
        || initialTask.pk
        || '',
    );

    currentTaskType = (
        taskType
        || initialTask.tipo
        || ''
    );

    currentFetchTask = (
        typeof fetchTask === 'function'
            ? fetchTask
            : null
    );

    currentOnUpdate = (
        typeof onUpdate === 'function'
            ? onUpdate
            : null
    );

    currentOnFinish = (
        typeof onFinish === 'function'
            ? onFinish
            : null
    );

    if (!currentTaskId) {
        throw new Error(
            'Não foi possível acompanhar a operação: tarefa sem identificador.',
        );
    }

    if (!currentFetchTask) {
        throw new Error(
            'Não foi possível acompanhar a operação: fetchTask não informado.',
        );
    }

    const profile = getLongOperationProfile(
        currentTaskType,
        parameters,
    );

    if (!profile) {
        /*
         * Diagnóstico usa seu próprio componente.
         */
        return false;
    }

    openLongOperation({
        taskId: currentTaskId,
        taskType: currentTaskType,
        parameters,
        progress: readTaskProgress(
            initialTask,
        ),
        stage: readTaskStage(
            initialTask,
        ),
        message: readTaskMessage(
            initialTask,
        ),
        startedAt: readTaskStartedAt(
            initialTask,
        ),
    });

    applyTaskToLongOperation(
        initialTask,
    );

    const poll = async () => {
        if (
            pollInFlight
            || !currentTaskId
            || document.hidden
        ) {
            return;
        }

        pollInFlight = true;

        try {
            const freshTask = await currentFetchTask(
                currentTaskId,
            );

            if (
                !freshTask
                || typeof freshTask !== 'object'
            ) {
                return;
            }

            applyTaskToLongOperation(
                freshTask,
            );

            if (currentOnUpdate) {
                await currentOnUpdate(
                    freshTask,
                );
            }

            const status = normalizeStatus(
                freshTask.status
                || freshTask.estado,
            );

            if (
                FINAL_STATUSES.has(
                    status,
                )
            ) {
                stopLongOperationPolling();

                if (currentOnFinish) {
                    await currentOnFinish(
                        freshTask,
                    );
                }

                finishLongOperation(
                    freshTask,
                );
            }
        } catch (error) {
            console.error(
                '[MoonShield] Falha temporária ao acompanhar operação longa:',
                error,
            );

            setText(
                'longOperationMessage',
                'A tarefa continua no worker, mas a última atualização não pôde ser consultada.',
            );
        } finally {
            pollInFlight = false;
        }
    };

    poll();

    pollTimer = window.setInterval(
        poll,
        Math.max(
            900,
            numberValue(
                pollInterval,
                DEFAULT_POLL_INTERVAL,
            ),
        ),
    );

    return true;
}


export function applyTaskToLongOperation(
    task,
) {
    if (
        !task
        || typeof task !== 'object'
    ) {
        return;
    }

    const taskId = (
        task.id
        || task.pk
        || ''
    );

    if (taskId) {
        currentTaskId = String(
            taskId,
        );

        setText(
            'longOperationTaskId',
            `Tarefa ${currentTaskId}`,
        );
    }

    if (task.tipo) {
        currentTaskType = (
            task.tipo
        );
    }

    updateLongOperation({
        status: (
            task.status
            || task.estado
            || 'executando'
        ),
        progress: readTaskProgress(
            task,
        ),
        stage: readTaskStage(
            task,
        ),
        message: readTaskMessage(
            task,
        ),
        startedAt: readTaskStartedAt(
            task,
        ),
        finishedAt: (
            task.finalizado_em
            || task.finalizada_em
            || null
        ),
        durationSeconds: (
            task.duracao_segundos
            ?? null
        ),
    });
}


/* ==========================================================================
   FINALIZAÇÃO
   ========================================================================== */

export function finishLongOperation(
    task,
) {
    const status = normalizeStatus(
        task?.status
        || task?.estado
        || 'erro',
    );

    const success = (
        status === 'sucesso'
    );

    const cancelled = (
        status === 'cancelado'
    );

    const ignored = (
        status === 'ignorado'
    );

    const progress = success
        ? 100
        : readTaskProgress(
            task,
        );

    updateLongOperation({
        status,
        progress,
        stage: success
            ? 'Concluído'
            : cancelled
                ? 'Cancelado'
                : ignored
                    ? 'Ignorado'
                    : 'Falha',
        message: (
            task?.mensagem
            || task?.erro
            || (
                success
                    ? 'Operação concluída com sucesso.'
                    : cancelled
                        ? 'A operação foi cancelada.'
                        : ignored
                            ? 'A operação foi ignorada pelo worker.'
                            : 'A operação terminou com erro.'
            )
        ),
        startedAt: readTaskStartedAt(
            task,
        ),
        finishedAt: (
            task?.finalizado_em
            || task?.finalizada_em
            || null
        ),
        durationSeconds: (
            task?.duracao_segundos
            ?? null
        ),
    });

    setText(
        'longOperationEyebrow',
        success
            ? 'Operação concluída'
            : cancelled
                ? 'Operação cancelada'
                : ignored
                    ? 'Operação encerrada'
                    : 'Falha na operação',
    );

    setOverlayState(
        success
            ? 'success'
            : cancelled || ignored
                ? 'warning'
                : 'error',
    );

    stopElapsedTimer();

    window.setTimeout(
        () => {
            closeLongOperation();
        },
        success
            ? 900
            : 1800,
    );
}


export function failLongOperation(
    message = 'Não foi possível concluir a operação.',
) {
    stopLongOperationPolling();
    stopElapsedTimer();

    setText(
        'longOperationEyebrow',
        'Falha na operação',
    );

    setText(
        'longOperationStage',
        'Erro',
    );

    setText(
        'longOperationMessage',
        message,
    );

    setOverlayState(
        'error',
    );

    window.setTimeout(
        () => closeLongOperation(),
        1800,
    );
}


export function closeLongOperation() {
    stopLongOperationPolling();
    stopElapsedTimer();

    setOverlayVisible(false);

    currentTaskId = null;
    currentTaskType = null;
    currentStartedAt = null;
    currentFetchTask = null;
    currentOnUpdate = null;
    currentOnFinish = null;
    pollInFlight = false;
}


export function isLongOperationActive() {
    return Boolean(
        currentTaskId
        && $(
            'longOperationOverlay',
        )
        && !$(
            'longOperationOverlay',
        ).hidden
    );
}


export function getTrackedLongOperationTaskId() {
    return currentTaskId;
}


/* ==========================================================================
   POLLING / TIMER
   ========================================================================== */

function stopLongOperationPolling() {
    if (pollTimer) {
        window.clearInterval(
            pollTimer,
        );

        pollTimer = null;
    }
}


function startElapsedTimer(
    startedAt = null,
) {
    stopElapsedTimer();

    currentStartedAt = resolveStartedAt(
        startedAt,
    );

    renderElapsed();

    elapsedTimer = window.setInterval(
        renderElapsed,
        1000,
    );
}


function stopElapsedTimer() {
    if (elapsedTimer) {
        window.clearInterval(
            elapsedTimer,
        );

        elapsedTimer = null;
    }
}


function renderElapsed() {
    if (!currentStartedAt) {
        setText(
            'longOperationElapsed',
            '00:00',
        );

        return;
    }

    const seconds = Math.max(
        0,
        Math.floor(
            (
                Date.now()
                - currentStartedAt
            )
            / 1000,
        ),
    );

    setText(
        'longOperationElapsed',
        formatElapsed(
            seconds,
        ),
    );
}


/* ==========================================================================
   DOM
   ========================================================================== */

function setOverlayVisible(
    visible,
) {
    const overlay = $(
        'longOperationOverlay',
    );

    if (!overlay) {
        if (visible) {
            console.warn(
                '[MoonShield] _operacao_longa.html não foi incluído no painel.',
            );
        }

        return;
    }

    overlay.hidden = !visible;
    overlay.classList.toggle(
        'is-open',
        visible,
    );

    overlay.setAttribute(
        'aria-hidden',
        visible
            ? 'false'
            : 'true',
    );

    document.body.classList.toggle(
        'is-long-operation-open',
        visible,
    );
}


function setOverlayState(
    stateName,
) {
    const card = $(
        'longOperationCard',
    );

    if (!card) {
        return;
    }

    card.classList.remove(
        'is-running',
        'is-success',
        'is-warning',
        'is-error',
    );

    card.classList.add(
        `is-${stateName}`,
    );
}


/* ==========================================================================
   HELPERS
   ========================================================================== */

function normalizeStatus(
    value,
) {
    const status = normalizeText(
        value,
    );

    if (
        status === 'ok'
        || status === 'concluido'
        || status === 'concluida'
    ) {
        return 'sucesso';
    }

    if (
        status === 'falha'
        || status === 'failed'
        || status === 'error'
    ) {
        return 'erro';
    }

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

    return (
        status
        || 'pendente'
    );
}


function visualStateFromStatus(
    status,
) {
    if (status === 'sucesso') {
        return 'success';
    }

    if (
        status === 'cancelado'
        || status === 'ignorado'
    ) {
        return 'warning';
    }

    if (status === 'erro') {
        return 'error';
    }

    return 'running';
}


function defaultMessageForStatus(
    status,
) {
    if (status === 'pendente') {
        return 'Aguardando o worker automático iniciar a tarefa.';
    }

    if (status === 'executando') {
        return 'Operação em processamento.';
    }

    if (status === 'sucesso') {
        return 'Operação concluída com sucesso.';
    }

    if (status === 'cancelado') {
        return 'Operação cancelada.';
    }

    if (status === 'erro') {
        return 'A operação terminou com erro.';
    }

    return 'Aguardando atualização.';
}


function readTaskProgress(
    task,
) {
    return clampProgress(
        task?.progresso
        ?? task?.progress
        ?? 0,
    );
}


function readTaskStage(
    task,
) {
    return textValue(
        task?.etapa_atual
        || task?.etapa
        || task?.stage
        || 'Preparando',
        'Preparando',
    );
}


function readTaskMessage(
    task,
) {
    return textValue(
        task?.mensagem
        || task?.message
        || (
            normalizeStatus(
                task?.status
                || task?.estado
            ) === 'pendente'
                ? 'Aguardando o worker automático.'
                : 'Operação em processamento.'
        ),
        'Operação em processamento.',
    );
}


function readTaskStartedAt(
    task,
) {
    return (
        task?.iniciado_em
        || task?.iniciada_em
        || task?.criado_em
        || task?.criada_em
        || null
    );
}


function resolveStartedAt(
    value,
) {
    const date = value
        ? new Date(value)
        : null;

    if (
        date
        && Number.isFinite(
            date.getTime(),
        )
    ) {
        return date.getTime();
    }

    if (
        typeof value === 'number'
        && Number.isFinite(value)
    ) {
        return value;
    }

    return (
        currentStartedAt
        || Date.now()
    );
}


function formatStage(
    value,
) {
    const stage = String(
        value || '',
    )
        .replaceAll(
            '_',
            ' ',
        )
        .trim();

    if (!stage) {
        return 'Processando';
    }

    return (
        stage.charAt(0).toUpperCase()
        + stage.slice(1)
    );
}


function formatElapsed(
    seconds,
) {
    const safeSeconds = Math.max(
        0,
        Math.floor(
            numberValue(
                seconds,
                0,
            ),
        ),
    );

    const hours = Math.floor(
        safeSeconds / 3600,
    );

    const minutes = Math.floor(
        (
            safeSeconds % 3600
        )
        / 60,
    );

    const secs = (
        safeSeconds % 60
    );

    if (hours > 0) {
        return (
            `${String(hours).padStart(2, '0')}:`
            + `${String(minutes).padStart(2, '0')}:`
            + `${String(secs).padStart(2, '0')}`
        );
    }

    return (
        `${String(minutes).padStart(2, '0')}:`
        + `${String(secs).padStart(2, '0')}`
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


function normalizeText(
    value,
) {
    return String(
        value || '',
    )
        .trim()
        .toLowerCase();
}


function cleanupLongOperation() {
    stopLongOperationPolling();
    stopElapsedTimer();
}
