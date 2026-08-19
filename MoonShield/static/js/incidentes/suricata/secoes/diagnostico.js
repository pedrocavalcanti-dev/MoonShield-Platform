import {
    fetchJSON,
    unwrapPayload,
    apiUrl,
    handleError,
} from '../nucleo/api.js';

import {
    state,
} from '../nucleo/estado.js';

import {
    setButtonLoading,
    setText,
    $,
} from '../nucleo/dom.js';

import {
    applyChip,
    iconSVG,
    statusLabel,
} from '../nucleo/interface.js';

import {
    safeObject,
    readPath,
    safeArray,
    numberValue,
    boolValue,
    textValue,
    formatDate,
    formatDuration,
    escapeHTML,
    sanitizeUrl,
} from '../nucleo/utilitarios.js';

import {
    showToast,
} from '../componentes/notificacoes.js';


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

const DIAGNOSTIC_POLL_INTERVAL = 2000;

let diagnosticPollTimer = null;
let diagnosticElapsedTimer = null;
let diagnosticStartedAt = null;
let diagnosticTaskId = null;
let diagnosticOnSuccess = null;


// ============================================================================
// INICIALIZAÇÃO
// ============================================================================

export function initDiagnostico(onSuccess) {
    diagnosticOnSuccess = (
        typeof onSuccess === 'function'
            ? onSuccess
            : null
    );

    const buttons = getDiagnosticButtons();

    buttons.forEach((button) => {
        button.addEventListener(
            'click',
            () => runDiagnostic(
                button,
                diagnosticOnSuccess,
            ),
        );
    });

    // Somente CONSULTA o último diagnóstico persistido.
    // Não executa Doctor automaticamente.
    loadPersistedDiagnostic({
        resumeRunningTask: true,
        silent: true,
    }).catch((error) => {
        console.error(
            '[MoonShield] Falha ao carregar último diagnóstico:',
            error,
        );

        renderNeverExecuted();
    });

    window.addEventListener(
        'beforeunload',
        cleanupDiagnostic,
        { once: true },
    );
}


// ============================================================================
// EXECUÇÃO
// ============================================================================

export async function runDiagnostic(
    button = null,
    onSuccess = diagnosticOnSuccess,
) {
    if (state.isRunningDiagnostic) {
        showToast(
            'Já existe um diagnóstico em andamento.',
            'warning',
        );
        return;
    }

    state.isRunningDiagnostic = true;

    const buttons = getDiagnosticButtons();

    buttons.forEach((item) => {
        setButtonLoading(item, true);
        item.disabled = true;
    });

    applyChip(
        'diagnosticGeneralChip',
        'pending',
        'Aguardando worker',
    );

    setRuntimeVisible(true);
    updateRuntime({
        title: 'Preparando diagnóstico',
        message: (
            'O MoonShield está registrando a tarefa no worker. '
            + 'A análise completa pode levar entre 40 e 90 segundos.'
        ),
        progress: 2,
    });

    startElapsedTimer();

    try {
        const task = await createDiagnosticTask();

        const taskId = getTaskId(task);

        if (!taskId) {
            throw new Error(
                'A API criou a operação, mas não retornou o identificador da tarefa.',
            );
        }

        diagnosticTaskId = taskId;

        const status = normalizeTaskStatus(
            readPath(task, ['status'], 'pendente'),
        );

        updateRuntimeFromTask(task);

        if (RUNNING_TASK_STATUSES.has(status)) {
            startDiagnosticPolling(
                taskId,
                onSuccess,
            );

            showToast(
                readPath(task, ['reutilizada'], false)
                    ? 'Diagnóstico em andamento retomado.'
                    : 'Diagnóstico enviado ao worker.',
                'info',
            );

            return;
        }

        await finishDiagnosticTask(
            task,
            onSuccess,
        );
    } catch (error) {
        state.isRunningDiagnostic = false;
        stopDiagnosticPolling();
        stopElapsedTimer();

        buttons.forEach((item) => {
            setButtonLoading(item, false);
            item.disabled = false;
        });

        setRuntimeVisible(false);

        applyChip(
            'diagnosticGeneralChip',
            'error',
            'Falhou',
        );

        handleError(error);
    }
}


// ============================================================================
// CRIAÇÃO DA TAREFA
// ============================================================================

async function createDiagnosticTask() {
    const payload = await fetchJSON(
        apiUrl('criarTarefa'),
        {
            method: 'POST',
            body: {
                tipo: 'diagnostico',
                parametros: {
                    incluir_validacao_suricata: true,
                    incluir_checks_eve: true,
                    incluir_checks_servicos: true,
                },
            },
        },
    );

    const data = unwrapPayload(payload);

    const task = (
        readPath(data, ['tarefa'], null)
        || readPath(payload, ['tarefa'], null)
        || data
    );

    if (!task || typeof task !== 'object') {
        throw new Error(
            'A API não retornou a tarefa de diagnóstico.',
        );
    }

    // A view pode reutilizar uma tarefa que já esteja rodando.
    if (
        readPath(data, ['reutilizada'], false)
        && !readPath(task, ['reutilizada'], false)
    ) {
        task.reutilizada = true;
    }

    return task;
}


// ============================================================================
// POLLING
// ============================================================================

function startDiagnosticPolling(
    taskId,
    onSuccess,
) {
    stopDiagnosticPolling();

    diagnosticPollTimer = window.setInterval(
        async () => {
            if (
                document.hidden
                || !diagnosticTaskId
                || diagnosticTaskId !== taskId
            ) {
                return;
            }

            try {
                const task = await loadDiagnosticTask(
                    taskId,
                );

                updateRuntimeFromTask(task);

                const status = normalizeTaskStatus(
                    readPath(
                        task,
                        ['status'],
                        'pendente',
                    ),
                );

                if (
                    FINAL_TASK_STATUSES.has(
                        status,
                    )
                ) {
                    await finishDiagnosticTask(
                        task,
                        onSuccess,
                    );
                }
            } catch (error) {
                console.error(
                    '[MoonShield] Falha no polling do diagnóstico:',
                    error,
                );
            }
        },
        DIAGNOSTIC_POLL_INTERVAL,
    );
}


function stopDiagnosticPolling() {
    if (diagnosticPollTimer) {
        window.clearInterval(
            diagnosticPollTimer,
        );
        diagnosticPollTimer = null;
    }
}


async function loadDiagnosticTask(taskId) {
    const detailUrl = sanitizeUrl(
        apiUrl('detalheTarefaTemplate'),
        taskId,
    );

    const payload = await fetchJSON(
        detailUrl,
        {
            timeout: 15000,
        },
    );

    const data = unwrapPayload(payload);

    const task = (
        readPath(data, ['tarefa'], null)
        || readPath(payload, ['tarefa'], null)
        || data
    );

    if (!task || typeof task !== 'object') {
        throw new Error(
            'Não foi possível ler o estado da tarefa de diagnóstico.',
        );
    }

    return task;
}


async function finishDiagnosticTask(
    task,
    onSuccess,
) {
    const status = normalizeTaskStatus(
        readPath(
            task,
            ['status'],
            'erro',
        ),
    );

    stopDiagnosticPolling();
    stopElapsedTimer();

    diagnosticTaskId = null;
    state.isRunningDiagnostic = false;

    const buttons = getDiagnosticButtons();

    buttons.forEach((item) => {
        setButtonLoading(item, false);
        item.disabled = false;
    });

    if (status === 'sucesso') {
        updateRuntime({
            title: 'Diagnóstico concluído',
            message: (
                'O worker finalizou o checkup. '
                + 'Carregando o resultado persistido...'
            ),
            progress: 100,
        });

        await loadPersistedDiagnostic({
            resumeRunningTask: false,
            silent: true,
        });

        window.setTimeout(
            () => setRuntimeVisible(false),
            700,
        );

        showToast(
            'Diagnóstico concluído e salvo.',
            'ok',
        );

        if (
            typeof onSuccess === 'function'
        ) {
            await onSuccess();
        }

        return;
    }

    setRuntimeVisible(false);

    if (status === 'cancelado') {
        applyChip(
            'diagnosticGeneralChip',
            'warning',
            'Cancelado',
        );

        showToast(
            'Diagnóstico cancelado.',
            'warning',
        );
    } else {
        applyChip(
            'diagnosticGeneralChip',
            'error',
            'Falhou',
        );

        const errorMessage = (
            readPath(task, ['erro'], '')
            || readPath(
                task,
                ['mensagem'],
                'O diagnóstico terminou com erro.',
            )
        );

        showToast(
            errorMessage,
            'error',
        );
    }

    // Mantém o último diagnóstico BOM visível,
    // mesmo que uma nova tentativa tenha falhado.
    await loadPersistedDiagnostic({
        resumeRunningTask: false,
        silent: true,
    });
}


// ============================================================================
// LEITURA DO ÚLTIMO RESULTADO PERSISTIDO
// ============================================================================

export async function loadPersistedDiagnostic(
    {
        resumeRunningTask = true,
        silent = false,
    } = {},
) {
    const payload = await fetchJSON(
        apiUrl('diagnostico'),
        {
            timeout: 15000,
        },
    );

    const data = safeObject(
        unwrapPayload(payload),
    );

    state.diagnosticData = data;

    const running = boolValue(
        readPath(
            data,
            ['em_andamento'],
            false,
        ),
    );

    const runningTask = safeObject(
        readPath(
            data,
            ['tarefa_em_andamento'],
            {},
        ),
    );

    if (
        running
        && resumeRunningTask
    ) {
        const taskId = getTaskId(
            runningTask,
        );

        if (taskId) {
            state.isRunningDiagnostic = true;
            diagnosticTaskId = taskId;

            getDiagnosticButtons().forEach(
                (button) => {
                    setButtonLoading(
                        button,
                        true,
                    );
                    button.disabled = true;
                },
            );

            setRuntimeVisible(true);
            updateRuntimeFromTask(
                runningTask,
            );

            const startedAt = (
                readPath(
                    runningTask,
                    ['iniciado_em'],
                    null,
                )
                || readPath(
                    runningTask,
                    ['criado_em'],
                    null,
                )
            );

            startElapsedTimer(
                startedAt,
            );

            startDiagnosticPolling(
                taskId,
                diagnosticOnSuccess,
            );
        }
    }

    const executed = boolValue(
        readPath(
            data,
            ['executado'],
            false,
        ),
    );

    if (executed) {
        renderDiagnostic(data);
        return data;
    }

    if (!running) {
        renderNeverExecuted();
    }

    if (!silent) {
        showToast(
            executed
                ? 'Último diagnóstico carregado.'
                : 'Nenhum diagnóstico salvo.',
            'info',
        );
    }

    return data;
}


// ============================================================================
// RENDERIZAÇÃO
// ============================================================================

export function renderDiagnostic(data) {
    const root = safeObject(data);

    const diagnostic = safeObject(
        readPath(
            root,
            ['diagnostico'],
            {},
        ),
    );

    const result = safeObject(
        readPath(
            diagnostic,
            ['resultado'],
            diagnostic,
        ),
    );

    const summary = safeObject(
        readPath(
            root,
            ['resumo'],
            readPath(
                diagnostic,
                ['resumo'],
                {},
            ),
        ),
    );

    const actions = safeArray(
        readPath(
            root,
            ['acoes_recomendadas', 'acoes'],
            readPath(
                diagnostic,
                ['acoes_recomendadas', 'acoes'],
                [],
            ),
        ),
    );

    const items = safeArray(
        readPath(
            result,
            ['itens', 'checks'],
            readPath(
                diagnostic,
                ['itens', 'checks'],
                [],
            ),
        ),
    );

    const total = numberValue(
        readPath(
            summary,
            ['total_checks', 'total'],
            items.length,
        ),
        items.length,
    );

    const ok = numberValue(
        readPath(
            summary,
            ['total_ok', 'total_saudaveis', 'ok'],
            items.filter(
                isCheckOk,
            ).length,
        ),
    );

    const warnings = numberValue(
        readPath(
            summary,
            ['total_avisos', 'avisos'],
            items.filter(
                isCheckWarning,
            ).length,
        ),
    );

    const critical = numberValue(
        readPath(
            summary,
            ['total_criticos', 'falhas_criticas'],
            items.filter(
                isCheckCriticalFailure,
            ).length,
        ),
    );

    setText(
        'diagnosticTotal',
        total,
    );
    setText(
        'diagnosticOk',
        ok,
    );
    setText(
        'diagnosticWarnings',
        warnings,
    );
    setText(
        'diagnosticCritical',
        critical,
    );

    const ready = boolValue(
        readPath(
            summary,
            ['pronto'],
            critical === 0 && total > 0,
        ),
    );

    const status = (
        ready
            ? (
                warnings > 0
                    ? 'warning'
                    : 'ok'
            )
            : 'error'
    );

    applyChip(
        'diagnosticGeneralChip',
        status,
        ready
            ? (
                warnings > 0
                    ? 'Com avisos'
                    : 'Saudável'
            )
            : 'Crítico',
    );

    renderDiagnosticGroups(
        items,
    );

    renderRecommendedActions(
        actions,
    );

    renderDiagnosticMeta(
        root,
        summary,
    );

    setDiagnosticButtonLabel(
        'Executar novo diagnóstico',
    );

    const executedAt = (
        readPath(
            root,
            ['executado_em'],
            null,
        )
        || readPath(
            summary,
            ['executado_em'],
            null,
        )
    );

    if ($('healthLastDiagnostic')) {
        setText(
            'healthLastDiagnostic',
            executedAt
                ? `Último diagnóstico: ${formatDate(executedAt)}`
                : 'Último diagnóstico disponível',
        );
    }
}


function renderDiagnosticMeta(
    root,
    summary,
) {
    const meta = $('diagnosticMeta');

    if (!meta) {
        return;
    }

    const executedAt = (
        readPath(
            root,
            ['executado_em'],
            null,
        )
        || readPath(
            summary,
            ['executado_em'],
            null,
        )
    );

    const duration = numberValue(
        readPath(
            root,
            ['duracao_segundos'],
            readPath(
                summary,
                ['duracao_segundos'],
                0,
            ),
        ),
        0,
    );

    const source = textValue(
        readPath(
            root,
            ['fonte'],
            'tarefa',
        ),
        'tarefa',
    );

    setText(
        'diagnosticLastRun',
        executedAt
            ? formatDate(executedAt)
            : '—',
    );

    setText(
        'diagnosticDuration',
        duration > 0
            ? formatDuration(duration)
            : '—',
    );

    setText(
        'diagnosticSource',
        source === 'configuracao'
            ? 'Snapshot da configuração'
            : source === 'tarefa'
                ? 'Histórico de tarefas'
                : 'Persistência local',
    );

    meta.hidden = false;
}


function renderNeverExecuted() {
    setText(
        'diagnosticTotal',
        0,
    );
    setText(
        'diagnosticOk',
        0,
    );
    setText(
        'diagnosticWarnings',
        0,
    );
    setText(
        'diagnosticCritical',
        0,
    );

    applyChip(
        'diagnosticGeneralChip',
        'pending',
        'Não executado',
    );

    setDiagnosticButtonLabel(
        'Executar diagnóstico',
    );

    const meta = $('diagnosticMeta');

    if (meta) {
        meta.hidden = true;
    }

    const groups = $('diagnosticGroups');

    if (groups) {
        groups.innerHTML = `
            <div class="sp-empty-state">
                <span class="sp-empty-state__icon">
                    ${iconSVG('pulse', 22)}
                </span>

                <div>
                    <strong>Diagnóstico ainda não executado</strong>
                    <span>
                        Inicie uma análise para visualizar os checks técnicos.
                    </span>
                </div>
            </div>
        `;
    }

    const actions = $('recommendedActions');

    if (actions) {
        actions.innerHTML = `
            <div class="sp-empty-state sp-empty-state--compact">
                <span class="sp-empty-state__icon">
                    ${iconSVG('check', 20)}
                </span>

                <div>
                    <strong>Sem recomendações</strong>
                    <span>
                        Execute o diagnóstico para gerar ações.
                    </span>
                </div>
            </div>
        `;
    }
}


export function isCheckOk(item) {
    return boolValue(
        readPath(
            item,
            ['sucesso', 'ok'],
            false,
        ),
    );
}


export function isCheckWarning(item) {
    return (
        !isCheckOk(item)
        && !boolValue(
            readPath(
                item,
                ['critico'],
                false,
            ),
        )
    );
}


export function isCheckCriticalFailure(item) {
    return (
        !isCheckOk(item)
        && boolValue(
            readPath(
                item,
                ['critico'],
                false,
            ),
        )
    );
}


export function renderDiagnosticGroups(
    items,
) {
    const container = $(
        'diagnosticGroups',
    );

    if (!container) {
        return;
    }

    container.innerHTML = '';

    if (!items.length) {
        container.innerHTML = `
            <div class="sp-empty-state">
                <span class="sp-empty-state__icon">
                    ${iconSVG('pulse', 22)}
                </span>

                <div>
                    <strong>Nenhum check retornado</strong>
                    <span>
                        O diagnóstico foi salvo, mas não retornou itens detalhados.
                    </span>
                </div>
            </div>
        `;

        return;
    }

    const groups = new Map();

    for (const item of items) {
        const group = textValue(
            readPath(
                item,
                ['grupo'],
                'Outros',
            ),
            'Outros',
        );

        if (!groups.has(group)) {
            groups.set(
                group,
                [],
            );
        }

        groups.get(group).push(
            item,
        );
    }

    for (
        const [groupName, checks]
        of groups.entries()
    ) {
        const groupElement = (
            document.createElement(
                'div',
            )
        );

        groupElement.className = (
            'sp-diagnostic-group'
        );

        const failures = checks.filter(
            (item) => !isCheckOk(item),
        ).length;

        const groupStatus = (
            checks.some(
                isCheckCriticalFailure,
            )
                ? 'error'
                : failures > 0
                    ? 'warning'
                    : 'ok'
        );

        groupElement.innerHTML = `
            <div class="sp-diagnostic-group__head">
                <div>
                    <span class="sp-status-dot sp-status-dot--${groupStatus}"></span>
                    <strong>${escapeHTML(groupName)}</strong>
                </div>

                <span class="sp-status-pill sp-status-pill--${groupStatus}">
                    ${checks.length - failures}/${checks.length}
                </span>
            </div>

            <div class="sp-diagnostic-group__body"></div>
        `;

        const body = groupElement.querySelector(
            '.sp-diagnostic-group__body',
        );

        for (const check of checks) {
            const checkStatus = (
                isCheckOk(check)
                    ? 'ok'
                    : boolValue(
                        readPath(
                            check,
                            ['critico'],
                            false,
                        ),
                    )
                        ? 'error'
                        : 'warning'
            );

            const element = (
                document.createElement(
                    'div',
                )
            );

            element.className = (
                `sp-diagnostic-check sp-diagnostic-check--${checkStatus}`
            );

            element.innerHTML = `
                <span class="sp-diagnostic-check__dot"></span>

                <span class="sp-diagnostic-check__copy">
                    <strong>
                        ${escapeHTML(
                            readPath(
                                check,
                                ['titulo', 'nome', 'id'],
                                'Check',
                            ),
                        )}
                    </strong>

                    <span>
                        ${escapeHTML(
                            readPath(
                                check,
                                ['mensagem', 'detalhe'],
                                statusLabel(checkStatus),
                            ),
                        )}
                    </span>
                </span>

                <span class="sp-status-pill sp-status-pill--${checkStatus}">
                    ${statusLabel(checkStatus)}
                </span>
            `;

            body?.appendChild(
                element,
            );
        }

        container.appendChild(
            groupElement,
        );
    }
}


export function renderRecommendedActions(
    actions,
) {
    const container = $(
        'recommendedActions',
    );

    if (!container) {
        return;
    }

    container.innerHTML = '';

    if (!actions.length) {
        container.innerHTML = `
            <div class="sp-empty-state sp-empty-state--compact">
                <span class="sp-empty-state__icon">
                    ${iconSVG('check', 20)}
                </span>

                <div>
                    <strong>Nenhuma ação necessária</strong>
                    <span>
                        Não foram encontradas recomendações pendentes.
                    </span>
                </div>
            </div>
        `;

        return;
    }

    for (const action of actions) {
        const element = (
            document.createElement(
                'div',
            )
        );

        element.className = (
            'sp-recommended-action'
        );

        element.innerHTML = `
            <span class="sp-recommended-action__priority">
                ${escapeHTML(
                    readPath(
                        action,
                        ['prioridade'],
                        '•',
                    ),
                )}
            </span>

            <span class="sp-recommended-action__copy">
                <strong>
                    ${escapeHTML(
                        readPath(
                            action,
                            ['titulo', 'grupo'],
                            'Ação recomendada',
                        ),
                    )}
                </strong>

                <span>
                    ${escapeHTML(
                        readPath(
                            action,
                            ['acao', 'mensagem'],
                            'Revise este item.',
                        ),
                    )}
                </span>
            </span>
        `;

        container.appendChild(
            element,
        );
    }
}


// ============================================================================
// FEEDBACK VISUAL DE OPERAÇÃO LONGA
// ============================================================================

function updateRuntimeFromTask(task) {
    const progress = Math.max(
        0,
        Math.min(
            100,
            numberValue(
                readPath(
                    task,
                    ['progresso'],
                    0,
                ),
                0,
            ),
        ),
    );

    const status = normalizeTaskStatus(
        readPath(
            task,
            ['status'],
            'pendente',
        ),
    );

    const stage = textValue(
        readPath(
            task,
            ['etapa_atual'],
            'Preparando',
        ),
        'Preparando',
    );

    const message = textValue(
        readPath(
            task,
            ['mensagem'],
            (
                'O diagnóstico está em execução. '
                + 'Aguarde a conclusão das verificações.'
            ),
        ),
        'Aguarde a conclusão das verificações.',
    );

    const startedAt = (
        readPath(
            task,
            ['iniciado_em'],
            null,
        )
        || readPath(
            task,
            ['criado_em'],
            null,
        )
    );

    if (
        !diagnosticStartedAt
        && startedAt
    ) {
        startElapsedTimer(
            startedAt,
        );
    }

    setRuntimeVisible(
        RUNNING_TASK_STATUSES.has(
            status,
        ),
    );

    updateRuntime({
        title: formatDiagnosticStage(
            stage,
        ),
        message: (
            `${message} `
            + runtimeHint(
                progress,
            )
        ),
        progress,
    });

    applyChip(
        'diagnosticGeneralChip',
        RUNNING_TASK_STATUSES.has(status)
            ? 'pending'
            : status === 'sucesso'
                ? 'ok'
                : 'error',
        RUNNING_TASK_STATUSES.has(status)
            ? `${progress}%`
            : statusLabel(status),
    );
}


function updateRuntime({
    title,
    message,
    progress,
}) {
    setText(
        'diagnosticRuntimeTitle',
        title,
    );

    setText(
        'diagnosticRuntimeMessage',
        message,
    );

    const bar = $(
        'diagnosticProgressBar',
    );

    if (bar) {
        const safeProgress = Math.max(
            0,
            Math.min(
                100,
                numberValue(
                    progress,
                    0,
                ),
            ),
        );

        bar.style.width = (
            `${safeProgress}%`
        );
    }
}


function setRuntimeVisible(visible) {
    const runtime = $(
        'diagnosticRuntime',
    );

    if (runtime) {
        runtime.hidden = !visible;
    }
}


function runtimeHint(progress) {
    if (progress >= 90) {
        return 'Consolidando o relatório final.';
    }

    if (progress >= 50) {
        return (
            'Algumas verificações profundas podem demorar um pouco.'
        );
    }

    return (
        'A validação de configuração e regras pode levar entre 40 e 90 segundos.'
    );
}


function formatDiagnosticStage(stage) {
    const value = String(
        stage || '',
    )
        .replaceAll('_', ' ')
        .trim();

    if (!value) {
        return 'Executando diagnóstico';
    }

    return (
        value.charAt(0).toUpperCase()
        + value.slice(1)
    );
}


// ============================================================================
// CRONÔMETRO
// ============================================================================

function startElapsedTimer(
    startedAt = null,
) {
    stopElapsedTimer();

    const parsed = startedAt
        ? new Date(startedAt)
        : null;

    diagnosticStartedAt = (
        parsed
        && !Number.isNaN(
            parsed.getTime(),
        )
    )
        ? parsed.getTime()
        : Date.now();

    renderElapsed();

    diagnosticElapsedTimer = (
        window.setInterval(
            renderElapsed,
            1000,
        )
    );
}


function stopElapsedTimer() {
    if (diagnosticElapsedTimer) {
        window.clearInterval(
            diagnosticElapsedTimer,
        );

        diagnosticElapsedTimer = null;
    }

    diagnosticStartedAt = null;
}


function renderElapsed() {
    if (!diagnosticStartedAt) {
        setText(
            'diagnosticElapsed',
            '00:00',
        );

        return;
    }

    const elapsedSeconds = Math.max(
        0,
        Math.floor(
            (
                Date.now()
                - diagnosticStartedAt
            )
            / 1000,
        ),
    );

    const minutes = Math.floor(
        elapsedSeconds / 60,
    );

    const seconds = (
        elapsedSeconds % 60
    );

    setText(
        'diagnosticElapsed',
        `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`,
    );
}


// ============================================================================
// HELPERS
// ============================================================================

function getDiagnosticButtons() {
    return [
        $('btnRunDiagnosticTop'),
        $('btnRunDiagnosticHero'),
        $('btnRunDiagnostic'),
    ].filter(Boolean);
}


function getTaskId(task) {
    return textValue(
        readPath(
            task,
            ['id', 'pk', 'tarefa_id'],
            '',
        ),
        '',
    );
}


function normalizeTaskStatus(value) {
    return String(
        value || 'pendente',
    )
        .trim()
        .toLowerCase();
}


function setDiagnosticButtonLabel(label) {
    const explicitLabel = $(
        'diagnosticButtonLabel',
    );

    if (explicitLabel) {
        explicitLabel.textContent = label;
    }
}


function cleanupDiagnostic() {
    stopDiagnosticPolling();
    stopElapsedTimer();
}
