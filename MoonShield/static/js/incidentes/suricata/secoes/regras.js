import {
    safeObject,
    safeArray,
    readPath,
    boolValue,
    formatBoolean,
    formatDate,
    textValue,
    numberValue,
} from '../nucleo/utilitarios.js';

import {
    setText,
    setHidden,
    $,
} from '../nucleo/dom.js';

import {
    applyPill,
    applyChip,
    iconSVG,
} from '../nucleo/interface.js';

import {
    fetchJSON,
    unwrapPayload,
    apiUrl,
} from '../nucleo/api.js';


const FINAL_VALIDATION_STATUSES = new Set([
    'sucesso',
    'erro',
    'cancelado',
    'ignorado',
]);

const RUNNING_VALIDATION_STATUSES = new Set([
    'pendente',
    'executando',
]);

const VALIDATION_POLL_INTERVAL = 1800;

let validationPollTimer = null;
let validationPollInFlight = false;
let lastValidationTaskId = null;


/* ==========================================================================
   INICIALIZAÇÃO
   ========================================================================== */

export function initRegras(onConfirmTask) {
    $('btnUpdateAllRules')?.addEventListener(
        'click',
        () => {
            onConfirmTask({
                tipo: 'atualizacao_regras',

                parametros: {
                    atualizar_et: true,
                    atualizar_moonshield: true,
                    validar_depois: true,
                    reiniciar_depois: false,
                },

                title:
                    'Atualizar todas as regras?',

                text:
                    'O MoonShield atualizará ET Open e reaplicará as regras MoonShield.',

                details:
                    'A operação pode levar alguns minutos e exige execução pelo worker do Suricata.',
            });
        },
    );

    $('btnUpdateMoonRules')?.addEventListener(
        'click',
        () => {
            onConfirmTask({
                tipo: 'atualizacao_regras',

                parametros: {
                    atualizar_et: false,
                    atualizar_moonshield: true,
                    validar_depois: true,
                    reiniciar_depois: false,
                },

                title:
                    'Reaplicar regras MoonShield?',

                text:
                    'As regras locais do MoonShield serão copiadas novamente e validadas.',
            });
        },
    );

    $('btnUpdateEtRules')?.addEventListener(
        'click',
        () => {
            onConfirmTask({
                tipo: 'atualizacao_regras',

                parametros: {
                    atualizar_et: true,
                    atualizar_moonshield: false,
                    validar_depois: true,
                    reiniciar_depois: false,
                },

                title:
                    'Atualizar ET Open?',

                text:
                    'O suricata-update será executado para atualizar as assinaturas comunitárias.',
            });
        },
    );

    $('btnValidateRules')?.addEventListener(
        'click',
        () => {
            /*
             * Feedback imediato:
             * não deixa mais o card parecer "pendente" enquanto a tarefa
             * está sendo criada/executada.
             */
            renderValidationRunning({
                status: 'pendente',
                progresso: 0,
                etapa_atual: 'Aguardando worker',
                mensagem: 'Criando tarefa de validação do Suricata...',
            });

            onConfirmTask({
                tipo: 'validacao',
                parametros: {},

                title:
                    'Validar configuração?',

                text:
                    'O MoonShield verificará o YAML e executará o suricata -T.',

                details:
                    'A validação costuma levar cerca de 40–60 segundos.',
            });

            /*
             * O modal ainda precisa ser confirmado pelo usuário.
             * Depois da confirmação, a tarefa aparecerá na API.
             */
            window.setTimeout(
                () => {
                    refreshLatestValidationTask({
                        startPollingIfRunning: true,
                    }).catch(
                        (error) => {
                            console.debug(
                                '[MoonShield] Validação ainda não disponível após confirmação:',
                                error,
                            );
                        },
                    );
                },
                1200,
            );
        },
    );

    /*
     * Busca a última validação real já executada.
     *
     * Isso resolve o problema do card permanecer em:
     * "Validação ainda não executada"
     * mesmo quando uma tarefa de validação já terminou com sucesso.
     */
    refreshLatestValidationTask({
        startPollingIfRunning: true,
    }).catch(
        (error) => {
            console.debug(
                '[MoonShield] Não foi possível recuperar a última validação:',
                error,
            );
        },
    );

    window.addEventListener(
        'beforeunload',
        stopValidationPolling,
        {
            once: true,
        },
    );
}


/* ==========================================================================
   RENDERIZAÇÃO GERAL DA SEÇÃO
   ========================================================================== */

export function renderRulesSection(
    suricata,
    stack,
) {
    const rules = safeObject(
        readPath(
            suricata,
            [
                'regras',
            ],
            readPath(
                stack,
                [
                    'regras',
                ],
                {},
            ),
        ),
    );

    const moon = safeObject(
        readPath(
            rules,
            [
                'moonshield',
                'regras_moonshield',
            ],
            {},
        ),
    );

    const et = safeObject(
        readPath(
            rules,
            [
                'et_open',
                'etopen',
            ],
            {},
        ),
    );

    const updater = safeObject(
        readPath(
            rules,
            [
                'suricata_update',
                'updater',
            ],
            {},
        ),
    );

    const validation = resolveValidationFromStatus(
        suricata,
        stack,
    );


    /* ------------------------------------------------------------------
       MoonShield Rules
       ------------------------------------------------------------------ */

    const moonInstalled = boolValue(
        readPath(
            moon,
            [
                'instaladas',
                'instalada',
                'instalado',
            ],
            false,
        ),
    );

    const moonReferenced = boolValue(
        readPath(
            moon,
            [
                'referenciadas',
                'referenciada',
                'referenciado',
            ],
            false,
        ),
    );

    applyPill(
        'rulesMoonStatus',
        moonInstalled && moonReferenced
            ? 'ok'
            : moonInstalled
                ? 'warning'
                : 'error',
    );

    setText(
        'rulesMoonFile',
        readPath(
            moon,
            [
                'arquivo',
                'caminho',
            ],
            '—',
        ),
    );

    setText(
        'rulesMoonInstalled',
        formatBoolean(
            moonInstalled,
        ),
    );

    setText(
        'rulesMoonReferenced',
        formatBoolean(
            moonReferenced,
        ),
    );

    setText(
        'rulesMoonCount',
        readPath(
            moon,
            [
                'total',
                'quantidade_regras',
                'quantidade',
            ],
            '—',
        ),
    );


    /* ------------------------------------------------------------------
       ET Open
       ------------------------------------------------------------------ */

    const etInstalled = boolValue(
        readPath(
            et,
            [
                'instalado',
                'instalada',
            ],
            false,
        ),
    );

    const updaterInstalled = boolValue(
        readPath(
            updater,
            [
                'instalado',
                'disponivel',
            ],
            readPath(
                rules,
                [
                    'suricata_update_instalado',
                ],
                false,
            ),
        ),
    );

    applyPill(
        'rulesEtStatus',
        etInstalled
            ? 'ok'
            : 'warning',
    );

    setText(
        'rulesUpdaterInstalled',
        formatBoolean(
            updaterInstalled,
        ),
    );

    setText(
        'rulesEtInstalled',
        formatBoolean(
            etInstalled,
        ),
    );

    setText(
        'rulesEtUpdatedAt',
        safeFormatDate(
            readPath(
                et,
                [
                    'atualizado_em',
                    'ultima_atualizacao',
                ],
                null,
            ),
        ),
    );

    setText(
        'rulesEtSummary',
        readPath(
            et,
            [
                'mensagem',
            ],
            etInstalled
                ? 'Disponível'
                : 'Não confirmado',
        ),
    );


    /* ------------------------------------------------------------------
       Validação
       ------------------------------------------------------------------ */

    /*
     * Se o endpoint de status já passar uma validação persistida,
     * usamos imediatamente.
     *
     * Caso contrário, NÃO sobrescrevemos uma validação de tarefa que
     * já tenha sido recuperada pela API de tarefas.
     */
    if (
        Object.keys(
            validation,
        ).length
    ) {
        renderValidationData(
            validation,
        );
    } else if (!lastValidationTaskId) {
        renderValidationPending();
    }

    /*
     * A API de tarefas é a fonte de verdade complementar para a última
     * execução manual de suricata -T.
     */
    refreshLatestValidationTask({
        startPollingIfRunning: true,
    }).catch(
        () => {},
    );
}


/* ==========================================================================
   RECUPERAÇÃO DA ÚLTIMA TAREFA DE VALIDAÇÃO
   ========================================================================== */

async function refreshLatestValidationTask({
    startPollingIfRunning = false,
} = {}) {
    const task = await fetchLatestValidationTask();

    if (!task) {
        if (!lastValidationTaskId) {
            renderValidationPending();
        }

        return null;
    }

    lastValidationTaskId = getTaskId(
        task,
    );

    const status = normalizeTaskStatus(
        task.status
        || task.estado,
    );

    if (
        RUNNING_VALIDATION_STATUSES.has(
            status,
        )
    ) {
        renderValidationRunning(
            task,
        );

        if (startPollingIfRunning) {
            startValidationPolling(
                lastValidationTaskId,
            );
        }

        return task;
    }

    stopValidationPolling();

    if (status === 'sucesso') {
        const detailedTask = lastValidationTaskId
            ? await fetchValidationTaskDetail(
                lastValidationTaskId,
            ).catch(
                () => task,
            )
            : task;

        renderValidationFromTask(
            detailedTask,
        );

        return detailedTask;
    }

    renderValidationFromTask(
        task,
    );

    return task;
}


async function fetchLatestValidationTask() {
    const params = new URLSearchParams();

    /*
     * O backend atual aceita "tipo" e paginação por limite/offset.
     * Mandamos as duas convenções de limite para manter compatibilidade
     * com versões anteriores do endpoint.
     */
    params.set(
        'tipo',
        'validacao',
    );

    params.set(
        'limite',
        '10',
    );

    params.set(
        'limit',
        '10',
    );

    params.set(
        'offset',
        '0',
    );

    params.set(
        'page',
        '1',
    );

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
    )
        .filter(
            (task) =>
                String(
                    task?.tipo || '',
                ).toLowerCase() === 'validacao',
        )
        .sort(
            (a, b) =>
                taskDateValue(
                    b,
                )
                - taskDateValue(
                    a,
                ),
        );

    return (
        tasks[0]
        || null
    );
}


async function fetchValidationTaskDetail(
    taskId,
) {
    if (!taskId) {
        return null;
    }

    const url = replaceTaskId(
        apiUrl(
            'detalheTarefaTemplate',
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


/* ==========================================================================
   POLLING DA VALIDAÇÃO
   ========================================================================== */

function startValidationPolling(
    taskId,
) {
    stopValidationPolling();

    if (!taskId) {
        return;
    }

    validationPollTimer = window.setInterval(
        async () => {
            if (
                validationPollInFlight
                || document.hidden
            ) {
                return;
            }

            validationPollInFlight = true;

            try {
                const task = await fetchValidationTaskDetail(
                    taskId,
                );

                if (!task) {
                    return;
                }

                const status = normalizeTaskStatus(
                    task.status
                    || task.estado,
                );

                lastValidationTaskId = getTaskId(
                    task,
                ) || taskId;

                if (
                    RUNNING_VALIDATION_STATUSES.has(
                        status,
                    )
                ) {
                    renderValidationRunning(
                        task,
                    );

                    return;
                }

                stopValidationPolling();

                renderValidationFromTask(
                    task,
                );

            } catch (error) {
                console.debug(
                    '[MoonShield] Falha temporária no polling da validação:',
                    error,
                );
            } finally {
                validationPollInFlight = false;
            }
        },
        VALIDATION_POLL_INTERVAL,
    );
}


function stopValidationPolling() {
    if (validationPollTimer) {
        window.clearInterval(
            validationPollTimer,
        );

        validationPollTimer = null;
    }

    validationPollInFlight = false;
}


/* ==========================================================================
   RENDER DA VALIDAÇÃO
   ========================================================================== */

function renderValidationPending() {
    applyChip(
        'rulesValidationChip',
        'pending',
        'Pendente',
    );

    setValidationIcon(
        'pending',
    );

    setText(
        'rulesValidationTitle',
        'Validação ainda não executada',
    );

    setText(
        'rulesValidationText',
        'Execute uma validação para confirmar se o YAML e todas as referências de regras estão corretos.',
    );

    setHidden(
        'rulesValidationMeta',
        true,
    );

    setHidden(
        'rulesValidationOutput',
        true,
    );
}


function renderValidationRunning(
    task = {},
) {
    const progress = clampProgress(
        task.progresso
        ?? 0,
    );

    applyChip(
        'rulesValidationChip',
        'pending',
        progress > 0
            ? `Validando ${progress}%`
            : 'Validando',
    );

    setValidationIcon(
        'running',
    );

    setText(
        'rulesValidationTitle',
        'Validação em andamento',
    );

    setText(
        'rulesValidationText',
        task.mensagem
        || task.etapa_atual
        || task.etapa
        || 'O Suricata está carregando o YAML e as assinaturas configuradas.',
    );

    setValidationMeta(
        task,
    );

    setHidden(
        'rulesValidationOutput',
        true,
    );
}


function renderValidationFromTask(
    task,
) {
    const status = normalizeTaskStatus(
        task?.status
        || task?.estado,
    );

    if (
        RUNNING_VALIDATION_STATUSES.has(
            status,
        )
    ) {
        renderValidationRunning(
            task,
        );

        return;
    }

    const result = safeObject(
        task?.resultado
        || task?.result
        || {},
    );

    /*
     * A tarefa de validação que você mostrou retorna:
     *
     * resultado.dados.etapas.validar_suricata
     *
     * contendo sucesso, mensagem, dados.stdout, dados.stderr,
     * iniciado_em e finalizado_em.
     */
    const validation = safeObject(
        readPath(
            result,
            [
                'dados.etapas.validar_suricata',
                'etapas.validar_suricata',
                'validar_suricata',
            ],
            {},
        ),
    );

    const success = (
        status === 'sucesso'
        || boolValue(
            readPath(
                validation,
                [
                    'sucesso',
                ],
                false,
            ),
        )
    );

    if (success) {
        renderValidationSuccess(
            validation,
            task,
        );

        return;
    }

    renderValidationFailure(
        validation,
        task,
    );
}


function renderValidationData(
    validation,
) {
    const success = boolValue(
        readPath(
            validation,
            [
                'sucesso',
                'valido',
            ],
            false,
        ),
    );

    const status = normalizeTaskStatus(
        readPath(
            validation,
            [
                'status',
            ],
            success
                ? 'sucesso'
                : 'erro',
        ),
    );

    if (
        RUNNING_VALIDATION_STATUSES.has(
            status,
        )
    ) {
        renderValidationRunning(
            validation,
        );

        return;
    }

    if (success) {
        renderValidationSuccess(
            validation,
            validation,
        );

        return;
    }

    renderValidationFailure(
        validation,
        validation,
    );
}


function renderValidationSuccess(
    validation,
    task = {},
) {
    applyChip(
        'rulesValidationChip',
        'ok',
        'Válida',
    );

    setValidationIcon(
        'ok',
    );

    setText(
        'rulesValidationTitle',
        'Configuração validada',
    );

    setText(
        'rulesValidationText',
        readPath(
            validation,
            [
                'mensagem',
            ],
            task?.mensagem
            || 'O Suricata aceitou o YAML e todas as referências de regras.',
        ),
    );

    setValidationMeta(
        {
            ...task,
            ...validation,
        },
    );

    const output = extractValidationOutput(
        validation,
        task,
    );

    renderValidationOutput(
        output,
    );
}


function renderValidationFailure(
    validation,
    task = {},
) {
    const cancelled = normalizeTaskStatus(
        task?.status
        || task?.estado,
    ) === 'cancelado';

    applyChip(
        'rulesValidationChip',
        cancelled
            ? 'warning'
            : 'error',
        cancelled
            ? 'Cancelada'
            : 'Inválida',
    );

    setValidationIcon(
        cancelled
            ? 'warning'
            : 'error',
    );

    setText(
        'rulesValidationTitle',
        cancelled
            ? 'Validação cancelada'
            : 'Falha na validação',
    );

    setText(
        'rulesValidationText',
        readPath(
            validation,
            [
                'mensagem',
                'erro',
            ],
            task?.erro
            || task?.mensagem
            || (
                cancelled
                    ? 'A validação foi cancelada.'
                    : 'O Suricata não conseguiu validar a configuração.'
            ),
        ),
    );

    setValidationMeta(
        {
            ...task,
            ...validation,
        },
    );

    renderValidationOutput(
        extractValidationOutput(
            validation,
            task,
        ),
    );
}


function setValidationIcon(
    status,
) {
    const icon = $(
        'rulesValidationIcon',
    );

    if (!icon) {
        return;
    }

    icon.className = (
        `sp-validation-state__icon sp-validation-state__icon--${status}`
    );

    if (status === 'running') {
        icon.innerHTML = (
            '<span class="sp-spinner" aria-hidden="true"></span>'
        );

        return;
    }

    if (status === 'ok') {
        icon.innerHTML = iconSVG(
            'check',
            22,
        );

        return;
    }

    if (status === 'error') {
        icon.innerHTML = `
            <svg
                width="22"
                height="22"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                aria-hidden="true"
            >
                <circle cx="12" cy="12" r="9" />
                <path d="m9 9 6 6M15 9l-6 6" />
            </svg>
        `;

        return;
    }

    if (status === 'warning') {
        icon.innerHTML = `
            <svg
                width="22"
                height="22"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                aria-hidden="true"
            >
                <path d="M12 3 2.7 20h18.6L12 3Z" />
                <path d="M12 9v4M12 17h.01" />
            </svg>
        `;

        return;
    }

    /*
     * Pendente não gira.
     * O spinner é reservado exclusivamente para tarefa realmente ativa.
     */
    icon.innerHTML = `
        <svg
            width="22"
            height="22"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="1.8"
            aria-hidden="true"
        >
            <circle cx="12" cy="12" r="9" />
            <path d="M12 7v5l3 2" />
        </svg>
    `;
}


function setValidationMeta(
    source,
) {
    const startedAt = (
        source?.iniciado_em
        || source?.iniciada_em
        || source?.criado_em
        || source?.criada_em
        || null
    );

    const finishedAt = (
        source?.finalizado_em
        || source?.finalizada_em
        || null
    );

    const duration = numberValue(
        source?.duracao_segundos,
        0,
    );

    const taskId = getTaskId(
        source,
    ) || lastValidationTaskId;

    const hasAny = Boolean(
        startedAt
        || finishedAt
        || duration
        || taskId
    );

    setHidden(
        'rulesValidationMeta',
        !hasAny,
    );

    if (!hasAny) {
        return;
    }

    setText(
        'rulesValidationTaskId',
        taskId
            ? String(taskId)
            : '—',
    );

    setText(
        'rulesValidationStartedAt',
        safeFormatDate(
            startedAt,
        ),
    );

    setText(
        'rulesValidationFinishedAt',
        safeFormatDate(
            finishedAt,
        ),
    );

    setText(
        'rulesValidationDuration',
        duration
            ? `${Math.round(duration)}s`
            : '—',
    );
}


function renderValidationOutput(
    output,
) {
    if (!output) {
        setHidden(
            'rulesValidationOutput',
            true,
        );

        setText(
            'rulesValidationTextOutput',
            '',
        );

        return;
    }

    setHidden(
        'rulesValidationOutput',
        false,
    );

    setText(
        'rulesValidationTextOutput',
        typeof output === 'string'
            ? output
            : JSON.stringify(
                output,
                null,
                2,
            ),
    );
}


/* ==========================================================================
   EXTRAÇÃO DE RESULTADOS
   ========================================================================== */

function resolveValidationFromStatus(
    suricata,
    stack,
) {
    const candidates = [
        readPath(
            suricata,
            [
                'configuracao.validacao',
                'configuracao.validacao_suricata',
                'validacao',
                'validacao_suricata',
                'ultima_validacao',
                'ultima_validacao_suricata',
            ],
            null,
        ),

        readPath(
            stack,
            [
                'validacao',
                'validacao_suricata',
                'ultima_validacao',
                'ultima_validacao_suricata',
                'configuracao.validacao',
                'configuracao.validacao_suricata',
            ],
            null,
        ),
    ];

    for (const candidate of candidates) {
        if (
            candidate
            && typeof candidate === 'object'
            && Object.keys(
                candidate,
            ).length
        ) {
            return safeObject(
                candidate,
            );
        }
    }

    return {};
}


function extractValidationOutput(
    validation,
    task = {},
) {
    const validationData = safeObject(
        validation?.dados
        || {},
    );

    const stdout = textValue(
        validationData.stdout
        || validation.stdout
        || '',
        '',
    );

    const stderr = textValue(
        validationData.stderr
        || validation.stderr
        || '',
        '',
    );

    const genericOutput = (
        validationData.saida
        || validation.saida
        || validation.detalhes
        || ''
    );

    const parts = [];

    if (stdout) {
        parts.push(
            stdout,
        );
    }

    if (stderr) {
        parts.push(
            `STDERR:\n${stderr}`,
        );
    }

    if (
        !parts.length
        && genericOutput
    ) {
        parts.push(
            typeof genericOutput === 'string'
                ? genericOutput
                : JSON.stringify(
                    genericOutput,
                    null,
                    2,
                ),
        );
    }

    if (
        !parts.length
        && task?.erro
    ) {
        parts.push(
            String(
                task.erro,
            ),
        );
    }

    return parts.join(
        '\n\n',
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
    const raw = String(
        value || '',
    )
        .trim()
        .toLowerCase();

    if (
        raw === 'ok'
        || raw === 'concluido'
        || raw === 'concluida'
    ) {
        return 'sucesso';
    }

    if (
        raw === 'running'
        || raw === 'processando'
    ) {
        return 'executando';
    }

    if (
        raw === 'pending'
        || raw === 'aguardando'
    ) {
        return 'pendente';
    }

    if (
        raw === 'error'
        || raw === 'failed'
        || raw === 'falha'
    ) {
        return 'erro';
    }

    return raw;
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


function replaceTaskId(
    template,
    taskId,
) {
    return String(
        template || '',
    )
        .replace(
            '__ID__',
            encodeURIComponent(
                String(
                    taskId,
                ),
            ),
        );
}


function taskDateValue(
    task,
) {
    const value = (
        task?.finalizado_em
        || task?.finalizada_em
        || task?.iniciado_em
        || task?.iniciada_em
        || task?.criado_em
        || task?.criada_em
        || ''
    );

    const timestamp = new Date(
        value,
    ).getTime();

    return Number.isFinite(
        timestamp,
    )
        ? timestamp
        : 0;
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
        const date = new Date(
            value,
        );

        return Number.isFinite(
            date.getTime(),
        )
            ? date.toLocaleString(
                'pt-BR',
            )
            : '—';
    }
}
