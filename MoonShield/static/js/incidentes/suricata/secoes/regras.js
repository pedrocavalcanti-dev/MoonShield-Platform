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
   INIT
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
                title: 'Atualizar todas as regras?',
                text: 'O MoonShield atualizará ET Open e reaplicará as regras MoonShield.',
                details: 'A operação pode levar alguns minutos e será acompanhada pelo worker do Suricata.',
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
                title: 'Reaplicar MoonShield Rules?',
                text: 'As regras locais serão copiadas novamente, verificadas e validadas.',
                details: 'Use esta opção quando quiser garantir que o pacote MoonShield está sincronizado com o Suricata.',
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
                title: 'Atualizar ET Open?',
                text: 'O suricata-update será executado para buscar as assinaturas comunitárias mais recentes.',
                details: 'Ao final, o MoonShield valida novamente a configuração.',
            });
        },
    );

    $('btnValidateRules')?.addEventListener(
        'click',
        () => {
            onConfirmTask({
                tipo: 'validacao',
                parametros: {},
                title: 'Validar configuração?',
                text: 'O MoonShield executará o suricata -T para confirmar se o YAML e todas as referências de regras podem ser carregados.',
                details: 'A validação costuma levar cerca de 40–60 segundos.',
            });
        },
    );

    $('btnToggleValidationOutput')?.addEventListener(
        'click',
        () => {
            const output = $('rulesValidationOutput');

            if (!output) {
                return;
            }

            const hidden = output.hidden;

            setHidden(
                'rulesValidationOutput',
                !hidden,
            );

            setText(
                'btnToggleValidationOutputLabel',
                hidden
                    ? 'Ocultar detalhes técnicos'
                    : 'Ver detalhes técnicos',
            );
        },
    );

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
   RENDER PRINCIPAL
   ========================================================================== */

export function renderRulesSection(
    suricata,
    stack,
) {
    const rules = safeObject(
        readPath(
            suricata,
            ['regras'],
            readPath(
                stack,
                ['regras'],
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
       MoonShield
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

    const moonHealthy = (
        moonInstalled
        && moonReferenced
    );

    applyPill(
        'rulesMoonStatus',
        moonHealthy
            ? 'ok'
            : moonInstalled
                ? 'warning'
                : 'error',
        moonHealthy
            ? 'Saudável'
            : moonInstalled
                ? 'Atenção'
                : 'Indisponível',
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

    setText(
        'rulesMoonSummary',
        moonHealthy
            ? 'Pacote instalado e carregado pelo Suricata.'
            : moonInstalled
                ? 'Pacote instalado, mas a referência no YAML precisa ser revisada.'
                : 'Pacote MoonShield não confirmado neste sensor.',
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

    const etReferenced = boolValue(
        readPath(
            et,
            [
                'referenciado',
                'referenciada',
            ],
            etInstalled,
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
                ['suricata_update_instalado'],
                false,
            ),
        ),
    );

    const etHealthy = (
        etInstalled
        && etReferenced
        && updaterInstalled
    );

    applyPill(
        'rulesEtStatus',
        etHealthy
            ? 'ok'
            : etInstalled
                ? 'warning'
                : 'error',
        etHealthy
            ? 'Saudável'
            : etInstalled
                ? 'Atenção'
                : 'Indisponível',
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
            ['mensagem'],
            etHealthy
                ? 'ET Open instalado, válido e referenciado pelo Suricata.'
                : etInstalled
                    ? 'ET Open encontrado, mas requer atenção.'
                    : 'ET Open não confirmado.',
        ),
    );


    /* ------------------------------------------------------------------
       Resumo
       ------------------------------------------------------------------ */

    renderRulesSummary({
        moonHealthy,
        etHealthy,
        moonInstalled,
        etInstalled,
        moonReferenced,
        etReferenced,
        updaterInstalled,
    });


    /* ------------------------------------------------------------------
       Validação
       ------------------------------------------------------------------ */

    if (
        Object.keys(
            validation,
        ).length
    ) {
        renderValidationData(
            validation,
        );
    } else if (!lastValidationTaskId) {
        renderValidationChecking();
    }

    refreshLatestValidationTask({
        startPollingIfRunning: true,
    }).catch(
        () => {},
    );
}


/* ==========================================================================
   RESUMO DA TELA
   ========================================================================== */

function renderRulesSummary({
    moonHealthy,
    etHealthy,
    moonInstalled,
    etInstalled,
    moonReferenced,
    etReferenced,
    updaterInstalled,
}) {
    const healthyCount = [
        moonHealthy,
        etHealthy,
    ].filter(Boolean).length;

    let tone = 'warning';
    let title = 'Regras precisam de atenção';
    let text = 'Há componentes do mecanismo de detecção que ainda precisam ser revisados.';

    if (
        moonHealthy
        && etHealthy
    ) {
        tone = 'ok';
        title = 'Mecanismos de detecção prontos';
        text = 'MoonShield Rules e ET Open estão disponíveis e referenciados pelo Suricata.';
    } else if (
        !moonInstalled
        && !etInstalled
    ) {
        tone = 'error';
        title = 'Regras indisponíveis';
        text = 'Nenhum dos conjuntos de regras principais foi confirmado neste sensor.';
    }

    applyChip(
        'rulesOverviewChip',
        tone,
        tone === 'ok'
            ? 'Operacional'
            : tone === 'error'
                ? 'Crítico'
                : 'Atenção',
    );

    setText(
        'rulesOverviewTitle',
        title,
    );

    setText(
        'rulesOverviewText',
        text,
    );

    setText(
        'rulesOverviewHealthyCount',
        `${healthyCount}/2`,
    );

    setText(
        'rulesOverviewMoonValue',
        moonHealthy
            ? 'Pronta'
            : moonInstalled
                ? 'Revisar'
                : 'Ausente',
    );

    setText(
        'rulesOverviewEtValue',
        etHealthy
            ? 'Pronta'
            : etInstalled
                ? 'Revisar'
                : 'Ausente',
    );

    setText(
        'rulesOverviewEngineValue',
        (
            moonReferenced
            && etReferenced
            && updaterInstalled
        )
            ? 'Sincronizada'
            : 'Revisar',
    );
}


/* ==========================================================================
   BUSCA DA ÚLTIMA VALIDAÇÃO
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


async function fetchLatestValidationTask() {
    const params = new URLSearchParams();

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
            ['tarefa'],
            data,
        ),
    );
}


/* ==========================================================================
   POLLING
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

                lastValidationTaskId = (
                    getTaskId(
                        task,
                    )
                    || taskId
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
   VALIDAÇÃO — ESTADOS
   ========================================================================== */

function renderValidationChecking() {
    applyChip(
        'rulesValidationChip',
        'pending',
        'Consultando',
    );

    setValidationIcon(
        'checking',
    );

    setText(
        'rulesValidationTitle',
        'Verificando a última validação',
    );

    setText(
        'rulesValidationText',
        'Consultando o histórico para mostrar o último resultado confirmado do Suricata.',
    );

    setText(
        'rulesValidationGuidance',
        'Aguarde alguns instantes.',
    );

    setHidden(
        'rulesValidationMeta',
        true,
    );

    setHidden(
        'rulesValidationActions',
        true,
    );

    setHidden(
        'rulesValidationOutput',
        true,
    );
}


function renderValidationPending() {
    applyChip(
        'rulesValidationChip',
        'pending',
        'Não validada',
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
        'Ainda não existe um resultado salvo do suricata -T para esta configuração.',
    );

    setText(
        'rulesValidationGuidance',
        'Execute a validação antes de considerar o conjunto de regras pronto para produção.',
    );

    setHidden(
        'rulesValidationMeta',
        true,
    );

    setHidden(
        'rulesValidationActions',
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
            ? `${progress}%`
            : 'Em andamento',
    );

    setValidationIcon(
        'running',
    );

    setText(
        'rulesValidationTitle',
        'Validando a configuração',
    );

    setText(
        'rulesValidationText',
        task.mensagem
        || task.etapa_atual
        || task.etapa
        || 'O Suricata está carregando o YAML e as assinaturas configuradas.',
    );

    setText(
        'rulesValidationGuidance',
        'Aguarde a conclusão. Esta etapa costuma levar cerca de 40–60 segundos.',
    );

    setValidationMeta(
        task,
    );

    setHidden(
        'rulesValidationActions',
        true,
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
                ['sucesso'],
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
            ['status'],
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
        'Aprovada',
    );

    setValidationIcon(
        'ok',
    );

    setText(
        'rulesValidationTitle',
        'Configuração pronta para carregar',
    );

    setText(
        'rulesValidationText',
        'O Suricata aceitou o YAML e todas as referências de regras sem erros.',
    );

    setText(
        'rulesValidationGuidance',
        'Nenhuma ação é necessária neste momento.',
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

    setHidden(
        'rulesValidationActions',
        false,
    );
}


function renderValidationFailure(
    validation,
    task = {},
) {
    const cancelled = (
        normalizeTaskStatus(
            task?.status
            || task?.estado,
        ) === 'cancelado'
    );

    applyChip(
        'rulesValidationChip',
        cancelled
            ? 'warning'
            : 'error',
        cancelled
            ? 'Cancelada'
            : 'Reprovada',
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
            : 'Configuração precisa de correção',
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
                    ? 'A operação foi cancelada antes da conclusão.'
                    : 'O Suricata encontrou um problema ao carregar a configuração.'
            ),
        ),
    );

    setText(
        'rulesValidationGuidance',
        cancelled
            ? 'Execute novamente quando quiser concluir a verificação.'
            : 'Revise a saída técnica abaixo, corrija o problema e execute a validação novamente.',
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

    setHidden(
        'rulesValidationActions',
        false,
    );
}


/* ==========================================================================
   VALIDAÇÃO — UI
   ========================================================================== */

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

    if (
        status === 'running'
        || status === 'checking'
    ) {
        icon.innerHTML = (
            '<span class="sp-spinner" aria-hidden="true"></span>'
        );

        return;
    }

    if (status === 'ok') {
        icon.innerHTML = iconSVG(
            'check',
            24,
        );

        return;
    }

    if (status === 'error') {
        icon.innerHTML = `
            <svg
                width="24"
                height="24"
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
                width="24"
                height="24"
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

    icon.innerHTML = `
        <svg
            width="24"
            height="24"
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

    const taskId = (
        getTaskId(
            source,
        )
        || lastValidationTaskId
    );

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
    const hasOutput = Boolean(
        output,
    );

    setHidden(
        'btnToggleValidationOutput',
        !hasOutput,
    );

    if (!hasOutput) {
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

    /*
     * Detalhe técnico fica recolhido por padrão.
     * O usuário comum vê primeiro a conclusão em linguagem simples.
     */
    setHidden(
        'rulesValidationOutput',
        true,
    );

    setText(
        'btnToggleValidationOutputLabel',
        'Ver detalhes técnicos',
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
   EXTRAÇÃO / HELPERS
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
