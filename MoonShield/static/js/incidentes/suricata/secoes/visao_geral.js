import {
    applyStatusDot,
    applyChip,
    statusLabel,
    iconSVG,
    normalizeStatus,
} from '../nucleo/interface.js';

import {
    $,
    setText,
} from '../nucleo/dom.js';

import {
    TASK_LABELS,
    TASK_ICONS,
    state,
} from '../nucleo/estado.js';

import {
    safeObject,
    safeArray,
    readPath,
    boolValue,
    numberValue,
    textValue,
    formatRelativeTime,
    escapeHTML,
    capitalize,
} from '../nucleo/utilitarios.js';


/* ==========================================================================
   FUNDO / ESTRELAS
   ========================================================================== */

export function initStars() {
    const canvas = $('starsCanvas');

    if (!canvas) {
        return;
    }

    const context = canvas.getContext('2d');

    if (!context) {
        return;
    }

    let stars = [];
    let frameId = null;

    const resize = () => {
        const ratio = Math.min(
            window.devicePixelRatio || 1,
            2,
        );

        canvas.width = Math.floor(
            window.innerWidth * ratio,
        );

        canvas.height = Math.floor(
            window.innerHeight * ratio,
        );

        canvas.style.width = (
            `${window.innerWidth}px`
        );

        canvas.style.height = (
            `${window.innerHeight}px`
        );

        context.setTransform(
            ratio,
            0,
            0,
            ratio,
            0,
            0,
        );

        const count = Math.max(
            50,
            Math.floor(
                (
                    window.innerWidth
                    * window.innerHeight
                )
                / 8500,
            ),
        );

        stars = Array.from(
            {
                length: count,
            },
            () => ({
                x: (
                    Math.random()
                    * window.innerWidth
                ),
                y: (
                    Math.random()
                    * window.innerHeight
                ),
                radius: (
                    Math.random()
                    * 1.05
                    + 0.15
                ),
                alpha: (
                    Math.random()
                    * 0.55
                    + 0.12
                ),
                speed: (
                    Math.random()
                    * 0.0025
                    + 0.001
                ),
                phase: (
                    Math.random()
                    * Math.PI
                    * 2
                ),
            }),
        );
    };

    const draw = (timestamp) => {
        context.clearRect(
            0,
            0,
            window.innerWidth,
            window.innerHeight,
        );

        for (const star of stars) {
            const alpha = (
                star.alpha
                * (
                    0.55
                    + 0.45
                    * Math.sin(
                        star.phase
                        + timestamp
                        * star.speed,
                    )
                )
            );

            context.beginPath();

            context.arc(
                star.x,
                star.y,
                star.radius,
                0,
                Math.PI * 2,
            );

            context.fillStyle = (
                `rgba(190, 213, 255, ${Math.max(0.05, alpha)})`
            );

            context.fill();
        }

        frameId = window.requestAnimationFrame(
            draw,
        );
    };

    resize();

    frameId = window.requestAnimationFrame(
        draw,
    );

    window.addEventListener(
        'resize',
        resize,
    );

    window.addEventListener(
        'beforeunload',
        () => {
            if (frameId) {
                window.cancelAnimationFrame(
                    frameId,
                );
            }
        },
        {
            once: true,
        },
    );
}


/* ==========================================================================
   STATUS GLOBAL
   ========================================================================== */

export function renderGlobalStatus({
    status,
    healthy,
    active,
    message,
}) {
    const normalized = healthy
        ? 'ok'
        : normalizeStatus(
            status,
            active
                ? 'warning'
                : 'error',
        );

    applyStatusDot(
        'sidebarStatusDot',
        normalized,
    );

    applyStatusDot(
        'heroStatusDot',
        normalized,
    );

    applyChip(
        'headerStackChip',
        normalized,
        statusLabel(normalized),
    );

    setText(
        'headerStackText',
        healthy
            ? 'Saudável'
            : active
                ? 'Com avisos'
                : 'Atenção',
    );

    setText(
        'sidebarStatusTitle',
        healthy
            ? 'Proteção ativa'
            : active
                ? 'Proteção degradada'
                : 'Proteção indisponível',
    );

    setText(
        'sidebarStatusText',
        message,
    );

    setText(
        'heroStatusEyebrow',
        healthy
            ? 'Proteção operacional'
            : active
                ? 'Operação com avisos'
                : 'Intervenção necessária',
    );

    setText(
        'heroDescription',
        message,
    );

    const orbit = $('orbitStatus');

    if (orbit) {
        for (
            const className
            of Array.from(
                orbit.classList,
            )
        ) {
            if (
                className.startsWith(
                    'sp-orbit__status--',
                )
            ) {
                orbit.classList.remove(
                    className,
                );
            }
        }

        orbit.classList.add(
            `sp-orbit__status--${normalized}`,
        );
    }

    setText(
        'orbitStatusText',
        healthy
            ? 'Stack operacional'
            : active
                ? 'Stack degradada'
                : 'Stack indisponível',
    );

    /*
     * IMPORTANTE:
     * O painel principal atualiza state.statusData antes de chamar
     * renderGlobalStatus(). Aproveitamos o mesmo snapshot para atualizar
     * o card "Stack Suricata" da Visão Geral.
     *
     * Isso evita:
     * - segundo request;
     * - cálculo paralelo;
     * - card preso em 0%;
     * - divergência com a tela Saúde da stack.
     */
    renderOverviewHealth(
        state.statusData,
    );
}


/* ==========================================================================
   CARD "STACK SURICATA" DA VISÃO GERAL
   ========================================================================== */

export function renderOverviewHealth(
    payload = null,
) {
    const raw = safeObject(
        payload || state.statusData,
    );

    const data = safeObject(
        readPath(
            raw,
            [
                'dados',
            ],
            raw,
        ),
    );

    const stack = safeObject(
        readPath(
            data,
            [
                'stack',
                'dados.stack',
                'novo_status',
                'status_stack',
            ],
            data,
        ),
    );

    const backendSummary = safeObject(
        readPath(
            stack,
            [
                'resumo_saude',
            ],
            readPath(
                data,
                [
                    'resumo_saude',
                ],
                {},
            ),
        ),
    );

    const summary = Object.keys(
        backendSummary,
    ).length
        ? normalizeBackendHealthSummary(
            backendSummary,
            stack,
        )
        : calculateHealthSummaryFallback(
            stack,
            data,
        );

    renderHealthSummaryValues(
        summary,
        stack,
    );
}


function normalizeBackendHealthSummary(
    backendSummary,
    stack,
) {
    const healthyCount = numberValue(
        readPath(
            backendSummary,
            [
                'saudaveis',
                'total_saudaveis',
                'ok',
            ],
            0,
        ),
        0,
    );

    const warningCount = numberValue(
        readPath(
            backendSummary,
            [
                'avisos',
                'total_avisos',
                'warnings',
            ],
            0,
        ),
        0,
    );

    const errorCount = numberValue(
        readPath(
            backendSummary,
            [
                'erros',
                'total_erros',
                'criticos',
                'total_criticos',
            ],
            0,
        ),
        0,
    );

    const total = numberValue(
        readPath(
            backendSummary,
            [
                'total',
                'total_checks',
            ],
            (
                healthyCount
                + warningCount
                + errorCount
            ),
        ),
        (
            healthyCount
            + warningCount
            + errorCount
        ),
    );

    let score = numberValue(
        readPath(
            backendSummary,
            [
                'score',
                'score_integridade',
            ],
            -1,
        ),
        -1,
    );

    if (score < 0) {
        score = total > 0
            ? Math.round(
                (
                    (
                        healthyCount
                        + warningCount * 0.5
                    )
                    / total
                )
                * 100,
            )
            : 0;
    }

    const backendStatus = normalizeStatus(
        readPath(
            stack,
            [
                'status',
            ],
            'desconhecido',
        ),
    );

    let status = backendStatus;

    if (
        boolValue(
            readPath(
                stack,
                [
                    'operacional',
                    'saudavel',
                ],
                false,
            ),
        )
    ) {
        status = 'ok';
    } else if (
        errorCount > 0
    ) {
        status = 'error';
    } else if (
        warningCount > 0
    ) {
        status = 'warning';
    }

    return {
        total,
        healthyCount,
        warningCount,
        errorCount,
        score: clampScore(score),
        status,
    };
}


function calculateHealthSummaryFallback(
    stack,
    data,
) {
    const checks = collectHealthChecks(
        stack,
    );

    const warnings = safeArray(
        readPath(
            stack,
            [
                'avisos',
            ],
            readPath(
                data,
                [
                    'avisos',
                ],
                [],
            ),
        ),
    );

    const errors = safeArray(
        readPath(
            stack,
            [
                'erros',
            ],
            readPath(
                data,
                [
                    'erros',
                ],
                [],
            ),
        ),
    );

    let healthyCount = 0;
    let warningCount = 0;
    let errorCount = 0;

    for (const check of checks) {
        const normalized = normalizeStatus(
            check.status,
        );

        if (normalized === 'ok') {
            healthyCount += 1;
        } else if (
            normalized === 'warning'
        ) {
            warningCount += 1;
        } else if (
            normalized === 'error'
        ) {
            errorCount += 1;
        }
    }

    /*
     * Não duplicamos mensagens de stack quando já existem checks reais.
     * Avisos/erros extras só entram se não estiverem representados.
     */
    if (
        warnings.length > 0
        && warningCount === 0
    ) {
        warningCount = warnings.length;
    }

    if (
        errors.length > 0
        && errorCount === 0
    ) {
        errorCount = errors.length;
    }

    const total = Math.max(
        1,
        healthyCount
        + warningCount
        + errorCount,
    );

    const score = Math.round(
        (
            (
                healthyCount
                + warningCount * 0.5
            )
            / total
        )
        * 100,
    );

    const stackStatus = normalizeStatus(
        readPath(
            stack,
            [
                'status',
            ],
            'desconhecido',
        ),
    );

    const status = boolValue(
        readPath(
            stack,
            [
                'operacional',
                'saudavel',
            ],
            false,
        ),
    )
        ? 'ok'
        : errorCount > 0
            ? 'error'
            : warningCount > 0
                ? 'warning'
                : stackStatus;

    return {
        total,
        healthyCount,
        warningCount,
        errorCount,
        score: clampScore(score),
        status,
    };
}


function collectHealthChecks(
    stack,
) {
    const checks = [];

    const suricata = safeObject(
        readPath(
            stack,
            [
                'suricata',
            ],
            {},
        ),
    );

    const monitor = safeObject(
        readPath(
            stack,
            [
                'monitor',
            ],
            {},
        ),
    );

    const services = safeObject(
        readPath(
            stack,
            [
                'servicos',
            ],
            {},
        ),
    );

    const worker = safeObject(
        readPath(
            services,
            [
                'worker_tarefas',
                'moonshield-suricata-worker',
                'worker',
            ],
            {},
        ),
    );

    const eve = safeObject(
        readPath(
            monitor,
            [
                'eve',
            ],
            readPath(
                suricata,
                [
                    'eve',
                ],
                {},
            ),
        ),
    );

    const cursor = safeObject(
        readPath(
            monitor,
            [
                'cursor',
            ],
            {},
        ),
    );

    checks.push({
        title: 'Suricata ativo',
        message: textValue(
            readPath(
                suricata,
                [
                    'mensagem',
                ],
                '',
            ),
            '',
        ),
        status: boolValue(
            readPath(
                suricata,
                [
                    'ativo',
                ],
                false,
            ),
        )
            ? 'ok'
            : 'error',
    });

    checks.push({
        title: 'Monitor ativo',
        message: textValue(
            readPath(
                monitor,
                [
                    'mensagem',
                ],
                '',
            ),
            '',
        ),
        status: boolValue(
            readPath(
                monitor,
                [
                    'ativo',
                ],
                false,
            ),
        )
            ? 'ok'
            : 'error',
    });

    checks.push({
        title: 'EVE atualizando',
        message: textValue(
            readPath(
                eve,
                [
                    'mensagem',
                ],
                '',
            ),
            '',
        ),
        status: boolValue(
            readPath(
                eve,
                [
                    'atualizando',
                ],
                false,
            ),
        )
            ? 'ok'
            : (
                boolValue(
                    readPath(
                        eve,
                        [
                            'existe',
                        ],
                        false,
                    ),
                )
                    ? 'warning'
                    : 'error'
            ),
    });

    checks.push({
        title: 'Cursor acompanhando',
        message: textValue(
            readPath(
                cursor,
                [
                    'mensagem',
                ],
                '',
            ),
            '',
        ),
        status: boolValue(
            readPath(
                cursor,
                [
                    'acompanhando',
                ],
                false,
            ),
        )
            ? 'ok'
            : (
                boolValue(
                    readPath(
                        cursor,
                        [
                            'valido',
                        ],
                        false,
                    ),
                )
                    ? 'warning'
                    : 'error'
            ),
    });

    if (
        Object.keys(worker).length
    ) {
        checks.push({
            title: 'Worker automático',
            message: boolValue(
                readPath(
                    worker,
                    [
                        'ativo',
                    ],
                    false,
                ),
            )
                ? 'Worker de tarefas ativo.'
                : 'Worker de tarefas parado.',
            status: boolValue(
                readPath(
                    worker,
                    [
                        'ativo',
                    ],
                    false,
                ),
            )
                ? 'ok'
                : 'error',
        });
    }

    return checks;
}


function renderHealthSummaryValues(
    summary,
    stack,
) {
    const {
        healthyCount,
        warningCount,
        errorCount,
        score,
    } = summary;

    let status = normalizeStatus(
        summary.status,
    );

    const stackOperational = boolValue(
        readPath(
            stack,
            [
                'operacional',
            ],
            false,
        ),
    );

    const stackHealthy = boolValue(
        readPath(
            stack,
            [
                'saudavel',
            ],
            false,
        ),
    );

    if (
        stackOperational
        || stackHealthy
    ) {
        status = 'ok';
    } else if (
        errorCount > 0
    ) {
        status = 'error';
    } else if (
        warningCount > 0
    ) {
        status = 'warning';
    }

    setText(
        'healthScoreValue',
        score,
    );

    setText(
        'healthOkCount',
        healthyCount,
    );

    setText(
        'healthWarningCount',
        warningCount,
    );

    setText(
        'healthErrorCount',
        errorCount,
    );

    updateHealthScoreCircle(
        score,
        status,
    );

    setText(
        'healthScoreTitle',
        status === 'ok'
            ? 'Stack saudável'
            : status === 'warning'
                ? 'Stack com avisos'
                : status === 'error'
                    ? 'Stack requer atenção'
                    : 'Estado da stack',
    );

    const backendMessage = textValue(
        readPath(
            stack,
            [
                'mensagem',
            ],
            '',
        ),
        '',
    );

    setText(
        'healthScoreText',
        backendMessage
        || (
            status === 'ok'
                ? 'Todos os componentes obrigatórios estão operacionais.'
                : status === 'warning'
                    ? `${warningCount} aviso(s) precisam ser revisados.`
                    : status === 'error'
                        ? `${errorCount} falha(s) exigem intervenção.`
                        : 'Estado operacional ainda não confirmado.'
        ),
    );

    applyChip(
        'healthSummaryChip',
        status,
        status === 'ok'
            ? 'Saudável'
            : status === 'warning'
                ? 'Com avisos'
                : status === 'error'
                    ? 'Crítico'
                    : 'Verificando',
    );
}


function updateHealthScoreCircle(
    score,
    status,
) {
    const circle = $(
        'healthScoreCircle',
    );

    if (!circle) {
        return;
    }

    /*
     * r = 48
     * circunferência ≈ 2πr ≈ 301.59
     */
    const circumference = 301.59;

    circle.style.strokeDasharray = (
        `${circumference}`
    );

    circle.style.strokeDashoffset = (
        `${circumference - (
            score / 100
        ) * circumference}`
    );

    circle.style.stroke = (
        status === 'ok'
            ? 'var(--sp-green)'
            : status === 'warning'
                ? 'var(--sp-yellow)'
                : status === 'error'
                    ? 'var(--sp-red)'
                    : 'var(--sp-dim)'
    );
}


function clampScore(
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


/* ==========================================================================
   ÚLTIMA ATUALIZAÇÃO
   ========================================================================== */

export function updateLastRefresh() {
    const value = (
        state.lastStatusFetchAt
        || new Date()
    );

    setText(
        'lastUpdateText',
        formatRelativeTime(value),
    );
}


/* ==========================================================================
   TAREFAS RECENTES
   ========================================================================== */

export function renderOverviewTasks(
    tasks,
) {
    const container = $(
        'overviewTaskList',
    );

    if (!container) {
        return;
    }

    container.innerHTML = '';

    if (!tasks.length) {
        container.innerHTML = `
            <div class="sp-empty-state sp-empty-state--compact">
                <span class="sp-empty-state__icon">
                    ${iconSVG('task', 20)}
                </span>

                <div>
                    <strong>
                        Nenhuma atividade recente
                    </strong>

                    <span>
                        As últimas tarefas aparecerão aqui.
                    </span>
                </div>
            </div>
        `;

        return;
    }

    for (const task of tasks) {
        const status = normalizeStatus(
            task.status,
        );

        const element = (
            document.createElement(
                'button',
            )
        );

        element.type = 'button';

        element.className = (
            'sp-activity-item'
        );

        element.dataset.taskOpen = (
            task.id
            || task.pk
            || ''
        );

        element.innerHTML = `
            <span class="sp-activity-item__icon">
                ${iconSVG(
                    TASK_ICONS[task.tipo]
                    || 'task',
                    15,
                )}
            </span>

            <span class="sp-activity-item__copy">
                <strong>
                    ${escapeHTML(
                        TASK_LABELS[task.tipo]
                        || capitalize(
                            task.tipo,
                        ),
                    )}
                </strong>

                <span>
                    ${escapeHTML(
                        task.mensagem
                        || task.etapa_atual
                        || 'Sem detalhes',
                    )}
                </span>
            </span>

            <span class="sp-status-pill sp-status-pill--${status}">
                ${escapeHTML(
                    statusLabel(
                        task.status,
                    ),
                )}
            </span>
        `;

        container.appendChild(
            element,
        );
    }
}
