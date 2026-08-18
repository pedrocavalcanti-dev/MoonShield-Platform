import {
    safeObject,
    safeArray,
    readPath,
    boolValue,
    formatBoolean,
    formatBytes,
    numberValue,
    textValue,
    escapeHTML
} from '../nucleo/utilitarios.js';

import {
    updateClassByPrefix,
    setText,
    $
} from '../nucleo/dom.js';

import {
    applyPill,
    applyChip,
    normalizeStatus,
    statusLabel
} from '../nucleo/interface.js';


/* ==========================================================================
   CARD DE STATUS
   ========================================================================== */

function updateStatusCard(
    cardId,
    config
) {
    const card =
        $(cardId);

    if (!card) {
        return;
    }

    updateClassByPrefix(
        card,
        'sp-status-card--',
        config.status
    );

    setText(
        config.stateId,
        statusLabel(config.status)
    );

    setText(
        config.valueId,
        config.value
    );

    setText(
        config.detailId,
        config.detail
    );

    setText(
        config.metaId,
        config.meta
    );
}


/* ==========================================================================
   SURICATA
   ========================================================================== */

export function renderSuricata(
    suricata,
    services,
    environment
) {
    const suricataData =
        safeObject(suricata);

    const servicesData =
        safeObject(services);

    const environmentData =
        safeObject(environment);

    const service =
        safeObject(
            readPath(
                suricataData,
                ['servico'],
                readPath(
                    servicesData,
                    ['suricata'],
                    {}
                )
            )
        );


    const installed =
        boolValue(
            readPath(
                suricataData,
                ['instalado'],
                readPath(
                    service,
                    ['instalado'],
                    false
                )
            )
        );


    const active =
        boolValue(
            readPath(
                suricataData,
                ['ativo'],
                readPath(
                    service,
                    ['ativo'],
                    false
                )
            )
        );


    const enabled =
        boolValue(
            readPath(
                service,
                ['habilitado'],
                false
            )
        );


    const ready =
        boolValue(
            readPath(
                suricataData,
                ['pronto'],
                active && installed
            )
        );


    /*
     * Compatibilidade com os contratos atuais do backend:
     *
     * suricata.versao
     * suricata.versao_suricata
     * ambiente.suricata.versao
     * ambiente.versao_suricata
     */
    const version =
        readPath(
            suricataData,
            [
                'versao',
                'versao_suricata'
            ],
            readPath(
                environmentData,
                [
                    'suricata.versao',
                    'versao_suricata'
                ],
                ''
            )
        );


    const message =
        readPath(
            suricataData,
            ['mensagem'],
            readPath(
                service,
                ['mensagem'],
                ''
            )
        );


    const status =
        ready
            ? 'ok'
            : active
                ? 'warning'
                : 'error';


    updateStatusCard(
        'cardSuricata',
        {
            status,

            stateId:
                'cardSuricataState',

            valueId:
                'cardSuricataValue',

            detailId:
                'cardSuricataDetail',

            metaId:
                'cardSuricataMeta',

            value:
                active
                    ? 'Ativo'
                    : installed
                        ? 'Inativo'
                        : 'Não instalado',

            detail:
                message ||
                (
                    active
                        ? 'Serviço executando normalmente'
                        : 'Serviço não está ativo'
                ),

            meta:
                version
                    ? `Suricata ${version}`
                    : 'Versão indisponível'
        }
    );


    applyPill(
        'healthSuricataStatus',
        status
    );

    setText(
        'healthSuricataMessage',
        message ||
        'Estado do serviço consultado'
    );

    setText(
        'healthSuricataInstalled',
        formatBoolean(installed)
    );

    setText(
        'healthSuricataActive',
        formatBoolean(
            active,
            'Ativo',
            'Inativo'
        )
    );

    setText(
        'healthSuricataEnabled',
        formatBoolean(enabled)
    );

    setText(
        'healthSuricataPid',
        readPath(
            service,
            ['pid'],
            '—'
        )
    );

    setText(
        'healthSuricataVersion',
        version || '—'
    );

    setText(
        'healthSuricataService',
        readPath(
            service,
            [
                'nome',
                'servico'
            ],
            'suricata'
        )
    );
}


/* ==========================================================================
   MONITOR
   ========================================================================== */

export function renderMonitor(
    monitor,
    services
) {
    const monitorData =
        safeObject(monitor);

    const servicesData =
        safeObject(services);


    const service =
        safeObject(
            readPath(
                monitorData,
                ['servico'],
                readPath(
                    servicesData,
                    ['monitor'],
                    {}
                )
            )
        );


    const installed =
        boolValue(
            readPath(
                monitorData,
                ['instalado'],
                readPath(
                    service,
                    ['instalado'],
                    false
                )
            )
        );


    const active =
        boolValue(
            readPath(
                monitorData,
                ['ativo'],
                readPath(
                    service,
                    ['ativo'],
                    false
                )
            )
        );


    /*
     * Dependendo do backend, lendo_eve pode ainda não existir.
     * Nesse caso não consideramos false automaticamente se o monitor
     * estiver operacional.
     */
    const readingRaw =
        readPath(
            monitorData,
            [
                'lendo_eve',
                'lendo',
                'acompanhando_eve'
            ],
            null
        );

    const reading =
        readingRaw === null
            ? active
            : boolValue(readingRaw);


    const healthy =
        boolValue(
            readPath(
                monitorData,
                ['saudavel'],
                active && reading
            )
        );


    const message =
        readPath(
            monitorData,
            ['mensagem'],
            readPath(
                service,
                ['mensagem'],
                ''
            )
        );


    const status =
        healthy
            ? 'ok'
            : active
                ? 'warning'
                : 'error';


    updateStatusCard(
        'cardMonitor',
        {
            status,

            stateId:
                'cardMonitorState',

            valueId:
                'cardMonitorValue',

            detailId:
                'cardMonitorDetail',

            metaId:
                'cardMonitorMeta',

            value:
                active
                    ? 'Ativo'
                    : 'Inativo',

            detail:
                message ||
                (
                    reading
                        ? 'Monitor acompanhando o eve.json'
                        : 'Monitor não está acompanhando o arquivo'
                ),

            meta:
                reading
                    ? 'Cursor acompanhando o EVE'
                    : 'Leitura não confirmada'
        }
    );


    applyPill(
        'healthMonitorStatus',
        status
    );

    setText(
        'healthMonitorMessage',
        message ||
        'Estado do monitor consultado'
    );

    setText(
        'healthMonitorInstalled',
        formatBoolean(installed)
    );

    setText(
        'healthMonitorActive',
        formatBoolean(
            active,
            'Ativo',
            'Inativo'
        )
    );

    setText(
        'healthMonitorReading',
        formatBoolean(reading)
    );

    setText(
        'healthMonitorHealthy',
        formatBoolean(healthy)
    );

    setText(
        'healthMonitorPid',
        readPath(
            service,
            ['pid'],
            '—'
        )
    );

    setText(
        'healthMonitorService',
        readPath(
            service,
            [
                'nome',
                'servico'
            ],
            'moonshield-suricata-monitor'
        )
    );
}


/* ==========================================================================
   EVE JSON
   ========================================================================== */

export function renderEve(
    suricata,
    monitor
) {
    const suricataData =
        safeObject(suricata);

    const monitorData =
        safeObject(monitor);


    const eve =
        safeObject(
            readPath(
                monitorData,
                ['eve'],
                readPath(
                    suricataData,
                    ['eve'],
                    {}
                )
            )
        );


    const exists =
        boolValue(
            readPath(
                eve,
                ['existe'],
                false
            )
        );


    const readable =
        boolValue(
            readPath(
                eve,
                ['legivel'],
                false
            )
        );


    const updating =
        boolValue(
            readPath(
                eve,
                ['atualizando'],
                false
            )
        );


    const status =
        updating
            ? 'ok'
            : exists && readable
                ? 'warning'
                : 'error';


    const age =
        readPath(
            eve,
            [
                'idade_segundos',
                'idade'
            ],
            null
        );


    const size =
        readPath(
            eve,
            [
                'tamanho',
                'tamanho_bytes'
            ],
            null
        );


    const message =
        readPath(
            eve,
            ['mensagem'],
            ''
        );


    updateStatusCard(
        'cardEve',
        {
            status,

            stateId:
                'cardEveState',

            valueId:
                'cardEveValue',

            detailId:
                'cardEveDetail',

            metaId:
                'cardEveMeta',

            value:
                updating
                    ? 'Atualizando'
                    : exists
                        ? 'Parado'
                        : 'Ausente',

            detail:
                message ||
                (
                    updating
                        ? 'Arquivo recebendo novos eventos'
                        : 'Arquivo sem atualização recente'
                ),

            meta:
                size !== null
                    ? formatBytes(size)
                    : 'Sem tamanho disponível'
        }
    );


    applyPill(
        'healthEveStatus',
        status
    );

    setText(
        'healthEveMessage',
        message ||
        'Estado do arquivo consultado'
    );

    setText(
        'healthEveExists',
        formatBoolean(exists)
    );

    setText(
        'healthEveReadable',
        formatBoolean(readable)
    );

    setText(
        'healthEveUpdating',
        formatBoolean(updating)
    );

    setText(
        'healthEveSize',
        size !== null
            ? formatBytes(size)
            : '—'
    );

    setText(
        'healthEveAge',
        age !== null
            ? `${Math.round(numberValue(age))}s atrás`
            : '—'
    );

    setText(
        'healthEvePath',
        readPath(
            eve,
            [
                'caminho',
                'path'
            ],
            '—'
        )
    );
}


/* ==========================================================================
   CURSOR
   ========================================================================== */

export function renderCursor(
    monitor
) {
    const monitorData =
        safeObject(monitor);

    const cursor =
        safeObject(
            readPath(
                monitorData,
                ['cursor'],
                {}
            )
        );


    const exists =
        boolValue(
            readPath(
                cursor,
                ['existe'],
                false
            )
        );


    const valid =
        boolValue(
            readPath(
                cursor,
                ['valido'],
                false
            )
        );


    const following =
        boolValue(
            readPath(
                cursor,
                ['acompanhando'],
                false
            )
        );


    const status =
        following
            ? 'ok'
            : exists && valid
                ? 'warning'
                : 'error';


    const message =
        readPath(
            cursor,
            ['mensagem'],
            ''
        );


    applyPill(
        'healthCursorStatus',
        status
    );

    setText(
        'healthCursorMessage',
        message ||
        'Estado do cursor consultado'
    );

    setText(
        'healthCursorExists',
        formatBoolean(exists)
    );

    setText(
        'healthCursorValid',
        formatBoolean(valid)
    );

    setText(
        'healthCursorFollowing',
        formatBoolean(following)
    );

    setText(
        'healthCursorPosition',
        readPath(
            cursor,
            [
                'posicao',
                'offset'
            ],
            '—'
        )
    );


    const lag =
        readPath(
            cursor,
            [
                'atraso_bytes',
                'lag_bytes'
            ],
            null
        );


    setText(
        'healthCursorLag',
        lag !== null
            ? formatBytes(lag)
            : '—'
    );

    setText(
        'healthCursorPath',
        readPath(
            cursor,
            [
                'caminho',
                'path'
            ],
            '—'
        )
    );
}


/* ==========================================================================
   COLETA DE CHECKS
   ========================================================================== */

export function collectHealthChecks(
    stack
) {
    const stackData =
        safeObject(stack);


    const checks = [];


    const suricata =
        safeObject(
            readPath(
                stackData,
                ['suricata'],
                {}
            )
        );


    const monitor =
        safeObject(
            readPath(
                stackData,
                ['monitor'],
                {}
            )
        );


    const eve =
        safeObject(
            readPath(
                monitor,
                ['eve'],
                readPath(
                    suricata,
                    ['eve'],
                    {}
                )
            )
        );


    const cursor =
        safeObject(
            readPath(
                monitor,
                ['cursor'],
                {}
            )
        );


    checks.push({
        title:
            'Suricata ativo',

        message:
            readPath(
                suricata,
                ['mensagem'],
                ''
            ),

        status:
            boolValue(
                readPath(
                    suricata,
                    ['ativo'],
                    false
                )
            )
                ? 'ok'
                : 'error'
    });


    checks.push({
        title:
            'Monitor ativo',

        message:
            readPath(
                monitor,
                ['mensagem'],
                ''
            ),

        status:
            boolValue(
                readPath(
                    monitor,
                    ['ativo'],
                    false
                )
            )
                ? 'ok'
                : 'error'
    });


    checks.push({
        title:
            'EVE atualizando',

        message:
            readPath(
                eve,
                ['mensagem'],
                ''
            ),

        status:
            boolValue(
                readPath(
                    eve,
                    ['atualizando'],
                    false
                )
            )
                ? 'ok'
                : 'warning'
    });


    /*
     * Cursor só entra como check quando existe informação de cursor.
     * Assim não penalizamos o painel quando o backend não envia esse
     * bloco no status leve.
     */
    if (
        Object.keys(cursor).length
    ) {
        checks.push({
            title:
                'Cursor acompanhando',

            message:
                readPath(
                    cursor,
                    ['mensagem'],
                    ''
                ),

            status:
                boolValue(
                    readPath(
                        cursor,
                        ['acompanhando'],
                        false
                    )
                )
                    ? 'ok'
                    : 'warning'
        });
    }


    return checks;
}


/* ==========================================================================
   LISTA DE SAÚDE
   ========================================================================== */

export function renderStackChecks(
    stack,
    data
) {
    const container =
        $('stackChecksList');

    if (!container) {
        return;
    }


    const checks =
        collectHealthChecks(
            stack
        );


    const errors =
        safeArray(
            readPath(
                stack,
                ['erros'],
                readPath(
                    data,
                    ['erros'],
                    []
                )
            )
        );


    const warnings =
        safeArray(
            readPath(
                stack,
                ['avisos'],
                readPath(
                    data,
                    ['avisos'],
                    []
                )
            )
        );


    for (
        const message
        of warnings
    ) {
        checks.push({
            title:
                'Aviso',

            message:
                textValue(message),

            status:
                'warning'
        });
    }


    for (
        const message
        of errors
    ) {
        checks.push({
            title:
                'Erro',

            message:
                textValue(message),

            status:
                'error'
        });
    }


    container.innerHTML = '';


    if (!checks.length) {
        container.innerHTML = `
            <div class="sp-empty-state">
                <div>
                    <strong>
                        Nenhuma verificação disponível
                    </strong>

                    <span>
                        O backend ainda não retornou informações de saúde.
                    </span>
                </div>
            </div>
        `;

        applyChip(
            'stackGeneralStatus',
            'pending',
            'Verificando'
        );

        return;
    }


    for (
        const check
        of checks
    ) {
        const status =
            normalizeStatus(
                check.status
            );


        const element =
            document.createElement(
                'div'
            );


        element.className =
            `sp-stack-check sp-stack-check--${status}`;


        element.innerHTML = `
            <span
                class="sp-stack-check__status"
                aria-hidden="true"
            ></span>

            <div>
                <strong>
                    ${escapeHTML(check.title)}
                </strong>

                <span>
                    ${
                        escapeHTML(
                            check.message ||
                            statusLabel(status)
                        )
                    }
                </span>
            </div>
        `;


        container.appendChild(
            element
        );
    }


    const hasError =
        checks.some(
            (item) =>
                normalizeStatus(
                    item.status
                ) === 'error'
        );


    const hasWarning =
        checks.some(
            (item) =>
                normalizeStatus(
                    item.status
                ) === 'warning'
        );


    const overall =
        hasError
            ? 'error'
            : hasWarning
                ? 'warning'
                : 'ok';


    applyChip(
        'stackGeneralStatus',
        overall
    );
}


/* ==========================================================================
   REGRAS — CARD DA VISÃO GERAL
   ========================================================================== */

export function renderRules(
    suricata,
    stack
) {
    const suricataData =
        safeObject(suricata);

    const stackData =
        safeObject(stack);


    const rules =
        safeObject(
            readPath(
                suricataData,
                ['regras'],
                readPath(
                    stackData,
                    ['regras'],
                    {}
                )
            )
        );


    const moon =
        safeObject(
            readPath(
                rules,
                [
                    'moonshield',
                    'regras_moonshield'
                ],
                {}
            )
        );


    const et =
        safeObject(
            readPath(
                rules,
                [
                    'et_open',
                    'etopen'
                ],
                {}
            )
        );


    const moonInstalled =
        boolValue(
            readPath(
                moon,
                [
                    'instaladas',
                    'instalado'
                ],
                readPath(
                    rules,
                    ['moonshield_instalado'],
                    false
                )
            )
        );


    const etInstalled =
        boolValue(
            readPath(
                et,
                ['instalado'],
                readPath(
                    rules,
                    ['et_open_instalado'],
                    false
                )
            )
        );


    const totalRules =
        readPath(
            rules,
            [
                'total_regras',
                'total'
            ],
            readPath(
                moon,
                ['total'],
                null
            )
        );


    const status =
        moonInstalled
            ? (
                etInstalled
                    ? 'ok'
                    : 'warning'
            )
            : 'error';


    updateStatusCard(
        'cardRules',
        {
            status,

            stateId:
                'cardRulesState',

            valueId:
                'cardRulesValue',

            detailId:
                'cardRulesDetail',

            metaId:
                'cardRulesMeta',

            value:
                moonInstalled
                    ? 'Carregadas'
                    : 'Incompletas',

            detail:
                moonInstalled
                    ? 'Regras MoonShield disponíveis'
                    : 'Regras MoonShield não confirmadas',

            meta:
                totalRules !== null
                    ? `${numberValue(totalRules)} regras`
                    : etInstalled
                        ? 'MoonShield + ET Open'
                        : 'Pacotes incompletos'
        }
    );
}