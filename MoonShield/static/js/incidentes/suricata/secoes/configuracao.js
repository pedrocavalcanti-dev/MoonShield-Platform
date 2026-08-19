import {
    safeObject,
    readPath,
    formatCaptureMode,
    formatBoolean,
    formatDate,
    boolValue,
    safeArray,
    textValue,
    numberValue,
} from '../nucleo/utilitarios.js';

import {
    setText,
    $,
} from '../nucleo/dom.js';

import {
    applyChip,
} from '../nucleo/interface.js';

import {
    state,
} from '../nucleo/estado.js';


let configurationStatusTimer = null;
let lastOperationalSignature = '';


/* ==========================================================================
   API PÚBLICA
   ========================================================================== */

export function renderConfiguration(
    configuration,
    statusPayload = null,
) {
    const config = safeObject(configuration);

    renderPersistedConfiguration(config);
    renderConfigurationOperational(
        statusPayload || state.statusData,
        config,
    );

    startConfigurationStatusObserver(config);
}


export function renderConfigurationOperational(
    statusPayload,
    configuration = null,
) {
    const config = safeObject(configuration);
    const status = normalizeStatusPayload(statusPayload);

    const stack = safeObject(
        readPath(
            status,
            ['stack'],
            status,
        ),
    );

    const suricata = safeObject(
        readPath(
            stack,
            ['suricata'],
            {},
        ),
    );

    const monitor = safeObject(
        readPath(
            stack,
            ['monitor'],
            {},
        ),
    );

    const services = safeObject(
        readPath(
            stack,
            ['servicos'],
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

    const rules = safeObject(
        readPath(
            suricata,
            ['regras'],
            {},
        ),
    );

    const moonRules = safeObject(
        readPath(
            rules,
            ['moonshield'],
            {},
        ),
    );

    const etOpen = safeObject(
        readPath(
            rules,
            ['et_open', 'etopen'],
            {},
        ),
    );

    const yaml = safeObject(
        readPath(
            suricata,
            ['yaml'],
            {},
        ),
    );

    const eve = safeObject(
        readPath(
            monitor,
            ['eve'],
            readPath(
                suricata,
                ['eve'],
                {},
            ),
        ),
    );

    const cursor = safeObject(
        readPath(
            monitor,
            ['cursor'],
            {},
        ),
    );

    const componentes = safeObject(
        readPath(
            suricata,
            ['componentes'],
            {},
        ),
    );

    const backendOperational = boolValue(
        readPath(
            stack,
            ['operacional'],
            false,
        ),
    );

    const backendInstalled = boolValue(
        readPath(
            stack,
            ['instalado'],
            false,
        ),
    );

    const backendConfigured = boolValue(
        readPath(
            stack,
            ['configurado'],
            false,
        ),
    );

    const suricataInstalled = boolValue(
        readPath(
            suricata,
            ['instalado'],
            readPath(
                componentes,
                ['binario.instalado'],
                false,
            ),
        ),
    );

    const suricataActive = boolValue(
        readPath(
            suricata,
            ['ativo'],
            readPath(
                suricata,
                ['servico.ativo'],
                false,
            ),
        ),
    );

    const suricataVersion = textValue(
        readPath(
            suricata,
            ['versao'],
            readPath(
                componentes,
                ['binario.versao'],
                '',
            ),
        ),
        '',
    );

    const yamlExists = boolValue(
        readPath(
            yaml,
            ['existe'],
            readPath(
                componentes,
                ['yaml.existe'],
                false,
            ),
        ),
    );

    const yamlConfigured = boolValue(
        readPath(
            suricata,
            ['configurado'],
            readPath(
                componentes,
                ['yaml.configurado'],
                false,
            ),
        ),
    );

    const eveAvailable = boolValue(
        readPath(
            componentes,
            ['eve.disponivel'],
            boolValue(
                readPath(
                    eve,
                    ['existe'],
                    false,
                ),
            )
            && boolValue(
                readPath(
                    eve,
                    ['legivel'],
                    false,
                ),
            ),
        ),
    );

    const eveUpdating = boolValue(
        readPath(
            eve,
            ['atualizando'],
            readPath(
                componentes,
                ['eve.atualizando'],
                false,
            ),
        ),
    );

    const moonInstalled = boolValue(
        readPath(
            moonRules,
            ['instaladas', 'instalado', 'instalada'],
            readPath(
                componentes,
                ['moonshield_rules.instaladas'],
                false,
            ),
        ),
    );

    const moonReferenced = boolValue(
        readPath(
            moonRules,
            ['referenciado', 'referenciadas', 'referenciada'],
            readPath(
                componentes,
                ['moonshield_rules.referenciadas'],
                false,
            ),
        ),
    );

    const moonTotal = numberValue(
        readPath(
            moonRules,
            ['total', 'total_regras'],
            readPath(
                componentes,
                ['moonshield_rules.total'],
                0,
            ),
        ),
        0,
    );

    const etInstalled = boolValue(
        readPath(
            etOpen,
            ['instalada', 'instalado', 'instaladas'],
            readPath(
                componentes,
                ['et_open.instalado'],
                false,
            ),
        ),
    );

    const etReferenced = boolValue(
        readPath(
            etOpen,
            ['referenciado', 'referenciada', 'referenciadas'],
            readPath(
                componentes,
                ['et_open.referenciado'],
                etInstalled,
            ),
        ),
    );

    const monitorInstalled = boolValue(
        readPath(
            monitor,
            ['instalado'],
            readPath(
                monitor,
                ['servico.instalado'],
                false,
            ),
        ),
    );

    const monitorActive = boolValue(
        readPath(
            monitor,
            ['ativo'],
            readPath(
                monitor,
                ['servico.ativo'],
                false,
            ),
        ),
    );

    const monitorHealthy = boolValue(
        readPath(
            monitor,
            ['saudavel'],
            false,
        ),
    );

    const cursorValid = boolValue(
        readPath(
            cursor,
            ['valido'],
            false,
        ),
    );

    const cursorFollowing = boolValue(
        readPath(
            cursor,
            ['acompanhando'],
            false,
        ),
    );

    const workerInstalled = boolValue(
        readPath(
            worker,
            ['instalado'],
            false,
        ),
    );

    const workerActive = boolValue(
        readPath(
            worker,
            ['ativo'],
            false,
        ),
    );

    const operational = (
        backendOperational
        || (
            suricataInstalled
            && suricataActive
            && yamlExists
            && yamlConfigured
            && eveAvailable
            && moonInstalled
            && moonReferenced
            && monitorInstalled
            && monitorActive
            && monitorHealthy
            && cursorValid
            && cursorFollowing
            && workerInstalled
            && workerActive
        )
    );

    const installed = (
        backendInstalled
        || (
            suricataInstalled
            && monitorInstalled
            && workerInstalled
        )
    );

    const configured = (
        backendConfigured
        || (
            yamlExists
            && yamlConfigured
            && moonInstalled
            && moonReferenced
        )
    );

    const hasError = (
        readPath(stack, ['status'], '') === 'erro'
        || readPath(suricata, ['status'], '') === 'erro'
        || readPath(monitor, ['status'], '') === 'erro'
    );

    const operationalState = operational
        ? 'ok'
        : hasError
            ? 'error'
            : 'warning';

    const operationalLabel = operational
        ? 'OPERACIONAL'
        : hasError
            ? 'INDISPONÍVEL'
            : 'ATENÇÃO';

    updateConfigurationShellState(
        operationalState,
    );

    applyChip(
        'configReadyChip',
        operationalState,
        operationalLabel,
    );

    applyChip(
        'configOperationalChip',
        operationalState,
        operationalLabel,
    );

    setText(
        'configOperationalTitle',
        operational
            ? 'Sensor operacional'
            : hasError
                ? 'Sensor indisponível'
                : 'Sensor requer atenção',
    );

    setText(
        'configOperationalDescription',
        operational
            ? (
                'Suricata, monitor, worker, EVE e regras '
                + 'foram confirmados pelo servidor.'
            )
            : hasError
                ? (
                    readPath(
                        stack,
                        ['mensagem'],
                        'A stack possui uma falha que exige intervenção.',
                    )
                )
                : (
                    readPath(
                        stack,
                        ['mensagem'],
                        'A instalação está parcialmente pronta.',
                    )
                ),
    );

    setText(
        'configOperationalCheckedAt',
        formatDate(
            readPath(
                stack,
                ['verificado_em'],
                readPath(
                    status,
                    ['verificado_em'],
                    null,
                ),
            ),
        ),
    );

    setBinaryState(
        'configStateInstalled',
        installed,
        'Instalado',
        'Incompleto',
    );

    setBinaryState(
        'configStateConfigured',
        configured,
        'Configurado',
        'Pendente',
    );

    setBinaryState(
        'configStateOperational',
        operational,
        'Operacional',
        'Não operacional',
    );

    renderComponentStatus(
        'configComponentSuricata',
        suricataInstalled && suricataActive,
        suricataInstalled
            ? (
                suricataActive
                    ? 'Ativo'
                    : 'Parado'
            )
            : 'Não instalado',
        suricataVersion
            ? `Versão ${suricataVersion}`
            : 'Versão não identificada',
    );

    renderComponentStatus(
        'configComponentYaml',
        yamlExists && yamlConfigured,
        yamlConfigured
            ? 'Configurado'
            : yamlExists
                ? 'Incompleto'
                : 'Ausente',
        textValue(
            readPath(
                config,
                ['yaml_path'],
                readPath(
                    yaml,
                    ['caminho'],
                    '/etc/suricata/suricata.yaml',
                ),
            ),
        ),
    );

    renderComponentStatus(
        'configComponentEve',
        eveAvailable,
        eveUpdating
            ? 'Atualizando'
            : eveAvailable
                ? 'Disponível'
                : 'Indisponível',
        eveUpdating
            ? 'Recebendo eventos recentemente'
            : textValue(
                readPath(
                    eve,
                    ['mensagem'],
                    'Estado de atualização não confirmado',
                ),
            ),
        eveAvailable && !eveUpdating
            ? 'warning'
            : null,
    );

    renderComponentStatus(
        'configComponentMoonRules',
        moonInstalled && moonReferenced,
        moonInstalled
            ? (
                moonReferenced
                    ? 'Ativas'
                    : 'Não referenciadas'
            )
            : 'Ausentes',
        moonTotal > 0
            ? `${moonTotal} regras`
            : 'Total não informado',
    );

    renderComponentStatus(
        'configComponentEtOpen',
        etInstalled && etReferenced,
        etInstalled
            ? (
                etReferenced
                    ? 'Ativo'
                    : 'Não referenciado'
            )
            : 'Não instalado',
        textValue(
            readPath(
                etOpen,
                ['mensagem'],
                etInstalled
                    ? 'Pacote comunitário disponível'
                    : 'Pacote comunitário ausente',
            ),
        ),
        etInstalled && !etReferenced
            ? 'warning'
            : null,
    );

    renderComponentStatus(
        'configComponentMonitor',
        monitorInstalled && monitorActive && monitorHealthy,
        monitorActive
            ? (
                monitorHealthy
                    ? 'Ativo'
                    : 'Com atenção'
            )
            : monitorInstalled
                ? 'Parado'
                : 'Não instalado',
        textValue(
            readPath(
                monitor,
                ['mensagem'],
                'Estado do monitor não identificado',
            ),
        ),
        monitorActive && !monitorHealthy
            ? 'warning'
            : null,
    );

    renderComponentStatus(
        'configComponentCursor',
        cursorValid && cursorFollowing,
        cursorFollowing
            ? 'Acompanhando'
            : cursorValid
                ? 'Com atraso'
                : 'Inválido',
        textValue(
            readPath(
                cursor,
                ['mensagem'],
                'Estado do cursor não identificado',
            ),
        ),
        cursorValid && !cursorFollowing
            ? 'warning'
            : null,
    );

    renderComponentStatus(
        'configComponentWorker',
        workerInstalled && workerActive,
        workerActive
            ? 'Ativo'
            : workerInstalled
                ? 'Parado'
                : 'Não instalado',
        workerActive
            ? 'Worker automático disponível'
            : 'Execução de tarefas não confirmada',
    );

    setText(
        'configStatusMessage',
        readPath(
            stack,
            ['mensagem'],
            operational
                ? 'Stack Suricata operacional e sincronizada.'
                : 'Estado operacional ainda não confirmado.',
        ),
    );

    const warningPanel = $(
        'configOperationalWarning',
    );

    if (warningPanel) {
        warningPanel.hidden = operational;
    }

    const successPanel = $(
        'configOperationalSuccess',
    );

    if (successPanel) {
        successPanel.hidden = !operational;
    }
}


export function renderTopology(
    topology,
    configuration,
) {
    const config = safeObject(
        configuration,
    );

    const data = safeObject(
        topology,
    );

    const wan = readPath(
        data,
        ['interface_wan', 'wan.nome', 'wan'],
        readPath(
            config,
            ['interface_wan'],
            'WAN',
        ),
    );

    const lan = readPath(
        data,
        ['interface_lan', 'lan.nome', 'lan'],
        readPath(
            config,
            ['interface_lan'],
            'LAN',
        ),
    );

    const homeNet = safeArray(
        readPath(
            data,
            ['home_net'],
            readPath(
                config,
                ['home_net'],
                [],
            ),
        ),
    );

    const monitored = safeArray(
        readPath(
            data,
            ['interfaces_monitoradas'],
            readPath(
                config,
                ['interfaces_monitoradas'],
                [],
            ),
        ),
    );

    setText(
        'topologyWanLabel',
        wan || 'WAN',
    );

    setText(
        'topologyLanLabel',
        lan || 'LAN',
    );

    setText(
        'topologyCaptureMode',
        formatCaptureMode(
            readPath(
                config,
                ['modo_captura'],
                readPath(
                    data,
                    ['modo_captura'],
                    '',
                ),
            ),
        ),
    );

    setText(
        'topologyHomeNet',
        homeNet.length
            ? homeNet.join(', ')
            : 'HOME_NET não informado',
    );

    renderChips(
        'topologyInterfaceChips',
        monitored,
        'Nenhuma interface',
    );
}


export function renderChips(
    containerId,
    values,
    emptyLabel = 'Nenhum',
) {
    const container = $(
        containerId,
    );

    if (!container) {
        return;
    }

    container.innerHTML = '';

    if (!values.length) {
        const chip = document.createElement(
            'span',
        );

        chip.className = (
            'sp-interface-chip'
        );

        chip.textContent = emptyLabel;

        container.appendChild(
            chip,
        );

        return;
    }

    for (const value of values) {
        const chip = document.createElement(
            'span',
        );

        chip.className = (
            'sp-interface-chip'
        );

        chip.textContent = textValue(
            value,
        );

        container.appendChild(
            chip,
        );
    }
}


export function renderCodeList(
    containerId,
    values,
    emptyLabel,
) {
    const container = $(
        containerId,
    );

    if (!container) {
        return;
    }

    container.innerHTML = '';

    const source = values.length
        ? values
        : [emptyLabel];

    for (const value of source) {
        const code = document.createElement(
            'code',
        );

        code.textContent = textValue(
            value,
        );

        container.appendChild(
            code,
        );
    }
}


/* ==========================================================================
   CONFIGURAÇÃO PERSISTIDA
   ========================================================================== */

function renderPersistedConfiguration(
    config,
) {
    setText(
        'configName',
        readPath(
            config,
            ['nome'],
            'Suricata Local',
        ),
    );

    setText(
        'configCaptureMode',
        formatCaptureMode(
            readPath(
                config,
                ['modo_captura'],
                '',
            ),
        ),
    );

    setText(
        'configOnboarding',
        formatBoolean(
            readPath(
                config,
                ['onboarding_concluido'],
                false,
            ),
            'Concluído',
            'Pendente',
        ),
    );

    setText(
        'configInstallation',
        formatBoolean(
            readPath(
                config,
                ['instalacao_concluida'],
                false,
            ),
            'Concluída',
            'Pendente',
        ),
    );

    setText(
        'configSuricataConfigured',
        formatBoolean(
            readPath(
                config,
                ['suricata_configurado'],
                false,
            ),
            'Sim',
            'Não',
        ),
    );

    setText(
        'configUpdatedAt',
        formatDate(
            readPath(
                config,
                ['atualizado_em'],
                null,
            ),
        ),
    );

    setText(
        'configWan',
        readPath(
            config,
            ['interface_wan'],
            '—',
        ),
    );

    setText(
        'configLan',
        readPath(
            config,
            ['interface_lan'],
            '—',
        ),
    );

    setText(
        'configMgmt',
        readPath(
            config,
            ['interface_mgmt'],
            '—',
        ),
    );

    setText(
        'configInternalDns',
        readPath(
            config,
            ['dns_interno'],
            '—',
        ),
    );

    setText(
        'configEtOpen',
        formatBoolean(
            readPath(
                config,
                ['instalar_et_open'],
                false,
            ),
            'Ativado',
            'Desativado',
        ),
    );

    setText(
        'configMoonShieldRules',
        formatBoolean(
            readPath(
                config,
                ['instalar_regras_moonshield'],
                true,
            ),
            'Ativadas',
            'Desativadas',
        ),
    );

    setText(
        'configYamlPath',
        readPath(
            config,
            ['yaml_path'],
            '/etc/suricata/suricata.yaml',
        ),
    );

    setText(
        'configEvePath',
        readPath(
            config,
            ['eve_path'],
            '/var/log/suricata/eve.json',
        ),
    );

    setText(
        'configCursorPath',
        readPath(
            config,
            ['cursor_path'],
            'var/cursors/suricata_eve.cursor',
        ),
    );

    renderChips(
        'configMonitoredInterfaces',
        safeArray(
            readPath(
                config,
                ['interfaces_monitoradas'],
                [],
            ),
        ),
        'Nenhuma',
    );

    renderCodeList(
        'configHomeNetList',
        safeArray(
            readPath(
                config,
                ['home_net'],
                [],
            ),
        ),
        'Nenhuma rede informada',
    );
}


/* ==========================================================================
   OBSERVADOR DO STATUS CENTRAL
   ========================================================================== */

function startConfigurationStatusObserver(
    config,
) {
    if (configurationStatusTimer) {
        return;
    }

    configurationStatusTimer = (
        window.setInterval(
            () => {
                if (
                    document.hidden
                    || !state.statusData
                ) {
                    return;
                }

                const signature = createOperationalSignature(
                    state.statusData,
                );

                if (
                    signature
                    && signature !== lastOperationalSignature
                ) {
                    lastOperationalSignature = signature;

                    renderConfigurationOperational(
                        state.statusData,
                        config,
                    );
                }
            },
            1500,
        )
    );

    window.addEventListener(
        'beforeunload',
        () => {
            if (configurationStatusTimer) {
                window.clearInterval(
                    configurationStatusTimer,
                );

                configurationStatusTimer = null;
            }
        },
        { once: true },
    );
}


function createOperationalSignature(
    payload,
) {
    try {
        const status = normalizeStatusPayload(
            payload,
        );

        const stack = safeObject(
            readPath(
                status,
                ['stack'],
                status,
            ),
        );

        return JSON.stringify({
            verificado_em: readPath(
                stack,
                ['verificado_em'],
                '',
            ),
            status: readPath(
                stack,
                ['status'],
                '',
            ),
            operacional: readPath(
                stack,
                ['operacional'],
                false,
            ),
            suricata: readPath(
                stack,
                ['suricata.status'],
                '',
            ),
            monitor: readPath(
                stack,
                ['monitor.status'],
                '',
            ),
            worker: readPath(
                stack,
                ['servicos.worker_tarefas.ativo'],
                false,
            ),
        });
    } catch {
        return '';
    }
}


/* ==========================================================================
   HELPERS VISUAIS
   ========================================================================== */

function normalizeStatusPayload(
    payload,
) {
    const raw = safeObject(
        payload,
    );

    const data = safeObject(
        readPath(
            raw,
            ['dados'],
            raw,
        ),
    );

    return data;
}


function setBinaryState(
    id,
    ok,
    okLabel,
    failLabel,
) {
    const element = $(
        id,
    );

    if (!element) {
        return;
    }

    element.textContent = (
        ok
            ? okLabel
            : failLabel
    );

    element.classList.toggle(
        'is-ok',
        ok,
    );

    element.classList.toggle(
        'is-warning',
        !ok,
    );
}


function renderComponentStatus(
    id,
    ok,
    label,
    detail,
    forcedState = null,
) {
    const card = $(
        id,
    );

    if (!card) {
        return;
    }

    const stateName = (
        forcedState
        || (
            ok
                ? 'ok'
                : 'error'
        )
    );

    card.classList.remove(
        'is-ok',
        'is-warning',
        'is-error',
    );

    card.classList.add(
        `is-${stateName}`,
    );

    const labelElement = card.querySelector(
        '[data-component-state]',
    );

    const detailElement = card.querySelector(
        '[data-component-detail]',
    );

    if (labelElement) {
        labelElement.textContent = (
            label || '—'
        );
    }

    if (detailElement) {
        detailElement.textContent = (
            detail || '—'
        );
    }
}


function updateConfigurationShellState(
    stateName,
) {
    const section = $(
        'section-configuration',
    );

    if (!section) {
        return;
    }

    section.classList.remove(
        'sp-config-state--ok',
        'sp-config-state--warning',
        'sp-config-state--error',
    );

    section.classList.add(
        `sp-config-state--${stateName}`,
    );
}
