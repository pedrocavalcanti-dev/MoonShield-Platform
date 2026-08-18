import { safeObject, readPath, formatCaptureMode, formatBoolean, formatDate, boolValue, safeArray, textValue } from '../nucleo/utilitarios.js';
import { setText, $ } from '../nucleo/dom.js';
import { applyChip } from '../nucleo/interface.js';

export function renderConfiguration(configuration) {
    const config = safeObject(configuration);

    setText('configName', readPath(config, ['nome'], 'Suricata Local'));
    setText('configCaptureMode', formatCaptureMode(readPath(config, ['modo_captura'], '')));
    setText('configOnboarding', formatBoolean(readPath(config, ['onboarding_concluido'], false), 'Concluído', 'Pendente'));
    setText('configInstallation', formatBoolean(readPath(config, ['instalacao_concluida'], false), 'Concluída', 'Pendente'));
    setText('configSuricataConfigured', formatBoolean(readPath(config, ['suricata_configurado'], false), 'Sim', 'Não'));
    setText('configUpdatedAt', formatDate(readPath(config, ['atualizado_em'], null)));
    setText('configWan', readPath(config, ['interface_wan'], '—'));
    setText('configLan', readPath(config, ['interface_lan'], '—'));
    setText('configMgmt', readPath(config, ['interface_mgmt'], '—'));
    setText('configInternalDns', readPath(config, ['dns_interno'], '—'));
    setText('configEtOpen', formatBoolean(readPath(config, ['instalar_et_open'], false), 'Ativado', 'Desativado'));
    setText('configMoonShieldRules', formatBoolean(readPath(config, ['instalar_regras_moonshield'], true), 'Ativadas', 'Desativadas'));
    setText('configYamlPath', readPath(config, ['yaml_path'], '/etc/suricata/suricata.yaml'));
    setText('configEvePath', readPath(config, ['eve_path'], '/var/log/suricata/eve.json'));
    setText('configCursorPath', readPath(config, ['cursor_path'], 'var/cursors/suricata_eve.cursor'));

    const ready = boolValue(readPath(config, ['pronto'], false), boolValue(readPath(config, ['suricata_instalado'], false)) && boolValue(readPath(config, ['suricata_configurado'], false)));
    applyChip('configReadyChip', ready ? 'ok' : 'warning', ready ? 'Pronta' : 'Pendente');

    renderChips('configMonitoredInterfaces', safeArray(readPath(config, ['interfaces_monitoradas'], [])), 'Nenhuma');
    renderCodeList('configHomeNetList', safeArray(readPath(config, ['home_net'], [])), 'Nenhuma rede informada');
}

export function renderTopology(topology, configuration) {
    const config = safeObject(configuration);
    const data = safeObject(topology);

    const wan = readPath(data, ['interface_wan', 'wan.nome', 'wan'], readPath(config, ['interface_wan'], 'WAN'));
    const lan = readPath(data, ['interface_lan', 'lan.nome', 'lan'], readPath(config, ['interface_lan'], 'LAN'));
    const homeNet = safeArray(readPath(data, ['home_net'], readPath(config, ['home_net'], [])));
    const monitored = safeArray(readPath(data, ['interfaces_monitoradas'], readPath(config, ['interfaces_monitoradas'], [])));

    setText('topologyWanLabel', wan || 'WAN');
    setText('topologyLanLabel', lan || 'LAN');
    setText('topologyCaptureMode', formatCaptureMode(readPath(config, ['modo_captura'], readPath(data, ['modo_captura'], ''))));
    setText('topologyHomeNet', homeNet.length ? homeNet.join(', ') : 'HOME_NET não informado');

    renderChips('topologyInterfaceChips', monitored, 'Nenhuma interface');
}

export function renderChips(containerId, values, emptyLabel = 'Nenhum') {
    const container = $(containerId);
    if (!container) return;

    container.innerHTML = '';
    if (!values.length) {
        const chip = document.createElement('span');
        chip.className = 'sp-interface-chip';
        chip.textContent = emptyLabel;
        container.appendChild(chip);
        return;
    }

    for (const value of values) {
        const chip = document.createElement('span');
        chip.className = 'sp-interface-chip';
        chip.textContent = textValue(value);
        container.appendChild(chip);
    }
}

export function renderCodeList(containerId, values, emptyLabel) {
    const container = $(containerId);
    if (!container) return;

    container.innerHTML = '';
    const source = values.length ? values : [emptyLabel];
    for (const value of source) {
        const code = document.createElement('code');
        code.textContent = textValue(value);
        container.appendChild(code);
    }
}