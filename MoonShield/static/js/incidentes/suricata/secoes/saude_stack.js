import { safeObject, readPath, boolValue, formatBoolean, formatBytes, numberValue, textValue, escapeHTML } from '../nucleo/utilitarios.js';
import { updateClassByPrefix, setText, $ } from '../nucleo/dom.js';
import { applyPill, applyChip, normalizeStatus, statusLabel } from '../nucleo/interface.js';

function updateStatusCard(cardId, config) {
    const card = $(cardId);
    if (!card) return;

    updateClassByPrefix(card, 'sp-status-card--', config.status);
    setText(config.stateId, statusLabel(config.status));
    setText(config.valueId, config.value);
    setText(config.detailId, config.detail);
    setText(config.metaId, config.meta);
}

export function renderSuricata(suricata, services, environment) {
    const service = safeObject(readPath(suricata, ['servico'], readPath(services, ['suricata'], {})));
    const installed = boolValue(readPath(suricata, ['instalado'], readPath(service, ['instalado'], false)));
    const active = boolValue(readPath(suricata, ['ativo'], readPath(service, ['ativo'], false)));
    const enabled = boolValue(readPath(service, ['habilitado'], false));
    const ready = boolValue(readPath(suricata, ['pronto'], active && installed));
    const version = readPath(suricata, ['versao'], readPath(environment, ['versao_suricata'], ''));
    const message = readPath(suricata, ['mensagem'], readPath(service, ['mensagem'], ''));

    const status = ready ? 'ok' : active ? 'warning' : 'error';

    updateStatusCard('cardSuricata', {
        status, stateId: 'cardSuricataState', valueId: 'cardSuricataValue', detailId: 'cardSuricataDetail', metaId: 'cardSuricataMeta',
        value: active ? 'Ativo' : installed ? 'Inativo' : 'Não instalado',
        detail: message || (active ? 'Serviço executando normalmente' : 'Serviço não está ativo'),
        meta: version ? `Suricata ${version}` : 'Versão indisponível',
    });

    applyPill('healthSuricataStatus', status);
    setText('healthSuricataMessage', message || 'Estado do serviço consultado');
    setText('healthSuricataInstalled', formatBoolean(installed));
    setText('healthSuricataActive', formatBoolean(active, 'Ativo', 'Inativo'));
    setText('healthSuricataEnabled', formatBoolean(enabled));
    setText('healthSuricataPid', readPath(service, ['pid'], '—'));
    setText('healthSuricataVersion', version || '—');
    setText('healthSuricataService', readPath(service, ['nome', 'servico'], 'suricata'));
}

export function renderMonitor(monitor, services) {
    const service = safeObject(readPath(monitor, ['servico'], readPath(services, ['monitor'], {})));
    const installed = boolValue(readPath(service, ['instalado'], false));
    const active = boolValue(readPath(monitor, ['ativo'], readPath(service, ['ativo'], false)));
    const reading = boolValue(readPath(monitor, ['lendo_eve'], false));
    const healthy = boolValue(readPath(monitor, ['saudavel'], active && reading));
    const message = readPath(monitor, ['mensagem'], readPath(service, ['mensagem'], ''));

    const status = healthy ? 'ok' : active ? 'warning' : 'error';

    updateStatusCard('cardMonitor', {
        status, stateId: 'cardMonitorState', valueId: 'cardMonitorValue', detailId: 'cardMonitorDetail', metaId: 'cardMonitorMeta',
        value: active ? 'Ativo' : 'Inativo',
        detail: message || (reading ? 'Monitor acompanhando o eve.json' : 'Monitor não está acompanhando o arquivo'),
        meta: reading ? 'Cursor acompanhando o EVE' : 'Leitura não confirmada',
    });

    applyPill('healthMonitorStatus', status);
    setText('healthMonitorMessage', message || 'Estado do monitor consultado');
    setText('healthMonitorInstalled', formatBoolean(installed));
    setText('healthMonitorActive', formatBoolean(active, 'Ativo', 'Inativo'));
    setText('healthMonitorReading', formatBoolean(reading));
    setText('healthMonitorHealthy', formatBoolean(healthy));
    setText('healthMonitorPid', readPath(service, ['pid'], '—'));
    setText('healthMonitorService', readPath(service, ['nome', 'servico'], 'moonshield-suricata-monitor'));
}

export function renderEve(suricata, monitor) {
    const eve = safeObject(readPath(monitor, ['eve'], readPath(suricata, ['eve'], {})));
    const exists = boolValue(readPath(eve, ['existe'], false));
    const readable = boolValue(readPath(eve, ['legivel'], false));
    const updating = boolValue(readPath(eve, ['atualizando'], false));
    const status = updating ? 'ok' : exists && readable ? 'warning' : 'error';
    const age = readPath(eve, ['idade_segundos'], null);
    const size = readPath(eve, ['tamanho'], null);
    const message = readPath(eve, ['mensagem'], '');

    updateStatusCard('cardEve', {
        status, stateId: 'cardEveState', valueId: 'cardEveValue', detailId: 'cardEveDetail', metaId: 'cardEveMeta',
        value: updating ? 'Atualizando' : exists ? 'Parado' : 'Ausente',
        detail: message || (updating ? 'Arquivo recebendo novos eventos' : 'Arquivo sem atualização recente'),
        meta: size !== null ? formatBytes(size) : 'Sem tamanho disponível',
    });

    applyPill('healthEveStatus', status);
    setText('healthEveMessage', message || 'Estado do arquivo consultado');
    setText('healthEveExists', formatBoolean(exists));
    setText('healthEveReadable', formatBoolean(readable));
    setText('healthEveUpdating', formatBoolean(updating));
    setText('healthEveSize', size !== null ? formatBytes(size) : '—');
    setText('healthEveAge', age !== null ? `${Math.round(numberValue(age))}s atrás` : '—');
    setText('healthEvePath', readPath(eve, ['caminho'], '—'));
}

export function renderCursor(monitor) {
    const cursor = safeObject(readPath(monitor, ['cursor'], {}));
    const exists = boolValue(readPath(cursor, ['existe'], false));
    const valid = boolValue(readPath(cursor, ['valido'], false));
    const following = boolValue(readPath(cursor, ['acompanhando'], false));
    const status = following ? 'ok' : exists && valid ? 'warning' : 'error';
    const message = readPath(cursor, ['mensagem'], '');

    applyPill('healthCursorStatus', status);
    setText('healthCursorMessage', message || 'Estado do cursor consultado');
    setText('healthCursorExists', formatBoolean(exists));
    setText('healthCursorValid', formatBoolean(valid));
    setText('healthCursorFollowing', formatBoolean(following));
    setText('healthCursorPosition', readPath(cursor, ['posicao'], '—'));

    const lag = readPath(cursor, ['atraso_bytes'], null);
    setText('healthCursorLag', lag !== null ? formatBytes(lag) : '—');
    setText('healthCursorPath', readPath(cursor, ['caminho'], '—'));
}

export function collectHealthChecks(stack) {
    const checks = [];
    const suricata = safeObject(readPath(stack, ['suricata'], {}));
    const monitor = safeObject(readPath(stack, ['monitor'], {}));
    const eve = safeObject(readPath(monitor, ['eve'], readPath(suricata, ['eve'], {})));
    const cursor = safeObject(readPath(monitor, ['cursor'], {}));

    checks.push({ title: 'Suricata ativo', message: readPath(suricata, ['mensagem'], ''), status: boolValue(readPath(suricata, ['ativo'], false)) ? 'ok' : 'error' });
    checks.push({ title: 'Monitor ativo', message: readPath(monitor, ['mensagem'], ''), status: boolValue(readPath(monitor, ['ativo'], false)) ? 'ok' : 'error' });
    checks.push({ title: 'EVE atualizando', message: readPath(eve, ['mensagem'], ''), status: boolValue(readPath(eve, ['atualizando'], false)) ? 'ok' : 'warning' });
    checks.push({ title: 'Cursor acompanhando', message: readPath(cursor, ['mensagem'], ''), status: boolValue(readPath(cursor, ['acompanhando'], false)) ? 'ok' : 'warning' });

    return checks;
}

export function renderStackChecks(stack, data) {
    const container = $('stackChecksList');
    if (!container) return;

    const checks = collectHealthChecks(stack);
    const errors = Array.isArray(readPath(stack, ['erros'], readPath(data, ['erros'], []))) ? readPath(stack, ['erros'], readPath(data, ['erros'], [])) : [];
    const warnings = Array.isArray(readPath(stack, ['avisos'], readPath(data, ['avisos'], []))) ? readPath(stack, ['avisos'], readPath(data, ['avisos'], [])) : [];

    for (const message of warnings) checks.push({ title: 'Aviso', message: textValue(message), status: 'warning' });
    for (const message of errors) checks.push({ title: 'Erro', message: textValue(message), status: 'error' });

    container.innerHTML = '';
    for (const check of checks) {
        const status = normalizeStatus(check.status);
        const element = document.createElement('div');
        element.className = `sp-stack-check sp-stack-check--${status}`;
        element.innerHTML = `
            <span class="sp-stack-check__status"></span>
            <div>
                <strong>${escapeHTML(check.title)}</strong>
                <span>${escapeHTML(check.message || statusLabel(status))}</span>
            </div>
        `;
        container.appendChild(element);
    }

    const overall = checks.some((item) => normalizeStatus(item.status) === 'error') ? 'error' : checks.some((item) => normalizeStatus(item.status) === 'warning') ? 'warning' : 'ok';
    applyChip('stackGeneralStatus', overall);
}

export function renderRules(suricata, stack) {
    const rules = safeObject(readPath(suricata, ['regras'], readPath(stack, ['regras'], {})));
    const moon = safeObject(readPath(rules, ['moonshield', 'regras_moonshield'], {}));
    const et = safeObject(readPath(rules, ['et_open', 'etopen'], {}));

    const moonInstalled = boolValue(readPath(moon, ['instaladas', 'instalado'], readPath(rules, ['moonshield_instalado'], false)));
    const etInstalled = boolValue(readPath(et, ['instalado'], readPath(rules, ['et_open_instalado'], false)));
    const totalRules = readPath(rules, ['total_regras', 'total'], readPath(moon, ['total'], null));

    const status = moonInstalled ? (etInstalled ? 'ok' : 'warning') : 'error';

    updateStatusCard('cardRules', {
        status, stateId: 'cardRulesState', valueId: 'cardRulesValue', detailId: 'cardRulesDetail', metaId: 'cardRulesMeta',
        value: moonInstalled ? 'Carregadas' : 'Incompletas',
        detail: moonInstalled ? 'Regras MoonShield disponíveis' : 'Regras MoonShield não confirmadas',
        meta: totalRules !== null ? `${numberValue(totalRules)} regras` : etInstalled ? 'MoonShield + ET Open' : 'Pacotes incompletos',
    });
}