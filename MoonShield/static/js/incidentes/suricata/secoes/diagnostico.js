import { fetchJSON, unwrapPayload, apiUrl, handleError } from '../nucleo/api.js';
import { state } from '../nucleo/estado.js';
import { setButtonLoading, setText, $ } from '../nucleo/dom.js';
import { applyChip, iconSVG, statusLabel } from '../nucleo/interface.js';
import { safeObject, readPath, safeArray, numberValue, boolValue, textValue, formatDate, escapeHTML } from '../nucleo/utilitarios.js';
import { showToast } from '../componentes/notificacoes.js';

export function initDiagnostico(onSuccess) {
    const buttons = [$('btnRunDiagnosticTop'), $('btnRunDiagnosticHero'), $('btnRunDiagnostic')].filter(Boolean);
    buttons.forEach((button) => {
        button.addEventListener('click', () => runDiagnostic(button, onSuccess));
    });
}

export async function runDiagnostic(button, onSuccess) {
    if (state.isRunningDiagnostic) return;
    state.isRunningDiagnostic = true;

    const buttons = [$('btnRunDiagnosticTop'), $('btnRunDiagnosticHero'), $('btnRunDiagnostic')].filter(Boolean);
    buttons.forEach((item) => setButtonLoading(item, true));
    applyChip('diagnosticGeneralChip', 'pending', 'Executando');

    try {
        const payload = await fetchJSON(apiUrl('diagnostico'), { timeout: 120000 });
        const data = unwrapPayload(payload);
        
        state.diagnosticData = data;
        renderDiagnostic(data);

        if (onSuccess) onSuccess();
        showToast('Diagnóstico concluído.', 'ok');
    } catch (error) {
        applyChip('diagnosticGeneralChip', 'error', 'Falhou');
        handleError(error);
    } finally {
        state.isRunningDiagnostic = false;
        buttons.forEach((item) => setButtonLoading(item, false));
    }
}

export function renderDiagnostic(data) {
    const diagnostic = safeObject(readPath(data, ['diagnostico'], data));
    const result = safeObject(readPath(diagnostic, ['resultado'], diagnostic));
    const summary = safeObject(readPath(data, ['resumo'], readPath(diagnostic, ['resumo'], {})));
    const actions = safeArray(readPath(data, ['acoes', 'acoes_recomendadas'], readPath(diagnostic, ['acoes_recomendadas'], [])));
    const items = safeArray(readPath(result, ['itens', 'checks'], readPath(diagnostic, ['itens', 'checks'], [])));

    const total = numberValue(readPath(summary, ['total_checks', 'total'], items.length), items.length);
    const ok = numberValue(readPath(summary, ['total_ok', 'ok'], items.filter(isCheckOk).length));
    const warnings = numberValue(readPath(summary, ['total_avisos', 'avisos'], items.filter(isCheckWarning).length));
    const critical = numberValue(readPath(summary, ['total_criticos', 'falhas_criticas'], items.filter(isCheckCriticalFailure).length));

    setText('diagnosticTotal', total);
    setText('diagnosticOk', ok);
    setText('diagnosticWarnings', warnings);
    setText('diagnosticCritical', critical);

    const ready = boolValue(readPath(summary, ['pronto'], critical === 0));
    const status = ready ? (warnings > 0 ? 'warning' : 'ok') : 'error';
    applyChip('diagnosticGeneralChip', status, ready ? (warnings > 0 ? 'Com avisos' : 'Saudável') : 'Crítico');

    renderDiagnosticGroups(items);
    renderRecommendedActions(actions);
    setText('healthLastDiagnostic', `Último diagnóstico: ${formatDate(new Date())}`);
}

export function isCheckOk(item) {
    return boolValue(readPath(item, ['sucesso', 'ok'], false));
}

export function isCheckWarning(item) {
    return !isCheckOk(item) && !boolValue(readPath(item, ['critico'], false));
}

export function isCheckCriticalFailure(item) {
    return !isCheckOk(item) && boolValue(readPath(item, ['critico'], false));
}

export function renderDiagnosticGroups(items) {
    const container = $('diagnosticGroups');
    if (!container) return;

    container.innerHTML = '';
    if (!items.length) {
        container.innerHTML = `<div class="sp-empty-state"><span class="sp-empty-state__icon">${iconSVG('pulse', 22)}</span><div><strong>Nenhum check retornado</strong><span>A API não retornou itens de diagnóstico.</span></div></div>`;
        return;
    }

    const groups = new Map();
    for (const item of items) {
        const group = textValue(readPath(item, ['grupo'], 'Outros'), 'Outros');
        if (!groups.has(group)) groups.set(group, []);
        groups.get(group).push(item);
    }

    for (const [groupName, checks] of groups.entries()) {
        const groupElement = document.createElement('div');
        groupElement.className = 'sp-diagnostic-group';
        const failures = checks.filter((item) => !isCheckOk(item)).length;
        const groupStatus = checks.some(isCheckCriticalFailure) ? 'error' : failures > 0 ? 'warning' : 'ok';

        groupElement.innerHTML = `
            <div class="sp-diagnostic-group__head">
                <div><span class="sp-status-dot sp-status-dot--${groupStatus}"></span><strong>${escapeHTML(groupName)}</strong></div>
                <span class="sp-status-pill sp-status-pill--${groupStatus}">${checks.length - failures}/${checks.length}</span>
            </div>
            <div class="sp-diagnostic-group__body"></div>
        `;

        const body = groupElement.querySelector('.sp-diagnostic-group__body');
        for (const check of checks) {
            const status = isCheckOk(check) ? 'ok' : boolValue(readPath(check, ['critico'], false)) ? 'error' : 'warning';
            const element = document.createElement('div');
            element.className = `sp-diagnostic-check sp-diagnostic-check--${status}`;
            element.innerHTML = `
                <span class="sp-diagnostic-check__dot"></span>
                <span class="sp-diagnostic-check__copy">
                    <strong>${escapeHTML(readPath(check, ['titulo', 'nome', 'id'], 'Check'))}</strong>
                    <span>${escapeHTML(readPath(check, ['mensagem', 'detalhe'], statusLabel(status)))}</span>
                </span>
                <span class="sp-status-pill sp-status-pill--${status}">${statusLabel(status)}</span>
            `;
            body.appendChild(element);
        }
        container.appendChild(groupElement);
    }
}

export function renderRecommendedActions(actions) {
    const container = $('recommendedActions');
    if (!container) return;

    container.innerHTML = '';
    if (!actions.length) {
        container.innerHTML = `<div class="sp-empty-state sp-empty-state--compact"><span class="sp-empty-state__icon">${iconSVG('check', 20)}</span><div><strong>Nenhuma ação necessária</strong><span>Não foram encontradas recomendações pendentes.</span></div></div>`;
        return;
    }

    for (const action of actions) {
        const element = document.createElement('div');
        element.className = 'sp-recommended-action';
        element.innerHTML = `
            <span class="sp-recommended-action__priority">${escapeHTML(readPath(action, ['prioridade'], '•'))}</span>
            <span class="sp-recommended-action__copy">
                <strong>${escapeHTML(readPath(action, ['titulo', 'grupo'], 'Ação recomendada'))}</strong>
                <span>${escapeHTML(readPath(action, ['acao', 'mensagem'], 'Revise este item.'))}</span>
            </span>
        `;
        container.appendChild(element);
    }
}