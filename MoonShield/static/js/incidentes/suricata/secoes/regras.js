import { safeObject, readPath, boolValue, formatBoolean, formatDate } from '../nucleo/utilitarios.js';
import { setText, setHidden, $ } from '../nucleo/dom.js';
import { applyPill, applyChip, iconSVG } from '../nucleo/interface.js';

export function initRegras(onConfirmTask) {
    $('btnUpdateAllRules')?.addEventListener('click', () => {
        onConfirmTask({
            tipo: 'atualizacao_regras',
            parametros: { atualizar_et: true, atualizar_moonshield: true, validar_depois: true, reiniciar_depois: false },
            title: 'Atualizar todas as regras?',
            text: 'O MoonShield atualizará ET Open e reaplicará as regras MoonShield.',
            details: 'A operação pode levar alguns minutos e exige execução pelo worker do Suricata.'
        });
    });

    $('btnUpdateMoonRules')?.addEventListener('click', () => {
        onConfirmTask({
            tipo: 'atualizacao_regras',
            parametros: { atualizar_et: false, atualizar_moonshield: true, validar_depois: true, reiniciar_depois: false },
            title: 'Reaplicar regras MoonShield?',
            text: 'As regras locais do MoonShield serão copiadas novamente e validadas.',
        });
    });

    $('btnUpdateEtRules')?.addEventListener('click', () => {
        onConfirmTask({
            tipo: 'atualizacao_regras',
            parametros: { atualizar_et: true, atualizar_moonshield: false, validar_depois: true, reiniciar_depois: false },
            title: 'Atualizar ET Open?',
            text: 'O suricata-update será executado para atualizar as assinaturas comunitárias.',
        });
    });

    $('btnValidateRules')?.addEventListener('click', () => {
        onConfirmTask({
            tipo: 'validacao',
            parametros: {},
            title: 'Validar configuração?',
            text: 'O MoonShield verificará o YAML e executará a validação técnica disponível.',
        });
    });
}

export function renderRulesSection(suricata, stack) {
    const rules = safeObject(readPath(suricata, ['regras'], readPath(stack, ['regras'], {})));
    const moon = safeObject(readPath(rules, ['moonshield', 'regras_moonshield'], {}));
    const et = safeObject(readPath(rules, ['et_open', 'etopen'], {}));
    const updater = safeObject(readPath(rules, ['suricata_update', 'updater'], {}));
    const validation = safeObject(readPath(suricata, ['configuracao.validacao', 'configuracao.validacao_suricata'], readPath(stack, ['validacao'], {})));

    const moonInstalled = boolValue(readPath(moon, ['instaladas', 'instalado'], false));
    const moonReferenced = boolValue(readPath(moon, ['referenciadas', 'referenciado'], false));
    const etInstalled = boolValue(readPath(et, ['instalado'], false));
    const updaterInstalled = boolValue(readPath(updater, ['instalado'], readPath(rules, ['suricata_update_instalado'], false)));

    applyPill('rulesMoonStatus', moonInstalled && moonReferenced ? 'ok' : moonInstalled ? 'warning' : 'error');
    applyPill('rulesEtStatus', etInstalled ? 'ok' : 'warning');

    setText('rulesMoonFile', readPath(moon, ['arquivo', 'caminho'], '—'));
    setText('rulesMoonInstalled', formatBoolean(moonInstalled));
    setText('rulesMoonReferenced', formatBoolean(moonReferenced));
    setText('rulesMoonCount', readPath(moon, ['total', 'quantidade'], '—'));

    setText('rulesUpdaterInstalled', formatBoolean(updaterInstalled));
    setText('rulesEtInstalled', formatBoolean(etInstalled));
    setText('rulesEtUpdatedAt', formatDate(readPath(et, ['atualizado_em', 'ultima_atualizacao'], null)));
    setText('rulesEtSummary', readPath(et, ['mensagem'], etInstalled ? 'Disponível' : 'Não confirmado'));

    const validationSuccess = boolValue(readPath(validation, ['sucesso', 'valido'], false));
    const hasValidation = Object.keys(validation).length > 0 || readPath(validation, ['mensagem'], null) !== null;

    if (!hasValidation) {
        applyChip('rulesValidationChip', 'pending', 'Pendente');
        return;
    }

    const status = validationSuccess ? 'ok' : 'error';
    applyChip('rulesValidationChip', status, validationSuccess ? 'Válida' : 'Inválida');

    const icon = $('rulesValidationIcon');
    if (icon) {
        icon.className = `sp-validation-state__icon sp-validation-state__icon--${status}`;
        icon.innerHTML = validationSuccess ? iconSVG('check', 22) : '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="m9 9 6 6M15 9l-6 6"/></svg>';
    }

    setText('rulesValidationTitle', validationSuccess ? 'Configuração validada' : 'Falha na validação');
    setText('rulesValidationText', readPath(validation, ['mensagem'], validationSuccess ? 'O Suricata aceitou o arquivo de configuração.' : 'O arquivo de configuração possui erros.'));

    const output = readPath(validation, ['saida', 'stdout', 'stderr', 'detalhes'], '');
    if (output) {
        setHidden('rulesValidationOutput', false);
        setText('rulesValidationTextOutput', typeof output === 'string' ? output : JSON.stringify(output, null, 2));
    }
}