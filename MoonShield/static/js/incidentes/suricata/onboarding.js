/**
 * MOONSHIELD — SURICATA ONBOARDING v3
 * Script otimizado, modular, com proteção de escopo e feedback visual completo.
 */

'use strict';

document.addEventListener('DOMContentLoaded', () => {
    // ═══════════════════════════════════════════════════════════
    // CONTROLE DE TEMA
    // ═══════════════════════════════════════════════════════════
    const themeToggle = document.getElementById('themeToggle');
    if (themeToggle) {
        const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
        themeToggle.checked = currentTheme === 'dark';
        
        themeToggle.addEventListener('change', (e) => {
            const newTheme = e.target.checked ? 'dark' : 'light';
            document.documentElement.setAttribute('data-theme', newTheme);
            localStorage.setItem('moonshield_theme', newTheme);
        });
    }

    // ═══════════════════════════════════════════════════════════
    // ESTADO E CONFIGURAÇÕES
    // ═══════════════════════════════════════════════════════════
    const CFG = window.MS_SURICATA || {};
    const TOTAL_STEPS = 6;
    const POLL_INTERVAL_MS = 2000;
    const LOG_POLL_INTERVAL_MS = 1500;
    const MAX_RENDERED_LOGS = 500;

    const state = {
        currentStep: 1,
        maxUnlockedStep: 1,
        environmentReady: false,
        interfaces: [],
        homeNet: [],
        autoHomeNetBase: "",
        selectedInterfaces: new Set(),
        configuration: normaliseObject(CFG.configuracao),
        activeTask: null,
        taskRunning: false,
        taskFinished: false,
        taskSucceeded: false,
        taskStartedAt: null,
        elapsedTimer: null,
        taskPollTimer: null,
        logPollTimer: null,
        lastLogOffset: 0,
        renderedLogKeys: new Set(),
        leavingAllowed: false,
        logsVisible: true,
    };

    const el = id => document.getElementById(id);
    const all = selector => Array.from(document.querySelectorAll(selector));

    // Inicialização
    init();

    function init() {
        // Saudação
        const name = CFG.usuario?.nome || CFG.usuario?.username || 'operador';
        if (el('greetName')) el('greetName').textContent = name;

        // Hidratação
        applyConfigurationToForm(state.configuration);
        updateReview();
        updateSidebarSystem('pending', 'Aguardando verificação');

        // Binds
        bindNavigation();
        bindEnvironmentActions();
        bindNetworkActions();
        bindProtectionActions();
        bindReviewActions();
        bindInstallationActions();
        bindLeaveProtection();

        // Sempre hidrata o ambiente ao carregar a página. Isso evita que valores
        // brutos renderizados pelo backend (ex.: ResultadoEtapa(...)) permaneçam
        // visíveis quando o usuário atualiza o navegador já dentro do wizard.
        loadEnvironment(false).catch(() => {});
    }

    // ═══════════════════════════════════════════════════════════
    // NAVEGAÇÃO
    // ═══════════════════════════════════════════════════════════
    function bindNavigation() {
        el('btnStep1Next')?.addEventListener('click', async () => {
            unlockStep(2);
            goToStep(2);
            await loadEnvironment(true);
        });

        el('btnStep2Next')?.addEventListener('click', async () => {
            if (!state.environmentReady) {
                showEnvironmentError('Conclua a verificação do ambiente antes de continuar.');
                return;
            }
            unlockStep(3);
            goToStep(3);
            if (!state.interfaces.length) await detectInterfaces();
        });

        el('btnStep3Next')?.addEventListener('click', async () => {
            clearNetworkError();
            const validation = validateNetworkForm();
            if (!validation.ok) {
                showNetworkError(validation.errors.join('<br>'));
                return;
            }
            try {
                await saveConfiguration({ quiet: true });
                unlockStep(4);
                goToStep(4);
            } catch (error) {
                showNetworkError(error.message || 'Não foi possível salvar a configuração de rede.');
            }
        });

        el('btnStep4Next')?.addEventListener('click', async () => {
            const paths = validateProtectionForm();
            if (!paths.ok) {
                showToast(paths.errors.join('\n'), 'error');
                return;
            }
            try {
                await saveConfiguration({ quiet: true });
                updateReview();
                unlockStep(5);
                goToStep(5);
            } catch (error) {
                showToast(error.message || 'Não foi possível salvar as opções de proteção.', 'error');
            }
        });

        all('[data-back]').forEach(btn => {
            btn.addEventListener('click', () => goToStep(Number(btn.dataset.back || 1)));
        });

        all('[data-edit-step]').forEach(btn => {
            btn.addEventListener('click', () => goToStep(Number(btn.dataset.editStep || 1)));
        });

        all('.step-item').forEach(btn => {
            btn.addEventListener('click', () => {
                const target = Number(btn.dataset.step || 1);
                if (target <= state.maxUnlockedStep && !btn.classList.contains('disabled')) {
                    goToStep(target);
                }
            });
        });
    }

    function goToStep(step) {
        if (!Number.isInteger(step) || step < 1 || step > TOTAL_STEPS || step > state.maxUnlockedStep) return;
        all('.step-page').forEach(panel => panel.classList.toggle('active', Number(panel.dataset.step) === step));
        state.currentStep = step;
        updateNavigation(step);
        const content = document.querySelector('.app-content');
        if (content) content.scrollTo({ top: 0, behavior: 'smooth' });
    }

    function unlockStep(step) {
        state.maxUnlockedStep = Math.max(state.maxUnlockedStep, step);
        all('.step-item').forEach(item => {
            const num = Number(item.dataset.step || 1);
            item.classList.toggle('disabled', num > state.maxUnlockedStep);
        });
    }

    function updateNavigation(current) {
        all('.step-item').forEach(item => {
            const num = Number(item.dataset.step || 1);
            item.classList.remove('active', 'completed');
            if (num < current) item.classList.add('completed');
            if (num === current) item.classList.add('active');
        });
    }

    // ═══════════════════════════════════════════════════════════
    // AMBIENTE
    // ═══════════════════════════════════════════════════════════
    function bindEnvironmentActions() {
        el('btnRefreshEnvironment')?.addEventListener('click', () => loadEnvironment(true));
    }

    async function loadEnvironment(force = false) {
        setEnvironmentLoading();
        clearEnvironmentError();

        try {
            const separator = CFG.urls?.status?.includes('?') ? '&' : '?';
            const url = `${CFG.urls.status}${separator}diagnostico=0${force ? '&refresh=1' : ''}`;
            const payload = await requestJSON(url, { method: 'GET' });
            const data = unwrapData(payload);

            const stack = normaliseObject(data.stack || data.dados?.stack || data.status || data);
            const env = normaliseObject(stack.ambiente || data.ambiente || stack.environment || stack);
            const sys = normaliseObject(env.sistema || stack.sistema || {});
            const suri = normaliseSuricataStatus(stack.suricata ?? data.suricata ?? env.suricata ?? {});

            const linux = readBoolean(sys, ['linux', 'eh_linux', 'is_linux'], false);
            const root = readBoolean(sys, ['root', 'privilegios', 'privilegiado', 'is_root'], false);
            const installed = readBoolean(suri, ['instalado'], false);
            const version = firstText(suri.versao, suri.version, env.versao_suricata, data.versao_suricata);

            const checks = {
                linux: { ok: linux, warning: !linux, value: linux ? 'Linux detectado' : 'Linux necessário' },
                privilegios: { ok: root, warning: !root, value: root ? 'Privilégios disponíveis' : 'Execução privilegiada necessária' },
                suricata: {
                    ok: true,
                    warning: false,
                    value: installed ? (version ? `Suricata ${version}` : 'Suricata instalado') : 'Será instalado automaticamente'
                },
            };

            Object.entries(checks).forEach(([name, check]) => setEnvironmentCheck(name, check));

            const errors = [];
            if (!linux) errors.push('A instalação precisa ser executada em um servidor Linux.');
            if (linux && !root) errors.push('A execução deve possuir privilégios administrativos.');

            state.environmentReady = errors.length === 0;
            if (el('btnStep2Next')) el('btnStep2Next').disabled = !state.environmentReady;

            if (state.environmentReady) {
                const summary = installed
                    ? (version ? `Suricata ${version} detectado. O ambiente está pronto para continuar.` : 'Suricata detectado. O ambiente está pronto para continuar.')
                    : 'Os pré-requisitos foram validados. O Suricata será instalado durante a execução.';
                setEnvironmentSummary('success', 'Ambiente pronto para continuar', summary);
                updateSidebarSystem('ok', installed ? (version ? `Suricata ${version}` : 'Suricata detectado') : 'Ambiente compatível');
            } else {
                setEnvironmentSummary('error', 'O ambiente possui bloqueios', errors.join(' '));
                showEnvironmentError(errors.join('\n'));
                updateSidebarSystem('error', 'Incompatível');
            }
        } catch (error) {
            state.environmentReady = false;
            const message = safeUserMessage(error?.message, 'Erro ao consultar o ambiente do servidor.');
            setEnvironmentSummary('error', 'Falha ao verificar ambiente', message);
            showEnvironmentError(message);
            updateSidebarSystem('error', 'Falha na verificação');
            if (el('btnStep2Next')) el('btnStep2Next').disabled = true;
        }
    }

    function setEnvironmentLoading() {
        setEnvironmentSummary('loading', 'Verificando ambiente...', 'Aguarde enquanto coletamos os pré-requisitos.');
        ['linux', 'privilegios', 'suricata'].forEach(name => setEnvironmentCheck(name, { pending: true, value: 'Verificando...' }));
        if (el('btnStep2Next')) el('btnStep2Next').disabled = true;
    }

    function setEnvironmentSummary(type, title, text) {
        const icon = el('environmentSummaryIcon');
        if (icon) {
            icon.className = type === 'loading' ? 'spinner' : '';
            icon.innerHTML = type === 'loading' ? '' : iconSvg(type);
            icon.style.color = type === 'success' ? 'var(--ok)' : type === 'error' ? 'var(--danger)' : type === 'warning' ? 'var(--warn)' : 'inherit';
            icon.style.border = type === 'loading' ? '' : 'none';
        }
        setText('environmentSummaryTitle', safeDisplayText(title, 'Verificação do ambiente'));
        setText('environmentSummaryText', safeDisplayText(text, ''));
    }

    function setEnvironmentCheck(name, check) {
        const row = document.querySelector(`[data-check="${cssEscape(name)}"]`);
        if (!row) return;

        // Compatibilidade com as duas versões do HTML do onboarding.
        const status = row.querySelector('.info-card__icon, .ob-check-row__status');
        const value = row.querySelector('.ob-check-row__value, [id^="check"]');

        if (status) {
            status.style.background = 'transparent';
            status.classList.remove(
                'ob-check-row__status--pending',
                'ob-check-row__status--ok',
                'ob-check-row__status--warning',
                'ob-check-row__status--error'
            );

            if (check.pending) {
                status.innerHTML = '<span class="spinner"></span>';
                status.classList.add('ob-check-row__status--pending');
                status.style.color = '';
            } else if (check.ok) {
                status.innerHTML = iconSvg('check');
                status.classList.add('ob-check-row__status--ok');
                status.style.color = 'var(--ok)';
            } else if (check.warning) {
                status.innerHTML = iconSvg('warning');
                status.classList.add('ob-check-row__status--warning');
                status.style.color = 'var(--warn)';
            } else {
                status.innerHTML = iconSvg('error');
                status.classList.add('ob-check-row__status--error');
                status.style.color = 'var(--danger)';
            }
        }

        if (value) value.textContent = safeDisplayText(check.value, '—');
    }

    // ═══════════════════════════════════════════════════════════
    // REDE E INTERFACES
    // ═══════════════════════════════════════════════════════════
    function bindNetworkActions() {
        el('btnDetectInterfaces')?.addEventListener('click', detectInterfaces);
        el('btnAddHomeNet')?.addEventListener('click', addHomeNetFromInput);

        el('fieldHomeNet')?.addEventListener('keydown', event => {
            if (event.key === 'Enter' || event.key === ',') {
                event.preventDefault();
                addHomeNetFromInput();
            }
        });

        ['modoCaptura', 'fieldWan', 'fieldLan', 'fieldMgmt'].forEach(nameOrId => {
            const els = document.querySelectorAll(`[name="${nameOrId}"], #${nameOrId}`);
            els.forEach(element => {
                element.addEventListener('change', () => {
                    syncMonitoredInterfacesForMode();
                    renderMonitoredInterfaces(state.interfaces);
                    clearNetworkError();
                });
            });
        });

        el('fieldDns')?.addEventListener('change', clearNetworkError);
        el('fieldDns')?.addEventListener('input', clearNetworkError);
    }

    async function detectInterfaces() {
        const button = el('btnDetectInterfaces');
        setButtonLoading(button, true);
        clearNetworkError();
        renderInterfacesLoading();

        try {
            const payload = await requestJSON(CFG.urls.detectarInterfaces, { method: 'GET' });
            const data = unwrapData(payload);
            const candidates = data.topologia?.interfaces || data.interfaces || [];

            const seen = new Set();
            state.interfaces = [];

            for (const item of candidates) {
                const obj = typeof item === 'string' ? { nome: item } : (item || {});
                const nome = firstText(obj.nome, obj.name, obj.interface);
                
                if (!nome || seen.has(nome) || nome === 'lo') continue;
                seen.add(nome);

                const ipv4 = firstText(obj.ipv4, obj.ip);
                const cidr = firstText(obj.cidr, obj.ipv4_cidr);
                
                state.interfaces.push({
                    nome,
                    ipv4: ipv4.includes('/') ? ipv4.split('/')[0] : ipv4,
                    cidr,
                    mac: firstText(obj.mac),
                    estado: firstText(obj.estado, obj.state, 'detectada'),
                });
            }

            if (!state.interfaces.length) throw new Error('Nenhuma interface de rede útil detectada.');

            populateInterfaceSelects(state.interfaces);
            initialiseHomeNetBaseFromCurrentSelection();
            syncMonitoredInterfacesForMode({ preservePersonalized: true });
            renderHomeNetTokens();
            renderMonitoredInterfaces(state.interfaces);

            showToast(`${state.interfaces.length} interface(s) detectada(s).`, 'success');
        } catch (error) {
            state.interfaces = [];
            renderInterfacesError(error.message);
            showNetworkError(error.message);
        } finally {
            setButtonLoading(button, false);
        }
    }

    function populateInterfaceSelects(interfaces) {
        for (const id of ['fieldWan', 'fieldLan', 'fieldMgmt']) {
            const select = el(id);
            if (!select) continue;
            const prev = select.value;
            select.innerHTML = `<option value="">${id === 'fieldMgmt' ? 'Nenhuma' : 'Selecione...'}</option>`;
            
            for (const item of interfaces) {
                const opt = document.createElement('option');
                opt.value = item.nome;
                opt.textContent = `${item.nome}${item.cidr ? ` · ${item.cidr}` : ''}`;
                select.appendChild(opt);
            }
            if (interfaces.some(i => i.nome === prev)) select.value = prev;
        }
    }

    function getInterfaceNetwork(name) {
        const item = state.interfaces.find(i => i.nome === name);
        if (!item || !item.cidr || !isValidCidr(item.cidr)) return '';
        return networkFromCidr(item.cidr);
    }

    function initialiseHomeNetBaseFromCurrentSelection() {
        const lan = el('fieldLan')?.value || '';
        const net = getInterfaceNetwork(lan);
        if (!net) {
            state.autoHomeNetBase = '';
            return;
        }
        state.autoHomeNetBase = net;
        if (!state.homeNet.includes(net)) state.homeNet.push(net);
    }

    function syncMonitoredInterfacesForMode({ preservePersonalized = false } = {}) {
        const mode = getCaptureMode();
        const wan = el('fieldWan')?.value || '';
        const lan = el('fieldLan')?.value || '';
        const mgmt = el('fieldMgmt')?.value || '';

        if (mode === 'lan') {
            state.selectedInterfaces = new Set([lan].filter(Boolean));
        } else if (mode === 'lan_wan') {
            state.selectedInterfaces = new Set([lan, wan].filter(Boolean));
        }

        if (mgmt) state.selectedInterfaces.delete(mgmt);
        
        const avail = new Set(state.interfaces.map(i => i.nome));
        state.selectedInterfaces = new Set(Array.from(state.selectedInterfaces).filter(n => avail.has(n)));
    }

    function renderMonitoredInterfaces(interfaces) {
        const container = el('interfacesMonitoradasList');
        if (!container) return;
        container.innerHTML = '';
        
        const mode = getCaptureMode();
        const manual = mode === 'personalizado';
        const mgmt = el('fieldMgmt')?.value || '';

        if (!interfaces.length) {
            container.innerHTML = '<div style="padding:16px; text-align:center; color:var(--text-muted);">Nenhuma interface</div>';
            return;
        }

        for (const item of interfaces) {
            const isMgmt = mgmt && item.nome === mgmt;
            const disabled = !manual || isMgmt;
            const checked = state.selectedInterfaces.has(item.nome) && !isMgmt;

            const label = document.createElement('label');
            label.className = 'selectable-card';
            label.style.padding = '12px 16px';
            label.style.opacity = disabled ? '0.6' : '1';

            label.innerHTML = `
                <input type="checkbox" value="${escapeHtml(item.nome)}" ${checked ? 'checked' : ''} ${disabled ? 'disabled' : ''}>
                <div class="selectable-card__content" style="flex:1;">
                    <span class="selectable-card__title" style="margin-bottom:0;">${escapeHtml(item.nome)} ${isMgmt ? '<span class="selectable-card__badge" style="color:var(--warn)">(Gerência)</span>' : ''}</span>
                    <span class="selectable-card__desc">${escapeHtml(item.cidr || item.ipv4 || '')}</span>
                </div>
            `;

            const input = label.querySelector('input');
            input?.addEventListener('change', () => {
                if (getCaptureMode() !== 'personalizado') {
                    syncMonitoredInterfacesForMode();
                    renderMonitoredInterfaces(state.interfaces);
                    return;
                }
                if (input.checked) state.selectedInterfaces.add(input.value);
                else state.selectedInterfaces.delete(input.value);
                clearNetworkError();
            });
            container.appendChild(label);
        }
    }

    function renderInterfacesLoading() {
        const container = el('interfacesMonitoradasList');
        if (container) container.innerHTML = '<div style="text-align:center; padding:20px;"><span class="spinner"></span></div>';
    }

    function renderInterfacesError(message) {
        const container = el('interfacesMonitoradasList');
        if (container) container.innerHTML = `<div class="alert alert--error" style="margin:0;"><div class="alert__icon">${iconSvg('error')}</div><div class="alert__content"><div class="alert__message">${escapeHtml(message)}</div></div></div>`;
    }

    function addHomeNetFromInput() {
        const input = el('fieldHomeNet');
        if (!input) return;
        const values = input.value.split(',').map(v => v.trim()).filter(Boolean);
        if (!values.length) return;

        const invalid = values.filter(v => !isValidCidr(v));
        if (invalid.length) {
            showNetworkError(`CIDR inválido: ${invalid.join(', ')}`);
            return;
        }

        for (const value of values) {
            const net = networkFromCidr(value);
            if (net && !state.homeNet.includes(net)) state.homeNet.push(net);
        }

        input.value = '';
        renderHomeNetTokens();
        clearNetworkError();
    }

    function renderHomeNetTokens() {
        const container = el('homeNetTokens');
        if (!container) return;
        container.innerHTML = '';

        for (const network of state.homeNet) {
            const token = document.createElement('div');
            token.style.cssText = 'display:flex; align-items:center; gap:8px; padding:6px 12px; font-size:12px; background:var(--bg-secondary); border-radius:6px; border:1px solid var(--border);';
            const isBase = state.autoHomeNetBase && network === state.autoHomeNetBase;

            if (isBase) {
                token.innerHTML = `<span style="font-weight:600;">${escapeHtml(network)}</span><span style="color:var(--text-muted);">LAN</span>`;
            } else {
                token.innerHTML = `
                    <span style="font-weight:600;">${escapeHtml(network)}</span>
                    <button type="button" style="cursor:pointer; color:var(--text-muted); font-size:16px; padding:0 4px; border:0; background:none; line-height:1;" aria-label="Remover">&times;</button>
                `;
                token.querySelector('button')?.addEventListener('click', () => {
                    state.homeNet = state.homeNet.filter(n => n !== network);
                    renderHomeNetTokens();
                });
            }
            container.appendChild(token);
        }
    }

    function validateNetworkForm() {
        const input = el('fieldHomeNet');
        if (input?.value.trim()) addHomeNetFromInput();
        syncMonitoredInterfacesForMode({ preservePersonalized: true });

        const wan = el('fieldWan')?.value || '';
        const lan = el('fieldLan')?.value || '';
        const mgmt = el('fieldMgmt')?.value || '';
        const dns = el('fieldDns')?.value.trim() || '';
        const errors = [];

        if (!wan) errors.push('Selecione a interface WAN.');
        if (!lan) errors.push('Selecione a interface LAN.');
        if (wan && lan && wan === lan) errors.push('WAN e LAN devem ser interfaces diferentes.');
        if (mgmt && (mgmt === wan || mgmt === lan)) errors.push('Interface de gerenciamento deve ser diferente de WAN e LAN.');
        if (!state.homeNet.length) errors.push('Sua HOME_NET está vazia.');
        if (dns && !isValidIpv4(dns)) errors.push('O DNS interno informado não é um IPv4 válido.');
        if (!state.selectedInterfaces.size) errors.push('Selecione ao menos uma interface para ser monitorada.');

        return { ok: errors.length === 0, errors };
    }

    // ═══════════════════════════════════════════════════════════
    // PROTEÇÃO E CONFIGURAÇÃO
    // ═══════════════════════════════════════════════════════════
    function bindProtectionActions() {
        for (const id of ['fieldEtOpen', 'fieldRestartServices', 'fieldYamlPath', 'fieldEvePath']) {
            el(id)?.addEventListener('change', updateReview);
            el(id)?.addEventListener('input', updateReview);
        }
    }

    function validateProtectionForm() {
        const yaml = el('fieldYamlPath')?.value.trim() || '';
        const eve = el('fieldEvePath')?.value.trim() || '';
        const errors = [];
        if (!yaml.startsWith('/')) errors.push('O caminho do YAML deve ser absoluto (iniciar com /).');
        if (!eve.startsWith('/')) errors.push('O caminho do EVE JSON deve ser absoluto (iniciar com /).');
        return { ok: errors.length === 0, errors };
    }

    function collectConfiguration() {
        const input = el('fieldHomeNet');
        if (input?.value.trim()) addHomeNetFromInput();
        
        return {
            interface_wan: el('fieldWan')?.value || '',
            interface_lan: el('fieldLan')?.value || '',
            interface_mgmt: el('fieldMgmt')?.value || '',
            interfaces_monitoradas: Array.from(state.selectedInterfaces),
            home_net: [...state.homeNet],
            dns_interno: el('fieldDns')?.value.trim() || '',
            yaml_path: el('fieldYamlPath')?.value.trim() || '/etc/suricata/suricata.yaml',
            eve_path: el('fieldEvePath')?.value.trim() || '/var/log/suricata/eve.json',
            modo_captura: getCaptureMode(),
            instalar_et_open: Boolean(el('fieldEtOpen')?.checked),
            instalar_regras_moonshield: true,
            reiniciar_servicos: Boolean(el('fieldRestartServices')?.checked),
        };
    }

    async function saveConfiguration({ quiet = false } = {}) {
        const cfg = collectConfiguration();
        const payload = await requestJSON(CFG.urls.salvarConfiguracao, { method: 'POST', body: cfg });
        const data = unwrapData(payload);
        state.configuration = normaliseObject(data.configuracao || data);
        applyConfigurationToForm(state.configuration);
        if (!quiet) showToast('Configuração salva com sucesso.', 'success');
    }

    function applyConfigurationToForm(cfg) {
        const c = normaliseObject(cfg);
        if (!Object.keys(c).length) return;

        state.homeNet = Array.isArray(c.home_net) ? c.home_net.filter(Boolean) : [];
        state.selectedInterfaces = new Set(Array.isArray(c.interfaces_monitoradas) ? c.interfaces_monitoradas : []);

        if (el('fieldDns')) el('fieldDns').value = c.dns_interno || '';
        if (el('fieldYamlPath')) el('fieldYamlPath').value = c.yaml_path || '/etc/suricata/suricata.yaml';
        if (el('fieldEvePath')) el('fieldEvePath').value = c.eve_path || '/var/log/suricata/eve.json';
        if (el('fieldEtOpen')) el('fieldEtOpen').checked = c.instalar_et_open !== false;
        if (el('fieldRestartServices')) el('fieldRestartServices').checked = c.reiniciar_servicos !== false;

        const mode = c.modo_captura || 'lan_wan';
        const radio = document.querySelector(`input[name="modoCaptura"][value="${mode}"]`);
        if (radio) radio.checked = true;

        const setSelect = (id, val) => {
            const sel = el(id);
            if (sel && val && Array.from(sel.options).some(o => o.value === val)) sel.value = val;
        };
        setSelect('fieldWan', c.interface_wan);
        setSelect('fieldLan', c.interface_lan);
        setSelect('fieldMgmt', c.interface_mgmt);

        if (state.interfaces.length) {
            initialiseHomeNetBaseFromCurrentSelection();
            syncMonitoredInterfacesForMode({ preservePersonalized: true });
            renderMonitoredInterfaces(state.interfaces);
        }
        renderHomeNetTokens();
    }

    // ═══════════════════════════════════════════════════════════
    // REVISÃO
    // ═══════════════════════════════════════════════════════════
    function bindReviewActions() {
        el('confirmInstall')?.addEventListener('change', () => {
            if (el('btnStartInstall')) el('btnStartInstall').disabled = !el('confirmInstall').checked;
            clearReviewError();
        });
        el('btnStartInstall')?.addEventListener('click', startInstallation);
    }

    function updateReview() {
        const cfg = collectConfiguration();
        const modes = { lan: 'Somente LAN', lan_wan: 'LAN + WAN', personalizado: 'Personalizado' };
        setText('reviewMode', modes[cfg.modo_captura] || cfg.modo_captura);
        setText('reviewWan', cfg.interface_wan || 'Não definida');
        setText('reviewLan', cfg.interface_lan || 'Não definida');
        setText('reviewEtOpen', cfg.instalar_et_open ? 'Ativado' : 'Desativado');
        setText('reviewRestart', cfg.reiniciar_servicos ? 'Reiniciar após instalar' : 'Não reiniciar automaticamente');
    }

    // ═══════════════════════════════════════════════════════════
    // INSTALAÇÃO E TAREFAS
    // ═══════════════════════════════════════════════════════════
    function bindInstallationActions() {
        el('btnCancelInstall')?.addEventListener('click', cancelActiveTask);
        el('btnRetryInstall')?.addEventListener('click', () => {
            resetInstallationUI();
            unlockStep(5);
            goToStep(5);
        });
        el('btnFinishOnboarding')?.addEventListener('click', finishOnboarding);
        el('btnToggleLogs')?.addEventListener('click', toggleLogs);
    }

    async function startInstallation() {
        clearReviewError();
        if (!el('confirmInstall')?.checked) {
            showReviewError('Confirme a autorização antes de iniciar.');
            return;
        }

        const net = validateNetworkForm();
        const prot = validateProtectionForm();
        if (!net.ok || !prot.ok) {
            showReviewError([...net.errors, ...prot.errors].join('<br>'));
            return;
        }

        const btn = el('btnStartInstall');
        setButtonLoading(btn, true);

        try {
            await saveConfiguration({ quiet: true });
            const params = {
                configuracao: collectConfiguration(),
                instalar_et_open: Boolean(el('fieldEtOpen')?.checked),
                reiniciar_servicos: Boolean(el('fieldRestartServices')?.checked),
                executar_diagnostico_final: true,
            };

            const payload = await requestJSON(CFG.urls.criarTarefa, { method: 'POST', body: { tipo: 'instalacao', parametros: params } });
            const data = unwrapData(payload);
            const task = data.tarefa || data.task || data;
            
            if (!task?.id) throw new Error('O ID da tarefa não foi retornado pela API.');

            state.activeTask = task;
            state.taskRunning = true;
            state.taskFinished = false;
            state.taskSucceeded = false;
            state.taskStartedAt = new Date();
            state.lastLogOffset = 0;
            state.renderedLogKeys.clear();

            unlockStep(6);
            goToStep(6);
            prepareInstallationUI(task);
            startElapsedTimer();
            startTaskPolling(task.id);
            startLogPolling(task.id);

            appendLocalLog('info', 'Tarefa criada. Aguardando o executor seguro.');
            showToast('Tarefa de instalação iniciada.', 'success');
        } catch (error) {
            showReviewError(error.message);
            showToast(error.message, 'error');
        } finally {
            setButtonLoading(btn, false);
        }
    }

    function prepareInstallationUI(task) {
        if (el('installResult')) el('installResult').hidden = true;
        if (el('progressCard')) el('progressCard').hidden = false;
        if (el('btnCancelInstall')) el('btnCancelInstall').hidden = false;
        if (el('btnRetryInstall')) el('btnRetryInstall').hidden = true;
        if (el('btnFinishOnboarding')) el('btnFinishOnboarding').hidden = true;

        setText('installTitle', 'Preparando o sensor MoonShield');
        updateTaskProgress(task);
        clearTerminal();
    }

    function startTaskPolling(taskId) {
        if (state.taskPollTimer) clearTimeout(state.taskPollTimer);
        
        const poll = async () => {
            try {
                const url = resolveTemplateUrl(CFG.urls.detalheTarefaTemplate, taskId);
                const payload = await requestJSON(url, { method: 'GET' });
                const data = unwrapData(payload);
                const task = data.tarefa || data.task || data;
                
                state.activeTask = task;
                updateTaskProgress(task);
                
                if (isFinalTaskStatus(task.status)) {
                    await handleTaskFinished(task);
                    return;
                }
            } catch (error) {
                appendLocalLog('aviso', `Aviso: Falha temporária ao consultar a tarefa (${error.message})`);
            }
            state.taskPollTimer = setTimeout(poll, POLL_INTERVAL_MS);
        };
        poll();
    }

    function startLogPolling(taskId) {
        if (state.logPollTimer) clearTimeout(state.logPollTimer);
        
        const poll = async () => {
            try {
                const url = `${resolveTemplateUrl(CFG.urls.logsTarefaTemplate, taskId)}?offset=${state.lastLogOffset}&limite=200`;
                const payload = await requestJSON(url, { method: 'GET' });
                const data = unwrapData(payload);
                const logs = Array.isArray(data.logs) ? data.logs : [];
                
                renderTaskLogs(logs);
                state.lastLogOffset = Number(data.proximo_offset ?? (state.lastLogOffset + logs.length));
            } catch (error) {
                // Silencioso no console para não floodar
            }
            if (!state.taskFinished) state.logPollTimer = setTimeout(poll, LOG_POLL_INTERVAL_MS);
        };
        poll();
    }

    function updateTaskProgress(task) {
        const prog = clamp(Number(task.progresso ?? 0), 0, 100);
        setText('installPercent', `${Math.round(prog)}%`);
        if (el('installProgressBar')) el('installProgressBar').style.width = `${prog}%`;
        
        const stageStr = firstText(task.etapa_atual, 'Processando');
        const formattedStage = stageStr.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
        setText('currentStageTitle', formattedStage);
        setText('currentStageMessage', statusMessage(task.status));
    }

    async function handleTaskFinished(task) {
        state.taskFinished = true;
        state.taskRunning = false;
        state.taskSucceeded = String(task.status).toLowerCase() === 'sucesso';
        
        if (state.taskPollTimer) clearTimeout(state.taskPollTimer);
        if (state.logPollTimer) clearTimeout(state.logPollTimer);
        if (state.elapsedTimer) clearInterval(state.elapsedTimer);

        try {
            const url = `${resolveTemplateUrl(CFG.urls.logsTarefaTemplate, task.id)}?offset=${state.lastLogOffset}&limite=500`;
            const payload = await requestJSON(url, { method: 'GET' });
            const data = unwrapData(payload);
            renderTaskLogs(Array.isArray(data.logs) ? data.logs : []);
        } catch (_) {}

        if (state.taskSucceeded) {
            setText('installTitle', 'Suricata pronto e validado!');
            
            // Força a UI de progresso para 100% visualmente
            setText('installPercent', '100%');
            if (el('installProgressBar')) el('installProgressBar').style.width = '100%';
            setText('currentStageTitle', 'Instalação Concluída');
            setText('currentStageMessage', 'Todos os processos foram finalizados.');

            // Arruma a visibilidade dos botões
            if (el('btnFinishOnboarding')) el('btnFinishOnboarding').hidden = false;
            if (el('btnCancelInstall')) el('btnCancelInstall').hidden = true;
            if (el('btnRetryInstall')) el('btnRetryInstall').hidden = true; 

            if (el('installResult')) {
                el('installResult').hidden = false;
                el('installResult').className = 'alert alert--success';
                setText('resultTitle', 'Instalação concluída');
                setText('resultMessage', 'O sensor foi configurado com sucesso e já está protegendo a rede.');
            }
            showToast('Instalação concluída com sucesso.', 'success');
            updateSidebarSystem('ok', 'Suricata ativo');
        } else {
            const cancelled = String(task.status).toLowerCase() === 'cancelado';
            setText('installTitle', cancelled ? 'Instalação cancelada.' : 'Falha na instalação.');
            
            // Arruma a visibilidade dos botões no caso de erro
            if (el('btnFinishOnboarding')) el('btnFinishOnboarding').hidden = true;
            if (el('btnCancelInstall')) el('btnCancelInstall').hidden = true;
            if (el('btnRetryInstall')) el('btnRetryInstall').hidden = false; 
            
            if (el('installResult')) {
                el('installResult').hidden = false;
                el('installResult').className = 'alert alert--error';
                setText('resultTitle', cancelled ? 'Operação interrompida.' : 'Ocorreu um erro.');
                const erroMsg = firstText(task.erro, task.mensagem, 'Verifique o terminal acima para mais detalhes.');
                setText('resultMessage', erroMsg);
            }
            showToast(cancelled ? 'Instalação cancelada.' : 'Instalação falhou.', 'error');
            updateSidebarSystem('error', 'Erro na instalação');
        }
    }

    // ═══════════════════════════════════════════════════════════
    // TERMINAL DE LOGS
    // ═══════════════════════════════════════════════════════════
    function renderTaskLogs(logs) {
        for (const log of logs) {
            const key = `${log.id ?? ''}|${log.criado_em ?? ''}|${log.mensagem ?? ''}`;
            if (state.renderedLogKeys.has(key)) continue;
            state.renderedLogKeys.add(key);
            appendTerminalLine(log);
        }
    }

    function appendLocalLog(level, message) {
        appendTerminalLine({ nivel: level.toLowerCase(), mensagem: message, criado_em: new Date().toISOString() });
    }

    function appendTerminalLine(log) {
        const container = el('installLogs');
        if (!container) return;
        if (container.children.length === 1 && container.firstElementChild.textContent.includes('Aguardando')) {
            container.innerHTML = '';
        }

        const level = String(log.nivel || 'info').toLowerCase();
        let colorClass = 'var(--info)';
        if (['erro', 'error', 'critical'].includes(level)) colorClass = 'var(--danger)';
        if (['aviso', 'warning', 'warn'].includes(level)) colorClass = 'var(--warn)';
        if (['sucesso', 'success', 'ok'].includes(level)) colorClass = 'var(--ok)';

        const line = document.createElement('div');
        line.className = 'terminal-line';

        const time = new Date(log.criado_em || Date.now());
        const hours = String(time.getHours()).padStart(2, '0');
        const mins = String(time.getMinutes()).padStart(2, '0');
        const secs = String(time.getSeconds()).padStart(2, '0');

        line.innerHTML = `
            <span class="terminal-time">${hours}:${mins}:${secs}</span>
            <span class="terminal-level" style="color: ${colorClass};">${level.toUpperCase()}</span>
            <span>${escapeHtml(log.mensagem || '')}</span>
        `;
        container.appendChild(line);
        container.scrollTop = container.scrollHeight;

        if (container.children.length > MAX_RENDERED_LOGS) container.firstElementChild?.remove();
    }

    function clearTerminal() {
        const container = el('installLogs');
        if (!container) return;
        container.innerHTML = `
            <div class="terminal-line">
                <span class="terminal-time">--:--:--</span>
                <span class="terminal-level" style="color: var(--info);">INFO</span>
                <span>Aguardando início...</span>
            </div>
        `;
    }

    function toggleLogs() {
        state.logsVisible = !state.logsVisible;
        if (el('installLogs')) el('installLogs').hidden = !state.logsVisible;
        setText('btnToggleLogs', state.logsVisible ? 'Ocultar' : 'Mostrar');
    }

    // ═══════════════════════════════════════════════════════════
    // AÇÕES DE FINALIZAÇÃO E CANCELAMENTO
    // ═══════════════════════════════════════════════════════════
    async function cancelActiveTask() {
        const task = state.activeTask;
        if (!task?.id) return;
        
        setButtonLoading(el('btnCancelInstall'), true);
        try {
            await requestJSON(resolveTemplateUrl(CFG.urls.cancelarTarefaTemplate, task.id), { method: 'POST', body: {} });
            appendLocalLog('aviso', 'Cancelamento solicitado ao servidor...');
            showToast('Cancelamento solicitado.', 'warning');
        } catch (error) {
            showToast(error.message, 'error');
        } finally {
            setButtonLoading(el('btnCancelInstall'), false);
        }
    }

    function resetInstallationUI() {
        state.activeTask = null;
        state.taskRunning = false;
        state.taskFinished = false;
        if (state.elapsedTimer) clearInterval(state.elapsedTimer);
        setText('installPercent', '0%');
        if (el('installProgressBar')) el('installProgressBar').style.width = '0%';
        clearTerminal();
        if (el('installResult')) el('installResult').hidden = true;
    }

    async function finishOnboarding() {
        setButtonLoading(el('btnFinishOnboarding'), true);
        try {
            await requestJSON(CFG.urls.concluirOnboarding, { method: 'POST', body: {} });
            state.leavingAllowed = true;
            window.location.assign(CFG.urls.painel);
        } catch (error) {
            showToast(error.message, 'error');
            setButtonLoading(el('btnFinishOnboarding'), false);
        }
    }

    function startElapsedTimer() {
        if (state.elapsedTimer) clearInterval(state.elapsedTimer);
        const update = () => {
            if (!state.taskStartedAt) return;
            const secs = Math.max(0, Math.floor((Date.now() - state.taskStartedAt) / 1000));
            const h = Math.floor(secs / 3600);
            const m = Math.floor((secs % 3600) / 60);
            const s = secs % 60;
            const title = el('installTerminal')?.querySelector('.terminal-title');
            if (title) {
                title.textContent = `moonshield-setup.sh — Decorrido: ${h > 0 ? `${h}h ` : ''}${m}m ${s}s`;
            }
        };
        update();
        state.elapsedTimer = setInterval(update, 1000);
    }

    // ═══════════════════════════════════════════════════════════
    // PROTEÇÃO DE SAÍDA (MODAL)
    // ═══════════════════════════════════════════════════════════
    function bindLeaveProtection() {
        window.addEventListener('beforeunload', event => {
            if (state.taskRunning && !state.taskFinished && !state.leavingAllowed) {
                event.preventDefault();
                event.returnValue = '';
            }
        });

        all('[data-close-modal]').forEach(node => node.addEventListener('click', () => {
            const modal = el('leaveModal');
            if (modal) modal.classList.remove('active');
        }));
    }

    // ═══════════════════════════════════════════════════════════
    // FETCH API CUSTOMIZADA
    // ═══════════════════════════════════════════════════════════
    async function requestJSON(url, { method = 'GET', body = undefined, timeout = 30000 } = {}) {
        if (!url) throw new Error('URL da API não configurada');
        
        const ctrl = new AbortController();
        const tid = setTimeout(() => ctrl.abort(), timeout);
        const headers = { Accept: 'application/json' };

        const opts = { method, credentials: 'same-origin', headers, signal: ctrl.signal };
        if (method !== 'GET' && method !== 'HEAD') {
            headers['Content-Type'] = 'application/json';
            if (CFG.csrfToken) headers['X-CSRFToken'] = CFG.csrfToken;
            opts.body = JSON.stringify(body ?? {});
        }

        try {
            const res = await fetch(url, opts);
            const ct = res.headers.get('content-type') || '';
            const data = ct.includes('json') ? await res.json() : { ok: false, mensagem: await res.text() };
            
            if (!res.ok || data?.ok === false) {
                // Extrai o erro não importa como o backend retorne
                const rawMessage = data?.mensagem || data?.msg || data?.erro || data?.error || (Array.isArray(data?.erros) ? data.erros.join('\n') : `Erro de requisição (HTTP ${res.status})`);
                throw new Error(safeUserMessage(rawMessage, `Erro de requisição (HTTP ${res.status})`));
            }
            return data;
        } catch (error) {
            if (error.name === 'AbortError') throw new Error('A requisição excedeu o tempo limite (Timeout).');
            throw error;
        } finally {
            clearTimeout(tid);
        }
    }

    // ═══════════════════════════════════════════════════════════
    // HELPERS E UTILITÁRIOS
    // ═══════════════════════════════════════════════════════════
    function unwrapData(payload) {
        return (payload?.dados && typeof payload.dados === 'object') ? payload.dados : payload || {};
    }

    function showToast(message, type = 'info', duration = 4200) {
        const container = el('toastContainer');
        if (!container || !message) return;
        const toast = document.createElement('div');
        toast.className = `alert alert--${type}`;
        toast.style.marginBottom = '8px';
        toast.style.boxShadow = 'var(--shadow-lg)';
        toast.style.animation = 'fadeIn 0.3s ease-out';
        
        const icons = { success: '✓', error: '!', warning: '!', info: 'i' };
        toast.innerHTML = `
            <div class="alert__icon">${icons[type] || 'i'}</div>
            <div class="alert__content"><div class="alert__message" style="font-weight:500;">${escapeHtml(message)}</div></div>
            <button type="button" style="background:none; border:none; color:inherit; opacity:0.5; cursor:pointer; font-size:16px; padding:0 8px;">&times;</button>
        `;
        
        const close = () => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(-10px)';
            toast.style.transition = 'all 0.2s ease';
            setTimeout(() => toast.remove(), 200);
        };
        
        toast.querySelector('button')?.addEventListener('click', close);
        container.appendChild(toast);
        setTimeout(close, duration);
    }

    function showEnvironmentError(msg) {
        if (el('environmentError')) el('environmentError').hidden = false;
        const textNode = el('environmentErrorText');
        if (textNode) textNode.innerHTML = messageToSafeHtml(msg);
    }

    function clearEnvironmentError() {
        if (el('environmentError')) el('environmentError').hidden = true;
    }

    function showNetworkError(msg) {
        if (el('networkError')) el('networkError').hidden = false;
        const textNode = el('networkErrorText');
        if (textNode) textNode.innerHTML = messageToSafeHtml(msg);
    }

    function clearNetworkError() {
        if (el('networkError')) el('networkError').hidden = true;
    }

    function showReviewError(msg) {
        if (el('reviewError')) el('reviewError').hidden = false;
        const textNode = el('reviewErrorText');
        if (textNode) textNode.innerHTML = messageToSafeHtml(msg);
    }

    function clearReviewError() {
        if (el('reviewError')) el('reviewError').hidden = true;
    }

    function updateSidebarSystem(status, text) {
        const dot = el('sidebarSystemDot');
        if (dot) {
            if (status === 'ok') {
                dot.className = '';
                dot.innerHTML = iconSvg('check');
                dot.style.color = 'var(--ok)';
                dot.style.border = 'none';
            } else if (status === 'error') {
                dot.className = '';
                dot.innerHTML = iconSvg('error');
                dot.style.color = 'var(--danger)';
                dot.style.border = 'none';
            } else {
                dot.className = 'spinner';
                dot.innerHTML = '';
                dot.style.border = '';
            }
        }
        setText('sidebarSystemText', text);
    }

    function setButtonLoading(btn, loading) {
        if (!btn) return;
        btn.disabled = loading;
        btn.classList.toggle('loading', loading);
        const originalText = btn.dataset.originalText || btn.textContent;
        if (loading) {
            btn.dataset.originalText = originalText;
            btn.innerHTML = `<span class="spinner" style="width:14px; height:14px; border-width:2px; border-top-color:currentColor; margin-right:8px;"></span> Aguarde...`;
        } else {
            btn.textContent = originalText;
        }
    }

    function normaliseObject(v) {
        return (v && typeof v === 'object' && !Array.isArray(v)) ? v : {};
    }

    function looksLikeInternalRepresentation(value) {
        const text = String(value ?? '').trim();
        if (!text) return false;
        return /ResultadoEtapa\s*\(|<StatusEtapa\.|StatusEtapa\.|ConfiguracaoSuricataDados\s*\(|^\[object Object\]$/i.test(text);
    }

    function safeDisplayText(value, fallback = '') {
        if (value === null || value === undefined) return fallback;
        if (typeof value === 'object') return fallback;

        const text = String(value).trim();
        if (!text || looksLikeInternalRepresentation(text)) return fallback;
        return text;
    }

    function safeUserMessage(value, fallback = 'Ocorreu um erro ao processar a solicitação.') {
        const text = safeDisplayText(value, '');
        if (!text) return fallback;

        if (/Dificuldade técnica na gravação do modelo/i.test(text)) {
            return 'Não foi possível salvar a configuração. Verifique os campos informados e tente novamente.';
        }

        return text;
    }

    function messageToSafeHtml(value) {
        return escapeHtml(safeUserMessage(value, 'Não foi possível concluir esta operação.')).replace(/\n/g, '<br>');
    }

    function normaliseSuricataStatus(value) {
        if (value && typeof value === 'object' && !Array.isArray(value)) {
            const obj = value;
            const dados = normaliseObject(obj.dados);
            const servico = normaliseObject(obj.servico);
            const resultado = normaliseObject(obj.resultado);

            return {
                ...dados,
                ...servico,
                ...resultado,
                ...obj,
                instalado: readBoolean(
                    { ...dados, ...servico, ...resultado, ...obj },
                    ['instalado', 'installed'],
                    false
                ),
                versao: firstText(
                    obj.versao,
                    obj.version,
                    dados.versao,
                    dados.version,
                    servico.versao,
                    resultado.versao
                ),
            };
        }

        // Alguns retornos antigos chegavam como repr() Python:
        // ResultadoEtapa(... dados={'instalado': False, 'versao': '...'} ...)
        const raw = String(value ?? '').trim();
        if (!raw) return {};

        if (looksLikeInternalRepresentation(raw)) {
            const instaladoMatch = raw.match(/['"]?instalado['"]?\s*:\s*(True|False|true|false)/);
            const versaoMatch = raw.match(/['"]?versao['"]?\s*:\s*['"]([^'"]*)['"]/);
            return {
                instalado: instaladoMatch ? instaladoMatch[1].toLowerCase() === 'true' : false,
                versao: versaoMatch ? versaoMatch[1].trim() : '',
            };
        }

        return {};
    }

    function firstText(...vals) {
        for (const value of vals) {
            const text = safeDisplayText(value, '');
            if (text) return text;
        }
        return '';
    }

    function readBoolean(obj, keys, fallback = false) {
        for (const key of keys) {
            if (!Object.hasOwn(obj || {}, key)) continue;
            const value = obj[key];

            if (typeof value === 'boolean') return value;
            if (typeof value === 'number') return value !== 0;

            const text = String(value ?? '').trim().toLowerCase();
            if (['1', 'true', 'yes', 'sim', 'on', 'ativo', 'installed', 'instalado'].includes(text)) return true;
            if (['0', 'false', 'no', 'nao', 'não', 'off', 'inativo', ''].includes(text)) return false;

            return Boolean(value);
        }
        return fallback;
    }
    function clamp(v, min, max) { return Math.min(max, Math.max(min, v)); }
    
    function isValidIpv4(v) {
        const p = String(v).split('.');
        return p.length === 4 && p.every(x => /^\d{1,3}$/.test(x) && Number(x) >= 0 && Number(x) <= 255);
    }
    
    function isValidCidr(v) {
        const [ip, pre, extra] = String(v).split('/');
        return extra === undefined && isValidIpv4(ip) && /^\d{1,2}$/.test(pre || '') && Number(pre) >= 0 && Number(pre) <= 32;
    }
    
    function ipToUint32(ip) {
        const p = String(ip).split('.').map(Number);
        return (p.length === 4 && p.every(x => Number.isInteger(x) && x >= 0 && x <= 255)) 
            ? (((p[0] << 24) >>> 0) + ((p[1] << 16) >>> 0) + ((p[2] << 8) >>> 0) + (p[3] >>> 0)) >>> 0 
            : null;
    }
    
    function uint32ToIp(v) {
        const n = Number(v) >>> 0;
        return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
    }

    function networkFromCidr(value) {
        if (!isValidCidr(value)) return '';
        const [ip, prefixText] = value.split('/');
        const prefix = Number(prefixText);
        const ipNumber = ipToUint32(ip);
        if (ipNumber === null) return '';
        const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
        const network = (ipNumber & mask) >>> 0;
        return `${uint32ToIp(network)}/${prefix}`;
    }

    function escapeHtml(v) {
        return String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
    }
    
    function cssEscape(v) {
        return window.CSS?.escape ? window.CSS.escape(String(v)) : String(v).replace(/[^a-zA-Z0-9_-]/g, '\\$&');
    }
    
    function setText(id, v) {
        const n = el(id);
        if (n) n.textContent = v ?? '';
    }
    
    function getCaptureMode() {
        return document.querySelector('input[name="modoCaptura"]:checked')?.value || 'lan_wan';
    }
    
    function resolveTemplateUrl(t, id) {
        return String(t).replace('__ID__', encodeURIComponent(id));
    }
    
    function isFinalTaskStatus(s) {
        return ['sucesso', 'erro', 'cancelado', 'ignorado'].includes(String(s).toLowerCase());
    }
    
    function statusMessage(s) {
        return { pendente: 'Aguardando execução', executando: 'Em execução', sucesso: 'Concluído com sucesso', erro: 'Falhou', cancelado: 'Cancelado' }[String(s).toLowerCase()] || 'Processando etapa...';
    }
    
    function iconSvg(t) {
        return { 
            check: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>', 
            error: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>', 
            warning: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>' 
        }[t] || '?';
    }
});