/**
 * MOONSHIELD — SURICATA ONBOARDING v2
 * Navegação, configuração, tarefas, progresso e logs.
 */

'use strict';

document.addEventListener('DOMContentLoaded', () => {
    const CFG = window.MS_SURICATA || {};
    const TOTAL_STEPS = 6;
    const POLL_INTERVAL_MS = 1800;
    const LOG_POLL_INTERVAL_MS = 1500;
    const MAX_RENDERED_LOGS = 500;

    const state = {
        currentStep: 1,
        maxUnlockedStep: 1,
        environmentReady: false,
        environmentData: null,
        topology: null,
        interfaces: [],
        homeNet: [],
        autoHomeNetBase: "",
        selectedInterfaces: new Set(),
        configuration: normaliseObject(CFG.configuracao),
        onboardingStatus: normaliseObject(CFG.statusOnboarding),
        plan: normaliseObject(CFG.planoInstalacao),
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

    initialiseGreeting();
    bindNavigation();
    bindEnvironmentActions();
    bindNetworkActions();
    bindProtectionActions();
    bindReviewActions();
    bindInstallationActions();
    bindLeaveProtection();
    hydrateFromInitialData();
    resumeExistingTask().catch(error => console.warn('Não foi possível restaurar tarefa:', error));

    function initialiseGreeting() {
        const name = CFG.usuario?.nome || CFG.usuario?.username || 'operador';
        if (el('greetName')) el('greetName').textContent = name;
    }

    function hydrateFromInitialData() {
        applyConfigurationToForm(state.configuration);
        applyPlan(state.plan);
        updateReview();
        updateSidebarSystem('pending', 'Aguardando verificação');
    }

    /* ═══════════════════════════════════════════════════════════
       NAVEGAÇÃO
    ═══════════════════════════════════════════════════════════ */
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
                showNetworkError(validation.errors.join(' '));
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
                showToast(paths.errors.join(' '), 'error');
                return;
            }

            try {
                await saveConfiguration({ quiet: true });
                await refreshOnboardingData();
                updateReview();
                unlockStep(5);
                goToStep(5);
            } catch (error) {
                showToast(error.message || 'Não foi possível salvar as opções de proteção.', 'error');
            }
        });

        all('[data-back]').forEach(button => {
            button.addEventListener('click', () => goToStep(Number(button.dataset.back || 1)));
        });

        all('[data-edit-step]').forEach(button => {
            button.addEventListener('click', () => goToStep(Number(button.dataset.editStep || 1)));
        });

        all('.step-item').forEach(button => {
            button.addEventListener('click', () => {
                const target = Number(button.dataset.step || 1);
                if (target <= state.maxUnlockedStep && !button.classList.contains('disabled')) goToStep(target);
            });
        });
    }

    function goToStep(step) {
        if (!Number.isInteger(step) || step < 1 || step > TOTAL_STEPS) return;
        if (step > state.maxUnlockedStep) return;

        all('.step-page').forEach(panel => {
            panel.classList.toggle('active', Number(panel.dataset.step) === step);
        });

        state.currentStep = step;
        updateNavigation(step);

        const content = document.querySelector('.app-content');
        if (content) content.scrollTo({ top: 0, behavior: 'smooth' });
    }

    function unlockStep(step) {
        state.maxUnlockedStep = Math.max(state.maxUnlockedStep, step);
        all('.step-item').forEach(item => {
            const number = Number(item.dataset.step || 1);
            item.classList.toggle('disabled', number > state.maxUnlockedStep);
        });
    }

    function updateNavigation(current) {
        all('.step-item').forEach(item => {
            const number = Number(item.dataset.step || 1);
            item.classList.remove('active', 'completed');
            item.removeAttribute('aria-current');

            if (number < current) item.classList.add('completed');
            if (number === current) {
                item.classList.add('active');
                item.setAttribute('aria-current', 'step');
            }
        });
    }

    /* ═══════════════════════════════════════════════════════════
       AMBIENTE
    ═══════════════════════════════════════════════════════════ */
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
            state.environmentData = data;

            const stack = data.stack || data.dados?.stack || data.status || data;
            const environment = stack.ambiente || data.ambiente || stack.environment || data.environment || stack;
            const systemInfo = environment.sistema || stack.sistema || data.sistema || {};
            const capabilities = environment.capacidades || stack.capacidades || data.capacidades || {};
            const distribution = environment.distribuicao || stack.distribuicao || data.distribuicao || {};
            const suricata = stack.suricata || data.suricata || environment.suricata || {};
            const services = stack.servicos || data.servicos || environment.servicos || {};
            const paths = stack.caminhos || data.caminhos || environment.caminhos || suricata.caminhos || {};

            const linux = readBoolean(systemInfo, ['linux', 'eh_linux', 'is_linux'], readBoolean(environment, ['linux', 'eh_linux', 'is_linux'], false));
            const root = readBoolean(systemInfo, ['root', 'privilegios', 'privilegiado', 'is_root'], readBoolean(environment, ['root', 'privilegios', 'privilegiado', 'is_root'], false));
            const systemd = readBoolean(capabilities, ['pode_controlar_servicos', 'systemd', 'tem_systemd'], readBoolean(services, ['disponivel', 'systemd', 'tem_systemd'], readBoolean(environment, ['systemd', 'tem_systemd'], false)));
            const installed = readBoolean(suricata, ['instalado'], readBoolean(environment, ['suricata_instalado'], false));
            const version = firstText(suricata.versao, environment.versao_suricata, data.versao_suricata);

            const yamlInfo = paths.yaml || suricata.yaml || {};
            const eveInfo = paths.eve || suricata.eve || {};
            const pathReady = Boolean((yamlInfo.existe === true || yamlInfo.arquivo === true) && (eveInfo.existe === true || eveInfo.arquivo === true));

            const checks = {
                linux: {
                    ok: linux,
                    warning: !linux,
                    value: linux ? firstText(distribution.nome, distribution.id, systemInfo.nome, 'Linux detectado') : 'Linux necessário',
                },
                privilegios: {
                    ok: root,
                    warning: !root,
                    value: root ? 'Privilégios disponíveis' : 'Execução privilegiada necessária',
                },
                suricata: {
                    ok: installed,
                    warning: !installed,
                    value: installed ? (version || 'Instalado') : 'Será instalado',
                },
                systemd: {
                    ok: systemd,
                    warning: !systemd,
                    value: systemd ? 'Disponível' : 'Não detectado',
                },
                paths: {
                    ok: pathReady || !installed,
                    warning: !pathReady && installed,
                    value: pathReady ? 'Caminhos localizados' : installed ? 'Revisão necessária' : 'Criados na instalação',
                },
            };

            Object.entries(checks).forEach(([name, check]) => setEnvironmentCheck(name, check));

            const fatalErrors = [];
            if (!linux) fatalErrors.push('A instalação real precisa ser executada em um servidor Linux.');
            if (linux && !root) fatalErrors.push('A execução deve possuir privilégios administrativos.');
            if (linux && !systemd) fatalErrors.push('O systemd não foi detectado neste servidor.');

            state.environmentReady = fatalErrors.length === 0;
            const nextButton = el('btnStep2Next');
            if (nextButton) nextButton.disabled = !state.environmentReady;

            if (state.environmentReady) {
                setEnvironmentSummary('success', 'Ambiente pronto para continuar', installed
                    ? `Suricata ${version || ''} detectado. Você pode revisar a rede.`.trim()
                    : 'Os pré-requisitos foram validados. O Suricata será instalado durante a execução.');
                updateSidebarSystem('ok', installed ? `Suricata ${version || 'detectado'}` : 'Ambiente compatível');
            } else {
                setEnvironmentSummary('error', 'O ambiente possui bloqueios', fatalErrors.join(' '));
                showEnvironmentError(fatalErrors.join(' '));
                updateSidebarSystem('error', 'Ambiente incompatível');
            }
        } catch (error) {
            state.environmentReady = false;
            setEnvironmentSummary('error', 'Falha ao verificar o ambiente', error.message || 'A API de status não respondeu.');
            showEnvironmentError(error.message || 'Não foi possível consultar o ambiente.');
            updateSidebarSystem('error', 'Falha na verificação');
            if (el('btnStep2Next')) el('btnStep2Next.disabled = true');
        }
    }

    function setEnvironmentLoading() {
        setEnvironmentSummary('loading', 'Verificando ambiente...', 'Aguarde enquanto coletamos os pré-requisitos.');
        for (const name of ['linux', 'privilegios', 'suricata', 'systemd', 'paths']) {
            setEnvironmentCheck(name, { pending: true, value: 'Verificando...' });
        }
        if (el('btnStep2Next')) el('btnStep2Next').disabled = true;
    }

    function setEnvironmentSummary(type, title, text) {
        const icon = el('environmentSummaryIcon');
        if (icon) {
            icon.className = type === 'loading' ? 'spinner' : '';
            icon.innerHTML = type === 'loading' ? '' : iconSvg(type);
            icon.style.color = type === 'success' ? 'var(--color-success)' : type === 'warning' ? 'var(--color-warning)' : type === 'error' ? 'var(--color-error)' : 'inherit';
        }
        if (el('environmentSummaryTitle')) el('environmentSummaryTitle').textContent = title;
        if (el('environmentSummaryText')) el('environmentSummaryText').textContent = text;
    }

    function setEnvironmentCheck(name, check) {
        const row = document.querySelector(`[data-check="${cssEscape(name)}"]`);
        if (!row) return;
        const status = row.querySelector('.info-card__icon');
        const value = row.querySelector('div[id^="check"]'); // Seleciona a div de valor

        if (status) {
            status.style.background = 'transparent';
            if (check.pending) {
                status.innerHTML = '<span class="spinner"></span>';
                status.style.color = 'inherit';
            } else if (check.ok) {
                status.innerHTML = iconSvg('check');
                status.style.color = 'var(--color-success)';
            } else if (check.warning) {
                status.innerHTML = iconSvg('warning');
                status.style.color = 'var(--color-warning)';
            } else {
                status.innerHTML = iconSvg('error');
                status.style.color = 'var(--color-error)';
            }
        }
        if (value) value.textContent = check.value || '—';
    }

    /* ═══════════════════════════════════════════════════════════
       REDE E INTERFACES
    ═══════════════════════════════════════════════════════════ */
    function bindNetworkActions() {
        el('btnDetectInterfaces')?.addEventListener('click', detectInterfaces);
        el('btnAddHomeNet')?.addEventListener('click', addHomeNetFromInput);

        el('fieldHomeNet')?.addEventListener('keydown', event => {
            if (event.key === 'Enter' || event.key === ',') {
                event.preventDefault();
                addHomeNetFromInput();
            }
        });

        all('input[name="modoCaptura"]').forEach(radio => {
            radio.addEventListener('change', () => {
                syncMonitoredInterfacesForMode();
                renderMonitoredInterfaces(state.interfaces);
                updateCaptureModeHint();
                clearNetworkError();
            });
        });

        el('fieldWan')?.addEventListener('change', () => {
            refreshRoleOptionAvailability();
            syncMonitoredInterfacesForMode();
            renderMonitoredInterfaces(state.interfaces);
            updateCaptureModeHint();
            clearNetworkError();
        });

        el('fieldLan')?.addEventListener('change', () => {
            refreshRoleOptionAvailability();
            syncHomeNetFromSelectedLan();
            syncMonitoredInterfacesForMode();
            renderMonitoredInterfaces(state.interfaces);
            updateCaptureModeHint();
            clearNetworkError();
        });

        el('fieldMgmt')?.addEventListener('change', () => {
            refreshRoleOptionAvailability();
            removeMgmtFromMonitoring();
            syncMonitoredInterfacesForMode();
            renderMonitoredInterfaces(state.interfaces);
            updateCaptureModeHint();
            clearNetworkError();
        });

        el('fieldDns')?.addEventListener('change', clearNetworkError);
        el('fieldDns')?.addEventListener('input', clearNetworkError);
    }

    async function detectInterfaces() {
        const button = el('btnDetectInterfaces');
        setButtonLoading(button, true);
        clearNetworkError();
        renderInterfacesLoading();

        const roleSnapshot = {
            wan: firstText(el('fieldWan')?.value, state.configuration?.interface_wan),
            lan: firstText(el('fieldLan')?.value, state.configuration?.interface_lan),
            mgmt: firstText(el('fieldMgmt')?.value, state.configuration?.interface_mgmt),
        };

        try {
            const payload = await requestJSON(CFG.urls.detectarInterfaces, { method: 'GET' });
            const data = unwrapData(payload);

            state.topology = data.topologia || data;
            state.interfaces = extractInterfaces(state.topology, data);

            if (!state.interfaces.length) {
                throw new Error('Nenhuma interface de rede utilizável foi detectada.');
            }

            populateInterfaceSelects(state.interfaces);
            restoreRoleSelections(roleSnapshot);
            initialiseHomeNetBaseFromCurrentSelection();
            syncMonitoredInterfacesForMode({ preservePersonalized: true });
            refreshRoleOptionAvailability();
            renderHomeNetTokens();
            renderMonitoredInterfaces(state.interfaces);
            updateCaptureModeHint();

            showToast(`${state.interfaces.length} interface(s) detectada(s). Defina os papéis conforme sua topologia.`, 'success');
        } catch (error) {
            state.interfaces = [];
            renderInterfacesError(error.message || 'Falha ao detectar interfaces.');
            showNetworkError(error.message || 'Não foi possível detectar as interfaces.');
        } finally {
            setButtonLoading(button, false);
        }
    }

    function extractInterfaces(topology, data) {
        const candidates = [
            topology?.interfaces,
            topology?.interfaces_disponiveis,
            topology?.todas_interfaces,
            data?.interfaces,
            data?.interfaces_disponiveis,
        ].find(Array.isArray) || [];

        const seen = new Set();
        const result = [];

        for (const item of candidates) {
            const object = typeof item === 'string' ? { nome: item } : (item || {});
            const name = firstText(object.nome, object.name, object.interface, object.id);

            if (!name || seen.has(name) || name === 'lo') continue;
            seen.add(name);

            const ipv4 = firstText(object.ipv4, object.ip, object.endereco_ipv4);
            const cidr = firstText(object.cidr, object.ipv4_cidr, object.endereco_cidr, ipv4 && ipv4.includes('/') ? ipv4 : '');
            const rede = firstText(object.rede, object.network, object.rede_ipv4, cidr ? networkFromCidr(cidr) : '');

            result.push({
                nome: name,
                ipv4: ipv4.includes('/') ? ipv4.split('/')[0] : ipv4,
                cidr,
                rede,
                mac: firstText(object.mac, object.endereco_mac),
                estado: firstText(object.estado, object.state, object.status, object.ativa ? 'up' : ''),
                tipo: firstText(object.tipo, object.kind, object.descricao),
                rotaPadrao: Boolean(object.rota_padrao ?? object.default_route ?? false),
            });
        }
        return result;
    }

    function populateInterfaceSelects(interfaces) {
        for (const id of ['fieldWan', 'fieldLan', 'fieldMgmt']) {
            const select = el(id);
            if (!select) continue;

            const previous = select.value;
            select.innerHTML = `<option value="">${id === 'fieldMgmt' ? 'Nenhuma' : 'Selecione...'}</option>`;

            for (const item of interfaces) {
                const option = document.createElement('option');
                option.value = item.nome;
                const endereco = item.cidr || item.ipv4 || '';
                option.textContent = `${item.nome}${endereco ? ` · ${endereco}` : ''}`;
                select.appendChild(option);
            }

            if (interfaces.some(item => item.nome === previous)) select.value = previous;
        }
    }

    function restoreRoleSelections(snapshot) {
        const available = new Set(state.interfaces.map(item => item.nome));
        if (snapshot.wan && available.has(snapshot.wan)) setSelectIfAvailable('fieldWan', snapshot.wan);
        if (snapshot.lan && available.has(snapshot.lan)) setSelectIfAvailable('fieldLan', snapshot.lan);
        if (snapshot.mgmt && available.has(snapshot.mgmt)) setSelectIfAvailable('fieldMgmt', snapshot.mgmt);
    }

    function refreshRoleOptionAvailability() {
        const selections = {
            fieldWan: el('fieldWan')?.value || '',
            fieldLan: el('fieldLan')?.value || '',
            fieldMgmt: el('fieldMgmt')?.value || '',
        };

        for (const id of ['fieldWan', 'fieldLan', 'fieldMgmt']) {
            const select = el(id);
            if (!select) continue;

            for (const option of Array.from(select.options)) {
                if (!option.value) {
                    option.disabled = false;
                    continue;
                }
                option.disabled = Object.entries(selections).some(([otherId, value]) => otherId !== id && Boolean(value) && option.value === value);
            }
        }
    }

    function getInterfaceByName(name) {
        return state.interfaces.find(item => item.nome === name) || null;
    }

    function getInterfaceNetwork(name) {
        const item = getInterfaceByName(name);
        if (!item) return '';
        if (item.rede && isValidCidr(item.rede)) return networkFromCidr(item.rede);
        if (item.cidr && isValidCidr(item.cidr)) return networkFromCidr(item.cidr);
        return '';
    }

    function initialiseHomeNetBaseFromCurrentSelection() {
        const lan = el('fieldLan')?.value || '';
        const lanNetwork = getInterfaceNetwork(lan);

        if (!lanNetwork) {
            state.autoHomeNetBase = '';
            return;
        }

        if (state.homeNet.includes(lanNetwork)) {
            state.autoHomeNetBase = lanNetwork;
            return;
        }

        if (!state.homeNet.length) {
            state.autoHomeNetBase = lanNetwork;
            state.homeNet = [lanNetwork];
        }
    }

    function syncHomeNetFromSelectedLan() {
        const lan = el('fieldLan')?.value || '';
        const newBase = getInterfaceNetwork(lan);
        const oldBase = state.autoHomeNetBase;

        if (oldBase) state.homeNet = state.homeNet.filter(value => value !== oldBase);
        state.autoHomeNetBase = newBase;
        if (newBase && !state.homeNet.includes(newBase)) state.homeNet.unshift(newBase);
        renderHomeNetTokens();
    }

    function removeMgmtFromMonitoring() {
        const mgmt = el('fieldMgmt')?.value || '';
        if (mgmt) state.selectedInterfaces.delete(mgmt);
    }

    function syncMonitoredInterfacesForMode({ preservePersonalized = false } = {}) {
        const mode = getCaptureMode();
        const wan = el('fieldWan')?.value || '';
        const lan = el('fieldLan')?.value || '';
        const mgmt = el('fieldMgmt')?.value || '';

        if (mode === 'lan') state.selectedInterfaces = new Set([lan].filter(Boolean));
        else if (mode === 'lan_wan') state.selectedInterfaces = new Set([lan, wan].filter(Boolean));
        else if (!preservePersonalized && mode === 'personalizado') {
            state.selectedInterfaces = new Set(Array.from(state.selectedInterfaces).filter(Boolean));
        }

        if (mgmt) state.selectedInterfaces.delete(mgmt);
        const available = new Set(state.interfaces.map(item => item.nome));
        state.selectedInterfaces = new Set(Array.from(state.selectedInterfaces).filter(name => available.has(name)));
    }

    function roleForInterface(name) {
        if (!name) return '';
        if (name === (el('fieldWan')?.value || '')) return 'WAN';
        if (name === (el('fieldLan')?.value || '')) return 'LAN';
        if (name === (el('fieldMgmt')?.value || '')) return 'MGMT';
        return '';
    }

    function renderMonitoredInterfaces(interfaces) {
        const container = el('interfacesMonitoradasList');
        if (!container) return;

        container.innerHTML = '';
        const mode = getCaptureMode();
        const manualMode = mode === 'personalizado';
        const mgmt = el('fieldMgmt')?.value || '';

        if (!interfaces.length) {
            renderInterfacesError('Nenhuma interface detectada.');
            return;
        }

        for (const item of interfaces) {
            const role = roleForInterface(item.nome);
            const isMgmt = Boolean(mgmt && item.nome === mgmt);
            const disabled = !manualMode || isMgmt;
            const checked = state.selectedInterfaces.has(item.nome) && !isMgmt;

            const label = document.createElement('label');
            // NOVO ESTILO: Usa a mesma classe dos cartões de seleção bonitos
            label.className = 'selectable-card'; 
            label.style.padding = '12px 16px'; // Um pouco mais compacto
            if (disabled) label.style.opacity = '0.6';

            const roleText = role ? `<span class="selectable-card__badge" style="color:var(--color-primary); font-weight:600;">· ${role}</span>` : '';
            const address = item.cidr || item.ipv4 || '';

            label.innerHTML = `
                <input type="checkbox" value="${escapeHtml(item.nome)}" ${checked ? 'checked' : ''} ${disabled ? 'disabled' : ''}>
                <div class="selectable-card__content" style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span class="selectable-card__title" style="margin-bottom:0;">${escapeHtml(item.nome)}</span>
                        <span class="selectable-card__desc">${escapeHtml(address)}</span>
                    </div>
                    <div style="text-align:right; font-size:12px; color:var(--color-text-tertiary);">
                        ${escapeHtml(isMgmt ? 'gerência' : (item.estado || 'detectada'))} ${roleText}
                    </div>
                </div>
            `;

            const input = label.querySelector('input');
            input?.addEventListener('change', () => {
                if (getCaptureMode() !== 'personalizado') {
                    syncMonitoredInterfacesForMode();
                    renderMonitoredInterfaces(state.interfaces);
                    return;
                }
                if (input.value === (el('fieldMgmt')?.value || '')) {
                    input.checked = false;
                    state.selectedInterfaces.delete(input.value);
                    showNetworkError('A interface de gerenciamento não pode ser monitorada.');
                    return;
                }
                if (input.checked) state.selectedInterfaces.add(input.value);
                else state.selectedInterfaces.delete(input.value);
                clearNetworkError();
            });
            container.appendChild(label);
        }
    }

    // AJUSTE PARA O TERMINAL NOVO
    function appendTerminalLine(log) {
        const container = el('installLogs');
        if (!container) return;

        // Limpa estado vazio
        if (container.children.length === 1 && container.firstElementChild.textContent.includes('Aguardando o início')) {
            container.innerHTML = '';
        }

        const level = String(log.nivel || log.level || 'info').toLowerCase();
        let colorClass = 'info';
        if (['erro', 'error', 'critical'].includes(level)) colorClass = 'error';
        if (['aviso', 'warning', 'warn'].includes(level)) colorClass = 'warning';
        if (['sucesso', 'success', 'ok'].includes(level)) colorClass = 'success';

        const line = document.createElement('div');
        line.className = 'terminal-line';

        const timestamp = parseDate(log.criado_em || log.timestamp || new Date());
        const stage = firstText(log.etapa, log.stage);
        const message = firstText(log.mensagem, log.message, 'Evento sem mensagem');
        
        line.innerHTML = `
            <span class="terminal-time">${formatTime(timestamp)}</span>
            <span class="terminal-level ${colorClass}">${escapeHtml(level.toUpperCase())}</span>
            <span>${stage ? `<span style="opacity:0.7;">[${escapeHtml(stage)}]</span> ` : ''}${escapeHtml(message)}</span>
        `;
        
        container.appendChild(line);
        container.scrollTop = container.scrollHeight;
    }

    function updateCaptureModeHint() {
        const hint = el('captureModeHint');
        const monitoredHint = el('monitoredInterfacesHint');
        const mode = getCaptureMode();

        const messages = {
            lan: 'Somente LAN: o Suricata monitora automaticamente apenas a placa definida como LAN.',
            lan_wan: 'LAN + WAN: o Suricata monitora automaticamente as placas definidas como LAN e WAN.',
            personalizado: 'Personalizado: escolha manualmente as interfaces abaixo. A placa de gerenciamento permanece excluída.',
        };

        if (hint) hint.textContent = messages[mode] || '';
        if (monitoredHint) {
            monitoredHint.textContent = mode === 'personalizado'
                ? 'Modo personalizado ativo: marque somente as interfaces que o Suricata deve capturar.'
                : 'Seleção automática: altere WAN/LAN acima e esta lista será atualizada imediatamente.';
        }
    }

    function renderInterfacesLoading() {
        const container = el('interfacesMonitoradasList');
        if (!container) return;
        container.className = 'card card--highlighted';
        container.style.padding = 'var(--spacing-md)';
        container.innerHTML = `
            <div style="display: flex; gap: var(--spacing-sm); align-items: center; justify-content: center; width: 100%;">
                <span class="spinner"></span>
                <span>Detectando interfaces...</span>
            </div>
        `;
    }

    function renderInterfacesError(message) {
        const container = el('interfacesMonitoradasList');
        if (!container) return;
        container.className = 'alert alert--error';
        container.style.padding = 'var(--spacing-md)';
        container.innerHTML = `
            <div class="alert__icon">⚠</div>
            <div class="alert__content">
                <div class="alert__message">${escapeHtml(message)}</div>
            </div>
        `;
    }

    function addHomeNetFromInput() {
        const input = el('fieldHomeNet');
        if (!input) return;

        const values = input.value.split(',').map(v => v.trim()).filter(Boolean);
        if (!values.length) return;

        const invalid = values.filter(value => !isValidCidr(value));
        if (invalid.length) {
            showNetworkError(`CIDR inválido: ${invalid.join(', ')}.`);
            shake(input.closest('.form-group'));
            return;
        }

        const wanNetwork = getInterfaceNetwork(el('fieldWan')?.value || '');
        const forbiddenWan = values.map(networkFromCidr).filter(value => Boolean(wanNetwork) && value === wanNetwork);

        if (forbiddenWan.length) {
            showNetworkError(`A rede da WAN (${wanNetwork}) não deve entrar no HOME_NET. HOME_NET representa as redes internas protegidas.`);
            shake(input.closest('.form-group'));
            return;
        }

        for (const value of values) {
            const normalised = networkFromCidr(value);
            if (normalised && !state.homeNet.includes(normalised)) state.homeNet.push(normalised);
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
            token.className = 'card';
            token.style.padding = '4px 8px';
            token.style.display = 'flex';
            token.style.alignItems = 'center';
            token.style.gap = 'var(--spacing-sm)';
            token.style.fontSize = '12px';
            token.style.background = 'var(--color-bg-secondary)';

            const isBase = Boolean(state.autoHomeNetBase && network === state.autoHomeNetBase);

            if (isBase) {
                token.innerHTML = `<span style="font-weight:600;">${escapeHtml(network)}</span> <span style="color:var(--color-text-tertiary);">· LAN</span>`;
                token.title = 'Rede base calculada automaticamente a partir da interface LAN.';
            } else {
                token.innerHTML = `
                    <span style="font-weight:600;">${escapeHtml(network)}</span>
                    <button type="button" aria-label="Remover" style="cursor:pointer; color:var(--color-text-secondary); font-size:14px; line-height:1; padding:0 4px;">&times;</button>
                `;
                token.querySelector('button')?.addEventListener('click', () => {
                    state.homeNet = state.homeNet.filter(value => value !== network);
                    renderHomeNetTokens();
                });
            }
            container.appendChild(token);
        }
    }

    function validateNetworkForm() {
        addPendingHomeNet();
        syncMonitoredInterfacesForMode({ preservePersonalized: true });

        const mode = getCaptureMode();
        const wan = el('fieldWan')?.value || '';
        const lan = el('fieldLan')?.value || '';
        const mgmt = el('fieldMgmt')?.value || '';
        const dns = el('fieldDns')?.value.trim() || '';
        const errors = [];

        if (!wan) errors.push('Selecione a interface WAN.');
        if (!lan) errors.push('Selecione a interface LAN.');
        if (wan && lan && wan === lan) errors.push('WAN e LAN devem usar interfaces diferentes.');
        if (mgmt && (mgmt === wan || mgmt === lan)) errors.push('A interface de gerenciamento deve ser diferente da WAN e LAN.');
        if (!state.homeNet.length) errors.push('O HOME_NET precisa conter pelo menos a rede interna da LAN.');
        if (state.homeNet.some(value => !isValidCidr(value))) errors.push('Existe uma rede HOME_NET inválida.');

        const lanNetwork = getInterfaceNetwork(lan);
        if (lanNetwork && !state.homeNet.includes(lanNetwork)) errors.push(`O HOME_NET precisa incluir a rede da LAN (${lanNetwork}).`);

        const wanNetwork = getInterfaceNetwork(wan);
        if (wanNetwork && lanNetwork && wanNetwork !== lanNetwork && state.homeNet.includes(wanNetwork)) {
            errors.push(`A rede da WAN (${wanNetwork}) não deve fazer parte do HOME_NET.`);
        }

        if (!state.selectedInterfaces.size) errors.push('Selecione pelo menos uma interface monitorada.');
        if (mgmt && state.selectedInterfaces.has(mgmt)) errors.push('A interface de gerenciamento não pode ser monitorada.');
        if (mode === 'lan' && lan && !state.selectedInterfaces.has(lan)) errors.push('No modo Somente LAN, a interface LAN precisa ser monitorada.');
        if (mode === 'lan_wan' && ((lan && !state.selectedInterfaces.has(lan)) || (wan && !state.selectedInterfaces.has(wan)))) {
            errors.push('No modo LAN + WAN, as duas interfaces precisam ser monitoradas.');
        }
        if (dns && !isValidIpv4(dns)) errors.push('O DNS interno não é um IPv4 válido.');

        return { ok: errors.length === 0, errors };
    }

    function addPendingHomeNet() {
        const input = el('fieldHomeNet');
        if (input?.value.trim()) addHomeNetFromInput();
    }

    /* ═══════════════════════════════════════════════════════════
       PROTEÇÃO E CONFIGURAÇÃO
    ═══════════════════════════════════════════════════════════ */
    function bindProtectionActions() {
        for (const id of ['fieldEtOpen', 'fieldRestartServices', 'fieldYamlPath', 'fieldEvePath']) {
            el(id)?.addEventListener('change', updateReview);
            el(id)?.addEventListener('input', updateReview);
        }
    }

    function validateProtectionForm() {
        const errors = [];
        const yaml = el('fieldYamlPath')?.value.trim() || '';
        const eve = el('fieldEvePath')?.value.trim() || '';
        if (!yaml || !yaml.startsWith('/')) errors.push('Informe um caminho absoluto para o suricata.yaml.');
        if (!eve || !eve.startsWith('/')) errors.push('Informe um caminho absoluto para o eve.json.');
        if (yaml.includes('\0') || eve.includes('\0')) errors.push('Os caminhos informados são inválidos.');
        return { ok: errors.length === 0, errors };
    }

    function collectConfiguration() {
        addPendingHomeNet();
        return {
            nome: state.configuration?.nome || 'Suricata Local',
            interface_wan: el('fieldWan')?.value || '',
            interface_lan: el('fieldLan')?.value || '',
            interface_mgmt: el('fieldMgmt')?.value || '',
            interfaces_monitoradas: Array.from(state.selectedInterfaces),
            home_net: [...state.homeNet],
            dns_interno: el('fieldDns')?.value.trim() || null,
            yaml_path: el('fieldYamlPath')?.value.trim() || '/etc/suricata/suricata.yaml',
            eve_path: el('fieldEvePath')?.value.trim() || '/var/log/suricata/eve.json',
            cursor_path: state.configuration?.cursor_path || 'var/cursors/suricata_eve.cursor',
            modo_captura: getCaptureMode(),
            instalar_et_open: Boolean(el('fieldEtOpen')?.checked),
            instalar_regras_moonshield: true,
            reiniciar_servicos: Boolean(el('fieldRestartServices')?.checked),
        };
    }

    async function saveConfiguration({ quiet = false } = {}) {
        const configuration = collectConfiguration();
        const payload = await requestJSON(CFG.urls.salvarConfiguracao, {
            method: 'POST',
            body: configuration,
        });
        const data = unwrapData(payload);
        state.configuration = normaliseObject(data.configuracao || data.configuration || data);
        applyConfigurationToForm(state.configuration);
        if (!quiet) showToast('Configuração salva com sucesso.', 'success');
        return state.configuration;
    }

    function applyConfigurationToForm(configuration) {
        const cfg = normaliseObject(configuration);
        if (!Object.keys(cfg).length) return;

        state.homeNet = arrayOfStrings(cfg.home_net);
        state.selectedInterfaces = new Set(arrayOfStrings(cfg.interfaces_monitoradas));
        state.autoHomeNetBase = '';

        setValue('fieldDns', cfg.dns_interno || '');
        setValue('fieldYamlPath', cfg.yaml_path || '/etc/suricata/suricata.yaml');
        setValue('fieldEvePath', cfg.eve_path || '/var/log/suricata/eve.json');

        if (el('fieldEtOpen')) el('fieldEtOpen').checked = cfg.instalar_et_open !== false;
        if (el('fieldRestartServices')) el('fieldRestartServices').checked = cfg.reiniciar_servicos !== false;

        const mode = cfg.modo_captura || 'lan_wan';
        const radio = document.querySelector(`input[name="modoCaptura"][value="${cssEscape(mode)}"]`);
        if (radio) radio.checked = true;

        setSelectIfAvailable('fieldWan', cfg.interface_wan || '');
        setSelectIfAvailable('fieldLan', cfg.interface_lan || '');
        setSelectIfAvailable('fieldMgmt', cfg.interface_mgmt || '');

        if (state.interfaces.length) {
            initialiseHomeNetBaseFromCurrentSelection();
            syncMonitoredInterfacesForMode({ preservePersonalized: true });
            refreshRoleOptionAvailability();
            renderMonitoredInterfaces(state.interfaces);
        }

        renderHomeNetTokens();
        updateCaptureModeHint();
    }

    /* ═══════════════════════════════════════════════════════════
       REVISÃO E PLANO
    ═══════════════════════════════════════════════════════════ */
    function bindReviewActions() {
        el('confirmInstall')?.addEventListener('change', () => {
            if (el('btnStartInstall')) el('btnStartInstall').disabled = !el('confirmInstall').checked;
            clearReviewError();
        });
        el('btnStartInstall')?.addEventListener('click', startInstallation);
    }

    function updateReview() {
        const cfg = collectConfiguration();
        const modeLabels = { lan: 'Somente LAN', lan_wan: 'LAN + WAN', personalizado: 'Personalizado' };
        setText('reviewMode', modeLabels[cfg.modo_captura] || cfg.modo_captura);
        setText('reviewWan', cfg.interface_wan || 'Não utilizada');
        setText('reviewLan', cfg.interface_lan || 'Não definida');
        setText('reviewHomeNet', cfg.home_net.length ? cfg.home_net.join(', ') : 'Não definida');
        setText('reviewEtOpen', cfg.instalar_et_open ? 'Ativado' : 'Desativado');
        setText('reviewRestart', cfg.reiniciar_servicos ? 'Reiniciar após instalar' : 'Não reiniciar automaticamente');
    }

    async function refreshOnboardingData() {
        try {
            const payload = await requestJSON(CFG.urls.onboardingStatus, { method: 'GET' });
            const data = unwrapData(payload);
            state.onboardingStatus = normaliseObject(data.status_onboarding || data.onboarding || data.status || {});
            state.plan = normaliseObject(data.plano_instalacao || data.plano || data.plan || {});
            if (data.configuracao) state.configuration = normaliseObject(data.configuracao);
            applyPlan(state.plan);
        } catch (error) {
            console.warn('Plano remoto indisponível; usando plano padrão.', error);
            applyPlan(state.plan);
        }
    }

    function applyPlan(plan) {
        const data = normaliseObject(plan);
        const steps = Array.isArray(data.etapas) ? data.etapas : [];
        const container = el('installationPlanSteps');

        if (steps.length && container) {
            container.innerHTML = '';
            steps.forEach((step, index) => {
                const item = document.createElement('li');
                item.className = 'list__item';
                item.innerHTML = `
                    <div class="list__marker">${index + 1}</div>
                    <div class="list__content">
                        <div class="list__title">${escapeHtml(firstText(step.titulo, step.nome, step.id, 'Etapa'))}</div>
                        <div class="list__desc">${escapeHtml(firstText(step.descricao, step.mensagem, step.obrigatoria === false ? 'Opcional' : 'Obrigatória'))}</div>
                    </div>
                `;
                container.appendChild(item);
            });
        }

        const seconds = Number(data.estimativa_segundos || data.duracao_estimada_segundos || 0);
        if (seconds > 0) setText('planDuration', `≈ ${humanDuration(seconds)}`);
    }

    /* ═══════════════════════════════════════════════════════════
       INSTALAÇÃO, TAREFAS E LOGS
    ═══════════════════════════════════════════════════════════ */
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

        const network = validateNetworkForm();
        const protection = validateProtectionForm();
        if (!network.ok || !protection.ok) {
            showReviewError([...network.errors, ...protection.errors].join(' '));
            return;
        }

        const button = el('btnStartInstall');
        setButtonLoading(button, true);

        try {
            await saveConfiguration({ quiet: true });
            const parameters = {
                configuracao: collectConfiguration(),
                instalar_et_open: Boolean(el('fieldEtOpen')?.checked),
                reiniciar_servicos: Boolean(el('fieldRestartServices')?.checked),
                executar_diagnostico_final: true,
            };

            const payload = await requestJSON(CFG.urls.criarTarefa, {
                method: 'POST',
                body: { tipo: 'instalacao', parametros: parameters },
            });
            const data = unwrapData(payload);
            const task = data.tarefa || data.task || data;
            if (!task?.id) throw new Error('A API não retornou o identificador da tarefa.');

            state.activeTask = task;
            state.taskRunning = true;
            state.taskFinished = false;
            state.taskSucceeded = false;
            state.taskStartedAt = new Date(task.iniciado_em || task.criado_em || Date.now());
            state.lastLogOffset = 0;
            state.renderedLogKeys.clear();

            unlockStep(6);
            goToStep(6);
            prepareInstallationUI(task);
            startElapsedTimer();
            startTaskPolling(task.id);
            startLogPolling(task.id);

            appendLocalLog('INFO', 'Tarefa criada. Aguardando o executor seguro iniciar a instalação.', 'tarefa');
            showToast('Tarefa de instalação criada.', 'success');
        } catch (error) {
            showReviewError(error.message || 'Não foi possível criar a tarefa de instalação.');
            showToast(error.message || 'Falha ao iniciar a instalação.', 'error');
        } finally {
            setButtonLoading(button, false);
        }
    }

    async function resumeExistingTask() {
        if (!CFG.urls?.listarTarefas) return;
        try {
            const payload = await requestJSON(`${CFG.urls.listarTarefas}?tipo=instalacao&limite=10&offset=0`, { method: 'GET' });
            const data = unwrapData(payload);
            const tasks = data.tarefas || data.results || [];
            const active = tasks.find(task => ['pendente', 'executando'].includes(String(task.status).toLowerCase()));
            if (!active) return;

            state.activeTask = active;
            state.taskRunning = true;
            state.taskStartedAt = new Date(active.iniciado_em || active.criado_em || Date.now());
            unlockStep(6);
            goToStep(6);
            prepareInstallationUI(active);
            startElapsedTimer();
            startTaskPolling(active.id);
            startLogPolling(active.id);
            showToast('Uma tarefa de instalação em andamento foi restaurada.', 'info');
        } catch (error) {
            console.debug('Nenhuma tarefa restaurada:', error);
        }
    }

    function prepareInstallationUI(task) {
        if (el('installResult')) el('installResult').hidden = true;
        if (el('progressCard')) el('progressCard').hidden = false;
        if (el('btnCancelInstall')) el('btnCancelInstall').hidden = false;
        if (el('btnRetryInstall')) el('btnRetryInstall').hidden = true;
        if (el('btnFinishOnboarding')) el('btnFinishOnboarding').hidden = true;

        setText('installEyebrow', 'Instalação em andamento');
        setText('installTitle', 'Preparando o sensor MoonShield.');
        setText('installDescription', 'Não feche esta página enquanto a configuração estiver em andamento.');
        setText('installTaskId', `Tarefa: ${task.id}`);
        updateTaskProgress(task);
        resetStages();
        clearTerminal();
    }

    function startTaskPolling(taskId) {
        stopTaskPolling();
        const poll = async () => {
            try {
                const payload = await requestJSON(resolveTemplateUrl(CFG.urls.detalheTarefaTemplate, taskId), { method: 'GET' });
                const data = unwrapData(payload);
                const task = data.tarefa || data.task || data;
                state.activeTask = task;
                updateTaskProgress(task);

                if (isFinalTaskStatus(task.status)) {
                    await handleTaskFinished(task);
                    return;
                }
            } catch (error) {
                appendLocalLog('AVISO', `Falha temporária ao consultar a tarefa: ${error.message}`, 'consulta');
            }
            state.taskPollTimer = window.setTimeout(poll, POLL_INTERVAL_MS);
        };
        poll();
    }

    function stopTaskPolling() {
        if (state.taskPollTimer) window.clearTimeout(state.taskPollTimer);
        state.taskPollTimer = null;
    }

    function startLogPolling(taskId) {
        stopLogPolling();
        const poll = async () => {
            try {
                const url = `${resolveTemplateUrl(CFG.urls.logsTarefaTemplate, taskId)}?offset=${state.lastLogOffset}&limite=200`;
                const payload = await requestJSON(url, { method: 'GET' });
                const data = unwrapData(payload);
                const logs = Array.isArray(data.logs) ? data.logs : [];
                renderTaskLogs(logs);
                state.lastLogOffset = Number(data.proximo_offset ?? (state.lastLogOffset + logs.length));
            } catch (error) {
                console.debug('Falha ao consultar logs:', error);
            }
            if (!state.taskFinished) state.logPollTimer = window.setTimeout(poll, LOG_POLL_INTERVAL_MS);
        };
        poll();
    }

    function stopLogPolling() {
        if (state.logPollTimer) window.clearTimeout(state.logPollTimer);
        state.logPollTimer = null;
    }

    function updateTaskProgress(task) {
        const progress = clamp(Number(task.progresso ?? task.percentual ?? 0), 0, 100);
        const stage = firstText(task.etapa_atual, task.etapa, inferStageFromProgress(progress), 'verificar_ambiente');
        const message = firstText(task.mensagem, statusMessage(task.status), 'Aguardando atualização');

        setText('installPercent', `${Math.round(progress)}%`);
        if (el('installProgressBar')) el('installProgressBar').style.width = `${progress}%`;
        setText('currentStageTitle', stageTitle(stage));
        setText('currentStageMessage', message);
        setText('installTaskId', `Tarefa: ${task.id || '—'}`);
        updateStages(stage, task.status, progress);

        if (String(task.status).toLowerCase() === 'pendente') {
            setText('installEyebrow', 'Tarefa aguardando execução');
            setText('installDescription', 'A tarefa foi registrada e aguarda o executor seguro do MoonShield.');
        } else if (String(task.status).toLowerCase() === 'executando') {
            setText('installEyebrow', 'Instalação em andamento');
            setText('installDescription', 'O servidor está sendo preparado e validado etapa por etapa.');
        }
    }

    async function handleTaskFinished(task) {
        state.taskFinished = true;
        state.taskRunning = false;
        state.taskSucceeded = String(task.status).toLowerCase() === 'sucesso';
        stopTaskPolling();
        stopLogPolling();
        stopElapsedTimer();

        try {
            const url = `${resolveTemplateUrl(CFG.urls.logsTarefaTemplate, task.id)}?offset=${state.lastLogOffset}&limite=500`;
            const payload = await requestJSON(url, { method: 'GET' });
            const data = unwrapData(payload);
            renderTaskLogs(Array.isArray(data.logs) ? data.logs : []);
        } catch (_) {}

        if (state.taskSucceeded) showInstallationSuccess(task);
        else showInstallationFailure(task);
    }

    function showInstallationSuccess(task) {
        setText('installEyebrow', 'Instalação concluída');
        setText('installTitle', 'O Suricata está pronto.');
        setText('installDescription', 'O sensor foi configurado, validado e ativado com sucesso.');
        if (el('btnCancelInstall')) el('btnCancelInstall').hidden = true;
        if (el('btnRetryInstall')) el('btnRetryInstall').hidden = true;
        if (el('btnFinishOnboarding')) el('btnFinishOnboarding').hidden = false;

        renderResult({
            success: true,
            eyebrow: 'Instalação concluída',
            title: 'O Suricata está pronto.',
            message: firstText(task.mensagem, 'O sensor foi configurado e já pode enviar eventos ao MoonShield.'),
            task,
        });
        updateSidebarSystem('ok', 'Suricata ativo');
        showToast('Instalação concluída com sucesso.', 'success');
    }

    function showInstallationFailure(task) {
        const cancelled = String(task.status).toLowerCase() === 'cancelado';
        setText('installEyebrow', cancelled ? 'Instalação cancelada' : 'Falha na instalação');
        setText('installTitle', cancelled ? 'A tarefa foi cancelada.' : 'A instalação precisa de atenção.');
        setText('installDescription', firstText(task.erro, task.mensagem, 'Revise os logs e tente novamente.'));
        if (el('btnCancelInstall')) el('btnCancelInstall').hidden = true;
        if (el('btnRetryInstall')) el('btnRetryInstall').hidden = false;
        if (el('btnFinishOnboarding')) el('btnFinishOnboarding').hidden = true;

        renderResult({
            success: false,
            eyebrow: cancelled ? 'Tarefa cancelada' : 'Instalação não concluída',
            title: cancelled ? 'A instalação foi interrompida.' : 'Não foi possível concluir a instalação.',
            message: firstText(task.erro, task.mensagem, 'Consulte os logs para identificar a etapa que falhou.'),
            task,
        });
        updateSidebarSystem('error', cancelled ? 'Instalação cancelada' : 'Instalação com erro');
        showToast(cancelled ? 'Tarefa cancelada.' : 'A instalação falhou.', cancelled ? 'warning' : 'error');
    }

    function renderResult({ success, eyebrow, title, message, task }) {
        const result = el('installResult');
        if (!result) return;
        result.hidden = false;
        result.className = `alert alert--${success ? 'success' : 'error'}`;
        
        if (el('resultTitle')) el('resultTitle').textContent = title;
        if (el('resultMessage')) el('resultMessage').textContent = message;

        const details = normaliseObject(task.resultado || task.result || {});
        const status = normaliseObject(details.status_final || details.status || details.stack || {});
        const suricata = normaliseObject(status.suricata || details.suricata || {});
        const version = firstText(suricata.versao, details.versao_suricata, state.configuration?.versao_suricata, success ? 'Detectada' : '—');
        const mainInterface = firstText(state.configuration?.interface_lan, state.configuration?.interface_wan, Array.from(state.selectedInterfaces)[0], '—');

        setText('resultVersion', version);
        setText('resultInterface', mainInterface);
        setText('resultStatus', success ? 'Ativo' : String(task.status || 'Erro'));
        if (el('resultStatus')) el('resultStatus').style.color = success ? 'var(--color-success)' : 'var(--color-error)';
    }

    function updateStages(currentStage, taskStatus, progress) {
        const stages = all('.list__item[data-stage]');
        let currentIndex = stages.findIndex(item => item.dataset.stage === currentStage);
        if (currentIndex < 0) currentIndex = stageIndexFromProgress(progress, stages.length);
        const final = isFinalTaskStatus(taskStatus);
        const success = String(taskStatus).toLowerCase() === 'sucesso';

        stages.forEach((item, index) => {
            const marker = item.querySelector('.list__marker');
            const detail = item.querySelector('.list__desc');
            
            if (marker) {
                marker.style.background = 'var(--color-bg-secondary)';
                marker.style.color = 'var(--color-text-secondary)';
                marker.innerHTML = '';
            }

            if (index < currentIndex || (final && success)) {
                if (marker) {
                    marker.style.background = 'var(--color-success)';
                    marker.style.color = '#fff';
                    marker.innerHTML = iconSvg('check');
                }
                if (detail) detail.textContent = 'Concluído';
            } else if (index === currentIndex && !final) {
                if (marker) {
                    marker.style.background = 'var(--color-primary-light)';
                    marker.style.color = 'var(--color-primary)';
                    marker.innerHTML = '<span class="spinner"></span>';
                }
                if (detail) detail.textContent = 'Em execução';
            } else if (index === currentIndex && final && !success) {
                if (marker) {
                    marker.style.background = 'var(--color-error)';
                    marker.style.color = '#fff';
                    marker.innerHTML = '⚠';
                }
                if (detail) detail.textContent = 'Falhou';
            } else {
                if (detail) detail.textContent = 'Aguardando';
            }
        });
    }

    function resetStages() {
        all('.list__item[data-stage]').forEach((item, index) => {
            const marker = item.querySelector('.list__marker');
            const detail = item.querySelector('.list__desc');
            
            if (marker) {
                if (index === 0) {
                    marker.style.background = 'var(--color-primary-light)';
                    marker.style.color = 'var(--color-primary)';
                    marker.innerHTML = '<span class="spinner"></span>';
                } else {
                    marker.style.background = 'var(--color-bg-secondary)';
                    marker.style.color = 'var(--color-text-secondary)';
                    marker.innerHTML = '';
                }
            }
            if (detail) detail.textContent = index === 0 ? 'Aguardando execução' : 'Aguardando';
        });
    }

    async function cancelActiveTask() {
        const task = state.activeTask;
        if (!task?.id || state.taskFinished) return;
        const button = el('btnCancelInstall');
        setButtonLoading(button, true);
        try {
            const payload = await requestJSON(resolveTemplateUrl(CFG.urls.cancelarTarefaTemplate, task.id), {
                method: 'POST',
                body: {},
            });
            const data = unwrapData(payload);
            state.activeTask = data.tarefa || data.task || data;
            appendLocalLog('AVISO', 'Cancelamento solicitado. A interrupção ocorrerá entre etapas seguras.', 'cancelamento');
            showToast('Cancelamento solicitado.', 'warning');
        } catch (error) {
            showToast(error.message || 'Não foi possível solicitar o cancelamento.', 'error');
        } finally {
            setButtonLoading(button, false);
        }
    }

    async function finishOnboarding() {
        const button = el('btnFinishOnboarding');
        setButtonLoading(button, true);
        try {
            await requestJSON(CFG.urls.concluirOnboarding, { method: 'POST', body: {} });
            state.leavingAllowed = true;
            window.location.assign(CFG.urls.painel);
        } catch (error) {
            showToast(error.message || 'Não foi possível concluir o onboarding.', 'error');
            setButtonLoading(button, false);
        }
    }

    function resetInstallationUI() {
        state.activeTask = null;
        state.taskRunning = false;
        state.taskFinished = false;
        state.taskSucceeded = false;
        state.lastLogOffset = 0;
        state.renderedLogKeys.clear();
        stopTaskPolling();
        stopLogPolling();
        stopElapsedTimer();
        setText('installPercent', '0%');
        if (el('installProgressBar')) el('installProgressBar').style.width = '0%';
        setText('installTaskId', 'Tarefa: —');
        setText('installElapsed', '00:00');
        resetStages();
        clearTerminal();
        if (el('installResult')) el('installResult').hidden = true;
    }

    /* ═══════════════════════════════════════════════════════════
       LOGS
    ═══════════════════════════════════════════════════════════ */
    function renderTaskLogs(logs) {
        for (const log of logs) {
            const key = `${log.id ?? ''}|${log.sequencia ?? ''}|${log.criado_em ?? ''}|${log.mensagem ?? ''}`;
            if (state.renderedLogKeys.has(key)) continue;
            state.renderedLogKeys.add(key);
            appendTerminalLine(log);
        }
        trimTerminalLogs();
    }

    function appendLocalLog(level, message, stage = '') {
        appendTerminalLine({
            nivel: level.toLowerCase(),
            mensagem: message,
            etapa: stage,
            criado_em: new Date().toISOString(),
        });
    }

    function appendTerminalLine(log) {
        const container = el('installLogs');
        if (!container) return;

        // Limpa o placeholder de inicio se existir
        if (container.children.length === 1 && container.firstElementChild.textContent.includes('Aguardando o início')) {
            container.innerHTML = '';
        }

        const level = String(log.nivel || log.level || 'info').toLowerCase();
        const line = document.createElement('div');
        
        let colorLevel = 'var(--color-info)';
        if (['erro', 'error', 'critical'].includes(level)) colorLevel = 'var(--color-error)';
        if (['aviso', 'warning', 'warn'].includes(level)) colorLevel = 'var(--color-warning)';
        if (['sucesso', 'success', 'ok'].includes(level)) colorLevel = 'var(--color-success)';
        if (['debug'].includes(level)) colorLevel = 'var(--color-text-tertiary)';

        line.style.display = 'flex';
        line.style.gap = 'var(--spacing-md)';
        line.style.marginBottom = '4px';
        line.style.opacity = '0.9';

        const timestamp = parseDate(log.criado_em || log.timestamp || new Date());
        const stage = firstText(log.etapa, log.stage);
        const message = firstText(log.mensagem, log.message, 'Evento sem mensagem');
        
        line.innerHTML = `
            <span style="color: var(--color-text-tertiary); min-width: 60px;">${formatTime(timestamp)}</span>
            <span style="color: ${colorLevel}; min-width: 50px; font-weight: 600;">${escapeHtml(level.toUpperCase())}</span>
            <span style="flex: 1; word-break: break-all;">${stage ? `<strong style="opacity:0.8;">[${escapeHtml(stage)}]</strong> ` : ''}${escapeHtml(message)}</span>
        `;
        
        container.appendChild(line);
        container.scrollTop = container.scrollHeight;
    }

    function clearTerminal() {
        const container = el('installLogs');
        if (!container) return;
        container.innerHTML = `
            <div style="display: flex; gap: var(--spacing-sm); margin-bottom: 4px; opacity: 0.7;">
                <span style="color: var(--color-text-tertiary);">--:--:--</span>
                <span style="color: var(--color-info); font-weight: 600;">INFO</span>
                <span>Aguardando o início da tarefa...</span>
            </div>
        `;
    }

    function trimTerminalLogs() {
        const container = el('installLogs');
        if (!container) return;
        while (container.children.length > MAX_RENDERED_LOGS) container.firstElementChild?.remove();
    }

    function toggleLogs() {
        const terminal = el('installTerminal');
        if (!terminal) return;
        state.logsVisible = !state.logsVisible;
        if (el('installLogs')) el('installLogs').hidden = !state.logsVisible;
        setText('btnToggleLogs', state.logsVisible ? 'Ocultar logs' : 'Mostrar logs');
    }

    /* ═══════════════════════════════════════════════════════════
       TEMPO
    ═══════════════════════════════════════════════════════════ */
    function startElapsedTimer() {
        stopElapsedTimer();
        const update = () => {
            if (!state.taskStartedAt) return;
            const seconds = Math.max(0, Math.floor((Date.now() - state.taskStartedAt.getTime()) / 1000));
            setText('installElapsed', formatElapsed(seconds));
        };
        update();
        state.elapsedTimer = window.setInterval(update, 1000);
    }

    function stopElapsedTimer() {
        if (state.elapsedTimer) window.clearInterval(state.elapsedTimer);
        state.elapsedTimer = null;
    }

    /* ═══════════════════════════════════════════════════════════
       PROTEÇÃO DE SAÍDA E MODAL
    ═══════════════════════════════════════════════════════════ */
    function bindLeaveProtection() {
        window.addEventListener('beforeunload', event => {
            if (state.taskRunning && !state.taskFinished && !state.leavingAllowed) {
                event.preventDefault();
                event.returnValue = '';
            }
        });

        all('[data-close-modal]').forEach(node => node.addEventListener('click', closeLeaveModal));
        document.addEventListener('keydown', event => {
            if (event.key === 'Escape' && el('leaveModal')?.classList.contains('active')) closeLeaveModal();
        });
    }

    function closeLeaveModal() {
        const modal = el('leaveModal');
        if (modal) modal.classList.remove('active');
    }

    /* ═══════════════════════════════════════════════════════════
       API
    ═══════════════════════════════════════════════════════════ */
    async function requestJSON(url, { method = 'GET', body = undefined, headers = {}, timeout = 30000 } = {}) {
        if (!url) throw new Error('URL da API não configurada.');

        const controller = new AbortController();
        const timeoutId = window.setTimeout(() => controller.abort(), timeout);
        const requestHeaders = {
            Accept: 'application/json',
            ...headers,
        };

        const options = {
            method,
            credentials: 'same-origin',
            headers: requestHeaders,
            signal: controller.signal,
        };

        if (method !== 'GET' && method !== 'HEAD') {
            requestHeaders['Content-Type'] = 'application/json';
            if (CFG.csrfToken) requestHeaders['X-CSRFToken'] = CFG.csrfToken;
            options.body = JSON.stringify(body ?? {});
        }

        try {
            const response = await fetch(url, options);
            const contentType = response.headers.get('content-type') || '';
            const payload = contentType.includes('application/json')
                ? await response.json()
                : { ok: false, mensagem: (await response.text()).trim() || `HTTP ${response.status}` };

            if (!response.ok || payload?.ok === false) {
                const errors = Array.isArray(payload?.erros) ? payload.erros.filter(Boolean) : [];
                const message = firstText(payload?.mensagem, payload?.msg, payload?.erro, errors.join(' '), `Erro HTTP ${response.status}`);
                const error = new Error(message);
                error.status = response.status;
                error.payload = payload;
                throw error;
            }
            return payload;
        } catch (error) {
            if (error.name === 'AbortError') throw new Error('A operação excedeu o tempo limite.');
            throw error;
        } finally {
            window.clearTimeout(timeoutId);
        }
    }

    function unwrapData(payload) {
        if (payload && typeof payload === 'object' && payload.dados && typeof payload.dados === 'object') return payload.dados;
        return payload || {};
    }

    /* ═══════════════════════════════════════════════════════════
       FEEDBACK VISUAL E HELPERS
    ═══════════════════════════════════════════════════════════ */
    function showToast(message, type = 'info', duration = 4200) {
        const container = el('toastContainer');
        if (!container || !message) return;
        const toast = document.createElement('div');
        
        toast.className = `alert alert--${type}`;
        toast.style.position = 'relative';
        toast.style.marginBottom = 'var(--spacing-sm)';
        toast.style.boxShadow = 'var(--shadow-md)';
        toast.style.animation = 'fadeIn 0.3s ease';
        toast.style.minWidth = '280px';
        
        toast.setAttribute('role', type === 'error' ? 'alert' : 'status');
        
        const icon = type === 'success' ? '✓' : type === 'error' ? '⚠' : type === 'warning' ? '⚠' : 'ℹ';
        
        toast.innerHTML = `
            <div class="alert__icon">${icon}</div>
            <div class="alert__content" style="padding-right: 24px;">
                <div class="alert__message" style="font-weight: 500;">${escapeHtml(message)}</div>
            </div>
            <button type="button" style="position: absolute; right: 8px; top: 12px; cursor: pointer; opacity: 0.5; font-size: 16px; line-height: 1;" aria-label="Fechar">&times;</button>
        `;
        
        const close = () => {
            toast.style.opacity = '0';
            toast.style.transition = 'opacity 0.2s ease';
            window.setTimeout(() => toast.remove(), 200);
        };
        
        toast.querySelector('button')?.addEventListener('click', close);
        container.appendChild(toast);
        window.setTimeout(close, duration);
    }

    function showEnvironmentError(message) {
        if (el('environmentError')) el('environmentError').hidden = false;
        setText('environmentErrorText', message);
    }

    function clearEnvironmentError() {
        if (el('environmentError')) el('environmentError').hidden = true;
        setText('environmentErrorText', '');
    }

    function showNetworkError(message) {
        if (el('networkError')) el('networkError').hidden = false;
        setText('networkErrorText', message);
    }

    function clearNetworkError() {
        if (el('networkError')) el('networkError').hidden = true;
        setText('networkErrorText', '');
    }

    function showReviewError(message) {
        if (el('reviewError')) el('reviewError').hidden = false;
        setText('reviewErrorText', message);
    }

    function clearReviewError() {
        if (el('reviewError')) el('reviewError').hidden = true;
        setText('reviewErrorText', '');
    }

    function updateSidebarSystem(status, text) {
        const dot = el('sidebarSystemDot');
        if (dot) {
            dot.className = 'spinner';
            dot.style.borderColor = 'var(--color-border-light)';
            if (status === 'ok') {
                dot.style.borderTopColor = 'var(--color-success)';
                dot.style.animation = 'none'; // Para de girar se estiver ok
                dot.style.background = 'var(--color-success)';
            } else if (status === 'error') {
                dot.style.borderTopColor = 'var(--color-error)';
                dot.style.animation = 'none';
                dot.style.background = 'var(--color-error)';
            } else {
                dot.style.borderTopColor = 'var(--color-primary)';
                dot.style.animation = 'spin 0.8s linear infinite';
                dot.style.background = 'transparent';
            }
        }
        setText('sidebarSystemText', text);
    }

    function setButtonLoading(button, loading) {
        if (!button) return;
        button.classList.toggle('loading', loading);
        button.disabled = loading || button.dataset.forceDisabled === 'true';
        button.setAttribute('aria-busy', String(loading));
    }

    function shake(node) {
        if (!node) return;
        // Injetamos estilo básico de shake caso não exista no CSS base
        if (!document.getElementById('ob-shake-style')) {
            const style = document.createElement('style');
            style.id = 'ob-shake-style';
            style.innerHTML = `
                @keyframes ob-shake {
                    0%, 100% { transform: translateX(0); }
                    25% { transform: translateX(-4px); }
                    75% { transform: translateX(4px); }
                }
                .ob-shake { animation: ob-shake 0.3s ease-in-out; }
            `;
            document.head.appendChild(style);
        }
        
        node.classList.remove('ob-shake');
        void node.offsetWidth;
        node.classList.add('ob-shake');
        node.addEventListener('animationend', () => node.classList.remove('ob-shake'), { once: true });
    }

    function getCaptureMode() {
        return document.querySelector('input[name="modoCaptura"]:checked')?.value || 'lan_wan';
    }

    function setValue(id, value) {
        const node = el(id);
        if (node) node.value = value ?? '';
    }

    function setText(id, value) {
        const node = el(id);
        if (node) node.textContent = value ?? '';
    }

    function setSelectIfAvailable(id, value) {
        const select = el(id);
        if (!select) return;
        if (!value) {
            select.value = '';
            return;
        }
        const exists = Array.from(select.options).some(option => option.value === value);
        if (exists) select.value = value;
        else select.dataset.pendingValue = value;
    }

    function normaliseObject(value) {
        return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
    }

    function arrayOfStrings(value) {
        if (!Array.isArray(value)) return [];
        return value.map(item => String(item).trim()).filter(Boolean);
    }

    function firstText(...values) {
        for (const value of values) {
            if (value === null || value === undefined) continue;
            const text = String(value).trim();
            if (text) return text;
        }
        return '';
    }

    function readBoolean(object, keys, fallback = false) {
        for (const key of keys) {
            if (Object.prototype.hasOwnProperty.call(object || {}, key)) return Boolean(object[key]);
        }
        return fallback;
    }

    function clamp(value, min, max) {
        return Math.min(max, Math.max(min, Number.isFinite(value) ? value : min));
    }

    function isValidIpv4(value) {
        const parts = String(value).split('.');
        return parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
    }

    function ipToUint32(ip) {
        const parts = String(ip).split('.').map(Number);
        if (parts.length !== 4 || parts.some(part => !Number.isInteger(part) || part < 0 || part > 255)) {
            return null;
        }
        return (((parts[0] << 24) >>> 0) + ((parts[1] << 16) >>> 0) + ((parts[2] << 8) >>> 0) + (parts[3] >>> 0)) >>> 0;
    }

    function uint32ToIp(value) {
        const number = Number(value) >>> 0;
        return [(number >>> 24) & 255, (number >>> 16) & 255, (number >>> 8) & 255, number & 255].join('.');
    }

    function networkFromCidr(value) {
        const raw = String(value || '').trim();
        if (!isValidCidr(raw)) return '';

        const [ip, prefixText] = raw.split('/');
        const prefix = Number(prefixText);
        const ipNumber = ipToUint32(ip);

        if (ipNumber === null) return '';

        const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
        const network = (ipNumber & mask) >>> 0;
        return `${uint32ToIp(network)}/${prefix}`;
    }

    function isValidCidr(value) {
        const [ip, prefix, extra] = String(value).split('/');
        if (extra !== undefined || !isValidIpv4(ip) || !/^\d{1,2}$/.test(prefix || '')) return false;
        return Number(prefix) >= 0 && Number(prefix) <= 32;
    }

    function resolveTemplateUrl(template, taskId) {
        return String(template || '').replace('__ID__', encodeURIComponent(taskId));
    }

    function isFinalTaskStatus(status) {
        return ['sucesso', 'erro', 'cancelado', 'ignorado'].includes(String(status || '').toLowerCase());
    }

    function statusMessage(status) {
        const messages = {
            pendente: 'Aguardando o executor seguro',
            executando: 'Executando tarefa',
            sucesso: 'Tarefa concluída',
            erro: 'A tarefa falhou',
            cancelado: 'Tarefa cancelada',
            ignorado: 'Tarefa ignorada',
        };
        return messages[String(status || '').toLowerCase()] || 'Atualizando status';
    }

    function stageTitle(stage) {
        const titles = {
            verificar_ambiente: 'Verificando ambiente',
            validar_pre_requisitos: 'Validando pré-requisitos',
            instalar_suricata: 'Instalando Suricata',
            instalar_suricata_update: 'Preparando suricata-update',
            atualizar_et_open: 'Atualizando regras ET Open',
            validar_topologia: 'Validando topologia',
            copiar_regras_moonshield: 'Aplicando regras MoonShield',
            configurar_suricata: 'Aplicando configuração',
            validar_suricata: 'Validando o Suricata',
            reiniciar_servicos: 'Ativando serviços',
            validar_instalacao: 'Executando diagnóstico final',
        };
        return titles[stage] || String(stage || 'Executando').replaceAll('_', ' ');
    }

    function inferStageFromProgress(progress) {
        if (progress < 15) return 'verificar_ambiente';
        if (progress < 30) return 'instalar_suricata';
        if (progress < 50) return 'atualizar_et_open';
        if (progress < 72) return 'configurar_suricata';
        if (progress < 84) return 'validar_suricata';
        if (progress < 94) return 'reiniciar_servicos';
        return 'validar_instalacao';
    }

    function stageIndexFromProgress(progress, count) {
        return Math.min(count - 1, Math.max(0, Math.floor((progress / 100) * count)));
    }

    function parseDate(value) {
        const date = value instanceof Date ? value : new Date(value);
        return Number.isNaN(date.getTime()) ? new Date() : date;
    }

    function formatTime(date) {
        return new Intl.DateTimeFormat('pt-BR', {
            hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
        }).format(date);
    }

    function formatElapsed(seconds) {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = seconds % 60;
        return hours > 0
            ? `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(secs).padStart(2, '0')}`
            : `${String(minutes).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
    }

    function humanDuration(seconds) {
        if (seconds < 60) return `${Math.ceil(seconds)} s`;
        const min = Math.max(1, Math.round(seconds / 60));
        return `${min} min`;
    }

    function escapeHtml(value) {
        return String(value ?? '')
            .replaceAll('&', '&amp;')
            .replaceAll('<', '&lt;')
            .replaceAll('>', '&gt;')
            .replaceAll('"', '&quot;')
            .replaceAll("'", '&#039;');
    }

    function cssEscape(value) {
        if (window.CSS?.escape) return window.CSS.escape(String(value));
        return String(value).replace(/[^a-zA-Z0-9_-]/g, '\\$&');
    }

    function iconSvg(type) {
        const icons = {
            check: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="margin-top:2px"><polyline points="20 6 9 17 4 12"/></svg>',
            error: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="margin-top:2px"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
            warning: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="margin-top:2px"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
        };
        return icons[type] || '';
    }
});