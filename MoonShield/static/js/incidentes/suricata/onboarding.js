/**
 * MOONSHIELD — SURICATA ONBOARDING
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

    initialiseBackground();
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
       FUNDO ESPACIAL
    ═══════════════════════════════════════════════════════════ */
    function initialiseBackground() {
        const canvas = el('starsCanvas');
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        if (!ctx) return;

        let stars = [];
        let animationFrame = null;

        const rebuild = () => {
            const ratio = Math.min(window.devicePixelRatio || 1, 2);
            const width = window.innerWidth;
            const height = window.innerHeight;
            canvas.width = Math.floor(width * ratio);
            canvas.height = Math.floor(height * ratio);
            canvas.style.width = `${width}px`;
            canvas.style.height = `${height}px`;
            ctx.setTransform(ratio, 0, 0, ratio, 0, 0);

            const quantity = Math.max(60, Math.floor((width * height) / 6500));
            stars = Array.from({ length: quantity }, () => ({
                x: Math.random() * width,
                y: Math.random() * height,
                radius: Math.random() * 1.05 + 0.15,
                alpha: Math.random() * 0.5 + 0.15,
                phase: Math.random() * Math.PI * 2,
                speed: Math.random() * 0.0018 + 0.0005,
            }));
        };

        const draw = timestamp => {
            ctx.clearRect(0, 0, window.innerWidth, window.innerHeight);
            for (const star of stars) {
                const alpha = Math.max(0.08, star.alpha + Math.sin(star.phase + timestamp * star.speed) * 0.22);
                ctx.beginPath();
                ctx.arc(star.x, star.y, star.radius, 0, Math.PI * 2);
                ctx.fillStyle = `rgba(205, 220, 255, ${alpha.toFixed(3)})`;
                ctx.fill();
            }
            animationFrame = window.requestAnimationFrame(draw);
        };

        rebuild();
        animationFrame = window.requestAnimationFrame(draw);
        window.addEventListener('resize', debounce(rebuild, 120));
        window.addEventListener('pagehide', () => {
            if (animationFrame) window.cancelAnimationFrame(animationFrame);
        }, { once: true });
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

        all('.ob-nav-step').forEach(button => {
            button.addEventListener('click', () => {
                const target = Number(button.dataset.step || 1);
                if (target <= state.maxUnlockedStep && !button.disabled) goToStep(target);
            });
        });
    }

    function goToStep(step) {
        if (!Number.isInteger(step) || step < 1 || step > TOTAL_STEPS) return;
        if (step > state.maxUnlockedStep) return;

        all('[data-step-panel]').forEach(panel => {
            panel.classList.toggle('active', Number(panel.dataset.stepPanel) === step);
        });

        state.currentStep = step;
        updateNavigation(step);
        updateMobileProgress(step);

        const content = document.querySelector('.ob-content');
        if (content) content.scrollTo({ top: 0, behavior: 'smooth' });
    }

    function unlockStep(step) {
        state.maxUnlockedStep = Math.max(state.maxUnlockedStep, step);
        all('.ob-nav-step').forEach(button => {
            const number = Number(button.dataset.step || 1);
            button.disabled = number > state.maxUnlockedStep;
        });
    }

    function updateNavigation(current) {
        all('.ob-nav-step').forEach(button => {
            const number = Number(button.dataset.step || 1);
            button.classList.remove('ob-nav-step--active', 'ob-nav-step--done');
            button.removeAttribute('aria-current');

            if (number < current) button.classList.add('ob-nav-step--done');
            if (number === current) {
                button.classList.add('ob-nav-step--active');
                button.setAttribute('aria-current', 'step');
            }
        });
    }

    function updateMobileProgress(step) {
        if (el('mobileBar')) el('mobileBar').style.width = `${(step / TOTAL_STEPS) * 100}%`;
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

            const linux = readBoolean(
                systemInfo,
                ['linux', 'eh_linux', 'is_linux'],
                readBoolean(environment, ['linux', 'eh_linux', 'is_linux'], false)
            );

            const root = readBoolean(
                systemInfo,
                ['root', 'privilegios', 'privilegiado', 'is_root'],
                readBoolean(environment, ['root', 'privilegios', 'privilegiado', 'is_root'], false)
            );

            const systemd = readBoolean(
                capabilities,
                ['pode_controlar_servicos', 'systemd', 'tem_systemd'],
                readBoolean(
                    services,
                    ['disponivel', 'systemd', 'tem_systemd'],
                    readBoolean(environment, ['systemd', 'tem_systemd'], false)
                )
            );

            const installed = readBoolean(
                suricata,
                ['instalado'],
                readBoolean(environment, ['suricata_instalado'], false)
            );

            const version = firstText(
                suricata.versao,
                environment.versao_suricata,
                data.versao_suricata
            );

            const yamlInfo = paths.yaml || suricata.yaml || {};
            const eveInfo = paths.eve || suricata.eve || {};
            const pathReady = Boolean(
                (yamlInfo.existe === true || yamlInfo.arquivo === true) &&
                (eveInfo.existe === true || eveInfo.arquivo === true)
            );

            const checks = {
                linux: {
                    ok: linux,
                    warning: !linux,
                    value: linux
                        ? firstText(
                            distribution.nome,
                            distribution.id,
                            systemInfo.nome,
                            'Linux detectado'
                        )
                        : 'Linux necessário',
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

            // Em desenvolvimento Windows, a API responde corretamente, mas a instalação real fica bloqueada.
            // Em Linux, Linux + privilégios + systemd são os requisitos críticos para prosseguir.
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
            if (el('btnStep2Next')) el('btnStep2Next').disabled = true;
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
            icon.className = `ob-check-summary__icon ob-check-summary__icon--${type}`;
            icon.innerHTML = type === 'loading'
                ? '<span class="ob-spinner"></span>'
                : type === 'success'
                    ? iconSvg('check')
                    : type === 'warning'
                        ? iconSvg('warning')
                        : iconSvg('error');
        }
        if (el('environmentSummaryTitle')) el('environmentSummaryTitle').textContent = title;
        if (el('environmentSummaryText')) el('environmentSummaryText').textContent = text;
    }

    function setEnvironmentCheck(name, check) {
        const row = document.querySelector(`[data-check="${cssEscape(name)}"]`);
        if (!row) return;
        const status = row.querySelector('.ob-check-row__status');
        const value = row.querySelector('.ob-check-row__value');

        if (status) {
            status.className = 'ob-check-row__status';
            if (check.pending) {
                status.classList.add('ob-check-row__status--pending');
                status.innerHTML = '<span class="ob-spinner ob-spinner--sm"></span>';
            } else if (check.ok) {
                status.classList.add('ob-check-row__status--ok');
                status.innerHTML = iconSvg('check');
            } else if (check.warning) {
                status.classList.add('ob-check-row__status--warning');
                status.innerHTML = iconSvg('warning');
            } else {
                status.classList.add('ob-check-row__status--error');
                status.innerHTML = iconSvg('error');
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
                applyCaptureModeDefaults(radio.value);
                clearNetworkError();
            });
        });

        for (const id of ['fieldWan', 'fieldLan', 'fieldMgmt', 'fieldDns']) {
            el(id)?.addEventListener('change', clearNetworkError);
            el(id)?.addEventListener('input', clearNetworkError);
        }
    }

    async function detectInterfaces() {
        const button = el('btnDetectInterfaces');
        setButtonLoading(button, true);
        clearNetworkError();
        renderInterfacesLoading();

        try {
            const payload = await requestJSON(CFG.urls.detectarInterfaces, { method: 'GET' });
            const data = unwrapData(payload);
            state.topology = data.topologia || data;
            const suggested = data.configuracao_sugerida || data.configuracao || {};
            state.interfaces = extractInterfaces(state.topology, data);

            if (!state.interfaces.length) {
                throw new Error('Nenhuma interface de rede utilizável foi detectada.');
            }

            populateInterfaceSelects(state.interfaces);
            applySuggestedConfiguration(suggested);
            renderMonitoredInterfaces(state.interfaces);
            showToast(`${state.interfaces.length} interface(s) detectada(s).`, 'success');
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
            result.push({
                nome: name,
                ipv4: firstText(object.ipv4, object.ip, object.endereco_ipv4),
                mac: firstText(object.mac, object.endereco_mac),
                estado: firstText(object.estado, object.state, object.status, object.ativa ? 'up' : ''),
                tipo: firstText(object.tipo, object.kind, object.descricao),
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
                option.textContent = `${item.nome}${item.ipv4 ? ` · ${item.ipv4}` : ''}`;
                select.appendChild(option);
            }
            if (interfaces.some(item => item.nome === previous)) select.value = previous;
        }
    }

    function renderMonitoredInterfaces(interfaces) {
        const container = el('interfacesMonitoradasList');
        if (!container) return;
        container.innerHTML = '';

        const configured = arrayOfStrings(state.configuration?.interfaces_monitoradas);
        if (!state.selectedInterfaces.size && configured.length) {
            configured.forEach(value => state.selectedInterfaces.add(value));
        }
        if (!state.selectedInterfaces.size) {
            interfaces.forEach(item => state.selectedInterfaces.add(item.nome));
        }

        for (const item of interfaces) {
            const label = document.createElement('label');
            label.className = 'ob-interface-item';
            label.innerHTML = `
        <input type="checkbox" value="${escapeHtml(item.nome)}" ${state.selectedInterfaces.has(item.nome) ? 'checked' : ''}>
        <span class="ob-interface-item__check">${iconSvg('check')}</span>
        <span class="ob-interface-item__body">
          <strong>${escapeHtml(item.nome)}</strong>
          <small>${escapeHtml([item.ipv4, item.tipo, item.estado].filter(Boolean).join(' · ') || 'Interface disponível')}</small>
        </span>
        <span class="ob-interface-item__state">${escapeHtml(item.estado || 'detectada')}</span>
      `;
            const input = label.querySelector('input');
            input?.addEventListener('change', () => {
                if (input.checked) state.selectedInterfaces.add(input.value);
                else state.selectedInterfaces.delete(input.value);
                clearNetworkError();
            });
            container.appendChild(label);
        }
    }

    function renderInterfacesLoading() {
        const container = el('interfacesMonitoradasList');
        if (!container) return;
        container.innerHTML = '<div class="ob-empty-state ob-empty-state--compact"><span class="ob-spinner ob-spinner--sm"></span><span>Detectando interfaces...</span></div>';
    }

    function renderInterfacesError(message) {
        const container = el('interfacesMonitoradasList');
        if (!container) return;
        container.innerHTML = `<div class="ob-empty-state ob-empty-state--compact"><span>${iconSvg('error')}</span><span>${escapeHtml(message)}</span></div>`;
    }

    function applySuggestedConfiguration(suggested) {
        const cfg = normaliseObject(suggested);
        setSelectIfAvailable('fieldWan', firstText(cfg.interface_wan, cfg.wan));
        setSelectIfAvailable('fieldLan', firstText(cfg.interface_lan, cfg.lan));
        setSelectIfAvailable('fieldMgmt', firstText(cfg.interface_mgmt, cfg.mgmt));
        if (el('fieldDns') && !el('fieldDns').value) el('fieldDns').value = firstText(cfg.dns_interno, cfg.dns);

        const suggestedHome = arrayOfStrings(cfg.home_net || cfg.redes_home_net);
        if (!state.homeNet.length && suggestedHome.length) {
            state.homeNet = suggestedHome;
            renderHomeNetTokens();
        }

        const suggestedMonitored = arrayOfStrings(cfg.interfaces_monitoradas);
        if (suggestedMonitored.length) {
            state.selectedInterfaces = new Set(suggestedMonitored);
            renderMonitoredInterfaces(state.interfaces);
        }
    }

    function applyCaptureModeDefaults(mode) {
        const wan = el('fieldWan');
        const lan = el('fieldLan');
        if (mode === 'lan' && lan?.value) {
            state.selectedInterfaces = new Set([lan.value]);
        } else if (mode === 'lan_wan') {
            state.selectedInterfaces = new Set([wan?.value, lan?.value].filter(Boolean));
        }
        if (state.interfaces.length) renderMonitoredInterfaces(state.interfaces);
    }

    function addHomeNetFromInput() {
        const input = el('fieldHomeNet');
        if (!input) return;
        const values = input.value.split(',').map(value => value.trim()).filter(Boolean);
        if (!values.length) return;

        const invalid = values.filter(value => !isValidCidr(value));
        if (invalid.length) {
            showNetworkError(`CIDR inválido: ${invalid.join(', ')}.`);
            shake(input.closest('.ob-token-input') || input);
            return;
        }

        for (const value of values) {
            if (!state.homeNet.includes(value)) state.homeNet.push(value);
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
            const token = document.createElement('span');
            token.className = 'ob-token';
            token.innerHTML = `<span>${escapeHtml(network)}</span><button type="button" aria-label="Remover ${escapeHtml(network)}">×</button>`;
            token.querySelector('button')?.addEventListener('click', () => {
                state.homeNet = state.homeNet.filter(value => value !== network);
                renderHomeNetTokens();
            });
            container.appendChild(token);
        }
    }

    function validateNetworkForm() {
        addPendingHomeNet();
        const mode = getCaptureMode();
        const wan = el('fieldWan')?.value || '';
        const lan = el('fieldLan')?.value || '';
        const dns = el('fieldDns')?.value.trim() || '';
        const errors = [];

        if (!lan) errors.push('Selecione a interface LAN.');
        if (mode === 'lan_wan' && !wan) errors.push('Selecione a interface WAN.');
        if (mode === 'lan_wan' && wan && lan && wan === lan) errors.push('WAN e LAN devem usar interfaces diferentes.');
        if (!state.homeNet.length) errors.push('Adicione pelo menos uma rede HOME_NET.');
        if (state.homeNet.some(value => !isValidCidr(value))) errors.push('Existe uma rede HOME_NET inválida.');
        if (!state.selectedInterfaces.size) errors.push('Selecione pelo menos uma interface monitorada.');
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
        renderHomeNetTokens();

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
                item.innerHTML = `
          <span>${String(index + 1).padStart(2, '0')}</span>
          <div>
            <strong>${escapeHtml(firstText(step.titulo, step.nome, step.id, 'Etapa'))}</strong>
            <small>${escapeHtml(firstText(step.descricao, step.mensagem, step.obrigatoria === false ? 'Opcional' : 'Obrigatória'))}</small>
          </div>
        `;
                container.appendChild(item);
            });
        }

        const seconds = Number(data.estimativa_segundos || data.duracao_estimada_segundos || 0);
        if (seconds > 0) setText('planDuration', `≈ ${humanDuration(seconds)}`);
        setText('planSummary', steps.length
            ? `${steps.length} etapas serão executadas de forma controlada.`
            : 'A instalação será validada etapa por etapa.');

        const blockers = arrayOfStrings(data.bloqueios);
        if (blockers.length) showReviewError(blockers.join(' '));
        else clearReviewError();
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

            // A instalação privilegiada não é executada dentro da requisição web.
            // Um executor/management command deve consumir a tarefa pendente.
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
            // A restauração é auxiliar e não deve bloquear o onboarding.
            console.debug('Nenhuma tarefa restaurada:', error);
        }
    }

    function prepareInstallationUI(task) {
        if (el('installResult')) el('installResult').hidden = true;
        if (el('progressCard')) el('progressCard').hidden = false;
        if (el('btnCancelInstall')) el('btnCancelInstall').hidden = false;
        if (el('btnRetryInstall')) el('btnRetryInstall').hidden = true;
        if (el('btnFinishOnboarding')) el('btnFinishOnboarding').hidden = true;
        if (el('installOrbit')) el('installOrbit').classList.remove('is-success', 'is-error');
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

        // Busca o lote final de logs antes de apresentar o resultado.
        try {
            const url = `${resolveTemplateUrl(CFG.urls.logsTarefaTemplate, task.id)}?offset=${state.lastLogOffset}&limite=500`;
            const payload = await requestJSON(url, { method: 'GET' });
            const data = unwrapData(payload);
            renderTaskLogs(Array.isArray(data.logs) ? data.logs : []);
        } catch (_) {
            // Resultado permanece utilizável mesmo sem o último lote de logs.
        }

        if (state.taskSucceeded) showInstallationSuccess(task);
        else showInstallationFailure(task);
    }

    function showInstallationSuccess(task) {
        setText('installEyebrow', 'Instalação concluída');
        setText('installTitle', 'O Suricata está pronto.');
        setText('installDescription', 'O sensor foi configurado, validado e ativado com sucesso.');
        if (el('installOrbit')) el('installOrbit').classList.add('is-success');
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
        if (el('installOrbit')) el('installOrbit').classList.add('is-error');
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
        result.classList.toggle('is-success', success);
        result.classList.toggle('is-error', !success);
        if (el('resultIcon')) el('resultIcon').innerHTML = success ? iconSvg('check') : iconSvg('error');
        setText('resultEyebrow', eyebrow);
        setText('resultTitle', title);
        setText('resultMessage', message);

        const details = normaliseObject(task.resultado || task.result || {});
        const status = normaliseObject(details.status_final || details.status || details.stack || {});
        const suricata = normaliseObject(status.suricata || details.suricata || {});
        const version = firstText(suricata.versao, details.versao_suricata, state.configuration?.versao_suricata, success ? 'Detectada' : '—');
        const mainInterface = firstText(state.configuration?.interface_lan, state.configuration?.interface_wan, Array.from(state.selectedInterfaces)[0], '—');

        setText('resultVersion', version);
        setText('resultInterface', mainInterface);
        setText('resultStatus', success ? 'Ativo' : String(task.status || 'Erro'));
    }

    function updateStages(currentStage, taskStatus, progress) {
        const stages = all('[data-stage]');
        let currentIndex = stages.findIndex(item => item.dataset.stage === currentStage);
        if (currentIndex < 0) currentIndex = stageIndexFromProgress(progress, stages.length);
        const final = isFinalTaskStatus(taskStatus);
        const success = String(taskStatus).toLowerCase() === 'sucesso';

        stages.forEach((item, index) => {
            const status = item.querySelector('.ob-install-stage__status');
            const detail = item.querySelector('small');
            item.classList.remove('is-active', 'is-done', 'is-error');
            if (index < currentIndex || (final && success)) {
                item.classList.add('is-done');
                if (status) status.innerHTML = iconSvg('check');
                if (detail) detail.textContent = 'Concluído';
            } else if (index === currentIndex && !final) {
                item.classList.add('is-active');
                if (status) status.innerHTML = '<span class="ob-spinner ob-spinner--sm"></span>';
                if (detail) detail.textContent = 'Em execução';
            } else if (index === currentIndex && final && !success) {
                item.classList.add('is-error');
                if (status) status.innerHTML = iconSvg('error');
                if (detail) detail.textContent = 'Falhou';
            } else {
                if (status) status.innerHTML = '';
                if (detail) detail.textContent = 'Aguardando';
            }
        });
    }

    function resetStages() {
        all('[data-stage]').forEach((item, index) => {
            item.classList.remove('is-active', 'is-done', 'is-error');
            if (index === 0) item.classList.add('is-active');
            const status = item.querySelector('.ob-install-stage__status');
            const detail = item.querySelector('small');
            if (status) status.innerHTML = index === 0 ? '<span class="ob-spinner ob-spinner--sm"></span>' : '';
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
            await runWarpTransition();
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
        const empty = container.querySelector('.ob-terminal__line--muted');
        if (empty && container.children.length === 1) empty.remove();

        const level = String(log.nivel || log.level || 'info').toLowerCase();
        const line = document.createElement('div');
        line.className = `ob-terminal__line ob-terminal__line--${terminalLevelClass(level)}`;

        const timestamp = parseDate(log.criado_em || log.timestamp || new Date());
        const stage = firstText(log.etapa, log.stage);
        const message = firstText(log.mensagem, log.message, 'Evento sem mensagem');
        line.innerHTML = `
      <span>${formatTime(timestamp)}</span>
      <em>${escapeHtml(level.toUpperCase())}</em>
      <p>${stage ? `<b>[${escapeHtml(stage)}]</b> ` : ''}${escapeHtml(message)}</p>
    `;
        container.appendChild(line);
        container.scrollTop = container.scrollHeight;
    }

    function clearTerminal() {
        const container = el('installLogs');
        if (!container) return;
        container.innerHTML = '<div class="ob-terminal__line ob-terminal__line--muted"><span>--:--:--</span><em>INFO</em><p>Aguardando o início da tarefa...</p></div>';
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
        terminal.classList.toggle('is-collapsed', !state.logsVisible);
        if (el('installLogs')) el('installLogs').hidden = !state.logsVisible;
        setText('btnToggleLogs', state.logsVisible ? 'Ocultar logs' : 'Mostrar logs');
    }

    /* ═══════════════════════════════════════════════════════════
       TEMPO E TRANSIÇÃO
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

    async function runWarpTransition() {
        const canvas = el('warpCanvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        if (!ctx) return;

        const ratio = Math.min(window.devicePixelRatio || 1, 2);
        canvas.width = Math.floor(window.innerWidth * ratio);
        canvas.height = Math.floor(window.innerHeight * ratio);
        ctx.scale(ratio, ratio);
        canvas.classList.add('active');

        const centreX = window.innerWidth / 2;
        const centreY = window.innerHeight / 2;
        const particles = Array.from({ length: 150 }, () => ({
            angle: Math.random() * Math.PI * 2,
            distance: Math.random() * 20 + 2,
            speed: Math.random() * 18 + 8,
            length: Math.random() * 80 + 20,
            alpha: Math.random() * 0.7 + 0.2,
        }));

        const start = performance.now();
        await new Promise(resolve => {
            const draw = now => {
                const progress = Math.min(1, (now - start) / 720);
                ctx.fillStyle = `rgba(5, 7, 14, ${0.18 + progress * 0.22})`;
                ctx.fillRect(0, 0, window.innerWidth, window.innerHeight);
                for (const particle of particles) {
                    particle.distance += particle.speed * (1 + progress * 4);
                    const x1 = centreX + Math.cos(particle.angle) * particle.distance;
                    const y1 = centreY + Math.sin(particle.angle) * particle.distance;
                    const x2 = centreX + Math.cos(particle.angle) * (particle.distance + particle.length * progress);
                    const y2 = centreY + Math.sin(particle.angle) * (particle.distance + particle.length * progress);
                    const gradient = ctx.createLinearGradient(x1, y1, x2, y2);
                    gradient.addColorStop(0, 'rgba(96,165,250,0)');
                    gradient.addColorStop(1, `rgba(196,181,253,${particle.alpha})`);
                    ctx.strokeStyle = gradient;
                    ctx.lineWidth = 1;
                    ctx.beginPath();
                    ctx.moveTo(x1, y1);
                    ctx.lineTo(x2, y2);
                    ctx.stroke();
                }
                if (progress < 1) requestAnimationFrame(draw);
                else resolve();
            };
            requestAnimationFrame(draw);
        });
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
            if (event.key === 'Escape' && !el('leaveModal')?.hidden) closeLeaveModal();
        });
    }

    function closeLeaveModal() {
        const modal = el('leaveModal');
        if (modal) modal.hidden = true;
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
       FEEDBACK VISUAL
    ═══════════════════════════════════════════════════════════ */
    function showToast(message, type = 'info', duration = 4200) {
        const container = el('toastContainer');
        if (!container || !message) return;
        const toast = document.createElement('div');
        toast.className = `ob-toast ob-toast--${type}`;
        toast.setAttribute('role', type === 'error' ? 'alert' : 'status');
        toast.innerHTML = `
      <span class="ob-toast__icon">${iconSvg(type === 'success' ? 'check' : type === 'error' ? 'error' : type === 'warning' ? 'warning' : 'info')}</span>
      <span class="ob-toast__message">${escapeHtml(message)}</span>
      <button type="button" class="ob-toast__close" aria-label="Fechar">×</button>
    `;
        const close = () => {
            toast.classList.add('is-leaving');
            window.setTimeout(() => toast.remove(), 220);
        };
        toast.querySelector('button')?.addEventListener('click', close);
        container.appendChild(toast);
        requestAnimationFrame(() => toast.classList.add('is-visible'));
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
        if (dot) dot.className = `ob-system-dot ob-system-dot--${status}`;
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
        node.classList.remove('ob-shake');
        void node.offsetWidth;
        node.classList.add('ob-shake');
        node.addEventListener('animationend', () => node.classList.remove('ob-shake'), { once: true });
    }

    /* ═══════════════════════════════════════════════════════════
       HELPERS
    ═══════════════════════════════════════════════════════════ */
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

    function terminalLevelClass(level) {
        if (['erro', 'error', 'critical'].includes(level)) return 'error';
        if (['aviso', 'warning', 'warn'].includes(level)) return 'warning';
        if (['sucesso', 'success', 'ok'].includes(level)) return 'success';
        if (['debug'].includes(level)) return 'muted';
        return 'info';
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

    function debounce(fn, wait) {
        let timer = null;
        return (...args) => {
            if (timer) window.clearTimeout(timer);
            timer = window.setTimeout(() => fn(...args), wait);
        };
    }

    function iconSvg(type) {
        const icons = {
            check: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>',
            error: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
            warning: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
            info: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
        };
        return icons[type] || icons.info;
    }
});
