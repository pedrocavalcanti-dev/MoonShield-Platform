// painel.js
(() => {
    'use strict';

    const config = window.MS_SURICATA_PANEL;
    if (!config) {
        console.error('[MoonShield] Configuração não encontrada');
        return;
    }

    let currentSection = 'overview';
    let currentTaskPage = 1;
    let taskFilters = { status: '', type: '' };
    let statusRefreshInterval = null;

    const DOM = {
        sections: {},
        sidebar: document.querySelector('.ob-sidebar'),
        main: document.querySelector('.ob-main'),
        topbar: document.querySelector('.ob-topbar'),
        navItems: document.querySelectorAll('.ob-nav__item'),
        themeToggle: document.getElementById('themeToggle'),
        menuBtn: document.getElementById('btnOpenSidebar'),
        refreshBtn: document.getElementById('btnRefreshStatus'),
        diagnosticBtns: document.querySelectorAll('[id*="btnRunDiagnostic"]'),
        configBtn: document.getElementById('btnOpenConfiguration'),
        statusDots: {
            sidebar: document.getElementById('sidebarStatusDot'),
            hero: document.getElementById('heroStatusDot'),
            chip: document.getElementById('headerStackChip')
        },
        statusLabels: {
            sidebar: document.getElementById('sidebarStatusLabel'),
            desc: document.getElementById('sidebarStatusDesc')
        },
        drawer: document.getElementById('taskDrawer'),
        modal: document.getElementById('confirmationModal'),
        toastContainer: document.getElementById('toastContainer')
    };

    document.querySelectorAll('.ob-section').forEach(el => {
        DOM.sections[el.dataset.section] = el;
    });

    // Tema
    const initTheme = () => {
        const savedTheme = localStorage.getItem('moonshield_theme') || 'dark';
        document.documentElement.setAttribute('data-theme', savedTheme);
        updateThemeToggle(savedTheme);

        DOM.themeToggle?.addEventListener('click', () => {
            const current = document.documentElement.getAttribute('data-theme');
            const next = current === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', next);
            localStorage.setItem('moonshield_theme', next);
            updateThemeToggle(next);
        });
    };

    const updateThemeToggle = (theme) => {
        if (DOM.themeToggle) {
            DOM.themeToggle.classList.toggle('is-active', theme === 'light');
        }
    };

    // Navegação
    const switchSection = (sectionName) => {
        if (currentSection === sectionName) return;

        Object.values(DOM.sections).forEach(s => s.classList.remove('is-active'));
        DOM.navItems.forEach(n => n.classList.remove('is-active'));

        const targetSection = DOM.sections[sectionName];
        const targetNav = document.querySelector(`[data-section="${sectionName}"]`);

        if (targetSection) targetSection.classList.add('is-active');
        if (targetNav) targetNav.classList.add('is-active');

        currentSection = sectionName;
        loadSectionData(sectionName);
    };

    DOM.navItems.forEach(item => {
        item.addEventListener('click', () => {
            const section = item.dataset.section;
            if (section) switchSection(section);
        });
    });

    // Mobile sidebar
    DOM.menuBtn?.addEventListener('click', () => {
        DOM.sidebar.classList.toggle('is-open');
    });

    document.addEventListener('click', (e) => {
        if (!DOM.sidebar.contains(e.target) && !DOM.menuBtn.contains(e.target)) {
            DOM.sidebar.classList.remove('is-open');
        }
    });

    // Status
    const updateStatus = (status) => {
        const stateClass = `ob-status-dot--${status.estado || 'pending'}`;
        const label = status.label || 'Desconhecido';
        const desc = status.descricao || '';

        DOM.statusDots.sidebar?.className.baseVal ?
            DOM.statusDots.sidebar.setAttribute('class', `ob-status-dot ${stateClass}`) :
            (DOM.statusDots.sidebar.className = `ob-status-dot ${stateClass}`);

        Object.values(DOM.statusDots).forEach(dot => {
            if (dot === DOM.statusDots.sidebar) return;
            dot?.className ? (dot.className = `ob-status-dot ${stateClass}`) : null;
        });

        if (DOM.statusLabels.sidebar) DOM.statusLabels.sidebar.textContent = label;
        if (DOM.statusLabels.desc) DOM.statusLabels.desc.textContent = desc;
        if (DOM.statusDots.chip) {
            DOM.statusDots.chip.className = `ob-chip ob-chip--${status.estado || 'pending'}`;
            DOM.statusDots.chip.textContent = label;
        }

        updateLastUpdate();
    };

    const updateLastUpdate = () => {
        const now = new Date();
        const minutes = Math.floor((Date.now() - (window.lastStatusTime || Date.now())) / 60000);
        const text = minutes === 0 ? 'agora' : `há ${minutes}m`;
        const el = document.getElementById('lastUpdateText');
        if (el) el.textContent = text;
        window.lastStatusTime = Date.now();
    };

    const fetchStatus = async () => {
        try {
            const res = await fetch(config.urls.status, {
                headers: { 'X-CSRFToken': config.csrfToken }
            });
            const data = await res.json();
            updateStatus(data.stack || {});
            updateHealthCards(data);
            return data;
        } catch (error) {
            console.error('[MoonShield] Erro ao buscar status:', error);
            updateStatus({ estado: 'error', label: 'Erro de conexão' });
        }
    };

    const updateHealthCards = (data) => {
        if (!data.componentes) return;

        const cards = {
            suricata: document.getElementById('cardSuricata'),
            monitor: document.getElementById('cardMonitor'),
            eve: document.getElementById('cardEve'),
            rules: document.getElementById('cardRules')
        };

        const comps = {
            suricata: data.componentes.suricata,
            monitor: data.componentes.monitor_local,
            eve: data.componentes.eve_json,
            rules: data.componentes.regras
        };

        Object.entries(comps).forEach(([key, comp]) => {
            const card = cards[key];
            if (!card || !comp) return;

            const stateClass = `ob-status-card--${comp.estado || 'pending'}`;
            card.className = card.className.replace(/ob-status-card--\w+/, stateClass);

            const stateEl = card.querySelector('.ob-status-card__state');
            const valueEl = card.querySelector('[id$="Value"]');
            const detailEl = card.querySelector('[id$="Detail"]');
            const metaEl = card.querySelector('[id$="Meta"]');

            if (stateEl) stateEl.textContent = comp.estado || 'verificando';
            if (valueEl) valueEl.textContent = comp.valor || '—';
            if (detailEl) detailEl.textContent = comp.detalhe || '';
            if (metaEl) metaEl.textContent = comp.metadado || '';
        });

        updateHealthScore(data.saude || {});
        updateTopology(data.topologia || {});
    };

    const updateHealthScore = (saude) => {
        const score = saude.pontuacao || 0;
        const circle = document.getElementById('healthScoreCircle');
        const value = document.getElementById('healthScoreValue');
        const title = document.getElementById('healthScoreTitle');
        const text = document.getElementById('healthScoreText');
        const chip = document.getElementById('healthSummaryChip');

        if (value) value.textContent = score;
        if (circle) {
            const circumference = 2 * Math.PI * 48;
            const offset = circumference - (score / 100) * circumference;
            circle.style.strokeDashoffset = offset;
        }

        const stateClass = `ob-chip--${saude.estado || 'pending'}`;
        if (chip) {
            chip.className = chip.className.replace(/ob-chip--\w+/, stateClass);
            chip.textContent = saude.label || 'Analisando';
        }

        if (title) title.textContent = saude.titulo || 'Calculando integridade';
        if (text) text.textContent = saude.mensagem || '';

        const okCount = document.getElementById('healthOkCount');
        const warnCount = document.getElementById('healthWarningCount');
        const errCount = document.getElementById('healthErrorCount');

        if (okCount) okCount.textContent = saude.ok_count || 0;
        if (warnCount) warnCount.textContent = saude.warning_count || 0;
        if (errCount) errCount.textContent = saude.error_count || 0;
    };

    const updateTopology = (topo) => {
        const container = document.getElementById('topologyContainer');
        if (!container) return;

        if (!topo.wan && !topo.lan) {
            container.innerHTML = '<p class="ob-hint">Topologia não configurada.</p>';
            return;
        }

        let html = '<div class="ob-topology-display">';

        if (topo.wan) {
            html += `<div class="ob-topo-item">
                <span class="ob-topo-icon">🌐</span>
                <div class="ob-topo-info">
                    <strong>${topo.wan}</strong>
                    <small>WAN / Externa</small>
                </div>
            </div>`;
        }

        if (topo.lan) {
            html += `<div class="ob-topo-item">
                <span class="ob-topo-icon">🏠</span>
                <div class="ob-topo-info">
                    <strong>${topo.lan}</strong>
                    <small>LAN / Interna</small>
                </div>
            </div>`;
        }

        if (topo.mgmt) {
            html += `<div class="ob-topo-item">
                <span class="ob-topo-icon">⚙</span>
                <div class="ob-topo-info">
                    <strong>${topo.mgmt}</strong>
                    <small>Gerenciamento</small>
                </div>
            </div>`;
        }

        html += '</div>';
        container.innerHTML = html;
    };

    // Carregar dados por seção
    const loadSectionData = async (section) => {
        switch (section) {
            case 'health':
                loadHealthSection();
                break;
            case 'configuration':
                loadConfigurationSection();
                break;
            case 'rules':
                loadRulesSection();
                break;
            case 'tasks':
                loadTasksSection();
                break;
            case 'diagnostic':
                loadDiagnosticSection();
                break;
        }
    };

    const loadHealthSection = async () => {
        const container = document.getElementById('healthComponentsContainer');
        if (!container) return;

        container.innerHTML = '<p class="ob-hint">Carregando componentes...</p>';

        try {
            const res = await fetch(config.urls.status, {
                headers: { 'X-CSRFToken': config.csrfToken }
            });
            const data = await res.json();
            const comps = data.componentes || {};

            let html = '';
            Object.entries(comps).forEach(([key, comp]) => {
                const stateClass = `ob-panel--${comp.estado}`;
                html += `
                    <div class="ob-panel ${stateClass}">
                        <div class="ob-panel__header">
                            <div>
                                <h3 class="ob-panel__title">${comp.nome || key}</h3>
                                <p class="ob-panel__subtitle">${comp.detalhe || ''}</p>
                            </div>
                            <span class="ob-chip ob-chip--${comp.estado}">${comp.estado}</span>
                        </div>
                        <div class="ob-panel__body">
                            <div class="ob-detail-list">
                                <div><dt>Status</dt><dd>${comp.valor || '—'}</dd></div>
                                <div><dt>Detalhes</dt><dd>${comp.metadado || '—'}</dd></div>
                            </div>
                        </div>
                    </div>
                `;
            });

            container.innerHTML = html || '<p class="ob-hint">Nenhum componente encontrado.</p>';
        } catch (error) {
            container.innerHTML = `<div class="ob-alert ob-alert--error">
                <strong>Erro ao carregar componentes</strong>
                <p>${error.message}</p>
            </div>`;
        }
    };

    const loadConfigurationSection = async () => {
        const container = document.getElementById('configurationContainer');
        if (!container) return;

        container.innerHTML = '<p class="ob-hint">Carregando configuração...</p>';

        try {
            const res = await fetch(config.urls.status, {
                headers: { 'X-CSRFToken': config.csrfToken }
            });
            const data = await res.json();
            const config_data = data.configuracao || config.configuracao || {};

            let html = `
                <div class="ob-panel">
                    <div class="ob-panel__header">
                        <h3>Sensor Suricata</h3>
                    </div>
                    <div class="ob-panel__body">
                        <div class="ob-detail-list">
                            <div><dt>Versão</dt><dd>${config_data.versao || '—'}</dd></div>
                            <div><dt>Caminho YAML</dt><dd><code>${config_data.yaml_path || '—'}</code></dd></div>
                            <div><dt>EVE JSON</dt><dd><code>${config_data.eve_path || '—'}</code></dd></div>
                        </div>
                    </div>
                </div>

                <div class="ob-panel">
                    <div class="ob-panel__header">
                        <h3>Topologia</h3>
                    </div>
                    <div class="ob-panel__body">
                        <div class="ob-detail-list">
                            <div><dt>WAN</dt><dd>${config_data.interface_wan || '—'}</dd></div>
                            <div><dt>LAN</dt><dd>${config_data.interface_lan || '—'}</dd></div>
                            <div><dt>HOME_NET</dt><dd><code>${config_data.home_net || '—'}</code></dd></div>
                        </div>
                    </div>
                </div>

                <div class="ob-panel">
                    <div class="ob-panel__header">
                        <h3>Regras ativas</h3>
                    </div>
                    <div class="ob-panel__body">
                        <div class="ob-detail-list">
                            <div><dt>MoonShield</dt><dd>${config_data.moonshield_rules ? '✓ Ativado' : '✗ Desativado'}</dd></div>
                            <div><dt>ET Open</dt><dd>${config_data.et_open_rules ? '✓ Ativado' : '✗ Desativado'}</dd></div>
                        </div>
                    </div>
                </div>
            `;

            container.innerHTML = html;
        } catch (error) {
            container.innerHTML = `<div class="ob-alert ob-alert--error">
                <strong>Erro ao carregar configuração</strong>
                <p>${error.message}</p>
            </div>`;
        }
    };

    const loadRulesSection = async () => {
        const container = document.getElementById('rulesContainer');
        if (!container) return;

        container.innerHTML = '<p class="ob-hint">Carregando regras...</p>';

        try {
            const res = await fetch(config.urls.status, {
                headers: { 'X-CSRFToken': config.csrfToken }
            });
            const data = await res.json();
            const rules = data.regras || {};

            let html = '';
            Object.entries(rules).forEach(([key, rule]) => {
                html += `
                    <div class="ob-panel">
                        <div class="ob-panel__header">
                            <h3>${rule.nome || key}</h3>
                            <span class="ob-chip ob-chip--${rule.estado}">${rule.estado}</span>
                        </div>
                        <div class="ob-panel__body">
                            <div class="ob-detail-list">
                                <div><dt>Status</dt><dd>${rule.valor || '—'}</dd></div>
                                <div><dt>Detalhes</dt><dd>${rule.detalhe || '—'}</dd></div>
                            </div>
                        </div>
                    </div>
                `;
            });

            container.innerHTML = html || '<p class="ob-hint">Nenhuma regra encontrada.</p>';
        } catch (error) {
            container.innerHTML = `<div class="ob-alert ob-alert--error">
                <strong>Erro ao carregar regras</strong>
                <p>${error.message}</p>
            </div>`;
        }
    };

    const loadTasksSection = async () => {
        await fetchTasksList();
    };

    const loadDiagnosticSection = async () => {
        const container = document.getElementById('diagnosticContainer');
        container.innerHTML = '<p class="ob-hint">Diagnóstico não executado ainda. Clique em "Executar diagnóstico" para começar.</p>';
    };

    const fetchTasksList = async () => {
        try {
            const res = await fetch(config.urls.listarTarefas, {
                headers: { 'X-CSRFToken': config.csrfToken }
            });
            const data = await res.json();
            renderTasksTable(data.tarefas || []);
        } catch (error) {
            console.error('[MoonShield] Erro ao listar tarefas:', error);
        }
    };

    const renderTasksTable = (tarefas) => {
        const tbody = document.getElementById('taskTableBody');
        if (!tbody) return;

        if (!tarefas.length) {
            tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; padding: 20px;">Nenhuma tarefa encontrada.</td></tr>';
            return;
        }

        tbody.innerHTML = tarefas.map(t => `
            <tr>
                <td><strong>${t.tipo}</strong></td>
                <td><span class="ob-chip ob-chip--${t.estado}">${t.estado}</span></td>
                <td><span>${t.progresso || 0}%</span></td>
                <td><small>${t.etapa || '—'}</small></td>
                <td>${new Date(t.criada_em).toLocaleTimeString('pt-BR')}</td>
                <td>${formatDuration(t.duracao_segundos || 0)}</td>
                <td><button class="ob-icon-btn ob-icon-btn--sm" data-task-id="${t.id}" type="button">→</button></td>
            </tr>
        `).join('');

        tbody.querySelectorAll('button[data-task-id]').forEach(btn => {
            btn.addEventListener('click', () => {
                const taskId = btn.dataset.taskId;
                openTaskDrawer(taskId);
            });
        });
    };

    const formatDuration = (seconds) => {
        if (!seconds) return '—';
        const h = Math.floor(seconds / 3600);
        const m = Math.floor((seconds % 3600) / 60);
        const s = seconds % 60;
        if (h > 0) return `${h}h ${m}m`;
        if (m > 0) return `${m}m ${s}s`;
        return `${s}s`;
    };

    const openTaskDrawer = async (taskId) => {
        if (!DOM.drawer) return;

        DOM.drawer.classList.add('is-open');
        DOM.drawer.setAttribute('aria-hidden', 'false');

        try {
            const url = config.urls.detalheTarefaTemplate.replace('__ID__', taskId);
            const res = await fetch(url, {
                headers: { 'X-CSRFToken': config.csrfToken }
            });
            const task = await res.json();

            document.getElementById('taskDrawerTitle').textContent = `Tarefa #${task.id}`;
            document.getElementById('drawerTaskStatus').textContent = task.estado;
            document.getElementById('drawerTaskStatus').className = `ob-pill ob-pill--${task.estado}`;
            document.getElementById('drawerTaskType').textContent = task.tipo;
            document.getElementById('drawerTaskId').textContent = `#${task.id}`;
            document.getElementById('drawerTaskStage').textContent = task.etapa || 'Aguardando';
            document.getElementById('drawerTaskPercent').textContent = `${task.progresso || 0}%`;
            document.getElementById('drawerTaskMessage').textContent = task.mensagem || 'Sem atualizações.';

            const progressBar = document.getElementById('drawerTaskProgressBar');
            if (progressBar) {
                progressBar.style.width = `${task.progresso || 0}%`;
            }

            document.getElementById('drawerTaskCreated').textContent = new Date(task.criada_em).toLocaleString('pt-BR');
            document.getElementById('drawerTaskStarted').textContent = task.iniciada_em ? new Date(task.iniciada_em).toLocaleString('pt-BR') : '—';
            document.getElementById('drawerTaskFinished').textContent = task.finalizada_em ? new Date(task.finalizada_em).toLocaleString('pt-BR') : '—';
            document.getElementById('drawerTaskDuration').textContent = formatDuration(task.duracao_segundos || 0);

            if (task.erro) {
                document.getElementById('drawerTaskError').hidden = false;
                document.getElementById('drawerTaskErrorText').textContent = task.erro;
            } else {
                document.getElementById('drawerTaskError').hidden = true;
            }

            const logsContainer = document.getElementById('drawerTaskLogs');
            if (task.logs && task.logs.length) {
                logsContainer.innerHTML = task.logs.map(log =>
                    `<div class="ob-terminal-line">
                        <span class="ob-terminal-time">${log.timestamp}</span>
                        <span class="ob-terminal-level">${log.nivel}</span>
                        <span>${log.mensagem}</span>
                    </div>`
                ).join('');
            } else {
                logsContainer.innerHTML = '<div class="ob-terminal__empty">Nenhum log disponível.</div>';
            }
        } catch (error) {
            console.error('[MoonShield] Erro ao carregar tarefa:', error);
        }
    };

    const closeTaskDrawer = () => {
        if (DOM.drawer) {
            DOM.drawer.classList.remove('is-open');
            DOM.drawer.setAttribute('aria-hidden', 'true');
        }
    };

    document.getElementById('btnCloseDrawer')?.addEventListener('click', closeTaskDrawer);
    document.getElementById('btnCloseDrawerFooter')?.addEventListener('click', closeTaskDrawer);
    document.getElementById('taskDrawer')?.addEventListener('click', (e) => {
        if (e.target === DOM.drawer) closeTaskDrawer();
    });

    // Botoões de diagnóstico
    DOM.diagnosticBtns.forEach(btn => {
        btn?.addEventListener('click', runDiagnostic);
    });

    const runDiagnostic = async () => {
        showToast('Iniciando diagnóstico...', 'info');

        try {
            const res = await fetch(config.urls.diagnostico, {
                method: 'POST',
                headers: { 'X-CSRFToken': config.csrfToken }
            });
            const data = await res.json();

            if (data.sucesso) {
                showToast('Diagnóstico concluído.', 'ok');
                switchSection('diagnostic');
                displayDiagnosticResults(data.resultado || {});
            } else {
                showToast(`Erro: ${data.erro}`, 'error');
            }
        } catch (error) {
            showToast('Erro ao executar diagnóstico.', 'error');
            console.error('[MoonShield] Erro diagnóstico:', error);
        }
    };

    const displayDiagnosticResults = (resultado) => {
        const container = document.getElementById('diagnosticContainer');
        if (!container) return;

        let html = '<div class="ob-diagnostic-results">';

        Object.entries(resultado).forEach(([key, value]) => {
            const stateClass = value.estado ? `ob-panel--${value.estado}` : '';
            html += `
                <div class="ob-panel ${stateClass}">
                    <div class="ob-panel__header">
                        <h3>${value.titulo || key}</h3>
                        <span class="ob-chip ob-chip--${value.estado || 'info'}">${value.estado || 'info'}</span>
                    </div>
                    <div class="ob-panel__body">
                        <p>${value.descricao || ''}</p>
                        ${value.detalhes ? `<pre style="background: rgba(255,255,255,.02); padding: 12px; border-radius: 8px; overflow-x: auto; font-size: 8px;">${value.detalhes}</pre>` : ''}
                    </div>
                </div>
            `;
        });

        html += '</div>';
        container.innerHTML = html;
    };

    const showToast = (message, type = 'info') => {
        const toast = document.createElement('div');
        toast.className = `ob-toast ob-toast--${type}`;
        toast.setAttribute('role', 'status');
        toast.setAttribute('aria-live', 'polite');
        toast.innerHTML = `
            <span class="ob-toast__icon">${type === 'ok' ? '✓' : type === 'error' ? '!' : 'i'}</span>
            <span>${message}</span>
        `;

        DOM.toastContainer?.appendChild(toast);

        setTimeout(() => {
            toast.classList.add('is-closing');
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    };

    // Refresh
    DOM.refreshBtn?.addEventListener('click', fetchStatus);

    // Configuração
    DOM.configBtn?.addEventListener('click', () => {
        switchSection('configuration');
    });

    // Init
    const init = async () => {
        initTheme();
        await fetchStatus();

        statusRefreshInterval = setInterval(() => {
            if (currentSection === 'overview') {
                fetchStatus();
            }
        }, 8000);
    };

    window.addEventListener('beforeunload', () => {
        if (statusRefreshInterval) clearInterval(statusRefreshInterval);
    });

    init();

})();