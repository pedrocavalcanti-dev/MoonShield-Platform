/**
 * MOONSHIELD — PAINEL SURICATA v4 (Otimizado)
 *
 * Otimizações implementadas:
 *  - Optional Chaining (?.) e Nullish Coalescing (??) nativos.
 *  - Event Delegation nas tabelas e listas para evitar memory leaks.
 *  - Suspensão de renderização do Canvas no Tema Claro para poupar CPU.
 */

document.addEventListener('DOMContentLoaded', () => {
    'use strict';

    // ================================================================
    // [01] CONTRATO, CONFIGURAÇÃO E ESTADO
    // ================================================================
    const APP = window.MS_SURICATA_PANEL || {};
    const URLS = APP.urls || {};
    const CONFIG = APP.configuracao || null;

    const REQUIRED_URLS = Object.freeze([
        'status', 'diagnostico', 'criarTarefa', 'listarTarefas',
        'detalheTarefaTemplate', 'cancelarTarefaTemplate', 'logsTarefaTemplate',
    ]);

    function apiUrl(name) {
        const value = URLS?.[name];
        if (typeof value !== 'string' || !value.trim() || value === 'undefined') {
            throw new Error(`URL da API não configurada: ${name}.`);
        }
        return value;
    }

    function validatePanelContract() {
        const missing = REQUIRED_URLS.filter((name) => {
            const value = URLS?.[name];
            return typeof value !== 'string' || !value.trim() || value === 'undefined';
        });

        if (missing.length) {
            throw new Error(`Contrato do painel incompleto. URLs ausentes: ${missing.join(', ')}.`);
        }
        return true;
    }

    const state = {
        currentSection: 'overview',
        statusData: normalizeInitialPayload(APP.statusInicial),
        cardsData: normalizeInitialPayload(APP.cardsIniciais),
        diagnosticData: null,
        tasks: [],
        taskTotal: 0,
        taskOffset: 0,
        taskLimit: 20,
        taskPage: 1,
        currentTaskId: null,
        currentTask: null,
        taskPollTimer: null,
        statusPollTimer: null,
        pendingConfirmation: null,
        lastStatusFetchAt: null,
        isFetchingStatus: false,
        isRunningDiagnostic: false,
        destroyed: false,
    };

    const FINAL_TASK_STATUSES = new Set(['sucesso', 'erro', 'cancelado', 'ignorado']);
    const RUNNING_TASK_STATUSES = new Set(['pendente', 'executando']);

    const TASK_LABELS = {
        diagnostico: 'Diagnóstico',
        instalacao: 'Instalação',
        configuracao: 'Configuração',
        atualizacao_regras: 'Atualização de regras',
        validacao: 'Validação',
        reinicio_suricata: 'Reinício do Suricata',
        reinicio_monitor: 'Reinício do monitor',
    };

    const TASK_ICONS = {
        diagnostico: 'pulse',
        instalacao: 'download',
        configuracao: 'settings',
        atualizacao_regras: 'refresh',
        validacao: 'check',
        reinicio_suricata: 'restart',
        reinicio_monitor: 'activity',
    };

    const STATUS_LABELS = {
        ok: 'Saudável', aviso: 'Aviso', warning: 'Aviso', erro: 'Erro', error: 'Erro',
        desconhecido: 'Desconhecido', desativado: 'Desativado', pendente: 'Pendente',
        executando: 'Executando', sucesso: 'Sucesso', cancelado: 'Cancelado',
        ignorado: 'Ignorado', ativo: 'Ativo', inativo: 'Inativo', true: 'Sim', false: 'Não',
    };

    const STATUS_CLASS_MAP = {
        ok: 'ok', sucesso: 'ok', ativo: 'ok', healthy: 'ok',
        warning: 'warning', aviso: 'warning', degradado: 'warning',
        pending: 'pending', pendente: 'pending', executando: 'pending', desconhecido: 'pending', desativado: 'pending',
        error: 'error', erro: 'error', offline: 'error', inativo: 'error', cancelado: 'error',
    };

    function $(id) { return document.getElementById(id); }
    function $all(selector, root = document) { return Array.from(root.querySelectorAll(selector)); }

    // ================================================================
    // [02] UTILITÁRIOS, NORMALIZAÇÃO E FORMATAÇÃO
    // ================================================================
    function normalizeInitialPayload(value) {
        if (!value) return {};
        if (typeof value === 'object') return value;
        if (typeof value !== 'string') return {};
        try { return JSON.parse(value); } catch (error) { return {}; }
    }

    function safeObject(value) { return value && typeof value === 'object' && !Array.isArray(value) ? value : {}; }
    function safeArray(value) { return Array.isArray(value) ? value : []; }

    function boolValue(value, fallback = false) {
        if (typeof value === 'boolean') return value;
        if (typeof value === 'number') return value !== 0;
        if (typeof value === 'string') {
            const normalized = value.trim().toLowerCase();
            if (['true', '1', 'sim', 'yes', 'ativo', 'ok'].includes(normalized)) return true;
            if (['false', '0', 'não', 'nao', 'no', 'inativo', 'erro'].includes(normalized)) return false;
        }
        return fallback;
    }

    function numberValue(value, fallback = 0) {
        const parsed = Number(value);
        return Number.isFinite(parsed) ? parsed : fallback;
    }

    function textValue(value, fallback = '—') {
        if (value === null || value === undefined || value === '') return fallback;
        if (typeof value === 'boolean') return value ? 'Sim' : 'Não';
        return String(value);
    }

    function setText(id, value, fallback = '—') {
        const element = $(id);
        if (element) element.textContent = textValue(value, fallback);
    }

    function setHidden(id, hidden) {
        const element = $(id);
        if (element) element.hidden = Boolean(hidden);
    }

    function setButtonLoading(button, loading) {
        if (!button) return;
        if (loading) {
            button.dataset.previousDisabled = String(button.disabled);
            button.disabled = true;
            button.classList.add('is-loading');
        } else {
            button.classList.remove('is-loading');
            button.disabled = button.dataset.previousDisabled === 'true';
            delete button.dataset.previousDisabled;
        }
    }

    function normalizeStatus(status, fallback = 'pending') {
        if (typeof status === 'boolean') return status ? 'ok' : 'error';
        const normalized = String(status || '').trim().toLowerCase();
        return STATUS_CLASS_MAP[normalized] || fallback;
    }

    function statusLabel(status, fallback = 'Verificando') {
        const normalized = String(status || '').trim().toLowerCase();
        return STATUS_LABELS[normalized] || capitalize(normalized) || fallback;
    }

    function capitalize(value) {
        const text = String(value || '').trim();
        return text ? text.charAt(0).toUpperCase() + text.slice(1) : '';
    }

    function updateClassByPrefix(element, prefix, status) {
        if (!element) return;
        element.className = element.className.split(' ').filter(c => !c.startsWith(prefix)).join(' ');
        element.classList.add(prefix + normalizeStatus(status));
    }

    function applyChip(id, status, label = null) {
        const element = $(id);
        if (element) {
            updateClassByPrefix(element, 'sp-chip--', status);
            element.textContent = label || statusLabel(status);
        }
    }

    function applyPill(id, status, label = null) {
        const element = $(id);
        if (element) {
            updateClassByPrefix(element, 'sp-status-pill--', status);
            element.textContent = label || statusLabel(status);
        }
    }

    function applyStatusDot(id, status) {
        updateClassByPrefix($(id), 'sp-status-dot--', status);
    }

    function formatDate(value, options = {}) {
        if (!value) return '—';
        const date = value instanceof Date ? value : new Date(value);
        if (Number.isNaN(date.getTime())) return textValue(value);
        return new Intl.DateTimeFormat('pt-BR', { dateStyle: options.dateStyle || 'short', timeStyle: options.timeStyle || 'medium' }).format(date);
    }

    function formatRelativeTime(value) {
        if (!value) return 'agora';
        const date = value instanceof Date ? value : new Date(value);
        if (Number.isNaN(date.getTime())) return 'agora';
        const diffSeconds = Math.round((date.getTime() - Date.now()) / 1000);
        const absolute = Math.abs(diffSeconds);
        let unit = 'second', divisor = 1;
        if (absolute >= 86400) { unit = 'day'; divisor = 86400; }
        else if (absolute >= 3600) { unit = 'hour'; divisor = 3600; }
        else if (absolute >= 60) { unit = 'minute'; divisor = 60; }
        try {
            return new Intl.RelativeTimeFormat('pt-BR', { numeric: 'auto' }).format(Math.round(diffSeconds / divisor), unit);
        } catch (error) { return formatDate(date); }
    }

    function formatDuration(seconds) {
        const value = numberValue(seconds, -1);
        if (value < 0) return '—';
        if (value < 60) return `${Math.round(value)}s`;
        const minutes = Math.floor(value / 60);
        const remainingSeconds = Math.round(value % 60);
        if (minutes < 60) return `${minutes}m ${remainingSeconds}s`;
        const hours = Math.floor(minutes / 60);
        const remainingMinutes = minutes % 60;
        return `${hours}h ${remainingMinutes}m`;
    }

    function formatBytes(bytes) {
        const value = numberValue(bytes, -1);
        if (value < 0) return '—';
        if (value === 0) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
        const result = value / Math.pow(1024, index);
        return `${result.toFixed(index === 0 ? 0 : result >= 10 ? 1 : 2)} ${units[index]}`;
    }

    function formatBoolean(value, yes = 'Sim', no = 'Não') {
        if (value === null || value === undefined) return '—';
        return boolValue(value) ? yes : no;
    }

    function formatCaptureMode(value) {
        const labels = { lan: 'Somente LAN', lan_wan: 'LAN + WAN', personalizado: 'Personalizado' };
        return labels[String(value || '')] || textValue(value);
    }

    function sanitizeUrl(template, id) { return String(template || '').replace('__ID__', encodeURIComponent(id)); }
    function getCookie(name) {
        const cookies = document.cookie ? document.cookie.split(';') : [];
        for (const cookie of cookies) {
            const [key, ...rest] = cookie.trim().split('=');
            if (key === name) return decodeURIComponent(rest.join('='));
        }
        return null;
    }
    function csrfToken() { return APP.csrfToken || getCookie('csrftoken') || ''; }

    // ================================================================
    // [03] CLIENTE HTTP / API
    // ================================================================
    async function fetchJSON(url, options = {}) {
        if (!url) throw new Error('URL da API não configurada.');
        const method = String(options.method || 'GET').toUpperCase();
        const headers = new Headers(options.headers || {});
        headers.set('Accept', 'application/json');

        if (options.body !== undefined && !(options.body instanceof FormData) && !headers.has('Content-Type')) {
            headers.set('Content-Type', 'application/json');
        }

        if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) headers.set('X-CSRFToken', csrfToken());

        const controller = new AbortController();
        const timeout = window.setTimeout(() => controller.abort(), options.timeout || 30000);
        let body = options.body;
        if (body !== undefined && body !== null && !(body instanceof FormData) && typeof body !== 'string') {
            body = JSON.stringify(body);
        }

        try {
            const response = await fetch(url, { ...options, method, headers, body, credentials: 'same-origin', signal: controller.signal });
            const contentType = response.headers.get('content-type') || '';
            let payload;

            if (contentType.includes('application/json')) {
                payload = await response.json();
            } else {
                const text = await response.text();
                payload = { ok: response.ok, mensagem: text || response.statusText };
            }

            if (!response.ok) {
                const message = payload?.mensagem || payload?.erro || payload?.detail || `Erro HTTP ${response.status}.`;
                const error = new Error(message);
                error.status = response.status;
                error.payload = payload;
                throw error;
            }

            return payload;
        } catch (error) {
            if (error.name === 'AbortError') throw new Error('A solicitação excedeu o tempo limite.');
            throw error;
        } finally {
            window.clearTimeout(timeout);
        }
    }

    function unwrapPayload(payload) {
        if (!payload || typeof payload !== 'object') return {};
        if (payload.dados && typeof payload.dados === 'object' && !Array.isArray(payload.dados)) return payload.dados;
        if (payload.data && typeof payload.data === 'object' && !Array.isArray(payload.data)) return payload.data;
        return payload;
    }

    // ================================================================
    // [04] FEEDBACK VISUAL E COMPONENTES BASE
    // ================================================================
    function showToast(message, type = 'info', title = null, duration = 5000) {
        const container = $('toastContainer');
        if (!container) return;

        const toastType = type === 'success' ? 'ok' : type === 'warn' ? 'warning' : type === 'danger' ? 'error' : type;
        const iconMap = {
            ok: '<path d="m5 12 4 4L19 6"/>',
            warning: '<path d="M10.3 2.9 1.8 17a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 2.9a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4M12 17h.01"/>',
            error: '<circle cx="12" cy="12" r="9"/><path d="m9 9 6 6M15 9l-6 6"/>',
            info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>',
        };
        const titleMap = { ok: 'Concluído', warning: 'Atenção', error: 'Erro', info: 'Informação' };

        const toast = document.createElement('div');
        toast.className = `sp-toast sp-toast--${toastType}`;
        toast.innerHTML = `
            <span class="sp-toast__icon">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">${iconMap[toastType] || iconMap.info}</svg>
            </span>
            <span class="sp-toast__copy">
                <strong>${escapeHTML(title || titleMap[toastType] || titleMap.info)}</strong>
                <span>${escapeHTML(message)}</span>
            </span>
            <button class="sp-copy-btn" type="button" aria-label="Fechar">Fechar</button>
        `;

        const close = () => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(15px)';
            window.setTimeout(() => toast.remove(), 180);
        };

        toast.querySelector('button')?.addEventListener('click', close);
        container.appendChild(toast);
        if (duration > 0) window.setTimeout(close, duration);
    }

    function escapeHTML(value) {
        const div = document.createElement('div');
        div.textContent = textValue(value, '');
        return div.innerHTML;
    }

    function iconSVG(name, size = 16) {
        const paths = {
            pulse: '<path d="M3 12h4l2-5 4 10 2-5h6"/>',
            download: '<path d="M12 3v12M7 10l5 5 5-5"/><path d="M5 21h14"/>',
            settings: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06A1.65 1.65 0 0 0 15 19.4a1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.6 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06A2 2 0 1 1 7.04 4.3l.06.06A1.65 1.65 0 0 0 9 4.6a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9c.12.6.65 1 1.26 1H21a2 2 0 1 1 0 4h-.09c-.61 0-1.14.4-1.51 1Z"/>',
            refresh: '<path d="M20 11a8.1 8.1 0 1 0 2 5.3"/><path d="M20 4v7h-7"/>',
            check: '<path d="m5 12 4 4L19 6"/>',
            restart: '<path d="M20 11a8.1 8.1 0 1 0 2 5.3"/><path d="M20 4v7h-7"/>',
            activity: '<path d="M3 12h4l2-5 4 10 2-5h6"/>',
            task: '<path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>',
        };
        return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">${paths[name] || paths.task}</svg>`;
    }

    function initStars() {
        const canvas = $('starsCanvas');
        if (!canvas) return;
        const context = canvas.getContext('2d');
        if (!context) return;

        let stars = [];
        let frameId = null;

        const resize = () => {
            const ratio = Math.min(window.devicePixelRatio || 1, 2);
            canvas.width = Math.floor(window.innerWidth * ratio);
            canvas.height = Math.floor(window.innerHeight * ratio);
            canvas.style.width = `${window.innerWidth}px`;
            canvas.style.height = `${window.innerHeight}px`;
            context.setTransform(ratio, 0, 0, ratio, 0, 0);

            const count = Math.max(50, Math.floor((window.innerWidth * window.innerHeight) / 8500));
            stars = Array.from({ length: count }, () => ({
                x: Math.random() * window.innerWidth, y: Math.random() * window.innerHeight,
                radius: Math.random() * 1.05 + .15, alpha: Math.random() * .55 + .12,
                speed: Math.random() * .0025 + .001, phase: Math.random() * Math.PI * 2,
            }));
        };

        const draw = (timestamp) => {
            // OTIMIZAÇÃO: Não recalcula/renderiza nada no modo claro.
            if (document.documentElement.getAttribute('data-theme') === 'light') {
                frameId = window.requestAnimationFrame(draw);
                return;
            }

            context.clearRect(0, 0, window.innerWidth, window.innerHeight);
            for (const star of stars) {
                const alpha = star.alpha * (.55 + .45 * Math.sin(star.phase + timestamp * star.speed));
                context.beginPath();
                context.arc(star.x, star.y, star.radius, 0, Math.PI * 2);
                context.fillStyle = `rgba(190, 213, 255, ${Math.max(.05, alpha)})`;
                context.fill();
            }
            frameId = window.requestAnimationFrame(draw);
        };

        resize();
        frameId = window.requestAnimationFrame(draw);
        window.addEventListener('resize', resize);
        window.addEventListener('beforeunload', () => { if (frameId) window.cancelAnimationFrame(frameId); }, { once: true });
    }

    // ================================================================
    // [05] NAVEGAÇÃO E EVENTOS
    // ================================================================
    function initNavigation() {
        $all('[data-section-target]').forEach((button) => {
            button.addEventListener('click', () => navigateToSection(button.dataset.sectionTarget));
        });

        $all('[data-section-link]').forEach((button) => {
            button.addEventListener('click', () => navigateToSection(button.dataset.sectionLink));
        });

        $('btnOpenConfiguration')?.addEventListener('click', () => navigateToSection('configuration'));
        $('btnOpenSidebar')?.addEventListener('click', openSidebar);
        $('btnCloseSidebar')?.addEventListener('click', closeSidebar);
        $('sidebarBackdrop')?.addEventListener('click', closeSidebar);

        // EVENT DELEGATION: Listener centralizado para aberturas de tarefas via tabela ou lista de resumo
        $('taskTableBody')?.addEventListener('click', handleTaskTableClick);
        $('overviewTaskList')?.addEventListener('click', handleTaskTableClick);
    }

    function handleTaskTableClick(event) {
        const button = event.target.closest('[data-task-open]');
        if (button) openTaskDrawer(button.dataset.taskOpen);
    }

    function navigateToSection(sectionName) {
        const target = document.querySelector(`.sp-section[data-section="${CSS.escape(sectionName)}"]`);
        if (!target) return;

        $all('.sp-section').forEach(sec => sec.classList.toggle('is-active', sec.dataset.section === sectionName));
        $all('[data-section-target]').forEach(btn => btn.classList.toggle('is-active', btn.dataset.sectionTarget === sectionName));

        state.currentSection = sectionName;
        window.scrollTo({ top: 0, behavior: 'smooth' });
        closeSidebar();

        if (sectionName === 'tasks') loadTasks().catch(handleError);
        if (sectionName === 'diagnostic' && state.diagnosticData) renderDiagnostic(state.diagnosticData);
    }

    function openSidebar() {
        $('panelSidebar')?.classList.add('is-open');
        $('sidebarBackdrop')?.classList.add('is-open');
        document.body.style.overflow = 'hidden';
    }

    function closeSidebar() {
        $('panelSidebar')?.classList.remove('is-open');
        $('sidebarBackdrop')?.classList.remove('is-open');
        document.body.style.overflow = '';
    }

    function initButtons() {
        [ $('btnRefreshStatus'), $('btnRefreshHealth'), $('btnRefreshTopology') ].filter(Boolean).forEach((button) => {
            button.addEventListener('click', async () => {
                setButtonLoading(button, true);
                try { await refreshStatus(true); } catch (e) { handleError(e); } finally { setButtonLoading(button, false); }
            });
        });

        [ $('btnRunDiagnosticTop'), $('btnRunDiagnosticHero'), $('btnRunDiagnostic') ].filter(Boolean).forEach((btn) => {
            btn.addEventListener('click', () => runDiagnostic(btn));
        });

        $('btnUpdateAllRules')?.addEventListener('click', () => {
            confirmTask({
                tipo: 'atualizacao_regras',
                parametros: { atualizar_et: true, atualizar_moonshield: true, validar_depois: true, reiniciar_depois: false },
                title: 'Atualizar todas as regras?',
                text: 'O MoonShield atualizará ET Open e reaplicará as regras MoonShield.',
                details: 'A operação pode levar alguns minutos e exige execução pelo worker do Suricata.',
            });
        });

        $('btnUpdateMoonRules')?.addEventListener('click', () => {
            confirmTask({
                tipo: 'atualizacao_regras',
                parametros: { atualizar_et: false, atualizar_moonshield: true, validar_depois: true, reiniciar_depois: false },
                title: 'Reaplicar regras MoonShield?',
                text: 'As regras locais do MoonShield serão copiadas novamente e validadas.',
            });
        });

        $('btnUpdateEtRules')?.addEventListener('click', () => {
            confirmTask({
                tipo: 'atualizacao_regras',
                parametros: { atualizar_et: true, atualizar_moonshield: false, validar_depois: true, reiniciar_depois: false },
                title: 'Atualizar ET Open?',
                text: 'O suricata-update será executado para atualizar as assinaturas comunitárias.',
            });
        });

        $('btnValidateRules')?.addEventListener('click', () => {
            confirmTask({
                tipo: 'validacao', parametros: {},
                title: 'Validar configuração?',
                text: 'O MoonShield verificará o YAML e executará a validação técnica disponível.',
            });
        });

        $all('[data-action="restart-suricata"]').forEach((btn) => {
            btn.addEventListener('click', () => confirmTask({
                tipo: 'reinicio_suricata', parametros: {},
                title: 'Reiniciar o Suricata?', text: 'A captura pode ficar indisponível por alguns segundos.',
                details: 'O comando será enviado como tarefa privilegiada.',
            }));
        });

        $all('[data-action="restart-monitor"]').forEach((btn) => {
            btn.addEventListener('click', () => confirmTask({
                tipo: 'reinicio_monitor', parametros: {},
                title: 'Reiniciar o monitor?', text: 'A leitura do eve.json será reiniciada.',
                details: 'Eventos já persistidos não serão removidos.',
            }));
        });

        $('btnRefreshTasks')?.addEventListener('click', async () => {
            const btn = $('btnRefreshTasks');
            setButtonLoading(btn, true);
            try { await loadTasks(); showToast('Lista de tarefas atualizada.', 'ok'); }
            catch (e) { handleError(e); } finally { setButtonLoading(btn, false); }
        });

        $('taskStatusFilter')?.addEventListener('change', () => { state.taskOffset = 0; loadTasks().catch(handleError); });
        $('taskTypeFilter')?.addEventListener('change', () => { state.taskOffset = 0; loadTasks().catch(handleError); });
        $('btnClearTaskFilters')?.addEventListener('click', () => {
            if ($('taskStatusFilter')) $('taskStatusFilter').value = '';
            if ($('taskTypeFilter')) $('taskTypeFilter').value = '';
            state.taskOffset = 0; loadTasks().catch(handleError);
        });

        $('btnTaskPrev')?.addEventListener('click', () => { state.taskOffset = Math.max(0, state.taskOffset - state.taskLimit); loadTasks().catch(handleError); });
        $('btnTaskNext')?.addEventListener('click', () => { if (state.taskOffset + state.taskLimit < state.taskTotal) { state.taskOffset += state.taskLimit; loadTasks().catch(handleError); }});

        $('btnCloseTaskDrawer')?.addEventListener('click', closeTaskDrawer);
        $('btnCloseTaskDrawerFooter')?.addEventListener('click', closeTaskDrawer);
        $all('[data-close-task-drawer]').forEach(el => el.addEventListener('click', closeTaskDrawer));

        $('btnCancelTask')?.addEventListener('click', () => {
            if (!state.currentTaskId) return;
            confirmOperation({
                title: 'Solicitar cancelamento?',
                text: 'O cancelamento é cooperativo e ocorrerá entre as etapas da tarefa.',
                details: `Tarefa: ${state.currentTaskId}`,
                confirmLabel: 'Solicitar cancelamento',
                confirmClass: 'sp-btn--danger',
                onConfirm: () => requestTaskCancellation(state.currentTaskId),
            });
        });

        $('btnCopyTaskLogs')?.addEventListener('click', () => copyToClipboard($('drawerTaskLogs')?.innerText || '', 'Logs copiados.'));
        $('btnCopyValidation')?.addEventListener('click', () => copyToClipboard($('rulesValidationTextOutput')?.textContent || '', 'Validação copiada.'));

        $('btnCancelConfirmation')?.addEventListener('click', closeConfirmation);
        $all('[data-close-confirmation]').forEach(el => el.addEventListener('click', closeConfirmation));

        $('btnConfirmOperation')?.addEventListener('click', async () => {
            if (!state.pendingConfirmation?.onConfirm) { closeConfirmation(); return; }
            const callback = state.pendingConfirmation.onConfirm;
            const btn = $('btnConfirmOperation');
            setButtonLoading(btn, true);
            try { await callback(); closeConfirmation(); } catch (e) { handleError(e); } finally { setButtonLoading(btn, false); }
        });

        document.addEventListener('keydown', (event) => {
            if (event.key !== 'Escape') return;
            if ($('confirmationModal')?.classList.contains('is-open')) { closeConfirmation(); return; }
            if ($('taskDrawer')?.classList.contains('is-open')) { closeTaskDrawer(); return; }
            closeSidebar();
        });
    }

    function confirmTask(config) {
        confirmOperation({
            title: config.title, text: config.text, details: config.details || '', confirmLabel: 'Criar tarefa',
            onConfirm: async () => {
                const task = await createTask(config.tipo, config.parametros || {});
                showToast('Tarefa criada com sucesso.', 'ok');
                await loadTasks();
                openTaskDrawer(task.id || task.pk);
            },
        });
    }

    function confirmOperation({ title, text, details = '', confirmLabel = 'Confirmar', confirmClass = 'sp-btn--primary', onConfirm }) {
        state.pendingConfirmation = { onConfirm };
        setText('confirmationModalTitle', title, 'Confirmar operação');
        setText('confirmationModalText', text, 'Confirme para continuar.');
        const detailsEl = $('confirmationModalDetails');
        if (detailsEl) { detailsEl.hidden = !details; detailsEl.textContent = details || ''; }
        const confirmBtn = $('btnConfirmOperation');
        if (confirmBtn) { confirmBtn.textContent = confirmLabel; confirmBtn.className = `sp-btn ${confirmClass}`; }
        const modal = $('confirmationModal');
        if (modal) {
            modal.classList.add('is-open');
            modal.setAttribute('aria-hidden', 'false');
            window.setTimeout(() => confirmBtn?.focus(), 50);
        }
    }

    function closeConfirmation() {
        state.pendingConfirmation = null;
        const modal = $('confirmationModal');
        if (modal) { modal.classList.remove('is-open'); modal.setAttribute('aria-hidden', 'true'); }
    }

    // ================================================================
    // [06] STATUS, SAÚDE, CONFIGURAÇÃO E TOPOLOGIA
    // ================================================================
    async function refreshStatus(showSuccessToast = false) {
        if (state.isFetchingStatus) return state.statusData;
        state.isFetchingStatus = true;
        setStatusRefreshVisual(true);

        try {
            const payload = await fetchJSON(apiUrl('status'));
            const data = unwrapPayload(payload);
            state.statusData = data;
            state.lastStatusFetchAt = new Date();
            renderStatus(data);
            if (showSuccessToast) showToast('Status atualizado com sucesso.', 'ok');
            return data;
        } catch (error) {
            renderStatusError(error);
            throw error;
        } finally {
            state.isFetchingStatus = false;
            setStatusRefreshVisual(false);
        }
    }

    function setStatusRefreshVisual(loading) {
        const button = $('btnRefreshStatus');
        if (button) button.classList.toggle('is-loading', loading);
    }

    function renderStatus(data) {
        const stack = safeObject(data?.stack ?? data?.dados?.stack ?? data?.novo_status ?? data?.status_stack ?? data);
        const suricata = safeObject(stack?.suricata ?? stack?.status_suricata ?? data?.suricata ?? {});
        const monitor = safeObject(stack?.monitor ?? stack?.monitor_local ?? data?.monitor ?? {});
        const services = safeObject(stack?.servicos ?? data?.servicos ?? {});
        const environment = safeObject(stack?.ambiente ?? data?.ambiente ?? {});

        const statusGeneral = stack?.status ?? data?.status ?? 'desconhecido';
        const healthy = boolValue(stack?.saudavel ?? (normalizeStatus(statusGeneral) === 'ok'));
        const stackActive = boolValue(stack?.stack_ativa ?? (boolValue(suricata?.ativo ?? false) && boolValue(monitor?.ativo ?? false)));
        const message = stack?.mensagem ?? data?.mensagem ?? (healthy ? 'A stack Suricata está funcionando normalmente.' : 'Existem pontos que precisam de atenção.');

        renderGlobalStatus({ status: statusGeneral, healthy, active: stackActive, message });
        renderSuricata(suricata, services, environment);
        renderMonitor(monitor, services);
        renderEve(suricata, monitor);
        renderCursor(monitor);
        renderRules(suricata, stack);
        renderConfiguration(APP.configuracao ?? data?.configuracao ?? CONFIG);
        renderHealthSummary(stack, data);
        renderTopology(suricata?.topologia ?? stack?.topologia ?? {}, APP.configuracao ?? CONFIG);
        renderStackChecks(stack, data);
        renderRulesSection(suricata, stack);
        updateLastRefresh();
    }

    function renderGlobalStatus({ status, healthy, active, message }) {
        const normalized = healthy ? 'ok' : normalizeStatus(status, active ? 'warning' : 'error');

        applyStatusDot('sidebarStatusDot', normalized);
        applyStatusDot('heroStatusDot', normalized);
        applyChip('headerStackChip', normalized, statusLabel(normalized));

        setText('headerStackText', healthy ? 'Saudável' : active ? 'Com avisos' : 'Atenção');
        setText('sidebarStatusTitle', healthy ? 'Proteção ativa' : active ? 'Proteção degradada' : 'Proteção indisponível');
        setText('sidebarStatusText', message);
        setText('heroStatusEyebrow', healthy ? 'Proteção operacional' : active ? 'Operação com avisos' : 'Intervenção necessária');
        setText('heroDescription', message);

        const orbit = $('orbitStatus');
        if (orbit) {
            orbit.className = orbit.className.split(' ').filter(c => !c.startsWith('sp-orbit__status--')).join(' ');
            orbit.classList.add(`sp-orbit__status--${normalized}`);
        }
        setText('orbitStatusText', healthy ? 'Stack operacional' : active ? 'Stack degradada' : 'Stack indisponível');
    }

    function renderSuricata(suricata, services, environment) {
        const service = safeObject(suricata?.servico ?? services?.suricata ?? {});
        const installed = boolValue(suricata?.instalado ?? service?.instalado ?? false);
        const active = boolValue(suricata?.ativo ?? service?.ativo ?? false);
        const enabled = boolValue(service?.habilitado ?? false);
        const ready = boolValue(suricata?.pronto ?? (active && installed));
        const version = suricata?.versao ?? environment?.versao_suricata ?? '';
        const message = suricata?.mensagem ?? service?.mensagem ?? '';

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
        setText('healthSuricataPid', service?.pid ?? '—');
        setText('healthSuricataVersion', version || '—');
        setText('healthSuricataService', service?.nome ?? service?.servico ?? 'suricata');
    }

    function renderMonitor(monitor, services) {
        const service = safeObject(monitor?.servico ?? services?.monitor ?? {});
        const installed = boolValue(service?.instalado ?? false);
        const active = boolValue(monitor?.ativo ?? service?.ativo ?? false);
        const reading = boolValue(monitor?.lendo_eve ?? false);
        const healthy = boolValue(monitor?.saudavel ?? (active && reading));
        const message = monitor?.mensagem ?? service?.mensagem ?? '';

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
        setText('healthMonitorPid', service?.pid ?? '—');
        setText('healthMonitorService', service?.nome ?? service?.servico ?? 'moonshield-suricata-monitor');
    }

    function renderEve(suricata, monitor) {
        const eve = safeObject(monitor?.eve ?? suricata?.eve ?? {});
        const exists = boolValue(eve?.existe ?? false);
        const readable = boolValue(eve?.legivel ?? false);
        const updating = boolValue(eve?.atualizando ?? false);
        const age = eve?.idade_segundos ?? null;
        const size = eve?.tamanho ?? null;
        const message = eve?.mensagem ?? '';

        const status = updating ? 'ok' : exists && readable ? 'warning' : 'error';

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
        setText('healthEvePath', eve?.caminho ?? '—');
    }

    function renderCursor(monitor) {
        const cursor = safeObject(monitor?.cursor ?? {});
        const exists = boolValue(cursor?.existe ?? false);
        const valid = boolValue(cursor?.valido ?? false);
        const following = boolValue(cursor?.acompanhando ?? false);
        const message = cursor?.mensagem ?? '';

        const status = following ? 'ok' : exists && valid ? 'warning' : 'error';

        applyPill('healthCursorStatus', status);
        setText('healthCursorMessage', message || 'Estado do cursor consultado');
        setText('healthCursorExists', formatBoolean(exists));
        setText('healthCursorValid', formatBoolean(valid));
        setText('healthCursorFollowing', formatBoolean(following));
        setText('healthCursorPosition', cursor?.posicao ?? '—');
        const lag = cursor?.atraso_bytes ?? null;
        setText('healthCursorLag', lag !== null ? formatBytes(lag) : '—');
        setText('healthCursorPath', cursor?.caminho ?? '—');
    }

    function renderRules(suricata, stack) {
        const rules = safeObject(suricata?.regras ?? stack?.regras ?? {});
        const moon = safeObject(rules?.moonshield ?? rules?.regras_moonshield ?? {});
        const et = safeObject(rules?.et_open ?? rules?.etopen ?? {});

        const moonInstalled = boolValue(moon?.instaladas ?? moon?.instalado ?? rules?.moonshield_instalado ?? false);
        const etInstalled = boolValue(et?.instalado ?? rules?.et_open_instalado ?? false);
        const totalRules = rules?.total_regras ?? rules?.total ?? moon?.total ?? null;

        const status = moonInstalled ? (etInstalled ? 'ok' : 'warning') : 'error';

        updateStatusCard('cardRules', {
            status, stateId: 'cardRulesState', valueId: 'cardRulesValue', detailId: 'cardRulesDetail', metaId: 'cardRulesMeta',
            value: moonInstalled ? 'Carregadas' : 'Incompletas',
            detail: moonInstalled ? 'Regras MoonShield disponíveis' : 'Regras MoonShield não confirmadas',
            meta: totalRules !== null ? `${numberValue(totalRules)} regras` : etInstalled ? 'MoonShield + ET Open' : 'Pacotes incompletos',
        });
    }

    function updateStatusCard(cardId, config) {
        const card = $(cardId);
        if (!card) return;
        updateClassByPrefix(card, 'sp-status-card--', config.status);
        setText(config.stateId, statusLabel(config.status));
        setText(config.valueId, config.value);
        setText(config.detailId, config.detail);
        setText(config.metaId, config.meta);
    }

    function renderConfiguration(configuration) {
        const config = safeObject(configuration);

        setText('configName', config?.nome ?? 'Suricata Local');
        setText('configCaptureMode', formatCaptureMode(config?.modo_captura ?? ''));
        setText('configOnboarding', formatBoolean(config?.onboarding_concluido ?? false, 'Concluído', 'Pendente'));
        setText('configInstallation', formatBoolean(config?.instalacao_concluida ?? false, 'Concluída', 'Pendente'));
        setText('configSuricataConfigured', formatBoolean(config?.suricata_configurado ?? false, 'Sim', 'Não'));
        setText('configUpdatedAt', formatDate(config?.atualizado_em ?? null));
        setText('configWan', config?.interface_wan ?? '—');
        setText('configLan', config?.interface_lan ?? '—');
        setText('configMgmt', config?.interface_mgmt ?? '—');
        setText('configInternalDns', config?.dns_interno ?? '—');
        setText('configEtOpen', formatBoolean(config?.instalar_et_open ?? false, 'Ativado', 'Desativado'));
        setText('configMoonShieldRules', formatBoolean(config?.instalar_regras_moonshield ?? true, 'Ativadas', 'Desativadas'));
        setText('configYamlPath', config?.yaml_path ?? '/etc/suricata/suricata.yaml');
        setText('configEvePath', config?.eve_path ?? '/var/log/suricata/eve.json');
        setText('configCursorPath', config?.cursor_path ?? 'var/cursors/suricata_eve.cursor');

        const ready = boolValue(config?.pronto ?? (boolValue(config?.suricata_instalado ?? false) && boolValue(config?.suricata_configurado ?? false)));
        applyChip('configReadyChip', ready ? 'ok' : 'warning', ready ? 'Pronta' : 'Pendente');

        renderChips('configMonitoredInterfaces', safeArray(config?.interfaces_monitoradas ?? []), 'Nenhuma');
        renderCodeList('configHomeNetList', safeArray(config?.home_net ?? []), 'Nenhuma rede informada');
    }

    function renderChips(containerId, values, emptyLabel = 'Nenhum') {
        const container = $(containerId);
        if (!container) return;
        container.innerHTML = '';
        if (!values.length) {
            container.innerHTML = `<span class="sp-interface-chip">${emptyLabel}</span>`;
            return;
        }
        for (const value of values) {
            const chip = document.createElement('span');
            chip.className = 'sp-interface-chip';
            chip.textContent = textValue(value);
            container.appendChild(chip);
        }
    }

    function renderCodeList(containerId, values, emptyLabel) {
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

    function renderTopology(topology, configuration) {
        const config = safeObject(configuration);
        const data = safeObject(topology);

        const wan = data?.interface_wan ?? data?.wan?.nome ?? data?.wan ?? config?.interface_wan ?? 'WAN';
        const lan = data?.interface_lan ?? data?.lan?.nome ?? data?.lan ?? config?.interface_lan ?? 'LAN';
        const homeNet = safeArray(data?.home_net ?? config?.home_net ?? []);
        const monitored = safeArray(data?.interfaces_monitoradas ?? config?.interfaces_monitoradas ?? []);

        setText('topologyWanLabel', wan || 'WAN');
        setText('topologyLanLabel', lan || 'LAN');
        setText('topologyCaptureMode', formatCaptureMode(config?.modo_captura ?? data?.modo_captura ?? ''));
        setText('topologyHomeNet', homeNet.length ? homeNet.join(', ') : 'HOME_NET não informado');
        renderChips('topologyInterfaceChips', monitored, 'Nenhuma interface');
    }

    function renderHealthSummary(stack, data) {
        const errors = safeArray(stack?.erros ?? data?.erros ?? []);
        const warnings = safeArray(stack?.avisos ?? data?.avisos ?? []);

        let okCount = 0;
        let warningCount = warnings.length;
        let errorCount = errors.length;

        const checks = collectHealthChecks(stack);
        for (const check of checks) {
            const normalized = normalizeStatus(check.status);
            if (normalized === 'ok') okCount++;
            if (normalized === 'warning') warningCount++;
            if (normalized === 'error') errorCount++;
        }

        const total = Math.max(1, okCount + warningCount + errorCount);
        const score = Math.max(0, Math.min(100, Math.round(((okCount + warningCount * .45) / total) * 100)));

        setText('healthScoreValue', score);
        setText('healthOkCount', okCount);
        setText('healthWarningCount', warningCount);
        setText('healthErrorCount', errorCount);

        const circle = $('healthScoreCircle');
        if (circle) {
            const circumference = 302;
            circle.style.strokeDashoffset = String(circumference - (score / 100) * circumference);
            circle.style.stroke = score >= 85 ? 'var(--sp-green)' : score >= 60 ? 'var(--sp-yellow)' : 'var(--sp-red)';
        }

        const status = errorCount > 0 ? 'error' : warningCount > 0 ? 'warning' : 'ok';

        setText('healthScoreTitle', status === 'ok' ? 'Stack saudável' : status === 'warning' ? 'Stack com avisos' : 'Stack requer atenção');
        setText('healthScoreText', errorCount > 0 ? `${errorCount} falha(s) crítica(s) precisam de atenção.` : warningCount > 0 ? `${warningCount} aviso(s) foram encontrados.` : 'Todos os componentes consultados estão saudáveis.');

        applyChip('healthSummaryChip', status, status === 'ok' ? 'Saudável' : status === 'warning' ? 'Com avisos' : 'Crítico');
    }

    function collectHealthChecks(stack) {
        const checks = [];
        const suricata = safeObject(stack?.suricata ?? {});
        const monitor = safeObject(stack?.monitor ?? {});
        const eve = safeObject(monitor?.eve ?? suricata?.eve ?? {});
        const cursor = safeObject(monitor?.cursor ?? {});

        checks.push({ title: 'Suricata ativo', message: suricata?.mensagem ?? '', status: boolValue(suricata?.ativo ?? false) ? 'ok' : 'error' });
        checks.push({ title: 'Monitor ativo', message: monitor?.mensagem ?? '', status: boolValue(monitor?.ativo ?? false) ? 'ok' : 'error' });
        checks.push({ title: 'EVE atualizando', message: eve?.mensagem ?? '', status: boolValue(eve?.atualizando ?? false) ? 'ok' : 'warning' });
        checks.push({ title: 'Cursor acompanhando', message: cursor?.mensagem ?? '', status: boolValue(cursor?.acompanhando ?? false) ? 'ok' : 'warning' });

        return checks;
    }

    function renderStackChecks(stack, data) {
        const container = $('stackChecksList');
        if (!container) return;

        const checks = collectHealthChecks(stack);
        const errors = safeArray(stack?.erros ?? data?.erros ?? []);
        const warnings = safeArray(stack?.avisos ?? data?.avisos ?? []);

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

    function renderRulesSection(suricata, stack) {
        const rules = safeObject(suricata?.regras ?? stack?.regras ?? {});
        const moon = safeObject(rules?.moonshield ?? rules?.regras_moonshield ?? {});
        const et = safeObject(rules?.et_open ?? rules?.etopen ?? {});
        const updater = safeObject(rules?.suricata_update ?? rules?.updater ?? {});
        const validation = safeObject(suricata?.configuracao?.validacao ?? suricata?.configuracao?.validacao_suricata ?? stack?.validacao ?? {});

        const moonInstalled = boolValue(moon?.instaladas ?? moon?.instalado ?? false);
        const moonReferenced = boolValue(moon?.referenciadas ?? moon?.referenciado ?? false);
        const etInstalled = boolValue(et?.instalado ?? false);
        const updaterInstalled = boolValue(updater?.instalado ?? rules?.suricata_update_instalado ?? false);

        applyPill('rulesMoonStatus', moonInstalled && moonReferenced ? 'ok' : moonInstalled ? 'warning' : 'error');
        applyPill('rulesEtStatus', etInstalled ? 'ok' : 'warning');

        setText('rulesMoonFile', moon?.arquivo ?? moon?.caminho ?? '—');
        setText('rulesMoonInstalled', formatBoolean(moonInstalled));
        setText('rulesMoonReferenced', formatBoolean(moonReferenced));
        setText('rulesMoonCount', moon?.total ?? moon?.quantidade ?? '—');

        setText('rulesUpdaterInstalled', formatBoolean(updaterInstalled));
        setText('rulesEtInstalled', formatBoolean(etInstalled));
        setText('rulesEtUpdatedAt', formatDate(et?.atualizado_em ?? et?.ultima_atualizacao ?? null));
        setText('rulesEtSummary', et?.mensagem ?? (etInstalled ? 'Disponível' : 'Não confirmado'));

        const validationSuccess = boolValue(validation?.sucesso ?? validation?.valido ?? false);
        const hasValidation = Object.keys(validation).length > 0 || validation?.mensagem !== undefined;

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
        setText('rulesValidationText', validation?.mensagem ?? (validationSuccess ? 'O Suricata aceitou o arquivo de configuração.' : 'O arquivo de configuração possui erros.'));

        const output = validation?.saida ?? validation?.stdout ?? validation?.stderr ?? validation?.detalhes ?? '';
        if (output) {
            setHidden('rulesValidationOutput', false);
            setText('rulesValidationTextOutput', typeof output === 'string' ? output : JSON.stringify(output, null, 2));
        }
    }

    function renderStatusError(error) {
        applyStatusDot('sidebarStatusDot', 'error');
        applyStatusDot('heroStatusDot', 'error');
        applyChip('headerStackChip', 'error', 'Erro');
        setText('headerStackText', 'Erro');
        setText('sidebarStatusTitle', 'Falha na consulta');
        setText('sidebarStatusText', error.message);
        setText('heroStatusEyebrow', 'Não foi possível consultar a stack');
        setText('heroDescription', error.message);
        updateLastRefresh();
    }

    function updateLastRefresh() {
        const value = state.lastStatusFetchAt || new Date();
        setText('lastUpdateText', formatRelativeTime(value));
    }

    // ================================================================
    // [07] DIAGNÓSTICO
    // ================================================================
    async function runDiagnostic(button = null) {
        if (state.isRunningDiagnostic) return;
        state.isRunningDiagnostic = true;

        const buttons = [ $('btnRunDiagnosticTop'), $('btnRunDiagnosticHero'), $('btnRunDiagnostic') ].filter(Boolean);
        buttons.forEach((item) => setButtonLoading(item, true));
        applyChip('diagnosticGeneralChip', 'pending', 'Executando');

        try {
            const payload = await fetchJSON(apiUrl('diagnostico'), { timeout: 120000 });
            const data = unwrapPayload(payload);
            state.diagnosticData = data;
            renderDiagnostic(data);
            navigateToSection('diagnostic');
            showToast('Diagnóstico concluído.', 'ok');
        } catch (error) {
            applyChip('diagnosticGeneralChip', 'error', 'Falhou');
            handleError(error);
        } finally {
            state.isRunningDiagnostic = false;
            buttons.forEach((item) => setButtonLoading(item, false));
        }
    }

    function renderDiagnostic(data) {
        const diagnostic = safeObject(data?.diagnostico ?? data);
        const result = safeObject(diagnostic?.resultado ?? diagnostic);
        const summary = safeObject(data?.resumo ?? diagnostic?.resumo ?? {});
        const actions = safeArray(data?.acoes ?? data?.acoes_recomendadas ?? diagnostic?.acoes_recomendadas ?? []);
        const items = safeArray(result?.itens ?? result?.checks ?? diagnostic?.itens ?? diagnostic?.checks ?? []);

        const total = numberValue(summary?.total_checks ?? summary?.total ?? items.length, items.length);
        const ok = numberValue(summary?.total_ok ?? summary?.ok ?? items.filter(isCheckOk).length);
        const warnings = numberValue(summary?.total_avisos ?? summary?.avisos ?? items.filter(isCheckWarning).length);
        const critical = numberValue(summary?.total_criticos ?? summary?.falhas_criticas ?? items.filter(isCheckCriticalFailure).length);

        setText('diagnosticTotal', total);
        setText('diagnosticOk', ok);
        setText('diagnosticWarnings', warnings);
        setText('diagnosticCritical', critical);

        const ready = boolValue(summary?.pronto ?? (critical === 0));
        const status = ready ? (warnings > 0 ? 'warning' : 'ok') : 'error';

        applyChip('diagnosticGeneralChip', status, ready ? (warnings > 0 ? 'Com avisos' : 'Saudável') : 'Crítico');

        renderDiagnosticGroups(items);
        renderRecommendedActions(actions);
        setText('healthLastDiagnostic', `Último diagnóstico: ${formatDate(new Date())}`);
    }

    function isCheckOk(item) { return boolValue(item?.sucesso ?? item?.ok ?? false); }
    function isCheckWarning(item) { return !isCheckOk(item) && !boolValue(item?.critico ?? false); }
    function isCheckCriticalFailure(item) { return !isCheckOk(item) && boolValue(item?.critico ?? false); }

    function renderDiagnosticGroups(items) {
        const container = $('diagnosticGroups');
        if (!container) return;
        container.innerHTML = '';

        if (!items.length) {
            container.innerHTML = `
                <div class="sp-empty-state">
                    <span class="sp-empty-state__icon">${iconSVG('pulse', 22)}</span>
                    <div>
                        <strong>Nenhum check retornado</strong>
                        <span>A API não retornou itens de diagnóstico.</span>
                    </div>
                </div>`;
            return;
        }

        const groups = new Map();
        for (const item of items) {
            const group = textValue(item?.grupo ?? 'Outros', 'Outros');
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
                    <div>
                        <span class="sp-status-dot sp-status-dot--${groupStatus}"></span>
                        <strong>${escapeHTML(groupName)}</strong>
                    </div>
                    <span class="sp-status-pill sp-status-pill--${groupStatus}">${checks.length - failures}/${checks.length}</span>
                </div>
                <div class="sp-diagnostic-group__body"></div>
            `;

            const body = groupElement.querySelector('.sp-diagnostic-group__body');
            for (const check of checks) {
                const status = isCheckOk(check) ? 'ok' : boolValue(check?.critico ?? false) ? 'error' : 'warning';
                const element = document.createElement('div');
                element.className = `sp-diagnostic-check sp-diagnostic-check--${status}`;
                element.innerHTML = `
                    <span class="sp-diagnostic-check__dot"></span>
                    <span class="sp-diagnostic-check__copy">
                        <strong>${escapeHTML(check?.titulo ?? check?.nome ?? check?.id ?? 'Check')}</strong>
                        <span>${escapeHTML(check?.mensagem ?? check?.detalhe ?? statusLabel(status))}</span>
                    </span>
                    <span class="sp-status-pill sp-status-pill--${status}">${statusLabel(status)}</span>
                `;
                body.appendChild(element);
            }
            container.appendChild(groupElement);
        }
    }

    function renderRecommendedActions(actions) {
        const container = $('recommendedActions');
        if (!container) return;
        container.innerHTML = '';

        if (!actions.length) {
            container.innerHTML = `
                <div class="sp-empty-state sp-empty-state--compact">
                    <span class="sp-empty-state__icon">${iconSVG('check', 20)}</span>
                    <div>
                        <strong>Nenhuma ação necessária</strong>
                        <span>Não foram encontradas recomendações pendentes.</span>
                    </div>
                </div>`;
            return;
        }

        for (const action of actions) {
            const element = document.createElement('div');
            element.className = 'sp-recommended-action';
            element.innerHTML = `
                <span class="sp-recommended-action__priority">${escapeHTML(action?.prioridade ?? '•')}</span>
                <span class="sp-recommended-action__copy">
                    <strong>${escapeHTML(action?.titulo ?? action?.grupo ?? 'Ação recomendada')}</strong>
                    <span>${escapeHTML(action?.acao ?? action?.mensagem ?? 'Revise este item.')}</span>
                </span>
            `;
            container.appendChild(element);
        }
    }

    // ================================================================
    // [08] TAREFAS
    // ================================================================
    async function createTask(tipo, parametros = {}) {
        const payload = await fetchJSON(apiUrl('criarTarefa'), { method: 'POST', body: { tipo, parametros } });
        const data = unwrapPayload(payload);
        const task = data?.tarefa ?? payload?.tarefa ?? data;

        if (!task || typeof task !== 'object') throw new Error('A API não retornou a tarefa criada.');
        return task;
    }

    async function loadTasks() {
        const query = new URLSearchParams();
        const status = $('taskStatusFilter')?.value || '';
        const type = $('taskTypeFilter')?.value || '';

        query.set('offset', String(state.taskOffset));
        query.set('limite', String(state.taskLimit));
        if (status) query.set('status', status);
        if (type) query.set('tipo', type);

        const payload = await fetchJSON(`${apiUrl('listarTarefas')}?${query}`);
        const data = unwrapPayload(payload);

        const tasks = safeArray(data?.tarefas?.results ?? payload?.tarefas ?? []);
        const total = numberValue(data?.total?.count ?? data?.total ?? tasks.length, tasks.length);

        state.tasks = tasks;
        state.taskTotal = total;
        state.taskPage = Math.floor(state.taskOffset / state.taskLimit) + 1;

        renderTaskTable(tasks);
        renderOverviewTasks(tasks.slice(0, 5));
        renderTaskPagination();
        updateTaskBadge(tasks);

        return tasks;
    }

    function renderTaskTable(tasks) {
        const body = $('taskTableBody');
        if (!body) return;
        body.innerHTML = '';

        if (!tasks.length) {
            body.innerHTML = `<tr><td colspan="7"><div class="sp-empty-state"><span class="sp-empty-state__icon">${iconSVG('task', 22)}</span><div><strong>Nenhuma tarefa encontrada</strong><span>Altere os filtros ou crie uma nova operação.</span></div></div></td></tr>`;
            return;
        }

        // Os eventos de click foram delegados para o container `#taskTableBody` no initNavigation()
        for (const task of tasks) {
            const id = task.id || task.pk || '';
            const status = textValue(task.status, 'pendente').toLowerCase();
            const normalizedStatus = normalizeStatus(status);
            const progress = Math.max(0, Math.min(100, numberValue(task.progresso, 0)));
            const row = document.createElement('tr');

            row.innerHTML = `
                <td>
                    <div class="sp-task-cell">
                        <span class="sp-task-cell__icon">${iconSVG(TASK_ICONS[task.tipo] || 'task', 15)}</span>
                        <span class="sp-task-cell__copy">
                            <strong>${escapeHTML(TASK_LABELS[task.tipo] || capitalize(task.tipo))}</strong>
                            <span>${escapeHTML(id)}</span>
                        </span>
                    </div>
                </td>
                <td><span class="sp-status-pill sp-status-pill--${normalizedStatus}">${escapeHTML(statusLabel(status))}</span></td>
                <td>
                    <div class="sp-progress-mini">
                        <div class="sp-progress-mini__bar"><span style="width:${progress}%"></span></div>
                        <span class="sp-progress-mini__text">${progress}%</span>
                    </div>
                </td>
                <td>${escapeHTML(task.etapa_atual || '—')}</td>
                <td>${escapeHTML(formatDate(task.iniciado_em || task.criado_em))}</td>
                <td>${escapeHTML(formatDuration(task.duracao_segundos))}</td>
                <td>
                    <button class="sp-icon-btn sp-icon-btn--small" type="button" aria-label="Abrir tarefa" data-task-open="${escapeHTML(id)}">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
                    </button>
                </td>
            `;
            body.appendChild(row);
        }
    }

    function renderOverviewTasks(tasks) {
        const container = $('overviewTaskList');
        if (!container) return;
        container.innerHTML = '';

        if (!tasks.length) {
            container.innerHTML = `
                <div class="sp-empty-state sp-empty-state--compact">
                    <span class="sp-empty-state__icon">${iconSVG('task', 20)}</span>
                    <div><strong>Nenhuma atividade recente</strong><span>As últimas tarefas aparecerão aqui.</span></div>
                </div>`;
            return;
        }

        // Os eventos de click foram delegados para o container `#overviewTaskList` no initNavigation()
        for (const task of tasks) {
            const status = normalizeStatus(task.status);
            const element = document.createElement('button');
            element.type = 'button';
            element.className = 'sp-activity-item';
            element.dataset.taskOpen = task.id || task.pk || '';

            element.innerHTML = `
                <span class="sp-activity-item__icon">${iconSVG(TASK_ICONS[task.tipo] || 'task', 15)}</span>
                <span class="sp-activity-item__copy">
                    <strong>${escapeHTML(TASK_LABELS[task.tipo] || capitalize(task.tipo))}</strong>
                    <span>${escapeHTML(task.mensagem || task.etapa_atual || 'Sem detalhes')}</span>
                </span>
                <span class="sp-status-pill sp-status-pill--${status}">${escapeHTML(statusLabel(task.status))}</span>
            `;
            container.appendChild(element);
        }
    }

    function renderTaskPagination() {
        const start = state.taskTotal ? state.taskOffset + 1 : 0;
        const end = Math.min(state.taskOffset + state.taskLimit, state.taskTotal);
        const totalPages = Math.max(1, Math.ceil(state.taskTotal / state.taskLimit));

        setText('taskPaginationText', `${start}–${end} de ${state.taskTotal} tarefa(s)`);
        setText('taskPageText', `Página ${state.taskPage} de ${totalPages}`);

        if ($('btnTaskPrev')) $('btnTaskPrev').disabled = state.taskOffset <= 0;
        if ($('btnTaskNext')) $('btnTaskNext').disabled = state.taskOffset + state.taskLimit >= state.taskTotal;
    }

    function updateTaskBadge(tasks) {
        const running = tasks.filter((task) => RUNNING_TASK_STATUSES.has(String(task.status || '').toLowerCase())).length;
        const badge = $('navTaskBadge');
        if (!badge) return;
        badge.hidden = running === 0;
        badge.textContent = String(running);
    }

    async function openTaskDrawer(taskId) {
        if (!taskId) return;
        state.currentTaskId = taskId;

        const drawer = $('taskDrawer');
        if (drawer) {
            drawer.classList.add('is-open');
            drawer.setAttribute('aria-hidden', 'false');
            document.body.style.overflow = 'hidden';
        }

        renderTaskDrawerLoading(taskId);

        try { await loadTaskDetail(taskId); } catch (error) { handleError(error); }
    }

    function closeTaskDrawer() {
        stopTaskPolling();
        const drawer = $('taskDrawer');
        if (drawer) {
            drawer.classList.remove('is-open');
            drawer.setAttribute('aria-hidden', 'true');
        }
        state.currentTaskId = null;
        state.currentTask = null;
        document.body.style.overflow = '';
    }

    function renderTaskDrawerLoading(taskId) {
        setText('taskDrawerTitle', 'Carregando tarefa');
        setText('drawerTaskType', '—');
        setText('drawerTaskId', taskId);
        setText('drawerTaskStage', 'Consultando');
        setText('drawerTaskPercent', '0%');
        setText('drawerTaskMessage', 'Buscando dados da tarefa...');
        applyPill('drawerTaskStatus', 'pending', 'Carregando');

        const bar = $('drawerTaskProgressBar');
        if (bar) bar.style.width = '0%';

        setText('drawerTaskCreated', '—');
        setText('drawerTaskStarted', '—');
        setText('drawerTaskFinished', '—');
        setText('drawerTaskDuration', '—');
        setHidden('drawerTaskError', true);
        setHidden('btnCancelTask', true);

        const logs = $('drawerTaskLogs');
        if (logs) logs.innerHTML = '<div class="sp-terminal__empty">Carregando logs...</div>';
        setText('drawerTaskResult', 'Carregando...');
    }

    async function loadTaskDetail(taskId) {
        const detailUrl = sanitizeUrl(apiUrl('detalheTarefaTemplate'), taskId);
        const payload = await fetchJSON(detailUrl);
        const data = unwrapPayload(payload);
        const task = data?.tarefa ?? payload?.tarefa ?? data;

        state.currentTask = task;
        renderTaskDrawer(task);
        await loadTaskLogs(taskId);

        if (RUNNING_TASK_STATUSES.has(String(task.status || '').toLowerCase())) startTaskPolling(taskId);
        else stopTaskPolling();

        return task;
    }

    function renderTaskDrawer(task) {
        const id = task.id || task.pk || state.currentTaskId || '—';
        const status = String(task.status || 'pendente').toLowerCase();
        const progress = Math.max(0, Math.min(100, numberValue(task.progresso, 0)));

        setText('taskDrawerTitle', TASK_LABELS[task.tipo] || capitalize(task.tipo) || 'Tarefa Suricata');
        setText('drawerTaskType', TASK_LABELS[task.tipo] || capitalize(task.tipo));
        setText('drawerTaskId', id);
        applyPill('drawerTaskStatus', normalizeStatus(status), statusLabel(status));
        setText('drawerTaskStage', task.etapa_atual || 'Aguardando início');
        setText('drawerTaskPercent', `${progress}%`);
        setText('drawerTaskMessage', task.mensagem || 'Nenhuma atualização disponível.');
        setText('drawerTaskCreated', formatDate(task.criado_em));
        setText('drawerTaskStarted', formatDate(task.iniciado_em));
        setText('drawerTaskFinished', formatDate(task.finalizado_em));
        setText('drawerTaskDuration', formatDuration(task.duracao_segundos));

        const bar = $('drawerTaskProgressBar');
        if (bar) bar.style.width = `${progress}%`;

        const hasError = Boolean(task.erro);
        setHidden('drawerTaskError', !hasError);
        setText('drawerTaskErrorText', task.erro || '');

        const canCancel = boolValue(task.pode_cancelar) || RUNNING_TASK_STATUSES.has(status);
        setHidden('btnCancelTask', !canCancel);

        const result = task.resultado || {};
        setText('drawerTaskResult', Object.keys(safeObject(result)).length ? JSON.stringify(result, null, 2) : 'Nenhum resultado disponível.');
    }

    async function loadTaskLogs(taskId) {
        const url = new URL(sanitizeUrl(apiUrl('logsTarefaTemplate'), taskId), window.location.origin);
        url.searchParams.set('offset', '0');
        url.searchParams.set('limite', '500');

        const payload = await fetchJSON(url.toString());
        const data = unwrapPayload(payload);
        const logs = safeArray(data?.logs ?? payload?.logs ?? []);

        renderTaskLogs(logs);
        return logs;
    }

    function renderTaskLogs(logs) {
        const container = $('drawerTaskLogs');
        if (!container) return;
        container.innerHTML = '';

        if (!logs.length) {
            container.innerHTML = '<div class="sp-terminal__empty">Nenhum log registrado.</div>';
            return;
        }

        for (const log of logs) {
            const line = document.createElement('div');
            line.className = 'sp-terminal-line';
            const level = textValue(log.nivel, 'info').toUpperCase();
            const time = log.criado_em ? new Date(log.criado_em).toLocaleTimeString('pt-BR') : '--:--:--';

            line.innerHTML = `
                <span class="sp-terminal-line__time">${escapeHTML(time)}</span>
                <span class="sp-terminal-line__level">[${escapeHTML(level)}]</span>
                <span class="sp-terminal-line__message">${escapeHTML(log.etapa ? `${log.etapa}: ${log.mensagem}` : log.mensagem)}</span>
            `;
            container.appendChild(line);
        }
        container.scrollTop = container.scrollHeight;
    }

    function startTaskPolling(taskId) {
        stopTaskPolling();
        state.taskPollTimer = window.setInterval(async () => {
            if (state.destroyed || state.currentTaskId !== taskId || document.hidden) return;

            try {
                const task = await loadTaskDetailWithoutRestart(taskId);
                if (FINAL_TASK_STATUSES.has(String(task.status || '').toLowerCase())) {
                    stopTaskPolling();
                    await loadTasks();
                    await refreshStatus();

                    showToast(
                        task.status === 'sucesso' ? 'Tarefa concluída.' : task.status === 'cancelado' ? 'Tarefa cancelada.' : 'Tarefa finalizada com erro.',
                        task.status === 'sucesso' ? 'ok' : task.status === 'cancelado' ? 'warning' : 'error'
                    );
                }
            } catch (error) { console.error('Erro no polling da tarefa:', error); }
        }, 2500);
    }

    async function loadTaskDetailWithoutRestart(taskId) {
        const detailUrl = sanitizeUrl(apiUrl('detalheTarefaTemplate'), taskId);
        const payload = await fetchJSON(detailUrl);
        const data = unwrapPayload(payload);
        const task = data?.tarefa ?? payload?.tarefa ?? data;

        state.currentTask = task;
        renderTaskDrawer(task);
        await loadTaskLogs(taskId);
        return task;
    }

    function stopTaskPolling() {
        if (state.taskPollTimer) {
            window.clearInterval(state.taskPollTimer);
            state.taskPollTimer = null;
        }
    }

    async function requestTaskCancellation(taskId) {
        const url = sanitizeUrl(apiUrl('cancelarTarefaTemplate'), taskId);
        await fetchJSON(url, { method: 'POST', body: {} });
        showToast('Cancelamento solicitado.', 'warning');
        await loadTaskDetail(taskId);
    }

    async function copyToClipboard(text, successMessage) {
        if (!text) { showToast('Não há conteúdo para copiar.', 'warning'); return; }
        try {
            await navigator.clipboard.writeText(text);
            showToast(successMessage, 'ok');
        } catch (error) {
            const textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.position = 'fixed';
            textarea.style.opacity = '0';
            document.body.appendChild(textarea);
            textarea.select();
            try { document.execCommand('copy'); showToast(successMessage, 'ok'); }
            catch (copyError) { showToast('Não foi possível copiar.', 'error'); }
            finally { textarea.remove(); }
        }
    }

    // ================================================================
    // [09] POLLING E CICLO DE VIDA
    // ================================================================
    function startStatusPolling() {
        stopStatusPolling();
        state.statusPollTimer = window.setInterval(() => {
            if (state.destroyed || document.hidden || state.isFetchingStatus) return;
            refreshStatus().catch((error) => console.error('Falha ao atualizar status:', error));
        }, 30000);
    }

    function stopStatusPolling() {
        if (state.statusPollTimer) {
            window.clearInterval(state.statusPollTimer);
            state.statusPollTimer = null;
        }
    }

    function handleError(error) {
        console.error(error);
        const message = error?.payload?.mensagem || error?.payload?.erro || error?.message || 'Ocorreu um erro inesperado.';
        showToast(message, 'error');
    }

    function bindVisibility() {
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden) {
                refreshStatus().catch(console.error);
                if (state.currentTaskId) loadTaskDetail(state.currentTaskId).catch(console.error);
            }
        });
    }

    function cleanup() {
        state.destroyed = true;
        stopTaskPolling();
        stopStatusPolling();
    }

    // ================================================================
    // [10] BOOTSTRAP
    // ================================================================
    async function bootstrap() {
        validatePanelContract();
        initStars();
        initNavigation();
        initButtons();
        bindVisibility();

        if (Object.keys(state.statusData).length) {
            try { renderStatus(state.statusData); } catch (e) { console.error('Erro ao renderizar status inicial:', e); }
        }
        renderConfiguration(CONFIG);

        const initialTasksPromise = loadTasks().catch(e => console.error('Erro ao carregar tarefas iniciais:', e));
        const statusPromise = refreshStatus().catch(e => console.error('Erro ao carregar status inicial:', e));
        await Promise.allSettled([initialTasksPromise, statusPromise]);

        startStatusPolling();
    }

    window.addEventListener('beforeunload', cleanup, { once: true });
    bootstrap().catch(handleError);
});