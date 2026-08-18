// tarefas.js
(() => {
    'use strict';

    const config = window.MS_SURICATA_PANEL;
    if (!config) return;

    const DOM = {
        filterStatus: document.getElementById('taskStatusFilter'),
        filterType: document.getElementById('taskTypeFilter'),
        btnClearFilters: document.getElementById('btnClearTaskFilters'),
        btnRefreshTasks: document.getElementById('btnRefreshTasks'),
        btnUpdateRules: document.getElementById('btnUpdateAllRules'),
        btnTaskPrev: document.getElementById('btnTaskPrev'),
        btnTaskNext: document.getElementById('btnTaskNext'),
        taskTableBody: document.getElementById('taskTableBody'),
        taskPageText: document.getElementById('taskPageText'),
        taskPaginationText: document.getElementById('taskPaginationText'),
        navTaskBadge: document.getElementById('navTaskBadge'),
        modal: document.getElementById('confirmationModal')
    };

    let currentPage = 1;
    const pageSize = 10;

    const fetchTasks = async (page = 1) => {
        try {
            const params = new URLSearchParams({
                page,
                limit: pageSize,
                status: DOM.filterStatus?.value || '',
                type: DOM.filterType?.value || ''
            });

            const res = await fetch(`${config.urls.listarTarefas}?${params}`, {
                headers: { 'X-CSRFToken': config.csrfToken }
            });

            const data = await res.json();
            renderTasks(data.tarefas || []);
            updatePagination(data.pagina_atual || 1, data.total_paginas || 1, data.total || 0);
            updateTaskBadge(data.pendentes_count || 0);
        } catch (error) {
            console.error('[MoonShield] Erro ao buscar tarefas:', error);
            DOM.taskTableBody.innerHTML = '<tr><td colspan="7">Erro ao carregar tarefas.</td></tr>';
        }
    };

    const renderTasks = (tarefas) => {
        if (!DOM.taskTableBody) return;

        if (!tarefas.length) {
            DOM.taskTableBody.innerHTML = '<tr><td colspan="7" style="text-align: center; padding: 20px;">Nenhuma tarefa encontrada.</td></tr>';
            return;
        }

        DOM.taskTableBody.innerHTML = tarefas.map(t => {
            const criada = new Date(t.criada_em);
            const horaCriada = criada.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
            
            return `
                <tr data-task-id="${t.id}">
                    <td>
                        <strong style="display: block; margin-bottom: 2px;">${t.tipo}</strong>
                        <small style="color: var(--sp-dim);">${t.descricao || ''}</small>
                    </td>
                    <td><span class="ob-chip ob-chip--${t.estado}">${t.estado}</span></td>
                    <td><span style="font-family: 'DM Mono', monospace;">${t.progresso || 0}%</span></td>
                    <td><small>${t.etapa || '—'}</small></td>
                    <td><small>${horaCriada}</small></td>
                    <td><small>${formatDuration(t.duracao_segundos)}</small></td>
                    <td>
                        <button class="ob-icon-btn ob-icon-btn--sm task-open-btn" type="button" title="Ver detalhes">→</button>
                    </td>
                </tr>
            `;
        }).join('');

        DOM.taskTableBody.querySelectorAll('.task-open-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const taskId = e.target.closest('tr').dataset.taskId;
                openTaskDrawer(taskId);
            });
        });
    };

    const updatePagination = (current, total, totalItems) => {
        currentPage = current;

        if (DOM.btnTaskPrev) DOM.btnTaskPrev.disabled = current === 1;
        if (DOM.btnTaskNext) DOM.btnTaskNext.disabled = current === total;
        if (DOM.taskPageText) DOM.taskPageText.textContent = `Página ${current} / ${total}`;
        if (DOM.taskPaginationText) {
            const start = (current - 1) * pageSize + 1;
            const end = Math.min(current * pageSize, totalItems);
            DOM.taskPaginationText.textContent = `${start}–${end} de ${totalItems} tarefas`;
        }
    };

    const updateTaskBadge = (count) => {
        if (!DOM.navTaskBadge) return;
        if (count > 0) {
            DOM.navTaskBadge.textContent = count;
            DOM.navTaskBadge.hidden = false;
        } else {
            DOM.navTaskBadge.hidden = true;
        }
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
        const drawer = document.getElementById('taskDrawer');
        if (!drawer) return;

        drawer.classList.add('is-open');
        drawer.setAttribute('aria-hidden', 'false');

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
            document.getElementById('drawerTaskStage').textContent = task.etapa || '—';
            document.getElementById('drawerTaskPercent').textContent = `${task.progresso || 0}%`;
            document.getElementById('drawerTaskMessage').textContent = task.mensagem || 'Sem atualizações.';

            const progressBar = document.getElementById('drawerTaskProgressBar');
            if (progressBar) {
                progressBar.style.width = `${task.progresso || 0}%`;
            }

            document.getElementById('drawerTaskCreated').textContent = new Date(task.criada_em).toLocaleString('pt-BR');
            document.getElementById('drawerTaskStarted').textContent = task.iniciada_em ? new Date(task.iniciada_em).toLocaleString('pt-BR') : '—';
            document.getElementById('drawerTaskFinished').textContent = task.finalizada_em ? new Date(task.finalizada_em).toLocaleString('pt-BR') : '—';
            document.getElementById('drawerTaskDuration').textContent = formatDuration(task.duracao_segundos);

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

            pollTaskUpdates(taskId);
        } catch (error) {
            console.error('[MoonShield] Erro ao carregar tarefa:', error);
        }
    };

    let pollInterval = null;
    const pollTaskUpdates = (taskId) => {
        if (pollInterval) clearInterval(pollInterval);

        const updateTask = async () => {
            try {
                const url = config.urls.detalheTarefaTemplate.replace('__ID__', taskId);
                const res = await fetch(url, {
                    headers: { 'X-CSRFToken': config.csrfToken }
                });
                const task = await res.json();

                if (['sucesso', 'erro', 'cancelado'].includes(task.estado)) {
                    clearInterval(pollInterval);
                }

                document.getElementById('drawerTaskPercent').textContent = `${task.progresso || 0}%`;
                document.getElementById('drawerTaskStage').textContent = task.etapa || '—';
                document.getElementById('drawerTaskMessage').textContent = task.mensagem || '—';

                const progressBar = document.getElementById('drawerTaskProgressBar');
                if (progressBar) {
                    progressBar.style.width = `${task.progresso || 0}%`;
                }
            } catch (error) {
                console.error('[MoonShield] Erro ao atualizar tarefa:', error);
            }
        };

        updateTask();
        pollInterval = setInterval(updateTask, 1500);
    };

    // Event listeners
    DOM.btnRefreshTasks?.addEventListener('click', () => fetchTasks(1));
    DOM.filterStatus?.addEventListener('change', () => fetchTasks(1));
    DOM.filterType?.addEventListener('change', () => fetchTasks(1));

    DOM.btnClearFilters?.addEventListener('click', () => {
        if (DOM.filterStatus) DOM.filterStatus.value = '';
        if (DOM.filterType) DOM.filterType.value = '';
        fetchTasks(1);
    });

    DOM.btnTaskPrev?.addEventListener('click', () => {
        if (currentPage > 1) fetchTasks(currentPage - 1);
    });

    DOM.btnTaskNext?.addEventListener('click', () => {
        fetchTasks(currentPage + 1);
    });

    DOM.btnUpdateRules?.addEventListener('click', async () => {
        const confirmed = confirm('Atualizar todas as regras? Isso pode levar alguns minutos.');
        if (!confirmed) return;

        try {
            const res = await fetch(config.urls.criarTarefa, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': config.csrfToken
                },
                body: JSON.stringify({ tipo: 'atualizacao_regras' })
            });

            const data = await res.json();
            if (data.sucesso) {
                showToast('Tarefa de atualização criada.', 'ok');
                fetchTasks(1);
            } else {
                showToast(`Erro: ${data.erro}`, 'error');
            }
        } catch (error) {
            showToast('Erro ao criar tarefa.', 'error');
            console.error('[MoonShield] Erro:', error);
        }
    });

    const showToast = (message, type) => {
        const toast = document.createElement('div');
        toast.className = `ob-toast ob-toast--${type}`;
        toast.setAttribute('role', 'status');
        toast.innerHTML = `
            <span class="ob-toast__icon">${type === 'ok' ? '✓' : '!'}</span>
            <span>${message}</span>
        `;
        document.getElementById('toastContainer')?.appendChild(toast);
        setTimeout(() => {
            toast.classList.add('is-closing');
            setTimeout(() => toast.remove(), 300);
        }, 3500);
    };

    // Init
    fetchTasks(1);

})();