/**
 * MOONSHIELD — TERMINAL SURICATA
 * Responsável apenas por buscar, renderizar e atualizar logs de tarefas.
 */

(function () {
    'use strict';

    const APP = window.MS_SURICATA_PANEL || {};
    const URLS = APP.urls || {};

    const state = {
        tarefaId: null,
        offset: 0,
        limite: 500,
        total: 0,
        pollingId: null,
        registros: new Map(),
        carregando: false,
    };

    function elemento(id) {
        return document.getElementById(id);
    }

    function csrfToken() {
        if (APP.csrfToken) return APP.csrfToken;

        const cookie = document.cookie
            .split(';')
            .map((item) => item.trim())
            .find((item) => item.startsWith('csrftoken='));

        return cookie ? decodeURIComponent(cookie.split('=').slice(1).join('=')) : '';
    }

    function urlLogs(tarefaId) {
        const template = URLS.logsTarefaTemplate || '';
        return template.replace('__ID__', encodeURIComponent(tarefaId));
    }

    async function buscarJSON(url, opcoes = {}) {
        const headers = new Headers(opcoes.headers || {});
        headers.set('Accept', 'application/json');

        if (opcoes.method && opcoes.method !== 'GET') {
            headers.set('X-CSRFToken', csrfToken());
        }

        const resposta = await fetch(url, {
            credentials: 'same-origin',
            ...opcoes,
            headers,
        });

        const dados = await resposta.json().catch(() => ({}));

        if (!resposta.ok) {
            throw new Error(
                dados.mensagem ||
                dados.erro ||
                dados.detail ||
                `Erro HTTP ${resposta.status}`
            );
        }

        return dados;
    }

    function extrairDados(payload) {
        if (payload?.dados && typeof payload.dados === 'object') {
            return payload.dados;
        }

        return payload || {};
    }

    function normalizarNivel(nivel) {
        const valor = String(nivel || 'info').toLowerCase();

        if (['success', 'sucesso', 'ok'].includes(valor)) return 'success';
        if (['warning', 'warn', 'aviso'].includes(valor)) return 'warning';
        if (['error', 'erro', 'critical', 'critico'].includes(valor)) return 'error';
        if (['debug'].includes(valor)) return 'debug';

        return 'info';
    }

    function chaveLog(log) {
        return String(
            log.id ??
            log.sequencia ??
            `${log.criado_em || ''}|${log.etapa || ''}|${log.mensagem || ''}`
        );
    }

    function formatarHora(valor) {
        if (!valor) return '--:--:--';

        const data = new Date(valor);
        if (Number.isNaN(data.getTime())) return '--:--:--';

        return data.toLocaleTimeString('pt-BR');
    }

    function escapar(valor) {
        const div = document.createElement('div');
        div.textContent = String(valor ?? '');
        return div.innerHTML;
    }

    function criarLinha(log) {
        const nivel = normalizarNivel(log.nivel);
        const linha = document.createElement('div');

        linha.className = `sp-terminal-line sp-terminal-line--${nivel}`;
        linha.dataset.logKey = chaveLog(log);

        const mensagem = log.etapa
            ? `${log.etapa}: ${log.mensagem || ''}`
            : (log.mensagem || '');

        linha.innerHTML = `
            <span class="sp-terminal-line__time">
                ${escapar(formatarHora(log.criado_em))}
            </span>
            <span class="sp-terminal-line__level">
                [${escapar(nivel.toUpperCase())}]
            </span>
            <span class="sp-terminal-line__message">
                ${escapar(mensagem)}
            </span>
        `;

        return linha;
    }

    function renderizar(logs, substituir = false) {
        const terminal = elemento('drawerTaskLogs');
        if (!terminal) return;

        if (substituir) {
            terminal.innerHTML = '';
            state.registros.clear();
        }

        const estavaNoFim =
            terminal.scrollHeight - terminal.scrollTop - terminal.clientHeight < 40;

        for (const log of logs) {
            const chave = chaveLog(log);

            if (state.registros.has(chave)) continue;

            state.registros.set(chave, log);
            terminal.appendChild(criarLinha(log));
        }

        if (state.registros.size === 0) {
            terminal.innerHTML =
                '<div class="sp-terminal__empty">Nenhum log registrado.</div>';
            return;
        }

        terminal.querySelector('.sp-terminal__empty')?.remove();

        if (estavaNoFim || substituir) {
            terminal.scrollTop = terminal.scrollHeight;
        }
    }

    async function carregar(tarefaId, opcoes = {}) {
        if (!tarefaId || state.carregando) return [];

        state.carregando = true;
        state.tarefaId = tarefaId;

        const substituir = Boolean(opcoes.substituir);
        const offset = substituir ? 0 : state.offset;

        try {
            const params = new URLSearchParams({
                offset: String(offset),
                limite: String(state.limite),
            });

            const payload = await buscarJSON(`${urlLogs(tarefaId)}?${params}`);
            const dados = extrairDados(payload);
            const logs = Array.isArray(dados.logs) ? dados.logs : [];

            renderizar(logs, substituir);

            state.total = Number(dados.total || logs.length || 0);
            state.offset = Number(
                dados.proximo_offset ??
                (offset + logs.length)
            );

            return logs;
        } finally {
            state.carregando = false;
        }
    }

    function iniciarPolling(tarefaId, intervalo = 2500) {
        pararPolling();

        state.tarefaId = tarefaId;

        state.pollingId = window.setInterval(() => {
            if (document.hidden || !state.tarefaId) return;

            carregar(state.tarefaId).catch((erro) => {
                console.error('Erro ao atualizar logs da tarefa:', erro);
            });
        }, intervalo);
    }

    function pararPolling() {
        if (!state.pollingId) return;

        window.clearInterval(state.pollingId);
        state.pollingId = null;
    }

    async function abrir(tarefaId, acompanhar = true) {
        state.tarefaId = tarefaId;
        state.offset = 0;
        state.total = 0;
        state.registros.clear();

        await carregar(tarefaId, { substituir: true });

        if (acompanhar) {
            iniciarPolling(tarefaId);
        }
    }

    function limpar() {
        pararPolling();

        state.tarefaId = null;
        state.offset = 0;
        state.total = 0;
        state.registros.clear();

        const terminal = elemento('drawerTaskLogs');

        if (terminal) {
            terminal.innerHTML =
                '<div class="sp-terminal__empty">Os logs aparecerão aqui.</div>';
        }
    }

    async function copiar() {
        const terminal = elemento('drawerTaskLogs');
        const texto = terminal?.innerText?.trim() || '';

        if (!texto) return false;

        if (navigator.clipboard?.writeText) {
            await navigator.clipboard.writeText(texto);
            return true;
        }

        const textarea = document.createElement('textarea');
        textarea.value = texto;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';

        document.body.appendChild(textarea);
        textarea.select();

        const copiado = document.execCommand('copy');
        textarea.remove();

        return copiado;
    }

    function iniciar() {
        elemento('btnCopyTaskLogs')?.addEventListener('click', async () => {
            try {
                await copiar();
            } catch (erro) {
                console.error('Erro ao copiar logs:', erro);
            }
        });

        window.addEventListener('beforeunload', pararPolling, { once: true });
    }

    window.MoonShieldSuricataTerminal = {
        iniciar,
        abrir,
        carregar,
        renderizar,
        iniciarPolling,
        pararPolling,
        limpar,
        copiar,
        estado: state,
    };

    document.addEventListener('DOMContentLoaded', iniciar, { once: true });
})();
