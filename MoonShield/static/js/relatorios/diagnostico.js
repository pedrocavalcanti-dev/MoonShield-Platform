/* ============================================================
   MOONSHIELD — DIAGNOSTICO.JS  v1.0
   Front-end completo com dados simulados
   Back-end: conectar em /diagnostico/api/executar/ e /diagnostico/api/contexto/
   ============================================================ */

'use strict';

/* ══════════════════════════════════════════════════════════
   0. CONTEXTO SIMULADO
   BACK-END: substituir por fetch('/diagnostico/api/contexto/')
══════════════════════════════════════════════════════════ */
const MOCK_CTX = {
    iface: '—',
    cidr: '—',
    gateway: '—',
    dns1: '—',
    dns2: '—',
    hostname: '—',
    ip_local: '—',
    mode: 'N/D',
};

/* ══════════════════════════════════════════════════════════
   1. ESTADO GLOBAL
══════════════════════════════════════════════════════════ */
const Diag = {
    ctx: MOCK_CTX,
    lastResult: null,
    history: [],         // { tool, target, status, summary, result, ts }
    isRunning: false,
    autoRunning: false,
    execTimer: null,
    activeTermTab: 'saida',
};

/* ══════════════════════════════════════════════════════════
   2. CARREGAR CONTEXTO
══════════════════════════════════════════════════════════ */
function loadContext() {
    const c = Diag.ctx;
    setText('ctxIface', c.iface);
    setText('ctxCidr', c.cidr);
    setText('ctxGateway', c.gateway);
    setText('ctxDns1', c.dns1);
    setText('ctxDns2', c.dns2);
    setText('ctxHost', `${c.hostname} · ${c.ip_local}`);

    // Atualiza targets dos testes rápidos
    setText('qtPingGw', c.gateway);
    setText('qtDns', `${c.dns1} · google.com`);
    setText('qtDnsLat', `${c.dns1} / ${c.dns2}`);
    setText('qtArp', c.iface.split(' ')[0]);

    // Presets dos inputs de DNS
    const nsServer = document.getElementById('nsServer');
    if (nsServer) {
        nsServer.options[0].text = `DNS 1 — ${c.dns1}`;
        nsServer.options[1].text = `DNS 2 — ${c.dns2}`;
    }

    // Mode pill
    const pill = document.getElementById('modePill');
    const pillLabel = document.getElementById('modePillLabel');
    if (pill && pillLabel) {
        pillLabel.textContent = c.mode;
        if (c.mode === 'PROD') {
            pill.classList.add('diag-mode-pill--prod');
            pill.classList.remove('diag-mode-pill--demo');
        }
    }

    /* BACK-END:
     * fetch('/diagnostico/api/contexto/')
     *   .then(r => r.json())
     *   .then(data => { Diag.ctx = data; loadContext(); });
     */
}

/* ══════════════════════════════════════════════════════════
   3. MOCK DE EXECUÇÃO
   BACK-END: substituir simulateExec() por fetch real
══════════════════════════════════════════════════════════ */
const MOCK_RESPONSES = {};

const SUGGESTIONS = {
    'ping-err': 'Gateway não responde → verifique o cabo/Wi-Fi ou a configuração da VLAN.',
    'nslookup-err': 'DNS falhou → tente trocar DNS1/DNS2 nas Configurações.',
    'tcp_port_test-err': 'Porta fechada → verifique firewall local ou do destino.',
    'http_check-err': 'HTTP falhou → verifique a URL e se o servidor está online.',
    'ping-warn': 'Pacotes perdidos → possível instabilidade na rede.',
};

/* ══════════════════════════════════════════════════════════
   4. EXECUTAR FERRAMENTA
══════════════════════════════════════════════════════════ */
function executeToolMock(tool, target, options) {
    return new Promise(resolve => {
        resolve({
            ok: false,
            status: 'err',
            summary: 'Indisponível',
            stdout: 'Ferramenta não implementada nesta versão (aguardando backend).',
            stderr: 'Nenhum backend configurado.',
            meta: { duration_ms: 0, exit_code: 1 }
        });
    });
}

async function runTool(tool, target, options = {}, sourceCard = null) {
    if (Diag.isRunning) { toast('info', 'Aguarde a execução atual terminar.'); return; }
    if (!target && !['arp_table', 'routes', 'ipconfig', 'interfaces'].includes(tool)) {
        toast('err', 'Informe um alvo antes de executar.'); return;
    }

    Diag.isRunning = true;
    startExecUI(tool, target, sourceCard);

    try {
        const result = await executeToolMock(tool, target, options);
        Diag.lastResult = { tool, target, options, result, ts: new Date() };
        displayResult(Diag.lastResult);
        addToHistory(Diag.lastResult);
        updateQuickCardStatus(sourceCard, result.status, result.meta?.duration_ms);

        // Sugestão inteligente
        const suggKey = `${tool}-${result.status}`;
        const sugg = SUGGESTIONS[suggKey];
        const suggEl = document.getElementById('termSuggestion');
        const suggText = document.getElementById('termSuggestionText');
        if (sugg && suggEl && suggText) {
            suggText.textContent = sugg;
            suggEl.style.display = 'flex';
        } else if (suggEl) {
            suggEl.style.display = 'none';
        }

        // Chamado sugerido se erro
        if (result.status === 'err') tryShowChamado(tool);

    } catch (e) {
        displayError(e.message);
    } finally {
        Diag.isRunning = false;
        stopExecUI(sourceCard);
    }
}

/* ══════════════════════════════════════════════════════════
   5. UI DE EXECUÇÃO
══════════════════════════════════════════════════════════ */
function startExecUI(tool, target, cardId) {
    const execBar = document.getElementById('execBar');
    const execLabel = document.getElementById('execBarLabel');
    const execFill = document.getElementById('execFill');
    const termOutput = document.getElementById('termOutput');
    const termTitle = document.getElementById('termTitle');
    const termMeta = document.getElementById('termMeta');
    const termSummary = document.getElementById('termSummary');
    const suggEl = document.getElementById('termSuggestion');

    if (termTitle) termTitle.textContent = `${tool} · ${target || 'localhost'} · executando…`;
    if (termOutput) termOutput.textContent = `Executando ${tool}...\n`;
    if (termMeta) termMeta.style.display = 'none';
    if (termSummary) termSummary.style.display = 'none';
    if (suggEl) suggEl.style.display = 'none';
    if (execBar) execBar.style.display = 'flex';
    if (execLabel) execLabel.textContent = `Executando ${tool} → ${target || 'host'}…`;

    // Progress bar animation
    let p = 0;
    clearInterval(Diag.execTimer);
    Diag.execTimer = setInterval(() => {
        p = Math.min(p + Math.random() * 8 + 2, 90);
        if (execFill) execFill.style.width = p + '%';
    }, 150);

    // Disable run buttons
    if (cardId) {
        const card = document.getElementById(cardId);
        const btn = card?.querySelector('.diag-quick-card__btn');
        if (btn) { btn.textContent = 'Rodando…'; btn.classList.add('diag-quick-card__btn--running'); }
    }

    document.querySelectorAll('.diag-run-btn').forEach(b => b.classList.add('diag-run-btn--running'));
    document.querySelectorAll('.diag-quick-card__btn').forEach(b => { b.disabled = true; });
}

function stopExecUI(cardId) {
    clearInterval(Diag.execTimer);
    const execBar = document.getElementById('execBar');
    const execFill = document.getElementById('execFill');
    if (execFill) execFill.style.width = '100%';
    setTimeout(() => {
        if (execBar) execBar.style.display = 'none';
        if (execFill) execFill.style.width = '0';
    }, 400);

    if (cardId) {
        const card = document.getElementById(cardId);
        const btn = card?.querySelector('.diag-quick-card__btn');
        if (btn) { btn.textContent = 'Executar'; btn.classList.remove('diag-quick-card__btn--running'); btn.disabled = false; }
    }

    document.querySelectorAll('.diag-run-btn').forEach(b => b.classList.remove('diag-run-btn--running'));
    document.querySelectorAll('.diag-quick-card__btn').forEach(b => { b.disabled = false; });
}

/* ══════════════════════════════════════════════════════════
   6. EXIBIR RESULTADO NO TERMINAL
══════════════════════════════════════════════════════════ */
function displayResult(entry) {
    const { tool, target, result, ts } = entry;

    const termOutput = document.getElementById('termOutput');
    const termTitle = document.getElementById('termTitle');
    const termMeta = document.getElementById('termMeta');
    const termSummary = document.getElementById('termSummary');
    const termJson = document.getElementById('termJson');

    // Meta bar
    setText('metaTool', tool);
    setText('metaTarget', target || 'localhost');
    setText('metaTime', ts.toLocaleTimeString('pt-BR'));
    const metaStatus = document.getElementById('metaStatus');
    if (metaStatus) {
        metaStatus.textContent = result.status.toUpperCase();
        metaStatus.className = `diag-term-status diag-term-status--${result.status}`;
    }

    if (termMeta) termMeta.style.display = 'flex';
    if (termOutput) termOutput.textContent = result.stdout + (result.stderr ? `\n\n[STDERR]\n${result.stderr}` : '');
    if (termTitle) termTitle.textContent = `${tool} · ${target || 'localhost'} · ${ts.toLocaleTimeString('pt-BR')}`;

    // Summary
    if (termSummary) {
        termSummary.style.display = 'flex';
        termSummary.className = `diag-term-summary diag-term-summary--${result.status}`;
        const icon = termSummary.querySelector('svg');
        if (icon) {
            if (result.status === 'ok') icon.innerHTML = '<polyline points="20 6 9 17 4 12"/>';
            if (result.status === 'warn') icon.innerHTML = '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/>';
            if (result.status === 'err') icon.innerHTML = '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>';
        }
        setText('termSummaryText', result.summary);
    }

    // Details panel
    setText('detDuration', `${result.meta.duration_ms}ms`);
    setText('detExitCode', String(result.meta.exit_code));
    setText('detTool', tool);
    setText('detTarget', target || 'localhost');
    setText('detOutputSize', `${result.stdout.length} bytes`);
    setText('detTimestamp', ts.toLocaleString('pt-BR'));

    const stderrSection = document.getElementById('detStderr');
    if (stderrSection) {
        if (result.stderr) {
            stderrSection.style.display = 'block';
            setText('detStderrContent', result.stderr);
        } else {
            stderrSection.style.display = 'none';
        }
    }

    // JSON panel
    if (termJson) {
        termJson.textContent = JSON.stringify({ tool, target, options: entry.options, result, timestamp: ts.toISOString() }, null, 2);
    }
}

function displayError(msg) {
    const termOutput = document.getElementById('termOutput');
    const termTitle = document.getElementById('termTitle');
    if (termOutput) termOutput.textContent = `[ERRO] ${msg}`;
    if (termTitle) termTitle.textContent = 'Terminal · erro de execução';
    toast('err', `Erro: ${msg}`);
}

/* ══════════════════════════════════════════════════════════
   7. STATUS DOS CARDS RÁPIDOS
══════════════════════════════════════════════════════════ */
const STATUS_EMOJI = { ok: '✅', warn: '⚠️', err: '❌' };

function updateQuickCardStatus(cardId, status, ms) {
    if (!cardId) return;
    const card = document.getElementById(cardId);
    if (!card) return;

    const statusEl = card.querySelector('.diag-quick-card__status');
    const timeEl = card.querySelector('.diag-quick-card__time');

    if (statusEl) statusEl.textContent = STATUS_EMOJI[status] || '—';
    if (timeEl && ms) timeEl.textContent = `${ms}ms`;

    card.classList.remove('diag-quick-card--ok', 'diag-quick-card--warn', 'diag-quick-card--err');
    card.classList.add(`diag-quick-card--${status}`);

    // Atualiza o elemento de status específico (qsPingGw etc)
    const idMap = {
        qcPingGw: 'qsPingGw', qcInternet: 'qsInternet', qcDns: 'qsDns',
        qcDnsLat: 'qsDnsLat', qcArp: 'qsArp', qcRoutes: 'qsRoutes',
    };
    const sId = idMap[cardId];
    if (sId) setText(sId, STATUS_EMOJI[status]);

    const tMap = {
        qcPingGw: 'qqPingGw', qcInternet: 'qqInternet', qcDns: 'qqDns',
        qcDnsLat: 'qqDnsLat', qcArp: 'qqArp', qcRoutes: 'qqRoutes',
    };
    const tId = tMap[cardId];
    if (tId && ms) setText(tId, `${ms}ms`);
}

/* ══════════════════════════════════════════════════════════
   8. HISTÓRICO
══════════════════════════════════════════════════════════ */
function addToHistory(entry) {
    Diag.history.unshift(entry);
    if (Diag.history.length > 50) Diag.history.pop();
    renderHistory();
}

function renderHistory() {
    const list = document.getElementById('historyList');
    if (!list) return;

    if (Diag.history.length === 0) {
        list.innerHTML = '<div class="diag-history__empty">Nenhum teste executado ainda</div>';
        return;
    }

    list.innerHTML = Diag.history.map((e, i) => `
    <div class="diag-hist-item" data-idx="${i}">
      <div class="diag-hist-item__dot diag-hist-item__dot--${e.result.status}"></div>
      <div class="diag-hist-item__body">
        <span class="diag-hist-item__tool">${e.tool}</span>
        <span class="diag-hist-item__target">${e.target || 'localhost'}</span>
      </div>
      <span class="diag-hist-item__time">${e.ts.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })}</span>
      <button class="diag-hist-item__replay" data-idx="${i}" title="Reexecutar">
        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <polygon points="5 3 19 12 5 21 5 3"/>
        </svg>
      </button>
    </div>`).join('');

    // Clique para ver resultado
    list.querySelectorAll('.diag-hist-item').forEach(item => {
        item.addEventListener('click', e => {
            if (e.target.closest('.diag-hist-item__replay')) return;
            const idx = parseInt(item.dataset.idx);
            Diag.lastResult = Diag.history[idx];
            displayResult(Diag.lastResult);
        });
    });

    // Reexecutar
    list.querySelectorAll('.diag-hist-item__replay').forEach(btn => {
        btn.addEventListener('click', e => {
            e.stopPropagation();
            const idx = parseInt(btn.dataset.idx);
            const entry = Diag.history[idx];
            runTool(entry.tool, entry.target, entry.options);
        });
    });
}

/* ══════════════════════════════════════════════════════════
   9. DIAGNÓSTICO COMPLETO AUTOMÁTICO
══════════════════════════════════════════════════════════ */
async function runAutoCheck() {
    if (Diag.isRunning || Diag.autoRunning) return;
    Diag.autoRunning = true;

    const steps = [
        { id: 'gw', statusId: 'acGw', tool: 'ping', target: Diag.ctx.gateway, opts: { count: 4 } },
        { id: 'dns', statusId: 'acDns', tool: 'nslookup', target: 'google.com', opts: { server: 'dns1' } },
        { id: 'inet', statusId: 'acInet', tool: 'ping', target: '1.1.1.1', opts: { count: 4 } },
        { id: 'p443', statusId: 'acP443', tool: 'tcp_port_test', target: '8.8.8.8', opts: { port: 443 } },
        { id: 'trace', statusId: 'acTrace', tool: 'traceroute', target: '8.8.8.8', opts: { hops: 20 } },
    ];

    // Reset
    steps.forEach(s => {
        const el = document.getElementById(`ac${capitalize(s.id)}`);
        if (el) el.textContent = '—';
        const stepEl = document.querySelector(`.diag-ac-step[data-step="${s.id}"]`);
        if (stepEl) stepEl.className = 'diag-ac-step';
    });

    const autoResult = document.getElementById('autoResult');
    if (autoResult) autoResult.style.display = 'none';

    let failures = 0;

    for (const step of steps) {
        const stepEl = document.querySelector(`.diag-ac-step[data-step="${step.id}"]`);
        const statusEl = document.getElementById(step.statusId);

        if (stepEl) stepEl.classList.add('diag-ac-step--active');
        if (statusEl) statusEl.textContent = 'rodando…';

        const result = await executeToolMock(step.tool, step.target, step.opts);

        if (stepEl) {
            stepEl.classList.remove('diag-ac-step--active');
            stepEl.classList.add(result.ok ? 'diag-ac-step--done' : 'diag-ac-step--err');
        }
        if (statusEl) statusEl.textContent = result.status === 'ok' ? '✓ OK' : result.status === 'warn' ? '⚠ warn' : '✕ falha';

        if (!result.ok) failures++;

        // Se internet falhou, roda traceroute
        if (step.id === 'inet' && !result.ok) {
            // traceroute já está nos steps, será executado
        }
        // Se internet OK, pula traceroute
        if (step.id === 'p443' && result.ok) {
            const traceStep = document.querySelector('.diag-ac-step[data-step="trace"]');
            const traceStatus = document.getElementById('acTrace');
            if (traceStep) traceStep.classList.add('diag-ac-step--done');
            if (traceStatus) traceStatus.textContent = '— pulado';
            break;
        }
    }

    // Resultado final
    const autoResultEl = document.getElementById('autoResult');
    const autoResultText = document.getElementById('autoResultText');
    const autoResultIcon = document.getElementById('autoResultIcon');
    if (autoResultEl && autoResultText) {
        autoResultEl.style.display = 'flex';
        if (failures === 0) {
            autoResultEl.className = 'diag-autocheck__result diag-autocheck__result--ok';
            autoResultText.textContent = 'Rede funcionando corretamente';
            if (autoResultIcon) autoResultIcon.innerHTML = '<polyline points="20 6 9 17 4 12"/>';
        } else if (failures <= 2) {
            autoResultEl.className = 'diag-autocheck__result diag-autocheck__result--warn';
            autoResultText.textContent = `${failures} problema(s) detectado(s)`;
            if (autoResultIcon) autoResultIcon.innerHTML = '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/>';
            tryShowChamado('autocheck');
        } else {
            autoResultEl.className = 'diag-autocheck__result diag-autocheck__result--err';
            autoResultText.textContent = `${failures} falha(s) crítica(s) — checar rede`;
            if (autoResultIcon) autoResultIcon.innerHTML = '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>';
            tryShowChamado('autocheck');
        }
    }

    Diag.autoRunning = false;
    toast(failures === 0 ? 'ok' : 'err', failures === 0 ? 'Diagnóstico concluído: rede OK' : `Diagnóstico: ${failures} problema(s) detectado(s)`);
}

/* ══════════════════════════════════════════════════════════
   10. CHAMADO SUGERIDO
══════════════════════════════════════════════════════════ */
function tryShowChamado(tool) {
    const card = document.getElementById('chamadoCard');
    const desc = document.getElementById('chamadoDesc');
    if (!card || !desc) return;

    const msgs = {
        ping: 'Ping falhou para o destino. Pode indicar problema de roteamento ou host offline.',
        tcp_port_test: 'Porta fechada detectada. Pode ser bloqueio por firewall.',
        http_check: 'Serviço HTTP inacessível. Checar disponibilidade do servidor.',
        autocheck: 'Falhas detectadas no diagnóstico automático de rede.',
    };

    desc.textContent = msgs[tool] || 'Falha detectada — considere abrir um incidente.';
    card.style.display = '';

    /* BACK-END: ao clicar em "Criar Incidente", POST /incidentes/api/criar/ com os dados do resultado */
}

/* ══════════════════════════════════════════════════════════
   11. EXPORTAÇÃO
══════════════════════════════════════════════════════════ */
function exportTxt() {
    if (!Diag.lastResult) { toast('info', 'Nenhum resultado para exportar.'); return; }
    const { tool, target, result, ts } = Diag.lastResult;
    const content = [
        `MOONSHIELD — Diagnóstico de Rede`,
        `Exportado em: ${ts.toLocaleString('pt-BR')}`,
        `Host: ${Diag.ctx.hostname} (${Diag.ctx.ip_local})`,
        `─────────────────────────────────────────`,
        `Ferramenta: ${tool}`,
        `Alvo:       ${target}`,
        `Status:     ${result.status.toUpperCase()}`,
        `Duração:    ${result.meta.duration_ms}ms`,
        `─────────────────────────────────────────`,
        result.stdout,
        result.stderr ? `\nSTDERR:\n${result.stderr}` : '',
    ].join('\n');

    download(`moonshield-diag-${tool}-${Date.now()}.txt`, content, 'text/plain');
    toast('ok', 'TXT exportado!');
}

function exportJson() {
    if (!Diag.lastResult) { toast('info', 'Nenhum resultado para exportar.'); return; }
    download(
        `moonshield-diag-${Diag.lastResult.tool}-${Date.now()}.json`,
        JSON.stringify(Diag.lastResult, null, 2),
        'application/json'
    );
    toast('ok', 'JSON exportado!');
}

function download(filename, content, type) {
    const blob = new Blob([content], { type });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
}

/* ══════════════════════════════════════════════════════════
   12. TOAST
══════════════════════════════════════════════════════════ */
function toast(type, msg, duration = 3200) {
    const container = document.getElementById('diagToast');
    if (!container) return;
    const t = document.createElement('div');
    t.className = `diag-toast diag-toast--${type}`;
    const icons = { ok: '✓', err: '✕', info: '·' };
    t.innerHTML = `<span style="font-size:14px;flex-shrink:0">${icons[type] || '·'}</span><span>${msg}</span>`;
    container.appendChild(t);
    requestAnimationFrame(() => requestAnimationFrame(() => t.classList.add('visible')));
    setTimeout(() => {
        t.classList.add('hiding');
        t.addEventListener('transitionend', () => t.remove(), { once: true });
    }, duration);
}

/* ══════════════════════════════════════════════════════════
   13. UTILS
══════════════════════════════════════════════════════════ */
function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
}

function capitalize(s) {
    return s.charAt(0).toUpperCase() + s.slice(1);
}

function getCsrf() {
    const c = document.cookie.split(';').find(x => x.trim().startsWith('csrftoken='));
    return c ? c.split('=')[1] : '';
}

/* ══════════════════════════════════════════════════════════
   14. BIND DE EVENTOS
══════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', () => {

    loadContext();

    /* ── Testes rápidos ── */
    document.querySelectorAll('.diag-quick-card__btn').forEach(btn => {
        btn.addEventListener('click', e => {
            e.stopPropagation();
            const card = btn.closest('.diag-quick-card');
            if (!card) return;
            const cardId = card.id;
            const tool = card.dataset.tool;
            let target = card.dataset.target;

            // Resolver target dinâmico
            if (target === 'gateway') target = Diag.ctx.gateway;

            const optMap = {
                qcPingGw: { count: 4, timeout: 2 },
                qcInternet: { count: 4, timeout: 2 },
                qcDns: { server: 'dns1' },
                qcDnsLat: {},
                qcArp: {},
                qcRoutes: {},
            };

            runTool(tool, target, optMap[cardId] || {}, cardId);
        });
    });

    /* ── Botões guiados ── */
    document.querySelectorAll('.diag-run-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const tool = btn.dataset.tool;
            const form = btn.dataset.form;
            let target = '', opts = {};

            if (form === 'ping') { target = document.getElementById('pingTarget')?.value.trim(); opts = { count: document.getElementById('pingCount')?.value, timeout: document.getElementById('pingTimeout')?.value }; }
            if (form === 'trace') { target = document.getElementById('traceTarget')?.value.trim(); opts = { hops: document.getElementById('traceHops')?.value }; }
            if (form === 'ns') { target = document.getElementById('nsTarget')?.value.trim(); const sv = document.getElementById('nsServer')?.value; opts = { server: sv === 'custom' ? document.getElementById('nsCustomServer')?.value.trim() : sv }; }
            if (form === 'rev') { target = document.getElementById('revTarget')?.value.trim(); }
            if (form === 'cmp') { target = document.getElementById('cmpTarget')?.value.trim(); }
            if (form === 'port') { target = document.getElementById('portTarget')?.value.trim(); opts = { port: document.getElementById('portNumber')?.value }; }
            if (form === 'http') { target = document.getElementById('httpTarget')?.value.trim(); opts = { timeout: document.getElementById('httpTimeout')?.value }; }
            if (form === 'arpscan') { target = document.getElementById('arpScanTarget')?.value.trim() || Diag.ctx.cidr; }
            if (form === 'ipconfig') { target = Diag.ctx.hostname; opts = { mode: document.getElementById('ipconfigMode')?.value }; }
            if (form === 'netstat') { target = ''; opts = { filter: document.getElementById('netstatFilter')?.value, port: document.getElementById('netstatPort')?.value }; }
            if (form === 'ifaces') { target = ''; }

            runTool(tool, target, opts);
        });
    });

    /* ── Tabs de categoria ── */
    document.getElementById('guideTabs')?.addEventListener('click', e => {
        const tab = e.target.closest('.diag-guide-tab');
        if (!tab) return;
        document.querySelectorAll('.diag-guide-tab').forEach(t => t.classList.remove('diag-guide-tab--active'));
        tab.classList.add('diag-guide-tab--active');
        document.querySelectorAll('.diag-guide-panel').forEach(p => p.classList.remove('diag-guide-panel--active'));
        const panel = document.getElementById(`panel-${tab.dataset.tab}`);
        if (panel) panel.classList.add('diag-guide-panel--active');
    });

    /* ── Tabs do terminal ── */
    document.querySelectorAll('.diag-term-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            const ttab = tab.dataset.ttab;
            document.querySelectorAll('.diag-term-tab').forEach(t => t.classList.remove('diag-term-tab--active'));
            tab.classList.add('diag-term-tab--active');
            document.querySelectorAll('.diag-term-panel').forEach(p => p.classList.remove('diag-term-panel--active'));
            const panel = document.getElementById(`tpanel-${ttab}`);
            if (panel) panel.classList.add('diag-term-panel--active');
            Diag.activeTermTab = ttab;
        });
    });

    /* ── Terminal actions ── */
    document.getElementById('termCopyBtn')?.addEventListener('click', () => {
        const out = document.getElementById('termOutput')?.textContent;
        if (!out) return;
        navigator.clipboard.writeText(out).then(() => toast('ok', 'Copiado!'));
    });

    document.getElementById('termSaveBtn')?.addEventListener('click', () => {
        exportTxt();
    });

    document.getElementById('termClearBtn')?.addEventListener('click', () => {
        const termOutput = document.getElementById('termOutput');
        const termTitle = document.getElementById('termTitle');
        const termMeta = document.getElementById('termMeta');
        const termSummary = document.getElementById('termSummary');
        const suggEl = document.getElementById('termSuggestion');
        if (termOutput) termOutput.textContent = 'Terminal limpo.';
        if (termTitle) termTitle.textContent = 'Terminal · aguardando execução';
        if (termMeta) termMeta.style.display = 'none';
        if (termSummary) termSummary.style.display = 'none';
        if (suggEl) suggEl.style.display = 'none';
    });

    /* ── Custom DNS server ── */
    document.getElementById('nsServer')?.addEventListener('change', e => {
        const wrap = document.getElementById('nsCustomWrap');
        if (wrap) wrap.style.display = e.target.value === 'custom' ? '' : 'none';
    });

    /* ── Port presets ── */
    document.querySelectorAll('.diag-port-preset').forEach(btn => {
        btn.addEventListener('click', () => {
            const portInput = document.getElementById('portNumber');
            if (portInput) portInput.value = btn.dataset.port;
            document.querySelectorAll('.diag-port-preset').forEach(b => b.classList.remove('diag-port-preset--active'));
            btn.classList.add('diag-port-preset--active');
        });
    });

    /* ── Diagnóstico completo ── */
    document.getElementById('btnAutoCheck')?.addEventListener('click', runAutoCheck);
    document.getElementById('autoCheckRunBtn')?.addEventListener('click', runAutoCheck);

    /* ── Exportar ── */
    document.getElementById('btnExportTxt')?.addEventListener('click', exportTxt);
    document.getElementById('btnExportJson')?.addEventListener('click', exportJson);

    /* ── Limpar histórico ── */
    document.getElementById('clearHistoryBtn')?.addEventListener('click', () => {
        Diag.history = [];
        renderHistory();
        toast('info', 'Histórico limpo');
    });

    /* ── Refresh contexto ── */
    document.getElementById('ctxRefreshBtn')?.addEventListener('click', () => {
        const icon = document.getElementById('ctxRefreshIcon');
        const btn = document.getElementById('ctxRefreshBtn');
        if (icon) icon.style.animation = 'spin .7s linear infinite';
        if (btn) btn.disabled = true;
        setTimeout(() => {
            if (icon) icon.style.animation = '';
            if (btn) btn.disabled = false;
            loadContext();
            toast('ok', 'Contexto atualizado');
            /* BACK-END: fetch('/diagnostico/api/contexto/').then(r=>r.json()).then(d=>{ Diag.ctx=d; loadContext(); }); */
        }, 900);
    });

    /* ── Chamado ── */
    document.getElementById('chamadoBtn')?.addEventListener('click', () => {
        toast('info', 'Redirecionando para Incidentes…');
        /* BACK-END: window.location.href = '/incidentes/novo/?source=diagnostico'; */
        setTimeout(() => { /* window.location.href = '/incidentes/novo/'; */ }, 800);
    });

    /* Animação de entrada */
    document.querySelectorAll('.diag-quick-card').forEach((card, i) => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(8px)';
        card.style.transition = `opacity .3s ease ${i * 50}ms, transform .3s ease ${i * 50}ms`;
        requestAnimationFrame(() => requestAnimationFrame(() => {
            card.style.opacity = '1';
            card.style.transform = 'none';
        }));
    });
});