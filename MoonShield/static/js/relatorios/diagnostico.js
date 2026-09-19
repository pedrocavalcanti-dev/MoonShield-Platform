
'use strict';

const Diag = {
    ctx: {},
    lastResult: null,
    history: [],
    isRunning: false,
    activeTermTab: 'saida',
};

function getCsrf() {
    const c = document.cookie.split(';').find(x => x.trim().startsWith('csrftoken='));
    return c ? c.split('=')[1] : '';
}

async function fetchJSON(url, options = {}) {
    if (!options.headers) options.headers = {};
    options.headers['X-CSRFToken'] = getCsrf();
    options.headers['Content-Type'] = 'application/json';
    
    const res = await fetch(url, options);
    let data;
    try {
        data = await res.json();
    } catch(e) {
        throw new Error('Falha ao processar resposta do servidor.');
    }
    
    if (!res.ok) {
        throw new Error(data.summary || data.error_code || 'Erro na requisição');
    }
    return data;
}

function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text || '—';
}

async function loadContext() {
    try {
        const data = await fetchJSON('/relatorios/diagnostico/api/contexto/');
        Diag.ctx = data;
        
        setText('ctxIface', data.wan_iface);
        setText('ctxCidr', data.wan_cidr);
        setText('ctxGateway', data.gateway);
        setText('ctxDns1', data.dns1);
        setText('ctxDns2', data.dns2);
        setText('ctxHost', `${data.hostname} — ${data.ip_local}`);
        
        const badge = document.getElementById('agentStatusBadge');
        const lbl = document.getElementById('agentStatusLabel');
        if (badge && lbl) {
            if (data.agent === 'online') {
                badge.className = 'agent-status-badge agent-status-badge--online';
                lbl.textContent = 'Agent Online';
            } else {
                badge.className = 'agent-status-badge agent-status-badge--offline';
                lbl.textContent = 'Agent Offline';
            }
        }
        
        setText('qtPingGw', data.gateway);
        
        const nsServer = document.getElementById('nsServer');
        if (nsServer && nsServer.options.length >= 2) {
            nsServer.options[0].text = `DNS 1 — ${data.dns1 || 'N/A'}`;
            nsServer.options[1].text = `DNS 2 — ${data.dns2 || 'N/A'}`;
        }
    } catch(e) {
        toast('err', 'Erro ao carregar contexto: ' + e.message);
    }
}

async function loadHistory() {
    try {
        const data = await fetchJSON('/relatorios/diagnostico/api/historico/');
        Diag.history = data.items || [];
        renderHistory();
    } catch(e) {
        console.error('Falha ao carregar historico', e);
    }
}

function renderHistory() {
    const list = document.getElementById('historyList');
    if (!list) return;
    list.innerHTML = '';
    
    if (Diag.history.length === 0) {
        list.innerHTML = '<div class="diag-history__empty">Nenhum teste executado ainda</div>';
        return;
    }
    
    Diag.history.forEach(entry => {
        const ts = new Date(entry.created_at);
        const item = document.createElement('div');
        item.className = 'diag-history__item';
        
        let icon = '';
        if (entry.status === 'ok') icon = '<svg width="12" height="12" style="color:var(--teal-400)"><circle cx="12" cy="12" r="10"/></svg>';
        else if (entry.status === 'warn') icon = '<svg width="12" height="12" style="color:var(--amber-400)"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>';
        else icon = '<svg width="12" height="12" style="color:var(--rose-400)"><circle cx="12" cy="12" r="10"/></svg>';
        
        item.innerHTML = `
            ${icon}
            <div class="diag-history__info">
                <span class="diag-history__tool">${entry.tool} ${entry.target ? '→ '+entry.target : ''}</span>
                <span class="diag-history__ts">${ts.toLocaleTimeString('pt-BR')} — ${entry.duration_ms}ms</span>
            </div>
        `;
        
        item.addEventListener('click', () => fetchExecutionDetail(entry.id));
        list.appendChild(item);
    });
}

async function fetchExecutionDetail(id) {
    if (Diag.isRunning) { toast('info', 'Aguarde a execução atual terminar.'); return; }
    startExecUI('Carregando', id, null);
    try {
        const data = await fetchJSON(`/relatorios/diagnostico/api/execucao/${id}/`);
        Diag.lastResult = {
            tool: data.tool,
            target: data.target,
            options: data.options,
            result: data,
            ts: new Date(data.created_at)
        };
        displayResult(Diag.lastResult);
    } catch(e) {
        displayError(e.message);
    } finally {
        Diag.isRunning = false;
        stopExecUI(null);
    }
}

async function runTool(tool, target, options = {}, source = 'guided', sourceCard = null) {
    if (Diag.isRunning) { toast('info', 'Aguarde a execução atual terminar.'); return; }
    
    const targetless = ['routes', 'interfaces', 'arp_table', 'sockets'];
    if (!target && !targetless.includes(tool)) {
        toast('err', 'Informe um alvo antes de executar.'); return;
    }

    Diag.isRunning = true;
    startExecUI(tool, target, sourceCard);

    try {
        const data = await fetchJSON('/relatorios/diagnostico/api/executar/', {
            method: 'POST',
            body: JSON.stringify({ tool, target, options, source })
        });
        
        Diag.lastResult = {
            tool,
            target,
            options,
            result: data,
            ts: new Date()
        };
        displayResult(Diag.lastResult);
        loadHistory();
        
        if (sourceCard && typeof updateQuickCardStatus === 'function') {
            updateQuickCardStatus(sourceCard, data.status, data.meta?.duration_ms);
        }
        
    } catch (e) {
        displayError(e.message);
    } finally {
        Diag.isRunning = false;
        stopExecUI(sourceCard);
    }
}

function startExecUI(tool, target, cardId) {
    const execBar = document.getElementById('execBar');
    const execLabel = document.getElementById('execBarLabel');
    const termOutput = document.getElementById('termOutput');
    const termStruct = document.getElementById('termStructured');
    const termTitle = document.getElementById('termTitle');
    
    if (termTitle) termTitle.textContent = `${tool} → ${target || 'localhost'} — executando...`;
    if (termOutput) termOutput.textContent = `Executando ${tool}...`;
    if (termStruct) { termStruct.style.display = 'none'; termStruct.innerHTML = ''; }
    
    document.getElementById('termMeta').style.display = 'none';
    document.getElementById('termSummary').style.display = 'none';
    
    if (execBar) {
        execBar.style.display = 'flex';
        execBar.classList.add('diag-exec-bar--indet');
    }
    if (execLabel) execLabel.textContent = `Executando ${tool}...`;
    
    if (cardId) {
        const card = document.getElementById(cardId);
        const btn = card?.querySelector('.diag-quick-card__btn');
        if (btn) { btn.textContent = 'Rodando...'; btn.classList.add('diag-quick-card__btn--running'); }
    }
    
    document.querySelectorAll('.diag-run-btn').forEach(b => b.classList.add('diag-run-btn--running'));
    document.querySelectorAll('.diag-quick-card__btn').forEach(b => { b.disabled = true; });
}

function stopExecUI(cardId) {
    const execBar = document.getElementById('execBar');
    if (execBar) {
        execBar.classList.remove('diag-exec-bar--indet');
        execBar.style.display = 'none';
    }
    if (cardId) {
        const card = document.getElementById(cardId);
        const btn = card?.querySelector('.diag-quick-card__btn');
        if (btn) { btn.textContent = 'Executar'; btn.classList.remove('diag-quick-card__btn--running'); btn.disabled = false; }
    }
    document.querySelectorAll('.diag-run-btn').forEach(b => b.classList.remove('diag-run-btn--running'));
    document.querySelectorAll('.diag-quick-card__btn').forEach(b => { b.disabled = false; });
}

function displayError(msg) {
    const termOutput = document.getElementById('termOutput');
    const termMeta = document.getElementById('termMeta');
    const termTitle = document.getElementById('termTitle');
    
    if (termTitle) termTitle.textContent = 'Falha na execução';
    if (termOutput) termOutput.textContent = 'Erro: ' + msg;
    if (termMeta) termMeta.style.display = 'flex';
    
    setText('metaStatus', 'ERR');
    document.getElementById('metaStatus')?.classList.add('diag-term-status--err');
}

function escapeHTML(str) {
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function renderStructuredOutput(tool, structured) {
    if (!structured) return '';
    let html = '';
    
    if (tool === 'mtr' && structured.hops && structured.hops.length > 0) {
        html += '<table class="diag-table"><thead><tr><th>#</th><th>Host/IP</th><th>Loss %</th><th>Avg</th><th>Best</th><th>Worst</th></tr></thead><tbody>';
        structured.hops.forEach(h => {
            const lossCls = h.loss_percent > 20 ? 'loss-high' : (h.loss_percent > 0 ? 'loss-mid' : '');
            const msCls = h.avg_ms > 150 ? 'ms-high' : '';
            html += `<tr>
                <td>${escapeHTML(h.hop)}</td>
                <td>${escapeHTML(h.host || h.ip)}</td>
                <td class="${lossCls}">${escapeHTML(h.loss_percent)}%</td>
                <td class="${msCls}">${escapeHTML(h.avg_ms)}</td>
                <td>${escapeHTML(h.best_ms)}</td>
                <td>${escapeHTML(h.worst_ms)}</td>
            </tr>`;
        });
        html += '</tbody></table>';
    } 
    else if (tool === 'routes' && structured.routes) {
        html += '<table class="diag-table"><thead><tr><th>Destino</th><th>Gateway</th><th>Dev</th><th>Metric</th><th>Protocol</th></tr></thead><tbody>';
        structured.routes.forEach(r => {
            html += `<tr>
                <td>${escapeHTML(r.dst)}</td>
                <td>${escapeHTML(r.gateway || '-')}</td>
                <td>${escapeHTML(r.dev || '-')}</td>
                <td>${escapeHTML(r.metric || '-')}</td>
                <td>${escapeHTML(r.protocol || '-')}</td>
            </tr>`;
        });
        html += '</tbody></table>';
    }
    else if (tool === 'interfaces' && structured.interfaces) {
        html += '<table class="diag-table"><thead><tr><th>Interface</th><th>State</th><th>MTU</th><th>Address</th></tr></thead><tbody>';
        structured.interfaces.forEach(i => {
            const stCls = i.operstate === 'UP' ? 'loss-mid' : (i.operstate === 'DOWN' ? 'loss-high' : '');
            let addrs = (i.addresses || []).join(', ');
            html += `<tr>
                <td>${escapeHTML(i.ifname)}</td>
                <td class="${stCls}">${escapeHTML(i.operstate)}</td>
                <td>${escapeHTML(i.mtu)}</td>
                <td>${escapeHTML(addrs)}</td>
            </tr>`;
        });
        html += '</tbody></table>';
    }
    else if (tool === 'arp_table' && structured.arp) {
        html += '<table class="diag-table"><thead><tr><th>Destino</th><th>Interface</th><th>MAC Address</th><th>State</th></tr></thead><tbody>';
        structured.arp.forEach(a => {
            html += `<tr>
                <td>${escapeHTML(a.dst)}</td>
                <td>${escapeHTML(a.dev)}</td>
                <td>${escapeHTML(a.lladdr)}</td>
                <td>${escapeHTML(a.state)}</td>
            </tr>`;
        });
        html += '</tbody></table>';
    }
    else if (tool === 'ping' && structured.loss_percent !== undefined) {
        html += '<table class="diag-table"><thead><tr><th>Sent</th><th>Recv</th><th>Loss</th><th>Min (ms)</th><th>Avg (ms)</th><th>Max (ms)</th></tr></thead><tbody>';
        const lossCls = structured.loss_percent > 20 ? 'loss-high' : '';
        html += `<tr>
            <td>${escapeHTML(structured.sent)}</td>
            <td>${escapeHTML(structured.received)}</td>
            <td class="${lossCls}">${escapeHTML(structured.loss_percent)}%</td>
            <td>${escapeHTML(structured.min_ms)}</td>
            <td>${escapeHTML(structured.avg_ms)}</td>
            <td>${escapeHTML(structured.max_ms)}</td>
        </tr>`;
        html += '</tbody></table>';
    }
    
    return html;
}

function displayResult(entry) {
    const { tool, target, result, ts } = entry;
    
    const termOutput = document.getElementById('termOutput');
    const termStruct = document.getElementById('termStructured');
    const termTitle = document.getElementById('termTitle');
    const termMeta = document.getElementById('termMeta');
    const termSummary = document.getElementById('termSummary');
    const termJson = document.getElementById('termJson');
    
    setText('metaTool', tool);
    setText('metaTarget', target || 'localhost');
    setText('metaTime', ts.toLocaleTimeString('pt-BR'));
    
    const metaStatus = document.getElementById('metaStatus');
    if (metaStatus) {
        metaStatus.textContent = result.status.toUpperCase();
        metaStatus.className = `diag-term-status diag-term-status--${result.status}`;
    }
    
    termMeta.style.display = 'flex';
    termTitle.textContent = `${tool} → ${target || 'localhost'} — ${ts.toLocaleTimeString('pt-BR')}`;
    
    termOutput.textContent = (result.stdout || '') + (result.stderr ? `\n\n[STDERR]\n${result.stderr}` : '');
    
    if (termStruct) {
        const html = renderStructuredOutput(tool, result.structured);
        if (html) {
            termStruct.innerHTML = html;
            termStruct.style.display = 'block';
        } else {
            termStruct.style.display = 'none';
        }
    }
    
    if (termSummary) {
        termSummary.style.display = 'flex';
        termSummary.className = `diag-term-summary diag-term-summary--${result.status}`;
        setText('termSummaryText', result.summary);
    }
    
    setText('detDuration', `${result.duration_ms || result.meta?.duration_ms || 0}ms`);
    setText('detExitCode', String(result.exit_code !== undefined ? result.exit_code : (result.meta?.exit_code || 0)));
    setText('detTool', tool);
    setText('detTarget', target || '—');
    setText('detOutputSize', `${(termOutput.textContent.length / 1024).toFixed(2)} KB`);
    setText('detTimestamp', ts.toLocaleString('pt-BR'));
    
    if (termJson) {
        termJson.textContent = JSON.stringify(result, null, 2);
    }
}

function handleTerminalCommand(cmdRaw) {
    const cmdStr = cmdRaw.trim();
    if (!cmdStr) return;
    
    const parts = cmdStr.split(/\s+/);
    const cmd = parts[0].toLowerCase();
    const args = parts.slice(1);
    
    if (cmd === 'clear') {
        document.getElementById('termOutput').textContent = 'Terminal limpo.';
        document.getElementById('termStructured').style.display = 'none';
        document.getElementById('termMeta').style.display = 'none';
        document.getElementById('termSummary').style.display = 'none';
        return;
    }
    if (cmd === 'history') {
        document.getElementById('termOutput').textContent = Diag.history.slice(0, 10).map((h, i) => `[${i+1}] ${new Date(h.created_at).toLocaleTimeString()} | ${h.tool} ${h.target || '-'} | ${h.status}`).join('\n') || 'Nenhum historico.';
        document.getElementById('termStructured').style.display = 'none';
        return;
    }
    if (cmd === 'help') {
        document.getElementById('termOutput').textContent = `Comandos suportados:
ping <host>       trace <host>        mtr <host>
dns <domain>      rdns <ip>           tcp <host> <port>
http <url>        routes              arp
ifaces            sockets             history
clear`;
        document.getElementById('termStructured').style.display = 'none';
        return;
    }
    
    const map = {
        'ping': { tool: 'ping', req: true },
        'trace': { tool: 'traceroute', req: true },
        'mtr': { tool: 'mtr', req: true },
        'dns': { tool: 'dns_lookup', req: true },
        'rdns': { tool: 'reverse_dns', req: true },
        'tcp': { tool: 'tcp_connect', req: true, opt: 'port' },
        'http': { tool: 'http_check', req: true },
        'routes': { tool: 'routes', req: false },
        'arp': { tool: 'arp_table', req: false },
        'ifaces': { tool: 'interfaces', req: false },
        'sockets': { tool: 'sockets', req: false }
    };
    
    const mapped = map[cmd];
    if (!mapped) {
        toast('err', 'Comando desconhecido. Digite help.');
        return;
    }
    
    if (mapped.req && args.length === 0) {
        toast('err', `O comando ${cmd} exige um alvo.`);
        return;
    }
    
    let target = args[0] || '';
    let opts = {};
    if (mapped.opt === 'port' && args.length > 1) {
        opts.port = args[1];
    }
    
    runTool(mapped.tool, target, opts, 'terminal', null);
}

function toast(type, msg, duration = 3200) {
    const container = document.getElementById('diagToast');
    if (!container) return;
    const t = document.createElement('div');
    t.className = `diag-toast diag-toast--${type}`;
    const icons = { ok: '✓', err: '!', info: 'i' };
    t.innerHTML = `<span style="font-size:14px;flex-shrink:0">${icons[type] || ''}</span><span>${escapeHTML(msg)}</span>`;
    container.appendChild(t);
    requestAnimationFrame(() => requestAnimationFrame(() => t.classList.add('visible')));
    setTimeout(() => {
        t.classList.add('hiding');
        t.addEventListener('transitionend', () => t.remove(), { once: true });
    }, duration);
}

function exportTxt() {
    if (!Diag.lastResult) { toast('info', 'Nenhum resultado para exportar.'); return; }
    const { tool, target, result, ts } = Diag.lastResult;
    const content = [
        `MOONSHIELD — Diagnostico de Rede`,
        `Exportado em: ${ts.toLocaleString('pt-BR')}`,
        `Host: ${Diag.ctx.hostname || '—'} (${Diag.ctx.ip_local || '—'})`,
        `=====================================================`,
        `Ferramenta: ${tool}`,
        `Alvo:       ${target || '—'}`,
        `Status:     ${(result.status || '').toUpperCase()}`,
        `Duracao:    ${result.duration_ms || result.meta?.duration_ms || 0}ms`,
        `=====================================================`,
        result.stdout || '',
        result.stderr ? `\nSTDERR:\n${result.stderr}` : '',
    ].join('\n');

    download(`moonshield-diag-${tool}-${Date.now()}.txt`, content, 'text/plain');
    toast('ok', 'TXT exportado!');
}

function exportJson() {
    if (!Diag.lastResult) { toast('info', 'Nenhum resultado para exportar.'); return; }
    download(
        `moonshield-diag-${Diag.lastResult.tool}-${Date.now()}.json`,
        JSON.stringify(Diag.lastResult.result, null, 2),
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

document.addEventListener('DOMContentLoaded', () => {
    loadContext();
    loadHistory();

    /* Quick Cards */
    document.querySelectorAll('.diag-quick-card__btn').forEach(btn => {
        btn.addEventListener('click', e => {
            e.stopPropagation();
            const card = btn.closest('.diag-quick-card');
            if (!card) return;
            const tool = card.dataset.tool;
            let target = card.dataset.target;
            if (target === 'gateway') target = Diag.ctx.gateway;
            
            let opts = {};
            if (tool === 'ping') opts = { count: 4, timeout: 2 };
            if (tool === 'dns_lookup') opts = { server: Diag.ctx.dns1 || '8.8.8.8' };

            runTool(tool, target, opts, 'quick', card.id);
        });
    });

    /* Guided Tools */
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
            if (form === 'arpscan') { target = document.getElementById('arpScanTarget')?.value.trim() || Diag.ctx.wan_cidr; }
            if (form === 'ipconfig') { target = Diag.ctx.hostname; opts = { mode: document.getElementById('ipconfigMode')?.value }; }
            if (form === 'netstat') { target = ''; opts = { filter: document.getElementById('netstatFilter')?.value, port: document.getElementById('netstatPort')?.value }; }
            if (form === 'ifaces') { target = ''; }

            runTool(tool, target, opts, 'guided', null);
        });
    });

    /* Tabs */
    document.getElementById('guideTabs')?.addEventListener('click', e => {
        const tab = e.target.closest('.diag-guide-tab');
        if (!tab) return;
        document.querySelectorAll('.diag-guide-tab').forEach(t => t.classList.remove('diag-guide-tab--active'));
        tab.classList.add('diag-guide-tab--active');
        document.querySelectorAll('.diag-guide-panel').forEach(p => p.classList.remove('diag-guide-panel--active'));
        const panel = document.getElementById(`panel-${tab.dataset.tab}`);
        if (panel) panel.classList.add('diag-guide-panel--active');
    });

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

    /* Terminal Input */
    const cliInput = document.getElementById('termCliInput');
    if (cliInput) {
        cliInput.addEventListener('keydown', e => {
            if (e.key === 'Enter') {
                const cmd = cliInput.value;
                cliInput.value = '';
                handleTerminalCommand(cmd);
            }
        });
    }

    /* Actions */
    document.getElementById('termCopyBtn')?.addEventListener('click', () => {
        const out = document.getElementById('termOutput')?.textContent;
        if (!out) return;
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(out).then(() => toast('ok', 'Copiado!'));
        } else {
            const ta = document.createElement('textarea');
            ta.value = out;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
            toast('ok', 'Copiado (Fallback)!');
        }
    });

    document.getElementById('termSaveBtn')?.addEventListener('click', exportTxt);
    document.getElementById('btnExportTxt')?.addEventListener('click', exportTxt);
    document.getElementById('btnExportJson')?.addEventListener('click', exportJson);
    
    document.getElementById('termClearBtn')?.addEventListener('click', () => {
        document.getElementById('termOutput').textContent = 'Terminal limpo.';
        document.getElementById('termStructured').style.display = 'none';
        document.getElementById('termMeta').style.display = 'none';
        document.getElementById('termSummary').style.display = 'none';
    });

    document.getElementById('clearHistoryBtn')?.addEventListener('click', () => {
        Diag.history = [];
        renderHistory();
        toast('info', 'Historico visual limpo');
    });

    document.getElementById('ctxRefreshBtn')?.addEventListener('click', () => {
        const icon = document.getElementById('ctxRefreshIcon');
        if (icon) icon.style.animation = 'spin .7s linear infinite';
        loadContext().then(() => {
            if (icon) icon.style.animation = '';
            toast('ok', 'Contexto atualizado');
        });
    });

    /* Custom DNS server toggle */
    document.getElementById('nsServer')?.addEventListener('change', e => {
        const wrap = document.getElementById('nsCustomWrap');
        if (wrap) wrap.style.display = e.target.value === 'custom' ? '' : 'none';
    });

    /* Port presets */
    document.querySelectorAll('.diag-port-preset').forEach(btn => {
        btn.addEventListener('click', () => {
            const portInput = document.getElementById('portNumber');
            if (portInput) portInput.value = btn.dataset.port;
            document.querySelectorAll('.diag-port-preset').forEach(b => b.classList.remove('diag-port-preset--active'));
            btn.classList.add('diag-port-preset--active');
        });
    });

    /* AutoCheck disable for now */
    document.getElementById('autoCheckRunBtn')?.addEventListener('click', () => {
        toast('info', 'Diagnostico Automático será implementado na Etapa 3.');
    });
});
