'use strict';

const Diag = { ctx: {}, lastResult: null, history: [], isRunning: false, activeTermTab: 'saida', selectedId: null };
const TOOL_LABELS = {
    ping: 'Ping', traceroute: 'Traceroute', mtr: 'MTR', dns_lookup: 'DNS Lookup',
    reverse_dns: 'Reverse DNS', dns_latency: 'Latência DNS', tcp_connect: 'TCP',
    http_check: 'HTTP', arp_table: 'ARP', routes: 'Rotas', interfaces: 'Interfaces', sockets: 'Sockets'
};
const TARGETLESS = new Set(['routes', 'interfaces', 'arp_table', 'sockets']);
const $ = id => document.getElementById(id);
const value = id => $(id)?.value.trim() || '';
const scope = (tool, target) => TARGETLESS.has(tool) ? 'Sistema local' : (target || '—');
const statusClass = status => ['ok', 'warn', 'err'].includes(status) ? status : 'unknown';
const duration = ms => ms == null ? '—' : (ms < 1000 ? ms + ' ms' : (ms / 1000).toFixed(1) + ' s');
const elapsed = result => result.duration_ms ?? result.meta?.duration_ms;
const escapeHTML = value => String(value ?? '—').replace(/[&<>"']/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}[char]));
function setText(id, text) { if ($(id)) $(id).textContent = text == null || text === '' ? '—' : text; }
function api(name) { return $('diagPage').dataset[name + 'Url']; }

async function fetchJSON(url, options = {}) {
    const csrf = document.cookie.split(';').find(item => item.trim().startsWith('csrftoken='));
    const res = await fetch(url, {
        ...options,
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf ? csrf.split('=')[1] : '', ...options.headers }
    });
    let data;
    try { data = await res.json(); }
    catch { throw new Error('Resposta inválida do servidor (HTTP ' + res.status + ').'); }
    if (!res.ok) {
        const error = new Error(data.summary || data.error_code || 'Erro HTTP ' + res.status);
        error.data = data;
        throw error;
    }
    return data;
}

function quickUnavailable(card) {
    if (card.dataset.target === 'gateway' && !Diag.ctx.gateway) return 'Gateway não identificado';
    return '';
}
function syncButtons() {
    document.querySelectorAll('.diag-run-btn, .diag-quick-card__btn').forEach(btn => {
        // O botão de STOP Live é governado exclusivamente pelo estado Live.
        // Não pode ser desabilitado pelo lock global de execuções.
        if (btn.id === 'routeLiveStopBtn') return;
        const card = btn.closest('.diag-quick-card');
        const reason = card ? quickUnavailable(card) : '';
        btn.disabled = Diag.isRunning || Boolean(reason);
        btn.title = reason;
    });
}
async function loadContext() {
    try {
        const data = await fetchJSON(api('context'));
        Diag.ctx = data;
        setText('ctxIface', data.wan_iface ? 'WAN · ' + data.wan_iface : null);
        setText('ctxCidr', data.wan_cidr);
        setText('ctxGateway', data.gateway);
        const dns = [...new Set([data.dns1, data.dns2].filter(Boolean))].join(' / ');
        setText('ctxDns1', dns);
        setText('ctxHost', [...new Set([data.hostname, data.ip_local].filter(Boolean))].join(' / '));
        $('ctxLanWrap').hidden = !data.lan_iface && !data.lan_cidr;
        setText('ctxLan', [data.lan_iface, data.lan_cidr].filter(Boolean).join(' · '));
        $('agentStatusBadge').className = 'agent-status-badge agent-status-badge--' + (data.agent === 'online' ? 'online' : 'offline');
        setText('agentStatusLabel', data.agent === 'online' ? 'Agent Online' : 'Agent Offline');
        setText('qtPingGw', data.gateway || 'Gateway não identificado');
        const dnsLabel = dns ? 'DNS: ' + dns : 'Resolver do sistema';
        setText('qtDns', 'google.com · ' + dnsLabel);
        setText('qtDnsLat', 'google.com · ' + dnsLabel);
        return true;
    } catch (error) {
        Diag.ctx = {};
        ['ctxIface', 'ctxCidr', 'ctxGateway', 'ctxDns1', 'ctxHost'].forEach(id => setText(id, null));
        $('ctxLanWrap').hidden = true;
        setText('qtPingGw', 'Gateway não identificado');
        ['qtDns', 'qtDnsLat'].forEach(id => setText(id, 'google.com · Resolver do sistema'));
        $('agentStatusBadge').className = 'agent-status-badge';
        setText('agentStatusLabel', 'Agent · estado indisponível');
        toast('err', 'Erro ao carregar contexto: ' + error.message);
        return false;
    } finally { syncButtons(); }
}

async function loadHistory() {
    try {
        const data = await fetchJSON(api('history'));
        Diag.history = data.items || [];
        renderHistory();
    } catch (error) { toast('err', 'Histórico indisponível: ' + error.message); }
}
function renderHistory() {
    const list = $('historyList');
    list.replaceChildren();
    if (!Diag.history.length) {
        const empty = document.createElement('p');
        empty.className = 'diag-history__empty';
        empty.textContent = 'Nenhuma execução na lista.';
        list.append(empty);
    }
    Diag.history.forEach(entry => {
        const item = document.createElement('button');
        item.type = 'button';
        item.className = 'diag-hist-item' + (entry.id === Diag.selectedId ? ' diag-hist-item--selected' : '');
        item.setAttribute('aria-pressed', String(entry.id === Diag.selectedId));
        item.innerHTML = '<span class="diag-hist-item__dot diag-hist-item__dot--' + statusClass(entry.status) + '"></span>' +
            '<span class="diag-hist-item__body"><span class="diag-hist-item__tool">' + escapeHTML(TOOL_LABELS[entry.tool] || entry.tool) +
            '</span><span class="diag-hist-item__target">' + escapeHTML(scope(entry.tool, entry.target)) +
            '</span><span class="diag-hist-item__time"><span>' + escapeHTML(new Date(entry.created_at).toLocaleTimeString('pt-BR')) +
            '</span><span>' + escapeHTML(duration(entry.duration_ms)) + ' · ' + escapeHTML((entry.status || '—').toUpperCase()) + '</span></span></span>';
        item.addEventListener('click', () => fetchExecutionDetail(entry.id));
        list.append(item);
    });
}
async function fetchExecutionDetail(id) {
    if (Diag.isRunning) return;
    startExecUI('Carregando execução', null);
    try {
        const result = await fetchJSON(api('detail').replace('00000000-0000-0000-0000-000000000000', encodeURIComponent(id)));
        const source = Diag.history.find(entry => entry.id === id)?.source;
        displayResult({ tool: result.tool, target: result.target, result, source, ts: new Date(result.created_at) });
    } catch (error) { displayError(error); }
    finally { stopExecUI(); }
}
function clearResult() {
    Diag.lastResult = null;
    Diag.selectedId = null;
    $('termStructured').replaceChildren();
    $('termStructured').hidden = true;
    $('termStructured').style.display = 'none';
    $('termOutput').hidden = false;
    setText('termOutput', 'Nenhuma execução selecionada.');
    setText('termTitle', 'Resultado · aguardando execução');
    setText('termJson', '');
    ['termMeta', 'termSummary', 'detStderr'].forEach(id => $(id).style.display = 'none');
    document.querySelectorAll('.diag-detail-item__val').forEach(el => el.textContent = '—');
    renderHistory();
}
function selectResultTab(name) {
    Diag.activeTermTab = name;
    document.querySelectorAll('.diag-term-tab').forEach(tab => {
        const active = tab.dataset.ttab === name;
        tab.classList.toggle('diag-term-tab--active', active);
        tab.setAttribute('aria-selected', String(active));
        tab.tabIndex = active ? 0 : -1;
    });
    document.querySelectorAll('.diag-term-panel').forEach(panel => {
        const active = panel.id === 'tpanel-' + name;
        panel.hidden = !active;
        panel.classList.toggle('diag-term-panel--active', active);
    });
}
function startExecUI(title, button) {
    Diag.isRunning = true;
    clearResult();
    selectResultTab('saida');
    setText('termTitle', title);
    setText('termOutput', 'Executando…');
    setText('execBarLabel', title);
    $('execBar').style.display = 'flex';
    $('terminalSection').setAttribute('aria-busy', 'true');
    Diag.runningButton = button;
    if (button) {
        Diag.buttonContent = button.innerHTML;
        button.textContent = 'Executando…';
        button.classList.add('diag-button--running');
    }
    syncButtons();
}
function stopExecUI() {
    Diag.isRunning = false;
    $('execBar').style.display = 'none';
    $('terminalSection').setAttribute('aria-busy', 'false');
    if (Diag.runningButton) {
        Diag.runningButton.innerHTML = Diag.buttonContent;
        Diag.runningButton.classList.remove('diag-button--running');
    }
    Diag.runningButton = null;
    syncButtons();
}
function displayError(error) {
    clearResult();
    selectResultTab('saida');
    setText('termTitle', 'Não foi possível concluir o teste');
    setText('termOutput', error.message || String(error));
    setText('detStatus', 'ERR');
    setText('detStderrContent', error.message || String(error));
    $('detStderr').style.display = 'block';
    if (error.data) setText('termJson', JSON.stringify(error.data, null, 2));
}
async function runTool(tool, target, options = {}, source = 'guided', button = null) {
    if (Diag.isRunning) { toast('info', 'Aguarde a execução atual terminar.'); return; }
    target = TARGETLESS.has(tool) ? '' : String(target || '').trim();
    let invalid = '';
    if (!Object.hasOwn(TOOL_LABELS, tool)) invalid = 'Ferramenta não permitida.';
    else if (!TARGETLESS.has(tool) && !target) invalid = 'Informe um destino antes de executar.';
    else if (target.length > 255) invalid = 'Destino excedeu o limite de 255 caracteres.';
    else if (tool === 'tcp_connect' && (!Number.isInteger(Number(options.port)) || Number(options.port) < 1 || Number(options.port) > 65535)) invalid = 'Informe uma porta entre 1 e 65535.';
    if (invalid) { displayError(new Error(invalid)); if (source === 'terminal') consoleLine(invalid); return; }
    startExecUI((TOOL_LABELS[tool] || tool) + ' → ' + scope(tool, target), button);
    const entry = { tool, target, source, ts: new Date(), result: null };
    try {
        entry.result = await fetchJSON(api('execute'), { method: 'POST', body: JSON.stringify({ tool, target, options, source }) });
        displayResult(entry);
    } catch (error) {
        // Preserve real HTTP error payloads, including persisted 503/504 executions.
        if (error.data) { entry.result = error.data; displayResult(entry); }
        else displayError(error);
        if (source === 'terminal' && !entry.result) consoleLine(error.message);
    } finally {
        if (entry.result) {
            const card = button?.closest('.diag-quick-card');
            if (card) {
                const status = card.querySelector('.diag-quick-card__status');
                status.textContent = (entry.result.status || 'err').toUpperCase();
                status.dataset.status = statusClass(entry.result.status);
                card.querySelector('.diag-quick-card__time').textContent = duration(elapsed(entry.result));
            }
        }
        stopExecUI();
        await loadHistory();
    }
}

function table(headers, rows) {
    if (!rows.length) return '<p class="diag-empty">Nenhum registro retornado.</p>';
    return '<div class="diag-table-scroll"><table class="diag-table"><thead><tr>' +
        headers.map(header => '<th scope="col">' + escapeHTML(header) + '</th>').join('') +
        '</tr></thead><tbody>' + rows.map(row => '<tr>' + row.map(cell => '<td>' + escapeHTML(cell) + '</td>').join('') + '</tr>').join('') +
        '</tbody></table></div>';
}
function metrics(items) {
    return '<dl class="diag-metrics">' + items.map(([label, val]) => '<div><dt>' + escapeHTML(label) + '</dt><dd>' + escapeHTML(val) + '</dd></div>').join('') + '</dl>';
}
function unit(val, suffix) { return val == null ? '—' : val + suffix; }
function renderStructuredOutput(tool, s, entry) {
    if (!s || typeof s !== 'object') return '';
    if (tool === 'ping' && s.loss_percent != null) return metrics([
        ['Enviados', s.sent], ['Recebidos', s.received], ['Perda', unit(s.loss_percent, '%')],
        ['Mínimo', unit(s.min_ms, ' ms')], ['Média', unit(s.avg_ms, ' ms')], ['Máximo', unit(s.max_ms, ' ms')]
    ]);
    if (tool === 'routes' && Array.isArray(s.routes)) return table(['Destino', 'Gateway', 'Interface', 'Métrica', 'Protocolo'],
        s.routes.map(r => [r.dst, r.gateway, r.dev, r.metric, r.protocol]));
    if (tool === 'arp_table' && Array.isArray(s.neighbors)) return table(['IP', 'Interface', 'MAC', 'Estado'],
        s.neighbors.map(n => [n.dst, n.dev, n.lladdr, Array.isArray(n.state) ? n.state.join(', ') : n.state]));
    if (tool === 'interfaces' && Array.isArray(s.interfaces)) {
        const addresses = (iface, family) => (iface.addr_info || []).filter(a => a.family === family).map(a => a.local + (a.prefixlen == null ? '' : '/' + a.prefixlen)).join(', ') || '—';
        return table(['Interface', 'Estado', 'MTU', 'IPv4', 'IPv6'],
            s.interfaces.map(i => [i.ifname, i.operstate, i.mtu, addresses(i, 'inet'), addresses(i, 'inet6')]));
    }
    if (tool === 'mtr' && Array.isArray(s.hops)) {
        const rows = s.hops.map(h => {
            const loss = h.loss_percent;
            const cls = loss >= 100 ? 'loss-total' : loss > 20 ? 'loss-high' : loss > 0 ? 'loss-mid' : '';
            return '<tr><td>' + escapeHTML(h.hop) + '</td><td>' + escapeHTML(h.host || h.ip) +
                '</td><td class="' + cls + '">' + escapeHTML(unit(loss, '%')) + '</td>' +
                [h.sent, h.last_ms, h.avg_ms, h.best_ms, h.worst_ms, h.stdev_ms].map(v => '<td>' + escapeHTML(v) + '</td>').join('') + '</tr>';
        }).join('');
        return '<div class="diag-mtr-badges"><span>' + s.hops.length + ' hops</span><span>' + escapeHTML(duration(elapsed(entry.result))) +
            '</span><span class="diag-term-status--' + statusClass(entry.result.status) + '">' + escapeHTML((entry.result.status || '—').toUpperCase()) +
            '</span></div><div class="diag-table-scroll"><table class="diag-table"><thead><tr>' +
            ['Hop', 'Host', 'Loss', 'Sent', 'Last (ms)', 'Avg (ms)', 'Best (ms)', 'Worst (ms)', 'StDev (ms)'].map(h => '<th scope="col">' + h + '</th>').join('') +
            '</tr></thead><tbody>' + rows + '</tbody></table></div>' +
            '<p class="diag-mtr-note">Alguns equipamentos limitam respostas ICMP. Perda em hops intermediários não representa necessariamente perda fim a fim.</p>';
    }
    if (['dns_lookup', 'reverse_dns'].includes(tool) && Array.isArray(s.records)) return table(['Registro'], s.records.map(r => [r]));
    if (tool === 'dns_latency' && 'query_time_ms' in s) return metrics([['Domínio', entry.target], ['Tempo da consulta', unit(s.query_time_ms, ' ms')]]);
    if (tool === 'tcp_connect' && 'reachable' in s) return metrics([
        ['Host', entry.target], ['Porta', s.port], ['Estado', s.reachable ? 'Conectado' : 'Não conectado'], ['Duração da tentativa', duration(elapsed(entry.result))]
    ]);
    if (tool === 'http_check' && 'status_code' in s) return metrics([
        ['HTTP', s.status_code], ['Tempo', duration(elapsed(entry.result))], ['Destino final', s.final_url], ['Resultado', entry.result.summary]
    ]);
    return '';
}
function displayResult(entry) {
    Diag.lastResult = entry;
    const { tool, target, result, ts } = entry;
    Diag.selectedId = result.execution_id || result.id || null;
    const status = statusClass(result.status);
    setText('termTitle', (TOOL_LABELS[tool] || tool) + ' → ' + scope(tool, target) + ' · ' + ts.toLocaleTimeString('pt-BR') + ' · ' + (result.status || '—').toUpperCase());
    setText('metaTool', TOOL_LABELS[tool] || tool);
    setText('metaTarget', scope(tool, target));
    setText('metaTime', ts.toLocaleTimeString('pt-BR'));
    setText('metaStatus', (result.status || '—').toUpperCase());
    $('metaStatus').className = 'diag-term-status diag-term-status--' + status;
    $('termMeta').style.display = 'flex';
    const html = renderStructuredOutput(tool, result.structured, entry);
    $('termStructured').innerHTML = html; // Renderers escape every external value.
    $('termStructured').hidden = !html;
    $('termStructured').style.display = html ? 'block' : 'none';
    // Machine-readable stdout belongs exclusively in JSON; ping/traceroute/ss remain readable.
    const machineOutput = ['routes', 'interfaces', 'arp_table', 'mtr'].includes(tool);
    const stdout = (!html || tool === 'ping') && !machineOutput ? result.stdout || '' : '';
    $('termOutput').textContent = stdout || (!html ? result.summary || 'Nenhuma saída disponível.' : '');
    $('termOutput').hidden = !$('termOutput').textContent;
    $('termSummary').style.display = result.summary ? 'flex' : 'none';
    $('termSummary').className = 'diag-term-summary diag-term-summary--' + status;
    setText('termSummaryText', result.status === 'err' ? 'Não foi possível concluir o teste: ' + (result.summary || 'Erro') : result.summary);
    setText('detDuration', duration(elapsed(result)));
    setText('detExitCode', result.exit_code ?? result.meta?.exit_code);
    setText('detTool', tool);
    setText('detTarget', scope(tool, target));
    setText('detSource', result.source || entry.source);
    setText('detExecution', Diag.selectedId);
    setText('detStatus', result.status);
    setText('detOutputSize', ((result.stdout || '').length / 1024).toFixed(2) + ' KB');
    setText('detTimestamp', ts.toLocaleString('pt-BR'));
    setText('detStderrContent', result.stderr);
    $('detStderr').style.display = result.stderr ? 'block' : 'none';
    setText('termJson', JSON.stringify(result, null, 2));
    renderHistory();
}
function humanOutput() {
    const structured = $('termStructured');
    const rows = [...structured.querySelectorAll('tr')].map(row => [...row.cells].map(cell => cell.textContent).join('\t'));
    const values = [...structured.querySelectorAll('.diag-metrics > div')].map(item => item.querySelector('dt').textContent + ': ' + item.querySelector('dd').textContent);
    const notes = [...structured.querySelectorAll('p, .diag-mtr-badges')].map(item => item.textContent);
    return [$('termTitle').textContent, structured.hidden ? '' : [...values, ...rows, ...notes].join('\n'),
    $('termOutput').hidden ? '' : $('termOutput').textContent,
    $('termSummary').style.display === 'none' ? '' : $('termSummaryText').textContent].filter(Boolean).join('\n\n');
}
function consoleLine(text) {
    const output = $('consoleOutput');
    // Keep the console bounded independently of database history.
    output.textContent = (output.textContent + (output.textContent ? '\n\n' : '') + text).slice(-48000);
    output.scrollTop = output.scrollHeight;
}
function handleTerminalCommand(raw) {
    if (Diag.isRunning) { toast('info', 'Aguarde a execução atual terminar.'); return; }
    const line = raw.trim();
    if (!line) return;
    const [command, ...args] = line.split(/\s+/);
    const cmd = command.toLowerCase();
    if (cmd === 'clear' && !args.length) { $('consoleOutput').textContent = ''; return; }
    consoleLine('moonshield> ' + line);
    if (cmd === 'help' && !args.length) {
        consoleLine('help\nping <host>    trace <host>    mtr <host>\ndns <domain>   rdns <ip>       tcp <host> <port>\nhttp <url>     routes         arp\nifaces         sockets        history\nclear');
        return;
    }
    if (cmd === 'history' && !args.length) {
        consoleLine(Diag.history.map(h => (TOOL_LABELS[h.tool] || h.tool) + ' · ' + scope(h.tool, h.target) + ' · ' + h.status + ' · ' + duration(h.duration_ms)).join('\n') || 'Nenhuma execução na lista.');
        return;
    }
    const map = { ping: 'ping', trace: 'traceroute', mtr: 'mtr', dns: 'dns_lookup', rdns: 'reverse_dns', tcp: 'tcp_connect', http: 'http_check', routes: 'routes', arp: 'arp_table', ifaces: 'interfaces', sockets: 'sockets' };
    const tool = Object.hasOwn(map, cmd) ? map[cmd] : null;
    if (!tool) { consoleLine('Comando não permitido. Digite help.'); return; }
    const count = TARGETLESS.has(tool) ? 0 : cmd === 'tcp' ? 2 : 1;
    if (args.length !== count) { consoleLine('Argumentos inválidos. Digite help para consultar a sintaxe.'); return; }
    const options = cmd === 'tcp' ? { port: Number(args[1]) } : cmd === 'mtr' ? { cycles: 3 } : {};
    runTool(tool, args[0] || '', options, 'terminal');
}
function toast(type, msg) {
    const item = document.createElement('div');
    item.className = 'diag-toast diag-toast--' + type;
    item.textContent = msg;
    $('diagToast').append(item);
    requestAnimationFrame(() => item.classList.add('visible'));
    setTimeout(() => item.remove(), 4500);
}
function download(filename, content, type) {
    const url = URL.createObjectURL(new Blob([content], { type }));
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function exportResult(json) {
    if (!Diag.lastResult) { toast('info', 'Nenhum resultado para exportar.'); return; }
    const entry = Diag.lastResult;
    const content = json ? JSON.stringify(entry.result, null, 2) : [
        'MOONSHIELD — Diagnóstico de Rede', humanOutput(),
        'Duração: ' + duration(elapsed(entry.result)), 'Execution ID: ' + (Diag.selectedId || '—'),
        entry.result.stderr ? 'STDERR:\n' + entry.result.stderr : ''
    ].filter(Boolean).join('\n\n');
    download('moonshield-diag-' + entry.tool + '-' + Date.now() + (json ? '.json' : '.txt'), content, json ? 'application/json' : 'text/plain');
}
async function copyActivePanel() {
    const text = Diag.activeTermTab === 'saida' ? humanOutput() :
        Diag.activeTermTab === 'json' ? $('termJson').textContent : $('tpanel-detalhes').innerText;
    try {
        if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(text);
        else {
            const area = document.createElement('textarea');
            area.value = text;
            area.style.position = 'fixed';
            area.style.opacity = '0';
            document.body.append(area);
            area.select();
            const copied = document.execCommand('copy');
            area.remove();
            $('termCopyBtn').focus();
            if (!copied) throw new Error('Cópia indisponível neste navegador.');
        }
        toast('ok', 'Conteúdo copiado.');
    } catch { toast('err', 'Não foi possível copiar. Selecione o conteúdo para copiar manualmente.'); }
}
function initTabs(selector, group, panelPrefix, activeClass, select) {
    const tabs = [...document.querySelectorAll(selector)];
    group.setAttribute('role', 'tablist');
    tabs.forEach((tab, index) => {
        const name = tab.dataset.ttab || tab.dataset.tab;
        tab.id = panelPrefix + '-tab-' + name;
        tab.setAttribute('role', 'tab');
        tab.setAttribute('aria-controls', panelPrefix + name);
        const panel = $(panelPrefix + name);
        panel.setAttribute('role', 'tabpanel');
        panel.setAttribute('aria-labelledby', tab.id);
        panel.tabIndex = 0;
        tab.addEventListener('click', () => select(name));
        tab.addEventListener('keydown', event => {
            let next;
            if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
            if (event.key === 'ArrowLeft') next = (index + tabs.length - 1) % tabs.length;
            if (event.key === 'Home') next = 0;
            if (event.key === 'End') next = tabs.length - 1;
            if (next == null) return;
            event.preventDefault();
            tabs[next].click();
            tabs[next].focus();
        });
    });
    const active = tabs.find(tab => tab.classList.contains(activeClass)) || tabs[0];
    select(active.dataset.ttab || active.dataset.tab);
}
document.addEventListener('DOMContentLoaded', () => {
    // Associate existing field labels without changing global form styles.
    document.querySelectorAll('#diagPage .diag-field').forEach(field => {
        const label = field.querySelector('label'), input = field.querySelector('input, select');
        if (label && input) label.htmlFor = input.id;
    });
    syncButtons();
    loadContext();
    loadHistory();
    document.querySelectorAll('.diag-quick-card__btn').forEach(button => button.addEventListener('click', () => {
        const card = button.closest('.diag-quick-card');
        const reason = quickUnavailable(card);
        if (reason) { toast('info', reason); return; }
        const target = card.dataset.target === 'gateway' ? Diag.ctx.gateway : card.dataset.target;
        runTool(card.dataset.tool, target, card.dataset.tool === 'ping' ? { count: 4, timeout: 2 } : {}, 'quick', button);
    }));
    document.querySelectorAll('.diag-run-btn').forEach(button => button.addEventListener('click', () => {
        let target = '', options = {};
        switch (button.dataset.form) {
            case 'route':
                target = value('routeTarget');
                if (button.dataset.tool === 'mtr') { options = { cycles: Number(value('routeCycles')) }; }
                break;
            case 'ns': target = value('nsTarget'); break;
            case 'rev': target = value('revTarget'); break;
            case 'cmp': target = value('cmpTarget'); break;
            case 'port': target = value('portTarget'); options = { port: Number(value('portNumber')) }; break;
            case 'http': target = value('httpTarget'); options = { timeout: Number(value('httpTimeout')) }; break;
            case 'netstat': options = { flags: ['-t', '-u', '-n', value('netstatFilter') === 'listening' ? '-l' : '-a'] }; break;
        }
        runTool(button.dataset.tool, target, options, 'guided', button);
    }));
    initTabs('.diag-term-tab', document.querySelector('.diag-term-tabs'), 'tpanel-', 'diag-term-tab--active', selectResultTab);

    // Main Tabs logic
    const MAIN_TAB_KEY = 'moonshield.diagnostico.mainTab';

    function setMainTab(tabName) {
        if (tabName !== 'diagnostico' && tabName !== 'avancado') tabName = 'diagnostico';

        document.querySelectorAll('.diag-main-tab').forEach(t => {
            const active = t.dataset.maintab === tabName;
            t.classList.toggle('diag-main-tab--active', active);
            t.setAttribute('aria-selected', active);
        });
        document.querySelectorAll('.diag-tab-content').forEach(content => {
            const active = content.id === 'tab-' + tabName;
            content.style.display = active ? 'block' : 'none';
            content.classList.toggle('diag-tab-content--active', active);
        });

        try {
            localStorage.setItem(MAIN_TAB_KEY, tabName);
        } catch (e) {}
    }

    document.querySelectorAll('.diag-main-tab').forEach(tab => {
        tab.addEventListener('click', () => setMainTab(tab.dataset.maintab));
    });

    try {
        const savedTab = localStorage.getItem(MAIN_TAB_KEY);
        if (savedTab) setMainTab(savedTab);
    } catch (e) {}

    // Fullscreen Toggle
    function toggleFullscreen(sectionId) {
        const section = $(sectionId);
        if (section) {
            section.classList.toggle('diag-fullscreen');
            document.body.style.overflow = section.classList.contains('diag-fullscreen') ? 'hidden' : '';
        }
    }

    if ($('termFullscreenBtn')) $('termFullscreenBtn').addEventListener('click', () => toggleFullscreen('terminalSection'));
    if ($('consoleFullscreenBtn')) $('consoleFullscreenBtn').addEventListener('click', () => toggleFullscreen('consoleHeading').parentNode);
    // Note: consoleHeading is inside diag-section. So let's properly target the section
    if ($('consoleFullscreenBtn')) {
        $('consoleFullscreenBtn').addEventListener('click', () => {
            const consoleSec = $('consoleHeading').closest('.diag-console');
            consoleSec.classList.toggle('diag-fullscreen');
            document.body.style.overflow = consoleSec.classList.contains('diag-fullscreen') ? 'hidden' : '';
        });
    }

    if ($('termCloseFsBtn')) $('termCloseFsBtn').addEventListener('click', () => toggleFullscreen('terminalSection'));
    if ($('consoleCloseFsBtn')) $('consoleCloseFsBtn').addEventListener('click', () => {
        const consoleSec = $('consoleHeading').closest('.diag-console');
        consoleSec.classList.remove('diag-fullscreen');
        document.body.style.overflow = '';
    });

    // Escape to exit fullscreen
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            document.querySelectorAll('.diag-fullscreen').forEach(el => {
                el.classList.remove('diag-fullscreen');
            });
            document.body.style.overflow = '';
        }
    });

    // MTR Mode switch
    if ($('mtrModeTeste') && $('mtrModeLive')) {
        $('mtrModeTeste').addEventListener('click', () => {
            $('mtrModeTeste').classList.add('diag-mtr-mode-btn--active');
            $('mtrModeLive').classList.remove('diag-mtr-mode-btn--active');
            if ($('mtrLiveOverlay')) $('mtrLiveOverlay').style.display = 'none';
        });
        $('mtrModeLive').addEventListener('click', () => {
            $('mtrModeLive').classList.add('diag-mtr-mode-btn--active');
            $('mtrModeTeste').classList.remove('diag-mtr-mode-btn--active');
            if ($('mtrLiveOverlay')) $('mtrLiveOverlay').style.display = 'flex';
        });
    }
    $('termCliInput').addEventListener('keydown', event => {
        if (event.key !== 'Enter') return;
        event.preventDefault();
        if (Diag.isRunning) { toast('info', 'Aguarde a execução atual terminar.'); return; }
        handleTerminalCommand(event.target.value);
        event.target.value = '';
    });
    $('termCopyBtn').addEventListener('click', copyActivePanel);
    $('termSaveBtn').addEventListener('click', () => exportResult(false));
    $('btnExportTxt').addEventListener('click', () => exportResult(false));
    $('btnExportJson').addEventListener('click', () => exportResult(true));
    $('termClearBtn').addEventListener('click', () => { if (!Diag.isRunning) clearResult(); });
    $('clearHistoryBtn').addEventListener('click', () => {
        Diag.history = [];
        renderHistory();
        toast('info', 'Lista visual limpa. O histórico permanece salvo.');
    });
    $('ctxRefreshBtn').addEventListener('click', async () => {
        $('ctxRefreshBtn').disabled = true;
        try { if (await loadContext()) toast('ok', 'Contexto atualizado.'); }
        finally { $('ctxRefreshBtn').disabled = false; }
    });
    document.querySelectorAll('.diag-port-preset').forEach(button => button.addEventListener('click', () => {
        $('portNumber').value = button.dataset.port;
        document.querySelectorAll('.diag-port-preset').forEach(item => item.classList.toggle('diag-port-preset--active', item === button));
    }));

    // --- LIVE SESSIONS LOGIC ---
    const Live = {
        active: {},
        state: {},
        timers: {},
        stopping: {}
    };

    function formatTime(ms) {
        if (!ms) return '00:00:00';
        const total = Math.floor(ms / 1000);
        const h = String(Math.floor(total / 3600)).padStart(2, '0');
        const m = String(Math.floor((total % 3600) / 60)).padStart(2, '0');
        const s = String(total % 60).padStart(2, '0');
        return `${h}:${m}:${s}`;
    }

    function selectedLiveDurationSeconds() {
        return Number(value('routeLiveDuration')) || 0;
    }

    function formatLiveClock(elapsedMs, durationSeconds) {
        const current = formatTime(elapsedMs);
        return durationSeconds > 0 ? `${current} / ${formatTime(durationSeconds * 1000)}` : current;
    }

    function activeLiveTool() {
        return Object.keys(Live.active).find(tool => Boolean(Live.active[tool])) || null;
    }

    function syncTerminalLiveStop() {
        const button = $('termLiveStopBtn');
        if (!button) return;
        const tool = activeLiveTool();
        const stopping = tool ? Boolean(Live.stopping[tool]) : false;
        button.style.display = tool ? 'inline-flex' : 'none';
        button.disabled = !tool || stopping;
        button.style.opacity = button.disabled ? '0.55' : '1';
        button.textContent = stopping ? 'Parando…' : '■ Parar Live';
    }

    function liveEntry(tool, target, data) {
        const result = {
            ...data,
            duration_ms: data.elapsed_ms ?? data.duration_ms,
            source: data.source || 'live'
        };
        return { tool, target, source: 'live', ts: new Date(), result };
    }

    function updateLiveDetails(tool, target, data) {
        const entry = liveEntry(tool, target, data);
        Diag.lastResult = entry;
        Diag.selectedId = data.execution_id || data.id || data.session_id || null;

        setText('metaTool', TOOL_LABELS[tool] || tool);
        setText('metaTarget', scope(tool, target));
        setText('metaTime', entry.ts.toLocaleTimeString('pt-BR'));
        setText('metaStatus', (data.status || 'running').toUpperCase());
        $('metaStatus').className = 'diag-term-status diag-term-status--' + statusClass(data.status);
        setText('termTitle', (TOOL_LABELS[tool] || tool) + ' → ' + scope(tool, target) + ' · ' + entry.ts.toLocaleTimeString('pt-BR') + ' · ' + (data.status || 'running').toUpperCase());
        $('termMeta').style.display = 'flex';

        setText('detDuration', duration(data.elapsed_ms ?? data.duration_ms));
        setText('detExitCode', data.exit_code ?? data.meta?.exit_code);
        setText('detTool', tool);
        setText('detTarget', scope(tool, target));
        setText('detSource', data.source || 'live');
        setText('detExecution', data.execution_id || data.id || data.session_id);
        setText('detStatus', data.status || 'running');
        setText('detOutputSize', ((data.stdout || '').length / 1024).toFixed(2) + ' KB');
        setText('detTimestamp', entry.ts.toLocaleString('pt-BR'));
        setText('detStderrContent', data.stderr);
        $('detStderr').style.display = data.stderr ? 'block' : 'none';
        setText('termJson', JSON.stringify(data, null, 2));
    }

    function mtrValue(hop, primary, fallback, defaultValue = 0) {
        return hop?.[primary] ?? hop?.[fallback] ?? defaultValue;
    }

    function buildMtrTerminal(target, structured, elapsedMs) {
        const hops = Array.isArray(structured?.hops) ? structured.hops : [];
        const header = 'HOST                         Loss%   Snt   Last   Avg   Best   Wrst   StDev';
        const rows = hops.map((h, index) => {
            const hopNo = h.hop ?? (index + 1);
            const host = h.host || h.ip || '???';
            const loss = mtrValue(h, 'loss_percent', 'loss');
            const sent = h.sent ?? 0;
            const last = mtrValue(h, 'last_ms', 'last');
            const avg = mtrValue(h, 'avg_ms', 'avg');
            const best = mtrValue(h, 'best_ms', 'best');
            const worst = mtrValue(h, 'worst_ms', 'worst');
            const stdev = mtrValue(h, 'stdev_ms', 'stdev');
            const hostPad = (`${hopNo}. ${host}`).padEnd(28, ' ');
            return [
                hostPad,
                String(loss).padEnd(7, ' '),
                String(sent).padEnd(5, ' '),
                String(last).padEnd(6, ' '),
                String(avg).padEnd(5, ' '),
                String(best).padEnd(6, ' '),
                String(worst).padEnd(6, ' '),
                String(stdev)
            ].join(' ');
        });
        return `moonshield> mtr ${target} --live\n\nMy traceroute [MoonShield]\n\n${header}\n${rows.join('\n')}\n\nLive: ${formatTime(elapsedMs)}`;
    }

    async function startLiveSession(tool, target, options) {
        try {
            const res = await fetch('/relatorios/diagnostico/api/live/iniciar/', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRFToken': document.cookie.split(';').find(item => item.trim().startsWith('csrftoken='))?.split('=')[1] },
                body: JSON.stringify({ tool, target, options })
            });
            const data = await res.json();
            if (!data.ok) throw new Error(data.summary || data.error_code);
            return data.session_id;
        } catch (e) {
            toast('err', 'Erro ao iniciar live: ' + e.message);
            return null;
        }
    }

    async function stopLiveSession(sessionId) {
        try {
            const csrfToken = document.cookie.split(';').find(item => item.trim().startsWith('csrftoken='))?.split('=')[1];
            const fd = new FormData();
            if (csrfToken) fd.append('csrfmiddlewaretoken', csrfToken);
            const res = await fetch(`/relatorios/diagnostico/api/live/${sessionId}/parar/`, {
                method: 'POST',
                body: fd
            });
            return await res.json();
        } catch (e) {
            return null;
        }
    }

    async function pollLiveSession(sessionId, cb) {
        try {
            const res = await fetch(`/relatorios/diagnostico/api/live/${sessionId}/`);
            const data = await res.json();
            if (data.ok) cb(data);
        } catch (e) { }
    }

    function restoreAfterLive(tool) {
        if (Live.timers[tool]) clearInterval(Live.timers[tool]);
        delete Live.timers[tool];
        delete Live.active[tool];
        delete Live.state[tool];
        delete Live.stopping[tool];

        $('termCliInput').disabled = false;
        $('termCliInput').placeholder = "Digite 'help' para comandos...";
        Diag.isRunning = false;
        $('execBar').style.display = 'none';
        $('terminalSection').setAttribute('aria-busy', 'false');
        syncButtons();
        RouteUI.update();
        syncTerminalLiveStop();
    }

    function finalizeLiveResult(tool, target, data, reason) {
        const structured = data.structured || {};
        const elapsedMs = data.elapsed_ms ?? data.duration_ms ?? 0;
        const elapsedSeconds = (elapsedMs / 1000).toFixed(1);
        const autoText = reason === 'timeout'
            ? '\n\n[MoonShield] Tempo definido atingido.\nDiagnóstico encerrado automaticamente.'
            : '';

        let terminalText = '';
        if (tool === 'ping') {
            const tx = structured.sent ?? 0;
            const rx = structured.received ?? 0;
            const loss = structured.loss_percent ?? 0;
            const min = structured.min_ms ?? 0;
            const avg = structured.avg_ms ?? 0;
            const max = structured.max_ms ?? 0;
            terminalText = `moonshield> ping ${target} --live\n\n${data.stdout || ''}\n^C\n\n--- ${target} ping statistics ---\n${tx} packets transmitted, ${rx} received, ${loss}% packet loss\nrtt min/avg/max = ${min}/${avg}/${max} ms${autoText}\n\n[MoonShield] Diagnóstico encerrado.\nTempo total: ${elapsedSeconds} s`;
        } else {
            const hops = Array.isArray(structured.hops) ? structured.hops : [];
            const samples = hops.reduce((max, h) => Math.max(max, Number(h.sent) || 0), 0);
            terminalText = `${buildMtrTerminal(target, structured, elapsedMs)}${autoText}\n\n[MoonShield] MTR encerrado.\nAmostras: ${samples}\nHops: ${hops.length}\nTempo total: ${elapsedSeconds} s`;
        }

        const finalResult = {
            ...data,
            status: 'ok',
            duration_ms: elapsedMs,
            summary: reason === 'timeout' ? 'Diagnóstico finalizado automaticamente no tempo definido.' : (data.summary || 'Diagnóstico finalizado com sucesso.'),
            source: data.source || 'live'
        };
        const finalEntry = { tool, target, source: 'live', ts: new Date(), result: finalResult };
        Diag.lastResult = finalEntry;
        Diag.selectedId = finalResult.execution_id || finalResult.id || finalResult.session_id || null;

        selectResultTab('saida');
        setText('termTitle', (TOOL_LABELS[tool] || tool) + ' → ' + scope(tool, target) + ' · ' + finalEntry.ts.toLocaleTimeString('pt-BR') + ' · OK');
        if (tool === 'mtr') {
            // Mantém o visual rico/estruturado do MTR (mesmo padrão do one-shot).
            const html = renderStructuredOutput('mtr', structured, finalEntry);
            $('termStructured').innerHTML = html;
            $('termStructured').hidden = !html;
            $('termStructured').style.display = html ? 'block' : 'none';
            $('termOutput').hidden = true;
            $('termOutput').textContent = '';
        } else {
            $('termOutput').hidden = false;
            $('termOutput').textContent = terminalText;
            $('termStructured').replaceChildren();
            $('termStructured').hidden = true;
            $('termStructured').style.display = 'none';
        }
        $('termSummary').style.display = 'flex';
        $('termSummary').className = 'diag-term-summary diag-term-summary--ok';
        setText('termSummaryText', finalResult.summary);
        updateLiveDetails(tool, target, finalResult);
        setText('termJson', JSON.stringify(finalResult, null, 2));
    }

    async function finishLiveSession(tool, reason = 'manual') {
        if (!Live.active[tool] || Live.stopping[tool]) return;
        Live.stopping[tool] = true;
        if (Live.timers[tool]) clearInterval(Live.timers[tool]);

        const sid = Live.active[tool];
        const state = Live.state[tool] || {};
        const target = state.target || value('routeTarget');
        $('routeLiveStopBtn').disabled = true;
        $('routeLiveStopBtn').style.opacity = '0.5';
        syncTerminalLiveStop();

        const data = await stopLiveSession(sid);
        if (data && data.ok) {
            finalizeLiveResult(tool, target, data, reason);
            toast('ok', reason === 'timeout' ? `${tool.toUpperCase()} Live finalizado pelo tempo definido.` : `${tool.toUpperCase()} Live finalizado.`);
            restoreAfterLive(tool);
            await loadHistory();
            return;
        }

        const message = data?.summary || 'Não foi possível encerrar a sessão Live.';
        setText('termTitle', 'Não foi possível concluir o teste');
        $('termOutput').hidden = false;
        $('termOutput').textContent += `\n\n[ERRO] ${message}`;
        $('termSummary').style.display = 'flex';
        $('termSummary').className = 'diag-term-summary diag-term-summary--err';
        setText('termSummaryText', message);
        toast('err', message);
        restoreAfterLive(tool);
    }

    const RouteUI = {
        tool: 'ping',
        mode: 'teste',
        update: function () {
            const anyLive = Object.keys(Live.active).length > 0;
            document.querySelectorAll('#routeToolSwitch .diag-mtr-mode-btn').forEach(btn => {
                btn.classList.toggle('diag-mtr-mode-btn--active', btn.dataset.tool === this.tool);
                btn.disabled = anyLive;
            });
            document.querySelectorAll('#routeModeSwitch .diag-mtr-mode-btn').forEach(btn => {
                btn.classList.toggle('diag-mtr-mode-btn--active', btn.dataset.mode === this.mode);
                btn.disabled = anyLive;
            });

            const isLive = this.mode === 'live';
            const isTraceroute = this.tool === 'traceroute';
            const isMTR = this.tool === 'mtr';
            const isPing = this.tool === 'ping';
            const active = Boolean(Live.active[this.tool]);

            $('routeTestBtn').style.display = isLive ? 'none' : 'inline-block';
            $('routeTestBtn').dataset.tool = this.tool;
            $('routeTestBtn').textContent = 'Executar ' + (isMTR ? 'MTR' : (isTraceroute ? 'Traceroute' : 'Ping'));

            $('routeLiveStartBtn').style.display = (isLive && !isTraceroute) ? 'inline-block' : 'none';
            $('routeLiveStopBtn').style.display = (isLive && !isTraceroute) ? 'inline-block' : 'none';
            $('routeLiveStartBtn').disabled = active || Boolean(Live.stopping[this.tool]);
            $('routeLiveStopBtn').disabled = !active || Boolean(Live.stopping[this.tool]);
            $('routeLiveStopBtn').style.opacity = $('routeLiveStopBtn').disabled ? '0.5' : '1';
            $('routeTarget').disabled = anyLive;
            $('routeLiveBadge').style.display = active ? 'flex' : 'none';

            $('routeCyclesField').style.display = (!isLive && isMTR) ? 'block' : 'none';
            $('routeLiveDurationField').style.display = (isLive && !isTraceroute) ? 'block' : 'none';
            $('routeLiveDuration').disabled = anyLive;
            $('routeLiveTracerouteMsg').style.display = (isLive && isTraceroute) ? 'block' : 'none';
            $('pingLiveMetrics').style.display = (isLive && isPing && Live.active.ping) ? 'grid' : 'none';
            $('mtrLiveMetrics').style.display = (isLive && isMTR && Live.active.mtr) ? 'block' : 'none';

            let hint = 'Teste de conectividade ICMP.';
            if (isTraceroute) hint = 'Traça o caminho dos pacotes até o destino.';
            if (isMTR) hint = 'Analisa latência, perda e caminho continuamente.';
            if ($('routeHint')) $('routeHint').textContent = hint;
            syncTerminalLiveStop();
        }
    };

    if ($('routeToolSwitch')) {
        document.querySelectorAll('#routeToolSwitch .diag-mtr-mode-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                if (Object.keys(Live.active).length) { toast('info', 'Pare o diagnóstico ao vivo antes de trocar a ferramenta.'); return; }
                RouteUI.tool = btn.dataset.tool;
                RouteUI.update();
            });
        });
        document.querySelectorAll('#routeModeSwitch .diag-mtr-mode-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                if (Object.keys(Live.active).length) { toast('info', 'Pare o diagnóstico ao vivo antes de trocar o modo.'); return; }
                RouteUI.mode = btn.dataset.mode;
                RouteUI.update();
            });
        });
        $('routeUseMtrBtn').addEventListener('click', () => {
            if (Object.keys(Live.active).length) return;
            RouteUI.tool = 'mtr';
            RouteUI.update();
        });

        $('routeLiveStartBtn').addEventListener('click', async () => {
            const tool = RouteUI.tool;
            const target = value('routeTarget');
            if (!target) { toast('warn', 'Destino obrigatório'); return; }
            if (tool === 'traceroute') { toast('info', 'Para análise contínua de rota, utilize MTR.'); return; }

            const durationSeconds = selectedLiveDurationSeconds();
            Diag.isRunning = true;
            clearResult();
            selectResultTab('saida');
            syncButtons();
            $('terminalSection').setAttribute('aria-busy', 'true');
            $('termCliInput').disabled = true;
            $('termCliInput').placeholder = 'Diagnóstico ao vivo em execução...';
            $('termStructured').replaceChildren();
            $('termStructured').hidden = true;
            $('termStructured').style.display = 'none';
            if (tool === 'mtr') {
                $('termOutput').hidden = false;
                $('termOutput').textContent = 'Aguardando primeira amostra MTR…';
            } else {
                $('termOutput').hidden = false;
                $('termOutput').textContent = `moonshield> ${tool} ${target} --live\n\n[Iniciando diagnóstico ao vivo...]`;
            }
            setText('termTitle', 'Diagnóstico em execução');
            $('termSummary').style.display = 'none';
            $('execBarLabel').textContent = 'Diagnóstico ao vivo (' + tool.toUpperCase() + ')';
            $('execBar').style.display = 'flex';
            $('routeLiveTime').textContent = formatLiveClock(0, durationSeconds);

            const sid = await startLiveSession(tool, target, {});
            if (!sid) {
                $('termOutput').textContent = `[ERRO] Não foi possível iniciar diagnóstico Live para ${target}.`;
                setText('termTitle', 'Não foi possível concluir o teste');
                $('termSummary').style.display = 'flex';
                $('termSummary').className = 'diag-term-summary diag-term-summary--err';
                setText('termSummaryText', 'Falha ao iniciar a sessão ao vivo.');
                $('termCliInput').disabled = false;
                $('termCliInput').placeholder = "Digite 'help' para comandos...";
                Diag.isRunning = false;
                $('terminalSection').setAttribute('aria-busy', 'false');
                $('execBar').style.display = 'none';
                syncButtons();
                RouteUI.update();
                return;
            }

            Live.active[tool] = sid;
            Live.state[tool] = {
                stdoutLength: 0,
                outputText: `moonshield> ${tool} ${target} --live\n\n`,
                target,
                durationSeconds,
                lastData: null
            };
            RouteUI.update();
            syncTerminalLiveStop();

            Live.timers[tool] = setInterval(() => {
                pollLiveSession(sid, data => {
                    if (!Live.active[tool] || Live.stopping[tool]) return;
                    const state = Live.state[tool];
                    const structured = data.structured || {};
                    state.lastData = data;
                    updateLiveDetails(tool, target, data);
                    $('routeLiveTime').textContent = formatLiveClock(data.elapsed_ms, state.durationSeconds);

                    if (tool === 'ping') {
                        $('plSent').textContent = structured.sent ?? 0;
                        $('plRecv').textContent = structured.received ?? 0;
                        $('plLoss').textContent = (structured.loss_percent ?? 0) + '%';
                        $('plLast').textContent = (structured.last_ms ?? 0) + ' ms';
                        $('plAvg').textContent = (structured.avg_ms ?? 0) + ' ms';
                        $('plMin').textContent = (structured.min_ms ?? 0) + ' ms';
                        $('plMax').textContent = (structured.max_ms ?? 0) + ' ms';

                        const stdout = data.stdout || '';
                        if (stdout.length < state.stdoutLength) {
                            state.stdoutLength = 0;
                            state.outputText = `moonshield> ping ${target} --live\n\n`;
                        }
                        const delta = stdout.substring(state.stdoutLength);
                        if (delta) {
                            state.outputText += delta;
                            state.stdoutLength = stdout.length;
                            $('termOutput').textContent = state.outputText;
                            $('termOutput').scrollTop = $('termOutput').scrollHeight;
                        }
                    } else if (tool === 'mtr') {
                        const hops = Array.isArray(structured.hops) ? structured.hops : [];
                        const samples = hops.reduce((max, h) => Math.max(max, Number(h.sent) || 0), 0);
                        $('mtrLiveSamples').textContent = samples + ' amostras';
                        $('mtrLiveHops').textContent = hops.length + ' hops';

                        // Live MTR usa o mesmo visual estruturado bonito do MTR one-shot.
                        const entry = liveEntry('mtr', target, data);
                        const html = renderStructuredOutput('mtr', structured, entry);
                        $('termStructured').innerHTML = html;
                        $('termStructured').hidden = !html;
                        $('termStructured').style.display = html ? 'block' : 'none';
                        $('termOutput').hidden = true;
                        $('termOutput').textContent = '';
                    }

                    setText('termJson', JSON.stringify(data, null, 2));

                    if (data.status === 'error') {
                        const message = data.summary || 'Sessão Live encerrada com erro.';
                        $('termOutput').textContent += `\n\n[ERRO] ${message}`;
                        setText('termTitle', 'Não foi possível concluir o teste');
                        $('termSummary').style.display = 'flex';
                        $('termSummary').className = 'diag-term-summary diag-term-summary--err';
                        setText('termSummaryText', message);
                        toast('err', message);
                        restoreAfterLive(tool);
                        return;
                    }

                    if (state.durationSeconds > 0 && Number(data.elapsed_ms || 0) >= state.durationSeconds * 1000) {
                        finishLiveSession(tool, 'timeout');
                    }
                });
            }, 1000);
        });

        $('routeLiveStopBtn').addEventListener('click', () => finishLiveSession(RouteUI.tool, 'manual'));
        if ($('termLiveStopBtn')) {
            $('termLiveStopBtn').addEventListener('click', () => {
                const tool = activeLiveTool();
                if (tool) finishLiveSession(tool, 'manual');
            });
        }

        RouteUI.update();
        syncTerminalLiveStop();
    }

    window.addEventListener('beforeunload', () => {
        const csrfToken = document.cookie.split(';').find(item => item.trim().startsWith('csrftoken='))?.split('=')[1];
        for (const [tool, sid] of Object.entries(Live.active)) {
            const fd = new FormData();
            if (csrfToken) fd.append('csrfmiddlewaretoken', csrfToken);
            navigator.sendBeacon(`/relatorios/diagnostico/api/live/${sid}/parar/`, fd);
        }
    });

});
