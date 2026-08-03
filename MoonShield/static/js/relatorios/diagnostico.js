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
    iface: 'Wi-Fi (Intel AX201)',
    cidr: '192.168.1.0/24',
    gateway: '192.168.1.1',
    dns1: '1.1.1.1',
    dns2: '8.8.8.8',
    hostname: 'JARVIS-NODE-01',
    ip_local: '192.168.1.100',
    mode: 'DEMO',
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
const MOCK_RESPONSES = {
    ping: (target, opts) => {
        const ms = Math.floor(Math.random() * 15) + 1;
        const lost = Math.random() > 0.9 ? 1 : 0;
        const count = opts.count || 4;
        const ok = lost === 0;
        return {
            ok, status: ok ? 'ok' : 'warn',
            summary: `Ping ${ok ? 'OK' : 'PARCIAL'} (${count - lost}/${count}) avg ${ms}ms`,
            stdout: `Disparando ${count} pacotes para ${target}:\n\nResposta de ${target}: bytes=32 tempo=${ms}ms TTL=64\nResposta de ${target}: bytes=32 tempo=${ms + 1}ms TTL=64\nResposta de ${target}: bytes=32 tempo=${ms - 1}ms TTL=64\n${lost ? `Tempo limite da solicitação para host de destino.` : `Resposta de ${target}: bytes=32 tempo=${ms}ms TTL=64`}\n\nEstatísticas do Ping para ${target}:\n    Pacotes: Enviados = ${count}, Recebidos = ${count - lost}, Perdidos = ${lost} (${lost > 0 ? Math.round(lost / count * 100) : 0}% de perda),\nTempo aproximado de ida e volta em milissegundos:\n    Mínimo = ${ms - 1}ms, Máximo = ${ms + 2}ms, Média = ${ms}ms`,
            stderr: '',
            meta: { duration_ms: ms * count * 250 + 120, exit_code: ok ? 0 : 1 },
        };
    },
    traceroute: (target, opts) => {
        const hops = Math.floor(Math.random() * 8) + 4;
        let out = `Rastreando a rota para ${target} com no máximo ${opts.hops || 20} saltos:\n\n`;
        for (let i = 1; i <= hops; i++) {
            const ms = i * 3 + Math.floor(Math.random() * 8);
            const ip = i === hops ? target : `10.${Math.floor(i / 2)}.${i}.${Math.floor(Math.random() * 250) + 1}`;
            out += `  ${String(i).padStart(2)}    ${ms} ms    ${ms + 1} ms    ${ms} ms  ${ip}\n`;
        }
        out += `\nRastreamento concluído.`;
        return { ok: true, status: 'ok', summary: `Traceroute concluído — ${hops} hops`, stdout: out, stderr: '', meta: { duration_ms: hops * 1200, exit_code: 0 } };
    },
    nslookup: (target, opts) => {
        const server = opts.server === 'dns1' ? Diag.ctx.dns1 : opts.server === 'dns2' ? Diag.ctx.dns2 : (opts.server || Diag.ctx.dns1);
        const ips = ['142.250.79.46', '142.250.79.78', '172.217.28.110'];
        const ip = ips[Math.floor(Math.random() * ips.length)];
        return {
            ok: true, status: 'ok',
            summary: `${target} → ${ip} via ${server}`,
            stdout: `Servidor:  ${server}\nAddress:  ${server}#53\n\nResposta não autoritativa:\nNome:    ${target}\nAddress: ${ip}\nNome:    ${target}\nAddress: 2607:f8b0:4004:c08::64`,
            stderr: '', meta: { duration_ms: Math.floor(Math.random() * 80) + 20, exit_code: 0 },
        };
    },
    reverse_dns: (target) => {
        const names = { '8.8.8.8': 'dns.google', '8.8.4.4': 'dns.google', '1.1.1.1': 'one.one.one.one', '1.0.0.1': 'one.one.one.one' };
        const name = names[target] || `host-${target.replace(/\./g, '-')}.example.net`;
        return {
            ok: true, status: 'ok',
            summary: `${target} → ${name}`,
            stdout: `Servidor:  ${Diag.ctx.dns1}\nAddress:  ${Diag.ctx.dns1}#53\n\n${target}.in-addr.arpa  name = ${name}.`,
            stderr: '', meta: { duration_ms: 35, exit_code: 0 },
        };
    },
    dns_compare: (target) => {
        const d1 = Diag.ctx.dns1, d2 = Diag.ctx.dns2;
        const ip1 = '142.250.79.46', ip2 = '142.250.79.46';
        const match = ip1 === ip2;
        return {
            ok: true, status: match ? 'ok' : 'warn',
            summary: `DNS1 e DNS2 ${match ? 'concordam' : 'divergem'} para ${target}`,
            stdout: `=== DNS1 (${d1}) ===\n${target} → ${ip1}\n\n=== DNS2 (${d2}) ===\n${target} → ${ip2}\n\n${match ? '✓ Resultado idêntico nos dois servidores.' : '⚠ Divergência detectada! Possível envenenamento de cache ou split-DNS.'}`,
            stderr: '', meta: { duration_ms: 80, exit_code: 0 },
        };
    },
    tcp_port_test: (target, opts) => {
        const port = opts.port;
        const open = Math.random() > 0.3;
        return {
            ok: open, status: open ? 'ok' : 'err',
            summary: `${target}:${port} — ${open ? 'ABERTA' : 'FECHADA/TIMEOUT'}`,
            stdout: `Testando conexão TCP com ${target} na porta ${port}...\n\nResultado: porta ${port} está ${open ? 'ABERTA' : 'FECHADA'}\n${open ? `Conexão estabelecida com sucesso em ${Math.floor(Math.random() * 50) + 5}ms` : 'Conexão recusada ou timeout (sem resposta em 5s)'}`,
            stderr: '', meta: { duration_ms: open ? Math.floor(Math.random() * 80) + 10 : 5020, exit_code: open ? 0 : 1 },
        };
    },
    http_check: (target, opts) => {
        const codes = [200, 200, 200, 301, 403, 404, 200, 200];
        const code = codes[Math.floor(Math.random() * codes.length)];
        const ok = code < 400;
        const ms = Math.floor(Math.random() * 200) + 50;
        return {
            ok, status: ok ? 'ok' : 'warn',
            summary: `${target} → HTTP ${code} em ${ms}ms`,
            stdout: `GET ${target}\n\nHTTP/2 ${code}\ncontent-type: text/html; charset=utf-8\ndate: ${new Date().toUTCString()}\nserver: cloudflare\n\nTempo de resposta: ${ms}ms\nTamanho da resposta: ${Math.floor(Math.random() * 50) + 1} KB`,
            stderr: '', meta: { duration_ms: ms, exit_code: ok ? 0 : 1 },
        };
    },
    arp_table: () => {
        const entries = Array.from({ length: 6 }, (_, i) => {
            const ip = `192.168.1.${[1, 2, 10, 20, 50, 100][i]}`;
            const mac = Array.from({ length: 6 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join(':');
            const type = i === 0 ? 'dinâmico (gateway)' : 'dinâmico';
            return `  ${ip.padEnd(18)} ${mac}   ${type}`;
        });
        return {
            ok: true, status: 'ok',
            summary: `Tabela ARP — ${entries.length} entradas`,
            stdout: `Tabela ARP da interface ${Diag.ctx.iface}:\n\nEndereço IP           Endereço físico    Tipo\n${entries.join('\n')}`,
            stderr: '', meta: { duration_ms: 120, exit_code: 0 },
        };
    },
    routes: () => ({
        ok: true, status: 'ok',
        summary: 'Tabela de rotas capturada',
        stdout: `===========================================================================\nLista de Interfaces\n  ${Diag.ctx.iface}\n===========================================================================\nIPv4 Tabela de Rotas\n===========================================================================\nRotas Ativas:\n  Destino da Rede    Máscara de Rede   Gateway    Interface  Métrica\n          0.0.0.0          0.0.0.0   ${Diag.ctx.gateway}  ${Diag.ctx.ip_local}      25\n        127.0.0.0        255.0.0.0         Em host       127.0.0.1     331\n        127.0.0.1  255.255.255.255         Em host       127.0.0.1     331\n      192.168.1.0    255.255.255.0         Em host   ${Diag.ctx.ip_local}     281\n    ${Diag.ctx.ip_local}  255.255.255.255         Em host   ${Diag.ctx.ip_local}     281`,
        stderr: '', meta: { duration_ms: 85, exit_code: 0 },
    }),
    ipconfig: (target, opts) => {
        const all = opts && opts.mode === 'all';
        return {
            ok: true, status: 'ok',
            summary: `IPConfig ${all ? '/all' : 'básico'} — ${Diag.ctx.hostname}`,
            stdout: `Configuração de IP do Windows\n\nNome do Host. . . . . . . . . . . . . : ${Diag.ctx.hostname}\n${all ? `Sufixo DNS Primário . . . . . . . . . :\nTipo de Nó. . . . . . . . . . . . . . : Híbrido\nRoteamento IP Habilitado. . . . . . . : Não\nProxy WINS Habilitado . . . . . . . . : Não\n\n` : ''}Adaptador ${Diag.ctx.iface}:\n\n   Sufixo DNS específico de Conexão. . : lan\n   Endereço IPv4. . . . . . . . . . . . : ${Diag.ctx.ip_local}\n   Máscara de Sub-Rede . . . . . . . . : 255.255.255.0\n   Gateway Padrão. . . . . . . . . . . : ${Diag.ctx.gateway}\n   Servidores DNS. . . . . . . . . . . : ${Diag.ctx.dns1}\n                                          ${Diag.ctx.dns2}`,
            stderr: '', meta: { duration_ms: 45, exit_code: 0 },
        };
    },
    netstat: (target, opts) => {
        const states = { all: ['ESTABLISHED', 'LISTENING', 'TIME_WAIT'], established: ['ESTABLISHED'], listening: ['LISTENING'] };
        const filter = opts.filter || 'all';
        const stateList = states[filter] || states.all;
        const rows = Array.from({ length: 8 }, (_, i) => {
            const st = stateList[i % stateList.length];
            const lport = [443, 80, 3000, 22, 8080, 445, 3389, 53][i];
            const rport = Math.floor(Math.random() * 50000) + 1024;
            return `  TCP    ${Diag.ctx.ip_local}:${lport.toString().padEnd(6)} 0.0.0.0:${String(rport).padEnd(6)} ${st}`;
        });
        return {
            ok: true, status: 'ok',
            summary: `Netstat — ${rows.length} conexões (${filter})`,
            stdout: `Conexões Ativas\n\n  Proto  Endereço Local         Endereço Externo       Estado\n${rows.join('\n')}`,
            stderr: '', meta: { duration_ms: 160, exit_code: 0 },
        };
    },
    interfaces: () => ({
        ok: true, status: 'ok',
        summary: `3 interfaces detectadas`,
        stdout: `=== Interfaces de Rede ===\n\n[1] ${Diag.ctx.iface}\n    IP:  ${Diag.ctx.ip_local} / 24\n    MAC: a4:c3:f0:${Math.floor(Math.random() * 256).toString(16).padStart(2, '0')}:b2:11\n    Status: UP\n\n[2] Loopback Pseudo-Interface 1\n    IP:  127.0.0.1 / 8\n    Status: UP\n\n[3] Bluetooth PAN\n    Status: DOWN`,
        stderr: '', meta: { duration_ms: 55, exit_code: 0 },
    }),
    dns_latency: (target, opts) => {
        const ms1 = Math.floor(Math.random() * 40) + 5;
        const ms2 = Math.floor(Math.random() * 60) + 10;
        const best = ms1 <= ms2 ? `DNS1 (${Diag.ctx.dns1})` : `DNS2 (${Diag.ctx.dns2})`;
        return {
            ok: true, status: 'ok',
            summary: `DNS1: ${ms1}ms · DNS2: ${ms2}ms · Melhor: ${best}`,
            stdout: `=== Latência DNS ===\n\nDNS1 (${Diag.ctx.dns1}):\n  Consulta: google.com\n  Tempo:    ${ms1}ms\n  Resultado: OK\n\nDNS2 (${Diag.ctx.dns2}):\n  Consulta: google.com\n  Tempo:    ${ms2}ms\n  Resultado: OK\n\nMelhor servidor: ${best} (${Math.min(ms1, ms2)}ms)`,
            stderr: '', meta: { duration_ms: ms1 + ms2 + 20, exit_code: 0 },
        };
    },
    arp_scan: (target) => {
        const n = Math.floor(Math.random() * 8) + 3;
        const rows = Array.from({ length: n }, (_, i) => {
            const ip = `192.168.1.${[1, 2, 5, 10, 20, 50, 100, 150][i] || i + 1}`;
            const mac = Array.from({ length: 6 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join(':');
            const vendor = ['Intel Corp', 'Apple Inc', 'TP-Link', 'Xiaomi', 'Samsung', 'Raspberry Pi', 'Unknown'][i % 7];
            return `  ${ip.padEnd(16)} ${mac}   ${vendor}`;
        });
        return {
            ok: true, status: 'ok',
            summary: `ARP Scan — ${n} hosts encontrados em ${Diag.ctx.cidr}`,
            stdout: `Escaneando ${Diag.ctx.cidr}...\n\n  IP              MAC                Fabricante\n  ─────────────────────────────────────────────────\n${rows.join('\n')}\n\n${n} host(s) encontrado(s).`,
            stderr: '', meta: { duration_ms: n * 400 + 800, exit_code: 0 },
        };
    },
};

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
        const fn = MOCK_RESPONSES[tool];
        const base = fn ? fn(target, options) : { ok: true, status: 'ok', summary: 'OK', stdout: 'Ferramenta não simulada.', stderr: '', meta: { duration_ms: 500, exit_code: 0 } };

        /* BACK-END: substituir TODA esta função por:
         *
         * return fetch('/diagnostico/api/executar/', {
         *   method: 'POST',
         *   headers: { 'Content-Type':'application/json', 'X-CSRFToken': getCsrf() },
         *   body: JSON.stringify({ tool, target, options })
         * }).then(r => r.json());
         */

        const delay = Math.min(base.meta.duration_ms, 3500);
        setTimeout(() => resolve(base), delay);
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