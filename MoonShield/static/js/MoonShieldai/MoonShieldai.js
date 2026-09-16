/**
 * MOONSHIELD — JARVISAI.JS  v1
 * Página de AI — totalmente front-end simulado
 * State machine: MODE (text|voice) × VOICE_STATE (idle|listening|thinking|speaking|error)
 */

document.addEventListener('DOMContentLoaded', () => {

  /* ═══════════════════════════════════════════════════════
     UTILITÁRIOS
  ═══════════════════════════════════════════════════════ */
  const $ = id => document.getElementById(id);
  function pad(n) { return String(n).padStart(2,'0'); }
  function rand(min,max){ return Math.floor(Math.random()*(max-min+1))+min; }
  function pick(arr){ return arr[rand(0,arr.length-1)]; }
  function nowStr(){ const d=new Date(); return `${pad(d.getHours())}:${pad(d.getMinutes())}`; }
  function timeStr(){ const d=new Date(); return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; }

  /* ═══════════════════════════════════════════════════════
     STATE — declarado antes de qualquer uso
  ═══════════════════════════════════════════════════════ */
  let MODE        = 'text';   // 'text' | 'voice'
  let VOICE_STATE = 'idle';   // 'idle' | 'listening' | 'thinking' | 'speaking' | 'error'
  let currentSession = 0;
  let messageCount   = 0;
  let toastTimer;
  let waveAnimId, ringAnimId, particleAnimId;
  let voiceSimTimer;

  /* ═══════════════════════════════════════════════════════
     DATASET — SESSÕES E RESPOSTAS SIMULADAS
  ═══════════════════════════════════════════════════════ */
  const SESSIONS = [
    { id:1, name:'Análise de ameaças',   last:'Mostre os top IPs atacantes', time:'14:32', active:true  },
    { id:2, name:'Relatório diário',      last:'Gere relatório do SOC',       time:'11:08', active:false },
    { id:3, name:'Config. Firewall',      last:'Listar regras ativas',        time:'09:45', active:false },
    { id:4, name:'Sessão de ontem',       last:'Status DNS e rede',           time:'Ontem', active:false },
  ];



  const VOICE_TRANSCRIPTS = [
    'Resumo do SOC por favor',
    'Mostre os top IPs atacantes',
    'Qual o status do firewall?',
    'Tem algum dispositivo suspeito?',
    'Gera um relatório agora',
    'Como está o DNS?',
    'Ver mapa de ameaças',
    'Tem algum alerta crítico?',
  ];

  const SOC_ALERTS = [
    { sev:'critical', desc:'Port scan — 185.22.11.4',    time:'14:32' },
    { sev:'high',     desc:'Brute force SSH — 91.108.4', time:'13:18' },
    { sev:'medium',   desc:'DNS anômalo detectado',      time:'11:44' },
    { sev:'low',      desc:'Novo dispositivo na rede',   time:'09:20' },
  ];

  /* ═══════════════════════════════════════════════════════
     INIT
  ═══════════════════════════════════════════════════════ */
  updateLiveTime();
  setInterval(updateLiveTime, 30000);
  renderSessions();
  renderAlerts();
  renderConsoleEntry('system', 'Moon AI iniciado · versão 1.0');
  renderConsoleEntry('info',   'Conectado ao contexto de rede');
  renderConsoleEntry('info',   'Modo: Texto · Aguardando input');
  startRingCanvas();
  startWaveCanvas();

  /* ═══════════════════════════════════════════════════════
     LIVE TIME
  ═══════════════════════════════════════════════════════ */
  function updateLiveTime() {
    $('jarLastUpdate').textContent = `Atualizado ${nowStr()}`;
  }

  /* ═══════════════════════════════════════════════════════
     SESSIONS
  ═══════════════════════════════════════════════════════ */
  function renderSessions() {
    $('jarSessionsList').innerHTML = SESSIONS.map(s => `
      <div class="jar-session-item ${s.active ? 'jar-session-item--active' : ''}" data-sid="${s.id}">
        <div class="jar-session-item__info">
          <p class="jar-session-item__name">${s.name}</p>
          <p class="jar-session-item__last">${s.last}</p>
        </div>
        <span class="jar-session-item__time">${s.time}</span>
      </div>`).join('');

    document.querySelectorAll('.jar-session-item').forEach(el => {
      el.addEventListener('click', () => {
        SESSIONS.forEach(s => s.active = s.id === +el.dataset.sid);
        renderSessions();
        showToast(`Sessão "${SESSIONS.find(s=>s.id===+el.dataset.sid)?.name}" carregada`);
      });
    });
  }

  $('jarNewSessionBtn').addEventListener('click', () => {
    const newS = { id: Date.now(), name: `Sessão ${SESSIONS.length+1}`, last: 'Nova conversa', time: nowStr(), active: true };
    SESSIONS.forEach(s => s.active = false);
    SESSIONS.unshift(newS);
    renderSessions();
    clearChat();
    showToast('Nova sessão criada');
    renderConsoleEntry('info', 'Nova sessão iniciada');
  });

  /* ═══════════════════════════════════════════════════════
     ALERTS
  ═══════════════════════════════════════════════════════ */
  function renderAlerts() {
    $('jarAlertsList').innerHTML = SOC_ALERTS.map(a => `
      <div class="jar-alert-item jar-alert-item--${a.sev}">
        <span class="jar-alert-dot"></span>
        <div class="jar-alert-info">
          <p class="jar-alert-desc">${a.desc}</p>
          <p class="jar-alert-time">${a.time}</p>
        </div>
      </div>`).join('');
  }

  /* ═══════════════════════════════════════════════════════
     CONSOLE
  ═══════════════════════════════════════════════════════ */
  function renderConsoleEntry(type, msg) {
    const console = $('jarConsole');
    const el = document.createElement('div');
    el.className = `jar-console-line jar-console-line--${type}`;
    el.innerHTML = `<span class="jar-console-time">${timeStr()}</span><span class="jar-console-msg">${msg}</span>`;
    console.appendChild(el);
    while (console.children.length > 20) console.removeChild(console.firstChild);
    console.scrollTop = console.scrollHeight;
  }

  /* ═══════════════════════════════════════════════════════
     MODE TOGGLE
  ═══════════════════════════════════════════════════════ */
  function setMode(mode) {
    MODE = mode;
    const wrap = $('jarWrapper');
    wrap.classList.toggle('is-text',  mode === 'text');
    wrap.classList.toggle('is-voice', mode === 'voice');

    const btn   = $('jarModeToggleBtn');
    const label = $('jarModeLabel');
    const ind   = $('jarModeIndicator');

    if (mode === 'voice') {
      btn.innerHTML   = '<i class="bi bi-chat-dots-fill"></i><span>Modo Texto</span>';
      label.textContent = 'Modo: Voz';
      ind.querySelector('i').className = 'bi bi-soundwave';
      setVoiceState('idle');
      renderConsoleEntry('info', 'Modo voz ativado');
      showToast('Modo Voz ativado');
    } else {
      btn.innerHTML   = '<i class="bi bi-soundwave"></i><span>Modo Voz</span>';
      label.textContent = 'Modo: Texto';
      ind.querySelector('i').className = 'bi bi-chat-dots-fill';
      cancelVoiceSim();
      setVoiceState('idle');
      renderConsoleEntry('info', 'Modo texto ativado');
      showToast('Modo Texto ativado');
    }
  }

  $('jarModeToggleBtn').addEventListener('click', () => setMode(MODE === 'text' ? 'voice' : 'text'));

  /* ═══════════════════════════════════════════════════════
     VOICE STATE MACHINE
  ═══════════════════════════════════════════════════════ */
  function setVoiceState(state) {
    VOICE_STATE = state;
    const wrap = $('jarWrapper');
    ['v-idle','v-listening','v-thinking','v-speaking','v-error'].forEach(c => wrap.classList.remove(c));
    wrap.classList.add('v-' + state);

    const status    = $('jarVoiceStatus');
    const hi        = $('jarVoiceHi');
    const title     = $('jarVoiceTitle');
    const transcript= $('jarTranscript');
    const micPerm   = $('jarMicPermission');

    micPerm.style.display = state === 'error' ? 'flex' : 'none';
    transcript.style.display = ['thinking','speaking'].includes(state) ? 'block' : 'none';

    const texts = {
      idle:      { status:'What can I help you with?',  hi:'Hi',   title:'MoonShield' },
      listening: { status:'Ouvindo…',                   hi:'👂',   title:'Escutando' },
      thinking:  { status:'Processando…',               hi:'🤔',   title:'Pensando' },
      speaking:  { status:'Respondendo…',               hi:'💬',   title:'Falando' },
      error:     { status:'Sem acesso ao microfone',    hi:'⚠️',   title:'Erro' },
    };

    const t = texts[state] || texts.idle;
    status.textContent = t.status;
    hi.textContent     = t.hi;
    title.textContent  = t.title;

    renderConsoleEntry('info', `voice.state → ${state}`);
  }

  /* ═══════════════════════════════════════════════════════
     MIC BUTTON — simulação
  ═══════════════════════════════════════════════════════ */
  $('jarMicBtn').addEventListener('click', () => {
    if (VOICE_STATE === 'idle') startVoiceSim();
    else cancelVoiceSim();
  });

  $('jarStopBtn').addEventListener('click', () => {
    cancelVoiceSim();
    setVoiceState('idle');
  });

  $('jarReplayBtn').addEventListener('click', () => {
    if (VOICE_STATE === 'idle') {
      showToast('Nenhuma resposta para repetir');
      return;
    }
    setVoiceState('speaking');
    setTimeout(() => setVoiceState('idle'), 3000);
  });

  $('jarMicRetryBtn')?.addEventListener('click', () => setVoiceState('idle'));

  function startVoiceSim() {
    const transcript = pick(VOICE_TRANSCRIPTS);
    setVoiceState('listening');

    voiceSimTimer = setTimeout(() => {
      $('jarLiveTranscript').textContent = `Você disse: "${transcript}"`;
      setVoiceState('thinking');
      renderConsoleEntry('info', `intent.detect: "${transcript}"`);
      renderConsoleEntry('info', 'tool: none (simulado)');

      voiceSimTimer = setTimeout(() => {
        const resp = getAIResponse(transcript);
        $('jarLiveResponse').textContent = 'MoonShield: ' + resp.replace(/\*\*/g,'').replace(/\n/g,' ').slice(0, 120) + '…';
        setVoiceState('speaking');
        renderConsoleEntry('system', 'response.sent');

        voiceSimTimer = setTimeout(() => {
          setVoiceState('idle');
          // Adiciona ao chat texto também
          addMessage('user', transcript);
          setTimeout(() => addMessage('ai', resp), 400);
        }, 3500);
      }, 1800);
    }, 2200);
  }

  function cancelVoiceSim() {
    clearTimeout(voiceSimTimer);
    setVoiceState('idle');
  }

  // Espaço = toggle mic no modo voz
  document.addEventListener('keydown', e => {
    if (e.code === 'Space' && MODE === 'voice' && document.activeElement.tagName !== 'TEXTAREA' && document.activeElement.tagName !== 'INPUT') {
      e.preventDefault();
      $('jarMicBtn').click();
    }
    if (e.key === 'Escape') {
      cancelVoiceSim();
      closeSettings();
    }
  });

  /* ═══════════════════════════════════════════════════════
     CHAT — MODO TEXTO
  ═══════════════════════════════════════════════════════ */
  function addMessage(role, text) {
    const empty = $('jarChatEmpty');
    if (empty) empty.style.display = 'none';

    messageCount++;
    const chat = $('jarChat');
    const el   = document.createElement('div');
    el.className = `jar-msg jar-msg--${role}`;

    const html = formatMarkdown(text);
    el.innerHTML = `
      <div class="jar-msg__avatar">
        ${role === 'user'
          ? '<i class="bi bi-person-fill"></i>'
          : '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a5 5 0 0 1 5 5v3a5 5 0 0 1-10 0V7a5 5 0 0 1 5-5z"/><path d="M15 13a6 6 0 0 1-6 0"/></svg>'
        }
      </div>
      <div class="jar-msg__content">
        <div class="jar-msg__bubble">${html}</div>
        <p class="jar-msg__meta">${timeStr()}</p>
      </div>`;

    el.style.animation = 'jarMsgIn .25s var(--ease) both';
    chat.appendChild(el);
    chat.scrollTop = chat.scrollHeight;
  }

  function formatMarkdown(text) {
    return text
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/`(.+?)`/g, '<code>$1</code>')
      .replace(/•\s(.+)/g, '<li>$1</li>')
      .replace(/(<li>.*<\/li>)/gs, '<ul>$1</ul>')
      .replace(/\n/g, '<br>');
  }

  function clearChat() {
    const chat = $('jarChat');
    chat.innerHTML = `
      <div class="jar-chat__empty" id="jarChatEmpty">
        <div class="jar-chat__empty-ring"></div>
        <p class="jar-chat__empty-title">Moon AI</p>
        <p class="jar-chat__empty-sub">Como posso ajudar você hoje?</p>
      </div>`;
    messageCount = 0;
  }

  function sendMessage(text) {
    text = text.trim();
    if (!text) return;

    addMessage('user', text);
    renderConsoleEntry('info', `user.input: "${text.slice(0,40)}…"`);

    // Mostrar typing
    $('jarTyping').style.display = 'flex';
    $('jarInput').value = '';
    autoResize($('jarInput'));

    const delay = rand(800, 1800);
    setTimeout(() => {
      $('jarTyping').style.display = 'none';
      const resp = getAIResponse(text);
      addMessage('ai', resp);
      renderConsoleEntry('system', 'response.sent');
      renderConsoleEntry('info', `intent: ${detectIntent(text)}`);
    }, delay);
  }

  function getAIResponse(input) {
    return 'Moon AI ainda não está disponível nesta versão.';
  }

  function detectIntent(input) {
    const lower = input.toLowerCase();
    if (lower.includes('soc'))       return 'query.soc_summary';
    if (lower.includes('ip'))        return 'query.top_ips';
    if (lower.includes('dns'))       return 'query.dns_status';
    if (lower.includes('firewall'))  return 'query.firewall';
    if (lower.includes('relat'))     return 'action.generate_report';
    if (lower.includes('bloqu'))     return 'action.block_domain';
    return 'query.general';
  }

  // Send button
  $('jarSendBtn').addEventListener('click', () => sendMessage($('jarInput').value));

  // Enter key
  $('jarInput').addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage($('jarInput').value);
    }
  });

  // Auto resize textarea
  $('jarInput').addEventListener('input', () => autoResize($('jarInput')));

  function autoResize(el) {
    el.style.height = 'auto';
    el.style.height = Math.min(el.scrollHeight, 160) + 'px';
  }

  // Attach btn (fake)
  $('jarAttachBtn').addEventListener('click', () => showToast('Anexo simulado — sem backend disponível'));

  // Clear chat
  $('jarClearChatBtn').addEventListener('click', () => {
    clearChat();
    renderConsoleEntry('info', 'chat.cleared');
    showToast('Chat limpo');
  });

  // Quick prompts
  document.querySelectorAll('.jar-qp-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const prompt = btn.dataset.prompt;
      if (MODE === 'text') {
        $('jarInput').value = prompt;
        sendMessage(prompt);
      } else {
        showToast(`Prompt enviado: ${prompt}`);
        $('jarInput').value = prompt;
      }
    });
  });

  // Ações sugeridas (exposta globalmente)
  window.jarSendQuick = function(text) {
    if (MODE === 'text') {
      setMode('text');
      sendMessage(text);
    } else {
      showToast('Alternando para modo texto…');
      setMode('text');
      setTimeout(() => sendMessage(text), 300);
    }
  };

  /* ═══════════════════════════════════════════════════════
     SETTINGS DRAWER
  ═══════════════════════════════════════════════════════ */
  $('jarSettingsBtn').addEventListener('click', () => {
    $('jarSettingsDrawer').classList.add('open');
    $('jarSettingsOverlay').classList.add('open');
  });

  function closeSettings() {
    $('jarSettingsDrawer').classList.remove('open');
    $('jarSettingsOverlay').classList.remove('open');
  }

  $('jarSettingsClose').addEventListener('click', closeSettings);
  $('jarSettingsOverlay').addEventListener('click', closeSettings);

  // Sliders
  $('cfgSpeed').addEventListener('input', e => {
    $('cfgSpeedVal').textContent = (+e.target.value).toFixed(1) + 'x';
  });
  $('cfgMicSens').addEventListener('input', e => {
    $('cfgMicSensVal').textContent = e.target.value;
  });

  // Cinema mode sync
  $('cfgCinema').addEventListener('change', e => {
    $('jarWrapper').classList.toggle('jar-cinema', e.target.checked);
    $('cfgCinema2').checked = e.target.checked;
    showToast(e.target.checked ? 'Modo cinema ativado' : 'Modo cinema desativado');
  });
  $('cfgCinema2').addEventListener('change', e => {
    $('jarWrapper').classList.toggle('jar-cinema', e.target.checked);
    $('cfgCinema').checked = e.target.checked;
  });

  /* ═══════════════════════════════════════════════════════
     RING CANVAS — anel animado (modo voz)
  ═══════════════════════════════════════════════════════ */
  function startRingCanvas() {
    const canvas = $('jarRingCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const W = canvas.width, H = canvas.height;
    const cx = W/2, cy = H/2, r = 110;
    let angle = 0;

    function drawRing() {
      ctx.clearRect(0, 0, W, H);

      const stateMulti = {
        idle:      { speed: 0.004, glow: 14, alpha: 0.7,  width: 3   },
        listening: { speed: 0.018, glow: 28, alpha: 1,    width: 5   },
        thinking:  { speed: 0.025, glow: 20, alpha: 0.9,  width: 4   },
        speaking:  { speed: 0.012, glow: 36, alpha: 1,    width: 6   },
        error:     { speed: 0.005, glow: 8,  alpha: 0.5,  width: 2.5 },
      }[VOICE_STATE] || { speed:0.004, glow:14, alpha:0.7, width:3 };

      angle += stateMulti.speed;

      // Múltiplos arcos para efeito de fluxo
      for (let i = 0; i < 3; i++) {
        const offset = (i * Math.PI * 2) / 3;
        const arcStart = angle + offset;
        const arcEnd   = arcStart + Math.PI * 1.4;

        const grad = ctx.createLinearGradient(
          cx + r * Math.cos(arcStart), cy + r * Math.sin(arcStart),
          cx + r * Math.cos(arcEnd),   cy + r * Math.sin(arcEnd)
        );
        grad.addColorStop(0, `rgba(30, 100, 255, 0)`);
        grad.addColorStop(0.4, `rgba(80, 160, 255, ${stateMulti.alpha})`);
        grad.addColorStop(0.6, `rgba(140, 220, 255, ${stateMulti.alpha})`);
        grad.addColorStop(1, `rgba(30, 100, 255, 0)`);

        ctx.beginPath();
        ctx.arc(cx, cy, r, arcStart, arcEnd);
        ctx.strokeStyle = grad;
        ctx.lineWidth = stateMulti.width;
        ctx.shadowColor = '#4090ff';
        ctx.shadowBlur = stateMulti.glow;
        ctx.globalAlpha = stateMulti.alpha - i * 0.2;
        ctx.stroke();
        ctx.globalAlpha = 1;
        ctx.shadowBlur = 0;
      }

      // Breathing glow no listening
      if (VOICE_STATE === 'listening') {
        const breathe = Math.sin(Date.now() / 400) * 0.5 + 0.5;
        ctx.beginPath();
        ctx.arc(cx, cy, r + 8, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(80, 160, 255, ${breathe * 0.3})`;
        ctx.lineWidth = 12;
        ctx.shadowColor = '#60a0ff';
        ctx.shadowBlur = 20;
        ctx.stroke();
        ctx.shadowBlur = 0;
      }

      ringAnimId = requestAnimationFrame(drawRing);
    }

    drawRing();
  }

  /* ═══════════════════════════════════════════════════════
     WAVEFORM CANVAS — onda estilo Siri (imagens 1 e 3)
  ═══════════════════════════════════════════════════════ */
  function startWaveCanvas() {
    const canvas = $('jarWave');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const W = canvas.width, H = canvas.height;
    let t = 0;

    // Configuração das barras (estilo imagem 3)
    const BARS  = 48;
    const BAR_W = 4;
    const GAP   = 4;
    const totalW = BARS * (BAR_W + GAP);
    const startX = (W - totalW) / 2;

    function drawWave() {
      ctx.clearRect(0, 0, W, H);

      const amplitude = {
        idle:      0.12,
        listening: 0.75,
        thinking:  0.30,
        speaking:  0.85,
        error:     0.05,
      }[VOICE_STATE] || 0.12;

      const speed = {
        idle:      0.025,
        listening: 0.08,
        thinking:  0.05,
        speaking:  0.10,
        error:     0.01,
      }[VOICE_STATE] || 0.025;

      t += speed;

      for (let i = 0; i < BARS; i++) {
        const x = startX + i * (BAR_W + GAP);
        const center = BARS / 2;
        const dist   = Math.abs(i - center) / center;
        const envelope = Math.exp(-dist * dist * 3); // gaussiana
        const noise  = Math.sin(i * 0.4 + t) * 0.5 + Math.sin(i * 0.9 - t * 1.5) * 0.3 + Math.sin(i * 0.2 + t * 0.7) * 0.2;
        const barH   = Math.max(3, (0.5 + noise * 0.5) * amplitude * (H * 0.82) * envelope);

        // Gradiente por altura (azul escuro → ciano claro no centro)
        const hRatio = barH / (H * 0.82);
        const grad   = ctx.createLinearGradient(x, H/2 - barH, x, H/2 + barH);

        if (hRatio > 0.5) {
          grad.addColorStop(0,   `rgba(140, 220, 255, 0.9)`);
          grad.addColorStop(0.5, `rgba(80,  160, 255, 1.0)`);
          grad.addColorStop(1,   `rgba(140, 220, 255, 0.9)`);
        } else {
          grad.addColorStop(0,   `rgba(40,  100, 200, 0.6)`);
          grad.addColorStop(0.5, `rgba(60,  130, 230, 0.9)`);
          grad.addColorStop(1,   `rgba(40,  100, 200, 0.6)`);
        }

        // Glow nas barras centrais
        if (hRatio > 0.4) {
          ctx.shadowColor = '#60c0ff';
          ctx.shadowBlur  = 10 * hRatio;
        } else {
          ctx.shadowBlur = 0;
        }

        // Barra superior e inferior (simétrica)
        ctx.fillStyle = grad;
        ctx.beginPath();
        ctx.roundRect(x, H/2 - barH, BAR_W, barH * 2, 2);
        ctx.fill();
        ctx.shadowBlur = 0;
      }

      waveAnimId = requestAnimationFrame(drawWave);
    }

    drawWave();
  }

  /* ═══════════════════════════════════════════════════════
     TOAST
  ═══════════════════════════════════════════════════════ */
  function showToast(msg) {
    const t = $('jarToast');
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove('show'), 2800);
  }

  /* Animação de entrada de mensagem via CSS */
  document.head.appendChild(Object.assign(document.createElement('style'), {
    textContent: `
      @keyframes jarMsgIn {
        from { opacity:0; transform:translateY(10px) scale(.97); }
        to   { opacity:1; transform:none; }
      }
    `
  }));

});