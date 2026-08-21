/**
 * MOONSHIELD — LOGIN.JS  v8
 * Developed by Pedro Cavalcanti — BUILD-2026.05
 *
 * ESTRATÉGIA CORRETA:
 *  O form submete normalmente — Django controla o redirect.
 *  1ª vez  → Django manda para /auth/onboarding/
 *  2ª vez+ → Django manda para /painel/ → dashboard.js dispara o warp
 *
 *  Aqui cuidamos só do UX da tela de login:
 *  estrelas, lua (agora com terminador + glint + rotação lenta),
 *  terminal, toggle senha, shake, loader.
 */

document.addEventListener('DOMContentLoaded', () => {

  /* ══ 1. CANVAS DE ESTRELAS + LUA ════════════════════════════ */
  const canvas = document.getElementById('starsCanvas');
  const ctx = canvas ? canvas.getContext('2d') : null;
  let stars = [];

  function resizeCanvas() {
    if (!canvas) return;
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    buildStars();
  }

  function buildStars() {
    stars = [];
    const n = Math.floor((canvas.width * canvas.height) / 3500);
    for (let i = 0; i < n; i++) {
      stars.push({
        x: Math.random() * canvas.width, y: Math.random() * canvas.height,
        r: Math.random() * 1.4 + 0.2, phase: Math.random() * Math.PI * 2,
        speed: Math.random() * 0.006 + 0.002,
      });
    }
  }

  /* Crateras com profundidade base — a posição visível é recalculada
     a cada frame com uma leve rotação, pra lua parecer viva. */
  const CRATERS = [
    { rx: 0.28, ry: 0.35, r: 0.07 }, { rx: 0.55, ry: 0.22, r: 0.05 },
    { rx: 0.40, ry: 0.58, r: 0.09 }, { rx: 0.65, ry: 0.50, r: 0.04 },
    { rx: 0.20, ry: 0.60, r: 0.05 }, { rx: 0.72, ry: 0.32, r: 0.035 },
    { rx: 0.48, ry: 0.75, r: 0.045 },
  ];

  const MOON_ROT_SPEED = 0.000018;  // rotação bem lenta das crateras
  const GLINT_SPEED = 0.00042;      // brilho especular que varre a lua

  function drawMoon(c, cx, cy, radius, ts) {
    const rot = ts * MOON_ROT_SPEED;

    // Corpo base da lua
    const grad = c.createRadialGradient(cx - radius * .32, cy - radius * .32, radius * .05, cx, cy, radius);
    grad.addColorStop(0, 'rgba(58, 76, 104, 0.82)');
    grad.addColorStop(0.45, 'rgba(30, 42, 62, 0.74)');
    grad.addColorStop(0.8, 'rgba(14, 20, 32, 0.6)');
    grad.addColorStop(1, 'rgba(6, 10, 18, 0.0)');

    c.save();
    c.beginPath();
    c.arc(cx, cy, radius, 0, Math.PI * 2);
    c.clip();

    c.fillStyle = grad;
    c.fillRect(cx - radius, cy - radius, radius * 2, radius * 2);

    // Terminador — sombra suave de "lado escuro" que gira devagar,
    // dá a impressão de uma esfera real em vez de um círculo chapado
    const termAngle = rot * 6 + Math.PI * 0.15;
    const tx = cx + Math.cos(termAngle) * radius * 1.15;
    const ty = cy + Math.sin(termAngle) * radius * 1.15;
    const termGrad = c.createRadialGradient(tx, ty, radius * 0.2, tx, ty, radius * 2.1);
    termGrad.addColorStop(0, 'rgba(0,0,0,0)');
    termGrad.addColorStop(0.55, 'rgba(0,0,0,0)');
    termGrad.addColorStop(1, 'rgba(0,0,0,0.42)');
    c.fillStyle = termGrad;
    c.fillRect(cx - radius, cy - radius, radius * 2, radius * 2);

    // Crateras, levemente rotacionadas ao redor do centro
    for (const cr of CRATERS) {
      const dx0 = (cr.rx - 0.5) * radius * 2;
      const dy0 = (cr.ry - 0.5) * radius * 2;
      const cos = Math.cos(rot), sin = Math.sin(rot);
      const dx = dx0 * cos - dy0 * sin;
      const dy = dx0 * sin + dy0 * cos;
      const x = cx + dx, y = cy + dy, r = cr.r * radius;
      c.beginPath(); c.arc(x, y, r, 0, Math.PI * 2); c.fillStyle = 'rgba(0,0,0,0.30)'; c.fill();
      c.beginPath(); c.arc(x - r * .2, y - r * .2, r * .55, 0, Math.PI * 2); c.fillStyle = 'rgba(90,120,175,0.12)'; c.fill();
    }

    // Glint — arco de luz especular que varre lentamente a superfície
    const glintAngle = ts * GLINT_SPEED;
    const gx = cx + Math.cos(glintAngle) * radius * 0.5;
    const gy = cy + Math.sin(glintAngle) * radius * 0.5;
    const glintGrad = c.createRadialGradient(gx, gy, 0, gx, gy, radius * 0.55);
    glintGrad.addColorStop(0, 'rgba(150, 190, 255, 0.16)');
    glintGrad.addColorStop(1, 'rgba(150, 190, 255, 0)');
    c.fillStyle = glintGrad;
    c.fillRect(cx - radius, cy - radius, radius * 2, radius * 2);

    c.restore();

    // Anel de atmosfera / rim light
    c.save();
    c.beginPath(); c.arc(cx, cy, radius, 0, Math.PI * 2);
    c.strokeStyle = 'rgba(120,160,255,0.14)'; c.lineWidth = 2; c.stroke();
    c.beginPath(); c.arc(cx, cy, radius * 1.015, 0, Math.PI * 2);
    c.strokeStyle = 'rgba(120,160,255,0.05)'; c.lineWidth = 5; c.stroke();
    c.restore();
  }

  function drawScene(ts) {
    if (!ctx) return;
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    const moonR = Math.min(canvas.width, canvas.height) * 0.30;
    drawMoon(ctx, canvas.width + moonR * 0.32, -moonR * 0.32, moonR, ts);
    for (const s of stars) {
      const a = 0.35 + 0.65 * Math.sin(s.phase + ts * s.speed);
      ctx.beginPath(); ctx.arc(s.x, s.y, s.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(210,228,255,${a.toFixed(2)})`; ctx.fill();
    }
    if (!prefersReducedMotion) requestAnimationFrame(drawScene);
  }

  const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  resizeCanvas();
  requestAnimationFrame(drawScene);
  window.addEventListener('resize', () => {
    resizeCanvas();
    if (prefersReducedMotion) requestAnimationFrame(drawScene);
  });


  /* ══ 2. TERMINAL CMD ════════════════════════════════════════ */
  const termBody = document.getElementById('termBody');
  const LOG = [
    { time: '11:26:03', tag: 'BOOT', tc: 't-ok', msg: 'MoonShield v1.0 iniciado', mc: 't-white' },
    { time: '11:27:03', tag: 'NET', tc: 't-cyan', msg: 'Interface eth0 — ativa', mc: 't-ok' },
    { time: '11:28:03', tag: 'IDS', tc: 't-cyan', msg: 'Suricata engine — online', mc: 't-ok' },
    { time: '11:29:03', tag: 'DNS', tc: 't-cyan', msg: 'AdGuard Home — conectado', mc: 't-ok' },
    { time: '11:30:03', tag: 'FW', tc: 't-purple', msg: '15 regras carregadas', mc: 't-white' },
    { time: '11:30:19', tag: 'SOC', tc: 't-cyan', msg: 'Sensor Linux — respondendo', mc: 't-ok' },
    { time: '11:30:20', tag: 'GEO', tc: 't-info', msg: 'Geolocalização — ativa', mc: 't-white' },
    { time: '11:30:20', tag: 'ALRT', tc: 't-warn', msg: '3 alertas pendentes', mc: 't-warn' },
    { time: '11:30:20', tag: 'MAP', tc: 't-cyan', msg: 'Globo 3D — carregado', mc: 't-ok' },
    { time: '11:30:21', tag: 'AUTH', tc: 't-purple', msg: 'Aguardando operador...', mc: 't-white' },
    { time: '11:30:22', tag: '────', tc: 't-dash', msg: '─────────────────────────', mc: 't-dash' },
    { time: '11:30:22', tag: 'SCAN', tc: 't-pink', msg: 'Varredura ativa: 192.168/16', mc: 't-white' },
    { time: '11:30:23', tag: 'DEV', tc: 't-cyan', msg: '14 dispositivos online', mc: 't-ok' },
    { time: '11:30:24', tag: 'DEV', tc: 't-cyan', msg: '6 dispositivos offline', mc: 't-warn' },
    { time: '11:30:24', tag: 'TLS', tc: 't-info', msg: 'Certificados válidos', mc: 't-ok' },
  ];
  let termIdx = 0;

  function addLine() {
    if (!termBody) return;
    if (termIdx >= LOG.length) {
      const cur = document.createElement('div');
      cur.className = 't-line';
      cur.innerHTML = `<span class="t-time">       </span><span class="t-cursor"></span>`;
      termBody.appendChild(cur);
      termBody.scrollTop = termBody.scrollHeight;
      setTimeout(() => { termBody.innerHTML = ''; termIdx = 0; setTimeout(addLine, 400); }, 7000);
      return;
    }
    const e = LOG[termIdx++];
    const el = document.createElement('div');
    el.className = 't-line';
    if (e.tag === '────') {
      el.innerHTML = `<span class="t-time">${e.time}</span><span class="t-dash">${e.msg}</span>`;
    } else {
      el.innerHTML =
        `<span class="t-time">${e.time}</span>` +
        `<span class="t-tag ${e.tc}">${e.tag}</span>` +
        `<span class="${e.mc}">${e.msg}</span>`;
    }
    termBody.appendChild(el);
    termBody.scrollTop = termBody.scrollHeight;
    setTimeout(addLine, e.tag === '────' ? 80 : 300 + Math.random() * 600);
  }
  setTimeout(addLine, 800);


  /* ══ 3. TOGGLE SENHA ════════════════════════════════════════ */
  const toggleBtn = document.getElementById('togglePw');
  const passwordInput = document.getElementById('password');
  const eyeIcon = document.getElementById('eyeIcon');
  const OPEN = `<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>`;
  const CLOSED = `<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/>`;
  if (toggleBtn && passwordInput) {
    toggleBtn.addEventListener('click', () => {
      const isPw = passwordInput.type === 'password';
      passwordInput.type = isPw ? 'text' : 'password';
      eyeIcon.innerHTML = isPw ? CLOSED : OPEN;
    });
  }


  /* ══ 4. SUBMIT — form normal, Django controla redirect ══════
   *
   *  NÃO usamos fetch/redirect:manual.
   *  O Django decide: onboarding (1ª vez) ou painel (2ª vez+).
   *  O warp de boas-vindas é disparado pelo dashboard ao carregar.
   * ══════════════════════════════════════════════════════════ */
  const loginForm = document.getElementById('loginForm');
  const submitBtn = document.getElementById('submitBtn');

  if (loginForm && submitBtn) {
    loginForm.addEventListener('submit', e => {
      if (submitBtn.classList.contains('is-loading')) { e.preventDefault(); return; }
      const user = document.getElementById('username')?.value.trim();
      const pw = passwordInput?.value.trim();
      if (!user || !pw) { e.preventDefault(); shakeCard(); return; }
      submitBtn.classList.add('is-loading');
      /* Form submete normalmente — Django redireciona */
    });
  }


  /* ══ 5. SHAKE + FOCO ════════════════════════════════════════ */
  function shakeCard() {
    const card = document.getElementById('loginCard');
    if (!card) return;
    card.style.animation = 'none';
    card.offsetHeight;
    card.style.animation = 'shake 0.4s ease';
  }

  const s = document.createElement('style');
  s.textContent = `@keyframes shake{0%{transform:translateX(0)}20%{transform:translateX(-7px)}40%{transform:translateX(7px)}60%{transform:translateX(-4px)}80%{transform:translateX(4px)}100%{transform:translateX(0)}}`;
  document.head.appendChild(s);

  const usernameInput = document.getElementById('username');
  if (usernameInput) setTimeout(() => usernameInput.focus(), 700);
  if (usernameInput && passwordInput) {
    usernameInput.addEventListener('keydown', e => {
      if (e.key === 'Enter') { e.preventDefault(); passwordInput.focus(); }
    });
  }

});