/**
 * MOONSHIELD — ONBOARDING.JS  v14
 * 5 steps: Boas-vindas · Credenciais · Identidade · Avatar · Tema
 *
 * v13 — overlay final reformulado:
 *   - Removido "SEJA BEM-VINDO, [nome]" em estilo de login
 *   - Substituído por "Bem-vindo ao MoonShield" com escudo + nome do usuário
 *     como subtítulo discreto — visual próprio, distinto do welcome pós-login
 */

document.addEventListener('DOMContentLoaded', () => {

  const OB = window.OB || {};
  const TOTAL_STEPS = 5;

  /* ══ 1. CANVAS DE ESTRELAS (fundo do onboarding) ═══════ */
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
    const n = Math.floor((canvas.width * canvas.height) / 4200);
    for (let i = 0; i < n; i++) {
      stars.push({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        r: Math.random() * 1.1 + 0.2,
        phase: Math.random() * Math.PI * 2,
        speed: Math.random() * 0.005 + 0.002,
      });
    }
  }
  function drawStars(ts) {
    if (!ctx) return;
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    for (const s of stars) {
      const a = 0.2 + 0.6 * Math.abs(Math.sin(s.phase + ts * s.speed));
      ctx.beginPath();
      ctx.arc(s.x, s.y, s.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(200,220,255,${a.toFixed(2)})`;
      ctx.fill();
    }
    requestAnimationFrame(drawStars);
  }
  resizeCanvas();
  requestAnimationFrame(drawStars);
  window.addEventListener('resize', resizeCanvas);


  /* ══ 2. ESTADO GLOBAL ══════════════════════════════════ */
  let currentStep = 1;
  let avatarFile = null;
  let avatarColor = '#3b82f6';
  let chosenTheme = 'dark';

  const initials = OB.initials || (OB.username ? OB.username.slice(0, 2).toUpperCase() : 'OP');

  /* Greet */
  const greetEl = document.getElementById('greetName');
  if (greetEl) greetEl.textContent = OB.fullName || OB.username || 'operador';

  /* Avatar */
  const avatarPreview = document.getElementById('avatarPreview');
  const avatarInitials = document.getElementById('avatarInitials');
  const avatarImg = document.getElementById('avatarImg');
  if (avatarInitials) avatarInitials.textContent = initials;

  if (OB.avatarUrl && avatarImg) {
    avatarImg.src = OB.avatarUrl;
    avatarImg.style.display = 'block';
    if (avatarInitials) avatarInitials.style.display = 'none';
  }

  /* Tema salvo anteriormente */
  if (OB.tema === 'light') {
    const r = document.querySelector('input[name="obTheme"][value="light"]');
    if (r) r.checked = true;
    chosenTheme = 'light';
  }

  /* Aplica cor inicial do avatar */
  applyAvatarColor(avatarColor);


  /* ══ 3. NAVEGAÇÃO ══════════════════════════════════════ */
  function goToStep(n) {
    const prev = document.getElementById('step' + currentStep);
    const next = document.getElementById('step' + n);
    if (!prev || !next) return;

    prev.classList.remove('active');
    next.classList.add('active');

    updateSidebar(n);
    updateMobileBar(n);
    currentStep = n;

    const firstInput = next.querySelector('input:not([type="radio"]):not([type="hidden"])');
    if (firstInput) setTimeout(() => firstInput.focus(), 80);
  }

  function updateSidebar(n) {
    document.querySelectorAll('.ob-nav-step').forEach(el => {
      const s = parseInt(el.dataset.step);
      el.classList.remove('ob-nav-step--active', 'ob-nav-step--done');
      if (s < n) el.classList.add('ob-nav-step--done');
      else if (s === n) el.classList.add('ob-nav-step--active');
    });
  }

  function updateMobileBar(n) {
    const bar = document.getElementById('mobileBar');
    if (bar) bar.style.width = ((n / TOTAL_STEPS) * 100) + '%';
  }

  /* Botões avançar */
  document.getElementById('btnStep1Next')?.addEventListener('click', () => goToStep(2));
  document.getElementById('btnStep3Next')?.addEventListener('click', () => goToStep(4));
  document.getElementById('btnStep4Next')?.addEventListener('click', () => goToStep(5));

  /* Botões voltar */
  document.querySelectorAll('.ob-btn--back').forEach(btn => {
    btn.addEventListener('click', () => {
      const back = parseInt(btn.dataset.back);
      goToStep(back);
    });
  });

  /* Pular onboarding */
document.getElementById('btnSkip')?.addEventListener('click', () => {
    markComplete().finally(() => { window.location.href = OB.urls.dashboard; });
});


  /* ══ 4. STEP 2 — CREDENCIAIS ═══════════════════════════ */
  const fieldUsername = document.getElementById('fieldUsername');
  const fieldSenha = document.getElementById('fieldSenha');
  const fieldSenhaConfirm = document.getElementById('fieldSenhaConfirm');
  const confirmStatus = document.getElementById('confirmStatus');
  const usernameHint = document.getElementById('usernameHint');
  const confirmHint = document.getElementById('confirmHint');
  const strengthLabel = document.getElementById('strengthLabel');

  if (fieldUsername) fieldUsername.value = OB.username || '';

  document.getElementById('eyeSenha')?.addEventListener('click', () => {
    if (!fieldSenha) return;
    const isHidden = fieldSenha.type === 'password';
    fieldSenha.type = isHidden ? 'text' : 'password';
    document.getElementById('eyeIconHide').style.display = isHidden ? 'none' : 'block';
    document.getElementById('eyeIconShow').style.display = isHidden ? 'block' : 'none';
  });

  fieldSenha?.addEventListener('input', () => {
    const score = calcStrength(fieldSenha.value);
    const labels = ['', 'Fraca', 'Razoável', 'Boa', 'Forte'];
    const colors = ['', '#ef4444', '#f97316', '#eab308', '#22c55e'];
    for (let i = 1; i <= 4; i++) {
      const bar = document.getElementById('sbar' + i);
      if (!bar) continue;
      bar.className = 'ob-strength__bar' + (i <= score ? ' on-' + score : '');
    }
    if (strengthLabel) {
      strengthLabel.textContent = labels[score] || '';
      strengthLabel.style.color = colors[score] || 'var(--ob-dim)';
    }
    checkConfirm();
  });

  fieldSenhaConfirm?.addEventListener('input', checkConfirm);

  function calcStrength(p) {
    if (!p) return 0;
    let s = 0;
    if (p.length >= 8) s++;
    if (p.length >= 12) s++;
    if (/[A-Z]/.test(p) && /[a-z]/.test(p)) s++;
    if (/[0-9]/.test(p)) s++;
    if (/[^a-zA-Z0-9]/.test(p)) s++;
    return Math.min(4, Math.ceil(s * 0.8));
  }

  function checkConfirm() {
    if (!fieldSenha || !fieldSenhaConfirm) return;
    const s = fieldSenha.value;
    const c = fieldSenhaConfirm.value;
    if (!c) {
      setInputState(fieldSenhaConfirm, '');
      if (confirmStatus) confirmStatus.textContent = '';
      if (confirmHint) confirmHint.textContent = '';
      return;
    }
    if (s === c) {
      setInputState(fieldSenhaConfirm, 'ok');
      if (confirmStatus) { confirmStatus.textContent = '✓'; confirmStatus.style.color = '#22c55e'; }
      if (confirmHint) { confirmHint.textContent = 'Senhas conferem.'; confirmHint.style.color = '#22c55e'; }
    } else {
      setInputState(fieldSenhaConfirm, 'error');
      if (confirmStatus) { confirmStatus.textContent = '✕'; confirmStatus.style.color = '#ef4444'; }
      if (confirmHint) { confirmHint.textContent = 'Senhas não coincidem.'; confirmHint.style.color = '#ef4444'; }
    }
  }

  function setInputState(el, state) {
    el.classList.remove('is-error', 'is-ok');
    if (state === 'error') el.classList.add('is-error');
    if (state === 'ok') el.classList.add('is-ok');
  }

  document.getElementById('btnStep2Next')?.addEventListener('click', async () => {
    const username = fieldUsername?.value.trim() || '';
    const senha = fieldSenha?.value || '';
    const confirma = fieldSenhaConfirm?.value || '';

    if (!username) {
      shakeField(fieldUsername);
      if (usernameHint) { usernameHint.textContent = '⚠ Informe um nome de usuário.'; usernameHint.style.color = '#ef4444'; }
      return;
    }
    if (!/^[\w.@+\-]+$/.test(username)) {
      shakeField(fieldUsername);
      if (usernameHint) { usernameHint.textContent = '⚠ Apenas letras, números, @, ., +, -, _'; usernameHint.style.color = '#ef4444'; }
      return;
    }
    if (senha.length < 8) { shakeField(fieldSenha); return; }
    if (senha !== confirma) { shakeField(fieldSenhaConfirm); return; }

    const btn = document.getElementById('btnStep2Next');
    btn.classList.add('loading');
    btn.disabled = true;

    try {
      const res = await postJSON(OB.urls.salvarCredenciais, { username, senha });
      if (res.ok) {
        goToStep(3);
      } else {
        if (usernameHint) { usernameHint.textContent = '⚠ ' + (res.msg || 'Erro ao salvar.'); usernameHint.style.color = '#ef4444'; }
        shakeField(fieldUsername);
      }
    } catch (e) {
      if (usernameHint) { usernameHint.textContent = '⚠ Erro de conexão.'; usernameHint.style.color = '#ef4444'; }
    } finally {
      btn.classList.remove('loading');
      btn.disabled = false;
    }
  });

  function shakeField(el) {
    if (!el) return;
    const wrap = el.closest('.ob-input-wrap') || el;
    wrap.classList.add('ob-shake');
    wrap.addEventListener('animationend', () => wrap.classList.remove('ob-shake'), { once: true });
  }


  /* ══ 5. AVATAR ═════════════════════════════════════════ */
  document.querySelectorAll('.ob-color-dot').forEach(dot => {
    dot.addEventListener('click', () => {
      document.querySelectorAll('.ob-color-dot').forEach(d => d.classList.remove('active'));
      dot.classList.add('active');
      avatarColor = dot.dataset.color;
      applyAvatarColor(avatarColor);
    });
  });

  function applyAvatarColor(color) {
    if (!avatarPreview) return;
    avatarPreview.style.background = color + '18';
    avatarPreview.style.outline = `2px solid ${color}40`;
    avatarPreview.style.outlineOffset = '3px';
    if (avatarInitials) avatarInitials.style.color = color;
  }

  const avatarInput = document.getElementById('avatarInput');
  document.getElementById('btnUploadAvatar')?.addEventListener('click', () => {
    avatarInput?.click();
  });
  avatarInput?.addEventListener('change', e => {
    const file = e.target.files[0];
    if (!file) return;
    if (file.size > 2 * 1024 * 1024) {
      setHint('avatarHint', '⚠ Arquivo muito grande. Máx 2MB.', '#ef4444');
      return;
    }
    avatarFile = file;
    const reader = new FileReader();
    reader.onload = ev => {
      if (avatarImg) {
        avatarImg.src = ev.target.result;
        avatarImg.style.display = 'block';
        if (avatarInitials) avatarInitials.style.display = 'none';
      }
      setHint('avatarHint', '✓ Foto selecionada.', '#22c55e');
    };
    reader.readAsDataURL(file);
  });


  /* ══ 6. TEMA ═══════════════════════════════════════════ */
  document.querySelectorAll('input[name="obTheme"]').forEach(radio => {
    radio.addEventListener('change', () => { chosenTheme = radio.value; });
  });


  /* ══ 7. LAUNCH ═════════════════════════════════════════ */
document.getElementById('btnLaunch')?.addEventListener('click', async () => {
    const btn = document.getElementById('btnLaunch');
    btn.classList.add('loading');

    try {
        const displayName = document.getElementById('fieldDisplayName')?.value.trim() || '';
        const cargo = document.getElementById('fieldCargo')?.value.trim() || '';
        if (displayName || cargo) {
            await postJSON(OB.urls.salvarPerfil, { display_name: displayName, cargo });
        }
        if (avatarFile) {
            const fd = new FormData();
            fd.append('avatar', avatarFile);
            await fetch(OB.urls.uploadAvatar, {
                method: 'POST',
                headers: { 'X-CSRFToken': OB.csrfToken },
                body: fd,
            });
        }
        await postJSON(OB.urls.salvarPerfil, { avatar_color: avatarColor });
        await postJSON(OB.urls.salvarPrefs, { tema: chosenTheme });
        localStorage.setItem('jg_theme', chosenTheme);
        await markComplete();

        // SEM launchWelcome() aqui — o dashboard cuida disso
        window.location.href = OB.urls.dashboard;

    } catch (err) {
        console.error('Onboarding launch error:', err);
        window.location.href = OB.urls.dashboard;
    }
});

  /* ══ 8. LAUNCH WELCOME ══════════════════════════════════
   *
   * Overlay de transição entre o onboarding e o dashboard.
   * Intencionalmente DIFERENTE do welcome pós-login (welcome.js):
   *   - Foco em "Bem-vindo ao MoonShield" (produto), não no nome do usuário
   *   - Nome aparece só como subtítulo discreto ("Olá, Pedro")
   *   - Escudo SVG animado em vez do nome em tamanho de display
   *
   * ══════════════════════════════════════════════════════ */
  function launchWelcome(name, callback) {
    if (!document.getElementById('ms-welcome-inline-css')) {
      const style = document.createElement('style');
      style.id = 'ms-welcome-inline-css';
      style.textContent = `
        #msWelcomeOverlay{position:fixed;inset:0;z-index:9999;background:#06080f;display:flex;align-items:center;justify-content:center;overflow:hidden;animation:msOvIn .4s ease forwards;}
        @keyframes msOvIn{from{opacity:0}to{opacity:1}}
        #msWelcomeOverlay.ms-exit{animation:msWarpOut .7s cubic-bezier(.4,0,1,1) forwards;}
        @keyframes msWarpOut{0%{transform:scale(1);opacity:1;filter:blur(0)}35%{transform:scale(1.04);opacity:1;filter:blur(0)}100%{transform:scale(4.2);opacity:0;filter:blur(24px)}}
        #msStarsCanvas{position:absolute;inset:0;width:100%;height:100%;pointer-events:none;}
        .ms-ov-glow{position:absolute;border-radius:50%;pointer-events:none;}
        .ms-ov-glow--blue{width:800px;height:800px;top:50%;left:50%;transform:translate(-50%,-50%);background:radial-gradient(circle,rgba(59,130,246,.09) 0%,transparent 65%);animation:msGlowPulse 2.4s ease-in-out infinite alternate;}
        .ms-ov-glow--purple{width:500px;height:500px;top:50%;left:50%;transform:translate(-50%,-50%);background:radial-gradient(circle,rgba(168,85,247,.06) 0%,transparent 65%);animation:msGlowPulse 3s ease-in-out infinite alternate-reverse;}
        @keyframes msGlowPulse{from{opacity:.4}to{opacity:1}}

        .ms-ov-body{position:relative;z-index:10;display:flex;flex-direction:column;align-items:center;text-align:center;gap:0;animation:msBodyIn .8s cubic-bezier(.16,1,.3,1) .2s both;}
        @keyframes msBodyIn{from{opacity:0;transform:translateY(28px)}to{opacity:1;transform:none}}

        /* Escudo */
        .ms-ov-shield{margin-bottom:20px;animation:msShieldIn .7s cubic-bezier(.16,1,.3,1) .3s both;}
        @keyframes msShieldIn{from{opacity:0;transform:scale(.7)}to{opacity:1;transform:scale(1)}}
        .ms-ov-shield svg{filter:drop-shadow(0 0 18px rgba(147,197,253,.35));width:52px;height:52px;}

        /* "Bem-vindo ao" */
        .ms-ov-welcome-label{font-family:'Space Grotesk',sans-serif;font-size:clamp(13px,2vw,18px);font-weight:300;color:rgba(238,242,255,.45);margin:0 0 6px;letter-spacing:.01em;animation:msGreetIn .6s ease .55s both;}
        @keyframes msGreetIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}

        /* "MoonShield" — destaque principal */
        .ms-ov-brand{font-family:'Space Grotesk','DM Sans',sans-serif;font-size:clamp(36px,7vw,80px);font-weight:800;letter-spacing:-.04em;line-height:1;margin:0 0 22px;background:linear-gradient(135deg,#e0eaff 0%,#93c5fd 50%,#a78bfa 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;animation:msNameIn .8s cubic-bezier(.16,1,.3,1) .65s both;}
        @keyframes msNameIn{from{opacity:0;transform:translateY(14px) scale(.97);filter:blur(6px)}to{opacity:1;transform:none;filter:blur(0)}}

        .ms-ov-divider{width:40px;height:1px;background:linear-gradient(90deg,transparent,rgba(148,163,184,.3),transparent);margin:0 auto 16px;animation:msSubIn .5s ease 1s both;}

        /* "Olá, Nome — conta pronta" */
        .ms-ov-sub{font-family:'JetBrains Mono',monospace;font-size:11px;color:rgba(100,116,139,.85);letter-spacing:.06em;margin:0;animation:msSubIn .5s ease 1.1s both;}
        @keyframes msSubIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}

        .ms-ov-progress{position:absolute;bottom:0;left:0;height:1px;width:0%;background:linear-gradient(90deg,transparent,#3b82f6,#a855f7,transparent);animation:msProgress 5s linear .3s forwards;}
        @keyframes msProgress{from{width:0%}to{width:100%}}
        .ms-ov-status{position:absolute;bottom:24px;left:50%;transform:translateX(-50%);display:flex;align-items:center;gap:7px;animation:msSubIn .5s ease 1.3s both;}
        .ms-ov-status-dot{width:5px;height:5px;border-radius:50%;background:#22c55e;box-shadow:0 0 6px #22c55e;animation:msStatusPulse 2s ease-in-out infinite;}
        @keyframes msStatusPulse{0%,100%{opacity:1}50%{opacity:.25}}
        .ms-ov-status-txt{font-family:'JetBrains Mono',monospace;font-size:9px;color:rgba(34,197,94,.55);letter-spacing:.06em;white-space:nowrap;}
      `;
      document.head.appendChild(style);
    }

    const shell = document.querySelector('.ob-shell');
    if (shell) shell.style.opacity = '0';

    const ov = document.createElement('div');
    ov.id = 'msWelcomeOverlay';
    ov.innerHTML = `
      <canvas id="msStarsCanvas"></canvas>
      <div class="ms-ov-glow ms-ov-glow--blue"></div>
      <div class="ms-ov-glow ms-ov-glow--purple"></div>
      <div class="ms-ov-body">
        <div class="ms-ov-shield">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4" style="color:rgba(147,197,253,.8)">
            <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V7L12 2z"/>
          </svg>
        </div>
        <p class="ms-ov-welcome-label">Bem-vindo ao</p>
        <p class="ms-ov-brand">MoonShield</p>
        <div class="ms-ov-divider"></div>
        <p class="ms-ov-sub">Olá, ${escapeHtml(name)} &nbsp;·&nbsp; sua conta está pronta.</p>
      </div>
      <div class="ms-ov-status">
        <span class="ms-ov-status-dot"></span>
        <span class="ms-ov-status-txt">SISTEMAS OPERACIONAIS</span>
      </div>
      <div class="ms-ov-progress"></div>
    `;
    document.body.appendChild(ov);

    /* ── Warp Stars (idêntico ao original) ── */
    const wc = document.getElementById('msStarsCanvas');
    const wCtx = wc.getContext('2d');
    const N = 280;
    let W, H, wStars;

    function wResize() {
      W = wc.width = window.innerWidth;
      H = wc.height = window.innerHeight;
    }
    function wMakeStars() {
      wStars = Array.from({ length: N }, () => ({
        x: (Math.random() - .5) * (W || 1200),
        y: (Math.random() - .5) * (H || 800),
        z: Math.random() * (W || 1200),
        pz: W || 1200,
      }));
    }
    function wResetStar(s) {
      s.x = (Math.random() - .5) * W;
      s.y = (Math.random() - .5) * H;
      s.z = W;
      s.pz = W;
    }

    const DUR = 5000;
    let t0 = null;
    let rafId = null;

    function wDraw(ts) {
      if (!t0) t0 = ts;
      const p = Math.min((ts - t0) / DUR, 1);
      const speed = p < .4
        ? 0.3 + 5 * (p / .4)
        : 0.3 + 25 * ((p - .4) / .6);

      wCtx.fillStyle = 'rgba(6,8,15,0.2)';
      wCtx.fillRect(0, 0, W, H);

      const cx = W / 2, cy = H / 2;
      for (const s of wStars) {
        s.pz = s.z;
        s.z = Math.max(s.z - speed, 0.1);
        const sx = (s.x / s.z) * W + cx;
        const sy = (s.y / s.z) * H + cy;
        const spx = (s.x / s.pz) * W + cx;
        const spy = (s.y / s.pz) * H + cy;
        if (sx < 0 || sx > W || sy < 0 || sy > H) { wResetStar(s); continue; }
        const sz = Math.max((1 - s.z / W) * 3.2, 0.3);
        const sa = Math.min((1 - s.z / W) * 1.5, 1);
        wCtx.beginPath();
        wCtx.moveTo(spx, spy);
        wCtx.lineTo(sx, sy);
        wCtx.strokeStyle = `rgba(180,210,255,${sa.toFixed(2)})`;
        wCtx.lineWidth = sz;
        wCtx.stroke();
        wCtx.beginPath();
        wCtx.arc(sx, sy, sz * .5, 0, Math.PI * 2);
        wCtx.fillStyle = `rgba(220,235,255,${Math.min(sa * 1.3, 1).toFixed(2)})`;
        wCtx.fill();
      }

      if (p < 1) {
        rafId = requestAnimationFrame(wDraw);
      }
    }

    wResize();
    wMakeStars();
    const wResizeHandler = () => { wResize(); wMakeStars(); };
    window.addEventListener('resize', wResizeHandler);
    rafId = requestAnimationFrame(wDraw);

    setTimeout(() => {
      if (rafId) cancelAnimationFrame(rafId);
      window.removeEventListener('resize', wResizeHandler);
      ov.classList.add('ms-exit');
      setTimeout(() => {
        ov.remove();
        callback?.();
      }, 800);
    }, 5000);
  }

  function escapeHtml(str) {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }


  /* ══ 9. HELPERS ════════════════════════════════════════ */
  async function postJSON(url, data) {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': OB.csrfToken },
      body: JSON.stringify(data),
    });
    return res.json();
  }

  async function markComplete() {
    return postJSON(OB.urls.completar, {});
  }

  function setHint(id, msg, color) {
    const el = document.getElementById(id);
    if (el) { el.textContent = msg; el.style.color = color || ''; }
  }

  /* Init */
  updateSidebar(1);
  updateMobileBar(1);

});