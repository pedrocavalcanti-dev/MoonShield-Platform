/**
 * MOONSHIELD — PERFIL.JS  v2.2
 * Sem localStorage — tudo persiste no banco SQLite.
 *
 * v2.2 — Fix tema:
 *   Ao trocar o radio de tema, salva no banco IMEDIATAMENTE
 *   via /autenticacao/api/ui/tema/ — não espera "Salvar Preferências".
 */

document.addEventListener("DOMContentLoaded", () => {

  const P    = window.PERFIL;   // injetado pelo template
  const CSRF = P.csrfToken;

  /* ════════════════════════════════════════════════════════════
     UTILS
  ════════════════════════════════════════════════════════════ */
  const $ = id => document.getElementById(id);

  /* ── Toast stack ─────────────────────────────────────────── */
  const TOAST_ICONS = {
    ok:   "bi-check-circle-fill",
    err:  "bi-x-circle-fill",
    warn: "bi-exclamation-triangle-fill",
    info: "bi-info-circle-fill",
  };

  function showToast(msg, type = "ok", duration = 3200) {
    const container = $("toastContainer");
    if (!container) return;

    const toast = document.createElement("div");
    toast.className = `prf-toast prf-toast--${type}`;
    toast.innerHTML = `
      <i class="bi ${TOAST_ICONS[type] || TOAST_ICONS.info} prf-toast__icon"></i>
      <span>${msg}</span>
    `;

    container.prepend(toast);

    requestAnimationFrame(() => {
      requestAnimationFrame(() => toast.classList.add("prf-toast--visible"));
    });

    setTimeout(() => {
      toast.classList.add("prf-toast--hiding");
      toast.classList.remove("prf-toast--visible");
      setTimeout(() => toast.remove(), 250);
    }, duration);
  }

  /* ── Fetch helpers ───────────────────────────────────────── */
  async function apiPost(url, body) {
    const res = await fetch(url, {
      method:  "POST",
      headers: { "Content-Type": "application/json", "X-CSRFToken": CSRF },
      body:    JSON.stringify(body),
    });
    return res.json();
  }

  /* ── Botão loading ───────────────────────────────────────── */
  function setLoading(btn, on) {
    if (!btn) return;
    if (on) {
      btn.dataset.origHtml = btn.innerHTML;
      btn.innerHTML = '<i class="bi bi-arrow-repeat spin"></i> Aguarde…';
      btn.disabled = true;
    } else {
      btn.innerHTML = btn.dataset.origHtml || btn.innerHTML;
      btn.disabled = false;
    }
  }

  /* Spin CSS dinâmico */
  const styleTag = document.createElement("style");
  styleTag.textContent = `.spin { animation: spin360 .8s linear infinite; display:inline-block; }
  @keyframes spin360 { to { transform: rotate(360deg); } }`;
  document.head.appendChild(styleTag);


  /* ════════════════════════════════════════════════════════════
     TABS DE NAVEGAÇÃO
  ════════════════════════════════════════════════════════════ */
  document.querySelectorAll(".prf-tab").forEach(tab => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".prf-tab").forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".prf-panel").forEach(p => p.classList.remove("active"));
      tab.classList.add("active");
      const target = $(tab.dataset.target);
      if (target) target.classList.add("active");

      if (tab.dataset.target === "tab-ambiente") loadSysInfo();
    });
  });


  /* ════════════════════════════════════════════════════════════
     UPLOAD DE AVATAR
  ════════════════════════════════════════════════════════════ */
  const avatarInput    = $("avatarInput");
  const avatarImg      = $("avatarImg");
  const avatarInitials = $("avatarInitials");
  const avatarStatus   = $("avatarStatus");
  const navAvatar      = $("navAvatar");

  avatarInput?.addEventListener("change", async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    // Validação de tamanho (2MB)
    if (file.size > 2 * 1024 * 1024) {
      showToast("Arquivo muito grande. Máx. 2MB.", "err");
      return;
    }

    // Preview local imediato
    const reader = new FileReader();
    reader.onload = ev => {
      if (avatarImg)      { avatarImg.src = ev.target.result; avatarImg.style.display = "block"; }
      if (avatarInitials) avatarInitials.style.display = "none";
    };
    reader.readAsDataURL(file);

    if (avatarStatus) avatarStatus.textContent = "Enviando…";

    const formData = new FormData();
    formData.append("avatar", file);

    try {
      const res  = await fetch(P.urls.uploadAvatar, {
        method:  "POST",
        headers: { "X-CSRFToken": CSRF },
        body:    formData,
      });
      const data = await res.json();

      if (data.ok) {
        if (avatarStatus) avatarStatus.textContent = "";
        const stamp = `?t=${Date.now()}`;

        if (navAvatar && data.avatar_url) {
          navAvatar.innerHTML = `<img src="${data.avatar_url}${stamp}"
            style="width:100%;height:100%;object-fit:cover;border-radius:50%">`;
        }

        const topbarAvatar = document.getElementById("topbarAvatar");
        if (topbarAvatar && data.avatar_url) {
          topbarAvatar.innerHTML = `<img src="${data.avatar_url}${stamp}"
            style="width:100%;height:100%;object-fit:cover;border-radius:50%">`;
        }

        showToast("Foto atualizada com sucesso");
      } else {
        if (avatarStatus) avatarStatus.textContent = data.msg || "Erro no upload.";
        showToast(data.msg || "Erro no upload.", "err");
      }
    } catch {
      if (avatarStatus) avatarStatus.textContent = "Erro ao enviar.";
      showToast("Falha ao enviar foto.", "err");
    }
  });


  /* ════════════════════════════════════════════════════════════
     SALVAR INFORMAÇÕES PESSOAIS
  ════════════════════════════════════════════════════════════ */
  $("btnSalvarPerfil")?.addEventListener("click", async () => {
    const btn = $("btnSalvarPerfil");
    setLoading(btn, true);

    const parts     = ($("fieldFirstName")?.value || "").trim().split(/\s+/);
    const firstName = parts[0] || "";
    const lastName  = parts.slice(1).join(" ");

    try {
      const data = await apiPost(P.urls.salvarPerfil, {
        first_name:   firstName,
        last_name:    lastName,
        display_name: $("fieldDisplayName")?.value  || "",
        cargo:        $("fieldCargo")?.value        || "",
        departamento: $("fieldDepartamento")?.value || "",
        ramal:        $("fieldRamal")?.value        || "",
        bio:          $("fieldBio")?.value          || "",
      });

      if (data.ok) {
        showToast("Perfil atualizado");
        const displayName = $("fieldDisplayName")?.value || firstName;
        if ($("navName"))  $("navName").textContent  = displayName;
        if ($("navCargo")) $("navCargo").textContent = $("fieldCargo")?.value || "";

        const topbarName = document.getElementById("topbarUserName");
        if (topbarName) topbarName.textContent = displayName;

        const hint = $("perfilSaveHint");
        const now  = new Date();
        const fmt  = `${String(now.getDate()).padStart(2,"0")}/${String(now.getMonth()+1).padStart(2,"0")}/${now.getFullYear()} ${String(now.getHours()).padStart(2,"0")}:${String(now.getMinutes()).padStart(2,"0")}`;
        if (hint) hint.innerHTML = `<i class="bi bi-clock-history"></i> Salvo em ${fmt}`;
      } else {
        showToast(data.msg || "Erro ao salvar.", "err");
      }
    } catch {
      showToast("Falha na conexão.", "err");
    } finally {
      setLoading(btn, false);
    }
  });


  /* ════════════════════════════════════════════════════════════
     SALVAR CONTATO (email + telefone)
  ════════════════════════════════════════════════════════════ */
  $("btnSalvarContato")?.addEventListener("click", async () => {
    const btn = $("btnSalvarContato");
    setLoading(btn, true);

    try {
      const data = await apiPost(P.urls.salvarPerfil, {
        email:    $("fieldEmail")?.value    || "",
        telefone: $("fieldTelefone")?.value || "",
      });
      showToast(data.ok ? "Contato atualizado" : (data.msg || "Erro ao salvar."),
                data.ok ? "ok" : "err");
    } catch {
      showToast("Falha na conexão.", "err");
    } finally {
      setLoading(btn, false);
    }
  });


  /* ════════════════════════════════════════════════════════════
     TROCAR SENHA
  ════════════════════════════════════════════════════════════ */
  $("btnToggleSenha")?.addEventListener("click", () => {
    const wrap = $("formSenhaWrap");
    if (!wrap) return;
    const isOpen = wrap.style.display !== "none";
    wrap.style.display = isOpen ? "none" : "block";
  });

  $("btnCancelarSenha")?.addEventListener("click", () => {
    const wrap = $("formSenhaWrap");
    if (wrap) wrap.style.display = "none";
    [$("fieldSenhaAtual"), $("fieldNovaSenha"), $("fieldConfirmarSenha")]
      .forEach(el => { if (el) el.value = ""; });
  });

  $("btnConfirmarSenha")?.addEventListener("click", async () => {
    const novaSenha = $("fieldNovaSenha")?.value     || "";
    const confirmar = $("fieldConfirmarSenha")?.value || "";

    if (novaSenha.length < 8) {
      showToast("A nova senha precisa ter ao menos 8 caracteres.", "warn");
      return;
    }
    if (novaSenha !== confirmar) {
      showToast("As senhas não coincidem.", "warn");
      return;
    }

    const btn = $("btnConfirmarSenha");
    setLoading(btn, true);

    try {
      const data = await apiPost(P.urls.trocarSenha, {
        senha_atual: $("fieldSenhaAtual")?.value || "",
        nova_senha:  novaSenha,
        confirmar,
      });

      if (data.ok) {
        showToast("Senha alterada com sucesso");
        $("btnCancelarSenha")?.click();
      } else {
        showToast(data.msg || "Erro ao alterar senha.", "err");
      }
    } catch {
      showToast("Falha na conexão.", "err");
    } finally {
      setLoading(btn, false);
    }
  });


  /* ════════════════════════════════════════════════════════════
     CHAVE DE API
  ════════════════════════════════════════════════════════════ */
  let apiKeyVisible = false;
  let currentApiKey = P.apiKey || "";

  function renderApiKey() {
    const el = $("apiKeyVal"); if (!el) return;
    el.textContent = apiKeyVisible
      ? currentApiKey
      : (currentApiKey.slice(0, 6) || "jg_sk") + "••••••••••••••••••••••••••••••••";
  }
  renderApiKey();

  $("apiKeyToggle")?.addEventListener("click", () => {
    apiKeyVisible = !apiKeyVisible;
    const icon = $("apiKeyEyeIcon");
    if (icon) icon.className = apiKeyVisible ? "bi bi-eye-slash" : "bi bi-eye";
    renderApiKey();
  });

  $("btnCopyApiKey")?.addEventListener("click", () => {
    if (!currentApiKey) { showToast("Nenhuma chave disponível.", "warn"); return; }
    navigator.clipboard.writeText(currentApiKey)
      .then(() => showToast("Chave copiada para a área de transferência"))
      .catch(() => showToast("Não foi possível copiar.", "err"));
  });

  $("btnRegenApiKey")?.addEventListener("click", async () => {
    if (!confirm("Gerar nova API key? A chave atual ficará inválida imediatamente.")) return;
    const btn = $("btnRegenApiKey");
    setLoading(btn, true);

    try {
      const res  = await fetch(P.urls.regenKey, {
        method:  "POST",
        headers: { "X-CSRFToken": CSRF, "Content-Type": "application/json" },
        body:    "{}",
      });
      const data = await res.json();
      if (data.ok) {
        currentApiKey = data.api_key;
        apiKeyVisible = true;
        renderApiKey();
        const icon = $("apiKeyEyeIcon");
        if (icon) icon.className = "bi bi-eye-slash";
        showToast("Nova chave gerada. Guarde-a em local seguro.", "warn", 5000);
      } else {
        showToast(data.msg || "Erro ao gerar chave.", "err");
      }
    } catch {
      showToast("Falha na conexão.", "err");
    } finally {
      setLoading(btn, false);
    }
  });


  /* ════════════════════════════════════════════════════════════
     ENCERRAR SESSÕES
  ════════════════════════════════════════════════════════════ */
  $("btnEncerrarSessoes")?.addEventListener("click", async () => {
    if (!confirm("Isso vai encerrar TODAS as outras sessões. Continuar?")) return;
    const btn = $("btnEncerrarSessoes");
    setLoading(btn, true);

    try {
      const res  = await fetch(P.urls.encerrarSessoes, {
        method:  "POST",
        headers: { "X-CSRFToken": CSRF, "Content-Type": "application/json" },
        body:    "{}",
      });
      const data = await res.json();
      showToast(data.msg || (data.ok ? "Sessões encerradas." : "Erro."),
                data.ok ? "ok" : "err");
    } catch {
      showToast("Falha na conexão.", "err");
    } finally {
      setLoading(btn, false);
    }
  });


  /* ════════════════════════════════════════════════════════════
     SYSINFO — ABA AMBIENTE
  ════════════════════════════════════════════════════════════ */
  const SYS_ICONS = {
    os:       "bi-window-desktop",
    hostname: "bi-pc",
    ip:       "bi-wifi",
    python:   "bi-code-slash",
    uptime:   "bi-clock-history",
    cpu:      "bi-cpu",
    ram:      "bi-memory",
    disk:     "bi-hdd",
    kernel:   "bi-layers",
    arch:     "bi-cpu-fill",
  };

  const SYS_LABELS = {
    os:       "Sistema Operacional",
    hostname: "Hostname",
    ip:       "IP Local",
    python:   "Python",
    uptime:   "Uptime do Sistema",
    cpu:      "Processador",
    ram:      "Memória RAM",
    disk:     "Armazenamento",
    kernel:   "Kernel",
    arch:     "Arquitetura",
  };

  let sysInfoLoaded = false;

  async function loadSysInfo() {
    const grid = $("sysInfoGrid");
    if (!grid) return;

    if (sysInfoLoaded && !grid.dataset.forceReload) return;
    grid.dataset.forceReload = "";

    grid.innerHTML = Array(5).fill(
      `<div class="prf-sys-skeleton"></div>`
    ).join("");

    const btn  = $("btnRefreshEnv");
    const icon = $("refreshIcon");
    if (btn)  btn.disabled = true;
    if (icon) icon.classList.add("spin");

    try {
      const res  = await fetch(P.urls.sysinfo, {
        headers: { Accept: "application/json" },
      });
      const data = await res.json();
      const info = data.sysinfo || {};

      const priority  = ["os", "hostname", "ip", "python", "uptime", "cpu", "ram", "disk", "kernel", "arch"];
      const available = priority.filter(k => info[k] !== undefined && info[k] !== null && info[k] !== "");
      const fields    = available.length
        ? available
        : Object.keys(info).filter(k => info[k] !== undefined && info[k] !== "");

      if (!fields.length) {
        grid.innerHTML = `<div class="prf-sys-error">
          <i class="bi bi-exclamation-circle"></i>
          Nenhuma informação disponível no momento.
        </div>`;
        return;
      }

      grid.innerHTML = fields.map(key => {
        const ico   = SYS_ICONS[key]  || "bi-info-circle";
        const label = SYS_LABELS[key] || key;
        const val   = info[key];
        return `
          <div class="prf-sys-item">
            <i class="bi ${ico} prf-sys-item__icon"></i>
            <div class="prf-sys-item__body">
              <span class="prf-sys-item__label">${label}</span>
              <p class="prf-sys-item__val">${escapeHtml(String(val))}</p>
            </div>
          </div>
        `;
      }).join("");

      sysInfoLoaded = true;

    } catch {
      grid.innerHTML = `<div class="prf-sys-error">
        <i class="bi bi-wifi-off"></i>
        Erro ao carregar informações do host.
      </div>`;
    } finally {
      if (btn)  btn.disabled = false;
      if (icon) icon.classList.remove("spin");
    }
  }

  $("btnRefreshEnv")?.addEventListener("click", () => {
    const grid = $("sysInfoGrid");
    if (grid) grid.dataset.forceReload = "1";
    loadSysInfo();
  });


  /* ════════════════════════════════════════════════════════════
     PREFERÊNCIAS — TEMA
     ─────────────────────────────────────────────────────────
     v2.2 FIX: ao trocar o radio, aplica visualmente E persiste
     no banco IMEDIATAMENTE via /autenticacao/api/ui/tema/.
     Não precisa mais clicar em "Salvar Preferências" pro tema
     sobreviver à navegação entre páginas.
  ════════════════════════════════════════════════════════════ */
  document.querySelectorAll("input[name='themeChoice']").forEach(radio => {
    radio.addEventListener("change", async () => {
      const tema = radio.value;

      // 1. Aplica visualmente na hora
      document.documentElement.setAttribute("data-theme", tema);

      // 2. CORREÇÃO: Salva no localStorage para as outras páginas lerem na hora de carregar!
      localStorage.setItem('jg_theme', tema);

      // 3. Persiste no banco imediatamente
      try {
        await fetch("/autenticacao/api/ui/tema/", {
          method:  "POST",
          headers: { "Content-Type": "application/json", "X-CSRFToken": CSRF },
          body:    JSON.stringify({ tema }),
        });
      } catch {
        // falha silenciosa — o visual já foi aplicado
      }
    });
  });

  /* ════════════════════════════════════════════════════════════
     SALVAR PREFERÊNCIAS (densidade, scan, toggles)
     O tema já é salvo no change do radio (acima).
     Mantemos "tema" no payload por compatibilidade com
     api_salvar_prefs que consolida todas as prefs de uma vez.
  ════════════════════════════════════════════════════════════ */
  $("btnSalvarPrefs")?.addEventListener("click", async () => {
    const btn  = $("btnSalvarPrefs");
    setLoading(btn, true);

    const tema = document.querySelector("input[name='themeChoice']:checked")?.value || "dark";

    try {
      const data = await apiPost(P.urls.salvarPrefs, {
        tema,
        densidade:     $("prefDensidade")?.value      || "normal",
        scan_interval: $("prefScanInterval")?.value   || "5",
        auto_scan:     $("prefAutoScan")?.checked     ?? true,
        notificacoes:  $("prefNotificacoes")?.checked ?? true,
        som_alerta:    $("prefSomAlerta")?.checked    ?? false,
      });
      showToast(data.ok ? "Preferências salvas" : (data.msg || "Erro ao salvar."),
                data.ok ? "ok" : "err");
    } catch {
      showToast("Falha na conexão.", "err");
    } finally {
      setLoading(btn, false);
    }
  });


  /* ════════════════════════════════════════════════════════════
     SCORE DE SEGURANÇA
  ════════════════════════════════════════════════════════════ */
  function calcScore() {
    let score = 40;
    if (P.email)    score += 15;
    if (P.telefone) score += 5;
    // 2FA desativado → não pontua
    score += 15; // sessão única
    return Math.min(score, 100);
  }

  const scoreCircle = $("scoreCircle");
  const scoreNum    = $("scoreNum");

  if (scoreCircle && scoreNum) {
    const s    = calcScore();
    const circ = 163.36;
    const off  = circ - (circ * s / 100);

    setTimeout(() => {
      scoreCircle.style.strokeDashoffset = off;
      scoreNum.textContent = s;
      scoreCircle.style.stroke =
        s >= 80 ? "#22c55e" :
        s >= 60 ? "#eab308" : "#ef4444";
    }, 300);
  }


  /* ════════════════════════════════════════════════════════════
     UTIL: Escape HTML para evitar XSS nos valores do sysinfo
  ════════════════════════════════════════════════════════════ */
  function escapeHtml(str) {
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

});