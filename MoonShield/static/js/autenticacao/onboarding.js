/* Primeiro boot da MoonShield Appliance. O navegador coordena APIs existentes;
 * estado desejado, Safe Apply e rollback continuam pertencendo aos módulos oficiais. */
document.addEventListener("DOMContentLoaded", () => {
  const OB = window.OB || {};
  const TOTAL_STEPS = 10;
  let currentStep = 1;
  let avatarFile = null;
  let avatarColor = "#3b82f6";
  let chosenTheme = OB.tema === "light" ? "light" : "dark";
  let interfaces = [];
  let topology = {};
  let applianceConfig = {};
  let networkConfirmed = false;
  let safeApplyPoll = null;
  let safeApplyElapsed = null;
  let activeNetworkAlteration = null;
  let networkApplyInFlight = false;
  let progressCursor = Number(OB.onboardingStep) || 1;
  let preservedIpv4InterfaceIds = new Set();

  const $ = (id) => document.getElementById(id);
  const escapeHtml = (value) => String(value ?? "—").replace(/[&<>\"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;" }[char]));
  const csrfHeaders = () => ({ "Content-Type": "application/json", "X-CSRFToken": OB.csrfToken, Accept: "application/json" });

  async function requestJSON(url, options = {}) {
    const response = await fetch(url, { credentials: "same-origin", ...options });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || data.ok === false) {
      const error = new Error(data.msg || data.erro?.mensagem || "Não foi possível concluir esta etapa.");
      error.payload = data;
      error.status = response.status;
      throw error;
    }
    return data;
  }

  const getJSON = (url) => requestJSON(url, { headers: { Accept: "application/json" } });
  const postJSON = (url, body) => requestJSON(url, { method: "POST", headers: csrfHeaders(), body: JSON.stringify(body || {}) });

  function setHint(id, message, color = "") { const element = $(id); if (element) { element.textContent = message; element.style.color = color; } }
  function setBusy(button, busy, message = "") {
    if (!button) return;
    if (busy) {
      if (!button.dataset.obOriginalContent) button.dataset.obOriginalContent = button.innerHTML;
      button.disabled = true;
      button.classList.add("loading");
      button.setAttribute("aria-busy", "true");
      button.innerHTML = `<span class="ob-btn-loader" aria-hidden="true"></span><span>${escapeHtml(message || "Processando…")}</span>`;
      return;
    }
    button.classList.remove("loading");
    button.removeAttribute("aria-busy");
    if (button.dataset.obOriginalContent) {
      button.innerHTML = button.dataset.obOriginalContent;
      delete button.dataset.obOriginalContent;
    }
    button.disabled = false;
  }

  async function saveProgress(step) {
    const response = await postJSON(OB.urls.salvarProgresso, { etapa: step });
    progressCursor = Number(response.etapa || step);
    return progressCursor;
  }

  function initVisuals() {
    const canvas = $("starsCanvas"); const context = canvas?.getContext("2d"); let stars = [];
    const resize = () => { if (!canvas) return; canvas.width = window.innerWidth; canvas.height = window.innerHeight; stars = Array.from({ length: Math.floor((canvas.width * canvas.height) / 4200) }, () => ({ x: Math.random() * canvas.width, y: Math.random() * canvas.height, r: Math.random() * 1.1 + 0.2, phase: Math.random() * Math.PI * 2, speed: Math.random() * 0.005 + 0.002 })); };
    const draw = (time) => { if (!context || !canvas) return; context.clearRect(0, 0, canvas.width, canvas.height); stars.forEach((star) => { context.beginPath(); context.arc(star.x, star.y, star.r, 0, Math.PI * 2); context.fillStyle = `rgba(200,220,255,${(0.2 + 0.6 * Math.abs(Math.sin(star.phase + time * star.speed))).toFixed(2)})`; context.fill(); }); requestAnimationFrame(draw); };
    resize(); if (context) requestAnimationFrame(draw); window.addEventListener("resize", resize);

    const initials = OB.initials || (OB.username || "OP").slice(0, 2).toUpperCase(); const initialsEl = $("avatarInitials"); const imageEl = $("avatarImg"); const preview = $("avatarPreview");
    if (initialsEl) initialsEl.textContent = initials;
    if (OB.avatarUrl && imageEl) { imageEl.src = OB.avatarUrl; imageEl.style.display = "block"; if (initialsEl) initialsEl.style.display = "none"; }
    const applyColor = (color) => { if (preview) { preview.style.background = `${color}18`; preview.style.outline = `2px solid ${color}40`; preview.style.outlineOffset = "3px"; } if (initialsEl) initialsEl.style.color = color; };
    applyColor(avatarColor);
    $("eyeSenha")?.addEventListener("click", () => { const password = $("fieldSenha"); if (!password) return; const visible = password.type === "password"; password.type = visible ? "text" : "password"; if ($("eyeIconHide")) $("eyeIconHide").style.display = visible ? "none" : "block"; if ($("eyeIconShow")) $("eyeIconShow").style.display = visible ? "block" : "none"; });
    document.querySelectorAll(".ob-color-dot").forEach((dot) => dot.addEventListener("click", () => { document.querySelectorAll(".ob-color-dot").forEach((item) => item.classList.remove("active")); dot.classList.add("active"); avatarColor = dot.dataset.color || avatarColor; applyColor(avatarColor); }));
    $("avatarInput")?.addEventListener("change", (event) => { const file = event.target.files?.[0]; if (!file) return; if (file.size > 2 * 1024 * 1024) { setHint("avatarHint", "Arquivo muito grande. Máximo 2MB.", "#ef4444"); return; } avatarFile = file; const reader = new FileReader(); reader.onload = (loadEvent) => { if (imageEl) { imageEl.src = loadEvent.target.result; imageEl.style.display = "block"; if (initialsEl) initialsEl.style.display = "none"; } setHint("avatarHint", "Foto selecionada.", "#22c55e"); }; reader.readAsDataURL(file); });
    if (OB.tema === "light") { const light = document.querySelector("input[name=obTheme][value=light]"); if (light) light.checked = true; }
  }

  function goToStep(step) {
    const current = $("step" + currentStep);
    const next = $("step" + step);
    if (!next) return;
    current?.classList.remove("active"); next.classList.add("active"); currentStep = step;
    document.querySelectorAll(".ob-nav-step").forEach((item) => { const number = Number(item.dataset.step); item.classList.toggle("ob-nav-step--active", number === step); item.classList.toggle("ob-nav-step--done", number < step); });
    const bar = $("mobileBar"); if (bar) bar.style.width = `${(step / TOTAL_STEPS) * 100}%`;
    next.querySelector("input:not([type=hidden]):not([type=radio]), select")?.focus();
    if (step === 6) loadApplianceIdentity();
    if (step === 7) loadInterfaces();
    if (step === 8) { renderNetworkReview(); void restoreSafeApplyState(); }
    if (step === 9) loadServices();
  }

  function backButtons() { document.querySelectorAll(".ob-btn--back").forEach((button) => button.addEventListener("click", () => goToStep(Number(button.dataset.back)))); }

  function calcStrength(password) {
    if (!password) return 0;
    let score = 0; if (password.length >= 8) score++; if (password.length >= 12) score++; if (/[A-Z]/.test(password) && /[a-z]/.test(password)) score++; if (/\d/.test(password)) score++; if (/[^a-zA-Z0-9]/.test(password)) score++;
    return Math.min(4, Math.ceil(score * 0.8));
  }

  function updatePasswordFeedback() {
    const password = $("fieldSenha")?.value || ""; const score = calcStrength(password); const labels = ["", "Fraca", "Razoável", "Boa", "Forte"]; const colors = ["", "#ef4444", "#f97316", "#eab308", "#22c55e"];
    for (let index = 1; index <= 4; index++) { const bar = $("sbar" + index); if (bar) bar.className = `ob-strength__bar${index <= score ? ` on-${score}` : ""}`; }
    const label = $("strengthLabel"); if (label) { label.textContent = labels[score]; label.style.color = colors[score] || ""; }
    const confirm = $("fieldSenhaConfirm")?.value || ""; const hint = $("confirmHint");
    if (!confirm) { if (hint) hint.textContent = ""; return; }
    if (password === confirm) { if (hint) { hint.textContent = "Senhas conferem."; hint.style.color = "#22c55e"; } $("fieldSenhaConfirm")?.classList.remove("is-error"); }
    else { if (hint) { hint.textContent = "Senhas não coincidem."; hint.style.color = "#ef4444"; } $("fieldSenhaConfirm")?.classList.add("is-error"); }
  }

  async function saveCredentials() {
    const username = $("fieldUsername")?.value.trim() || ""; const password = $("fieldSenha")?.value || ""; const confirmation = $("fieldSenhaConfirm")?.value || "";
    if (!username || !/^[\w.@+\-]+$/.test(username)) { setHint("usernameHint", "Informe um nome de usuário válido.", "#ef4444"); return; }
    if (password.length < 8 || password !== confirmation) { setHint("confirmHint", password.length < 8 ? "A senha deve atender à política de segurança." : "Senhas não coincidem.", "#ef4444"); return; }
    const button = $("btnStep2Next"); setBusy(button, true, "Salvando credenciais…");
    try { await postJSON(OB.urls.salvarCredenciais, { username, senha: password }); await saveProgress(3); goToStep(3); } catch (error) { setHint("usernameHint", error.message, "#ef4444"); } finally { setBusy(button, false); }
  }

  async function saveProfile() {
    const button = $("btnStep3Next"); setBusy(button, true, "Salvando identidade…");
    try { await postJSON(OB.urls.salvarPerfil, { display_name: $("fieldDisplayName")?.value.trim() || "", cargo: $("fieldCargo")?.value.trim() || "" }); await saveProgress(4); goToStep(4); }
    catch (error) { setHint("profileHint", error.message, "#ef4444"); } finally { setBusy(button, false); }
  }

  async function saveAvatar() {
    const button = $("btnStep4Next"); setBusy(button, true, "Salvando avatar…");
    try {
      if (avatarFile) { const form = new FormData(); form.append("avatar", avatarFile); const response = await fetch(OB.urls.uploadAvatar, { method: "POST", headers: { "X-CSRFToken": OB.csrfToken }, body: form }); if (!response.ok) throw new Error("Não foi possível salvar o avatar."); }
      await postJSON(OB.urls.salvarPerfil, { avatar_color: avatarColor }); await saveProgress(5); goToStep(5);
    } catch (error) { setHint("profileHint", error.message, "#ef4444"); } finally { setBusy(button, false); }
  }

  async function saveProfilePreferences() {
    const button = $("btnStep5Next"); setBusy(button, true, "Salvando preferências…");
    try { await postJSON(OB.urls.salvarPrefs, { tema: chosenTheme }); await saveProgress(6); localStorage.setItem("moonshield_theme", chosenTheme); goToStep(6); }
    catch (error) { setHint("profileHint", error.message, "#ef4444"); } finally { setBusy(button, false); }
  }

  function displayValue(value, fallback = "Não informado") {
    const text = String(value ?? "").trim();
    return text && text !== "—" ? text : fallback;
  }

  function renderObservedAppliance(info) {
    const container = $("applianceObserved");
    if (!container) return;

    const version = info.moonshield_version || info.versao || info.version;
    const cards = [
      ["Hostname", info.hostname],
      ["Sistema", info.so],
      ["Fuso horário", info.timezone],
      ["IP de gerenciamento", info.ip_local],
    ];

    if (String(version ?? "").trim() && version !== "—") {
      cards.push(["MoonShield", version]);
    }

    container.innerHTML = cards.map(([label, value]) => `
      <div class="ob-observed__card">
        <small>${escapeHtml(label)}</small>
        <strong>${escapeHtml(displayValue(value))}</strong>
      </div>
    `).join("");
  }

  async function loadApplianceIdentity() {
    try {
      const [config, sysinfo] = await Promise.all([getJSON(OB.urls.config), getJSON(OB.urls.sysinfo)]);
      applianceConfig = config.config || {};
      const node = applianceConfig.node || {};

      if ($("fieldApplianceName")) $("fieldApplianceName").value = node.name || "";
      if ($("fieldApplianceEnvironment")) $("fieldApplianceEnvironment").value = node.ambiente || "lab";
      if ($("fieldApplianceTag")) $("fieldApplianceTag").value = node.tag || "";
      if ($("fieldApplianceDesc")) $("fieldApplianceDesc").value = node.desc || "";

      renderObservedAppliance(sysinfo.sysinfo || {});
    } catch (error) {
      setHint("applianceObserved", error.message, "#ef4444");
    }
  }

  async function saveApplianceIdentity() {
    const name = $("fieldApplianceName")?.value.trim() || ""; if (!name) { setHint("applianceObserved", "Informe o nome administrativo da appliance.", "#ef4444"); return; }
    const button = $("btnStep6Next"); setBusy(button, true, "Salvando configuração…");
    try { await postJSON(OB.urls.salvarConfig, { node: { name, ambiente: $("fieldApplianceEnvironment")?.value || "lab", tag: $("fieldApplianceTag")?.value.trim() || "", desc: $("fieldApplianceDesc")?.value.trim() || "" } }); await saveProgress(7); goToStep(7); }
    catch (error) { setHint("applianceObserved", error.message, "#ef4444"); } finally { setBusy(button, false); }
  }

  function interfaceRoleOptions(selected) {
    return [["unassigned", "Não atribuída"], ["wan", "WAN"], ["lan", "LAN"], ["mgmt", "MGMT"], ["dmz", "DMZ"], ["custom", "CUSTOM"]]
      .map(([value, label]) => `<option value="${value}"${selected === value ? " selected" : ""}>${label}</option>`)
      .join("");
  }

  function ipv4ChoiceOptions() {
    return [
      ["keep", "Manter configuração atual"],
      ["dhcp", "DHCP"],
      ["static", "Estático"],
    ].map(([value, label]) => `<option value="${value}">${label}</option>`).join("");
  }

  function initialIpv4Choice(item) {
    const real = item.real || {};
    const desired = item.desejado || {};
    const hasObservedConfiguration = Boolean(
      real.ipv4 || real.gateway || real.conexao_nome || real.conexao_uuid ||
      (Array.isArray(real.enderecos_ipv4) && real.enderecos_ipv4.length)
    );

    if (hasObservedConfiguration || desired.ipv4_modo === "disabled") return "keep";
    return desired.ipv4_modo === "static" ? "static" : "dhcp";
  }

  function ipv4ModeLabel(mode) {
    return { dhcp: "DHCP", static: "Estático", disabled: "Desativado" }[mode] || "Não informado";
  }

  function renderInterfaces() {
    const container = $("onboardingInterfaces");
    if (!container) return;
    if (!interfaces.length) {
      container.textContent = "Nenhuma interface foi detectada pelo módulo Rede.";
      return;
    }

    container.innerHTML = interfaces.map((item) => {
      const real = item.real || {};
      const desired = item.desejado || {};
      const role = desired.papel || "unassigned";
      const linkUp = real.estado_link === "up" || real.carrier === true;
      const linkLabel = linkUp ? "UP" : (real.estado_link || "Desconhecido").toUpperCase();

      return `
        <article class="ob-interface-card" data-interface-id="${item.id}" data-role="${role}">
          <header>
            <strong>${escapeHtml(item.nome)}</strong>
            <span class="ob-status-pill ${linkUp ? "is-up" : "is-neutral"}">${escapeHtml(linkLabel)}</span>
          </header>
          <div class="ob-interface-observed">
            <small>Observado</small>
            <p>MAC ${escapeHtml(displayValue(item.mac_address))} · IPv4 ${escapeHtml(displayValue(real.ipv4))}</p>
            <p>Gateway ${escapeHtml(displayValue(real.gateway))}</p>
          </div>
          <div class="ob-interface-desired">
            <small>Desejado</small>
            <p>IPv4 ${escapeHtml(ipv4ModeLabel(desired.ipv4_modo))} · Rota default ${desired.rota_padrao ? "Sim" : "Não"}</p>
          </div>
          <label>Função<select data-interface-role>${interfaceRoleOptions(role)}</select></label>
          <label>Configuração IPv4<select data-ipv4-choice>${ipv4ChoiceOptions()}</select></label>
          <p class="ob-ipv4-copy" data-ipv4-keep-copy>O IPv4 desejado atual será preservado sem copiar o estado observado.</p>
          <p class="ob-ipv4-copy" data-ipv4-dhcp-copy hidden>Endereço, prefixo e gateway serão obtidos automaticamente.</p>
          <div class="ob-ipv4-fields" data-ipv4-static-fields hidden>
            <label>Endereço IPv4<input data-ipv4-address inputmode="decimal" placeholder="Endereço definido pelo operador" value="${escapeHtml(desired.ipv4_endereco || "")}"></label>
            <label>Prefixo<input data-ipv4-prefix inputmode="numeric" placeholder="Prefixo" value="${escapeHtml(desired.ipv4_prefixo ?? "")}"></label>
            <label>Gateway (opcional)<input data-ipv4-gateway inputmode="decimal" value="${escapeHtml(desired.gateway || "")}"></label>
          </div>
        </article>
      `;
    }).join("");

    container.querySelectorAll("[data-interface-id]").forEach((card) => {
      const current = interfaces.find((item) => String(item.id) === card.dataset.interfaceId);
      const ipv4Choice = card.querySelector("[data-ipv4-choice]");
      if (ipv4Choice) ipv4Choice.value = initialIpv4Choice(current || {});

      card.querySelector("[data-interface-role]")?.addEventListener("change", () => refreshInterfaceCard(card));
      ipv4Choice?.addEventListener("change", () => refreshInterfaceCard(card));
      refreshInterfaceCard(card);
    });
  }

  function refreshInterfaceCard(card) {
    const role = card.querySelector("[data-interface-role]")?.value || "unassigned";
    const choice = card.querySelector("[data-ipv4-choice]")?.value || "keep";
    const keepCopy = card.querySelector("[data-ipv4-keep-copy]");
    const dhcpCopy = card.querySelector("[data-ipv4-dhcp-copy]");
    const staticFields = card.querySelector("[data-ipv4-static-fields]");

    card.dataset.role = role;
    if (keepCopy) keepCopy.hidden = choice !== "keep";
    if (dhcpCopy) dhcpCopy.hidden = choice !== "dhcp";
    if (staticFields) staticFields.hidden = choice !== "static";
  }

  async function loadInterfaces() {
    const container = $("onboardingInterfaces");
    if (container) container.textContent = "Carregando interfaces…";
    try {
      const response = await getJSON(OB.urls.redeInterfaces);
      interfaces = response.dados?.interfaces || [];
      renderInterfaces();
    } catch (error) {
      setHint("interfacesHint", error.message, "#ef4444");
    }
  }

  function preservedIpv4Payload(desired) {
    return {
      ipv4_modo: desired.ipv4_modo,
      ipv4_endereco: desired.ipv4_endereco,
      ipv4_prefixo: desired.ipv4_prefixo,
      gateway: desired.gateway,
      rota_padrao: desired.rota_padrao,
      metrica: desired.metrica,
      mtu: desired.mtu,
      habilitada: desired.habilitada,
    };
  }

  function interfacePayload(item, hasMgmt) {
    const desired = item.current.desejado || {};
    const preserveCurrent = item.ipv4Choice === "keep";
    const explicitIpv4 = item.ipv4Choice === "static"
      ? {
          ipv4_modo: "static",
          ipv4_endereco: item.address,
          ipv4_prefixo: Number(item.prefix),
          gateway: item.gateway || null,
        }
      : {
          ipv4_modo: "dhcp",
          ipv4_endereco: null,
          ipv4_prefixo: null,
          gateway: null,
        };

    return {
      papel: item.role,
      principal: ["wan", "lan", "mgmt"].includes(item.role),
      acesso_gerenciamento: item.role === "mgmt" || (!hasMgmt && item.role === "lan"),
      preservar_ipv4_atual: preserveCurrent,
      ...(preserveCurrent ? preservedIpv4Payload(desired) : { ...preservedIpv4Payload(desired), ...explicitIpv4 }),
    };
  }

  async function saveInterfaceRoles() {
    const selected = [...document.querySelectorAll("[data-interface-id]")].map((card) => {
      const current = interfaces.find((candidate) => String(candidate.id) === card.dataset.interfaceId) || {};
      return {
        id: Number(card.dataset.interfaceId),
        current,
        role: card.querySelector("[data-interface-role]")?.value || "unassigned",
        ipv4Choice: card.querySelector("[data-ipv4-choice]")?.value || "keep",
        address: card.querySelector("[data-ipv4-address]")?.value.trim() || "",
        prefix: card.querySelector("[data-ipv4-prefix]")?.value.trim() || "",
        gateway: card.querySelector("[data-ipv4-gateway]")?.value.trim() || "",
      };
    });
    const wan = selected.filter((item) => item.role === "wan");
    const lan = selected.filter((item) => item.role === "lan");

    if (wan.length !== 1 || lan.length !== 1) {
      setHint("interfacesHint", "Defina exatamente uma WAN e uma LAN. MGMT é opcional.", "#ef4444");
      return;
    }

    const invalidStatic = selected.find((item) => item.ipv4Choice === "static" && (!item.address || !item.prefix));
    if (invalidStatic) {
      setHint("interfacesHint", `Informe endereço e prefixo para a interface ${invalidStatic.current.nome || invalidStatic.id} estática.`, "#ef4444");
      return;
    }

    const button = $("btnStep7Next");
    setBusy(button, true, "Salvando configuração…");
    try {
      const hasMgmt = selected.some((item) => item.role === "mgmt");
      for (const item of selected) {
        await postJSON(
          OB.urls.redeConfigurar.replace("/0/", `/${item.id}/`),
          interfacePayload(item, hasMgmt),
        );
      }
      preservedIpv4InterfaceIds = new Set(selected.filter((item) => item.ipv4Choice === "keep").map((item) => item.id));
      topology = (await getJSON(OB.urls.redeTopologia)).dados?.topologia || {};
      await saveProgress(8);
      goToStep(8);
    } catch (error) {
      setHint("interfacesHint", error.message, "#ef4444");
    } finally {
      setBusy(button, false);
    }
  }

  function principal(role) { return topology[role]?.principal || null; }

  function observedIpv4Summary(item) {
    const real = item?.real || {};
    const address = real.ipv4 ? `${real.ipv4}${real.prefixo !== null && real.prefixo !== undefined ? `/${real.prefixo}` : ""}` : "Não informado";
    return `${address}${real.gateway ? ` · GW ${real.gateway}` : ""}`;
  }

  function plannedIpv4Summary(item) {
    const desired = item?.desejado || {};
    if (preservedIpv4InterfaceIds.has(Number(item?.id))) return "Manter configuração atual";
    if (desired.ipv4_modo === "static") return `Estático${desired.ipv4_endereco ? ` · ${desired.ipv4_endereco}/${desired.ipv4_prefixo}` : ""}`;
    return ipv4ModeLabel(desired.ipv4_modo);
  }

  function renderNetworkReview() {
    const container = $("networkReview");
    const status = $("networkTopologyStatus");
    if (!container) return;

    if (status) {
      status.className = `ob-network-topology-status ${topology.valida ? "is-valid" : "is-warning"}`;
      status.textContent = topology.valida ? "Topologia válida" : "Topologia requer atenção";
    }

    const rows = [["WAN", principal("wan")], ["LAN", principal("lan")], ["MGMT", principal("mgmt")]];
    container.innerHTML = rows.map(([label, item]) => `
      <article class="ob-network-review__card ob-network-review__card--${label.toLowerCase()}">
        <small>${label}</small>
        <strong>${escapeHtml(item?.nome || "Não configurada")}</strong>
        <span>Configuração a aplicar</span>
        <p>${escapeHtml(item ? plannedIpv4Summary(item) : "—")}</p>
        <span>Estado observado</span>
        <p>${escapeHtml(item ? observedIpv4Summary(item) : "—")}</p>
      </article>
    `).join("");
  }

  function alterationUrl(template, id) { return (template || "").replace("00000000-0000-0000-0000-000000000000", id); }
  function isSafeApplyActive(alteration) { return ["created", "validating", "applying", "waiting_confirmation", "rollback"].includes(alteration?.status); }
  function formatElapsed(seconds) { return `${Math.max(0, Math.floor(seconds))}s`; }

  function stopSafeApplyElapsed() {
    clearInterval(safeApplyElapsed);
    safeApplyElapsed = null;
  }

  function startSafeApplyElapsed(startedAt) {
    stopSafeApplyElapsed();
    const started = Date.parse(startedAt || "");
    const startedMs = Number.isNaN(started) ? Date.now() : started;
    const update = () => { const target = $("safeApplyElapsed"); if (target) target.textContent = formatElapsed((Date.now() - startedMs) / 1000); };
    update();
    safeApplyElapsed = window.setInterval(update, 1000);
  }

  function setNetworkAction(mode) {
    const button = $("btnApplyNetwork");
    if (!button) return;
    const canApply = mode === "apply" && !networkApplyInFlight;
    button.hidden = !canApply;
    button.disabled = !canApply;
  }

  function renderSafeApplyProcessing(alteration = {}) {
    const box = $("safeApplyState");
    if (!box) return;
    box.hidden = false;
    box.dataset.state = "processing";
    box.innerHTML = `
      <div class="ob-safe-apply__heading"><span class="ob-inline-spinner" aria-hidden="true"></span><div><small>SAFE APPLY</small><strong>Processando configuração de rede…</strong></div></div>
      <p>O MoonShield está validando a configuração e preparando o Safe Apply. Isso pode levar alguns segundos. Não feche esta página.</p>
      <p class="ob-safe-apply__elapsed">Tempo decorrido: <strong id="safeApplyElapsed">0s</strong></p>
    `;
    startSafeApplyElapsed(alteration.iniciada_em);
    setNetworkAction("locked");
  }

  function rollbackSucceeded(details, alteration) {
    const rollback = details?.rollback || details?.resultado_rollback || alteration?.resultado_agent?.falha_aplicacao?.rollback || alteration?.resultado_agent?.rollback || {};
    return alteration?.status === "reverted" || rollback?.status === "reverted" || rollback?.ok === true || rollback?.resultado_rollback?.ok === true;
  }

  function applyFailureReason(details, fallback) {
    const original = details?.erro_original || details?.erro || {};
    if (original?.codigo === "comando_timeout") return "Comando de rede excedeu o tempo limite.";
    return original?.mensagem || original?.message || fallback || "A aplicação de rede não foi concluída.";
  }

  function renderSafeApplyFailure(alteration = {}, details = {}, fallback = "") {
    const box = $("safeApplyState");
    if (!box) return;
    stopSafeApplyElapsed();
    const rollbackOk = rollbackSucceeded(details, alteration);
    box.hidden = false;
    box.dataset.state = rollbackOk ? "reverted" : "critical";
    box.innerHTML = `
      <div class="ob-safe-apply__heading"><div><small>ALTERAÇÃO NÃO APLICADA</small><strong>${rollbackOk ? "A configuração anterior foi restaurada com sucesso." : "A operação requer atenção."}</strong></div></div>
      <p><strong>Motivo:</strong> ${escapeHtml(applyFailureReason(details, alteration.erro || fallback))}</p>
      <p class="${rollbackOk ? "ob-safe-apply__rollback-ok" : "ob-safe-apply__rollback-critical"}"><strong>Status:</strong> ${rollbackOk ? "Rollback concluído" : "Não foi possível confirmar o rollback"}</p>
      <button type="button" class="ob-btn ob-btn--primary" id="btnRetryNetwork">Tentar novamente</button>
    `;
    $("btnRetryNetwork")?.addEventListener("click", applyNetwork);
    setNetworkAction("locked");
  }

  async function markNetworkConfirmed() {
    networkConfirmed = true;
    try { await saveProgress(9); } catch (error) { setHint("completionHint", error.message, "#ef4444"); }
    try { topology = (await getJSON(OB.urls.redeTopologia)).dados?.topologia || topology; renderNetworkReview(); } catch (_) { /* Mantém o último resumo persistido. */ }
  }

  function renderSafeApply(alteration) {
    const box = $("safeApplyState");
    if (!box || !alteration) return;
    activeNetworkAlteration = alteration;

    if (["created", "validating", "applying", "rollback"].includes(alteration.status)) {
      renderSafeApplyProcessing(alteration);
      return;
    }

    if (alteration.status === "waiting_confirmation") {
      stopSafeApplyElapsed();
      box.hidden = false;
      box.dataset.state = "waiting";
      box.innerHTML = `
        <div class="ob-safe-apply__heading"><div><small>SAFE APPLY ARMADO</small><strong>Confirmar conectividade</strong></div></div>
        <p>A configuração foi aplicada. Confirme que você ainda consegue acessar esta appliance para desarmar o rollback automático.</p>
        <p class="ob-safe-apply__elapsed">Tempo restante: <strong>${escapeHtml(String(alteration.segundos_restantes ?? "—"))}s</strong></p>
        <button type="button" class="ob-btn ob-btn--primary" id="btnConfirmConnectivity">Confirmar conectividade</button>
      `;
      $("btnConfirmConnectivity")?.addEventListener("click", () => confirmNetwork(alteration.id));
      setNetworkAction("locked");
      return;
    }

    if (alteration.status === "confirmed") {
      stopSafeApplyElapsed();
      box.hidden = false;
      box.dataset.state = "confirmed";
      box.innerHTML = `
        <div class="ob-safe-apply__heading"><div><small>REDE CONFIRMADA</small><strong>Conectividade confirmada com sucesso.</strong></div></div>
        <p>O rollback automático foi desarmado. Você pode continuar para a validação dos serviços locais.</p>
        <button type="button" class="ob-btn ob-btn--primary" id="btnContinueProtection">Continuar para proteção</button>
      `;
      $("btnContinueProtection")?.addEventListener("click", () => goToStep(9));
      setNetworkAction("locked");
      return;
    }

    renderSafeApplyFailure(alteration, alteration.resultado_agent?.falha_aplicacao || {}, alteration.erro);
  }

  async function pollAlteration(id) {
    clearTimeout(safeApplyPoll);
    try {
      const response = await getJSON(alterationUrl(OB.urls.redeAlteracao, id));
      const alteration = response.dados?.alteracao || response.dados;
      if (!alteration?.id) throw new Error("A alteração de Rede não retornou identificador.");
      renderSafeApply(alteration);

      if (isSafeApplyActive(alteration)) {
        safeApplyPoll = setTimeout(() => pollAlteration(id), 2000);
      } else if (alteration.status === "confirmed") {
        await markNetworkConfirmed();
      }
    } catch (error) {
      const box = $("safeApplyState");
      if (box) { box.hidden = false; box.dataset.state = "critical"; box.textContent = error.message; }
    }
  }

  async function applyNetwork() {
    if (networkApplyInFlight || isSafeApplyActive(activeNetworkAlteration) || activeNetworkAlteration?.status === "confirmed") return;
    const button = $("btnApplyNetwork");
    networkApplyInFlight = true;
    setBusy(button, true, "Aplicando configuração de rede…");
    renderSafeApplyProcessing();

    try {
      const response = await postJSON(OB.urls.redeAplicarTudo, {});
      const alteration = response.dados?.alteracao || response.alteracao;
      if (!alteration?.id) throw new Error("A aplicação de Rede não retornou uma alteração válida.");
      activeNetworkAlteration = alteration;
      renderSafeApply(alteration);
      await pollAlteration(alteration.id);
    } catch (error) {
      const details = error.payload?.erro?.detalhes || {};
      const alteration = details.alteracao || activeNetworkAlteration || {};
      if (isSafeApplyActive(alteration)) {
        activeNetworkAlteration = alteration;
        renderSafeApply(alteration);
        void pollAlteration(alteration.id);
      } else {
        renderSafeApplyFailure(alteration, details, error.message);
      }
    } finally {
      networkApplyInFlight = false;
      setBusy(button, false);
      if (activeNetworkAlteration?.status === "confirmed" || isSafeApplyActive(activeNetworkAlteration) || activeNetworkAlteration?.status === "failed" || activeNetworkAlteration?.status === "reverted") setNetworkAction("locked");
      else setNetworkAction("apply");
    }
  }

  async function confirmNetwork(id) {
    const button = $("btnConfirmConnectivity");
    setBusy(button, true, "Confirmando conectividade…");
    try {
      const response = await postJSON(alterationUrl(OB.urls.redeConfirmar, id), {});
      const alteration = response.dados?.alteracao || response.alteracao;
      activeNetworkAlteration = alteration;
      renderSafeApply(alteration);
      await markNetworkConfirmed();
      goToStep(9);
    } catch (error) {
      const box = $("safeApplyState");
      if (box) { box.hidden = false; box.dataset.state = "critical"; box.textContent = error.message; }
    } finally {
      setBusy(button, false);
    }
  }

  async function loadLatestNetworkAlteration() {
    try {
      const response = await getJSON(`${OB.urls.redeAlteracoes}?tipo=general&limite=1`);
      const alteration = response.dados?.alteracoes?.[0] || null;
      activeNetworkAlteration = alteration;
      networkConfirmed = alteration?.status === "confirmed";
      return alteration;
    } catch (_) {
      activeNetworkAlteration = null;
      networkConfirmed = false;
      return null;
    }
  }

  async function restoreSafeApplyState() {
    const alteration = await loadLatestNetworkAlteration();
    if (!alteration) {
      $("safeApplyState").hidden = true;
      setNetworkAction("apply");
      return;
    }
    renderSafeApply(alteration);
    if (isSafeApplyActive(alteration)) void pollAlteration(alteration.id);
    if (alteration.status === "confirmed") await markNetworkConfirmed();
  }

  function servicePresentation(service) {
    if (!service?.configurado) {
      return { label: "Ainda não configurado", level: "neutral", configuration: "Não configurado", health: "Ainda não validada" };
    }
    if (service.saudavel) {
      return { label: "Operacional", level: "ok", configuration: "Configurado", health: "Operacional" };
    }
    if (service.status === "erro" || service.status === "falha") {
      return { label: "Falha", level: "error", configuration: "Configurado", health: "Falha na verificação" };
    }
    return { label: "Requer atenção", level: "warning", configuration: "Configurado", health: service.status_label || "Requer atenção" };
  }

  function serviceCard({ eyebrow, name, service, details = [], actionUrl = "", actionLabel = "", note = "" }) {
    const presentation = servicePresentation(service);
    const facts = [
      ["Configuração", presentation.configuration],
      ["Saúde", presentation.health],
      ...details,
    ];

    return `
      <article class="ob-service-card">
        <header>
          <div><small>${escapeHtml(eyebrow)}</small><strong>${escapeHtml(name)}</strong></div>
          <span class="ob-service-status ob-service-status--${presentation.level}">${escapeHtml(presentation.label)}</span>
        </header>
        <div class="ob-service-facts">
          ${facts.map(([label, value]) => `<div><small>${escapeHtml(label)}</small><strong>${escapeHtml(value)}</strong></div>`).join("")}
        </div>
        ${note ? `<p class="ob-service-note">${escapeHtml(note)}</p>` : ""}
        ${actionUrl ? `<a class="ob-btn ob-btn--ghost" href="${escapeHtml(actionUrl)}">${escapeHtml(actionLabel)}</a>` : ""}
      </article>
    `;
  }

  async function loadServices() {
    const container = $("onboardingServices");
    if (!container) return;

    try {
      const response = await getJSON(OB.urls.servicos);
      const services = response.servicos || {};
      const adguard = services.adguard || {};
      const suricata = services.suricata || {};
      const firewall = services.firewall || {};

      container.innerHTML = [
        serviceCard({
          eyebrow: "DNS",
          name: "AdGuard Home",
          service: adguard,
          details: [
            ["Serviço local", adguard.ativo ? "Detectado" : "Não detectado"],
            ["Proteção", adguard.protecao ? "Ativa" : "Não informada"],
            ["Filtros", Number.isFinite(Number(adguard.filtros_ativos)) ? `${Number(adguard.filtros_ativos)} ativos` : "Não informado"],
          ],
          note: "Configurações avançadas ficam disponíveis em DNS & Rede após concluir.",
        }),
        serviceCard({
          eyebrow: "IDS",
          name: "Suricata",
          service: suricata,
          actionUrl: OB.urls.suricata,
          actionLabel: suricata.configurado ? "Revisar IDS" : "Configurar IDS",
        }),
        serviceCard({
          eyebrow: "FIREWALL",
          name: "nftables / MoonShield",
          service: firewall,
          actionUrl: OB.urls.firewall,
          actionLabel: firewall.configurado ? "Revisar Firewall" : "Configurar Firewall",
        }),
      ].join("");
    } catch (error) {
      container.textContent = error.message;
    }
  }

  async function completeOnboarding() { const button = $("btnCompleteOnboarding"); setBusy(button, true, "Validando serviços…"); try { await loadServices(); await postJSON(OB.urls.completar, {}); progressCursor = 10; goToStep(10); } catch (error) { const pending = error.payload?.pendencias; setHint("completionHint", pending?.length ? `Ainda falta: ${pending.join(", ")}.` : error.message, "#ef4444"); } finally { setBusy(button, false); } }

  function bindProfileControls() {
    $("fieldSenha")?.addEventListener("input", updatePasswordFeedback); $("fieldSenhaConfirm")?.addEventListener("input", updatePasswordFeedback); $("btnStep2Next")?.addEventListener("click", saveCredentials); $("btnStep3Next")?.addEventListener("click", saveProfile); $("btnStep4Next")?.addEventListener("click", saveAvatar); $("btnStep5Next")?.addEventListener("click", saveProfilePreferences);
    document.querySelectorAll("input[name=obTheme]").forEach((input) => input.addEventListener("change", () => { chosenTheme = input.value; }));
    document.querySelectorAll(".ob-color-dot").forEach((dot) => dot.addEventListener("click", () => { document.querySelectorAll(".ob-color-dot").forEach((item) => item.classList.remove("active")); dot.classList.add("active"); avatarColor = dot.dataset.color || avatarColor; }));
    $("avatarInput")?.addEventListener("change", (event) => { avatarFile = event.target.files?.[0] || null; if (avatarFile) setHint("avatarHint", "Foto selecionada.", "#22c55e"); }); $("btnUploadAvatar")?.addEventListener("click", () => $("avatarInput")?.click());
  }

  function applianceIdentityIncomplete() {
    const node = applianceConfig.node || {};
    const name = String(node.name ?? $("fieldApplianceName")?.value ?? "").trim();
    const tag = String(node.tag ?? $("fieldApplianceTag")?.value ?? "").trim();
    const desc = String(node.desc ?? $("fieldApplianceDesc")?.value ?? "").trim();
    const environment = String(node.ambiente ?? $("fieldApplianceEnvironment")?.value ?? "").trim();
    const defaultIdentity = name === "MS-NODE-01" && !tag && !desc;

    return !name || defaultIdentity || !["lab", "prod"].includes(environment);
  }

  function chooseResumeStep() {
    if (OB.passwordChanged !== true) return 2;
    if (progressCursor < 3) return 3;
    if (progressCursor < 6) return progressCursor;
    if (applianceIdentityIncomplete()) return 6;
    if (!topology.wan?.principal || !topology.lan?.principal) return 7;
    if (!networkConfirmed) return 8;
    return 9;
  }

  async function init() {
    if ($("greetName")) $("greetName").textContent = OB.fullName || OB.username || "operador"; if ($("fieldUsername")) $("fieldUsername").value = OB.username || "";
    initVisuals(); bindProfileControls(); backButtons(); $("btnStep1Next")?.addEventListener("click", () => goToStep(2)); $("btnStep6Next")?.addEventListener("click", saveApplianceIdentity); $("btnStep7Next")?.addEventListener("click", saveInterfaceRoles); $("btnApplyNetwork")?.addEventListener("click", applyNetwork); $("btnCompleteOnboarding")?.addEventListener("click", completeOnboarding);
    try { topology = (await getJSON(OB.urls.redeTopologia)).dados?.topologia || {}; } catch (_) { topology = {}; }
    await Promise.all([loadApplianceIdentity(), loadLatestNetworkAlteration()]);
    goToStep(chooseResumeStep());
  }
  init();
});
