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
  function setBusy(button, busy) { if (button) { button.disabled = busy; button.classList.toggle("loading", busy); } }

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
    if (step === 8) renderNetworkReview();
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
    const button = $("btnStep2Next"); setBusy(button, true);
    try { await postJSON(OB.urls.salvarCredenciais, { username, senha: password }); goToStep(3); } catch (error) { setHint("usernameHint", error.message, "#ef4444"); } finally { setBusy(button, false); }
  }

  async function saveProfile() {
    const button = $("btnStep3Next"); setBusy(button, true);
    try { await postJSON(OB.urls.salvarPerfil, { display_name: $("fieldDisplayName")?.value.trim() || "", cargo: $("fieldCargo")?.value.trim() || "" }); goToStep(4); }
    catch (error) { setHint("profileHint", error.message, "#ef4444"); } finally { setBusy(button, false); }
  }

  async function saveProfilePreferences() {
    const button = $("btnStep5Next"); setBusy(button, true);
    try {
      if (avatarFile) { const form = new FormData(); form.append("avatar", avatarFile); const response = await fetch(OB.urls.uploadAvatar, { method: "POST", headers: { "X-CSRFToken": OB.csrfToken }, body: form }); if (!response.ok) throw new Error("Não foi possível salvar o avatar."); }
      await postJSON(OB.urls.salvarPerfil, { avatar_color: avatarColor }); await postJSON(OB.urls.salvarPrefs, { tema: chosenTheme }); localStorage.setItem("moonshield_theme", chosenTheme); goToStep(6);
    } catch (error) { setHint("profileHint", error.message, "#ef4444"); } finally { setBusy(button, false); }
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
    const button = $("btnStep6Next"); setBusy(button, true);
    try { await postJSON(OB.urls.salvarConfig, { node: { name, ambiente: $("fieldApplianceEnvironment")?.value || "lab", tag: $("fieldApplianceTag")?.value.trim() || "", desc: $("fieldApplianceDesc")?.value.trim() || "" } }); goToStep(7); }
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
    setBusy(button, true);
    try {
      const hasMgmt = selected.some((item) => item.role === "mgmt");
      for (const item of selected) {
        await postJSON(
          OB.urls.redeConfigurar.replace("/0/", `/${item.id}/`),
          interfacePayload(item, hasMgmt),
        );
      }
      topology = (await getJSON(OB.urls.redeTopologia)).dados?.topologia || {};
      goToStep(8);
    } catch (error) {
      setHint("interfacesHint", error.message, "#ef4444");
    } finally {
      setBusy(button, false);
    }
  }

  function principal(role) { return topology[role]?.principal || null; }
  function renderNetworkReview() {
    const container = $("networkReview"); if (!container) return; const rows = [["WAN", principal("wan")], ["LAN", principal("lan")], ["MGMT", principal("mgmt")]];
    container.innerHTML = rows.map(([label, item]) => { const desired = item?.desejado || {}; return `<div><span>${label}</span><strong>${escapeHtml(item?.nome || "Não configurada")}</strong><small>${escapeHtml(desired.ipv4_modo || "—")} ${escapeHtml(desired.ipv4_endereco || "")}</small></div>`; }).join("") + `<p class="ob-review-status">Topologia: <strong>${topology.valida ? "Válida" : "Requer atenção"}</strong></p>`;
  }

  function alterationUrl(template, id) { return (template || "").replace("00000000-0000-0000-0000-000000000000", id); }
  function renderSafeApply(alteration) {
    const box = $("safeApplyState"); if (!box || !alteration) return; box.hidden = false; const waiting = ["waiting_confirmation", "applying"].includes(alteration.status);
    box.innerHTML = `<strong>${escapeHtml(alteration.status_label || alteration.status)}</strong><p>${waiting ? "Confirme que você ainda consegue acessar esta appliance." : escapeHtml(alteration.erro || alteration.descricao || "")}</p>${alteration.status === "waiting_confirmation" ? '<button type="button" class="ob-btn ob-btn--primary" id="btnConfirmConnectivity">Confirmar conectividade</button>' : ""}`;
    $("btnConfirmConnectivity")?.addEventListener("click", () => confirmNetwork(alteration.id));
  }

  async function pollAlteration(id) {
    clearTimeout(safeApplyPoll);
    try { const response = await getJSON(alterationUrl(OB.urls.redeAlteracao, id)); const alteration = response.dados?.alteracao || response.dados; renderSafeApply(alteration); if (["waiting_confirmation", "validating", "applying", "created", "rollback"].includes(alteration.status)) safeApplyPoll = setTimeout(() => pollAlteration(id), 2000); else if (alteration.status === "confirmed") { networkConfirmed = true; topology = (await getJSON(OB.urls.redeTopologia)).dados?.topologia || topology; setHint("safeApplyState", "Rede confirmada com sucesso.", "#22c55e"); $("btnApplyNetwork").disabled = true; } else setHint("safeApplyState", alteration.status === "reverted" ? "As alterações de rede foram revertidas para preservar o acesso." : "As alterações de rede falharam. Revise e tente novamente.", "#ef4444"); }
    catch (error) { setHint("safeApplyState", error.message, "#ef4444"); }
  }

  async function applyNetwork() { const button = $("btnApplyNetwork"); setBusy(button, true); try { const response = await postJSON(OB.urls.redeAplicarTudo, {}); const alteration = response.dados?.alteracao || response.alteracao; renderSafeApply(alteration); if (alteration?.id) pollAlteration(alteration.id); } catch (error) { setHint("safeApplyState", error.message, "#ef4444"); } finally { setBusy(button, false); } }
  async function confirmNetwork(id) { try { const response = await postJSON(alterationUrl(OB.urls.redeConfirmar, id), {}); networkConfirmed = true; renderSafeApply(response.dados?.alteracao || response.alteracao); goToStep(9); } catch (error) { setHint("safeApplyState", error.message, "#ef4444"); } }

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

  async function completeOnboarding() { const button = $("btnCompleteOnboarding"); setBusy(button, true); try { await loadServices(); await postJSON(OB.urls.completar, {}); goToStep(10); } catch (error) { const pending = error.payload?.pendencias; setHint("completionHint", pending?.length ? `Ainda falta: ${pending.join(", ")}.` : error.message, "#ef4444"); } finally { setBusy(button, false); } }

  function bindProfileControls() {
    $("fieldSenha")?.addEventListener("input", updatePasswordFeedback); $("fieldSenhaConfirm")?.addEventListener("input", updatePasswordFeedback); $("btnStep2Next")?.addEventListener("click", saveCredentials); $("btnStep3Next")?.addEventListener("click", saveProfile); $("btnStep5Next")?.addEventListener("click", saveProfilePreferences);
    document.querySelectorAll("input[name=obTheme]").forEach((input) => input.addEventListener("change", () => { chosenTheme = input.value; }));
    document.querySelectorAll(".ob-color-dot").forEach((dot) => dot.addEventListener("click", () => { document.querySelectorAll(".ob-color-dot").forEach((item) => item.classList.remove("active")); dot.classList.add("active"); avatarColor = dot.dataset.color || avatarColor; }));
    $("avatarInput")?.addEventListener("change", (event) => { avatarFile = event.target.files?.[0] || null; if (avatarFile) setHint("avatarHint", "Foto selecionada.", "#22c55e"); }); $("btnUploadAvatar")?.addEventListener("click", () => $("avatarInput")?.click());
  }

  async function loadNetworkConfirmation() {
    try {
      const response = await getJSON(`${OB.urls.redeAlteracoes}?status=confirmed&limite=1`);
      networkConfirmed = (response.dados?.alteracoes || []).some((alteracao) => alteracao.status === "confirmed");
    } catch (_) {
      networkConfirmed = false;
    }
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
    if (applianceIdentityIncomplete()) return 6;
    if (!topology.wan?.principal || !topology.lan?.principal) return 7;
    if (!networkConfirmed) return 8;
    return 9;
  }

  async function init() {
    if ($("greetName")) $("greetName").textContent = OB.fullName || OB.username || "operador"; if ($("fieldUsername")) $("fieldUsername").value = OB.username || "";
    initVisuals(); bindProfileControls(); backButtons(); $("btnStep1Next")?.addEventListener("click", () => goToStep(2)); $("btnStep4Next")?.addEventListener("click", () => goToStep(5)); $("btnStep6Next")?.addEventListener("click", saveApplianceIdentity); $("btnStep7Next")?.addEventListener("click", saveInterfaceRoles); $("btnApplyNetwork")?.addEventListener("click", applyNetwork); $("btnCompleteOnboarding")?.addEventListener("click", completeOnboarding);
    try { topology = (await getJSON(OB.urls.redeTopologia)).dados?.topologia || {}; } catch (_) { topology = {}; }
    await Promise.all([loadApplianceIdentity(), loadNetworkConfirmation()]);
    goToStep(chooseResumeStep());
  }
  init();
});
