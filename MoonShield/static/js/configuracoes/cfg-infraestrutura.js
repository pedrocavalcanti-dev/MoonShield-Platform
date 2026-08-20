/**
 * MOONSHIELD — cfg-infraestrutura.js
 * ─────────────────────────────────────────────────────────────────────
 * Gerencia a camada de sistema e diagnóstico da tela de configurações. Responsável por:
 *   - Carregar e exibir informações do sistema (hostname, SO, IP, uptime, RAM…)
 *   - Listar, selecionar e auto-descobrir interfaces de rede
 *   - Navegação entre abas (tabs) do painel
 *   - Salvar todas as configurações no banco (botão "Salvar Tudo")
 *   - Quick Tests de ping, DNS e gateway sempre com dados reais
 *   - Painel de diagnóstico: cards de status de provider + log de eventos
 *   - Orquestrar a inicialização de todos os módulos após DOMContentLoaded
 *
 * Depende de: cfg-nucleo.js e cfg-conexoes.js (window.CfgNucleo, window.CfgConexoes)
 * ─────────────────────────────────────────────────────────────────────
 */

(function () {

  const n = () => window.CfgNucleo;
  const $ = id => document.getElementById(id);

  let selectedIface = "";
  let _ifaceDataCache = []; // guarda a lista completa para uso no botão Aplicar

  /* ════════════════════════════════════════════════════════════
     SYSINFO
  ════════════════════════════════════════════════════════════ */
  async function loadSysInfo() {
    const grid = $("sysInfoGrid"); if (!grid) return;
    grid.innerHTML = `<p style="color:var(--text-dim);font-size:11px">Carregando...</p>`;
    try {
      const data = await n().apiFetch("/configuracoes/api/sysinfo/");
      if (!data.ok) throw new Error(data.erro || "Erro desconhecido");
      const info  = data.sysinfo;
      const items = [
        { label: "Hostname", val: info.hostname },
        { label: "Sistema",  val: info.so },
        { label: "IP Local", val: info.ip_local,  mono: true },
        { label: "Timezone", val: info.timezone },
        { label: "Uptime",   val: info.uptime,    mono: true, ok: true },
        { label: "Python",   val: info.python,    mono: true },
        { label: "Django",   val: info.django,    mono: true },
        { label: "RAM",      val: info.ram },
      ];
      grid.innerHTML = items.map(i => `
        <div class="cfg-info-card">
          <p class="cfg-info-card__label">${i.label}</p>
          <p class="cfg-info-card__val${i.mono ? " cfg-info-card__val--mono" : ""}${i.ok ? " cfg-info-card__val--ok" : ""}">${i.val ?? "—"}</p>
        </div>`).join("");
      if ($("cfgNodeSub")) $("cfgNodeSub").textContent = `${info.so} · ${info.ip_local}`;
    } catch (e) {
      grid.innerHTML = `<p style="color:#ef4444;font-size:11px">Falha ao carregar: ${e.message}</p>`;
    }
  }

  /* ════════════════════════════════════════════════════════════
     INTERFACES DE REDE
  ════════════════════════════════════════════════════════════ */
  async function loadInterfaces() {
    const el = $("ifaceList"); if (!el) return;
    el.innerHTML = `<p style="color:var(--text-dim);font-size:11px;padding:8px 0">Carregando...</p>`;
    try {
      const data = await n().apiFetch("/configuracoes/api/interfaces/");
      if (!data.ok) throw new Error(data.erro);
      _ifaceDataCache = data.interfaces;
      renderInterfaces(data.interfaces);
      n().logDiag("OK", `${data.interfaces.length} interface(s) detectada(s)`);
    } catch (e) {
      el.innerHTML = `<p style="color:#ef4444;font-size:11px">Falha: ${e.message}</p>`;
    }
  }

  function renderInterfaces(list) {
    const el = $("ifaceList"); if (!el) return;

    // Auto-seleciona a interface principal na primeira renderização
    // (independente do modo Demo ou Produção)
    if (!selectedIface) {
      const principal = list.find(i => i.principal) || list[0];
      if (principal) {
        selectedIface = principal.name;
        _applyIfaceToState(principal, { silent: true });
      }
    }

    el.innerHTML = list.map((iface, i) => `
      <div class="cfg-iface-row${iface.name === selectedIface ? " selected" : ""}"
           data-iface="${iface.name}" style="animation-delay:${i * 40}ms">
        <div class="cfg-iface-row__radio"></div>
        <span class="cfg-iface-name">
          ${iface.name}
          ${iface.principal ? '<span class="cfg-iface-principal">principal</span>' : ""}
        </span>
        <span class="cfg-iface-ip">${iface.ip}/${iface.prefix || "?"} · GW ${iface.gateway}</span>
        <span class="cfg-iface-mac">${iface.mac}</span>
        <span class="cfg-iface-status cfg-iface-status--${iface.status}">${iface.status.toUpperCase()}</span>
        <button
          class="cfg-iface-apply-btn"
          data-iface="${iface.name}"
          title="Aplicar dados desta interface na Rede Monitorada"
          style="
            margin-left:auto;
            padding:3px 10px;
            font-size:10px;
            font-family:var(--font-mono);
            background:rgba(34,197,94,.08);
            border:1px solid rgba(34,197,94,.25);
            border-radius:4px;
            color:#22c55e;
            cursor:pointer;
            transition:background .15s, border-color .15s;
            flex-shrink:0;
          "
          onmouseover="this.style.background='rgba(34,197,94,.18)';this.style.borderColor='rgba(34,197,94,.5)'"
          onmouseout="this.style.background='rgba(34,197,94,.08)';this.style.borderColor='rgba(34,197,94,.25)'"
        ><i class="bi bi-check2-circle"></i> Aplicar</button>
      </div>`).join("");

    // Clique na row → seleciona a interface
    el.querySelectorAll(".cfg-iface-row").forEach(row => {
      row.addEventListener("click", (e) => {
        // Não propaga se clicou no botão Aplicar (ele tem seu próprio handler)
        if (e.target.closest(".cfg-iface-apply-btn")) return;

        selectedIface = row.dataset.iface;
        const STATE = n().STATE;
        STATE.rede  = STATE.rede || {};
        STATE.rede.iface_principal = selectedIface;
        if ($("pillInterfaceLabel")) $("pillInterfaceLabel").textContent = `Interface: ${selectedIface}`;
        el.querySelectorAll(".cfg-iface-row").forEach(r =>
          r.classList.toggle("selected", r.dataset.iface === selectedIface));
        n().logDiag("INFO", `Interface selecionada: ${selectedIface}`);
      });
    });

    // Clique no botão Aplicar → preenche Rede Monitorada com dados da interface
    el.querySelectorAll(".cfg-iface-apply-btn").forEach(btn => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const ifaceName = btn.dataset.iface;
        const iface     = _ifaceDataCache.find(i => i.name === ifaceName);
        if (!iface) return;

        // Seleciona a interface também
        selectedIface = ifaceName;
        el.querySelectorAll(".cfg-iface-row").forEach(r =>
          r.classList.toggle("selected", r.dataset.iface === selectedIface));

        _applyIfaceToState(iface, { silent: false });
      });
    });
  }

  /**
   * Aplica os dados de uma interface ao STATE e aos campos do formulário de Rede.
   * @param {object} iface  - objeto da interface com { name, ip, prefix, gateway, cidr }
   * @param {object} opts   - { silent: bool } — se silent=true não exibe toast
   */
  function _applyIfaceToState(iface, opts = {}) {
    const { silent = false } = opts;
    const STATE = n().STATE;

    // Calcula CIDR a partir do IP + prefix (ex: 10.18.2.33/24 → 10.18.2.0/24)
    const cidr = iface.cidr || _calcCidr(iface.ip, iface.prefix);

    STATE.rede = {
      ...(STATE.rede || {}),
      iface_principal: iface.name,
      cidr:            cidr,
      gateway:         iface.gateway || STATE.rede?.gateway || "",
    };

    // Preenche campos do formulário de Rede Monitorada
    if ($("fieldCidr"))    $("fieldCidr").value    = cidr || "";
    if ($("fieldGateway")) $("fieldGateway").value = iface.gateway || "";

    // Atualiza status bar
    if ($("pillInterfaceLabel")) $("pillInterfaceLabel").textContent = `Interface: ${iface.name}`;
    n().renderStatusBar();
    n()._updateDiagLabels();

    if (!silent) {
      n().showToast(`✓ Interface ${iface.name} aplicada — CIDR e Gateway atualizados`);
      n().logDiag("OK", `Interface aplicada: ${iface.name} → CIDR ${cidr} · GW ${iface.gateway}`);
    } else {
      // Mesmo silencioso, loga
      n().logDiag("INFO", `Interface auto-selecionada: ${iface.name} (${cidr})`);
    }
  }

  /**
   * Calcula o endereço de rede (CIDR) a partir de um IP e prefixo.
   * Ex: "10.18.2.33", 24  →  "10.18.2.0/24"
   */
  function _calcCidr(ip, prefix) {
    if (!ip || !prefix) return "";
    try {
      const parts = ip.split(".").map(Number);
      const mask  = ~0 << (32 - Number(prefix));
      const net   = parts.map((o, i) => o & ((mask >> (24 - i * 8)) & 0xff));
      return `${net.join(".")}/${prefix}`;
    } catch (_) {
      return `${ip}/${prefix}`;
    }
  }

  /* ════════════════════════════════════════════════════════════
     TABS
  ════════════════════════════════════════════════════════════ */
  const TAB_STORAGE_KEY = "moonshield_cfg_tab";

  function _activateTab(tabName) {
    document.querySelectorAll(".cfg-tab").forEach(t => t.classList.remove("cfg-tab--active"));
    document.querySelectorAll(".cfg-panel").forEach(p => p.classList.remove("cfg-panel--active"));

    const btn   = document.querySelector(`.cfg-tab[data-tab="${tabName}"]`);
    const panel = $(`panel${n().capitalize(tabName)}`);

    if (btn)   btn.classList.add("cfg-tab--active");
    if (panel) panel.classList.add("cfg-panel--active");

    if (tabName === "diagnostico") renderDiagProviders();
    if (tabName === "integracoes") {
      Object.keys(n().PROVIDER_CFG).forEach(p => {
        const connEl = $(`connector${n().capitalize(p)}`); if (!connEl) return;
        connEl.style.borderColor = {
          ok:   "rgba(34,197,94,.3)",
          mock: "rgba(234,179,8,.12)",
          warn: "rgba(249,115,22,.2)",
          erro: "rgba(239,68,68,.3)",
          off:  "",
        }[n().PROV_STATUS[p]] || "";
      });
    }
  }

  function initTabs() {
    document.querySelectorAll(".cfg-tab[data-tab]").forEach(btn => {
      btn.addEventListener("click", () => {
        const tab = btn.dataset.tab;
        localStorage.setItem(TAB_STORAGE_KEY, tab);
        _activateTab(tab);
      });
    });

    const saved     = localStorage.getItem(TAB_STORAGE_KEY);
    const firstTab  = document.querySelector(".cfg-tab[data-tab]")?.dataset.tab;
    const targetTab = saved && document.querySelector(`.cfg-tab[data-tab="${saved}"]`)
      ? saved
      : firstTab;

    if (targetTab) _activateTab(targetTab);
  }

  /* ════════════════════════════════════════════════════════════
     SALVAR TUDO
  ════════════════════════════════════════════════════════════ */
  function initSalvarTudo() {
    $("cfgSaveAllBtn")?.addEventListener("click", async () => {
      const { apiFetch, collectStateFromForm, fillFormFromState, renderStatusBar, showToast, logDiag, STATE, _updateUrlIndicator } = n();
      const btn      = $("cfgSaveAllBtn");
      const origHTML = btn.innerHTML;
      btn.innerHTML  = `<i class="bi bi-hourglass-split"></i> Salvando...`;
      btn.disabled   = true;

      const payload = collectStateFromForm();

      try {
        const data = await apiFetch("/configuracoes/api/salvar/", "POST", payload);

        if (data.ok) {
          /*
           * Fonte de verdade:
           * 1. salva no backend;
           * 2. loadConfig() relê /api/config/;
           * 3. loadConfig() também relê /api/servicos/;
           * 4. só então a UI é renderizada.
           *
           * Isso impede o Suricata de voltar para "Simulado" após salvar
           * Modo Real por causa de STATE.servicos ausente/stale.
           */
          const loadedState = await n().loadConfig();

          if (!loadedState) {
            throw new Error("Configuração salva, mas não foi possível recarregar o estado.");
          }

          window.CfgConexoes.applyMode(
            n().STATE.modo,
            { silent: true }
          );

          renderStatusBar();
          renderDiagProviders();

          _updateUrlIndicator(
            "dnsUrl",
            "dnsUrlStatus",
            n().STATE.providers?.dns?.url || ""
          );

          showToast("✓ Configurações salvas e serviços sincronizados!");
          logDiag(
            "OK",
            `Salvo e sincronizado — modo: ${n().STATE.modo} · IDS: ${
              n().STATE.servicos?.suricata?.status || "desconhecido"
            }`
          );
        } else {
          showToast(data.erro || "Erro ao salvar", "erro");
          logDiag("ERRO", data.erro || "Falha no POST /api/salvar/");
        }
      } catch (e) {
        showToast("Erro de rede ao salvar", "erro");
        logDiag("ERRO", `Exceção: ${e.message}`);
      } finally {
        btn.innerHTML = origHTML;
        btn.disabled  = false;
      }
    });
  }

  /* ════════════════════════════════════════════════════════════
     QUICK TESTS — SEMPRE REAIS
  ════════════════════════════════════════════════════════════ */
  function initQuickTests() {
    document.querySelectorAll(".cfg-test-mini-btn").forEach(btn => {
      btn.addEventListener("click", async () => {
        const { apiFetch, capitalize, logDiag } = n();
        const tgt  = btn.dataset.test;
        const res  = $(`result${capitalize(tgt)}`);
        const orig = btn.textContent;

        btn.textContent = "…";
        btn.disabled    = true;
        if (res) { res.textContent = "testando…"; res.style.color = "var(--text-dim)"; }

        try {
          const data = await apiFetch(`/configuracoes/api/quick-test/?test=${tgt}`);
          const ok   = data.ok !== false;
          const ms   = data.ms ?? null;
          const msg  = data.msg || (ok ? "OK" : "Falha");

          if (res) {
            res.textContent = ok ? `OK ✓${ms !== null ? ` (${ms}ms)` : ""}` : `✗ ${msg}`;
            res.style.color = ok ? "#22c55e" : "#ef4444";
          }
          logDiag(ok ? "OK" : "ERRO", `[${tgt}] ${msg}`);
        } catch (e) {
          if (res) { res.textContent = `✗ Erro`; res.style.color = "#ef4444"; }
          n().logDiag("ERRO", `[${tgt}] ${e.message}`);
        } finally {
          btn.textContent = orig;
          btn.disabled    = false;
        }
      });
    });
  }

  /* ════════════════════════════════════════════════════════════
     DIAGNÓSTICO — CARDS DE STATUS DOS PROVIDERS
  ════════════════════════════════════════════════════════════ */
  function renderDiagProviders() {
    const { PROVIDER_CFG, PROV_STATUS, STATE } = n();
    const el = $("diagProviders"); if (!el) return;
    const items = [
      { name: "DNS / AdGuard",  key: "dns", icon: "bi-globe2",             infoFn: () => STATE.providers?.dns?.url || "—" },
      { name: "IDS / Suricata", key: "ids", icon: "bi-shield-exclamation", infoFn: () => `Suricata local · ${STATE.servicos?.suricata?.status || "desconhecido"}` },
      { name: "Firewall",       key: "fw",  icon: "bi-fire",               infoFn: () => STATE.providers?.fw?.host || "local" },
    ];

    el.innerHTML = items.map(c => {
      const s = PROV_STATUS[c.key];

      // O modo é global. Não inferir REAL/MOCK a partir de selects
      // legados ocultos, que podem estar vazios.
      const isReal = STATE.modo === n().MODO_REAL;

      const dotCls = { ok: "ok", mock: "mock", warn: "warn", erro: "erro" }[s] || "off";
      const statusLabel = {
        ok:   "Conectado ✓",
        mock: "Mock ativo",
        warn: "Aguardando teste",
        erro: "Erro de conexão",
        off:  "Desativado",
      }[s] || "—";

      const iconColor   = { ok: "#22c55e", mock: "#eab308", warn: "#f97316", erro: "#ef4444", off: "#888" }[s] || "#888";
      const borderColor = { ok: "rgba(34,197,94,.2)", mock: "rgba(234,179,8,.12)", erro: "rgba(239,68,68,.2)" }[s] || "rgba(255,255,255,.06)";

      return `
        <div class="cfg-diag-card" style="border-color:${borderColor}">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
            <i class="bi ${c.icon}" style="font-size:14px;color:${iconColor}"></i>
            <p class="cfg-diag-card__name">${c.name}</p>
            <span class="cfg-provider-mode-badge cfg-provider-mode-badge--${isReal ? "real" : "mock"}"
                  style="margin-left:auto;font-size:9px">${isReal ? "REAL" : "MOCK"}</span>
          </div>
          <div class="cfg-diag-card__status">
            <span class="cfg-diag-dot cfg-diag-dot--${dotCls}"></span> ${statusLabel}
          </div>
          <p style="font-size:10px;color:var(--text-dim);margin-top:6px;font-family:var(--font-mono)">
            Modo global: <strong>${STATE.modo}</strong>
          </p>
          <p style="font-size:10px;color:var(--text-dim);margin-top:2px;overflow:hidden;
             text-overflow:ellipsis;white-space:nowrap;font-family:var(--font-mono)"
             title="${c.infoFn()}">${c.infoFn()}</p>
        </div>`;
    }).join("");
  }

  /* ════════════════════════════════════════════════════════════
     INICIALIZAÇÃO
  ════════════════════════════════════════════════════════════ */
  document.addEventListener("DOMContentLoaded", async () => {
    const { showToast, logDiag } = n();

    initTabs();
    initSalvarTudo();
    initQuickTests();

    // Detectar interfaces manualmente
    $("btnDetectInterfaces")?.addEventListener("click", () => {
      const btn = $("btnDetectInterfaces");
      btn.classList.add("detecting");
      // Reseta seleção para forçar re-auto-seleção da principal
      selectedIface = "";
      loadInterfaces().finally(() => btn.classList.remove("detecting"));
    });

    // Auto-discover de rede
    $("btnAutoDiscover")?.addEventListener("click", async () => {
      const { apiFetch, renderStatusBar, _updateDiagLabels } = n();
      const btn = $("btnAutoDiscover");
      const res = $("autoDiscoverResult");
      btn.classList.add("detecting");
      res.style.display = "none";
      try {
        const data = await apiFetch("/configuracoes/api/auto-discover/", "POST");
        btn.classList.remove("detecting");
        if (!data.ok) { showToast(data.erro || "Falha na detecção", "erro"); return; }
        res.style.display = "block";
        res.innerHTML = `
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;font-size:12px">
            <div><p style="color:var(--text-dim);font-size:10px;font-family:var(--font-mono)">Interface</p><p>${data.iface} (${data.ip})</p></div>
            <div><p style="color:var(--text-dim);font-size:10px;font-family:var(--font-mono)">Rede (CIDR)</p><p style="color:#22c55e;font-weight:bold">${data.cidr}</p></div>
            <div style="grid-column:1/-1;display:flex;gap:10px;margin-top:5px">
              <button id="btnApplyDiscover" class="cfg-detect-btn" style="color:#22c55e;border-color:rgba(34,197,94,.3)">Aplicar</button>
              <button id="btnCancelDiscover" class="cfg-detect-btn">Cancelar</button>
            </div>
          </div>`;
        $("btnApplyDiscover").addEventListener("click", () => {
          const STATE = n().STATE;
          if ($("fieldCidr"))    $("fieldCidr").value    = data.cidr;
          if ($("fieldGateway")) $("fieldGateway").value = data.gateway;
          STATE.rede = { ...(STATE.rede || {}), cidr: data.cidr, gateway: data.gateway, iface_principal: data.iface };
          renderStatusBar();
          _updateDiagLabels();
          res.style.display = "none";
          showToast("Rede aplicada ✓");
          logDiag("OK", `Rede auto-configurada: ${data.cidr}`);
        });
        $("btnCancelDiscover").addEventListener("click", () => { res.style.display = "none"; });
        showToast("Rede detectada — confirme abaixo");
      } catch (e) {
        btn.classList.remove("detecting");
        showToast("Erro na auto-descoberta", "erro");
      }
    });

    // Botões de diagnóstico
    $("btnRefreshDiag")?.addEventListener("click", () => {
      renderDiagProviders();
      showToast("Diagnóstico atualizado");
    });

    $("btnClearDiagLog")?.addEventListener("click", () => {
      const log = $("diagLog"); if (!log) return;
      log.innerHTML = `<p class="cfg-diag-log__empty">Nenhuma entrada ainda.</p>`;
    });

    // Orquestra carregamento inicial de forma determinística.
    //
    // Antes estes três carregamentos eram disparados em paralelo.
    // O select podia receber "Real" do backend enquanto o card do Suricata
    // permanecia com a renderização inicial "Simulado".
    try {
      const loadedState = await n().loadConfig();

      if (loadedState) {
        window.CfgConexoes.applyMode(
          n().STATE.modo,
          { silent: true }
        );
      }

      // Só depois da configuração global estar carregada permitimos que
      // interfaces/sysinfo atualizem o STATE.
      await Promise.all([
        loadSysInfo(),
        loadInterfaces(),
      ]);

      n().renderStatusBar();
      renderDiagProviders();

      logDiag(
        "INFO",
        `MoonShield Configurações inicializado — modo: ${n().STATE.modo} · IDS: ${
          n().STATE.servicos?.suricata?.status || "desconhecido"
        }`
      );
    } catch (e) {
      logDiag("ERRO", `Falha no bootstrap das Configurações: ${e.message}`);
      showToast("Falha ao sincronizar a tela de Configurações", "erro");
    }
  });

})();