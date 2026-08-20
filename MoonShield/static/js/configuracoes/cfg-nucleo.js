/**
 * MOONSHIELD — cfg-nucleo.js  v5
 * ─────────────────────────────────────────────────────────────────────
 * v5: Estado global + serviços reais como fonte de verdade
 *   - Modo global: "simulacao" | "real" (internamente)
 *   - Compatibilidade: aceita "demo"/"prod" do backend e formulário
 *   - STATE.servicos: fonte de verdade para AdGuard, Suricata e Firewall
 *   - STATE.providers: somente camada de compatibilidade com o frontend legado
 *   - Suricata real nunca volta para MOCK quando a stack está operacional
 *   - PROV_STATUS é derivado do health consolidado retornado pelo backend
 * ─────────────────────────────────────────────────────────────────────
 */

(function () {

  /* ════════════════════════════════════════════════════════════
     01. CONSTANTES
  ════════════════════════════════════════════════════════════ */
  const $ = id => document.getElementById(id);

  const MODO_SIMULACAO = "simulacao";
  const MODO_REAL = "real";

  /* ════════════════════════════════════════════════════════════
     02. ESTADO PADRÃO
  ════════════════════════════════════════════════════════════ */
  let STATE = {
    // Modo global de operação
    modo: MODO_SIMULACAO,

    // Identidade do nó
    node: {
      name: "",
      ambiente: "lab",
      tag: "",
      desc: "",
    },

    // Configuração de rede
    rede: {
      cidr: "",
      gateway: "",
      dns1: "",
      dns2: "",
      ips_criticos: "",
      excluir: "",
      iface_principal: "",
    },

    // Scanner de rede
    scanner: {
      interval: 60,
      pingTimeout: 1000,
      maxHosts: 254,
      method: "ping_arp",
      hostname: true,
      mac: true,
      oui: true,
    },

    // Retenção de dados
    retencao: {
      devices: 30,
      logs: 7,
      dns: 7,
      incidents: 90,
    },

    // ═══ NOVO: Estrutura de Serviços (dados do backend) ═══
    servicos: {
      // AdGuard Home — DNS + Bloqueio
      adguard: {
        disponivel: false,
        configurado: false,
        conectado: false,
        url: "",
        user: "",
        pass: "",
        https: false,
        interval: 30,
        status: "simulado",
        ultima_coleta: null,
      },

      // Suricata IDS — componente Linux local
      suricata: {
        tipo: "suricata",
        nome: "Suricata IDS",
        modo: MODO_SIMULACAO,
        fonte: "simulada",
        instalado: false,
        versao: null,
        onboarding_concluido: false,
        instalacao_concluida: false,
        configurado: false,
        ativo: false,
        monitor_ativo: false,
        worker_ativo: false,
        eve_ativo: false,
        saudavel: false,
        status: "simulado",
        status_label: "Simulado",
        acao: "painel_simulado",
        componentes: {},
        interval: 5,
        minSeverity: 2,
        ultima_verificacao: null,
      },

      // Firewall — nftables local (placeholder)
      firewall: {
        disponivel: false,
        configurado: false,
        ativo: false,
        status: "simulado",
        target: "local",
        host: "",
        token: "",
        agente_porta: 8765,
        ultima_sync: null,
      },
    },

    // ═══ MANTIDO: Providers (compatibilidade com cfg-conexoes.js) ═══
    providers: {
      dns: {
        active: false,
        mode: "mock",
        url: "",
        user: "",
        pass: "",
        https: false,
        interval: 30,
      },
      ids: {
        active: false,
        mode: "mock",
        interval: 5,
        minSeverity: 2,
      },
      fw: {
        active: false,
        mode: "mock",
        target: "local",
        host: "",
        token: "",
        agente_porta: 8765,
      },
    },

    // Segurança
    seguranca: {
      sessionExpiry: 480,
      maxLoginAttempts: 5,
      forceHttps: false,
      accessLog: true,
      ipBan: true,
      logLevel: "INFO",
    },
  };

  const PROV_STATUS = {
    dns: "off",
    ids: "off",
    fw: "off",
  };

  /* ════════════════════════════════════════════════════════════
     03. NORMALIZAÇÃO / COMPATIBILIDADE
  ════════════════════════════════════════════════════════════ */

  /**
   * Normaliza valores de modo de qualquer formato para "simulacao" ou "real"
   * @param {string} input - valor do banco/formulário (demo, prod, mock, real, simulacao, ...)
   * @returns {string} - "simulacao" ou "real"
   */
  function normalizeMode(input) {
    if (!input) return MODO_SIMULACAO;

    const normalized = String(input).toLowerCase().trim();

    // Entrada legada/demo
    if (["demo", "mock", "demonstration", "test"].includes(normalized)) {
      return MODO_SIMULACAO;
    }

    // Entrada legada/prod
    if (["prod", "production", "real"].includes(normalized)) {
      return MODO_REAL;
    }

    // Entrada nova
    if (["simulacao", "simulation"].includes(normalized)) {
      return MODO_SIMULACAO;
    }

    // Fallback por segurança
    return MODO_SIMULACAO;
  }

  /**
   * Converte modo interno para formato visual (demo/prod)
   * Usado ao preencher SELECT#cfgModeSelect
   */
  function modoToVisual(internalMode) {
    return internalMode === MODO_REAL ? "prod" : "demo";
  }

  /**
   * Converte formato visual (demo/prod) para modo interno (simulacao/real)
   * Usado ao coletar do formulário
   */
  function visualToModo(visualMode) {
    return normalizeMode(visualMode);
  }

  /* ════════════════════════════════════════════════════════════
     04. HTTP / CSRF
  ════════════════════════════════════════════════════════════ */

  function getCsrfToken() {
    const el = document.querySelector("[name=csrfmiddlewaretoken]");
    if (el) return el.value;
    const match = document.cookie.match(/csrftoken=([^;]+)/);
    return match ? match[1] : "";
  }

  async function apiFetch(url, method = "GET", body = null) {
    const opts = {
      method,
      headers: { "Content-Type": "application/json" },
    };

    if (method !== "GET") {
      opts.headers["X-CSRFToken"] = getCsrfToken();
      if (body) opts.body = JSON.stringify(body);
    }

    const res = await fetch(url, opts);
    if (!res.ok && res.status !== 400) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }

  /* ════════════════════════════════════════════════════════════
     05. CARREGAMENTO
  ════════════════════════════════════════════════════════════ */

  /**
   * Carrega configuração global do sistema
   */
  async function loadConfig() {
    try {
      const data = await apiFetch("/configuracoes/api/config/");

      if (data.ok && data.config) {
        const remoteConfig = data.config;

        // Normaliza modo do backend (pode vir como "demo", "prod", "simulacao", "real", etc)
        remoteConfig.modo = normalizeMode(remoteConfig.modo);

        // Sincroniza providers legados com novo servicos (compatibilidade)
        if (remoteConfig.providers?.dns) {
          remoteConfig.servicos = remoteConfig.servicos || {};
          remoteConfig.servicos.adguard = {
            ...(remoteConfig.servicos.adguard || {}),
            url: remoteConfig.providers.dns.url || "",
            user: remoteConfig.providers.dns.user || "",
            pass: remoteConfig.providers.dns.pass || "",
            https: remoteConfig.providers.dns.https || false,
            interval: remoteConfig.providers.dns.interval || 30,
            conectado: remoteConfig.providers.dns.active || false,
          };
        }

        if (remoteConfig.providers?.ids) {
          remoteConfig.servicos = remoteConfig.servicos || {};
          remoteConfig.servicos.suricata = {
            ...(remoteConfig.servicos.suricata || {}),
            // Apenas preferências de consumo permanecem no provider legado.
            // O estado ativo/configurado/saudável virá exclusivamente de
            // GET /configuracoes/api/servicos/.
            interval: remoteConfig.providers.ids.interval || 5,
            minSeverity: remoteConfig.providers.ids.minSeverity || 2,
          };
        }

        if (remoteConfig.providers?.fw) {
          remoteConfig.servicos = remoteConfig.servicos || {};
          remoteConfig.servicos.firewall = {
            ...(remoteConfig.servicos.firewall || {}),
            target: remoteConfig.providers.fw.target || "local",
            host: remoteConfig.providers.fw.host || "",
            token: remoteConfig.providers.fw.token || "",
            agente_porta: remoteConfig.providers.fw.agente_porta || 8765,
            configurado: remoteConfig.providers.fw.active || false,
          };
        }

        STATE = remoteConfig;

        // Compatibilidade: cfg-conexoes.js ainda depende disso
        if (!PROV_STATUS.dns) PROV_STATUS.dns = "off";
        if (!PROV_STATUS.ids) PROV_STATUS.ids = "off";
        if (!PROV_STATUS.fw) PROV_STATUS.fw = "off";

        // v5: Carrega também status real dos serviços
        await loadServicosStatus();

        fillFormFromState();
        renderStatusBar();

        logDiag("OK", `Configurações carregadas. Modo: ${STATE.modo}`);
      }
    } catch (e) {
      logDiag("ERRO", `Falha ao carregar config: ${e.message}`);
      showToast("Falha ao carregar configurações", "erro");
    }
  }

  /**
   * v5: Carrega o estado consolidado dos serviços.
   *
   * A API /configuracoes/api/servicos/ é a fonte de verdade operacional.
   * Este método não executa Doctor, suricata -T, instalação ou reinício.
   */
  async function loadServicosStatus() {
    try {
      const data = await apiFetch("/configuracoes/api/servicos/");

      if (!data.ok) {
        logDiag("WARN", "Não foi possível carregar status dos serviços");
        return null;
      }

      STATE.modo = normalizeMode(data.modo);

      if (data.servicos) {
        const previous = STATE.servicos || {};

        STATE.servicos = {
          ...previous,

          adguard: {
            ...(previous.adguard || {}),
            ...(data.servicos.adguard || {}),
          },

          suricata: {
            ...(previous.suricata || {}),
            ...(data.servicos.suricata || {}),
            // Preferências locais que não fazem parte do health do backend.
            interval:
              previous.suricata?.interval
              ?? STATE.providers?.ids?.interval
              ?? 5,
            minSeverity:
              previous.suricata?.minSeverity
              ?? STATE.providers?.ids?.minSeverity
              ?? 2,
          },

          firewall: {
            ...(previous.firewall || {}),
            ...(data.servicos.firewall || {}),
          },
        };
      }

      STATE.resumo_servicos = data.resumo || {};
      STATE.servicos_atualizado_em = data.atualizado_em || null;

      _syncServicosToProviders();

      logDiag(
        "OK",
        `Status dos serviços carregado — modo: ${STATE.modo} · IDS: ${
          STATE.servicos?.suricata?.status || "desconhecido"
        }`
      );

      return data;
    } catch (e) {
      logDiag("WARN", `Falha ao carregar status dos serviços: ${e.message}`);
      return null;
    }
  }

  /**
   * Converte o status consolidado de um serviço para o indicador simples
   * utilizado pela barra superior.
   */
  function _providerHealthFromService(service, kind) {
    if (STATE.modo === MODO_SIMULACAO) return "mock";

    const status = String(service?.status || "").toLowerCase();

    if (kind === "ids") {
      if (status === "operacional" && service?.saudavel !== false) return "ok";
      if (status === "erro" || status === "nao_instalado") return "erro";
      if (status === "atencao" || status === "configuracao_pendente") return "warn";
      return "off";
    }

    if (kind === "dns") {
      if (status === "operacional" && service?.saudavel !== false) return "ok";
      if (status === "erro") return "erro";
      if (service?.configurado && status !== "operacional") return "warn";
      return "off";
    }

    if (kind === "fw") {
      if (status === "operacional" && service?.saudavel !== false) return "ok";
      if (status === "erro") return "erro";
      if (status === "atencao") return "warn";
      return "off";
    }

    return "off";
  }

  /**
   * STATE.servicos é a fonte de verdade.
   * STATE.providers existe apenas para manter os módulos legados funcionando.
   */
  function _syncServicosToProviders() {
    STATE.providers = STATE.providers || {};

    const adguard = STATE.servicos?.adguard || {};
    const suricata = STATE.servicos?.suricata || {};
    const firewall = STATE.servicos?.firewall || {};

    const isReal = STATE.modo === MODO_REAL;

    STATE.providers.dns = {
      ...(STATE.providers.dns || {}),
      active: isReal ? !!adguard.ativo : false,
      mode: isReal ? "real" : "mock",
      url: adguard.url || STATE.providers.dns?.url || "",
      interval: adguard.interval || STATE.providers.dns?.interval || 30,
    };

    STATE.providers.ids = {
      ...(STATE.providers.ids || {}),
      // O toggle legado não controla o daemon. Em modo real ele apenas
      // espelha o estado verdadeiro da stack local.
      active: isReal ? !!suricata.ativo : false,
      mode: isReal ? "eve" : "mock",
      interval: suricata.interval || STATE.providers.ids?.interval || 5,
      minSeverity: suricata.minSeverity || STATE.providers.ids?.minSeverity || 2,
    };

    STATE.providers.fw = {
      ...(STATE.providers.fw || {}),
      active: isReal ? !!firewall.ativo : false,
      mode: isReal ? "nftables" : "mock",
      target: firewall.target || STATE.providers.fw?.target || "local",
      host: firewall.host || STATE.providers.fw?.host || "",
      agente_porta:
        firewall.agente_porta
        || STATE.providers.fw?.agente_porta
        || 8765,
    };

    PROV_STATUS.dns = _providerHealthFromService(adguard, "dns");
    PROV_STATUS.ids = _providerHealthFromService(suricata, "ids");
    PROV_STATUS.fw = _providerHealthFromService(firewall, "fw");
  }

  /* ════════════════════════════════════════════════════════════
     06. FORMULÁRIO
  ════════════════════════════════════════════════════════════ */

  /**
   * Preenche o formulário a partir do STATE
   * SELECT#cfgModeSelect mostra "demo"/"prod" visualmente,
   * mas STATE.modo é "simulacao"/"real" internamente
   */
  function fillFormFromState() {
    const set = (id, v) => {
      if ($(id)) $(id).value = v ?? "";
    };
    const setChk = (id, v) => {
      if ($(id)) $(id).checked = !!v;
    };

    // Modo: converte "simulacao"/"real" para "demo"/"prod" para visual
    set("cfgModeSelect", modoToVisual(STATE.modo));

    // Node
    set("fieldNodeName", STATE.node?.name);
    set("fieldAmbiente", STATE.node?.ambiente);
    set("fieldTag", STATE.node?.tag);
    set("fieldDesc", STATE.node?.desc);

    // Rede
    const r = STATE.rede || {};
    set("fieldCidr", r.cidr);
    set("fieldGateway", r.gateway);
    set("fieldDns1", r.dns1);
    set("fieldDns2", r.dns2);
    set("fieldIpsCriticos", r.ips_criticos);
    set("fieldExcluir", r.excluir);

    // Scanner
    const sc = STATE.scanner || {};
    set("fieldScanInterval", sc.interval);
    set("fieldPingTimeout", sc.pingTimeout);
    set("fieldMaxHosts", sc.maxHosts);
    set("fieldScanMethod", sc.method);
    setChk("toggleHostname", sc.hostname);
    setChk("toggleMac", sc.mac);
    setChk("toggleOui", sc.oui);

    // Retenção
    const ret = STATE.retencao || {};
    set("fieldRetDevices", ret.devices);
    set("fieldRetLogs", ret.logs);
    set("fieldRetDns", ret.dns);
    set("fieldRetIncidents", ret.incidents);

    // Providers / Serviços (compatibilidade dual)
    const dns = STATE.providers?.dns || {};
    setChk("toggleDnsProvider", dns.active);
    _setSelectIfOptionExists("dnsMode", dns.mode);
    set("dnsUrl", dns.url);
    set("dnsUser", dns.user);
    set("dnsPass", dns.pass || "");
    setChk("dnsHttps", dns.https);
    set("dnsInterval", dns.interval);
    _updateUrlIndicator("dnsUrl", "dnsUrlStatus", dns.url);

    const ids = STATE.providers?.ids || {};
    setChk("toggleIdsProvider", ids.active);
    _setSelectIfOptionExists("idsMode", ids.mode);
    set("idsInterval", ids.interval);
    set("idsMinSeverity", ids.minSeverity);

    const fw = STATE.providers?.fw || {};
    setChk("toggleFwProvider", fw.active);
    _setSelectIfOptionExists("fwMode", fw.mode);
    set("fwTarget", fw.target);
    set("fwHost", fw.host);
    set("fwToken", fw.token || "");
    set("fwAgentePorta", fw.agente_porta ?? 8765);

    // Segurança
    const seg = STATE.seguranca || {};
    set("fieldSession", seg.sessionExpiry);
    set("fieldMaxLogin", seg.maxLoginAttempts);
    set("fieldLogLevel", seg.logLevel);
    setChk("toggleHttps", seg.forceHttps);
    setChk("toggleAccessLog", seg.accessLog);
    setChk("toggleIpBan", seg.ipBan);

    _updateDiagLabels();
  }

  /**
   * Coleta o estado do formulário e o converte para STATE
   * SELECT#cfgModeSelect enviará "demo"/"prod", convertendo para "simulacao"/"real"
   */
  function collectStateFromForm() {
    const g = (id, fb) => ($(id) ? $(id).value.trim() : fb);
    const gi = (id, fb) => ($(id) ? parseInt($(id).value) || fb : fb);
    const gb = (id, fb) => ($(id) ? $(id).checked : fb);

    // Coleta SELECT#cfgModeSelect como "demo"/"prod" e normaliza
    const visualMode = g("cfgModeSelect", "demo");
    const normalizedMode = visualToModo(visualMode);

    return {
      modo: normalizedMode,

      node: {
        name: g("fieldNodeName", STATE.node?.name),
        ambiente: g("fieldAmbiente", STATE.node?.ambiente),
        tag: g("fieldTag", STATE.node?.tag),
        desc: g("fieldDesc", STATE.node?.desc),
      },

      rede: {
        cidr: g("fieldCidr", STATE.rede?.cidr),
        gateway: g("fieldGateway", STATE.rede?.gateway),
        dns1: g("fieldDns1", STATE.rede?.dns1),
        dns2: g("fieldDns2", STATE.rede?.dns2),
        ips_criticos: g("fieldIpsCriticos", STATE.rede?.ips_criticos),
        excluir: g("fieldExcluir", STATE.rede?.excluir),
        iface_principal: STATE.rede?.iface_principal || "",
      },

      scanner: {
        interval: gi("fieldScanInterval", 60),
        pingTimeout: gi("fieldPingTimeout", 1000),
        maxHosts: gi("fieldMaxHosts", 254),
        method: g("fieldScanMethod", "ping_arp"),
        hostname: gb("toggleHostname", true),
        mac: gb("toggleMac", true),
        oui: gb("toggleOui", true),
      },

      retencao: {
        devices: gi("fieldRetDevices", 30),
        logs: gi("fieldRetLogs", 7),
        dns: gi("fieldRetDns", 7),
        incidents: gi("fieldRetIncidents", 90),
      },

      providers: {
        dns: {
          active: gb("toggleDnsProvider", false),
          mode: g("dnsMode", "mock"),
          url: g("dnsUrl", ""),
          user: g("dnsUser", ""),
          pass: g("dnsPass", ""),
          https: gb("dnsHttps", false),
          interval: gi("dnsInterval", 30),
        },
        ids: {
          // Suricata é local e auto-detectado. Em modo real o provider
          // legado espelha o runtime e nunca deve ser salvo como MOCK
          // por causa de um toggle visual antigo.
          active:
            normalizedMode === MODO_REAL
              ? !!STATE.servicos?.suricata?.ativo
              : false,
          mode:
            normalizedMode === MODO_REAL
              ? "eve"
              : "mock",
          interval: gi(
            "idsInterval",
            STATE.providers?.ids?.interval || 5
          ),
          minSeverity: gi(
            "idsMinSeverity",
            STATE.providers?.ids?.minSeverity || 2
          ),
        },
        fw: {
          active: gb("toggleFwProvider", false),
          mode: g("fwMode", "mock"),
          target: g("fwTarget", "local"),
          host: g("fwHost", ""),
          token: g("fwToken", ""),
          agente_porta: gi("fwAgentePorta", 8765),
        },
      },

      seguranca: {
        sessionExpiry: gi("fieldSession", 480),
        maxLoginAttempts: gi("fieldMaxLogin", 5),
        forceHttps: gb("toggleHttps", false),
        accessLog: gb("toggleAccessLog", true),
        ipBan: gb("toggleIpBan", true),
        logLevel: g("fieldLogLevel", "INFO"),
      },

      // Inclui servicos se existir (para futuro)
      servicos: STATE.servicos,
    };
  }

  function _setSelectIfOptionExists(selectId, value) {
    const el = $(selectId);
    if (!el || !value) return;
    const opt = el.querySelector(`option[value="${value}"]`);
    if (opt) el.value = value;
  }

  function _updateDiagLabels() {
    const gw = STATE.rede?.gateway || "—";
    const dns1 = STATE.rede?.dns1 || "1.1.1.1";
    if ($("#diagGateway")) $("#diagGateway").textContent = `Gateway: ${gw}`;
    if ($("#diagDns1")) $("#diagDns1").textContent = `DNS: ${dns1}`;
  }

  function _updateUrlIndicator(inputId, statusId, url) {
    const el = $(statusId);
    if (!el) return;
    if (url && url.startsWith("http")) {
      el.innerHTML = `<span style="color:#22c55e;font-size:10px;font-family:var(--font-mono)">✓ ${url}</span>`;
    } else {
      el.innerHTML = `<span style="color:var(--text-dim);font-size:10px;font-family:var(--font-mono)">Não configurada</span>`;
    }
  }

  /* ════════════════════════════════════════════════════════════
     07. STATUS
  ════════════════════════════════════════════════════════════ */

  function renderStatusBar() {
    if ($("#cfgNodeName"))
      $("#cfgNodeName").textContent = STATE.node?.name || "MS-NODE-01";
    if ($("#cfgNodeSub"))
      $("#cfgNodeSub").textContent = `Modo: ${
        STATE.modo === MODO_REAL ? "Real" : "Simulação"
      }`;
    if ($("#pillRedeLabel"))
      $("#pillRedeLabel").textContent = `Rede: ${STATE.rede?.cidr || "—"}`;
    if ($("#pillInterfaceLabel"))
      $("#pillInterfaceLabel").textContent = `Interface: ${
        STATE.rede?.iface_principal || "—"
      }`;

    ["dns", "ids", "fw"].forEach((p) =>
      renderProviderDot(`dot${p.toUpperCase()}`, PROV_STATUS[p])
    );

    const connected = Object.values(PROV_STATUS).filter(
      (s) => s === "ok"
    ).length;
    const badge = $("#tabBadgeIntegracoes");
    if (badge) {
      badge.textContent = `${connected}/3`;
      badge.style.background =
        connected === 3
          ? "rgba(34,197,94,.15)"
          : connected > 0
            ? "rgba(234,179,8,.15)"
            : "rgba(255,255,255,.08)";
      badge.style.color =
        connected === 3 ? "#22c55e" : connected > 0 ? "#eab308" : "#888";
    }
  }

  function renderProviderDot(id, status) {
    const el = $(id);
    if (!el) return;
    const cls = { ok: "ok", mock: "mock", warn: "warn", erro: "erro" }[
      status
    ] || "off";
    el.className = `cfg-provider-dot cfg-provider-dot--${cls}`;
  }

  /* ════════════════════════════════════════════════════════════
     08. DIAGNÓSTICO / HELPERS
  ════════════════════════════════════════════════════════════ */

  function nowStr() {
    return new Date().toLocaleTimeString("pt-BR", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  }

  function fmtLastSync(ts) {
    if (!ts) return "nunca";
    return new Date(ts).toLocaleTimeString("pt-BR", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  }

  function fmtTempo(segundos) {
    if (segundos === null || segundos === undefined)
      return "nunca conectou";
    if (segundos < 60) return `${segundos}s atrás`;
    if (segundos < 3600) return `${Math.floor(segundos / 60)}min atrás`;
    return `${Math.floor(segundos / 3600)}h atrás`;
  }

  function capitalize(s) {
    return s.charAt(0).toUpperCase() + s.slice(1);
  }

  let _toastTimer;
  function showToast(msg, type = "ok") {
    const t = $("#cfgToast");
    if (!t) return;
    t.textContent = msg;
    t.className = `cfg-toast cfg-toast--${type} show`;
    clearTimeout(_toastTimer);
    _toastTimer = setTimeout(() => t.classList.remove("show"), 3500);
  }

  function logDiag(level, msg) {
    const log = $("#diagLog");
    if (!log) return;
    log.querySelector(".cfg-diag-log__empty")?.remove();
    const row = document.createElement("div");
    row.className = `cfg-diag-log-entry cfg-diag-log-entry--${level.toLowerCase()}`;
    row.innerHTML = `
      <span class="cfg-diag-log-entry__time">${nowStr()}</span>
      <span class="cfg-diag-log-entry__level">${level}</span>
      <span class="cfg-diag-log-entry__msg">${msg}</span>`;
    log.insertBefore(row, log.firstChild);
    if (log.children.length > 60) log.removeChild(log.lastChild);
  }

  /* ════════════════════════════════════════════════════════════
     09. CONFIGURAÇÃO DOS PROVIDERS (Mantido para compatibilidade)
  ════════════════════════════════════════════════════════════ */

  const PROVIDER_CFG = {
    dns: {
      selectId: "dnsMode",
      badgeId: "badgeModeDns",
      overlayId: "overlayDns",
      statusId: "statusDns",
      toggleId: "toggleDnsProvider",
      lastSyncId: "dnsLastSync",
      label: "DNS",
      defaultRealMode: "real",
      demoOptions: [{ value: "mock", label: "Mock (simulado)" }],
      prodOptions: [{ value: "real", label: "AdGuard Real" }],
    },
    ids: {
      selectId: "idsMode",
      badgeId: "badgeModeIds",
      overlayId: "overlayIds",
      statusId: "statusIds",
      toggleId: "toggleIdsProvider",
      lastSyncId: "idsLastSync",
      label: "IDS",
      defaultRealMode: "eve",
      demoOptions: [{ value: "mock", label: "Mock (simulado)" }],
      prodOptions: [
        { value: "eve", label: "Sensor Linux (ms_sensor.py)" },
        { value: "syslog", label: "Syslog (em breve)", disabled: true },
      ],
    },
    fw: {
      selectId: "fwMode",
      badgeId: "badgeModeFw",
      overlayId: "overlayFw",
      statusId: "statusFw",
      toggleId: "toggleFwProvider",
      lastSyncId: "fwLastSync",
      label: "Firewall",
      defaultRealMode: "nftables",
      demoOptions: [{ value: "mock", label: "Mock (simulado)" }],
      prodOptions: [
        { value: "nftables", label: "nftables (ms_firewall.py)" },
        { value: "iptables", label: "iptables (em breve)", disabled: true },
        { value: "pfsense", label: "pfSense API (em breve)", disabled: true },
      ],
    },
  };

  /* ════════════════════════════════════════════════════════════
     10. EXPORTS PÚBLICOS
  ════════════════════════════════════════════════════════════ */

  window.CfgNucleo = {
    // Constantes
    MODO_SIMULACAO,
    MODO_REAL,

    // Elementos DOM
    $,

    // Estado
    get STATE() {
      return STATE;
    },
    set STATE(v) {
      STATE = v;
    },
    PROV_STATUS,
    PROVIDER_CFG,

    // Normalização
    normalizeMode,
    modoToVisual,
    visualToModo,

    // HTTP / CSRF
    getCsrfToken,
    apiFetch,

    // Carregamento
    loadConfig,
    loadServicosStatus,
    _syncServicosToProviders,
    _providerHealthFromService,

    // Formulário
    fillFormFromState,
    collectStateFromForm,
    _setSelectIfOptionExists,
    _updateUrlIndicator,
    _updateDiagLabels,

    // Status
    renderStatusBar,
    renderProviderDot,

    // Helpers
    nowStr,
    fmtLastSync,
    fmtTempo,
    capitalize,
    showToast,
    logDiag,
  };

  /* ════════════════════════════════════════════════════════════
     BOOTSTRAP (inicialização automática ao carregar)
  ════════════════════════════════════════════════════════════ */

  // Inicializado por cfg-infraestrutura.js após DOMContentLoaded

})();