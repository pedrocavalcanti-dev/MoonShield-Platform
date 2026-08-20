/**
 * MOONSHIELD — cfg-conexoes.js  v5
 * ─────────────────────────────────────────────────────────────────────
 * v5: Serviços reais + Suricata local como fonte operacional
 *   - $ = document.getElementById(id) → NUNCA usar "#" nas chamadas
 *   - AdGuard: integração remota isolada, teste real (INALTERADO)
 *   - Suricata: componente local, navegação por STATE.servicos.suricata.acao
 *     usando as URLs reais expostas em #suricataUrls (sem hardcode)
 *   - Firewall: componente local placeholder, sem implementação
 *   - Resumo da aba Sistema preenchido a partir do mesmo STATE (sem novas
 *     chamadas HTTP por card)
 * ─────────────────────────────────────────────────────────────────────
 */

(function () {

  const n = () => window.CfgNucleo;
  const $ = id => document.getElementById(id);

  /* ════════════════════════════════════════════════════════════
     01. CONSTANTES
  ════════════════════════════════════════════════════════════ */

  const MODO_SIMULACAO = "simulacao";
  const MODO_REAL = "real";

  // Mapas de UI do Suricata — chaveados pelo "status" que o backend já
  // decidiu (STATE.servicos.suricata.status). O frontend NUNCA infere
  // instalação/serviço sozinho, apenas renderiza o que veio pronto.
  const SURICATA_STATUS_UI = {
    simulado: {
      label: "Simulado",
      botao: "Abrir painel",
      icon: "bi-play-circle",
    },
    nao_instalado: {
      label: "Não instalado",
      botao: "Instalar Suricata",
      icon: "bi-download",
    },
    configuracao_pendente: {
      label: "Configuração pendente",
      botao: "Continuar configuração",
      icon: "bi-exclamation-circle",
    },
    operacional: {
      label: "Operacional",
      botao: "Abrir painel",
      icon: "bi-shield-check",
    },
    atencao: {
      label: "Requer atenção",
      botao: "Abrir painel",
      icon: "bi-exclamation-triangle",
    },
    erro: {
      label: "Erro",
      botao: "Abrir painel",
      icon: "bi-x-octagon",
    },
  };

  const SURICATA_BORDER_COLORS = {
    simulado: "rgba(234,179,8,.12)",
    nao_instalado: "rgba(239,68,68,.2)",
    configuracao_pendente: "rgba(249,115,22,.2)",
    operacional: "rgba(34,197,94,.3)",
    atencao: "rgba(249,115,22,.2)",
    erro: "rgba(239,68,68,.3)",
  };

  const SURICATA_DOT_COLORS = {
    simulado: "#eab308",
    nao_instalado: "#ef4444",
    configuracao_pendente: "#f97316",
    operacional: "#22c55e",
    atencao: "#f97316",
    erro: "#ef4444",
  };

  const ADGUARD_STATUS_LABEL = {
    simulado: "Simulado",
    operacional: "Operacional",
    desativado: "Desativado",
  };

  const ADGUARD_DOT_COLOR = {
    simulado: "#eab308",
    operacional: "#22c55e",
    desativado: "#888",
  };

  /* ════════════════════════════════════════════════════════════
     02. HELPERS DE MODO
  ════════════════════════════════════════════════════════════ */

  function isSimulationMode() {
    return n().STATE.modo === MODO_SIMULACAO;
  }

  function isRealMode() {
    return n().STATE.modo === MODO_REAL;
  }

  /* ════════════════════════════════════════════════════════════
     03. MODO GLOBAL — APLICAR MODO
  ════════════════════════════════════════════════════════════ */

  /**
   * Aplica modo global: "simulacao" ou "real"
   * Controla overlays, desabilita campos, renderiza estados apropriados
   * Não ativa/desativa providers individuais — tudo é global
   */
  function applyMode(mode, opts = {}) {
    const { silent = false } = opts;
    const nucleo = n();
    const normalizedMode = nucleo.normalizeMode(mode);
    nucleo.STATE.modo = normalizedMode;

    const isDemo = isSimulationMode();
    const isProd = isRealMode();

    // Banner de produção
    const prodBanner = $("prodModeBanner");
    if (prodBanner)
      prodBanner.style.display = isProd ? "flex" : "none";

    // Badge de modo na status bar
    const badge = $("modeBadge");
    if (badge) {
      badge.textContent = isProd ? "PROD" : "DEMO";
      badge.style.background = isProd
        ? "rgba(239,68,68,.18)"
        : "rgba(234,179,8,.18)";
      badge.style.color = isProd ? "#ef4444" : "#eab308";
    }

    // Overlays dos conectores (AdGuard, IDS, Firewall)
    // Em simulação, mostrar overlay; em produção, ocultar
    Object.values(nucleo.PROVIDER_CFG).forEach((cfg) => {
      const overlay = $(cfg.overlayId);
      if (overlay) overlay.style.display = isDemo ? "flex" : "none";
    });

    // Campos reais (URL, usuário, senha) — desabilitar em simulação
    const realFieldIds = [
      "dnsUrl",
      "dnsUser",
      "dnsPass",
      "dnsHttps",
      "fwHost",
      "fwToken",
      "fwAgentePorta",
    ];
    realFieldIds.forEach((id) => {
      const el = $(id);
      if (!el) return;
      el.disabled = isDemo;
      el.style.opacity = isDemo ? ".35" : "1";
      el.style.cursor = isDemo ? "not-allowed" : "";
    });

    // Hint de integrações
    _updateIntegrationHint(isDemo);

    // Renderiza estado de AdGuard (integração remota — lógica preservada)
    _renderAdGuardPanel(isProd);

    // Renderiza estado de Suricata (componente local)
    _renderSuricataPanel(isProd);

    // Renderiza estado de Firewall
    _renderFirewallPanel(isProd);

    // Resumo da aba Sistema — usa o mesmo STATE já carregado
    _renderSystemSummary();

    // Status bar
    nucleo.renderStatusBar();

    if (!silent) {
      nucleo.logDiag(
        "INFO",
        isDemo
          ? "Modo Simulação — integrações bloqueadas."
          : "Modo Real — integrações ativas."
      );
    }
  }

  /* ════════════════════════════════════════════════════════════
     04. HINT DE INTEGRAÇÕES
  ════════════════════════════════════════════════════════════ */

  function _updateIntegrationHint(isDemo) {
    const hint = $("integracoesHint");
    if (!hint) return;

    if (isDemo) {
      hint.className = "cfg-integrations-hint cfg-integrations-hint--demo";
      hint.innerHTML = `
        <i class="bi bi-lock-fill"></i>
        <span>
          Modo <strong>Simulação</strong> — integrações reais permanecem bloqueadas.
          Mude para <strong>Modo Real</strong> para utilizar os serviços deste nó.
        </span>`;
    } else {
      hint.className = "cfg-integrations-hint cfg-integrations-hint--prod";
      hint.innerHTML = `
        <i class="bi bi-unlock-fill"></i>
        <span>
          Modo <strong>Real</strong> ativo.
          O <strong>Suricata local é detectado automaticamente</strong>;
          o AdGuard continua sendo uma integração configurada separadamente.
        </span>`;
    }
  }

  /* ════════════════════════════════════════════════════════════
     05. ADGUARD — INTEGRAÇÃO REMOTA ISOLADA (INALTERADO)
  ════════════════════════════════════════════════════════════ */

  /**
   * Renderiza painel de AdGuard
   * AdGuard continua sendo uma integração REMOTA via API — roda em
   * outro servidor/host, não é um serviço Linux local.
   */
  function _renderAdGuardPanel(isProd) {
    const connector = $("connectorDns");
    if (!connector) return;

    const state = n().STATE.providers?.dns || {};
    const isActive = state.active || false;
    const isUrl = state.url && state.url.startsWith("http");

    // Status do conector
    if (isProd && isActive) {
      connector.style.borderColor = isUrl
        ? "rgba(34,197,94,.3)"
        : "rgba(234,179,8,.2)";
    } else if (isProd) {
      connector.style.borderColor = "rgba(255,255,255,.06)";
    } else {
      connector.style.borderColor = "rgba(234,179,8,.12)";
    }
  }

  /**
   * Testa conexão com AdGuard (integração remota real)
   * Lógica, endpoint, payload e campos preservados integralmente:
   *   POST /configuracoes/api/testar-provider/  { provider: "dns" }
   */
  async function _testAdGuardConnection() {
    const { apiFetch, capitalize, fmtLastSync, logDiag, showToast } = n();
    const key = "dns";
    const testBtn = $("btnTestDns");
    const resEl = $("testResultDns");
    const origHtml = testBtn ? testBtn.innerHTML : "";

    if (testBtn) {
      testBtn.innerHTML = `<i class="bi bi-hourglass-split"></i> Testando...`;
      testBtn.disabled = true;
    }
    if (resEl) {
      resEl.textContent = "Verificando...";
      resEl.className = "cfg-test-result";
    }

    try {
      await apiFetch(
        "/configuracoes/api/salvar/",
        "POST",
        n().collectStateFromForm()
      );
    } catch (_) {}

    try {
      const data = await apiFetch("/configuracoes/api/testar-provider/", "POST", {
        provider: key,
      });

      if (data.ok) {
        const isMock = data.status === "mock";
        if (resEl) {
          resEl.textContent = `✓ ${data.msg}`;
          resEl.className = `cfg-test-result cfg-test-result--${
            isMock ? "mock" : "ok"
          }`;
        }
        const ls = $("dnsLastSync");
        if (ls) ls.textContent = fmtLastSync(Date.now());
        if (testBtn) {
          testBtn.innerHTML = `<i class="bi bi-check-circle-fill"></i> Conectado`;
          testBtn.style.background = "rgba(34,197,94,.2)";
          setTimeout(() => {
            testBtn.innerHTML = origHtml;
            testBtn.style.background = "rgba(34,197,94,.1)";
          }, 3000);
        }
        logDiag("OK", `AdGuard: ${data.msg}`);
        showToast(`AdGuard — ${data.msg}`);
      } else {
        if (resEl) {
          resEl.textContent = `✗ ${data.msg}`;
          resEl.className = "cfg-test-result cfg-test-result--err";
        }
        if (testBtn) {
          testBtn.innerHTML = `<i class="bi bi-x-circle-fill"></i> Falhou`;
          testBtn.style.background = "rgba(239,68,68,.1)";
          testBtn.style.borderColor = "rgba(239,68,68,.35)";
          testBtn.style.color = "#ef4444";
          setTimeout(() => {
            testBtn.innerHTML = origHtml;
            testBtn.style.background = "rgba(34,197,94,.1)";
            testBtn.style.borderColor = "rgba(34,197,94,.35)";
            testBtn.style.color = "#3b82f6";
          }, 4000);
        }
        logDiag("ERRO", `AdGuard: ${data.msg}`);
        showToast(`AdGuard falhou: ${data.msg}`, "erro");
      }
    } catch (e) {
      if (resEl) {
        resEl.textContent = `✗ Erro de rede`;
        resEl.className = "cfg-test-result cfg-test-result--err";
      }
      if (testBtn) testBtn.innerHTML = origHtml;
      logDiag("ERRO", `AdGuard teste: ${e.message}`);
    } finally {
      if (testBtn) testBtn.disabled = false;
    }
  }

  /* ════════════════════════════════════════════════════════════
     06. SURICATA — COMPONENTE LOCAL (RENDERIZAÇÃO)
  ════════════════════════════════════════════════════════════ */

  /**
   * Retorna o estado do Suricata a partir de STATE.servicos.suricata,
   * que já vem pronto do backend (status + acao). O frontend não
   * decide nada sobre instalação/serviço — apenas mapeia para UI.
   */
  function getSuricataState() {
    const suricata = n().STATE.servicos?.suricata || {};
    const status = suricata.status || "simulado";
    const ui = SURICATA_STATUS_UI[status] || SURICATA_STATUS_UI.simulado;

    return {
      status,
      statusLabel: suricata.status_label || ui.label,
      acao: suricata.acao || "painel_simulado",
      label: suricata.status_label || ui.label,
      botao: ui.botao,
      icon: ui.icon,
      modo: suricata.modo || n().STATE.modo,
      fonte: suricata.fonte || (isRealMode() ? "local" : "simulada"),
      versao: suricata.versao || null,
      instalado: !!suricata.instalado,
      configurado: !!suricata.configurado,
      saudavel: suricata.saudavel === true || status === "operacional",
      ativo: !!suricata.ativo,
      monitorAtivo: !!suricata.monitor_ativo,
      workerAtivo: !!suricata.worker_ativo,
      eveAtivo: !!suricata.eve_ativo,
      atualizadoEm:
        n().STATE.servicos_atualizado_em
        || suricata.ultima_verificacao
        || null,
    };
  }

  /**
   * Lê o container #suricataUrls (preenchido pelo Django via {% url %})
   * e retorna as URLs reais de onboarding e painel do Suricata.
   * Nunca hardcodar essas URLs no JS.
   */
  function _getSuricataUrls() {
    const el = $("suricataUrls");
    if (!el) return { onboarding: null, painel: null };

    return {
      onboarding: el.dataset.onboardingUrl || null,
      painel: el.dataset.painelUrl || null,
    };
  }

  /**
   * Determina para qual URL o botão do Suricata deve navegar,
   * com base exclusivamente em STATE.servicos.suricata.acao.
   *
   *   instalar               → onboarding
   *   continuar_instalacao   → onboarding
   *   painel                 → painel
   *   painel_simulado        → painel
   */
  function _getSuricataActionDestination(acao, urls) {
    switch (acao) {
      case "instalar":
      case "continuar_instalacao":
        return urls.onboarding || null;
      case "painel":
      case "painel_simulado":
        return urls.painel || null;
      default:
        return null;
    }
  }

  /**
   * Renderiza painel de Suricata na aba Serviços a partir do
   * STATE.servicos.suricata já carregado (sem chamadas HTTP extras).
   */
  function _renderSuricataPanel(isProd) {
    const connector = $("connectorIds");
    if (!connector) return;

    const state = getSuricataState();

    // Borda do conector
    connector.style.borderColor =
      SURICATA_BORDER_COLORS[state.status]
      || "";

    // Status principal do card
    const statusEl = $("statusIds");

    if (statusEl) {
      const dotColor =
        SURICATA_DOT_COLORS[state.status]
        || "#888";

      statusEl.innerHTML = `
        <span
          class="cfg-conn-dot"
          style="
            background:${dotColor};
            box-shadow:0 0 6px ${dotColor}88
          "
        ></span>
        ${state.label}
      `;
    }

    // O badge deixa de representar provider MOCK no modo real.
    const modeBadge = $("badgeModeIds");

    if (modeBadge) {
      const realLocal = isProd && state.fonte === "local";

      modeBadge.textContent =
        realLocal
          ? "LOCAL"
          : "SIMULAÇÃO";

      modeBadge.className =
        `cfg-provider-mode-badge cfg-provider-mode-badge--${
          realLocal
            ? "real"
            : "mock"
        }`;

      modeBadge.title =
        realLocal
          ? "Componente local detectado automaticamente"
          : "Componente bloqueado pelo modo de simulação";
    }

    // O switch legado agora é somente indicador visual.
    // Ele NÃO liga/desliga o daemon do Suricata.
    const idsToggle = $("toggleIdsProvider");

    if (idsToggle) {
      idsToggle.checked =
        isProd
        && state.ativo;

      idsToggle.disabled = true;
      idsToggle.setAttribute(
        "aria-label",
        "Estado do Suricata gerenciado automaticamente"
      );

      const switchLabel = idsToggle.closest(".cfg-switch");

      if (switchLabel) {
        switchLabel.style.opacity = "1";
        switchLabel.style.cursor = "default";
        switchLabel.title =
          isProd
            ? "Estado automático do serviço local"
            : "Disponível apenas no Modo Real";
      }
    }

    // Versão
    const versionLabel = $("suricataVersionLabel");

    if (versionLabel) {
      versionLabel.textContent =
        state.versao
          ? `v${state.versao}`
          : "";
    }

    // Componentes da stack
    _renderSuricataDetailDot(
      "suricataServiceDot",
      "suricataServiceText",
      state.ativo,
      "Ativo",
      "Inativo"
    );

    _renderSuricataDetailDot(
      "suricataMonitorDot",
      "suricataMonitorText",
      state.monitorAtivo,
      "Ativo",
      "Inativo"
    );

    _renderSuricataDetailDot(
      "suricataWorkerDot",
      "suricataWorkerText",
      state.workerAtivo,
      "Ativo",
      "Inativo"
    );

    _renderSuricataDetailDot(
      "suricataEveDot",
      "suricataEveText",
      state.eveAtivo,
      "Atualizando",
      "Inativo"
    );

    // Botão contextual
    const actionBtn = $("suricataActionBtn");

    if (actionBtn) {
      actionBtn.innerHTML =
        `<i class="bi ${state.icon}"></i> ${state.botao}`;

      actionBtn.disabled = false;
    }

    // Resultado amigável no corpo do card
    const resultEl = $("testResultIds");

    if (resultEl) {
      if (!isProd) {
        resultEl.textContent =
          "Modo Simulação — o serviço real não é consultado.";

        resultEl.className =
          "cfg-test-result cfg-test-result--mock";
      } else if (state.saudavel && state.status === "operacional") {
        resultEl.textContent =
          "✓ Stack local operacional e integrada ao MoonShield.";

        resultEl.className =
          "cfg-test-result cfg-test-result--ok";
      } else if (state.status === "nao_instalado") {
        resultEl.textContent =
          "Suricata ainda não está instalado neste nó.";

        resultEl.className =
          "cfg-test-result cfg-test-result--err";
      } else {
        resultEl.textContent =
          state.statusLabel || "Requer atenção";

        resultEl.className =
          "cfg-test-result cfg-test-result--err";
      }
    }

    // Última verificação da API agregadora
    const lastSync = $("idsLastSync");

    if (lastSync) {
      lastSync.textContent =
        state.atualizadoEm
          ? n().fmtLastSync(state.atualizadoEm)
          : "agora";
    }

    // Sensores externos legados não fazem parte desta arquitetura
    const sensorPanel = $("idsSensorPanel");

    if (sensorPanel) {
      sensorPanel.style.display = "none";
    }

    n().logDiag(
      state.saudavel ? "OK" : "INFO",
      `Suricata: ${state.status} · local=${state.fonte === "local"} · ação=${state.acao}`
    );
  }

  function _renderSuricataDetailDot(
    dotId,
    textId,
    ativo,
    activeLabel = "Ativo",
    inactiveLabel = "Inativo"
  ) {
    const dot = $(dotId);
    const text = $(textId);

    if (dot) {
      dot.style.background =
        ativo
          ? "#22c55e"
          : "var(--text-dim)";

      dot.style.boxShadow =
        ativo
          ? "0 0 6px rgba(34,197,94,.35)"
          : "none";
    }

    if (text) {
      text.textContent =
        ativo
          ? activeLabel
          : inactiveLabel;

      text.style.color =
        ativo
          ? "#22c55e"
          : "var(--text-muted)";
    }
  }

  /* ════════════════════════════════════════════════════════════
     07. SURICATA — NAVEGAÇÃO (BOTÃO ÚNICO)
  ════════════════════════════════════════════════════════════ */

  function _handleSuricataActionClick() {
    const { logDiag, showToast, STATE } = n();
    const suricata = STATE.servicos?.suricata || {};
    const urls = _getSuricataUrls();
    const destino = _getSuricataActionDestination(suricata.acao, urls);

    if (!destino) {
      logDiag(
        "ERRO",
        `Suricata: não foi possível determinar a URL de destino para a ação "${suricata.acao}".`
      );
      showToast("Não foi possível abrir o Suricata — URL indisponível.", "erro");
      return;
    }

    window.location.assign(destino);
  }

  /* ════════════════════════════════════════════════════════════
     08. FIREWALL — COMPONENTE LOCAL PLACEHOLDER
  ════════════════════════════════════════════════════════════ */

  /**
   * Retorna estado conceitual do Firewall
   */
  function getFirewallState() {
    const isDemo = isSimulationMode();

    if (isDemo) {
      return {
        status: "simulado",
        label: "Simulado",
        icon: "bi-play-circle",
        color: "#eab308",
        description: "Modo simulação — dados de teste",
      };
    }

    // Modo real — placeholder até integração nftables
    return {
      status: "em_breve",
      label: "Em desenvolvimento",
      icon: "bi-gear",
      color: "#3b82f6",
      description: "Integração nftables em breve",
    };
  }

  /**
   * Renderiza painel de Firewall na aba Serviços
   */
  function _renderFirewallPanel(isProd) {
    const connector = $("connectorFw");
    if (!connector) return;

    const state = getFirewallState();

    const borderColors = {
      simulado: "rgba(234,179,8,.12)",
      em_breve: "rgba(255,255,255,.06)",
    };
    connector.style.borderColor = borderColors[state.status] || "";

    const statusEl = $("statusFw");
    if (statusEl) {
      const dotColors = {
        simulado: "#eab308",
        em_breve: "#3b82f6",
      };
      const dotColor = dotColors[state.status] || "#888";
      statusEl.innerHTML = `
        <span class="cfg-conn-dot" style="background:${dotColor};box-shadow:0 0 6px ${dotColor}88"></span>
        ${state.label}
      `;
    }

    // Não há sensores de firewall (sem agente Flask :8765)
    const sensorPanel = $("fwSensorPanel");
    if (sensorPanel) sensorPanel.style.display = "none";

    n().logDiag("INFO", `Firewall: ${state.status}`);
  }

  /* ════════════════════════════════════════════════════════════
     09. RESUMO DA ABA SISTEMA
  ════════════════════════════════════════════════════════════ */

  /**
   * Preenche o resumo da aba Sistema (AdGuard / Suricata / Firewall)
   * usando exclusivamente o STATE já carregado — sem novas chamadas
   * HTTP por card.
   */
  function _renderSystemSummary() {
    const servicos = n().STATE.servicos || {};
    const adguard = servicos.adguard || {};
    const suricata = servicos.suricata || {};
    const firewall = servicos.firewall || {};

    // AdGuard
    const adguardDot = $("systemAdguardDot");
    const adguardStatus = $("systemAdguardStatus");
    const adguardLabel = ADGUARD_STATUS_LABEL[adguard.status] || "—";
    if (adguardDot)
      adguardDot.style.background = ADGUARD_DOT_COLOR[adguard.status] || "var(--text-dim)";
    if (adguardStatus) adguardStatus.textContent = adguardLabel;

    // Suricata
    const suricataDot = $("systemSuricataDot");
    const suricataStatus = $("systemSuricataStatus");
    const suricataVersion = $("systemSuricataVersion");
    const suricataUi =
      SURICATA_STATUS_UI[suricata.status]
      || SURICATA_STATUS_UI.simulado;

    if (suricataDot) {
      suricataDot.style.background =
        SURICATA_DOT_COLORS[suricata.status]
        || "var(--text-dim)";

      suricataDot.style.boxShadow =
        suricata.saudavel
          ? "0 0 6px rgba(34,197,94,.35)"
          : "none";
    }

    if (suricataStatus) {
      suricataStatus.textContent =
        suricata.status_label
        || suricataUi.label;
    }

    if (suricataVersion) {
      suricataVersion.textContent =
        suricata.versao
          ? `v${suricata.versao}`
          : "";
    }

    // Firewall
    const fwDot = $("systemFirewallDot");
    const fwStatus = $("systemFirewallStatus");
    const fwLabel = firewall.status === "simulado" ? "Simulado" : "Em desenvolvimento";
    const fwColor = firewall.status === "simulado" ? "#eab308" : "#3b82f6";
    if (fwDot) fwDot.style.background = fwColor;
    if (fwStatus) fwStatus.textContent = fwLabel;
  }

  /* ════════════════════════════════════════════════════════════
     10. STATUS VISUAL (Helper legado — compatibilidade)
  ════════════════════════════════════════════════════════════ */

  function setProviderStatus(key, status, msg) {
    const { capitalize, PROV_STATUS } = n();
    const el = $(`status${capitalize(key)}`);
    if (!el) return;

    const colors = {
      ok: { bg: "#22c55e", sh: "#22c55e66" },
      mock: { bg: "#eab308", sh: "#eab30866" },
      warn: { bg: "#f97316", sh: "#f9731666" },
      erro: { bg: "#ef4444", sh: "#ef444466" },
      off: { bg: "#555", sh: "transparent" },
    };

    const c = colors[status] || colors.off;
    el.innerHTML = `<span class="cfg-conn-dot" style="background:${c.bg};box-shadow:0 0 6px ${c.sh}"></span>${msg}`;
    PROV_STATUS[key] = status;
    n().renderStatusBar();
  }

  /* ════════════════════════════════════════════════════════════
     11. COMPATIBILIDADE LEGADA — NO-OP STUBS
  ════════════════════════════════════════════════════════════ */

  // LEGADO TEMPORÁRIO — remover após refatoração completa do HTML
  function loadSensores() {
    // Não há mais polling/carregamento de sensores externos
  }

  // LEGADO TEMPORÁRIO — remover após refatoração completa do HTML
  function loadFwSensores() {
    // Não há mais polling/carregamento de sensores externos
  }

  /* ════════════════════════════════════════════════════════════
     12. LISTENERS
  ════════════════════════════════════════════════════════════ */

  document.addEventListener("DOMContentLoaded", () => {
    const { showToast, logDiag } = n();

    // Mudança de modo global
    $("cfgModeSelect")?.addEventListener("change", function () {
      applyMode(this.value);
      showToast(
        this.value === "prod"
          ? "⚡ Modo Real ativado"
          : "🔒 Modo Simulação ativado"
      );
    });

    // Botão de teste de AdGuard (único serviço com teste real)
    $("btnTestDns")?.addEventListener("click", async () => {
      await _testAdGuardConnection();
    });

    // Botão único do Suricata (navegação — sem chamada de API de instalação)
    $("suricataActionBtn")?.addEventListener("click", _handleSuricataActionClick);

    // Toggle de AdGuard
    const dnsToggle = $("toggleDnsProvider");
    dnsToggle?.addEventListener("change", function () {
      if (this.checked) {
        showToast("AdGuard ativado");
        logDiag("INFO", "AdGuard habilitado");
      } else {
        showToast("AdGuard desativado");
        logDiag("INFO", "AdGuard desabilitado");
      }
      _renderAdGuardPanel(isRealMode());
    });

    // Suricata é um serviço local auto-detectado.
    // O switch legado permanece apenas como indicador de estado e não possui
    // listener de ativação/desativação.
    const idsToggle = $("toggleIdsProvider");
    if (idsToggle) {
      idsToggle.disabled = true;
    }

    // Toggle de Firewall (compatibilidade)
    const fwToggle = $("toggleFwProvider");
    fwToggle?.addEventListener("change", function () {
      if (this.checked) {
        showToast("Firewall preparado");
        logDiag("INFO", "Firewall habilitado");
      } else {
        showToast("Firewall desabilitado");
        logDiag("INFO", "Firewall desabilitado");
      }
      _renderFirewallPanel(isRealMode());
    });

    logDiag("INFO", "MoonShield Conexões v5 inicializado.");
  });

  /* ════════════════════════════════════════════════════════════
     13. EXPORTS PÚBLICOS
  ════════════════════════════════════════════════════════════ */

  window.CfgConexoes = {
    // Modo
    applyMode,
    isSimulationMode,
    isRealMode,

    // AdGuard
    _testAdGuardConnection,

    // Suricata
    getSuricataState,
    _getSuricataUrls,
    _getSuricataActionDestination,

    // Firewall
    getFirewallState,

    // Status (compatibilidade)
    setProviderStatus,

    // Legado (manter para não quebrar página)
    loadSensores,
    loadFwSensores,
  };
})();