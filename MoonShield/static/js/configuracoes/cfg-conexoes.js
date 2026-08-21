/**
 * MOONSHIELD — cfg-conexoes.js  v6
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

  // Pequena animação usada pelo botão Atualizar do Firewall.
  // Injetada aqui para não exigir alteração em configuracoes.css.
  if (!document.getElementById("cfgFirewallRuntimeStyle")) {
    const style = document.createElement("style");
    style.id = "cfgFirewallRuntimeStyle";
    style.textContent = `
      @keyframes cfgFirewallSpin {
        to { transform: rotate(360deg); }
      }
    `;
    document.head.appendChild(style);
  }

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

    // Renderiza o último estado conhecido do Firewall
    _renderFirewallPanel(isProd);

    // No modo Real, atualiza o estado diretamente da API local do Firewall.
    // A chamada é assíncrona e não bloqueia a renderização da tela.
    if (isProd) {
      _fetchFirewallRuntimeStatus({
        silent: true,
      });
    }

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

    /*
     * Fonte de verdade visual:
     * - modo global vem de STATE.modo;
     * - configuração/saúde vem de STATE.servicos.adguard;
     * - STATE.providers.dns fica somente para campos/preferências legadas.
     *
     * Regra importante:
     * em Modo Real este card NUNCA deve exibir "MOCK".
     */
    const service = n().STATE.servicos?.adguard || {};
    const provider = n().STATE.providers?.dns || {};

    const configurado = service.configurado === true || !!provider.url;
    const ativo = service.ativo === true || provider.active === true;
    const saudavel = service.saudavel === true;
    const operacional =
      service.status === "operacional"
      || (configurado && ativo && saudavel);

    let visualStatus = "simulado";
    let statusLabel = "Simulado";
    let badgeLabel = "SIMULAÇÃO";
    let color = "#eab308";
    let borderColor = "rgba(234,179,8,.12)";

    if (isProd) {
      if (!configurado) {
        visualStatus = "pendente";
        statusLabel = "Não configurado";
        badgeLabel = "PENDENTE";
        color = "#f59e0b";
        borderColor = "rgba(245,158,11,.22)";
      } else if (operacional) {
        visualStatus = "operacional";
        statusLabel = "Operacional";
        badgeLabel = "REMOTO";
        color = "#22c55e";
        borderColor = "rgba(34,197,94,.30)";
      } else if (!ativo) {
        visualStatus = "desativado";
        statusLabel = "Desativado";
        badgeLabel = "REAL";
        color = "#94a3b8";
        borderColor = "rgba(148,163,184,.18)";
      } else {
        visualStatus = "pendente";
        statusLabel = service.status_label || "Pendente";
        badgeLabel = "PENDENTE";
        color = "#f59e0b";
        borderColor = "rgba(245,158,11,.22)";
      }
    }

    connector.style.borderColor = borderColor;

    const statusEl = $("statusDns");
    if (statusEl) {
      statusEl.innerHTML = `
        <span
          class="cfg-conn-dot"
          style="background:${color};box-shadow:0 0 6px ${color}88"
        ></span>
        ${statusLabel}
      `;
    }

    const badge = $("badgeModeDns");
    if (badge) {
      badge.textContent = badgeLabel;

      // Mantém as classes existentes do projeto, mas sem semântica "MOCK"
      // em modo real.
      badge.className =
        `cfg-provider-mode-badge cfg-provider-mode-badge--${
          visualStatus === "operacional" || visualStatus === "desativado"
            ? "real"
            : "mock"
        }`;

      if (isProd && visualStatus === "pendente") {
        badge.style.background = "rgba(245,158,11,.10)";
        badge.style.borderColor = "rgba(245,158,11,.35)";
        badge.style.color = "#f59e0b";
      } else if (isProd) {
        badge.style.background = "";
        badge.style.borderColor = "";
        badge.style.color = "";
      } else {
        badge.style.background = "";
        badge.style.borderColor = "";
        badge.style.color = "";
      }

      badge.title =
        !isProd
          ? "Integração bloqueada pelo Modo Simulação"
          : !configurado
            ? "Modo Real ativo — configure o AdGuard para concluir a integração"
            : operacional
              ? "Integração remota do AdGuard operacional"
              : "Integração real configurada, porém ainda não operacional";
    }

    /*
     * O switch do AdGuard continua sendo configurável pelo usuário em Modo Real.
     * Em simulação ele é bloqueado pela lógica global de applyMode().
     */
    const toggle = $("toggleDnsProvider");
    if (toggle && isProd) {
      toggle.checked = !!provider.active;
      toggle.title =
        configurado
          ? "Ativar ou desativar a integração AdGuard"
          : "Configure URL e credenciais antes de ativar";
    }

    n().logDiag(
      operacional ? "OK" : "INFO",
      `AdGuard: ${visualStatus} · modo=${isProd ? "real" : "simulacao"}`
    );
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

      const realSelected = isProd;

      modeBadge.textContent =
        realLocal
          ? "LOCAL"
          : realSelected
            ? "PENDENTE"
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
          : realSelected
            ? "Modo Real selecionado — salve para sincronizar o backend"
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

    // Resumo amigável do estado consolidado
    const summaryIcon = $("suricataSummaryIcon");
    const summaryTitle = $("suricataSummaryTitle");
    const summaryText = $("suricataSummaryText");
    const sourceLabel = $("suricataSourceLabel");

    const realPersisted = (
      isProd
      && state.modo === MODO_REAL
      && state.fonte === "local"
    );

    if (summaryIcon) {
      const summaryColor =
        state.status === "operacional"
          ? "#22c55e"
          : state.status === "erro" || state.status === "nao_instalado"
            ? "#ef4444"
            : state.status === "simulado"
              ? "#eab308"
              : "#f97316";

      summaryIcon.style.color = summaryColor;
      summaryIcon.style.borderColor = `${summaryColor}33`;
      summaryIcon.style.background = `${summaryColor}0D`;
    }

    if (summaryTitle) {
      if (!isProd) {
        summaryTitle.textContent = "Modo Simulação";
      } else if (!realPersisted && state.status === "simulado") {
        summaryTitle.textContent = "Modo Real selecionado";
      } else if (state.status === "operacional") {
        summaryTitle.textContent = "Stack Suricata operacional";
      } else if (state.status === "nao_instalado") {
        summaryTitle.textContent = "Suricata não instalado";
      } else if (state.status === "configuracao_pendente") {
        summaryTitle.textContent = "Configuração pendente";
      } else {
        summaryTitle.textContent = state.statusLabel || "Stack requer atenção";
      }
    }

    if (summaryText) {
      if (!isProd) {
        summaryText.textContent =
          "O Suricata real permanece bloqueado enquanto o MoonShield estiver em Modo Simulação.";
      } else if (!realPersisted && state.status === "simulado") {
        summaryText.textContent =
          "Clique em Salvar Tudo para persistir o Modo Real e consultar a stack local.";
      } else if (state.status === "operacional") {
        summaryText.textContent =
          "Motor IDS, monitor, worker e EVE estão ativos e integrados ao pipeline do MoonShield.";
      } else if (state.status === "nao_instalado") {
        summaryText.textContent =
          "O componente local ainda precisa ser instalado neste servidor.";
      } else {
        summaryText.textContent =
          state.statusLabel || "Consulte o painel do Suricata para revisar o estado da stack.";
      }
    }

    if (sourceLabel) {
      sourceLabel.textContent =
        realPersisted
          ? "local"
          : isProd
            ? "aguardando sincronização"
            : "simulada";
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
      } else if (state.status === "simulado") {
        resultEl.textContent =
          "Modo Real selecionado — clique em Salvar Tudo para sincronizar a stack local.";

        resultEl.className =
          "cfg-test-result";
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
     08. FIREWALL — COMPONENTE LOCAL / MOONSHIELD-AGENT
  ════════════════════════════════════════════════════════════ */

  const FIREWALL_STATUS_UI = {
    simulado: {
      label: "Simulado",
      button: "Abrir painel",
      icon: "bi-play-circle",
      color: "#eab308",
      border: "rgba(234,179,8,.12)",
    },
    somente_linux: {
      label: "Disponível no Linux",
      button: "Abrir instalador",
      icon: "bi-hdd-stack",
      color: "#eab308",
      border: "rgba(234,179,8,.20)",
    },
    agent_offline: {
      label: "Agent indisponível",
      button: "Abrir instalador",
      icon: "bi-exclamation-triangle",
      color: "#ef4444",
      border: "rgba(239,68,68,.22)",
    },
    nao_instalado: {
      label: "Não instalado",
      button: "Instalar Firewall",
      icon: "bi-download",
      color: "#f97316",
      border: "rgba(249,115,22,.22)",
    },
    atencao: {
      label: "Requer atenção",
      button: "Revisar / reparar",
      icon: "bi-wrench-adjustable",
      color: "#f97316",
      border: "rgba(249,115,22,.22)",
    },
    operacional: {
      label: "Operacional",
      button: "Abrir Firewall",
      icon: "bi-shield-check",
      color: "#22c55e",
      border: "rgba(34,197,94,.30)",
    },
    erro: {
      label: "Erro",
      button: "Abrir instalador",
      icon: "bi-x-octagon",
      color: "#ef4444",
      border: "rgba(239,68,68,.28)",
    },
  };

  function _getFirewallUrls() {
    const el = $("firewallUrls");

    if (!el) {
      return {
        status: null,
        install: null,
        painel: null,
      };
    }

    return {
      status: el.dataset.statusUrl || null,
      install: el.dataset.installUrl || null,
      painel: el.dataset.painelUrl || null,
    };
  }

  function _firewallErrorMessage(payload, fallback = "") {
    if (!payload) return fallback;

    if (typeof payload === "string") {
      return payload;
    }

    if (typeof payload.erro === "string") {
      return payload.erro;
    }

    if (payload.erro && typeof payload.erro === "object") {
      return (
        payload.erro.mensagem
        || payload.erro.erro
        || fallback
      );
    }

    return (
      payload.mensagem
      || payload.message
      || fallback
    );
  }

  function _isLinuxOnlyMessage(message) {
    const text = String(message || "").toLowerCase();

    return (
      text.includes("só está disponível no host linux")
      || text.includes("somente")
         && text.includes("linux")
      || text.includes("only")
         && text.includes("linux")
    );
  }

  function _normalizeFirewallRuntime(raw = {}, httpStatus = 200) {
    const isDemo = isSimulationMode();

    if (isDemo) {
      return {
        ...raw,
        status: "simulado",
        status_label: "Simulado",
        acao: "painel_simulado",
        fonte: "simulada",
        saudavel: false,
        operacional: false,
      };
    }

    const errorMessage = _firewallErrorMessage(raw, "");
    const linuxOnly = _isLinuxOnlyMessage(errorMessage);

    if (linuxOnly) {
      return {
        ...raw,
        status: "somente_linux",
        status_label: "Disponível somente no Linux",
        acao: "instalar",
        fonte: "local",
        agent_disponivel: false,
        nftables_instalado: false,
        instalado: false,
        tabela_instalada: false,
        chains_ok: false,
        operacional: false,
        saudavel: false,
        erro: errorMessage,
        http_status: httpStatus,
      };
    }

    const agentOk =
      raw.agent_disponivel === true
      || raw.agent_ativo === true;

    const nftOk = raw.nftables_instalado === true;

    const instalado =
      raw.instalado === true
      || raw.tabela_instalada === true
      || raw.ativo === true
      || raw.operacional === true;

    const operational = raw.operacional === true;
    const chainsOk = raw.chains_ok === true;

    if (operational) {
      return {
        ...raw,
        status: "operacional",
        status_label: raw.status_label || "Operacional",
        acao: "painel",
        fonte: "local",
        agent_disponivel: agentOk,
        nftables_instalado: nftOk,
        instalado: true,
        tabela_instalada: raw.tabela_instalada !== false,
        chains_ok: chainsOk,
        operacional: true,
        saudavel: true,
      };
    }

    if (!agentOk) {
      return {
        ...raw,
        status: httpStatus >= 500 ? "agent_offline" : "erro",
        status_label:
          raw.status_label
          || (httpStatus >= 500 ? "Agent indisponível" : "Erro"),
        acao: "instalar",
        fonte: "local",
        agent_disponivel: false,
        operacional: false,
        saudavel: false,
        erro:
          errorMessage
          || "MoonShield-Agent indisponível.",
        http_status: httpStatus,
      };
    }

    if (!instalado) {
      return {
        ...raw,
        status: "nao_instalado",
        status_label: "Não instalado",
        acao: "instalar",
        fonte: "local",
        agent_disponivel: true,
        nftables_instalado: nftOk,
        instalado: false,
        tabela_instalada: false,
        chains_ok: false,
        operacional: false,
        saudavel: false,
      };
    }

    return {
      ...raw,
      status: "atencao",
      status_label:
        raw.status_label
        || "Requer atenção",
      acao: "reparar",
      fonte: "local",
      agent_disponivel: true,
      nftables_instalado: nftOk,
      instalado: true,
      operacional: false,
      saudavel: false,
      erro: errorMessage || null,
    };
  }

  async function _fetchFirewallRuntimeStatus(opts = {}) {
    const { silent = false } = opts;
    const urls = _getFirewallUrls();

    if (!urls.status) {
      const runtime = _normalizeFirewallRuntime(
        {
          erro: "URL de status do Firewall não configurada no template.",
        },
        500
      );

      _storeFirewallRuntime(runtime);
      _renderFirewallPanel(isRealMode());

      return runtime;
    }

    if (!isRealMode()) {
      const runtime = _normalizeFirewallRuntime({});
      _storeFirewallRuntime(runtime);
      _renderFirewallPanel(false);
      return runtime;
    }

    const refreshBtn = $("firewallRefreshBtn");

    if (refreshBtn) {
      refreshBtn.disabled = true;
      const icon = refreshBtn.querySelector("i");
      if (icon) {
        icon.style.animation = "cfgFirewallSpin .7s linear infinite";
      }
    }

    try {
      /*
       * Não usa n().apiFetch aqui de propósito:
       * /firewall/api/status/ retorna 503 quando o Agent não está disponível.
       * Precisamos ler o JSON desse 503 para distinguir:
       * - Windows (somente Linux)
       * - Agent offline
       * - outro erro real
       */
      const response = await fetch(urls.status, {
        method: "GET",
        credentials: "same-origin",
        headers: {
          Accept: "application/json",
        },
      });

      let data = {};

      try {
        data = await response.json();
      } catch (_) {
        data = {};
      }

      const runtime = _normalizeFirewallRuntime(
        data,
        response.status
      );

      _storeFirewallRuntime(runtime);
      _renderFirewallPanel(true);

      if (!silent) {
        const level =
          runtime.status === "operacional"
            ? "OK"
            : runtime.status === "nao_instalado"
              ? "INFO"
              : "WARN";

        n().logDiag(
          level,
          `Firewall: ${runtime.status_label}`
        );
      }

      return runtime;
    } catch (e) {
      const runtime = _normalizeFirewallRuntime(
        {
          erro:
            e?.message
            || "Falha ao consultar o Firewall.",
        },
        503
      );

      _storeFirewallRuntime(runtime);
      _renderFirewallPanel(true);

      if (!silent) {
        n().logDiag(
          "WARN",
          `Firewall: ${runtime.erro || runtime.status_label}`
        );
      }

      return runtime;
    } finally {
      if (refreshBtn) {
        refreshBtn.disabled = false;
        const icon = refreshBtn.querySelector("i");
        if (icon) {
          icon.style.animation = "";
        }
      }
    }
  }

  function _storeFirewallRuntime(runtime) {
    const nucleo = n();

    nucleo.STATE.servicos =
      nucleo.STATE.servicos
      || {};

    nucleo.STATE.servicos.firewall = {
      ...(nucleo.STATE.servicos.firewall || {}),
      ...runtime,
    };

    const isReal = isRealMode();

    nucleo.STATE.providers =
      nucleo.STATE.providers
      || {};

    nucleo.STATE.providers.fw = {
      ...(nucleo.STATE.providers.fw || {}),
      active:
        isReal
        && runtime.operacional === true,
      mode:
        isReal
          ? "nftables"
          : "mock",
      target: "local",
    };

    if (!isReal) {
      nucleo.PROV_STATUS.fw = "mock";
    } else if (runtime.status === "operacional") {
      nucleo.PROV_STATUS.fw = "ok";
    } else if (
      runtime.status === "nao_instalado"
      || runtime.status === "atencao"
      || runtime.status === "somente_linux"
    ) {
      nucleo.PROV_STATUS.fw = "warn";
    } else {
      nucleo.PROV_STATUS.fw = "erro";
    }

    nucleo.renderStatusBar();
    _renderSystemSummary();
  }

  function getFirewallState() {
    const firewall =
      n().STATE.servicos?.firewall
      || {};

    if (isSimulationMode()) {
      const ui = FIREWALL_STATUS_UI.simulado;

      return {
        ...firewall,
        status: "simulado",
        label: ui.label,
        button: ui.button,
        icon: ui.icon,
        color: ui.color,
        border: ui.border,
        acao: "painel_simulado",
      };
    }

    const status =
      firewall.status
      || (
        firewall.operacional
          ? "operacional"
          : firewall.instalado
            ? "atencao"
            : "nao_instalado"
      );

    const ui =
      FIREWALL_STATUS_UI[status]
      || FIREWALL_STATUS_UI.erro;

    return {
      ...firewall,
      status,
      label:
        firewall.status_label
        || ui.label,
      button: ui.button,
      icon: ui.icon,
      color: ui.color,
      border: ui.border,
      acao:
        firewall.acao
        || (
          status === "operacional"
            ? "painel"
            : status === "atencao"
              ? "reparar"
              : "instalar"
        ),
    };
  }

  function _setFirewallHealthRow(dotId, textId, ok, okLabel, failLabel) {
    const dot = $(dotId);
    const text = $(textId);

    const color =
      ok
        ? "#22c55e"
        : "var(--text-dim)";

    if (dot) {
      dot.style.background = color;
      dot.style.boxShadow =
        ok
          ? "0 0 6px rgba(34,197,94,.35)"
          : "none";
    }

    if (text) {
      text.textContent =
        ok
          ? okLabel
          : failLabel;

      text.style.color =
        ok
          ? "#22c55e"
          : "var(--text-muted)";
    }
  }

  function _renderFirewallPanel(isProd) {
    const connector = $("connectorFw");

    if (!connector) return;

    const state = getFirewallState();

    connector.style.borderColor =
      state.border
      || "";

    const statusEl = $("statusFw");

    if (statusEl) {
      statusEl.innerHTML = `
        <span
          class="cfg-conn-dot"
          style="
            background:${state.color};
            box-shadow:0 0 6px ${state.color}88
          "
        ></span>
        ${state.label}
      `;
    }

    const badge = $("badgeModeFw");

    if (badge) {
      const localRuntime =
        isProd
        && state.status !== "somente_linux";

      badge.textContent =
        isProd
          ? localRuntime
            ? "LOCAL"
            : "LINUX"
          : "SIMULAÇÃO";

      badge.className =
        `cfg-provider-mode-badge cfg-provider-mode-badge--${
          isProd
            ? "real"
            : "mock"
        }`;

      if (isProd) {
        badge.style.background =
          state.status === "operacional"
            ? "rgba(34,197,94,.10)"
            : "rgba(249,115,22,.10)";

        badge.style.borderColor =
          state.status === "operacional"
            ? "rgba(34,197,94,.28)"
            : "rgba(249,115,22,.28)";

        badge.style.color =
          state.status === "operacional"
            ? "#22c55e"
            : "#f97316";
      } else {
        badge.style.background = "";
        badge.style.borderColor = "";
        badge.style.color = "";
      }
    }

    const toggle = $("toggleFwProvider");

    if (toggle) {
      toggle.checked =
        isProd
        && state.operacional === true;

      toggle.disabled = true;

      toggle.setAttribute(
        "aria-label",
        state.operacional
          ? "Firewall operacional"
          : "Firewall não operacional"
      );

      const switchLabel =
        toggle.closest(".cfg-switch");

      if (switchLabel) {
        switchLabel.style.opacity = ".72";
        switchLabel.style.cursor = "default";
        switchLabel.title =
          "Indicador automático do estado do Firewall";
      }
    }

    const title = $("firewallSummaryTitle");
    const summary = $("firewallSummaryText");
    const iconBox = $("firewallSummaryIcon");

    if (title) {
      title.textContent = state.label;
    }

    if (summary) {
      if (!isProd) {
        summary.textContent =
          "Modo Simulação ativo. Mude para Modo Real para usar o Firewall local.";
      } else if (state.status === "operacional") {
        summary.textContent =
          "MoonShield-Agent, nftables, tabela e chains estão operacionais.";
      } else if (state.status === "nao_instalado") {
        summary.textContent =
          "O Agent está disponível. Conclua o instalador para criar a estrutura do Firewall.";
      } else if (state.status === "somente_linux") {
        summary.textContent =
          state.erro
          || "O MoonShield-Agent e o nftables só funcionam no host Linux.";
      } else if (state.status === "agent_offline") {
        summary.textContent =
          state.erro
          || "O Django não consegue acessar o MoonShield-Agent.";
      } else {
        summary.textContent =
          state.erro
          || "A instalação existe, mas requer validação ou reparo.";
      }
    }

    if (iconBox) {
      iconBox.style.color = state.color;
      iconBox.style.background =
        `${state.color}14`;

      iconBox.innerHTML =
        `<i class="bi ${state.icon}"></i>`;
    }

    _setFirewallHealthRow(
      "firewallAgentDot",
      "firewallAgentText",
      state.agent_disponivel === true
        || state.agent_ativo === true,
      "ONLINE",
      isProd
        ? "OFFLINE"
        : "—"
    );

    _setFirewallHealthRow(
      "firewallNftDot",
      "firewallNftText",
      state.nftables_instalado === true,
      state.nftables_versao
        ? `v${state.nftables_versao}`
        : "INSTALADO",
      state.status === "somente_linux"
        ? "LINUX"
        : "NÃO CONFIRMADO"
    );

    _setFirewallHealthRow(
      "firewallTableDot",
      "firewallTableText",
      state.tabela_instalada === true
        || state.operacional === true,
      "ATIVA",
      state.instalado
        ? "ATENÇÃO"
        : "NÃO INSTALADA"
    );

    _setFirewallHealthRow(
      "firewallChainsDot",
      "firewallChainsText",
      state.chains_ok === true
        || state.operacional === true,
      "OK",
      "—"
    );

    if ($("firewallWanText")) {
      $("firewallWanText").textContent =
        state.interface_wan
        || "—";
    }

    if ($("firewallMgmtText")) {
      $("firewallMgmtText").textContent =
        state.interface_mgmt
        || "—";
    }

    if ($("firewallLanText")) {
      $("firewallLanText").textContent =
        state.interface_lan
        || "—";
    }

    if ($("firewallHomeNetText")) {
      $("firewallHomeNetText").textContent =
        state.home_net
        || "—";
    }

    const linuxNotice = $("firewallLinuxNotice");

    if (linuxNotice) {
      const show =
        isProd
        && state.status === "somente_linux";

      linuxNotice.hidden = !show;

      if (show && $("firewallLinuxNoticeText")) {
        $("firewallLinuxNoticeText").textContent =
          state.erro
          || "O MoonShield-Agent e o nftables estão disponíveis apenas no host Linux.";
      }
    }

    const actionBtn = $("firewallActionBtn");

    if (actionBtn) {
      actionBtn.disabled =
        !isProd
        && state.status !== "simulado";

      actionBtn.innerHTML = `
        <i class="bi ${state.icon}"></i>
        ${state.button}
      `;

      actionBtn.dataset.firewallAction =
        state.acao
        || "instalar";
    }

    const meta = $("firewallMetaText");

    if (meta) {
      const socketPath =
        state.ipc?.socket
        || state.ipc?.caminho
        || "/run/moonshield/agent.sock";

      const table =
        state.tabela
        || "inet moonshield";

      meta.textContent =
        `IPC: ${socketPath} · tabela: ${table}`;
    }

    // Não existem sensores HTTP / Flask :8765.
    const sensorPanel = $("fwSensorPanel");
    if (sensorPanel) {
      sensorPanel.style.display = "none";
    }
  }

  function _handleFirewallActionClick() {
    const state = getFirewallState();
    const urls = _getFirewallUrls();

    let destino = null;

    switch (state.acao) {
      case "painel":
      case "painel_simulado":
        destino = urls.painel;
        break;

      case "instalar":
      case "reparar":
      default:
        destino = urls.install;
        break;
    }

    if (!destino) {
      n().showToast(
        "Não foi possível abrir o Firewall — URL indisponível.",
        "erro"
      );
      return;
    }

    window.location.assign(destino);
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

    // Firewall — status real do MoonShield-Agent/nftables
    const fwDot = $("systemFirewallDot");
    const fwStatus = $("systemFirewallStatus");
    const firewallState = getFirewallState();

    if (fwDot) {
      fwDot.style.background = firewallState.color || "var(--text-dim)";
      fwDot.style.boxShadow =
        firewallState.status === "operacional"
          ? "0 0 6px rgba(34,197,94,.35)"
          : "none";
    }

    if (fwStatus) {
      fwStatus.textContent =
        firewallState.label
        || "—";
    }
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

    // Firewall local: o switch é somente indicador automático.
    const fwToggle = $("toggleFwProvider");
    if (fwToggle) {
      fwToggle.disabled = true;
    }

    $("firewallActionBtn")?.addEventListener(
      "click",
      _handleFirewallActionClick
    );

    $("firewallRefreshBtn")?.addEventListener(
      "click",
      async () => {
        await _fetchFirewallRuntimeStatus({
          silent: false,
        });
      }
    );

    logDiag("INFO", "MoonShield Conexões v6 inicializado.");
  });

  /* ════════════════════════════════════════════════════════════
     13. EXPORTS PÚBLICOS
  ════════════════════════════════════════════════════════════ */

  function refreshFromState() {
    applyMode(
      n().STATE.modo,
      { silent: true }
    );

    _fetchFirewallRuntimeStatus({
      silent: true,
    });
  }

  window.CfgConexoes = {
    // Modo
    applyMode,
    refreshFromState,
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
    _getFirewallUrls,
    _fetchFirewallRuntimeStatus,

    // Status (compatibilidade)
    setProviderStatus,

    // Legado (manter para não quebrar página)
    loadSensores,
    loadFwSensores,
  };
})();