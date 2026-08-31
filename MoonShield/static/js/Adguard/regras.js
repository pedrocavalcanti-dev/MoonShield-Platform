/**
 * MOONSHIELD — regras.js v2
 * Gestão de regras customizadas do AdGuard Home.
 *
 * Mantém compatibilidade com:
 * GET  /dns/api/regras/
 * POST /dns/api/regras/salvar/
 * POST /dns/api/block/
 * POST /dns/api/allow/
 */

document.addEventListener('DOMContentLoaded', () => {
  'use strict';

  const $ = (id) => document.getElementById(id);

  const state = {
    allRules: [],
    filtered: [],
    selected: new Set(),
    currentFilter: 'all',
    searchTerm: '',
    page: 1,
    pageSize: 25,
    activeTab: 'block',
    isDemo: false,
    loading: false,
  };

  let toastTimer = null;

  function escHtml(value) {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function getCsrf() {
    return document.cookie
      .split(';')
      .map((c) => c.trim())
      .find((c) => c.startsWith('csrftoken='))
      ?.split('=')[1] || '';
  }

  function normalizeRule(rule) {
    return String(rule || '').trim();
  }

  function classifyRule(rule) {
    const r = normalizeRule(rule);

    if (r.startsWith('@@')) return 'allow';
    if (r.startsWith('||')) return 'block';
    if (/^(0\.0\.0\.0|127\.\d+\.\d+\.\d+)\s+/.test(r)) return 'block';
    if (r.startsWith('!') || r.startsWith('#')) return 'comment';
    if (r.startsWith('/')) return 'regex';

    return 'other';
  }

  function extractDomain(rule) {
    const r = normalizeRule(rule);

    let match = r.match(/^@@\|\|([^/^*]+)\^?/);
    if (match) return match[1];

    match = r.match(/^\|\|([^/^*]+)\^?/);
    if (match) return match[1];

    match = r.match(/^(?:0\.0\.0\.0|127\.\d+\.\d+\.\d+)\s+(.+)/);
    if (match) return match[1].trim();

    return '';
  }

  function formatBadge(type) {
    const map = {
      block: ['BLOCK', 'rg-type-badge--block'],
      allow: ['ALLOW', 'rg-type-badge--allow'],
      comment: ['COMMENT', 'rg-type-badge--other'],
      regex: ['REGEX', 'rg-type-badge--other'],
      other: ['OUTRO', 'rg-type-badge--other'],
    };

    const [label, cls] = map[type] || map.other;
    return `<span class="rg-type-badge ${cls}">${label}</span>`;
  }

  function formatBadgeLabel(rule) {
    const r = normalizeRule(rule);

    if (r.startsWith('@@||')) return '@@||x^';
    if (r.startsWith('||')) return '||x^';
    if (r.startsWith('0.0.0.0') || r.startsWith('127.')) return 'hosts';
    if (r.startsWith('/')) return '/regex/';
    if (r.startsWith('!') || r.startsWith('#')) return 'comment';

    return 'custom';
  }

  function showToast(message) {
    const toast = $('rgToast');
    if (!toast) return;

    toast.textContent = message;
    toast.classList.add('show');

    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove('show'), 2800);
  }

  function hideAllStates() {
    ['rgStateLoading', 'rgStateDemo', 'rgStateEmpty', 'rgStateNoResults'].forEach((id) => {
      const el = $(id);
      if (el) el.style.display = 'none';
    });
  }

  function showState(name) {
    hideAllStates();

    if ($('rgTable')) $('rgTable').style.display = 'none';
    if ($('rgPagination')) $('rgPagination').style.display = 'none';

    const map = {
      loading: 'rgStateLoading',
      demo: 'rgStateDemo',
      empty: 'rgStateEmpty',
      noResults: 'rgStateNoResults',
    };

    if (map[name] && $(map[name])) {
      $(map[name]).style.display = '';
    }
  }

  function updateStats(rules) {
    const block = rules.filter((rule) => classifyRule(rule) === 'block').length;
    const allow = rules.filter((rule) => classifyRule(rule) === 'allow').length;
    const other = rules.length - block - allow;

    if ($('statTotal')) $('statTotal').textContent = rules.length;
    if ($('statBlock')) $('statBlock').textContent = block;
    if ($('statAllow')) $('statAllow').textContent = allow;
    if ($('statOther')) $('statOther').textContent = other;
  }

  function updateSelectedUI() {
    const count = state.selected.size;
    const button = $('rgRemoveSelectedBtn');
    const wrap = $('statSelectedWrap');

    if (button) button.disabled = count === 0;

    if (wrap) {
      wrap.style.display = count > 0 ? '' : 'none';
    }

    if ($('statSelected')) {
      $('statSelected').textContent = count;
    }
  }

  function currentPageRules() {
    const start = (state.page - 1) * state.pageSize;
    return state.filtered.slice(start, start + state.pageSize);
  }

  function syncSelectAll() {
    const checkbox = $('rgSelectAll');
    if (!checkbox) return;

    const pageRules = currentPageRules();

    checkbox.checked =
      pageRules.length > 0 &&
      pageRules.every((rule) => state.selected.has(rule));

    checkbox.indeterminate =
      !checkbox.checked &&
      pageRules.some((rule) => state.selected.has(rule));
  }

  function applyFilters() {
    let result = [...state.allRules];

    if (state.currentFilter !== 'all') {
      if (state.currentFilter === 'other') {
        result = result.filter((rule) => {
          const type = classifyRule(rule);
          return type !== 'block' && type !== 'allow';
        });
      } else {
        result = result.filter(
          (rule) => classifyRule(rule) === state.currentFilter
        );
      }
    }

    if (state.searchTerm) {
      const query = state.searchTerm.toLowerCase();

      result = result.filter((rule) => {
        const domain = extractDomain(rule);

        return (
          rule.toLowerCase().includes(query) ||
          domain.toLowerCase().includes(query)
        );
      });
    }

    state.filtered = result;
    state.page = 1;

    renderTable();
    renderPagination();
    syncSelectAll();
  }

  function renderTable() {
    const tbody = $('rgTableBody');
    if (!tbody) return;

    const rows = currentPageRules();

    if (state.filtered.length === 0) {
      if ($('rgTable')) $('rgTable').style.display = 'none';
      if ($('rgPagination')) $('rgPagination').style.display = 'none';

      if (state.searchTerm || state.currentFilter !== 'all') {
        showState('noResults');

        if ($('rgNoResultsHint')) {
          $('rgNoResultsHint').textContent = state.searchTerm
            ? `Nenhuma regra contendo "${state.searchTerm}".`
            : 'Nenhuma regra nesta categoria.';
        }
      } else {
        showState('empty');
      }

      return;
    }

    hideAllStates();

    if ($('rgTable')) $('rgTable').style.display = '';
    if ($('rgPagination')) $('rgPagination').style.display = '';

    tbody.innerHTML = rows.map((rule) => {
      const type = classifyRule(rule);
      const domain = extractDomain(rule);
      const checked = state.selected.has(rule);

      return `
        <tr
          data-rule="${escHtml(rule)}"
          class="${checked ? 'rg-row--selected' : ''}"
        >
          <td>
            <label class="rg-checkbox">
              <input
                type="checkbox"
                class="rg-row-check"
                data-rule="${escHtml(rule)}"
                ${checked ? 'checked' : ''}
              />
              <span class="rg-checkbox__box"></span>
            </label>
          </td>

          <td>${formatBadge(type)}</td>

          <td>
            <div class="rg-rule-text">${escHtml(rule)}</div>
            ${domain ? `<div class="rg-rule-domain">${escHtml(domain)}</div>` : ''}
          </td>

          <td>
            <span class="rg-fmt-badge">${formatBadgeLabel(rule)}</span>
          </td>

          <td>
            <div class="rg-row-actions">
              ${type === 'block' ? `
                <button
                  class="rg-row-btn rg-row-btn--toggle"
                  type="button"
                  data-act="toggle"
                  data-rule="${escHtml(rule)}"
                  title="Mudar para Permitir"
                >
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="20 6 9 17 4 12"/>
                  </svg>
                </button>
              ` : ''}

              ${type === 'allow' ? `
                <button
                  class="rg-row-btn rg-row-btn--danger"
                  type="button"
                  data-act="toggle"
                  data-rule="${escHtml(rule)}"
                  title="Mudar para Bloquear"
                >
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="10"/>
                    <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
                  </svg>
                </button>
              ` : ''}

              <button
                class="rg-row-btn"
                type="button"
                data-act="copy"
                data-rule="${escHtml(rule)}"
                title="Copiar regra"
              >
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <rect x="9" y="9" width="13" height="13" rx="2"/>
                  <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                </svg>
              </button>

              <button
                class="rg-row-btn rg-row-btn--danger"
                type="button"
                data-act="remove"
                data-rule="${escHtml(rule)}"
                title="Remover"
              >
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <polyline points="3 6 5 6 21 6"/>
                  <path d="M19 6l-1 14H6L5 6"/>
                </svg>
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join('');

    tbody.querySelectorAll('.rg-row-check').forEach((checkbox) => {
      checkbox.addEventListener('change', () => {
        const rule = checkbox.dataset.rule;

        if (checkbox.checked) state.selected.add(rule);
        else state.selected.delete(rule);

        checkbox
          .closest('tr')
          ?.classList.toggle('rg-row--selected', checkbox.checked);

        updateSelectedUI();
        syncSelectAll();
      });
    });

    tbody.querySelectorAll('[data-act]').forEach((button) => {
      button.addEventListener('click', async (event) => {
        event.stopPropagation();

        const rule = button.dataset.rule;
        const action = button.dataset.act;

        if (action === 'remove') {
          await confirmRemove([rule]);
        }

        if (action === 'toggle') {
          await toggleRule(rule);
        }

        if (action === 'copy') {
          await copyRule(rule);
        }
      });
    });

    tbody.querySelectorAll('tr[data-rule]').forEach((row) => {
      row.addEventListener('click', (event) => {
        if (
          event.target.closest('[data-act]') ||
          event.target.closest('.rg-checkbox')
        ) {
          return;
        }

        const checkbox = row.querySelector('.rg-row-check');
        if (!checkbox) return;

        checkbox.checked = !checkbox.checked;
        checkbox.dispatchEvent(new Event('change'));
      });
    });

    syncSelectAll();
  }

  function renderPagination() {
    const total = state.filtered.length;
    const pages = Math.max(1, Math.ceil(total / state.pageSize));

    if (state.page > pages) {
      state.page = pages;
    }

    const start =
      total === 0
        ? 0
        : (state.page - 1) * state.pageSize + 1;

    const end = Math.min(
      state.page * state.pageSize,
      total
    );

    if ($('rgPagInfo')) {
      $('rgPagInfo').textContent =
        `${start}–${end} de ${total} regra${total !== 1 ? 's' : ''}`;
    }

    if ($('rgPagPrev')) {
      $('rgPagPrev').disabled = state.page <= 1;
    }

    if ($('rgPagNext')) {
      $('rgPagNext').disabled = state.page >= pages;
    }

    const nums = $('rgPagNums');
    if (!nums) return;

    let pageNumbers;

    if (pages <= 7) {
      pageNumbers = Array.from({ length: pages }, (_, index) => index + 1);
    } else {
      const set = new Set([
        1,
        pages,
        state.page - 1,
        state.page,
        state.page + 1,
      ]);

      pageNumbers = [...set]
        .filter((value) => value >= 1 && value <= pages)
        .sort((a, b) => a - b);

      const expanded = [];

      pageNumbers.forEach((value, index) => {
        if (
          index > 0 &&
          value - pageNumbers[index - 1] > 1
        ) {
          expanded.push('…');
        }

        expanded.push(value);
      });

      pageNumbers = expanded;
    }

    nums.innerHTML = pageNumbers.map((value) => {
      if (value === '…') {
        return '<span style="padding:0 4px;color:var(--text-muted);font-size:11px">…</span>';
      }

      return `
        <button
          class="rg-pag-num${value === state.page ? ' rg-pag-num--active' : ''}"
          type="button"
          data-p="${value}"
        >
          ${value}
        </button>
      `;
    }).join('');

    nums.querySelectorAll('.rg-pag-num').forEach((button) => {
      button.addEventListener('click', () => {
        state.page = Number(button.dataset.p);

        renderTable();
        renderPagination();
        syncSelectAll();
      });
    });
  }

  async function loadRules() {
    if (state.loading) return;

    state.loading = true;
    showState('loading');

    state.selected.clear();
    updateSelectedUI();

    const refreshButton = $('rgRefreshBtn');
    if (refreshButton) refreshButton.disabled = true;

    try {
      const response = await fetch('/dns/api/regras/', {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
        },
        cache: 'no-store',
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok || !data.ok) {
        throw new Error(data.error || `HTTP ${response.status}`);
      }

      state.isDemo =
        data.mode === 'demo' ||
        data.mode === 'mock';

      if (state.isDemo) {
        state.allRules = [];
        state.filtered = [];

        updateStats([]);
        showState('demo');
        return;
      }

      const cleanRules = Array.isArray(data.rules)
        ? data.rules
          .map(normalizeRule)
          .filter(Boolean)
        : [];

      state.allRules = [...new Set(cleanRules)];

      updateStats(state.allRules);
      applyFilters();

    } catch (error) {
      state.allRules = [];
      state.filtered = [];

      updateStats([]);
      showState('empty');

      showToast(`Erro ao carregar regras: ${error.message}`);

    } finally {
      state.loading = false;

      if (refreshButton) {
        refreshButton.disabled = false;
      }
    }
  }

  async function saveFullRuleSet(rules) {
    try {
      const response = await fetch('/dns/api/regras/salvar/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'X-CSRFToken': getCsrf(),
        },
        body: JSON.stringify({
          rules,
        }),
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok || !data.ok) {
        throw new Error(data.error || `HTTP ${response.status}`);
      }

      return true;

    } catch (error) {
      showToast(`Erro ao salvar regras: ${error.message}`);
      return false;
    }
  }

  async function confirmRemove(rules) {
    const targets = [...new Set(rules)].filter((rule) =>
      state.allRules.includes(rule)
    );

    if (!targets.length) return;

    const message =
      targets.length === 1
        ? `Remover esta regra?\n\n${targets[0]}`
        : `Remover ${targets.length} regras selecionadas?`;

    if (!window.confirm(message)) return;

    const removeSet = new Set(targets);

    const newRules = state.allRules.filter(
      (rule) => !removeSet.has(rule)
    );

    const ok = await saveFullRuleSet(newRules);
    if (!ok) return;

    state.allRules = newRules;

    targets.forEach((rule) =>
      state.selected.delete(rule)
    );

    updateSelectedUI();
    updateStats(state.allRules);
    applyFilters();

    showToast(
      `${targets.length} regra${targets.length !== 1 ? 's' : ''} removida${targets.length !== 1 ? 's' : ''}`
    );
  }

  async function toggleRule(rule) {
    const type = classifyRule(rule);
    let newRule = '';

    if (type === 'block') {
      if (rule.startsWith('||')) {
        newRule = `@@${rule}`;
      } else {
        const domain = extractDomain(rule);

        if (!domain) {
          showToast('Não foi possível converter esta regra para ALLOW');
          return;
        }

        newRule = `@@||${domain}^`;
      }
    } else if (type === 'allow') {
      newRule = rule.replace(/^@@/, '');
    } else {
      showToast('Esse tipo de regra não pode ser alternado');
      return;
    }

    const newRules = state.allRules.map(
      (current) =>
        current === rule
          ? newRule
          : current
    );

    const deduped = [...new Set(newRules)];

    const ok = await saveFullRuleSet(deduped);
    if (!ok) return;

    state.allRules = deduped;

    state.selected.delete(rule);

    updateSelectedUI();
    updateStats(state.allRules);
    applyFilters();

    showToast(
      `Regra alterada para ${type === 'block' ? 'ALLOW' : 'BLOCK'}`
    );
  }

  async function copyRule(rule) {
    try {
      await navigator.clipboard.writeText(rule);
      showToast('Regra copiada');

    } catch {
      const textarea = document.createElement('textarea');

      textarea.value = rule;
      document.body.appendChild(textarea);

      textarea.select();
      document.execCommand('copy');

      textarea.remove();

      showToast('Regra copiada');
    }
  }

  function formatPreviewRules(raw, mode) {
    const lines = String(raw || '')
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);

    const result = [];

    for (const line of lines) {
      if (mode === 'advanced') {
        result.push(line);
        continue;
      }

      if (
        line.startsWith('||') ||
        line.startsWith('@@') ||
        line.startsWith('!') ||
        line.startsWith('#') ||
        line.startsWith('/') ||
        line.startsWith('0.0.0.0') ||
        line.startsWith('127.')
      ) {
        result.push(line);
        continue;
      }

      result.push(
        mode === 'allow'
          ? `@@||${line}^`
          : `||${line}^`
      );
    }

    return [...new Set(result)];
  }

  function updatePreview() {
    const raw = $('rgModalInput')?.value || '';
    const rules = formatPreviewRules(raw, state.activeTab);

    const preview = $('rgModalPreview');
    const list = $('rgModalPreviewList');

    if (!preview || !list) return;

    if (!rules.length) {
      preview.style.display = 'none';
      list.innerHTML = '';
      return;
    }

    preview.style.display = '';

    list.innerHTML = rules
      .map((rule) => `<div>${escHtml(rule)}</div>`)
      .join('');
  }

  function setTab(tab) {
    state.activeTab = tab;

    document
      .querySelectorAll('.rg-tab')
      .forEach((button) =>
        button.classList.remove('rg-tab--active')
      );

    document
      .querySelector(`.rg-tab[data-tab="${tab}"]`)
      ?.classList.add('rg-tab--active');

    const descriptions = {
      block:
        'Digite um domínio por linha. O backend aplicará o formato <code>||dominio^</code> e fará a validação.',
      allow:
        'Digite um domínio por linha. O backend criará a exceção <code>@@||dominio^</code>.',
      advanced:
        'Use a sintaxe completa do AdGuard. Uma regra por linha. Ex.: <code>||ads.example.com^</code>',
    };

    if ($('rgModalDesc')) {
      $('rgModalDesc').innerHTML =
        descriptions[tab] || '';
    }

    const confirmButton = $('rgModalConfirm');

    if (confirmButton) {
      confirmButton.textContent =
        tab === 'block'
          ? 'Bloquear'
          : tab === 'allow'
            ? 'Permitir'
            : 'Salvar Regras';

      confirmButton.style.background =
        tab === 'block'
          ? '#ef4444'
          : tab === 'allow'
            ? '#22c55e'
            : 'var(--text-primary)';

      confirmButton.style.color =
        tab === 'advanced'
          ? 'var(--bg)'
          : '#fff';
    }

    updatePreview();
  }

  function openModal() {
    if ($('rgModalInput')) {
      $('rgModalInput').value = '';
    }

    if ($('rgModalPreview')) {
      $('rgModalPreview').style.display = 'none';
    }

    if ($('rgModalPreviewList')) {
      $('rgModalPreviewList').innerHTML = '';
    }

    $('rgModalOverlay')?.classList.add('open');

    setTab('block');

    setTimeout(() => {
      $('rgModalInput')?.focus();
    }, 60);
  }

  function closeModal() {
    $('rgModalOverlay')?.classList.remove('open');
  }

  async function submitModal() {
    const raw = $('rgModalInput')?.value.trim() || '';

    if (!raw) {
      showToast('Digite ao menos um domínio ou regra');
      return;
    }

    const confirmButton = $('rgModalConfirm');
    const originalText =
      confirmButton?.textContent || 'Confirmar';

    if (confirmButton) {
      confirmButton.disabled = true;
      confirmButton.textContent = 'Processando...';
    }

    try {
      if (state.activeTab === 'advanced') {
        const newRules = formatPreviewRules(
          raw,
          'advanced'
        );

        const current = new Set(state.allRules);

        const toAdd = newRules.filter(
          (rule) => !current.has(rule)
        );

        if (!toAdd.length) {
          showToast('Todas as regras já existem');
          return;
        }

        const merged = [
          ...state.allRules,
          ...toAdd,
        ];

        const ok = await saveFullRuleSet(merged);
        if (!ok) return;

        state.allRules = merged;

        updateStats(state.allRules);
        applyFilters();

        closeModal();

        showToast(
          `${toAdd.length} regra${toAdd.length !== 1 ? 's' : ''} avançada${toAdd.length !== 1 ? 's' : ''} adicionada${toAdd.length !== 1 ? 's' : ''}`
        );

        return;
      }

      const url =
        state.activeTab === 'block'
          ? '/dns/api/block/'
          : '/dns/api/allow/';

      /*
       * Envia o texto original para o backend.
       * A normalização final fica concentrada em services/regras.py.
       */
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'X-CSRFToken': getCsrf(),
        },
        body: JSON.stringify({
          domains: raw,
        }),
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok || !data.ok) {
        throw new Error(
          data.error || `HTTP ${response.status}`
        );
      }

      const added =
        Array.isArray(data.added)
          ? data.added.length
          : 0;

      const skipped =
        Array.isArray(data.skipped)
          ? data.skipped.length
          : 0;

      closeModal();

      showToast(
        `${added} regra${added !== 1 ? 's' : ''} adicionada${added !== 1 ? 's' : ''}` +
        `${skipped ? ` · ${skipped} ignorada${skipped !== 1 ? 's' : ''}` : ''}`
      );

      await loadRules();

    } catch (error) {
      showToast(
        `Erro ao salvar: ${error.message}`
      );

    } finally {
      if (confirmButton) {
        confirmButton.disabled = false;

        confirmButton.textContent =
          state.activeTab === 'block'
            ? 'Bloquear'
            : state.activeTab === 'allow'
              ? 'Permitir'
              : originalText;
      }
    }
  }

  function bindEvents() {
    $('rgRefreshBtn')?.addEventListener(
      'click',
      loadRules
    );

    $('rgAddBtn')?.addEventListener(
      'click',
      openModal
    );

    $('rgAddFirstBtn')?.addEventListener(
      'click',
      openModal
    );

    $('rgRemoveSelectedBtn')?.addEventListener(
      'click',
      () => confirmRemove([...state.selected])
    );

    $('rgSelectAll')?.addEventListener(
      'change',
      (event) => {
        const rules = currentPageRules();

        if (event.target.checked) {
          rules.forEach((rule) =>
            state.selected.add(rule)
          );
        } else {
          rules.forEach((rule) =>
            state.selected.delete(rule)
          );
        }

        renderTable();
        updateSelectedUI();
      }
    );

    document
      .querySelectorAll('.rg-filter-btn')
      .forEach((button) => {
        button.addEventListener('click', () => {
          document
            .querySelectorAll('.rg-filter-btn')
            .forEach((current) =>
              current.classList.remove('rg-filter-btn--active')
            );

          button.classList.add(
            'rg-filter-btn--active'
          );

          state.currentFilter =
            button.dataset.filter || 'all';

          applyFilters();
        });
      });

    $('rgSearch')?.addEventListener(
      'input',
      (event) => {
        state.searchTerm =
          event.target.value.trim();

        if ($('rgSearchClear')) {
          $('rgSearchClear').style.display =
            state.searchTerm ? '' : 'none';
        }

        applyFilters();
      }
    );

    $('rgSearchClear')?.addEventListener(
      'click',
      () => {
        if ($('rgSearch')) {
          $('rgSearch').value = '';
        }

        state.searchTerm = '';

        if ($('rgSearchClear')) {
          $('rgSearchClear').style.display =
            'none';
        }

        applyFilters();
      }
    );

    $('rgPagPrev')?.addEventListener(
      'click',
      () => {
        if (state.page <= 1) return;

        state.page -= 1;

        renderTable();
        renderPagination();
        syncSelectAll();
      }
    );

    $('rgPagNext')?.addEventListener(
      'click',
      () => {
        const pages = Math.max(
          1,
          Math.ceil(
            state.filtered.length /
            state.pageSize
          )
        );

        if (state.page >= pages) return;

        state.page += 1;

        renderTable();
        renderPagination();
        syncSelectAll();
      }
    );

    $('rgModalClose')?.addEventListener(
      'click',
      closeModal
    );

    $('rgModalCancel')?.addEventListener(
      'click',
      closeModal
    );

    $('rgModalOverlay')?.addEventListener(
      'click',
      (event) => {
        if (event.target === $('rgModalOverlay')) {
          closeModal();
        }
      }
    );

    $('rgModalConfirm')?.addEventListener(
      'click',
      submitModal
    );

    $('rgModalInput')?.addEventListener(
      'input',
      updatePreview
    );

    document
      .querySelectorAll('.rg-tab')
      .forEach((button) => {
        button.addEventListener(
          'click',
          () => setTab(button.dataset.tab)
        );
      });

    document.addEventListener(
      'keydown',
      (event) => {
        if (event.key === 'Escape') {
          closeModal();
        }

        if (
          event.key === 'Enter' &&
          event.ctrlKey &&
          $('rgModalOverlay')?.classList.contains('open')
        ) {
          submitModal();
        }
      }
    );
  }

  bindEvents();
  loadRules();
});
