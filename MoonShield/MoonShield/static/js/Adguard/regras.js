/**
 * MOONSHIELD — regras.js
 * Página de Regras de Filtragem DNS
 */

document.addEventListener('DOMContentLoaded', () => {

    /* ── ESTADO ── */
    let allRules = [];   // todas as regras vindas do backend
    let filtered = [];   // após filtro/busca
    let selected = new Set();
    let currentFilter = 'all';
    let searchTerm = '';
    let page = 1;
    const PAGE_SIZE = 25;
    let activeTab = 'block';
    let isDemo = false;

    /* ── $ helper ── */
    const $ = id => document.getElementById(id);

    /* ═══════════════════════════════════════════════════════
       CLASSIFICAÇÃO DE REGRAS
    ═══════════════════════════════════════════════════════ */
    function classifyRule(rule) {
        const r = rule.trim();
        if (r.startsWith('@@')) return 'allow';
        if (r.startsWith('||') || r.startsWith('0.0.0.0') || r.startsWith('127.')) return 'block';
        if (r.startsWith('!') || r.startsWith('#')) return 'comment';
        if (r.startsWith('/')) return 'regex';
        return 'other';
    }

    function extractDomain(rule) {
        const r = rule.trim();
        let m = r.match(/^@@\|\|([^/^*]+)\^?/);
        if (m) return m[1];
        m = r.match(/^\|\|([^/^*]+)\^?/);
        if (m) return m[1];
        m = r.match(/^(?:0\.0\.0\.0|127\.\d+\.\d+\.\d+)\s+(.+)/);
        if (m) return m[1];
        return null;
    }

    function formatBadge(type) {
        const map = {
            block: { label: 'BLOCK', cls: 'rg-type-badge--block' },
            allow: { label: 'ALLOW', cls: 'rg-type-badge--allow' },
            comment: { label: 'COMMENT', cls: 'rg-type-badge--other' },
            regex: { label: 'REGEX', cls: 'rg-type-badge--other' },
            other: { label: 'OUTRO', cls: 'rg-type-badge--other' },
        };
        const c = map[type] || map.other;
        return `<span class="rg-type-badge ${c.cls}">${c.label}</span>`;
    }

    function formatBadgeLabel(rule) {
        const r = rule.trim();
        if (r.startsWith('@@||')) return '@@||x^';
        if (r.startsWith('||')) return '||x^';
        if (r.startsWith('0.0.0.0')) return 'hosts';
        if (r.startsWith('/')) return '/regex/';
        if (r.startsWith('!') || r.startsWith('#')) return 'comment';
        return 'custom';
    }

    /* ═══════════════════════════════════════════════════════
       CARREGAR REGRAS
    ═══════════════════════════════════════════════════════ */
    async function loadRules() {
        showState('loading');
        selected.clear();
        updateSelectedUI();

        try {
            const res = await fetch('/dns/api/regras/');
            const data = await res.json();

            if (!data.ok) throw new Error(data.error || 'Erro desconhecido');

            isDemo = data.mode === 'demo' || data.mode === 'mock';
            if (isDemo) { showState('demo'); updateStats([]); return; }

            allRules = (data.rules || []).filter(r => r.trim());
            applyFilters();
            updateStats(allRules);

        } catch (e) {
            showToast(`Erro ao carregar: ${e.message}`);
            showState('empty');
        }
    }

    /* ═══════════════════════════════════════════════════════
       FILTROS E BUSCA
    ═══════════════════════════════════════════════════════ */
    function applyFilters() {
        let result = [...allRules];

        if (currentFilter !== 'all') {
            if (currentFilter === 'other') {
                result = result.filter(r => !['block', 'allow'].includes(classifyRule(r)));
            } else {
                result = result.filter(r => classifyRule(r) === currentFilter);
            }
        }

        if (searchTerm) {
            const q = searchTerm.toLowerCase();
            result = result.filter(r => r.toLowerCase().includes(q));
        }

        filtered = result;
        page = 1;
        renderTable();
        renderPagination();
    }

    /* ═══════════════════════════════════════════════════════
       STATS
    ═══════════════════════════════════════════════════════ */
    function updateStats(rules) {
        const block = rules.filter(r => classifyRule(r) === 'block').length;
        const allow = rules.filter(r => classifyRule(r) === 'allow').length;
        const other = rules.filter(r => !['block', 'allow'].includes(classifyRule(r))).length;
        $('statTotal').textContent = rules.length;
        $('statBlock').textContent = block;
        $('statAllow').textContent = allow;
        $('statOther').textContent = other;
    }

    function updateSelectedUI() {
        const n = selected.size;
        const btn = $('rgRemoveSelectedBtn');
        const wrap = $('statSelectedWrap');
        btn.disabled = n === 0;
        if (n > 0) {
            wrap.style.display = '';
            $('statSelected').textContent = n;
        } else {
            wrap.style.display = 'none';
        }
    }

    /* ═══════════════════════════════════════════════════════
       RENDER TABELA
    ═══════════════════════════════════════════════════════ */
    function renderTable() {
        const tbody = $('rgTableBody');
        const start = (page - 1) * PAGE_SIZE;
        const rows = filtered.slice(start, start + PAGE_SIZE);

        if (filtered.length === 0) {
            $('rgTable').style.display = 'none';
            if (searchTerm || currentFilter !== 'all') {
                $('rgStateNoResults').style.display = '';
                $('rgNoResultsHint').textContent = searchTerm
                    ? `Nenhuma regra contendo "${searchTerm}".`
                    : 'Nenhuma regra nesta categoria.';
            } else {
                showState('empty');
            }
            return;
        }

        hideAllStates();
        $('rgTable').style.display = '';
        $('rgPagination').style.display = '';

        tbody.innerHTML = rows.map((rule, i) => {
            const type = classifyRule(rule);
            const domain = extractDomain(rule);
            const isChecked = selected.has(rule) ? 'checked' : '';

            return `
      <tr data-rule="${escHtml(rule)}" class="${selected.has(rule) ? 'rg-row--selected' : ''}">
        <td>
          <label class="rg-checkbox">
            <input type="checkbox" class="rg-row-check" data-rule="${escHtml(rule)}" ${isChecked}/>
            <span class="rg-checkbox__box"></span>
          </label>
        </td>
        <td>${formatBadge(type)}</td>
        <td>
          <div class="rg-rule-text">${escHtml(rule)}</div>
          ${domain ? `<div class="rg-rule-domain">${escHtml(domain)}</div>` : ''}
        </td>
        <td><span class="rg-fmt-badge">${formatBadgeLabel(rule)}</span></td>
        <td>
          <div class="rg-row-actions">
            ${type === 'block' ? `
            <button class="rg-row-btn rg-row-btn--toggle" data-act="toggle" data-rule="${escHtml(rule)}" title="Mudar para Permitir">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="20 6 9 17 4 12"/>
              </svg>
            </button>` : type === 'allow' ? `
            <button class="rg-row-btn rg-row-btn--danger" data-act="toggle" data-rule="${escHtml(rule)}" title="Mudar para Bloquear">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"/>
                <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
              </svg>
            </button>` : ''}
            <button class="rg-row-btn rg-row-btn--danger" data-act="remove" data-rule="${escHtml(rule)}" title="Remover">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="3 6 5 6 21 6"/>
                <path d="M19 6l-1 14H6L5 6"/>
              </svg>
            </button>
          </div>
        </td>
      </tr>`;
        }).join('');

        tbody.querySelectorAll('.rg-row-check').forEach(cb => {
            cb.addEventListener('change', () => {
                const rule = cb.dataset.rule;
                if (cb.checked) selected.add(rule); else selected.delete(rule);
                const row = cb.closest('tr');
                row.classList.toggle('rg-row--selected', cb.checked);
                updateSelectedUI();
                syncSelectAll();
            });
        });

        tbody.querySelectorAll('[data-act]').forEach(btn => {
            btn.addEventListener('click', e => {
                e.stopPropagation();
                const rule = btn.dataset.rule;
                const act = btn.dataset.act;
                if (act === 'remove') confirmRemove([rule]);
                if (act === 'toggle') toggleRule(rule);
            });
        });

        tbody.querySelectorAll('tr[data-rule]').forEach(tr => {
            tr.addEventListener('click', e => {
                if (e.target.closest('[data-act]') || e.target.closest('.rg-checkbox')) return;
                const cb = tr.querySelector('.rg-row-check');
                if (cb) { cb.checked = !cb.checked; cb.dispatchEvent(new Event('change')); }
            });
        });
    }

    function syncSelectAll() {
        const cb = $('rgSelectAll');
        if (!cb) return;
        const pageRules = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
        cb.checked = pageRules.length > 0 && pageRules.every(r => selected.has(r));
        cb.indeterminate = !cb.checked && pageRules.some(r => selected.has(r));
    }

    /* ═══════════════════════════════════════════════════════
       PAGINAÇÃO
    ═══════════════════════════════════════════════════════ */
    function renderPagination() {
        const total = filtered.length;
        const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
        const start = total === 0 ? 0 : (page - 1) * PAGE_SIZE + 1;
        const end = Math.min(page * PAGE_SIZE, total);

        $('rgPagInfo').textContent = `${start}–${end} de ${total} regra${total !== 1 ? 's' : ''}`;
        $('rgPagPrev').disabled = page <= 1;
        $('rgPagNext').disabled = page >= pages;

        const nums = $('rgPagNums');
        const ns = pages <= 7
            ? Array.from({ length: pages }, (_, i) => i + 1)
            : [1, '…', page - 1, page, page + 1, '…', pages].filter((v, i, a) =>
                v === '…' ? (a[i - 1] !== '…') : (v >= 1 && v <= pages)
            );

        nums.innerHTML = ns.map(n =>
            n === '…'
                ? `<span style="padding:0 4px;color:var(--text-muted);font-size:11px">…</span>`
                : `<button class="rg-pag-num${n === page ? ' rg-pag-num--active' : ''}" data-p="${n}">${n}</button>`
        ).join('');

        nums.querySelectorAll('.rg-pag-num').forEach(btn =>
            btn.addEventListener('click', () => { page = +btn.dataset.p; renderTable(); renderPagination(); syncSelectAll(); })
        );
    }

    $('rgPagPrev').addEventListener('click', () => { if (page > 1) { page--; renderTable(); renderPagination(); syncSelectAll(); } });
    $('rgPagNext').addEventListener('click', () => {
        const pages = Math.ceil(filtered.length / PAGE_SIZE);
        if (page < pages) { page++; renderTable(); renderPagination(); syncSelectAll(); }
    });

    /* ═══════════════════════════════════════════════════════
       ESTADOS DA TELA
    ═══════════════════════════════════════════════════════ */
    function hideAllStates() {
        ['rgStateLoading', 'rgStateDemo', 'rgStateEmpty', 'rgStateNoResults'].forEach(id => {
            const el = $(id); if (el) el.style.display = 'none';
        });
    }
    function showState(s) {
        hideAllStates();
        $('rgTable').style.display = 'none';
        $('rgPagination').style.display = 'none';
        const map = { loading: 'rgStateLoading', demo: 'rgStateDemo', empty: 'rgStateEmpty' };
        if (map[s]) $(map[s]).style.display = '';
    }

    /* ═══════════════════════════════════════════════════════
       AÇÕES DE REGRA (Remover/Toggle pela API Antiga de Save Completo)
    ═══════════════════════════════════════════════════════ */
    async function confirmRemove(rules) {
        if (!rules.length) return;
        const label = rules.length === 1
            ? `Remover: ${rules[0]}?`
            : `Remover ${rules.length} regras selecionadas?`;
        if (!confirm(label)) return;

        const set = new Set(rules);
        const newRules = allRules.filter(r => !set.has(r));

        // Remove rules uses the 'replace all' endpoint
        const ok = await saveFullRuleSet(newRules);
        if (ok) {
            allRules = newRules;
            selected.clear();
            updateSelectedUI();
            applyFilters();
            updateStats(allRules);
            showToast(`${rules.length} regra(s) removida(s)`);
        }
    }

    async function toggleRule(rule) {
        let newRule;
        const type = classifyRule(rule);
        if (type === 'block') {
            newRule = '@@' + rule.replace(/^\|\|/, '||');
        } else if (type === 'allow') {
            newRule = rule.replace(/^@@/, '');
        } else {
            showToast('Não é possível alternar este tipo de regra');
            return;
        }

        const newRules = allRules.map(r => r === rule ? newRule : r);
        const ok = await saveFullRuleSet(newRules);

        if (ok) {
            allRules = newRules;
            applyFilters();
            updateStats(allRules);
            showToast(`Regra alterada para ${type === 'block' ? 'ALLOW' : 'BLOCK'}`);
        }
    }

    async function saveFullRuleSet(rulesArray) {
        try {
            const res = await fetch('/dns/api/regras/salvar/', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrf() },
                body: JSON.stringify({ rules: rulesArray }),
            });
            const data = await res.json();
            if (!data.ok) { showToast(`Erro: ${data.error}`); return false; }
            return true;
        } catch (e) {
            showToast(`Erro de conexão: ${e.message}`);
            return false;
        }
    }

    /* ═══════════════════════════════════════════════════════
       MODAL — ADICIONAR REGRA (Chama API de Append Segura)
    ═══════════════════════════════════════════════════════ */
    function openModal() {
        $('rgModalInput').value = '';
        $('rgModalPreview').style.display = 'none';
        $('rgModalPreviewList').innerHTML = '';
        $('rgModalOverlay').classList.add('open');
        setTimeout(() => $('rgModalInput').focus(), 60);
        setTab('block');
    }

    function closeModal() {
        $('rgModalOverlay').classList.remove('open');
    }

    function setTab(tab) {
        activeTab = tab;
        document.querySelectorAll('.rg-tab').forEach(t => t.classList.remove('rg-tab--active'));
        document.querySelector(`.rg-tab[data-tab="${tab}"]`).classList.add('rg-tab--active');

        const descs = {
            block: 'Digite um domínio por linha. Será convertido para <code>||dominio^</code> automaticamente.',
            allow: 'Digite um domínio por linha. Será convertido para <code>@@||dominio^</code> (whitelist).',
            advanced: 'Use a sintaxe completa do AdGuard — uma regra por linha. Ex: <code>||ads.example.com^</code>',
        };
        $('rgModalDesc').innerHTML = descs[tab] || '';

        const confirmBtn = $('rgModalConfirm');
        confirmBtn.style.background = tab === 'block' ? '#ef4444' : tab === 'allow' ? '#22c55e' : 'var(--text-primary)';
        confirmBtn.style.color = tab === 'allow' ? '#fff' : tab === 'block' ? '#fff' : 'var(--bg)';
        confirmBtn.textContent = tab === 'block' ? 'Bloquear' : tab === 'allow' ? 'Permitir' : 'Salvar Regras';

        updatePreview();
    }

    function formatPreviewRules(raw, mode) {
        return raw.split('\n')
            .map(l => l.trim()).filter(Boolean)
            .flatMap(l => {
                if (mode === 'advanced') return [l];
                if (l.startsWith('||') || l.startsWith('@@') || l.startsWith('!') ||
                    l.startsWith('#') || l.startsWith('/') || l.startsWith('0.0.0.0') || l.startsWith('127.')) {
                    return [l];
                }

                const domains = [l];
                if (l.endsWith('.br')) {
                    domains.push(l.slice(0, -3));
                } else {
                    domains.push(l + '.br');
                }

                return domains.map(d => mode === 'allow' ? `@@||${d}^` : `||${d}^`);
            });
    }

    function updatePreview() {
        const raw = $('rgModalInput').value;
        const rules = formatPreviewRules(raw, activeTab);
        const wrap = $('rgModalPreview');
        const list = $('rgModalPreviewList');

        if (!rules.length) { wrap.style.display = 'none'; return; }
        wrap.style.display = '';

        const color = activeTab === 'allow' ? '#22c55e' : activeTab === 'block' ? '#ef4444' : 'var(--text-primary)';
        list.style.color = color;
        list.innerHTML = rules.map(r => `<div>${escHtml(r)}</div>`).join('');
    }

    async function submitModal() {
        const raw = $('rgModalInput').value.trim();
        if (!raw) { showToast('Digite ao menos um domínio'); return; }

        const confirmBtn = $('rgModalConfirm');
        const origText = confirmBtn.textContent;
        confirmBtn.textContent = "Processando...";
        confirmBtn.disabled = true;

        try {
            if (activeTab === 'advanced') {
                // Modo avançado usa Replace Total
                const newRules = formatPreviewRules(raw, activeTab);
                const current = new Set(allRules);
                const toAdd = newRules.filter(r => !current.has(r));

                if (!toAdd.length) {
                    showToast('Todas as regras já existem');
                    return;
                }

                const merged = [...allRules, ...toAdd];
                const ok = await saveFullRuleSet(merged);
                if (ok) {
                    allRules = merged;
                    applyFilters();
                    updateStats(allRules);
                    closeModal();
                    showToast(`✓ ${toAdd.length} regra(s) avançada(s) adicionada(s)`);
                }
            } else {
                // Block e Allow usam a nova API de serviço que faz o append seguro pelo backend
                const url = activeTab === 'block' ? '/dns/api/block/' : '/dns/api/allow/';
                const rulesToSend = formatPreviewRules(raw, activeTab).join('\n'); // Backend vai garantir não duplicar

                const res = await fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrf() },
                    body: JSON.stringify({ domains: rulesToSend }),
                });
                const data = await res.json();

                if (data.ok) {
                    const added = data.added?.length ?? 0;
                    const skip = data.skipped?.length ?? 0;
                    showToast(`✓ ${added} regra(s) adicionada(s)${skip ? ` · ${skip} já existia(m)` : ''}`);
                    closeModal();
                    loadRules(); // Recarrega a lista oficial do AdGuard para a tabela refletir
                } else {
                    showToast(`Erro: ${data.error}`);
                }
            }
        } catch (e) {
            showToast(`Erro de conexão: ${e.message}`);
        } finally {
            confirmBtn.textContent = origText;
            confirmBtn.disabled = false;
        }
    }

    // Bind modal
    $('rgAddBtn').addEventListener('click', openModal);
    $('rgModalClose').addEventListener('click', closeModal);
    $('rgModalCancel').addEventListener('click', closeModal);
    $('rgModalOverlay').addEventListener('click', e => { if (e.target === $('rgModalOverlay')) closeModal(); });
    $('rgModalConfirm').addEventListener('click', submitModal);
    $('rgModalInput').addEventListener('input', updatePreview);
    document.querySelectorAll('.rg-tab').forEach(t =>
        t.addEventListener('click', () => setTab(t.dataset.tab))
    );
    document.addEventListener('keydown', e => {
        if (e.key === 'Escape') closeModal();
    });

    /* ═══════════════════════════════════════════════════════
       CONTROLES GERAIS
    ═══════════════════════════════════════════════════════ */
    $('rgRefreshBtn').addEventListener('click', loadRules);

    $('rgRemoveSelectedBtn').addEventListener('click', () => {
        confirmRemove([...selected]);
    });

    // Select all
    $('rgSelectAll').addEventListener('change', e => {
        const pageRules = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
        if (e.target.checked) pageRules.forEach(r => selected.add(r));
        else pageRules.forEach(r => selected.delete(r));
        renderTable();
        updateSelectedUI();
    });

    // Filtros
    document.querySelectorAll('.rg-filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.rg-filter-btn').forEach(b => b.classList.remove('rg-filter-btn--active'));
            btn.classList.add('rg-filter-btn--active');
            currentFilter = btn.dataset.filter;
            applyFilters();
        });
    });

    // Busca
    const searchInput = $('rgSearch');
    const searchClear = $('rgSearchClear');
    searchInput.addEventListener('input', () => {
        searchTerm = searchInput.value.trim();
        searchClear.style.display = searchTerm ? '' : 'none';
        applyFilters();
    });
    searchClear.addEventListener('click', () => {
        searchInput.value = '';
        searchTerm = '';
        searchClear.style.display = 'none';
        applyFilters();
    });

    /* ═══════════════════════════════════════════════════════
       UTILS
    ═══════════════════════════════════════════════════════ */
    function escHtml(str) {
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function getCsrf() {
        return document.cookie.split(';')
            .find(c => c.trim().startsWith('csrftoken='))
            ?.split('=')[1] || '';
    }

    let _toastTimer;
    function showToast(msg) {
        const t = $('rgToast');
        t.textContent = msg;
        t.classList.add('show');
        clearTimeout(_toastTimer);
        _toastTimer = setTimeout(() => t.classList.remove('show'), 2800);
    }

    /* ── INIT ── */
    loadRules();

});