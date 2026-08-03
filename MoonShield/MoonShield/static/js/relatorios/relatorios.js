/* ============================================================
   MOONSHIELD — RELATORIOS.JS  v1.0
   Front-end completo com dados simulados
   Back-end: conectar nas views Django e substituir MOCK_DATA
   ============================================================ */

'use strict';

/* ══════════════════════════════════════════════════════════
   0. DADOS SIMULADOS (substituir por fetch Django)
══════════════════════════════════════════════════════════ */
const MOCK_REPORTS = (() => {
    const tipos = ['soc', 'auditoria', 'vulnerabilidade', 'compliance', 'executivo', 'forense', 'firewall', 'dns'];
    const status = ['pronto', 'pronto', 'pronto', 'pronto', 'gerando', 'agendado', 'erro'];
    const formatos = ['PDF', 'XLSX', 'CSV', 'JSON', 'PDF', 'PDF'];
    const nomes = {
        soc: ['SOC Operacional Diário', 'Resumo SOC — Turno Noite', 'SOC — Alertas Críticos'],
        auditoria: ['Auditoria de Acesso', 'Log de Autenticações', 'Revisão de Privilégios'],
        vulnerabilidade: ['Scan Completo de Vulnerabilidades', 'CVEs Críticos Q3', 'Patch Gap Analysis'],
        compliance: ['ISO 27001 Checklist', 'LGPD Conformidade', 'PCI-DSS Trimestral'],
        executivo: ['Resumo Executivo Mensal', 'Board Report Q3', 'KPI Dashboard Export'],
        forense: ['Análise Forense — Incidente #34', 'Memory Dump Analysis', 'Network Forensics'],
        firewall: ['Regras de Firewall Ativas', 'Bloqueios Recentes', 'Firewall Audit'],
        dns: ['DNS Queries Report', 'Domínios Suspeitos', 'DNS Anomalias'],
    };
    const periodos = ['Hoje', 'Últ. 7 dias', 'Últ. 30 dias', 'Jun 2025', 'Jul 2025', 'Ago 2025', 'Set 2025'];
    const tamanhos = ['1.2 MB', '340 KB', '4.8 MB', '820 KB', '2.1 MB', '156 KB', '6.3 MB', '512 KB'];

    const randomFrom = arr => arr[Math.floor(Math.random() * arr.length)];
    const randomDate = () => {
        const d = new Date();
        d.setDate(d.getDate() - Math.floor(Math.random() * 60));
        return d;
    };

    return Array.from({ length: 147 }, (_, i) => {
        const tipo = randomFrom(tipos);
        return {
            id: `REL-${String(i + 1).padStart(4, '0')}`,
            nome: randomFrom(nomes[tipo]),
            tipo,
            data: randomDate(),
            periodo: randomFrom(periodos),
            formato: randomFrom(formatos),
            status: randomFrom(status),
            tamanho: randomFrom(tamanhos),
        };
    }).sort((a, b) => b.data - a.data);
})();

const MOCK_ACTIVITY = [
    { type: 'gen', text: 'SOC Operacional Diário gerado com sucesso', time: 'há 3 min' },
    { type: 'down', text: 'ISO 27001 Checklist baixado por admin', time: 'há 18 min' },
    { type: 'sched', text: 'Compliance Semanal agendado para seg 08:00', time: 'há 1h' },
    { type: 'gen', text: 'Scan de Vulnerabilidades concluído · 23 CVEs', time: 'há 2h' },
    { type: 'err', text: 'Falha ao gerar Board Report Q3 · timeout', time: 'há 3h' },
    { type: 'gen', text: 'Resumo Executivo Mensal gerado', time: 'ontem' },
];

const MOCK_CHART = [
    { label: 'Abr', val: 28 },
    { label: 'Mai', val: 34 },
    { label: 'Jun', val: 22 },
    { label: 'Jul', val: 41 },
    { label: 'Ago', val: 38 },
    { label: 'Set', val: 29 },
    { label: 'Out', val: 47, cur: true },
];

/* ══════════════════════════════════════════════════════════
   1. ESTADO GLOBAL
══════════════════════════════════════════════════════════ */
const State = {
    currentTab: 'todos',
    currentPage: 1,
    perPage: 20,
    searchQuery: '',
    filterType: '',
    filterStatus: '',
    filterFormat: '',
    sortBy: 'data',
    sortDir: 'desc',
    viewMode: 'table',   // 'table' | 'grid'
    selectedIds: new Set(),
    generating: false,
    genInterval: null,
    genProgress: 0,
};

/* ══════════════════════════════════════════════════════════
   2. FILTRO + SORT
══════════════════════════════════════════════════════════ */
function getFilteredReports() {
    const tabMap = {
        todos: null,
        seguranca: ['soc', 'forense', 'vulnerabilidade'],
        infraestrutura: ['firewall', 'dns', 'auditoria'],
        conformidade: ['compliance', 'executivo'],
        agendados: null,  // filtra por status
    };

    let list = [...MOCK_REPORTS];

    // Tab
    if (State.currentTab === 'agendados') {
        list = list.filter(r => r.status === 'agendado');
    } else if (tabMap[State.currentTab]) {
        list = list.filter(r => tabMap[State.currentTab].includes(r.tipo));
    }

    // Filtros dropdown
    if (State.filterType) list = list.filter(r => r.tipo === State.filterType);
    if (State.filterStatus) list = list.filter(r => r.status === State.filterStatus);
    if (State.filterFormat) list = list.filter(r => r.formato.toLowerCase() === State.filterFormat);

    // Busca
    if (State.searchQuery) {
        const q = State.searchQuery.toLowerCase();
        list = list.filter(r =>
            r.nome.toLowerCase().includes(q) ||
            r.id.toLowerCase().includes(q) ||
            r.tipo.includes(q)
        );
    }

    // Sort
    list.sort((a, b) => {
        let va = a[State.sortBy];
        let vb = b[State.sortBy];
        if (State.sortBy === 'data') { va = va.getTime(); vb = vb.getTime(); }
        else { va = String(va).toLowerCase(); vb = String(vb).toLowerCase(); }
        const cmp = va < vb ? -1 : va > vb ? 1 : 0;
        return State.sortDir === 'asc' ? cmp : -cmp;
    });

    return list;
}

/* ══════════════════════════════════════════════════════════
   3. RENDERIZAÇÃO — TABELA
══════════════════════════════════════════════════════════ */
const statusLabels = { pronto: 'Pronto', gerando: 'Gerando...', agendado: 'Agendado', erro: 'Erro' };
const tipoLabels = { soc: 'SOC', auditoria: 'Auditoria', vulnerabilidade: 'Vuln.', compliance: 'Compliance', executivo: 'Executivo', forense: 'Forense', firewall: 'Firewall', dns: 'DNS' };

function fmtDate(d) {
    return d.toLocaleDateString('pt-BR', { day: '2-digit', month: 'short', year: 'numeric' });
}

function buildTableRow(r) {
    const checked = State.selectedIds.has(r.id) ? 'checked' : '';
    return `
    <tr class="rel-tr${State.selectedIds.has(r.id) ? ' rel-tr--selected' : ''}" data-id="${r.id}">
      <td class="rel-td">
        <input type="checkbox" class="rel-check row-check" data-id="${r.id}" ${checked}>
      </td>
      <td class="rel-td rel-td--name">
        <div class="rel-td__name-wrap">
          <span class="rel-td__name" title="${r.nome}">${r.nome}</span>
          <span class="rel-td__id">${r.id}</span>
        </div>
      </td>
      <td class="rel-td">
        <span class="rel-badge rel-badge--${r.tipo}">${tipoLabels[r.tipo] || r.tipo}</span>
      </td>
      <td class="rel-td" style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted)">
        ${fmtDate(r.data)}
      </td>
      <td class="rel-td" style="font-size:12px;color:var(--text-muted)">${r.periodo}</td>
      <td class="rel-td">
        <span class="rel-format-pill">${r.formato}</span>
      </td>
      <td class="rel-td">
        <span class="rel-status rel-status--${r.status}">
          <span class="rel-status__dot"></span>
          ${statusLabels[r.status]}
        </span>
      </td>
      <td class="rel-td" style="font-family:var(--font-mono);font-size:11px;color:var(--text-dim)">${r.tamanho}</td>
      <td class="rel-td">
        <div class="rel-row-actions">
          ${r.status === 'pronto' ? `
          <button class="rel-icon-btn btn-preview" data-id="${r.id}" title="Visualizar">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
          </button>
          <button class="rel-icon-btn btn-download" data-id="${r.id}" title="Download">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          </button>
          ` : ''}
          <button class="rel-icon-btn btn-delete" data-id="${r.id}" title="Excluir">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/></svg>
          </button>
        </div>
      </td>
    </tr>`;
}

function buildGridCard(r) {
    return `
    <div class="rel-grid-card" data-id="${r.id}">
      <div class="rel-grid-card__top">
        <div class="rel-grid-card__icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
            <polyline points="14 2 14 8 20 8"/>
          </svg>
        </div>
        <span class="rel-status rel-status--${r.status}">
          <span class="rel-status__dot"></span>
          ${statusLabels[r.status]}
        </span>
      </div>
      <div>
        <div class="rel-grid-card__name">${r.nome}</div>
        <div class="rel-grid-card__period">${r.periodo} · ${fmtDate(r.data)}</div>
      </div>
      <div class="rel-grid-card__footer">
        <span class="rel-badge rel-badge--${r.tipo}">${tipoLabels[r.tipo] || r.tipo}</span>
        <span class="rel-grid-card__size">${r.formato} · ${r.tamanho}</span>
      </div>
    </div>`;
}

function render() {
    const filtered = getFilteredReports();
    const total = filtered.length;
    const pages = Math.max(1, Math.ceil(total / State.perPage));

    if (State.currentPage > pages) State.currentPage = pages;

    const start = (State.currentPage - 1) * State.perPage;
    const end = Math.min(start + State.perPage, total);
    const slice = filtered.slice(start, end);

    const tbody = document.getElementById('reportTableBody');
    const grid = document.getElementById('reportGrid');
    const empty = document.getElementById('relEmpty');
    const tableWrap = document.getElementById('reportTableWrap');

    // Guard — elementos essenciais ainda nao no DOM
    if (!tbody || !grid || !tableWrap) return;

    // Table vs Grid visibility
    if (State.viewMode === 'grid') {
        tableWrap.style.display = 'none';
        grid.style.display = 'grid';
    } else {
        tableWrap.style.display = '';
        grid.style.display = 'none';
    }

    // Empty state
    if (empty) empty.style.display = total === 0 ? 'flex' : 'none';
    tbody.innerHTML = total === 0 ? '' : slice.map(buildTableRow).join('');
    grid.innerHTML = total === 0 ? '' : slice.map(buildGridCard).join('');

    // Pagination
    const paginationInfo = document.getElementById('paginationInfo');
    if (paginationInfo) {
        paginationInfo.textContent =
            total === 0 ? '0 resultados' : `Exibindo ${start + 1}\u2013${end} de ${total}`;
    }

    buildPageNumbers(pages);

    const prevBtn = document.getElementById('prevPage');
    const nextBtn = document.getElementById('nextPage');
    if (prevBtn) prevBtn.disabled = State.currentPage <= 1;
    if (nextBtn) nextBtn.disabled = State.currentPage >= pages;

    // Check all state
    const checkAll = document.getElementById('checkAll');
    if (checkAll) {
        const allChecked = slice.length > 0 && slice.every(r => State.selectedIds.has(r.id));
        checkAll.checked = allChecked;
        checkAll.indeterminate = !allChecked && slice.some(r => State.selectedIds.has(r.id));
    }

    // Bind row events
    bindRowEvents();
}

function buildPageNumbers(pages) {
    const cont = document.getElementById('pageNumbers');
    if (!cont) return;
    cont.innerHTML = '';
    const cur = State.currentPage;

    // Mostrar até 5 páginas centradas
    let start = Math.max(1, cur - 2);
    let end = Math.min(pages, start + 4);
    if (end - start < 4) start = Math.max(1, end - 4);

    for (let p = start; p <= end; p++) {
        const btn = document.createElement('button');
        btn.className = `rel-page-num${p === cur ? ' rel-page-num--active' : ''}`;
        btn.textContent = p;
        btn.addEventListener('click', () => { State.currentPage = p; render(); });
        cont.appendChild(btn);
    }
}

/* ══════════════════════════════════════════════════════════
   4. EVENTOS DE LINHA
══════════════════════════════════════════════════════════ */
function bindRowEvents() {
    // Checkboxes de linha
    document.querySelectorAll('.row-check').forEach(cb => {
        cb.addEventListener('change', e => {
            const id = e.target.dataset.id;
            if (e.target.checked) State.selectedIds.add(id);
            else State.selectedIds.delete(id);
            render();
        });
    });

    // Clique na linha — abre drawer
    document.querySelectorAll('.rel-tr').forEach(tr => {
        tr.addEventListener('click', e => {
            if (e.target.closest('.rel-icon-btn') || e.target.closest('.rel-check')) return;
            const id = tr.dataset.id;
            const r = MOCK_REPORTS.find(x => x.id === id);
            if (r) openDrawer(r);
        });
    });

    // Clique em grid card
    document.querySelectorAll('.rel-grid-card').forEach(card => {
        card.addEventListener('click', () => {
            const r = MOCK_REPORTS.find(x => x.id === card.dataset.id);
            if (r) openDrawer(r);
        });
    });

    // Botões de ação
    document.querySelectorAll('.btn-preview').forEach(b => {
        b.addEventListener('click', e => {
            e.stopPropagation();
            const r = MOCK_REPORTS.find(x => x.id === b.dataset.id);
            if (r) openDrawer(r);
        });
    });

    document.querySelectorAll('.btn-download').forEach(b => {
        b.addEventListener('click', e => {
            e.stopPropagation();
            toast('ok', `Download iniciado: ${b.dataset.id}`);
            /* BACK-END: window.location.href = `/relatorios/download/${b.dataset.id}/`; */
        });
    });

    document.querySelectorAll('.btn-delete').forEach(b => {
        b.addEventListener('click', e => {
            e.stopPropagation();
            if (confirm('Remover este relatório?')) {
                const idx = MOCK_REPORTS.findIndex(x => x.id === b.dataset.id);
                if (idx !== -1) MOCK_REPORTS.splice(idx, 1);
                toast('ok', 'Relatório removido');
                render();
                /* BACK-END: fetch(`/api/relatorios/${b.dataset.id}/`, { method:'DELETE', headers:{'X-CSRFToken':getCsrf()} }) */
            }
        });
    });
}

/* ══════════════════════════════════════════════════════════
   5. DRAWER — PREVIEW
══════════════════════════════════════════════════════════ */
function openDrawer(r) {
    const overlay = document.getElementById('drawerOverlay');
    const drawer = document.getElementById('reportDrawer');

    document.getElementById('drawerTitle').textContent = r.nome;
    document.getElementById('drawerSub').textContent = `${r.id} · ${fmtDate(r.data)} · ${r.formato}`;

    document.getElementById('drawerBody').innerHTML = `
    <div class="rel-preview-meta">
      <div class="rel-preview-meta-item">
        <div class="rel-preview-meta-item__lbl">Tipo</div>
        <div class="rel-preview-meta-item__val">${tipoLabels[r.tipo] || r.tipo}</div>
      </div>
      <div class="rel-preview-meta-item">
        <div class="rel-preview-meta-item__lbl">Status</div>
        <div class="rel-preview-meta-item__val">${statusLabels[r.status]}</div>
      </div>
      <div class="rel-preview-meta-item">
        <div class="rel-preview-meta-item__lbl">Período</div>
        <div class="rel-preview-meta-item__val">${r.periodo}</div>
      </div>
      <div class="rel-preview-meta-item">
        <div class="rel-preview-meta-item__lbl">Tamanho</div>
        <div class="rel-preview-meta-item__val">${r.tamanho}</div>
      </div>
    </div>

    <div class="rel-preview-section">
      <div class="rel-preview-section__title">Sumário Executivo</div>
      <div class="rel-preview-placeholder">[ Conteúdo renderizado pelo back-end ]</div>
    </div>

    <div class="rel-preview-section">
      <div class="rel-preview-section__title">Eventos do Período</div>
      <table class="rel-preview-table">
        <thead>
          <tr>
            <th>Evento</th><th>Severidade</th><th>Data</th><th>Status</th>
          </tr>
        </thead>
        <tbody>
          ${Array.from({ length: 6 }, (_, i) => `
          <tr>
            <td>EVT-${String(i + 1).padStart(4, '0')}</td>
            <td>${['ALTO', 'MÉDIO', 'BAIXO', 'CRÍTICO', 'MÉDIO', 'BAIXO'][i]}</td>
            <td>${fmtDate(new Date(r.data.getTime() - i * 86400000))}</td>
            <td>${i === 4 ? 'Aberto' : 'Fechado'}</td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>

    <div class="rel-preview-section">
      <div class="rel-preview-section__title">Gráficos</div>
      <div class="rel-preview-placeholder">[ Gráficos renderizados via Chart.js / back-end ]</div>
    </div>
  `;

    overlay.classList.add('open');
    drawer.classList.add('open');
    document.body.style.overflow = 'hidden';
}

function closeDrawer() {
    document.getElementById('drawerOverlay').classList.remove('open');
    document.getElementById('reportDrawer').classList.remove('open');
    document.body.style.overflow = '';
}

/* ══════════════════════════════════════════════════════════
   6. MODAL — NOVO RELATÓRIO
══════════════════════════════════════════════════════════ */
function openModal(title, bodyHTML, confirmLabel, onConfirm) {
    document.getElementById('modalTitle').textContent = title;
    document.getElementById('modalBody').innerHTML = bodyHTML;
    document.getElementById('modalConfirm').textContent = confirmLabel;
    document.getElementById('modalOverlay').classList.add('open');
    document.body.style.overflow = 'hidden';

    document.getElementById('modalConfirm').onclick = () => {
        onConfirm();
        closeModal();
    };
}

function closeModal() {
    document.getElementById('modalOverlay').classList.remove('open');
    document.body.style.overflow = '';
}

const newReportModalHTML = `
<div class="rel-modal-grid">
  <div class="rel-modal-field rel-modal-field--full">
    <label>Nome do relatório</label>
    <input class="rel-modal-input" id="mNome" placeholder="Ex: SOC Semanal — Turno Manhã" type="text">
  </div>
  <div class="rel-modal-field">
    <label>Tipo</label>
    <select class="rel-select" style="width:100%;height:36px" id="mTipo">
      <option value="soc">SOC</option>
      <option value="auditoria">Auditoria</option>
      <option value="vulnerabilidade">Vulnerabilidade</option>
      <option value="compliance">Compliance</option>
      <option value="executivo">Executivo</option>
      <option value="forense">Forense</option>
      <option value="firewall">Firewall</option>
      <option value="dns">DNS & Rede</option>
    </select>
  </div>
  <div class="rel-modal-field">
    <label>Formato</label>
    <select class="rel-select" style="width:100%;height:36px" id="mFormato">
      <option>PDF</option><option>XLSX</option><option>CSV</option><option>JSON</option>
    </select>
  </div>
  <div class="rel-modal-field">
    <label>Data início</label>
    <input class="rel-modal-input" id="mDataInicio" type="date">
  </div>
  <div class="rel-modal-field">
    <label>Data fim</label>
    <input class="rel-modal-input" id="mDataFim" type="date">
  </div>
  <div class="rel-modal-field rel-modal-field--full">
    <label>Observações</label>
    <input class="rel-modal-input" id="mObs" placeholder="Opcional" type="text">
  </div>
</div>`;

const newScheduleModalHTML = `
<div class="rel-modal-grid">
  <div class="rel-modal-field rel-modal-field--full">
    <label>Nome do agendamento</label>
    <input class="rel-modal-input" id="sNome" placeholder="Ex: Compliance Semanal" type="text">
  </div>
  <div class="rel-modal-field">
    <label>Tipo</label>
    <select class="rel-select" style="width:100%;height:36px" id="sTipo">
      <option value="soc">SOC</option>
      <option value="compliance">Compliance</option>
      <option value="executivo">Executivo</option>
      <option value="auditoria">Auditoria</option>
    </select>
  </div>
  <div class="rel-modal-field">
    <label>Recorrência</label>
    <select class="rel-select" style="width:100%;height:36px" id="sRecorr">
      <option>Diário</option><option>Semanal</option><option>Mensal</option><option>Trimestral</option>
    </select>
  </div>
  <div class="rel-modal-field">
    <label>Horário</label>
    <input class="rel-modal-input" id="sHora" type="time" value="06:00">
  </div>
  <div class="rel-modal-field">
    <label>Formato</label>
    <select class="rel-select" style="width:100%;height:36px" id="sFormato">
      <option>PDF</option><option>XLSX</option><option>PDF + XLSX</option>
    </select>
  </div>
</div>`;

/* ══════════════════════════════════════════════════════════
   7. GERAÇÃO — SIMULAÇÃO
══════════════════════════════════════════════════════════ */
function startGeneration() {
    if (State.generating) return;
    State.generating = true;
    State.genProgress = 0;

    const quickCard = document.getElementById('quickGenCard');
    const progressCard = document.getElementById('progressCard');
    quickCard.style.display = 'none';
    progressCard.style.display = '';

    const steps = [
        { id: 'ps1', label: 'Coletando dados', from: 0, to: 25 },
        { id: 'ps2', label: 'Processando eventos', from: 25, to: 65 },
        { id: 'ps3', label: 'Renderizando gráficos', from: 65, to: 88 },
        { id: 'ps4', label: 'Exportando arquivo', from: 88, to: 100 },
    ];

    let stepIdx = 0;
    const bar = document.getElementById('genProgressBar');

    // Reset visual
    steps.forEach(s => {
        const el = document.getElementById(s.id);
        el.classList.remove('rel-pstep--done', 'rel-pstep--active');
    });

    document.getElementById('ps1').classList.add('rel-pstep--active');

    State.genInterval = setInterval(() => {
        State.genProgress = Math.min(State.genProgress + Math.random() * 3 + 1, 100);
        bar.style.width = State.genProgress + '%';

        // Avança steps
        while (stepIdx < steps.length && State.genProgress >= steps[stepIdx].to) {
            document.getElementById(steps[stepIdx].id).classList.remove('rel-pstep--active');
            document.getElementById(steps[stepIdx].id).classList.add('rel-pstep--done');
            stepIdx++;
            if (stepIdx < steps.length) {
                document.getElementById(steps[stepIdx].id).classList.add('rel-pstep--active');
            }
        }

        // Atualiza meta do step atual
        if (stepIdx < steps.length) {
            const pct = Math.round((State.genProgress - steps[stepIdx].from) / (steps[stepIdx].to - steps[stepIdx].from) * 100);
            const metaEl = document.getElementById(steps[stepIdx].id)?.querySelector('.rel-pstep__meta');
            if (metaEl) metaEl.textContent = Math.min(pct, 99) + '%';
        }

        if (State.genProgress >= 100) {
            clearInterval(State.genInterval);
            State.generating = false;

            setTimeout(() => {
                progressCard.style.display = 'none';
                quickCard.style.display = '';

                // Injeta relatório simulado na lista
                const tipo = document.getElementById('quickType').value;
                const formato = document.querySelector('input[name="qFormat"]:checked')?.value?.toUpperCase() || 'PDF';
                const novoRel = {
                    id: `REL-${String(MOCK_REPORTS.length + 1).padStart(4, '0')}`,
                    nome: document.getElementById('quickType').options[document.getElementById('quickType').selectedIndex].text.split(' — ')[0],
                    tipo,
                    data: new Date(),
                    periodo: document.getElementById('quickPeriod').value,
                    formato,
                    status: 'pronto',
                    tamanho: (Math.random() * 4 + 0.5).toFixed(1) + ' MB',
                };
                MOCK_REPORTS.unshift(novoRel);
                render();
                toast('ok', `Relatório "${novoRel.nome}" gerado com sucesso!`);

                /* BACK-END:
                 * fetch('/api/relatorios/gerar/', {
                 *   method: 'POST',
                 *   headers: { 'Content-Type':'application/json', 'X-CSRFToken': getCsrf() },
                 *   body: JSON.stringify({ tipo, formato, periodo: document.getElementById('quickPeriod').value })
                 * })
                 * .then(r => r.json())
                 * .then(data => { ... });
                 */
            }, 600);
        }
    }, 80);
}

/* ══════════════════════════════════════════════════════════
   8. MINI CHART
══════════════════════════════════════════════════════════ */
function renderMiniChart() {
    const chart = document.getElementById('miniChart');
    const labels = document.getElementById('miniChartLabels');
    if (!chart || !labels) return;

    const max = Math.max(...MOCK_CHART.map(d => d.val));
    const chartH = 50;

    chart.innerHTML = MOCK_CHART.map(d => {
        const h = Math.round((d.val / max) * (chartH - 6)) + 6;
        return `<div class="rel-mini-bar${d.cur ? ' rel-mini-bar--cur' : ''}" style="height:${h}px" title="${d.label}: ${d.val} relatórios"></div>`;
    }).join('');

    labels.innerHTML = MOCK_CHART.map(d =>
        `<span>${d.label}</span>`
    ).join('');
}

/* ══════════════════════════════════════════════════════════
   9. FEED DE ATIVIDADE
══════════════════════════════════════════════════════════ */
function renderActivity() {
    const feed = document.getElementById('activityFeed');
    if (!feed) return;

    feed.innerHTML = MOCK_ACTIVITY.map(a => `
    <div class="rel-activity-item">
      <div class="rel-activity-item__dot rel-activity-item__dot--${a.type}"></div>
      <div class="rel-activity-item__body">
        <div class="rel-activity-item__text">${a.text}</div>
        <div class="rel-activity-item__time">${a.time}</div>
      </div>
    </div>`).join('');
}

/* ══════════════════════════════════════════════════════════
   10. TOAST
══════════════════════════════════════════════════════════ */
function toast(type, msg, duration = 3000) {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const t = document.createElement('div');
    t.className = `rel-toast rel-toast--${type}`;
    t.innerHTML = `<span class="rel-toast__icon"></span><span>${msg}</span>`;
    container.appendChild(t);

    requestAnimationFrame(() => {
        requestAnimationFrame(() => t.classList.add('visible'));
    });

    setTimeout(() => {
        t.classList.add('hiding');
        t.addEventListener('transitionend', () => t.remove(), { once: true });
    }, duration);
}

/* ══════════════════════════════════════════════════════════
   11. REFRESH
══════════════════════════════════════════════════════════ */
function triggerRefresh() {
    const icon = document.getElementById('refreshIcon');
    icon.style.animation = 'spin .7s linear infinite';
    document.getElementById('refreshBtn').disabled = true;

    setTimeout(() => {
        icon.style.animation = '';
        document.getElementById('refreshBtn').disabled = false;
        toast('info', 'Dados atualizados');
        render();

        /* BACK-END:
         * fetch('/api/relatorios/?period=30')
         *   .then(r => r.json())
         *   .then(data => { MOCK_REPORTS.length=0; MOCK_REPORTS.push(...data); render(); });
         */
    }, 1200);
}

/* ══════════════════════════════════════════════════════════
   12. CSRF HELPER (para integração Django)
══════════════════════════════════════════════════════════ */
function getCsrf() {
    const cookie = document.cookie.split(';').find(c => c.trim().startsWith('csrftoken='));
    return cookie ? cookie.split('=')[1] : '';
}

/* ══════════════════════════════════════════════════════════
   13. BIND DE TODOS OS EVENTOS
══════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', () => {

    /* ── Tabs ── */
    document.getElementById('relTabs')?.addEventListener('click', e => {
        const tab = e.target.closest('.rel-tab');
        if (!tab) return;
        document.querySelectorAll('.rel-tab').forEach(t => t.classList.remove('rel-tab--active'));
        tab.classList.add('rel-tab--active');
        State.currentTab = tab.dataset.tab;
        State.currentPage = 1;
        render();
    });

    /* ── Busca ── */
    let searchTimeout;
    document.getElementById('reportSearch')?.addEventListener('input', e => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
            State.searchQuery = e.target.value.trim();
            State.currentPage = 1;
            render();
        }, 250);
    });

    /* ── Filtros dropdown ── */
    document.getElementById('filterType')?.addEventListener('change', e => {
        State.filterType = e.target.value;
        State.currentPage = 1;
        render();
    });

    document.getElementById('filterStatus')?.addEventListener('change', e => {
        State.filterStatus = e.target.value;
        State.currentPage = 1;
        render();
    });

    document.getElementById('filterFormat')?.addEventListener('change', e => {
        State.filterFormat = e.target.value.toLowerCase();
        State.currentPage = 1;
        render();
    });

    /* ── View toggle ── */
    document.getElementById('viewTable')?.addEventListener('click', () => {
        State.viewMode = 'table';
        document.getElementById('viewTable').classList.add('rel-view-btn--active');
        document.getElementById('viewGrid').classList.remove('rel-view-btn--active');
        render();
    });

    document.getElementById('viewGrid')?.addEventListener('click', () => {
        State.viewMode = 'grid';
        document.getElementById('viewGrid').classList.add('rel-view-btn--active');
        document.getElementById('viewTable').classList.remove('rel-view-btn--active');
        render();
    });

    /* ── Sort headers ── */
    document.querySelectorAll('.rel-th--sortable').forEach(th => {
        th.addEventListener('click', () => {
            const col = th.dataset.sort;
            if (State.sortBy === col) State.sortDir = State.sortDir === 'asc' ? 'desc' : 'asc';
            else { State.sortBy = col; State.sortDir = 'desc'; }
            State.currentPage = 1;
            render();
        });
    });

    /* ── Check all ── */
    document.getElementById('checkAll')?.addEventListener('change', e => {
        const filtered = getFilteredReports();
        const start = (State.currentPage - 1) * State.perPage;
        const slice = filtered.slice(start, start + State.perPage);
        if (e.target.checked) slice.forEach(r => State.selectedIds.add(r.id));
        else slice.forEach(r => State.selectedIds.delete(r.id));
        render();
    });

    /* ── Paginação ── */
    document.getElementById('prevPage')?.addEventListener('click', () => {
        if (State.currentPage > 1) { State.currentPage--; render(); }
    });

    document.getElementById('nextPage')?.addEventListener('click', () => {
        const total = getFilteredReports().length;
        const pages = Math.ceil(total / State.perPage);
        if (State.currentPage < pages) { State.currentPage++; render(); }
    });

    /* ── Seletor de período ── */
    const periodSelector = document.getElementById('periodSelector');
    const periodDropdown = document.getElementById('periodDropdown');

    periodSelector?.addEventListener('click', e => {
        e.stopPropagation();
        periodDropdown.classList.toggle('open');
    });

    document.addEventListener('click', () => periodDropdown?.classList.remove('open'));

    document.querySelectorAll('.rel-period-opt').forEach(opt => {
        opt.addEventListener('click', e => {
            e.stopPropagation();
            const days = opt.dataset.days;
            document.querySelectorAll('.rel-period-opt').forEach(o => o.classList.remove('rel-period-opt--active'));
            opt.classList.add('rel-period-opt--active');
            document.getElementById('periodLabel').textContent = opt.textContent.trim();
            periodDropdown.classList.remove('open');

            if (days !== 'custom') {
                toast('info', `Período alterado: ${opt.textContent.trim()}`);
                render();
                /* BACK-END: carregar dados do período selecionado */
            }
        });
    });

    /* ── Refresh ── */
    document.getElementById('refreshBtn')?.addEventListener('click', triggerRefresh);

    /* ── Novo relatório (modal) ── */
    document.getElementById('newReportBtn')?.addEventListener('click', () => {
        openModal('Novo Relatório', newReportModalHTML, 'Criar Relatório', () => {
            const nome = document.getElementById('mNome')?.value || 'Novo Relatório';
            const tipo = document.getElementById('mTipo')?.value || 'soc';
            const formato = document.getElementById('mFormato')?.value || 'PDF';
            const novoRel = {
                id: `REL-${String(MOCK_REPORTS.length + 1).padStart(4, '0')}`,
                nome: nome || 'Relatório sem título',
                tipo,
                data: new Date(),
                periodo: 'Personalizado',
                formato,
                status: 'gerando',
                tamanho: '—',
            };
            MOCK_REPORTS.unshift(novoRel);
            render();
            toast('ok', `Relatório "${novoRel.nome}" criado!`);

            /* BACK-END:
             * fetch('/api/relatorios/', {
             *   method: 'POST',
             *   headers: { 'Content-Type':'application/json', 'X-CSRFToken': getCsrf() },
             *   body: JSON.stringify({ nome, tipo, formato,
             *     data_inicio: document.getElementById('mDataInicio').value,
             *     data_fim:    document.getElementById('mDataFim').value,
             *     observacoes: document.getElementById('mObs').value })
             * }).then(r => r.json()).then(data => { MOCK_REPORTS.unshift(data); render(); });
             */
        });
    });

    /* ── Novo agendamento ── */
    document.getElementById('newScheduleBtn')?.addEventListener('click', () => {
        openModal('Novo Agendamento', newScheduleModalHTML, 'Criar Agendamento', () => {
            const nome = document.getElementById('sNome')?.value || 'Agendamento';
            toast('ok', `Agendamento "${nome}" criado!`);
            /* BACK-END: POST /api/relatorios/agendamentos/ */
        });
    });

    /* ── Modal fechar ── */
    document.getElementById('modalClose')?.addEventListener('click', closeModal);
    document.getElementById('modalCancel')?.addEventListener('click', closeModal);
    document.getElementById('modalOverlay')?.addEventListener('click', e => {
        if (e.target === document.getElementById('modalOverlay')) closeModal();
    });

    /* ── Drawer fechar ── */
    document.getElementById('drawerClose')?.addEventListener('click', closeDrawer);
    document.getElementById('drawerOverlay')?.addEventListener('click', closeDrawer);
    document.getElementById('drawerDownload')?.addEventListener('click', () => {
        toast('ok', 'Download iniciado');
        /* BACK-END: download do relatório atual */
    });

    /* ── Gerar agora ── */
    document.getElementById('generateBtn')?.addEventListener('click', startGeneration);

    /* ── Formato opts clicáveis ── */
    document.querySelectorAll('.rel-format-opt').forEach(opt => {
        opt.addEventListener('click', () => {
            document.querySelectorAll('.rel-format-opt').forEach(o => o.classList.remove('rel-format-opt--active'));
            opt.classList.add('rel-format-opt--active');
        });
    });

    /* ── Atalho de teclado — fechar drawer/modal ── */
    document.addEventListener('keydown', e => {
        if (e.key === 'Escape') {
            closeDrawer();
            closeModal();
        }
    });

    /* ══════════════════════════════════════════════
       INIT
    ══════════════════════════════════════════════ */
    render();
    renderMiniChart();
    renderActivity();

    /* Animação de entrada dos KPIs */
    document.querySelectorAll('.rel-kpi').forEach((kpi, i) => {
        kpi.style.opacity = '0';
        kpi.style.transform = 'translateY(8px)';
        kpi.style.transition = `opacity .3s ease ${i * 60}ms, transform .3s ease ${i * 60}ms`;
        requestAnimationFrame(() => {
            requestAnimationFrame(() => {
                kpi.style.opacity = '1';
                kpi.style.transform = 'none';
            });
        });
    });

});