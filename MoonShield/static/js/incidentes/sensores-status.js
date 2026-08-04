'use strict';

(() => {
  const POLLING_INTERVAL_MS = 10000;
  let pollingId = null;
  let requisicaoEmAndamento = false;
  const byId = id => document.getElementById(id);

  const formatarNumero = valor => Number.isFinite(Number(valor))
    ? new Intl.NumberFormat('pt-BR').format(Number(valor))
    : '0';

  function formatarBytes(bytes) {
    const n = Number(bytes);
    if (!Number.isFinite(n) || n < 0) return '—';
    if (n < 1024) return `${n} B`;
    const u = ['KB', 'MB', 'GB', 'TB'];
    let v = n / 1024, i = 0;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return `${v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2)} ${u[i]}`;
  }

  function formatarDataHora(valor) {
    if (!valor) return '—';
    const d = new Date(valor);
    if (Number.isNaN(d.getTime())) return '—';
    return d.toLocaleString('pt-BR', {
      day: '2-digit', month: '2-digit', year: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit'
    });
  }

  async function fetchJsonSeguro(url) {
    const r = await fetch(url, {
      credentials: 'same-origin', cache: 'no-store',
      headers: { Accept: 'application/json', 'X-Requested-With': 'XMLHttpRequest' }
    });
    const ct = r.headers.get('content-type') || '';
    if (!ct.includes('application/json')) {
      const txt = await r.text();
      if (txt.includes('<html') || txt.includes('<!DOCTYPE') || r.redirected) {
        throw new Error('A sessão pode ter expirado. Atualize a página e faça login novamente.');
      }
      throw new Error(`Resposta inválida do servidor (HTTP ${r.status}).`);
    }
    const data = await r.json();
    if (!r.ok) throw new Error(data?.erro || `Erro HTTP ${r.status}.`);
    if (!data || data.ok !== true) throw new Error(data?.erro || 'Falha ao obter o status do Suricata.');
    return data;
  }

  function statusFragment(ativo) {
    const frag = document.createDocumentFragment();
    const span = document.createElement('span');
    const icon = document.createElement('i');
    span.className = ativo ? 'text-success' : 'text-danger';
    icon.className = ativo ? 'fas fa-check-circle me-1' : 'fas fa-times-circle me-1';
    span.append(icon, document.createTextNode(ativo ? ' Ativo' : ' Inativo'));
    frag.appendChild(span);
    return frag;
  }

  function atualizarServico(prefixo, servico) {
    const status = byId(`${prefixo}-status`);
    const detalhe = byId(`${prefixo}-detalhe`);
    if (status) status.replaceChildren(statusFragment(Boolean(servico?.ativo)));
    if (detalhe) detalhe.textContent = `${servico?.estado || 'desconhecido'} / ${servico?.subestado || 'desconhecido'}`;
  }

  function atualizarBadge(saude) {
    const b = byId('local-saude-badge'); if (!b) return;
    b.className = 'badge';
    if (saude?.nivel === 'ok') { b.classList.add('bg-success'); b.textContent = 'OK'; }
    else if (saude?.nivel === 'warning') { b.classList.add('bg-warning', 'text-dark'); b.textContent = 'ATENÇÃO'; }
    else { b.classList.add('bg-danger'); b.textContent = 'CRÍTICO'; }
  }

  function atualizarProblemas(saude) {
    const box = byId('box-problemas'), lista = byId('lista-problemas');
    if (!box || !lista) return;
    const problemas = Array.isArray(saude?.problemas) ? saude.problemas : [];
    lista.replaceChildren();
    if (!problemas.length) { box.classList.add('d-none'); return; }
    problemas.forEach(p => { const li = document.createElement('li'); li.textContent = String(p); lista.appendChild(li); });
    box.classList.remove('d-none', 'alert-warning', 'alert-danger');
    box.classList.add(saude?.nivel === 'critical' ? 'alert-danger' : 'alert-warning');
  }

  function aplicarStatus(d) {
    atualizarBadge(d.saude);
    atualizarServico('local-suricata', d.suricata);
    atualizarServico('local-monitor', d.monitor);
    if (byId('local-sensor-nome')) byId('local-sensor-nome').textContent = d.sensor?.nome || 'Não registrado';
    if (byId('local-sensor-ip')) byId('local-sensor-ip').textContent = d.sensor?.ip || 'IP não informado';
    if (byId('local-last-seen')) byId('local-last-seen').textContent = formatarDataHora(d.sensor?.last_seen);
    if (byId('local-ultima-consulta')) byId('local-ultima-consulta').textContent = `Status consultado em ${formatarDataHora(d.consultado_em)}`;
    if (byId('local-eve-info')) {
      byId('local-eve-info').textContent = !d.eve?.existe ? 'Inacessível / ausente' : !d.eve?.legivel ? 'Sem permissão de leitura' : `Legível (${formatarBytes(d.eve?.tamanho)})`;
    }
    if (byId('local-cursor-offset')) {
      byId('local-cursor-offset').textContent = !d.cursor?.existe ? 'Cursor ausente' : !d.cursor?.valido ? 'Cursor inválido' : `Offset ${formatarNumero(d.cursor?.offset)}`;
    }
    if (byId('local-cursor-updated')) byId('local-cursor-updated').textContent = formatarDataHora(d.cursor?.updated_at);
    [['count-incidentes','incidentes'],['count-dns','dns'],['count-http','http'],['count-tls','tls']].forEach(([id,k]) => { if (byId(id)) byId(id).textContent = formatarNumero(d.eventos?.[k]); });
    atualizarProblemas(d.saude);
  }

  function mostrarErro(msg) {
    const b = byId('local-saude-badge');
    if (b) { b.className = 'badge bg-danger'; b.textContent = 'ERRO'; }
    atualizarProblemas({ nivel: 'critical', problemas: [msg] });
    if (byId('local-ultima-consulta')) byId('local-ultima-consulta').textContent = 'Não foi possível atualizar o status.';
  }

  function loading(ativo) {
    const btn = byId('btn-atualizar-status'), ic = byId('icone-atualizar-status');
    if (btn) { btn.disabled = ativo; btn.setAttribute('aria-busy', ativo ? 'true' : 'false'); }
    if (ic) ic.classList.toggle('fa-spin', ativo);
  }

  async function atualizarStatusSuricata() {
    if (requisicaoEmAndamento) return;
    const btn = byId('btn-atualizar-status');
    const url = btn?.dataset?.statusUrl;
    if (!url) { mostrarErro('A URL da API de status não foi configurada no template.'); return; }
    requisicaoEmAndamento = true; loading(true);
    try { aplicarStatus(await fetchJsonSeguro(url)); }
    catch (e) { console.error('Erro ao atualizar status do Suricata:', e); mostrarErro(e instanceof Error ? e.message : 'Erro inesperado.'); }
    finally { requisicaoEmAndamento = false; loading(false); }
  }

  function iniciarPolling() {
    if (pollingId !== null) return;
    pollingId = window.setInterval(atualizarStatusSuricata, POLLING_INTERVAL_MS);
  }

  function pararPolling() {
    if (pollingId === null) return;
    clearInterval(pollingId); pollingId = null;
  }

  function init() {
    const btn = byId('btn-atualizar-status'); if (!btn) return;
    btn.addEventListener('click', atualizarStatusSuricata);
    atualizarStatusSuricata(); iniciarPolling();
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) pararPolling(); else { atualizarStatusSuricata(); iniciarPolling(); }
    });
    window.addEventListener('beforeunload', pararPolling);
  }

  window.atualizarStatusSuricata = atualizarStatusSuricata;
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init, { once: true });
  else init();
})();
