/**
 * MoonShield Network Panel
 * Seção: Visão Geral
 */

'use strict';

import { estado } from '../nucleo/estado.js';
import { $, setHidden, setText, setStatusPill, setStatusDot } from '../nucleo/dom.js';
import { formatarIpv4, paraBooleano, rotuloBackend } from '../nucleo/utilitarios.js';

let inicializado = false;

const elementos = {
    agentStatus: null,
    agentDot: null,
    agentSocket: null,
    backend: null,
    backendState: null,
    interfacesTotal: null,
    interfacesConfigured: null,
    pendingChanges: null,
    syncState: null,
    internetStatus: null,
    wanInterface: null,
    wanAddress: null,
    wanGateway: null,
    lanInterface: null,
    lanAddress: null,
    lanStatus: null,
    forwardStatus: null,
    wanState: null,
    wanName: null,
    wanIpv4: null,
    wanGatewayInfo: null,
    wanMetric: null,
    lanState: null,
    lanName: null,
    lanIpv4: null,
    lanManagement: null,
    lanNat: null,
    notice: null,
    topologyState: null,
    topologyDetails: null,
    mgmt: null,
    management: null,
    homeNet: null,
};


/* ==========================================================================
   INICIALIZAÇÃO
========================================================================== */

function inicializar() {
    if (inicializado) return;
    inicializado = true;

    cachearElementos();
    sincronizar();
}


function cachearElementos() {
    elementos.agentStatus = $('#overviewAgentStatus');
    elementos.agentDot = $('#overviewAgentDot');
    elementos.agentSocket = $('#overviewAgentSocket');

    elementos.backend = $('#overviewBackend');
    elementos.backendState = $('#overviewBackendState');

    elementos.interfacesTotal = $('#overviewInterfacesTotal');
    elementos.interfacesConfigured = $('#overviewInterfacesConfigured');

    elementos.pendingChanges = $('#overviewPendingChanges');
    elementos.syncState = $('#overviewSyncState');

    elementos.internetStatus = $('#topologyInternetStatus');
    elementos.wanInterface = $('#topologyWanInterface');
    elementos.wanAddress = $('#topologyWanAddress');
    elementos.wanGateway = $('#topologyWanGateway');

    elementos.lanInterface = $('#topologyLanInterface');
    elementos.lanAddress = $('#topologyLanAddress');
    elementos.lanStatus = $('#topologyLanStatus');

    elementos.forwardStatus = $('#topologyForwardStatus');

    elementos.wanState = $('#overviewWanState');
    elementos.wanName = $('#overviewWanName');
    elementos.wanIpv4 = $('#overviewWanIpv4');
    elementos.wanGatewayInfo = $('#overviewWanGateway');
    elementos.wanMetric = $('#overviewWanMetric');

    elementos.lanState = $('#overviewLanState');
    elementos.lanName = $('#overviewLanName');
    elementos.lanIpv4 = $('#overviewLanIpv4');
    elementos.lanManagement = $('#overviewLanManagement');
    elementos.lanNat = $('#overviewLanNat');

    elementos.notice = $('#overviewNetworkNotice');
    elementos.topologyState = $('#overviewTopologyState');
    elementos.topologyDetails = $('#overviewTopologyDetails');
    elementos.mgmt = $('#overviewMgmt');
    elementos.management = $('#overviewManagement');
    elementos.homeNet = $('#overviewHomeNet');
}


/* ==========================================================================
   SINCRONIZAÇÃO
========================================================================== */

function sincronizar() {
    atualizarAgent();
    atualizarBackend();
    atualizarInterfaces();
    atualizarAlteracoes();
    atualizarRoteamento();
    atualizarTopologia();
}


function atualizarStatus(dados = null) {
    if (dados) estado.set('status', dados);
    sincronizar();
}


/* ==========================================================================
   AGENT
========================================================================== */

function atualizarAgent() {
    const agent = estado.get('agent') || estado.get('status.agent') || {};
    const online = paraBooleano(agent.online, false);

    setText(elementos.agentStatus, online ? 'Online' : 'Offline');
    setStatusDot(elementos.agentDot, online ? 'ok' : 'error');

    const socket =
        agent.socket ||
        agent.status?.socket ||
        estado.get('status.agent.socket') ||
        '/run/moonshield/agent.sock';

    setText(elementos.agentSocket, socket);
}


/* ==========================================================================
   BACKEND
========================================================================== */

function atualizarBackend() {
    const backend =
        estado.get('interfaces.backend') ||
        estado.get('status.backend') ||
        estado.get('status.agent.status.backend') ||
        estado.get('agent.status.backend') ||
        'unknown';

    const agentOnline = paraBooleano(estado.get('agent.online'), false);

    setText(elementos.backend, rotuloBackend(backend));
    setText(elementos.backendState, agentOnline ? 'Disponível' : 'Indisponível');
}


/* ==========================================================================
   INTERFACES
========================================================================== */

function atualizarInterfaces() {
    const resumo = obterResumoInterfaces();
    const lista = estado.get('interfaces.lista', []);
    const total = resumo.total ?? lista.length;
    const configuradas = resumo.configuradas ?? lista.filter(interfaceGerenciada).length;

    setText(elementos.interfacesTotal, total, '0');
    setText(elementos.interfacesConfigured, configuradas, '0');

    atualizarTopologia();
}


/* ==========================================================================
   ALTERAÇÕES
========================================================================== */

function atualizarAlteracoes() {
    const estados = obterResumoInterfaces().estados_sincronizacao || {};
    const pendentes = contarEstados(estados, 'pending_apply', 'applying', 'waiting_confirmation');
    const sincronizadas = Number(estados.synced || 0);
    const drifted = Number(estados.drifted || 0);
    const missing = Number(estados.missing || 0);
    const erros = Number(estados.error || 0);
    const resumo = [
        `${sincronizadas} sincronizada(s)`,
        `${pendentes} pendente(s)`,
    ];

    if (drifted) resumo.push(`${drifted} divergente(s)`);
    if (missing) resumo.push(`${missing} ausente(s)`);
    if (erros) resumo.push(`${erros} erro(s)`);

    setText(elementos.pendingChanges, pendentes, '0');
    setText(elementos.syncState, resumo.join(' · '));

    elementos.syncState?.classList.toggle('is-warning', pendentes > 0 || drifted > 0 || missing > 0 || erros > 0);
}


/* ==========================================================================
   ROTEAMENTO
========================================================================== */

function atualizarRoteamento() {
    const config = estado.get('roteamento.configuracao') || {};
    const real = estado.get('roteamento.real') || {};

    const forward =
        real.ipv4_forward ??
        real.forwarding ??
        config.ipv4_forward ??
        false;

    setText(elementos.forwardStatus, `IPv4 Forward ${paraBooleano(forward) ? 'ON' : 'OFF'}`);
}


/* ==========================================================================
   TOPOLOGIA
========================================================================== */

function atualizarTopologia() {
    const topologia = obterTopologia();
    const wan = atualizarObservado(topologia?.wan?.principal);
    const lan = atualizarObservado(topologia?.lan?.principal);

    renderizarWan(wan);
    renderizarLan(lan);
    renderizarInternet(wan);
    renderizarTopologia(topologia, lan);
}


/* ==========================================================================
   WAN
========================================================================== */

function renderizarWan(wan) {
    if (!wan) {
        setText(elementos.wanInterface, 'Não configurada');
        setText(elementos.wanAddress, '—');
        setText(elementos.wanGateway, 'Gateway —');

        setText(elementos.wanName, '—');
        setText(elementos.wanIpv4, '—');
        setText(elementos.wanGatewayInfo, '—');
        setText(elementos.wanMetric, '—');

        setStatusPill(elementos.wanState, 'pending', 'Não configurada');
        return;
    }

    const ipv4 = enderecoExibido(wan);
    const gateway = obterDesejado(wan, 'gateway') || obterReal(wan, 'gateway') || '—';
    const metrica = obterDesejado(wan, 'metrica') ?? obterReal(wan, 'metrica') ?? '—';

    setText(elementos.wanInterface, wan.nome);
    setText(elementos.wanAddress, ipv4);
    setText(elementos.wanGateway, gateway === '—' ? 'Gateway —' : `Gateway ${gateway}`);

    setText(elementos.wanName, wan.nome);
    setText(elementos.wanIpv4, ipv4);
    setText(elementos.wanGatewayInfo, gateway);
    setText(elementos.wanMetric, metrica);

    renderizarEstadoSincronizacao(elementos.wanState, wan);
}


/* ==========================================================================
   LAN
========================================================================== */

function renderizarLan(lan) {
    if (!lan) {
        setText(elementos.lanInterface, 'Não configurada');
        setText(elementos.lanAddress, '—');
        setText(elementos.lanStatus, '—');

        setText(elementos.lanName, '—');
        setText(elementos.lanIpv4, '—');
        setText(elementos.lanManagement, '—');
        setText(elementos.lanNat, '—');

        setStatusPill(elementos.lanState, 'pending', 'Não configurada');
        return;
    }

    const ipv4 = enderecoExibido(lan);
    const management = paraBooleano(obterDesejado(lan, 'acesso_gerenciamento'));
    const nat = natAtivoParaInterface(lan);

    setText(elementos.lanInterface, lan.nome);
    setText(elementos.lanAddress, ipv4);
    setText(
        elementos.lanStatus,
        `${interfaceOnline(lan) ? 'Link ativo' : 'Link inativo'} · ${rotuloSincronizacao(lan)}`
    );

    setText(elementos.lanName, lan.nome);
    setText(elementos.lanIpv4, ipv4);
    setText(elementos.lanManagement, management ? 'Permitido' : 'Não');
    setText(elementos.lanNat, nat ? 'Ativo' : 'Não configurado');

    renderizarEstadoSincronizacao(elementos.lanState, lan);
}


/* ==========================================================================
   INTERNET
========================================================================== */

function renderizarInternet(wan) {
    const status = estado.get('status') || {};
    const diagnostico = estado.get('diagnostico.resultado') || {};

    const internet =
        diagnostico.internet ??
        diagnostico.conectividade?.internet ??
        diagnostico.resultado?.internet ??
        status.internet ??
        status.conectividade?.internet;

    let online;

    if (internet !== undefined && internet !== null) {
        online = typeof internet === 'object'
            ? paraBooleano(internet.ok ?? internet.online ?? internet.sucesso, false)
            : paraBooleano(internet, false);
    } else {
        online = wan
            ? interfaceOnline(wan) && Boolean(obterDesejado(wan, 'gateway') || obterReal(wan, 'gateway'))
            : false;
    }

    setText(elementos.internetStatus, online ? 'Conectado' : 'Não verificado');
}


/* ==========================================================================
   HELPERS
========================================================================== */

function obterResumoInterfaces() {
    const resumo = estado.get('status.interfaces');
    if (resumo && typeof resumo === 'object') return resumo;

    const estados = {};
    const lista = estado.get('interfaces.lista', []);

    lista.forEach(interfaceRede => {
        const estadoSincronizacao = obterEstadoSincronizacao(interfaceRede);
        estados[estadoSincronizacao] = Number(estados[estadoSincronizacao] || 0) + 1;
    });

    return {
        total: lista.length,
        configuradas: lista.filter(interfaceGerenciada).length,
        estados_sincronizacao: estados,
    };
}


function obterTopologia() {
    const topologia = estado.get('status.topologia');
    if (topologia && typeof topologia === 'object') return topologia;

    const resumo = obterResumoInterfaces();
    const wan = resumo.wan_principal || null;
    const lan = resumo.lan_principal || null;
    const mgmt = resumo.mgmt_principal || null;

    return {
        valida: Boolean(wan && lan),
        problemas: [],
        avisos: [],
        wan: { principal: wan },
        lan: { principal: lan },
        mgmt: { principal: mgmt },
        gerenciamento: { principal: null },
        home_net: [],
    };
}


function atualizarObservado(interfaceRede) {
    if (!interfaceRede) return null;

    const atual = estado.get('interfaces.lista', []).find(item => obterId(item) === obterId(interfaceRede));
    return atual || interfaceRede;
}


function obterDesejado(interfaceRede, campo, fallback = null) {
    const desejado = interfaceRede?.desejado || interfaceRede?.desired || interfaceRede || {};
    return desejado[campo] ?? fallback;
}


function obterReal(interfaceRede, campo, fallback = null) {
    const real = interfaceRede?.real || interfaceRede?.observado || interfaceRede || {};
    return real[campo] ?? fallback;
}


function interfaceGerenciada(interfaceRede) {
    return obterDesejado(interfaceRede, 'papel', 'unassigned') !== 'unassigned';
}


function interfaceOnline(interfaceRede) {
    const estadoLink = String(obterReal(interfaceRede, 'estado_link', '')).toLowerCase();
    if (estadoLink === 'up') return true;
    if (estadoLink === 'down') return false;

    return paraBooleano(obterReal(interfaceRede, 'carrier'), false);
}


function obterEnderecoDesejado(interfaceRede) {
    const modo = obterDesejado(interfaceRede, 'ipv4_modo', 'dhcp');
    if (modo === 'dhcp') return 'DHCP';
    if (modo === 'disabled') return 'Desativado';

    const endereco = obterDesejado(interfaceRede, 'ipv4_endereco');
    return endereco ? formatarIpv4(endereco, obterDesejado(interfaceRede, 'ipv4_prefixo')) : '—';
}


function obterEnderecoObservado(interfaceRede) {
    const enderecos = obterReal(interfaceRede, 'enderecos_ipv4', []);
    const endereco = Array.isArray(enderecos) && enderecos.length
        ? enderecos[0]
        : obterReal(interfaceRede, 'ipv4');

    if (!endereco) return '—';
    if (String(endereco).includes('/')) return String(endereco);
    return formatarIpv4(endereco, obterReal(interfaceRede, 'prefixo'));
}


function enderecoExibido(interfaceRede) {
    const observado = obterEnderecoObservado(interfaceRede);
    const desejado = obterEnderecoDesejado(interfaceRede);

    if (observado === '—') return desejado;
    if (desejado === '—' || desejado === 'DHCP' || desejado === 'Desativado' || observado === desejado) {
        return observado;
    }

    return `${observado} · desejado ${desejado}`;
}


function obterEstadoSincronizacao(interfaceRede) {
    const estadoSincronizacao = String(interfaceRede?.estado_sincronizacao || '').toLowerCase();
    if (estadoSincronizacao) return estadoSincronizacao;
    if (paraBooleano(interfaceRede?.sincronizada, false)) return 'synced';
    if (paraBooleano(interfaceRede?.pendente, false)) return 'pending_apply';
    return interfaceGerenciada(interfaceRede) ? 'pending_apply' : 'unmanaged';
}


function rotuloSincronizacao(interfaceRede) {
    return {
        unmanaged: 'Não gerenciada',
        synced: 'Sincronizada',
        pending_apply: 'Pendente de aplicação',
        applying: 'Aplicando',
        waiting_confirmation: 'Aguardando confirmação',
        drifted: 'Divergente',
        missing: 'Interface ausente',
        error: 'Erro',
    }[obterEstadoSincronizacao(interfaceRede)] || 'Estado desconhecido';
}


function renderizarEstadoSincronizacao(elemento, interfaceRede) {
    const estadoSincronizacao = obterEstadoSincronizacao(interfaceRede);
    const estilo = {
        synced: 'ok',
        pending_apply: 'pending',
        applying: 'pending',
        waiting_confirmation: 'warning',
        drifted: 'warning',
        missing: 'error',
        error: 'error',
        unmanaged: 'warning',
    }[estadoSincronizacao] || 'pending';

    setStatusPill(elemento, estilo, rotuloSincronizacao(interfaceRede));
}


function contarEstados(estados, ...nomes) {
    return nomes.reduce((total, nome) => total + Number(estados[nome] || 0), 0);
}


function renderizarTopologia(topologia, lan) {
    const status = estado.get('status') || {};
    const problemas = Array.isArray(topologia?.problemas) ? topologia.problemas : [];
    const avisos = Array.isArray(topologia?.avisos) ? topologia.avisos : [];
    const valida = Boolean(topologia?.valida);
    const mgmt = atualizarObservado(topologia?.mgmt?.principal);
    const gerenciamento = atualizarObservado(topologia?.gerenciamento?.principal);
    const homeNet = Array.isArray(topologia?.home_net) ? topologia.home_net : [];

    setStatusPill(
        elementos.topologyState,
        valida ? 'ok' : 'warning',
        valida ? 'Rede configurada' : 'Configuração incompleta'
    );
    setText(
        elementos.topologyDetails,
        problemas[0]?.mensagem || avisos[0]?.mensagem ||
        (obterResumoInterfaces().configuradas ? 'WAN e LAN definem a topologia.' : 'Configure uma WAN e uma LAN para concluir a topologia básica.')
    );
    setText(
        elementos.mgmt,
        mgmt ? `MGMT · ${mgmt.nome}`
            : gerenciamento && obterId(gerenciamento) === obterId(lan)
                ? `Via LAN · ${lan.nome}`
                : gerenciamento ? `Via ${gerenciamento.nome}` : 'Não configurado'
    );
    setText(elementos.management, gerenciamento ? 'Permitido' : 'Não configurado');
    setText(elementos.homeNet, homeNet.length ? homeNet.join(' · ') : 'Não definida');

    const avisoAtualizacao = status.reconciliado === false
        ? status.aviso?.mensagem || 'Exibindo último estado conhecido.'
        : problemas[0]?.mensagem || avisos[0]?.mensagem || '';

    setHidden(elementos.notice, !avisoAtualizacao);
    if (avisoAtualizacao) setText(elementos.notice, avisoAtualizacao);
}


function natAtivoParaInterface(interfaceItem) {
    const regras = estado.get('nat.regras', []);

    return regras.some(regra => {
        const origem = typeof regra.interface_origem === 'object'
            ? regra.interface_origem?.id
            : regra.interface_origem_id || regra.interface_origem;

        return Number(origem) === Number(interfaceItem.id) && paraBooleano(regra.ativa, true);
    });
}


function obterId(item) {
    return item?.id || item?.uuid || item?.alteracao_id || null;
}


/* ==========================================================================
   ATIVAÇÃO
========================================================================== */

function aoAtivar() {
    sincronizar();
}


/* ==========================================================================
   EXPORT
========================================================================== */

export const visaoGeral = Object.freeze({
    inicializar,
    aoAtivar,
    sincronizar,
    atualizarStatus,
    atualizarInterfaces,
    atualizarAlteracoes,
});

export default visaoGeral;
