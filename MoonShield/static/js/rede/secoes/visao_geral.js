/**
 * MoonShield Network Panel
 * Seção: Visão Geral
 */

'use strict';

import { estado } from '../nucleo/estado.js';
import { $, setText, setStatusPill, setStatusDot } from '../nucleo/dom.js';
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
    const lista = estado.get('interfaces.lista', []);
    const configuradas = lista.filter(item => item.papel && item.papel !== 'unassigned').length;

    setText(elementos.interfacesTotal, lista.length, '0');
    setText(elementos.interfacesConfigured, configuradas, '0');

    atualizarTopologia();
}


/* ==========================================================================
   ALTERAÇÕES
========================================================================== */

function atualizarAlteracoes() {
    const lista = estado.get('alteracoes.lista', []);
    const ativa = estado.get('alteracoes.ativa');

    const pendentesLista = lista.filter(item => ['created', 'validating', 'applying', 'waiting_confirmation', 'rollback'].includes(item.status)).length;
    const pendentes = ativa && !lista.some(item => obterId(item) === obterId(ativa)) ? pendentesLista + 1 : pendentesLista;

    setText(elementos.pendingChanges, pendentes, '0');
    setText(elementos.syncState, pendentes > 0 ? 'Pendente' : 'Sincronizado');

    elementos.syncState?.classList.toggle('is-warning', pendentes > 0);
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
    const lista = estado.get('interfaces.lista', []);
    const wan = selecionarInterface(lista, 'wan');
    const lan = selecionarInterface(lista, 'lan');

    renderizarWan(wan);
    renderizarLan(lan);
    renderizarInternet(wan);
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

    const online = interfaceOnline(wan);
    const ipv4 = enderecoAtualOuDesejado(wan);
    const gateway = wan.gateway_atual || wan.gateway || '—';
    const metrica = wan.metrica_atual ?? wan.metrica ?? '—';

    setText(elementos.wanInterface, wan.nome);
    setText(elementos.wanAddress, ipv4);
    setText(elementos.wanGateway, gateway === '—' ? 'Gateway —' : `Gateway ${gateway}`);

    setText(elementos.wanName, wan.nome);
    setText(elementos.wanIpv4, ipv4);
    setText(elementos.wanGatewayInfo, gateway);
    setText(elementos.wanMetric, metrica);

    setStatusPill(elementos.wanState, online ? 'ok' : 'error', online ? 'Online' : 'Offline');
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

    const online = interfaceOnline(lan);
    const ipv4 = enderecoAtualOuDesejado(lan);
    const management = paraBooleano(lan.acesso_gerenciamento);
    const nat = natAtivoParaInterface(lan);

    setText(elementos.lanInterface, lan.nome);
    setText(elementos.lanAddress, ipv4);
    setText(elementos.lanStatus, online ? 'Link ativo' : 'Link inativo');

    setText(elementos.lanName, lan.nome);
    setText(elementos.lanIpv4, ipv4);
    setText(elementos.lanManagement, management ? 'Permitido' : 'Não');
    setText(elementos.lanNat, nat ? 'Ativo' : 'Não configurado');

    setStatusPill(elementos.lanState, online ? 'ok' : 'error', online ? 'Online' : 'Offline');
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
        online = wan ? interfaceOnline(wan) && Boolean(wan.gateway_atual || wan.gateway) : false;
    }

    setText(elementos.internetStatus, online ? 'Conectado' : 'Não verificado');
}


/* ==========================================================================
   HELPERS
========================================================================== */

function selecionarInterface(lista, papel) {
    const candidatas = lista.filter(item => item.papel === papel);
    if (!candidatas.length) return null;

    return candidatas.find(item => paraBooleano(item.principal)) ||
        candidatas.find(interfaceOnline) ||
        candidatas[0];
}


function interfaceOnline(item) {
    if (!item) return false;
    if (item.estado_link === 'up') return true;
    if (item.estado_link === 'down') return false;

    return paraBooleano(item.carrier, false);
}


function enderecoAtualOuDesejado(item) {
    if (item.ipv4_atual) {
        if (String(item.ipv4_atual).includes('/')) return item.ipv4_atual;
        return formatarIpv4(item.ipv4_atual, item.prefixo_atual);
    }

    if (item.ipv4_modo === 'dhcp') return 'DHCP';
    if (item.ipv4_modo === 'disabled') return 'Desativado';

    if (item.ipv4_endereco) return formatarIpv4(item.ipv4_endereco, item.ipv4_prefixo);

    return '—';
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