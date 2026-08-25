/**
 * MoonShield Network Panel
 * Seção: Roteamento & NAT
 */

'use strict';

import { api } from '../nucleo/api.js';
import { estado } from '../nucleo/estado.js';
import {
    $, $$, setText, setHidden, setValor, setMarcado, marcado,
    valorTrim, valorNumero, clonarTemplate, setStatusPill, criar,
} from '../nucleo/dom.js';
import {
    normalizarErro, paraBooleano, rotuloPapel,
} from '../nucleo/utilitarios.js';
import { abrirDrawer, fecharDrawer, drawers } from '../componentes/drawer.js';
import { notificacao } from '../componentes/notificacoes.js';
import { safeApply } from '../componentes/safe_apply.js';

let inicializado = false;
let carregando = false;
let salvandoRoteamento = false;
let salvandoRota = false;
let salvandoNat = false;
let removendoRota = false;
let removendoNat = false;
let aplicandoConfiguracao = false;
let rotaEditandoId = null;
let natEditandoId = null;

const elementos = {
    routingForm: null,
    ipv4Forward: null,
    defaultRouteManagement: null,
    autoRollback: null,
    confirmationTimeout: null,
    routingSaveState: null,
    routingSyncStatus: null,
    routingApplyButton: null,

    routesBody: null,
    routesEmpty: null,
    newRouteButton: null,
    routeDrawer: null,
    routeForm: null,
    routeId: null,
    routeName: null,
    routeDestination: null,
    routeGateway: null,
    routeInterface: null,
    routeMetric: null,
    routeEnabled: null,

    natContainer: null,
    natEmpty: null,
    natTemplate: null,
    newNatButton: null,
    natDrawer: null,
    natForm: null,
    natId: null,
    natName: null,
    natSourceInterface: null,
    natOutputInterface: null,
    natSourceCidr: null,
    natPriority: null,
    natEnabled: null,
};


/* ==========================================================================
   INICIALIZAÇÃO
========================================================================== */

function inicializar() {
    if (inicializado) return;
    inicializado = true;

    cachearElementos();
    registrarEventos();
    atualizarEstadoControles();
}


function cachearElementos() {
    elementos.routingForm = $('#routingConfigForm');
    elementos.ipv4Forward = $('#routingIpv4Forward');
    elementos.defaultRouteManagement = $('#routingDefaultRouteManagement');
    elementos.autoRollback = $('#routingAutoRollback');
    elementos.confirmationTimeout = $('#routingConfirmationTimeout');
    elementos.routingSaveState = $('#routingSaveState');
    elementos.routingSyncStatus = $('#routingSyncStatus');
    elementos.routingApplyButton = $('#routingApplyButton');

    elementos.routesBody = $('#routesTableBody');
    elementos.routesEmpty = $('#routesEmptyRow');
    elementos.newRouteButton = $('#newRouteButton');

    elementos.routeDrawer = $('#routeDrawer');
    elementos.routeForm = $('#routeForm');
    elementos.routeId = $('#routeId');
    elementos.routeName = $('#routeName');
    elementos.routeDestination = $('#routeDestination');
    elementos.routeGateway = $('#routeGateway');
    elementos.routeInterface = $('#routeInterface');
    elementos.routeMetric = $('#routeMetric');
    elementos.routeEnabled = $('#routeEnabled');

    elementos.natContainer = $('#natRulesContainer');
    elementos.natEmpty = $('#natEmptyState');
    elementos.natTemplate = $('#natRuleTemplate');
    elementos.newNatButton = $('#newNatButton');

    elementos.natDrawer = $('#natDrawer');
    elementos.natForm = $('#natForm');
    elementos.natId = $('#natId');
    elementos.natName = $('#natName');
    elementos.natSourceInterface = $('#natSourceInterface');
    elementos.natOutputInterface = $('#natOutputInterface');
    elementos.natSourceCidr = $('#natSourceCidr');
    elementos.natPriority = $('#natPriority');
    elementos.natEnabled = $('#natEnabled');
}


function registrarEventos() {
    elementos.routingForm?.addEventListener('submit', salvarRoteamento);
    elementos.routingApplyButton?.addEventListener('click', aplicarConfiguracao);

    elementos.newRouteButton?.addEventListener('click', () => abrirRota());
    elementos.routeForm?.addEventListener('submit', salvarRota);

    elementos.newNatButton?.addEventListener('click', () => abrirNat());
    elementos.natForm?.addEventListener('submit', salvarNat);

    elementos.routesBody?.addEventListener('click', tratarCliqueRota);
    elementos.natContainer?.addEventListener('click', tratarCliqueNat);

    document.addEventListener('moonshield:network-lock-change', atualizarEstadoControles);
    document.addEventListener('moonshield:safe-apply-finished', atualizarEstadoControles);
}


/* ==========================================================================
   CARREGAMENTO
========================================================================== */

async function carregar(opcoes = {}) {
    if (carregando) return;

    carregando = true;

    const chamadas = [
        ['roteamento', () => api.get(api.urls.roteamento)],
        ['roteamentoReal', () => api.get(api.urls.roteamentoReal)],
        ['nat', () => api.get(api.urls.nat)],
        ['natReal', () => api.get(api.urls.natReal)],
    ];

    const resultados = await Promise.allSettled(chamadas.map(([, executar]) => executar()));

    try {
        let sucesso = 0;
        let primeiroErro = null;

        resultados.forEach((resultado, indice) => {
            const nome = chamadas[indice][0];

            if (resultado.status === 'fulfilled') {
                sucesso++;
                processarCarga(nome, resultado.value);
            } else if (!primeiroErro) {
                primeiroErro = resultado.reason;
            }
        });

        estado.set('roteamento.carregado', sucesso > 0);
        estado.set('nat.carregado', sucesso > 0);

        renderizar();

        if (!sucesso && primeiroErro) throw primeiroErro;

        if (!opcoes.silencioso && sucesso < chamadas.length) {
            notificacao.aviso('Dados parciais', 'Parte do estado real da rede não pôde ser consultada.');
        }
    } catch (error) {
        if (!opcoes.silencioso) {
            const erro = normalizarErro(error);
            notificacao.erro(erro.titulo, erro.mensagem);
        }

        throw error;
    } finally {
        carregando = false;
    }
}


function processarCarga(nome, resposta) {
    const dados = resposta?.dados ?? resposta ?? {};

    if (nome === 'roteamento') {
        const configuracao = dados.configuracao || dados.roteamento || dados.settings || null;
        const rotas = extrairLista(dados.rotas || dados.routes || []);

        estado.set('roteamento.configuracao', configuracao);
        estado.set('roteamento.rotas', rotas);
        estado.set('roteamento.sujo', inferirRoteamentoPendente(configuracao, rotas));
        return;
    }

    if (nome === 'roteamentoReal') {
        estado.set('roteamento.real', dados);
        return;
    }

    if (nome === 'nat') {
        const regras = extrairLista(dados.regras || dados.nat || dados.rules || dados);

        estado.set('nat.regras', regras);
        estado.set('nat.sujo', regras.some(regra => paraBooleano(regra.pendente) || !paraBooleano(regra.sincronizada, true)));
        return;
    }

    if (nome === 'natReal') estado.set('nat.real', dados);
}


async function aoAtivar() {
    if (!estado.get('roteamento.carregado') || !estado.get('nat.carregado')) {
        try {
            await carregar({ silencioso: true });
        } catch {
            // Mantém a interface navegável em ambiente de desenvolvimento.
        }
    }

    atualizarOpcoesInterfaces();
}


/* ==========================================================================
   RENDER
========================================================================== */

function renderizar() {
    renderizarRoteamento();
    renderizarRotas();
    renderizarNat();
    atualizarOpcoesInterfaces();
    atualizarEstadoControles();
}


function sincronizar() {
    renderizar();
}


/* ==========================================================================
   ROTEAMENTO GLOBAL
========================================================================== */

function renderizarRoteamento() {
    const config = estado.get('roteamento.configuracao') || {};
    const sujo = Boolean(estado.get('roteamento.sujo'));

    setMarcado(elementos.ipv4Forward, paraBooleano(config.ipv4_forward));
    setMarcado(
        elementos.defaultRouteManagement,
        config.gerenciamento_automatico_rota_default === undefined
            ? true
            : paraBooleano(config.gerenciamento_automatico_rota_default)
    );
    setMarcado(
        elementos.autoRollback,
        config.rollback_automatico === undefined ? true : paraBooleano(config.rollback_automatico)
    );

    setValor(elementos.confirmationTimeout, config.tempo_confirmacao ?? 60);

    atualizarEstadoSalvamento(sujo);

    if (!estado.get('agent.online', false)) {
        setStatusPill(elementos.routingSyncStatus, 'error', 'Agent Offline');
    } else if (sujo) {
        setStatusPill(elementos.routingSyncStatus, 'warning', 'Pendente');
    } else {
        setStatusPill(elementos.routingSyncStatus, 'ok', 'Sincronizado');
    }
}


async function salvarRoteamento(event) {
    event.preventDefault();
    if (salvandoRoteamento) return;

    if (safeApply.ocupado?.()) {
        notificarBloqueio();
        return;
    }

    const payload = {
        ipv4_forward: marcado(elementos.ipv4Forward),
        gerenciamento_automatico_rota_default: marcado(elementos.defaultRouteManagement),
        rollback_automatico: marcado(elementos.autoRollback),
        tempo_confirmacao: valorNumero(elementos.confirmationTimeout, 60),
        ativo: true,
    };

    salvandoRoteamento = true;
    definirRoteamentoSalvando(true);
    atualizarEstadoControles();

    try {
        const resposta = await api.post(api.urls.configurarRoteamento, payload);
        const config = resposta?.dados?.configuracao || resposta?.configuracao || payload;

        estado.set('roteamento.configuracao', config);
        estado.set('roteamento.sujo', true);
        renderizarRoteamento();

        notificacao.sucesso(
            'Roteamento salvo',
            'A configuração desejada foi salva. Clique em Aplicar configuração para sincronizar o sistema.'
        );
    } catch (error) {
        const existente = safeApply.extrairAlteracaoDeErro?.(error);

        if (existente) {
            estado.set('alteracoes.ativa', existente);
            safeApply.sincronizar?.(existente);
            notificarBloqueio(existente);
            return;
        }

        const erro = normalizarErro(error);
        notificacao.erro(erro.titulo, erro.mensagem);
    } finally {
        salvandoRoteamento = false;
        definirRoteamentoSalvando(false);
        atualizarEstadoControles();
    }
}


function atualizarEstadoSalvamento(sujo) {
    if (!elementos.routingSaveState) return;

    elementos.routingSaveState.classList.remove('is-pending', 'is-ok', 'is-error');

    if (sujo) {
        elementos.routingSaveState.classList.add('is-pending');
        setText(elementos.routingSaveState, 'Alterações aguardando aplicação');
    } else {
        elementos.routingSaveState.classList.add('is-ok');
        setText(elementos.routingSaveState, 'Configuração sincronizada');
    }
}


function definirRoteamentoSalvando(ativo) {
    const botao = $('#routingSaveButton');
    if (!botao) return;

    botao.classList.toggle('is-loading', Boolean(ativo));
    botao.disabled = Boolean(ativo) || Boolean(safeApply.ocupado?.());
}


/* ==========================================================================
   ROTAS
========================================================================== */

function renderizarRotas() {
    if (!elementos.routesBody) return;

    const rotas = estado.get('roteamento.rotas', []);

    $$('[data-route-row]', elementos.routesBody).forEach(row => row.remove());
    setHidden(elementos.routesEmpty, rotas.length > 0);

    rotas.forEach(rota => {
        elementos.routesBody.appendChild(criarLinhaRota(rota));
    });
}


function criarLinhaRota(rota) {
    const row = criar('tr', {
        attrs: {
            'data-route-row': '',
            'data-route-id': String(rota.id),
        },
    });

    const destinoTd = criar('td');
    const destino = criar('div', { className: 'np-route-destination' });
    destino.append(
        criar('strong', { text: rota.destino || '—' }),
        criar('small', { text: rota.nome || 'Rota estática' })
    );
    destinoTd.appendChild(destino);

    const gatewayTd = criar('td');
    const gatewayCode = criar('code', { text: rota.gateway || '—' });
    gatewayTd.appendChild(gatewayCode);

    const interfaceTd = criar('td');
    const interfaceSpan = criar('span', {
        className: 'np-route-interface',
        text: nomeInterfaceRota(rota),
    });
    interfaceTd.appendChild(interfaceSpan);

    const metricTd = criar('td', { text: rota.metrica ?? '—' });

    const statusTd = criar('td');
    const status = criar('span', { className: 'np-status-pill' });

    if (rota.ultimo_erro) setStatusPill(status, 'error', 'Erro');
    else if (paraBooleano(rota.pendente)) setStatusPill(status, 'warning', 'Pendente');
    else if (!paraBooleano(rota.ativa, true)) setStatusPill(status, 'pending', 'Inativa');
    else setStatusPill(status, 'ok', 'Ativa');

    statusTd.appendChild(status);

    const actionsTd = criar('td', { className: 'np-table__actions' });
    const actions = criar('div', { className: 'np-route-actions' });

    const editar = criar('button', {
        className: 'np-btn np-btn--ghost np-btn--small',
        text: 'Editar',
        attrs: { type: 'button', 'data-route-edit': '' },
    });

    const remover = criar('button', {
        className: 'np-btn np-btn--danger np-btn--small',
        text: 'Remover',
        attrs: { type: 'button', 'data-route-delete': '' },
    });

    const bloqueado = Boolean(safeApply.ocupado?.());
    editar.disabled = bloqueado || salvandoRota || removendoRota;
    remover.disabled = bloqueado || salvandoRota || removendoRota;

    if (bloqueado) {
        editar.title = 'Existe uma alteração de rede em andamento.';
        remover.title = 'Existe uma alteração de rede em andamento.';
    }

    actions.append(editar, remover);
    actionsTd.appendChild(actions);

    row.append(destinoTd, gatewayTd, interfaceTd, metricTd, statusTd, actionsTd);
    return row;
}


function tratarCliqueRota(event) {
    const alvo = event.target instanceof Element ? event.target : null;
    if (!alvo) return;

    const row = alvo.closest('[data-route-row]');
    if (!row) return;

    const id = Number(row.dataset.routeId);

    if (alvo.closest('[data-route-edit]')) {
        if (safeApply.ocupado?.()) return notificarBloqueio();
        abrirRota(id);
    }

    if (alvo.closest('[data-route-delete]')) {
        if (safeApply.ocupado?.()) return notificarBloqueio();
        removerRota(id);
    }
}


function abrirRota(id = null) {
    if (safeApply.ocupado?.()) {
        notificarBloqueio();
        return false;
    }

    rotaEditandoId = id ? Number(id) : null;
    atualizarOpcoesInterfaces();

    const rota = rotaEditandoId ? obterRota(rotaEditandoId) : null;

    setValor(elementos.routeId, rota?.id || '');
    setValor(elementos.routeName, rota?.nome || '');
    setValor(elementos.routeDestination, rota?.destino || '');
    setValor(elementos.routeGateway, rota?.gateway || '');
    setValor(elementos.routeInterface, idInterfaceRota(rota) || '');
    setValor(elementos.routeMetric, rota?.metrica ?? 100);
    setMarcado(elementos.routeEnabled, rota ? paraBooleano(rota.ativa, true) : true);

    setText($('#routeDrawerTitle'), rota ? 'Editar rota' : 'Nova rota');
    abrirDrawer(drawers.rota, { foco: elementos.routeName });

    return true;
}


async function salvarRota(event) {
    event.preventDefault();
    if (salvandoRota) return;

    if (safeApply.ocupado?.()) {
        notificarBloqueio();
        return;
    }

    const payload = {
        nome: valorTrim(elementos.routeName),
        destino: valorTrim(elementos.routeDestination),
        gateway: valorTrim(elementos.routeGateway) || null,
        interface_id: valorNumero(elementos.routeInterface, null),
        metrica: valorNumero(elementos.routeMetric, 100),
        ativa: marcado(elementos.routeEnabled),
    };

    salvandoRota = true;
    atualizarEstadoControles();

    try {
        const url = rotaEditandoId ? urlRota(rotaEditandoId) : api.urls.rotas;
        const resposta = await api.post(url, payload);
        const rota = resposta?.dados?.rota || resposta?.rota || null;

        if (rota) substituirRota(rota);
        else await carregar({ silencioso: true });

        estado.set('roteamento.sujo', true);
        fecharDrawer(drawers.rota);

        renderizarRotas();
        renderizarRoteamento();

        notificacao.sucesso('Rota salva', 'A rota foi salva no estado desejado da rede.');
    } catch (error) {
        const existente = safeApply.extrairAlteracaoDeErro?.(error);

        if (existente) {
            estado.set('alteracoes.ativa', existente);
            safeApply.sincronizar?.(existente);
            notificarBloqueio(existente);
            return;
        }

        const erro = normalizarErro(error);
        notificacao.erro(erro.titulo, erro.mensagem);
    } finally {
        salvandoRota = false;
        atualizarEstadoControles();
    }
}


async function removerRota(id) {
    if (removendoRota || safeApply.ocupado?.()) {
        notificarBloqueio();
        return false;
    }

    const rota = obterRota(id);
    if (!rota) return false;

    const confirmado = await safeApply.confirmarOperacao({
        titulo: 'Remover rota estática?',
        mensagem: `A rota ${rota.destino || rota.nome || id} será removida do estado desejado.`,
        detalhes: 'A remoção precisa ser aplicada posteriormente para sincronizar o sistema operacional.',
        textoConfirmar: 'Remover rota',
        perigoso: true,
    });

    if (!confirmado) return false;
    if (safeApply.ocupado?.()) return notificarBloqueio();

    removendoRota = true;
    atualizarEstadoControles();

    try {
        await api.delete(urlRota(id));

        estado.update(
            'roteamento.rotas',
            lista => (lista || []).filter(item => Number(item.id) !== Number(id))
        );
        estado.set('roteamento.sujo', true);

        renderizarRotas();
        renderizarRoteamento();

        notificacao.aviso(
            'Rota removida',
            'A rota foi removida do estado desejado. Aplique a configuração para sincronizar.'
        );

        return true;
    } catch (error) {
        const existente = safeApply.extrairAlteracaoDeErro?.(error);

        if (existente) {
            estado.set('alteracoes.ativa', existente);
            safeApply.sincronizar?.(existente);
            notificarBloqueio(existente);
            return false;
        }

        const erro = normalizarErro(error);
        notificacao.erro(erro.titulo, erro.mensagem);
        return false;
    } finally {
        removendoRota = false;
        atualizarEstadoControles();
    }
}


function obterRota(id) {
    return estado.get('roteamento.rotas', []).find(item => Number(item.id) === Number(id)) || null;
}


function substituirRota(rota) {
    estado.update('roteamento.rotas', lista => {
        const novaLista = [...(lista || [])];
        const indice = novaLista.findIndex(item => Number(item.id) === Number(rota.id));

        if (indice >= 0) novaLista[indice] = rota;
        else novaLista.push(rota);

        return novaLista;
    });
}


/* ==========================================================================
   NAT
========================================================================== */

function renderizarNat() {
    if (!elementos.natContainer) return;

    const regras = estado.get('nat.regras', []);

    $$('[data-nat-card-rendered]', elementos.natContainer).forEach(card => card.remove());
    setHidden(elementos.natEmpty, regras.length > 0);

    regras.forEach(regra => {
        const card = criarCardNat(regra);
        if (card) elementos.natContainer.appendChild(card);
    });
}


function criarCardNat(regra) {
    const card = clonarTemplate(elementos.natTemplate, '[data-nat-card]');
    if (!card) return null;

    card.dataset.natCardRendered = 'true';
    card.dataset.natId = String(regra.id);

    const erro = regra.ultimo_erro;
    const pendente = paraBooleano(regra.pendente);
    const ativa = paraBooleano(regra.ativa, true);

    card.classList.toggle('is-error', Boolean(erro));
    card.classList.toggle('is-pending', pendente);

    setText($('[data-nat-name]', card), regra.nome || 'NAT MASQUERADE');
    setText($('[data-nat-source-interface]', card), nomeInterfaceNat(regra, 'origem'));
    setText($('[data-nat-source-cidr]', card), regra.origem_cidr || 'Rede da interface');
    setText($('[data-nat-output-interface]', card), nomeInterfaceNat(regra, 'saida'));

    const status = $('[data-nat-status]', card);

    if (erro) setStatusPill(status, 'error', 'Erro');
    else if (pendente) setStatusPill(status, 'warning', 'Pendente');
    else if (!ativa) setStatusPill(status, 'pending', 'Inativa');
    else setStatusPill(status, 'ok', 'Ativa');

    setText(
        $('[data-nat-sync]', card),
        erro ? 'Erro de sincronização' : pendente ? 'Configuração não aplicada' : 'Sincronizada'
    );

    const bloqueado = Boolean(safeApply.ocupado?.());
    const editar = $('[data-nat-edit]', card);
    const remover = $('[data-nat-delete]', card);

    if (editar) {
        editar.disabled = bloqueado || salvandoNat || removendoNat;
        if (bloqueado) editar.title = 'Existe uma alteração de rede em andamento.';
    }

    if (remover) {
        remover.disabled = bloqueado || salvandoNat || removendoNat;
        if (bloqueado) remover.title = 'Existe uma alteração de rede em andamento.';
    }

    return card;
}


function tratarCliqueNat(event) {
    const alvo = event.target instanceof Element ? event.target : null;
    if (!alvo) return;

    const card = alvo.closest('[data-nat-card]');
    if (!card) return;

    const id = Number(card.dataset.natId);

    if (alvo.closest('[data-nat-edit]')) {
        if (safeApply.ocupado?.()) return notificarBloqueio();
        abrirNat(id);
    }

    if (alvo.closest('[data-nat-delete]')) {
        if (safeApply.ocupado?.()) return notificarBloqueio();
        removerNat(id);
    }
}


function abrirNat(id = null) {
    if (safeApply.ocupado?.()) {
        notificarBloqueio();
        return false;
    }

    natEditandoId = id ? Number(id) : null;
    atualizarOpcoesInterfaces();

    const regra = natEditandoId ? obterNat(natEditandoId) : null;

    setValor(elementos.natId, regra?.id || '');
    setValor(elementos.natName, regra?.nome || 'NAT LAN → WAN');
    setValor(elementos.natSourceInterface, idInterfaceNat(regra, 'origem') || '');
    setValor(elementos.natOutputInterface, idInterfaceNat(regra, 'saida') || '');
    setValor(elementos.natSourceCidr, regra?.origem_cidr || '');
    setValor(elementos.natPriority, regra?.prioridade ?? 100);
    setMarcado(elementos.natEnabled, regra ? paraBooleano(regra.ativa, true) : true);

    setText($('#natDrawerTitle'), regra ? 'Editar regra NAT' : 'Nova regra NAT');
    abrirDrawer(drawers.nat, { foco: elementos.natName });

    return true;
}


async function salvarNat(event) {
    event.preventDefault();
    if (salvandoNat) return;

    if (safeApply.ocupado?.()) {
        notificarBloqueio();
        return;
    }

    const payload = {
        nome: valorTrim(elementos.natName),
        tipo: 'masquerade',
        interface_origem_id: valorNumero(elementos.natSourceInterface, null),
        interface_saida_id: valorNumero(elementos.natOutputInterface, null),
        origem_cidr: valorTrim(elementos.natSourceCidr) || null,
        prioridade: valorNumero(elementos.natPriority, 100),
        ativa: marcado(elementos.natEnabled),
    };

    salvandoNat = true;
    atualizarEstadoControles();

    try {
        const url = natEditandoId ? urlNat(natEditandoId) : api.urls.nat;
        const resposta = await api.post(url, payload);
        const regra =
            resposta?.dados?.regra ||
            resposta?.dados?.nat ||
            resposta?.regra ||
            resposta?.nat ||
            null;

        if (regra) substituirNat(regra);
        else await carregar({ silencioso: true });

        estado.set('nat.sujo', true);
        fecharDrawer(drawers.nat);
        renderizarNat();

        notificacao.sucesso('Regra NAT salva', 'A regra foi salva no estado desejado da rede.');
    } catch (error) {
        const existente = safeApply.extrairAlteracaoDeErro?.(error);

        if (existente) {
            estado.set('alteracoes.ativa', existente);
            safeApply.sincronizar?.(existente);
            notificarBloqueio(existente);
            return;
        }

        const erro = normalizarErro(error);
        notificacao.erro(erro.titulo, erro.mensagem);
    } finally {
        salvandoNat = false;
        atualizarEstadoControles();
    }
}


async function removerNat(id) {
    if (removendoNat || safeApply.ocupado?.()) {
        notificarBloqueio();
        return false;
    }

    const regra = obterNat(id);
    if (!regra) return false;

    const confirmado = await safeApply.confirmarOperacao({
        titulo: 'Remover regra NAT?',
        mensagem: `${regra.nome || 'A regra selecionada'} será removida do estado desejado.`,
        detalhes: 'A remoção será efetivada no Linux somente quando a configuração for aplicada.',
        textoConfirmar: 'Remover regra',
        perigoso: true,
    });

    if (!confirmado) return false;
    if (safeApply.ocupado?.()) return notificarBloqueio();

    removendoNat = true;
    atualizarEstadoControles();

    try {
        await api.delete(urlNat(id));

        estado.update(
            'nat.regras',
            lista => (lista || []).filter(item => Number(item.id) !== Number(id))
        );
        estado.set('nat.sujo', true);

        renderizarNat();

        notificacao.aviso(
            'Regra NAT removida',
            'A regra foi removida do estado desejado. Aplique a configuração para sincronizar.'
        );

        return true;
    } catch (error) {
        const existente = safeApply.extrairAlteracaoDeErro?.(error);

        if (existente) {
            estado.set('alteracoes.ativa', existente);
            safeApply.sincronizar?.(existente);
            notificarBloqueio(existente);
            return false;
        }

        const erro = normalizarErro(error);
        notificacao.erro(erro.titulo, erro.mensagem);
        return false;
    } finally {
        removendoNat = false;
        atualizarEstadoControles();
    }
}


function obterNat(id) {
    return estado.get('nat.regras', []).find(item => Number(item.id) === Number(id)) || null;
}


function substituirNat(regra) {
    estado.update('nat.regras', lista => {
        const novaLista = [...(lista || [])];
        const indice = novaLista.findIndex(item => Number(item.id) === Number(regra.id));

        if (indice >= 0) novaLista[indice] = regra;
        else novaLista.push(regra);

        return novaLista;
    });
}


/* ==========================================================================
   APLICAR
========================================================================== */

async function aplicarConfiguracao() {
    if (aplicandoConfiguracao || safeApply.ocupado?.()) {
        notificarBloqueio();
        return false;
    }

    const roteamentoSujo = Boolean(estado.get('roteamento.sujo'));
    const natSujo = Boolean(estado.get('nat.sujo'));

    if (!roteamentoSujo && !natSujo) {
        notificacao.info(
            'Nenhuma alteração',
            'Roteamento e NAT não possuem alterações pendentes.'
        );
        return false;
    }

    let endpoint;
    let titulo;
    let mensagem;
    let detalhes;
    let origemReserva;

    if (roteamentoSujo && natSujo) {
        endpoint = api.urls.aplicarTudo;
        titulo = 'Aplicar roteamento e NAT?';
        mensagem = 'Existem alterações pendentes em roteamento e NAT.';
        detalhes = 'Os dois conjuntos serão aplicados em uma única alteração segura. O estado completo da Rede será enviado ao Agent.';
        origemReserva = 'routing-nat:apply-all';
    } else if (roteamentoSujo) {
        endpoint = api.urls.aplicarRoteamento;
        titulo = 'Aplicar roteamento?';
        mensagem = 'O estado desejado de roteamento será enviado ao MoonShield Agent.';
        detalhes = 'O Agent criará um snapshot, armará o rollback e aguardará confirmação.';
        origemReserva = 'routing:apply';
    } else {
        endpoint = api.urls.aplicarNat;
        titulo = 'Aplicar NAT?';
        mensagem = 'As regras NAT desejadas serão enviadas ao MoonShield Agent.';
        detalhes = 'O Agent aplicará somente a configuração NAT prevista pelo backend.';
        origemReserva = 'nat:apply';
    }

    const confirmado = await safeApply.confirmarOperacao({
        titulo,
        mensagem,
        detalhes,
        textoConfirmar: 'Aplicar configuração',
        perigoso: false,
    });

    if (!confirmado) return false;

    if (!safeApply.reservarOperacao?.(origemReserva)) {
        notificarBloqueio();
        return false;
    }

    aplicandoConfiguracao = true;
    atualizarEstadoControles();

    safeApply.mostrarOperacao({
        titulo: 'Aplicando configuração',
        descricao: 'Validando o estado desejado, preparando snapshot e armando o rollback.',
    });

    try {
        const resposta = await api.post(endpoint, {});
        const alteracao = extrairAlteracao(resposta);

        if (!alteracao) {
            throw new Error('A API não retornou a alteração de rede criada.');
        }

        estado.set('alteracoes.ativa', alteracao);

        safeApply.ocultarOperacao();
        safeApply.sincronizar?.(alteracao);

        if (String(alteracao.status || '') === 'waiting_confirmation') {
            safeApply.abrir?.(alteracao);

            notificacao.aviso(
                'Confirmação necessária',
                'A configuração foi aplicada. Confirme a conectividade antes do término do Safe Apply.'
            );
        }

        await carregar({ silencioso: true });
        return true;
    } catch (error) {
        safeApply.ocultarOperacao();

        const existente = safeApply.extrairAlteracaoDeErro?.(error);

        if (existente) {
            estado.set('alteracoes.ativa', existente);
            safeApply.sincronizar?.(existente);
            notificarBloqueio(existente);
            return false;
        }

        safeApply.liberarReserva?.();

        const erro = normalizarErro(error);
        notificacao.erro(erro.titulo, erro.mensagem);

        return false;
    } finally {
        aplicandoConfiguracao = false;
        atualizarEstadoControles();
    }
}


/* ==========================================================================
   CONTROLES / LOCK GLOBAL
========================================================================== */

function atualizarEstadoControles() {
    const bloqueado = Boolean(safeApply.ocupado?.());

    const routingSaveButton = $('#routingSaveButton');

    if (routingSaveButton) {
        routingSaveButton.disabled = bloqueado || salvandoRoteamento;
        routingSaveButton.setAttribute(
            'aria-disabled',
            routingSaveButton.disabled ? 'true' : 'false'
        );
    }

    if (elementos.routingApplyButton) {
        const semPendencia =
            !Boolean(estado.get('roteamento.sujo')) &&
            !Boolean(estado.get('nat.sujo'));

        elementos.routingApplyButton.disabled =
            bloqueado ||
            aplicandoConfiguracao ||
            semPendencia;

        elementos.routingApplyButton.setAttribute(
            'aria-disabled',
            elementos.routingApplyButton.disabled ? 'true' : 'false'
        );

        if (bloqueado) {
            elementos.routingApplyButton.title = 'Existe uma alteração de rede em andamento.';
        } else if (semPendencia) {
            elementos.routingApplyButton.title = 'Não há alterações de roteamento ou NAT para aplicar.';
        } else {
            elementos.routingApplyButton.removeAttribute('title');
        }
    }

    if (elementos.newRouteButton) {
        elementos.newRouteButton.disabled = bloqueado || salvandoRota || removendoRota;
    }

    if (elementos.newNatButton) {
        elementos.newNatButton.disabled = bloqueado || salvandoNat || removendoNat;
    }

    [
        elementos.ipv4Forward,
        elementos.defaultRouteManagement,
        elementos.autoRollback,
        elementos.confirmationTimeout,
    ].forEach(campo => {
        if (campo) campo.disabled = bloqueado || salvandoRoteamento;
    });

    [
        elementos.routeName,
        elementos.routeDestination,
        elementos.routeGateway,
        elementos.routeInterface,
        elementos.routeMetric,
        elementos.routeEnabled,
    ].forEach(campo => {
        if (campo) campo.disabled = bloqueado || salvandoRota;
    });

    [
        elementos.natName,
        elementos.natSourceInterface,
        elementos.natOutputInterface,
        elementos.natSourceCidr,
        elementos.natPriority,
        elementos.natEnabled,
    ].forEach(campo => {
        if (campo) campo.disabled = bloqueado || salvandoNat;
    });

    if (elementos.routesBody) {
        $$('[data-route-row]', elementos.routesBody).forEach(row => {
            const editar = $('[data-route-edit]', row);
            const remover = $('[data-route-delete]', row);

            if (editar) editar.disabled = bloqueado || salvandoRota || removendoRota;
            if (remover) remover.disabled = bloqueado || salvandoRota || removendoRota;
        });
    }

    if (elementos.natContainer) {
        $$('[data-nat-card]', elementos.natContainer).forEach(card => {
            const editar = $('[data-nat-edit]', card);
            const remover = $('[data-nat-delete]', card);

            if (editar) editar.disabled = bloqueado || salvandoNat || removendoNat;
            if (remover) remover.disabled = bloqueado || salvandoNat || removendoNat;
        });
    }
}


function notificarBloqueio(alteracao = safeApply.obterAlteracaoAtiva?.()) {
    notificacao.aviso(
        'Alteração em andamento',
        alteracao?.titulo
            ? `${alteracao.titulo}. Confirme ou reverta antes de alterar Roteamento ou NAT.`
            : 'Confirme ou reverta a alteração atual antes de alterar Roteamento ou NAT.'
    );

    return false;
}


/* ==========================================================================
   INTERFACES NOS SELECTS
========================================================================== */

function atualizarOpcoesInterfaces() {
    const interfaces = estado.get('interfaces.lista', []);

    preencherSelectInterface(
        elementos.routeInterface,
        interfaces.filter(item => item.habilitada !== false),
        'Selecionar'
    );

    preencherSelectInterface(
        elementos.natSourceInterface,
        interfaces.filter(item => ['lan', 'dmz', 'custom'].includes(item.papel) && item.habilitada !== false),
        'Selecionar'
    );

    preencherSelectInterface(
        elementos.natOutputInterface,
        interfaces.filter(item => item.papel === 'wan' && item.habilitada !== false),
        'Selecionar WAN'
    );
}


function preencherSelectInterface(select, lista, placeholder) {
    if (!select) return;

    const valorAtual = select.value;
    select.replaceChildren();

    const primeira = document.createElement('option');
    primeira.value = '';
    primeira.textContent = placeholder;
    select.appendChild(primeira);

    lista.forEach(item => {
        const option = document.createElement('option');

        option.value = String(item.id);
        option.textContent = `${item.nome} · ${rotuloPapel(item.papel)}`;

        select.appendChild(option);
    });

    if ([...select.options].some(option => option.value === valorAtual)) select.value = valorAtual;
}


/* ==========================================================================
   HELPERS INTERFACES
========================================================================== */

function nomeInterfaceRota(rota) {
    return rota?.interface_nome ||
        rota?.interface?.nome ||
        buscarNomeInterface(rota?.interface_id || rota?.interface) ||
        '—';
}


function idInterfaceRota(rota) {
    if (!rota) return null;

    if (typeof rota.interface === 'object') return rota.interface?.id || null;

    return rota.interface_id || rota.interface || null;
}


function nomeInterfaceNat(regra, lado) {
    if (lado === 'origem') {
        return regra?.interface_origem_nome ||
            regra?.interface_origem?.nome ||
            buscarNomeInterface(regra?.interface_origem_id || regra?.interface_origem) ||
            '—';
    }

    return regra?.interface_saida_nome ||
        regra?.interface_saida?.nome ||
        buscarNomeInterface(regra?.interface_saida_id || regra?.interface_saida) ||
        '—';
}


function idInterfaceNat(regra, lado) {
    if (!regra) return null;

    const valor = lado === 'origem' ? regra.interface_origem : regra.interface_saida;
    const id = lado === 'origem' ? regra.interface_origem_id : regra.interface_saida_id;

    if (typeof valor === 'object') return valor?.id || id || null;

    return id || valor || null;
}


function buscarNomeInterface(id) {
    if (!id) return null;

    const item = estado.get('interfaces.lista', []).find(interfaceItem => Number(interfaceItem.id) === Number(id));
    return item?.nome || null;
}


/* ==========================================================================
   PENDÊNCIAS
========================================================================== */

function inferirRoteamentoPendente(configuracao, rotas) {
    if (paraBooleano(configuracao?.pendente)) return true;

    return (rotas || []).some(rota => {
        return paraBooleano(rota.pendente) || !paraBooleano(rota.sincronizada, true);
    });
}


/* ==========================================================================
   URL
========================================================================== */

function urlRota(id) {
    const base = api.urls.rotas;
    if (!base) throw new Error('URL de rotas não configurada.');

    return `${base.endsWith('/') ? base : `${base}/`}${encodeURIComponent(String(id))}/`;
}


function urlNat(id) {
    const base = api.urls.nat;
    if (!base) throw new Error('URL de NAT não configurada.');

    return `${base.endsWith('/') ? base : `${base}/`}${encodeURIComponent(String(id))}/`;
}


/* ==========================================================================
   EXTRAÇÃO
========================================================================== */

function extrairLista(valor) {
    if (Array.isArray(valor)) return valor;
    if (Array.isArray(valor?.resultados)) return valor.resultados;
    if (Array.isArray(valor?.lista)) return valor.lista;

    return [];
}


function extrairAlteracao(resposta) {
    return resposta?.dados?.alteracao ||
        resposta?.dados?.resultado?.alteracao ||
        resposta?.alteracao ||
        null;
}


/* ==========================================================================
   EXPORT
========================================================================== */

export const roteamentoNat = Object.freeze({
    inicializar,
    aoAtivar,
    carregar,
    renderizar,
    sincronizar,
    salvarRoteamento,
    aplicarConfiguracao,
    abrirRota,
    abrirNat,
});

export default roteamentoNat;