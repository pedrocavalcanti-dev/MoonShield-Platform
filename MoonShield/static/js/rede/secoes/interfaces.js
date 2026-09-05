/**
 * MoonShield Network Panel
 * Seção: Interfaces
 */

'use strict';

import { api } from '../nucleo/api.js';
import { estado } from '../nucleo/estado.js';
import { $, $$, setText, setHidden, criar } from '../nucleo/dom.js';
import { normalizarErro } from '../nucleo/utilitarios.js';
import { abrirDrawer, fecharDrawer, drawers } from '../componentes/drawer.js';
import { notificacao } from '../componentes/notificacoes.js';
import { safeApply } from '../componentes/safe_apply.js';

let inicializado = false;
let carregando = false;
let salvando = false;
let aplicandoId = null;
let carregamentoAtual = null;
let sequenciaSolicitada = 0;

const elementos = {
    container: null,
    empty: null,
    backend: null,
    total: null,
    configured: null,
    online: null,
    pending: null,
    refreshButton: null,
    detectButton: null,
    warning: null,

    form: null,
    id: null,
    name: null,
    description: null,
    role: null,
    primary: null,
    enabled: null,
    management: null,
    ipv4Mode: null,
    staticFields: null,
    ipv4Address: null,
    ipv4Prefix: null,
    gatewayGroup: null,
    gateway: null,
    defaultRouteRow: null,
    defaultRoute: null,
    metric: null,
    mtu: null,
    notice: null,
    saveButton: null,
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
    elementos.container =
        $('#interfacesContainer') ||
        $('#interfacesGrid') ||
        $('#networkInterfacesContainer') ||
        $('[data-interfaces-container]');

    elementos.empty =
        $('#interfacesEmptyState') ||
        $('[data-interfaces-empty]');

    elementos.backend =
        $('#interfacesBackend') ||
        $('#interfacesBackendName') ||
        $('[data-interfaces-backend]');

    elementos.total =
        $('#interfacesTotal') ||
        $('[data-interfaces-total]');

    elementos.configured = $('#interfacesConfigured');
    elementos.online = $('#interfacesOnline');
    elementos.pending = $('#interfacesPending');
    elementos.refreshButton = $('#interfacesRefreshButton');
    elementos.detectButton = $('#interfacesDetectButton');
    elementos.warning = $('#interfacesUpdateWarning');

    elementos.form = $('#interfaceConfigForm');
    elementos.id = $('#interfaceConfigId');
    elementos.name = $('#interfaceConfigName');
    elementos.description = $('#interfaceDescription');
    elementos.role = $('#interfaceRole');
    elementos.primary = $('#interfacePrimary');
    elementos.enabled = $('#interfaceEnabled');
    elementos.management = $('#interfaceManagement');
    elementos.ipv4Mode = $('#interfaceIpv4Mode');
    elementos.staticFields = $('#interfaceStaticFields');
    elementos.ipv4Address = $('#interfaceIpv4Address');
    elementos.ipv4Prefix = $('#interfaceIpv4Prefix');
    elementos.gatewayGroup = $('#interfaceGatewayGroup');
    elementos.gateway = $('#interfaceGateway');
    elementos.defaultRouteRow = $('#interfaceDefaultRouteRow');
    elementos.defaultRoute = $('#interfaceDefaultRoute');
    elementos.metric = $('#interfaceMetric');
    elementos.mtu = $('#interfaceMtu');
    elementos.notice = $('#interfaceConfigNotice');
    elementos.saveButton = $('#interfaceSaveButton');
}


function registrarEventos() {
    elementos.container?.addEventListener('click', tratarCliqueContainer);
    elementos.form?.addEventListener('submit', salvarConfiguracaoInterface);
    elementos.refreshButton?.addEventListener('click', atualizarInterfaces);
    elementos.role?.addEventListener('change', atualizarCamposFormulario);
    elementos.ipv4Mode?.addEventListener('change', atualizarCamposFormulario);

    document.addEventListener('moonshield:network-lock-change', atualizarEstadoControles);
    document.addEventListener('moonshield:safe-apply-finished', atualizarEstadoControles);
}


/* ==========================================================================
   CARREGAR / RENDER
========================================================================== */

function carregar(opcoes = {}) {
    const sequencia = ++sequenciaSolicitada;

    if (carregamentoAtual) return carregamentoAtual;

    const promessa = executarCarregamento(sequencia, opcoes);
    carregamentoAtual = promessa;

    const liberarCarregamento = () => {
        if (carregamentoAtual === promessa) carregamentoAtual = null;
    };

    promessa.then(liberarCarregamento, liberarCarregamento);

    return promessa;
}


async function executarCarregamento(sequencia, opcoes = {}) {
    carregando = true;
    definirCarregamento(true);
    let lista = estado.get('interfaces.lista', []);

    try {
        const resposta = await api.get(api.urls.interfaces);
        const dados = resposta?.dados ?? resposta ?? {};
        lista = extrairInterfaces(dados);

        if (sequencia === sequenciaSolicitada) {
            estado.set('interfaces.lista', lista);
            estado.set(
                'interfaces.backend',
                dados.backend ||
                dados.gerenciador ||
                dados.network_backend ||
                estado.get('interfaces.backend') ||
                null
            );
            estado.set('interfaces.carregado', true);
            estado.set('interfaces.reconciliado', dados.reconciliado !== false);
            estado.set('interfaces.aviso', dados.aviso || null);

            const ativa = dados.alteracao_ativa || dados.ativa || null;
            if (ativa) {
                estado.set('alteracoes.ativa', ativa);
                safeApply.sincronizar?.(ativa);
            }

            atualizarAvisoAtualizacao(dados);
            renderizar();
        }
    } catch (error) {
        if (sequencia === sequenciaSolicitada) {
            estado.set('interfaces.carregado', false);
            atualizarAvisoAtualizacao();

            if (!opcoes.silencioso) {
                const erro = normalizarErro(error);
                notificacao.erro(
                    erro.titulo || 'Erro nas interfaces',
                    erro.mensagem || 'Não foi possível carregar as interfaces de rede.'
                );
            }

            throw error;
        }
    } finally {
        carregando = false;
        definirCarregamento(false);
        atualizarEstadoControles();
    }

    if (sequencia < sequenciaSolicitada) {
        return executarCarregamento(sequenciaSolicitada, { silencioso: true });
    }

    return lista;
}


async function aoAtivar() {
    if (estado.get('ui.carregamentoInicial')) return;

    try {
        await carregar({ silencioso: true });
    } catch {
        // Mantém o painel utilizável caso a leitura falhe.
    }
}


async function atualizarInterfaces() {
    try {
        await carregar({ silencioso: false });
        return true;
    } catch {
        return false;
    }
}


function renderizar() {
    const lista = estado.get('interfaces.lista', []);
    const backend =
        estado.get('interfaces.backend') ||
        estado.get('status.agent.status.backend') ||
        'NetworkManager';

    const configuradas = lista.filter(interfaceConfigurada).length;
    const online = lista.filter(interfaceAtiva).length;
    const pendentes = lista.filter(interfacePendente).length;

    setText(elementos.backend, backend);
    setText(elementos.total, lista.length);
    setText(elementos.configured, configuradas);
    setText(elementos.online, online);
    setText(elementos.pending, pendentes);

    setHidden(elementos.empty, lista.length > 0);

    if (!elementos.container) return;

    removerCardsRenderizados();

    lista.forEach(interfaceRede => {
        const card = criarCardInterface(interfaceRede);
        if (card) elementos.container.appendChild(card);
    });

    atualizarEstadoControles();
}


function definirCarregamento(ativo) {
    elementos.container?.setAttribute('aria-busy', ativo ? 'true' : 'false');

    if (elementos.refreshButton) {
        elementos.refreshButton.disabled = Boolean(ativo);
        elementos.refreshButton.classList.toggle('is-loading', Boolean(ativo));
        elementos.refreshButton.setAttribute('aria-busy', ativo ? 'true' : 'false');
    }
}


function atualizarAvisoAtualizacao(dados = {}) {
    const aviso = dados.aviso;
    const exibir = dados.reconciliado === false && aviso;

    setHidden(elementos.warning, !exibir);

    if (exibir) {
        setText(
            elementos.warning,
            aviso.mensagem || 'Não foi possível atualizar o estado pelo Agent. Exibindo o último estado conhecido.'
        );
    }
}


function sincronizar() {
    renderizar();
}


/* ==========================================================================
   CARD
========================================================================== */

function criarCardInterface(interfaceRede) {
    const template = $('#interfaceCardTemplate') || $('[data-interface-template]');

    if (template instanceof HTMLTemplateElement) {
        const fragmento = template.content.cloneNode(true);
        const card =
            fragmento.querySelector('[data-interface-card]') ||
            fragmento.firstElementChild;

        if (!card) return null;

        preencherCard(card, interfaceRede);
        return card;
    }

    const card = criar('article', {
        className: 'np-interface-card',
        attrs: {
            'data-interface-card': '',
            'data-interface-rendered': 'true',
            'data-interface-id': String(obterId(interfaceRede) ?? ''),
        },
    });

    const cabecalho = criar('div', { className: 'np-interface-card__header' });
    const titulo = criar('div', { className: 'np-interface-card__title' });

    titulo.append(
        criar('strong', { text: obterNome(interfaceRede) }),
        criar('span', {
            className: 'np-status-pill',
            text: obterPapel(interfaceRede),
        })
    );

    const corpo = criar('div', { className: 'np-interface-card__body' });

    corpo.append(
        criarLinha('Estado', obterEstado(interfaceRede)),
        criarLinha('IPv4 desejado', obterIPv4Desejado(interfaceRede)),
        criarLinha('IPv4 atual', obterIPv4(interfaceRede)),
        criarLinha('MAC', obterMac(interfaceRede)),
        criarLinha('Gateway', obterGateway(interfaceRede))
    );

    const acoes = criar('div', { className: 'np-interface-card__actions' });

    const configurar = criar('button', {
        className: 'np-btn np-btn--ghost np-btn--small',
        text: 'Configurar',
        attrs: {
            type: 'button',
            'data-interface-configure': '',
        },
    });

    const aplicar = criar('button', {
        className: 'np-btn np-btn--primary np-btn--small',
        text: 'Aplicar',
        attrs: {
            type: 'button',
            'data-interface-apply': '',
        },
    });

    acoes.append(configurar, aplicar);
    cabecalho.appendChild(titulo);
    card.append(cabecalho, corpo, acoes);

    preencherCard(card, interfaceRede);

    return card;
}


function preencherCard(card, interfaceRede) {
    card.dataset.interfaceCard = '';
    card.dataset.interfaceRendered = 'true';

    const id = obterId(interfaceRede);

    if (id !== null && id !== undefined) {
        card.dataset.interfaceId = String(id);
    }

    setText($('[data-interface-name]', card), obterNome(interfaceRede));
    setText($('[data-interface-role]', card), obterPapel(interfaceRede));
    setText($('[data-interface-mac]', card), obterMac(interfaceRede));
    setText($('[data-interface-desired-ip]', card), obterIPv4Desejado(interfaceRede));
    setText($('[data-interface-current-ip]', card), obterIPv4(interfaceRede));
    setText($('[data-interface-current-ips]', card), obterIPv4sObservados(interfaceRede));
    setText($('[data-interface-gateway]', card), obterGateway(interfaceRede));
    setText($('[data-interface-mtu]', card), obterMtu(interfaceRede));
    setText($('[data-interface-backend]', card), obterBackend(interfaceRede));
    setText($('[data-interface-management]', card), obterGerenciamento(interfaceRede));
    setText($('[data-interface-revisions]', card), obterRevisoes(interfaceRede));

    const erro = String(interfaceRede?.ultimo_erro || '').trim();
    const erroLinha = $('[data-interface-error-row]', card);
    setHidden(erroLinha, !erro);
    setText($('[data-interface-error]', card), erro);

    atualizarLinkCard(card, interfaceRede);
    atualizarSincronizacaoCard(card, interfaceRede);

    const configurar = $('[data-interface-configure]', card);
    const aplicar = $('[data-interface-apply]', card);

    if (configurar && id !== null) configurar.dataset.interfaceId = String(id);
    if (aplicar && id !== null) aplicar.dataset.interfaceId = String(id);

    const ativa = interfaceAtiva(interfaceRede);
    const pendente = interfacePendente(interfaceRede);
    const estadoSincronizacao = obterEstadoSincronizacao(interfaceRede);

    card.classList.toggle('is-up', ativa);
    card.classList.toggle('is-down', !ativa);
    card.classList.toggle('is-pending', pendente);
    card.dataset.syncStatus = estadoSincronizacao;

    atualizarAcoesCard(card, interfaceRede);
}


function criarLinha(rotulo, valor) {
    const linha = criar('div', { className: 'np-interface-card__row' });

    linha.append(
        criar('span', { text: rotulo }),
        criar('strong', { text: valor || '—' })
    );

    return linha;
}


function removerCardsRenderizados() {
    $$('[data-interface-rendered]', elementos.container).forEach(card => card.remove());
}


function atualizarAcoesCard(card, interfaceRede) {
    const bloqueado = Boolean(safeApply.ocupado?.());
    const id = obterId(interfaceRede);

    const configurar = $('[data-interface-configure]', card);
    const aplicar = $('[data-interface-apply]', card);

    if (configurar) {
        configurar.disabled = bloqueado || salvando;
        configurar.setAttribute('aria-disabled', configurar.disabled ? 'true' : 'false');

        if (bloqueado) configurar.title = 'Existe uma alteração de rede em andamento.';
        else configurar.removeAttribute('title');
    }

    if (aplicar) {
        const aplicando = String(aplicandoId) === String(id);
        const estadoSincronizacao = obterEstadoSincronizacao(interfaceRede);
        const podeAplicar = interfacePodeAplicar(interfaceRede);
        const operacaoEmAndamento = [
            'applying',
            'waiting_confirmation',
        ].includes(estadoSincronizacao);

        aplicar.disabled =
            bloqueado ||
            aplicando ||
            operacaoEmAndamento ||
            !podeAplicar;

        aplicar.setAttribute('aria-disabled', aplicar.disabled ? 'true' : 'false');

        if (bloqueado) {
            aplicar.title = 'Existe uma alteração de rede em andamento.';
        } else if (operacaoEmAndamento) {
            aplicar.title = 'Esta interface possui uma aplicação em andamento.';
        } else if (!podeAplicar) {
            aplicar.title = 'Não há uma aplicação pendente para esta interface.';
        } else {
            aplicar.removeAttribute('title');
        }
    }
}


/* ==========================================================================
   CLIQUES / EDIÇÃO
========================================================================== */

function tratarCliqueContainer(event) {
    const alvo = event.target instanceof Element ? event.target : null;
    if (!alvo) return;

    const configurar = alvo.closest('[data-interface-configure]');

    if (configurar) {
        if (safeApply.ocupado?.()) {
            notificarBloqueio();
            return;
        }

        const id = obterIdElemento(configurar);
        if (id !== null) editarInterface(id);
        return;
    }

    const aplicar = alvo.closest('[data-interface-apply]');

    if (aplicar) {
        const id = obterIdElemento(aplicar);
        if (id !== null) aplicarInterface(id);
    }
}


function editarInterface(id) {
    if (safeApply.ocupado?.()) {
        notificarBloqueio();
        return false;
    }

    const interfaceRede = obterInterface(id);

    if (!interfaceRede) {
        notificacao.erro(
            'Interface não encontrada',
            'Não foi possível localizar a interface selecionada.'
        );
        return false;
    }

    if (!elementos.form) {
        notificacao.erro(
            'Formulário indisponível',
            'O formulário de configuração da interface não foi encontrado.'
        );
        return false;
    }

    preencherFormulario(interfaceRede);
    abrirDrawer(drawers.interface, {
        foco: elementos.description || elementos.role,
    });

    return true;
}


function preencherFormulario(interfaceRede) {
    definirValor(elementos.id, obterId(interfaceRede));
    definirValor(elementos.name, obterNome(interfaceRede));
    definirValor(elementos.description, obterDesejado(interfaceRede, 'descricao', ''));
    definirValor(
        elementos.role,
        String(obterDesejado(interfaceRede, 'papel', 'unassigned') || 'unassigned').toLowerCase()
    );

    definirMarcado(
        elementos.primary,
        paraBooleano(obterDesejado(interfaceRede, 'principal', false))
    );
    definirMarcado(
        elementos.enabled,
        paraBooleano(obterDesejado(interfaceRede, 'habilitada', true), true)
    );
    definirMarcado(
        elementos.management,
        paraBooleano(obterDesejado(interfaceRede, 'acesso_gerenciamento', false))
    );

    definirValor(
        elementos.ipv4Mode,
        String(obterDesejado(interfaceRede, 'ipv4_modo', 'dhcp') || 'dhcp').toLowerCase()
    );
    definirValor(elementos.ipv4Address, obterDesejado(interfaceRede, 'ipv4_endereco', '') || '');
    definirValor(elementos.ipv4Prefix, obterDesejado(interfaceRede, 'ipv4_prefixo', 24) ?? 24);
    definirValor(elementos.gateway, obterDesejado(interfaceRede, 'gateway', '') || '');
    definirMarcado(
        elementos.defaultRoute,
        paraBooleano(obterDesejado(interfaceRede, 'rota_padrao', false))
    );
    definirValor(elementos.metric, obterDesejado(interfaceRede, 'metrica', 100) ?? 100);
    definirValor(elementos.mtu, obterDesejado(interfaceRede, 'mtu', 1500) ?? 1500);

    ocultarAvisoFormulario();
    atualizarCamposFormulario();
    atualizarEstadoControles();
}


function atualizarCamposFormulario() {
    const papel = String(elementos.role?.value || 'unassigned').toLowerCase();
    const modo = String(elementos.ipv4Mode?.value || 'dhcp').toLowerCase();

    const estatico = modo === 'static';
    const wan = papel === 'wan';

    if (elementos.staticFields) elementos.staticFields.hidden = !estatico;
    if (elementos.gatewayGroup) elementos.gatewayGroup.hidden = !estatico;
    if (elementos.defaultRouteRow) elementos.defaultRouteRow.hidden = !wan;

    if (!wan) definirMarcado(elementos.defaultRoute, false);

    if (papel === 'unassigned') definirMarcado(elementos.primary, false);
}


/* ==========================================================================
   SALVAR CONFIGURAÇÃO
========================================================================== */

async function salvarConfiguracaoInterface(event) {
    event.preventDefault();

    if (salvando) return;

    if (safeApply.ocupado?.()) {
        mostrarAvisoFormulario(
            'Existe uma alteração de rede em andamento. Confirme ou reverta antes de editar outra configuração.',
            'warning'
        );
        notificarBloqueio();
        return;
    }

    const id = elementos.id?.value;

    if (!id) {
        mostrarAvisoFormulario(
            'Não foi possível identificar a interface.',
            'error'
        );
        return;
    }

    const payload = montarPayloadFormulario();
    const erroValidacao = validarPayload(payload);

    if (erroValidacao) {
        mostrarAvisoFormulario(erroValidacao, 'error');
        return;
    }

    salvando = true;
    definirBotaoSalvando(true);
    ocultarAvisoFormulario();
    atualizarEstadoControles();

    try {
        const resposta = await api.post(urlConfigurarInterface(id), payload);
        const interfaceSalva =
            resposta?.dados?.interface ||
            resposta?.interface ||
            null;

        if (interfaceSalva) substituirInterface(interfaceSalva);
        else await carregar({ silencioso: true });

        estado.set('interfaces.sujo', true);

        renderizar();

        mostrarAvisoFormulario(
            'Configuração salva. Ela ainda não foi aplicada no Linux.',
            'ok'
        );

        notificacao.sucesso(
            'Configuração salva',
            'O estado desejado foi salvo. Use Aplicar para sincronizar a interface.'
        );

        return interfaceSalva;
    } catch (error) {
        const existente = safeApply.extrairAlteracaoDeErro?.(error);

        if (existente) {
            estado.set('alteracoes.ativa', existente);
            safeApply.sincronizar?.(existente);

            mostrarAvisoFormulario(
                'Outra alteração de rede está em andamento. Conclua-a antes de salvar.',
                'warning'
            );

            notificarBloqueio(existente);
            return null;
        }

        const erro = normalizarErro(error);

        mostrarAvisoFormulario(
            erro.mensagem || 'Não foi possível salvar a configuração da interface.',
            'error'
        );

        notificacao.erro(
            erro.titulo || 'Falha ao salvar interface',
            erro.mensagem || 'Não foi possível salvar a configuração da interface.'
        );

        return null;
    } finally {
        salvando = false;
        definirBotaoSalvando(false);
        atualizarEstadoControles();
    }
}


/* ==========================================================================
   PAYLOAD / VALIDAÇÃO
========================================================================== */

function montarPayloadFormulario() {
    const papel = String(elementos.role?.value || 'unassigned').toLowerCase();
    const ipv4Modo = String(elementos.ipv4Mode?.value || 'dhcp').toLowerCase();

    const estatico = ipv4Modo === 'static';
    const wan = papel === 'wan';

    return {
        descricao: valorTrim(elementos.description),
        papel,
        principal: papel === 'unassigned' ? false : marcado(elementos.primary),
        habilitada: marcado(elementos.enabled),
        acesso_gerenciamento: marcado(elementos.management),
        ipv4_modo: ipv4Modo,
        ipv4_endereco: estatico ? valorTrim(elementos.ipv4Address) || null : null,
        ipv4_prefixo: estatico ? valorNumero(elementos.ipv4Prefix, 24) : null,
        gateway: estatico ? valorTrim(elementos.gateway) || null : null,
        rota_padrao: wan ? marcado(elementos.defaultRoute) : false,
        metrica: valorNumero(elementos.metric, 100),
        mtu: valorNumero(elementos.mtu, 1500),
    };
}


function validarPayload(payload) {
    if (!['unassigned', 'wan', 'lan', 'mgmt', 'dmz', 'custom'].includes(payload.papel)) {
        return 'Papel de interface inválido.';
    }

    if (!['dhcp', 'static', 'disabled'].includes(payload.ipv4_modo)) {
        return 'Modo IPv4 inválido.';
    }

    if (payload.ipv4_modo === 'static') {
        if (!ipv4Valido(payload.ipv4_endereco)) {
            return 'Informe um endereço IPv4 estático válido.';
        }

        if (
            !Number.isInteger(payload.ipv4_prefixo) ||
            payload.ipv4_prefixo < 0 ||
            payload.ipv4_prefixo > 32
        ) {
            return 'O prefixo IPv4 deve ficar entre 0 e 32.';
        }
    }

    if (payload.gateway && !ipv4Valido(payload.gateway)) {
        return 'Informe um gateway IPv4 válido.';
    }

    if (
        !Number.isInteger(payload.metrica) ||
        payload.metrica < 0 ||
        payload.metrica > 4294967295
    ) {
        return 'A métrica deve ficar entre 0 e 4294967295.';
    }

    if (
        !Number.isInteger(payload.mtu) ||
        payload.mtu < 576 ||
        payload.mtu > 65535
    ) {
        return 'O MTU deve ficar entre 576 e 65535.';
    }

    return '';
}


/* ==========================================================================
   AVISO / BOTÃO
========================================================================== */

function mostrarAvisoFormulario(mensagem, tipo = 'warning') {
    if (!elementos.notice) return;

    elementos.notice.hidden = false;
    elementos.notice.classList.remove('is-warning', 'is-error', 'is-ok');
    elementos.notice.classList.add(
        tipo === 'error'
            ? 'is-error'
            : tipo === 'ok'
                ? 'is-ok'
                : 'is-warning'
    );
    elementos.notice.textContent = mensagem;
}


function ocultarAvisoFormulario() {
    if (!elementos.notice) return;

    elementos.notice.hidden = true;
    elementos.notice.classList.remove('is-warning', 'is-error', 'is-ok');
    elementos.notice.textContent = '';
}


function definirBotaoSalvando(ativo) {
    const botao = elementos.saveButton;
    if (!botao) return;

    if (ativo) {
        if (!botao.dataset.originalText) {
            botao.dataset.originalText = botao.textContent;
        }

        botao.disabled = true;
        botao.classList.add('is-loading');
        botao.textContent = 'Salvando...';
        return;
    }

    botao.classList.remove('is-loading');

    if (botao.dataset.originalText) {
        botao.textContent = botao.dataset.originalText;
        delete botao.dataset.originalText;
    }

    botao.disabled = Boolean(safeApply.ocupado?.());
}


/* ==========================================================================
   APLICAR
========================================================================== */

async function aplicarInterface(id) {
    if (aplicandoId !== null || safeApply.ocupado?.()) {
        notificarBloqueio();
        return false;
    }

    const interfaceRede = obterInterface(id);

    if (!interfaceRede) {
        notificacao.erro(
            'Interface não encontrada',
            'Não foi possível localizar a interface selecionada.'
        );
        return false;
    }

    if (!interfacePodeAplicar(interfaceRede)) {
        notificacao.info?.(
            'Interface sincronizada',
            'Não existem alterações pendentes para aplicar nesta interface.'
        );
        return false;
    }

    const confirmado = await safeApply.confirmarOperacao({
        titulo: 'Aplicar configuração da interface?',
        mensagem: `A configuração de ${obterNome(interfaceRede)} será enviada ao MoonShield Agent.`,
        detalhes: 'Um snapshot será criado e o rollback automático permanecerá armado até a confirmação.',
        textoConfirmar: 'Aplicar configuração',
        perigoso: obterPapel(interfaceRede) === 'WAN',
    });

    if (!confirmado) return false;

    if (!safeApply.reservarOperacao?.(`interface:${id}`)) {
        notificarBloqueio();
        return false;
    }

    aplicandoId = id;
    atualizarEstadoControles();

    safeApply.mostrarOperacao({
        titulo: `Aplicando ${obterNome(interfaceRede)}`,
        descricao: 'Validando a interface, preparando snapshot e armando o rollback.',
    });

    try {
        const resposta = await api.post(urlAplicarInterface(id), {});
        const alteracao = extrairAlteracao(resposta);

        if (!alteracao) {
            throw new Error('A API não retornou a alteração criada.');
        }

        estado.set('alteracoes.ativa', alteracao);

        safeApply.ocultarOperacao();
        safeApply.sincronizar?.(alteracao);

        if (String(alteracao.status || '') === 'waiting_confirmation') {
            safeApply.abrir?.(alteracao);

            notificacao.aviso(
                'Confirmação necessária',
                'A configuração foi aplicada. Confirme que o acesso continua funcionando.'
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

        notificacao.erro(
            erro.titulo || 'Falha ao aplicar interface',
            erro.mensagem || 'Não foi possível aplicar a configuração da interface.'
        );

        return false;
    } finally {
        aplicandoId = null;
        atualizarEstadoControles();
    }
}


/* ==========================================================================
   ESTADO DOS CONTROLES
========================================================================== */

function atualizarEstadoControles() {
    const bloqueado = Boolean(safeApply.ocupado?.());

    if (elementos.saveButton) {
        elementos.saveButton.disabled = bloqueado || salvando;
        elementos.saveButton.setAttribute(
            'aria-disabled',
            elementos.saveButton.disabled ? 'true' : 'false'
        );
    }

    [
        elementos.description,
        elementos.role,
        elementos.primary,
        elementos.enabled,
        elementos.management,
        elementos.ipv4Mode,
        elementos.ipv4Address,
        elementos.ipv4Prefix,
        elementos.gateway,
        elementos.defaultRoute,
        elementos.metric,
        elementos.mtu,
    ].forEach(campo => {
        if (!campo) return;
        campo.disabled = bloqueado || salvando;
    });

    if (elementos.container) {
        $$('[data-interface-card]', elementos.container).forEach(card => {
            const id = card.dataset.interfaceId;
            const interfaceRede = obterInterface(id);

            if (interfaceRede) atualizarAcoesCard(card, interfaceRede);
        });
    }
}


function notificarBloqueio(alteracao = safeApply.obterAlteracaoAtiva?.()) {
    notificacao.aviso(
        'Alteração em andamento',
        alteracao?.titulo
            ? `${alteracao.titulo}. Confirme ou reverta antes de iniciar outra alteração.`
            : 'Confirme ou reverta a alteração atual antes de iniciar outra.'
    );
}


/* ==========================================================================
   URLs / EXTRAÇÃO
========================================================================== */

function urlBaseInterfaces() {
    const base = api.urls.interfaces;

    if (!base) throw new Error('URL de interfaces não configurada.');

    return base.endsWith('/') ? base : `${base}/`;
}


function urlInterface(id) {
    return `${urlBaseInterfaces()}${encodeURIComponent(String(id))}/`;
}


function urlConfigurarInterface(id) {
    if (typeof api.urls.configurarInterface === 'function') {
        return api.urls.configurarInterface(id);
    }

    if (typeof api.urls.interfaceConfigurar === 'function') {
        return api.urls.interfaceConfigurar(id);
    }

    return `${urlInterface(id)}configurar/`;
}


function urlAplicarInterface(id) {
    if (typeof api.urls.aplicarInterface === 'function') {
        return api.urls.aplicarInterface(id);
    }

    if (typeof api.urls.interfaceAplicar === 'function') {
        return api.urls.interfaceAplicar(id);
    }

    return `${urlInterface(id)}aplicar/`;
}


function extrairInterfaces(dados) {
    if (Array.isArray(dados)) return dados;
    if (Array.isArray(dados?.interfaces)) return dados.interfaces;
    if (Array.isArray(dados?.resultados)) return dados.resultados;
    if (Array.isArray(dados?.lista)) return dados.lista;

    return [];
}


function extrairAlteracao(resposta) {
    return (
        resposta?.dados?.alteracao ||
        resposta?.dados?.ativa ||
        resposta?.dados?.resultado?.alteracao ||
        resposta?.alteracao ||
        null
    );
}


/* ==========================================================================
   DADOS DE INTERFACE
========================================================================== */

function substituirInterface(interfaceRede) {
    estado.update('interfaces.lista', lista => {
        const novaLista = [...(lista || [])];
        const id = obterId(interfaceRede);

        const indice = novaLista.findIndex(
            item => String(obterId(item)) === String(id)
        );

        if (indice >= 0) novaLista[indice] = interfaceRede;
        else novaLista.push(interfaceRede);

        return novaLista;
    });
}


function obterInterface(id) {
    return estado
        .get('interfaces.lista', [])
        .find(item => String(obterId(item)) === String(id)) || null;
}


function obterId(interfaceRede) {
    return (
        interfaceRede?.id ??
        interfaceRede?.interface_id ??
        interfaceRede?.pk ??
        interfaceRede?.nome ??
        interfaceRede?.name ??
        interfaceRede?.interface ??
        null
    );
}


function obterIdElemento(elemento) {
    const card = elemento.closest('[data-interface-card]');

    return (
        elemento.dataset.interfaceId ||
        card?.dataset.interfaceId ||
        null
    );
}


function obterNome(interfaceRede) {
    return (
        interfaceRede?.nome ||
        interfaceRede?.name ||
        interfaceRede?.interface ||
        interfaceRede?.dispositivo ||
        interfaceRede?.device ||
        'Interface'
    );
}


function obterPapel(interfaceRede) {
    return String(
        obterDesejado(
            interfaceRede,
            'papel',
            interfaceRede?.role ||
            interfaceRede?.tipo ||
            'unassigned'
        )
    ).toUpperCase();
}


function obterReal(interfaceRede, campo, fallback = null) {
    const fontes = [
        interfaceRede?.real,
        interfaceRede?.estado_real,
        interfaceRede?.runtime,
        interfaceRede?.current,
        interfaceRede,
    ];

    for (const fonte of fontes) {
        if (
            fonte &&
            fonte[campo] !== undefined &&
            fonte[campo] !== null
        ) {
            return fonte[campo];
        }
    }

    return fallback;
}


function obterEstado(interfaceRede) {
    const estadoLink = String(
        obterReal(
            interfaceRede,
            'estado_link',
            interfaceRede?.estado ||
            interfaceRede?.state ||
            interfaceRede?.operstate ||
            ''
        )
    ).toLowerCase();

    const carrier = obterReal(interfaceRede, 'carrier', null);

    if (estadoLink && estadoLink !== 'unknown') return estadoLink.toUpperCase();
    if (carrier === true) return 'UP';
    if (carrier === false) return 'DOWN';

    return 'UNKNOWN';
}


function interfaceAtiva(interfaceRede) {
    const carrier = obterReal(interfaceRede, 'carrier', null);

    if (carrier === true) return true;
    if (carrier === false) return false;

    const estadoRede = String(
        obterReal(
            interfaceRede,
            'estado_link',
            interfaceRede?.estado ||
            interfaceRede?.state ||
            interfaceRede?.operstate ||
            ''
        )
    ).toLowerCase();

    return [
        'up',
        'connected',
        'ativo',
        'ativa',
        'online',
    ].includes(estadoRede);
}


function interfaceConfigurada(interfaceRede) {
    return String(
        obterDesejado(interfaceRede, 'papel', 'unassigned') || 'unassigned'
    ).toLowerCase() !== 'unassigned';
}


function interfacePendente(interfaceRede) {
    const estado = obterEstadoSincronizacao(interfaceRede, { fallback: false });

    if (estado) {
        return [
            'pending_apply',
            'applying',
            'waiting_confirmation',
        ].includes(estado);
    }

    if (interfaceRede?.pendente !== undefined) {
        return paraBooleano(interfaceRede.pendente, false);
    }

    if (interfaceRede?.sincronizada !== undefined) {
        return !paraBooleano(interfaceRede.sincronizada, false);
    }

    return false;
}


function interfacePodeAplicar(interfaceRede) {
    const estado = obterEstadoSincronizacao(interfaceRede, { fallback: false });

    if (estado) return ['pending_apply', 'drifted'].includes(estado);
    return interfacePendente(interfaceRede);
}


function obterIPv4Desejado(interfaceRede) {
    const modo = String(
        obterDesejado(interfaceRede, 'ipv4_modo', 'dhcp') || 'dhcp'
    ).toLowerCase();

    if (modo === 'disabled') return 'Desativado';
    if (modo === 'dhcp') return 'DHCP';

    const endereco = obterDesejado(interfaceRede, 'ipv4_endereco', null);
    const prefixo = obterDesejado(interfaceRede, 'ipv4_prefixo', null);

    if (!endereco) return 'Estático —';

    return (
        prefixo === null ||
        prefixo === undefined ||
        prefixo === ''
    )
        ? String(endereco)
        : `${endereco}/${prefixo}`;
}


function obterIPv4(interfaceRede) {
    return obterIPv4sObservados(interfaceRede).split(' · ')[0] || '—';
}


function obterIPv4sObservados(interfaceRede) {
    const enderecos = obterReal(interfaceRede, 'enderecos_ipv4', null);
    const lista = Array.isArray(enderecos)
        ? enderecos
        : interfaceRede?.enderecos || interfaceRede?.addresses || [];
    const ipv4s = lista
        .map(endereco => {
            if (typeof endereco === 'string') return endereco;
            return endereco?.endereco || endereco?.address || '';
        })
        .filter(endereco => endereco && !endereco.includes(':'));

    if (ipv4s.length) return [...new Set(ipv4s)].join(' · ');

    const direto = obterReal(
        interfaceRede,
        'ipv4',
        interfaceRede?.ipv4_atual ||
        interfaceRede?.ip ||
        interfaceRede?.endereco_ipv4 ||
        interfaceRede?.address ||
        null
    );

    const prefixo = obterReal(
        interfaceRede,
        'prefixo',
        interfaceRede?.prefixo_atual ?? null
    );

    if (typeof direto === 'string' && direto) {
        if (direto.includes('/') || prefixo === null || prefixo === undefined || prefixo === '') {
            return direto;
        }

        return `${direto}/${prefixo}`;
    }

    return '—';
}


function obterMac(interfaceRede) {
    return (
        interfaceRede?.mac ||
        interfaceRede?.mac_address ||
        interfaceRede?.endereco_mac ||
        '—'
    );
}


function obterGateway(interfaceRede) {
    return (
        obterDesejado(interfaceRede, 'gateway', null) ||
        obterReal(
            interfaceRede,
            'gateway',
            interfaceRede?.gateway_atual ||
            interfaceRede?.gateway_ipv4 ||
            null
        ) ||
        '—'
    );
}


function obterMtu(interfaceRede) {
    return (
        obterDesejado(interfaceRede, 'mtu', null) ??
        obterReal(
            interfaceRede,
            'mtu',
            interfaceRede?.mtu_atual ?? null
        ) ??
        '—'
    );
}


function obterBackend(interfaceRede) {
    return (
        obterReal(interfaceRede, 'backend', interfaceRede?.backend || null) ||
        estado.get('interfaces.backend') ||
        'NetworkManager'
    );
}


function obterGerenciamento(interfaceRede) {
    return paraBooleano(
        obterDesejado(interfaceRede, 'acesso_gerenciamento', false),
        false
    )
        ? 'Permitido'
        : 'Bloqueado';
}


function obterRevisoes(interfaceRede) {
    const desejada = interfaceRede?.revisao_desejada;
    const aplicada = interfaceRede?.revisao_aplicada;

    if (desejada === undefined && aplicada === undefined) return '—';
    return `${aplicada ?? '—'} aplicada / ${desejada ?? '—'} desejada`;
}


/* ==========================================================================
   STATUS DO CARD
========================================================================== */

const ESTADOS_SINCRONIZACAO = {
    unmanaged: { texto: 'Não gerenciada', classe: 'np-status-dot--warning' },
    synced: { texto: 'Sincronizada', classe: 'np-status-dot--ok' },
    pending_apply: { texto: 'Pendente de aplicação', classe: 'np-status-dot--pending' },
    applying: { texto: 'Aplicando', classe: 'np-status-dot--pending' },
    waiting_confirmation: { texto: 'Aguardando confirmação', classe: 'np-status-dot--warning' },
    drifted: { texto: 'Divergente', classe: 'np-status-dot--warning' },
    missing: { texto: 'Interface ausente', classe: 'np-status-dot--error' },
    error: { texto: 'Erro', classe: 'np-status-dot--error' },
};


function obterEstadoSincronizacao(interfaceRede, opcoes = {}) {
    const { fallback = true } = opcoes;
    const estado = String(interfaceRede?.estado_sincronizacao || '').toLowerCase();

    if (ESTADOS_SINCRONIZACAO[estado]) return estado;
    if (!fallback) return '';
    if (!interfaceConfigurada(interfaceRede)) return 'unmanaged';
    if (interfaceRede?.sincronizada !== undefined && paraBooleano(interfaceRede.sincronizada, false)) {
        return 'synced';
    }
    if (interfaceRede?.pendente !== undefined && paraBooleano(interfaceRede.pendente, false)) {
        return 'pending_apply';
    }

    return 'pending_apply';
}


function atualizarLinkCard(card, interfaceRede) {
    const pill = $('[data-interface-link]', card);
    if (!pill) return;

    const estadoLink = obterEstado(interfaceRede);
    const ativa = interfaceAtiva(interfaceRede);

    pill.classList.remove(
        'np-status-pill--ok',
        'np-status-pill--warning',
        'np-status-pill--error',
        'np-status-pill--pending'
    );

    if (ativa) {
        pill.classList.add('np-status-pill--ok');
        setText(pill, 'Link ativo');
    } else if (estadoLink === 'DOWN') {
        pill.classList.add('np-status-pill--error');
        setText(pill, 'Link down');
    } else {
        pill.classList.add('np-status-pill--pending');
        setText(pill, 'Link —');
    }
}


function atualizarSincronizacaoCard(card, interfaceRede) {
    const texto = $('[data-interface-sync]', card);
    const dot = $('[data-interface-sync-dot]', card);

    const erro = String(interfaceRede?.ultimo_erro || '').trim();
    const estado = obterEstadoSincronizacao(interfaceRede);
    const configuracao = ESTADOS_SINCRONIZACAO[estado];

    if (dot) {
        dot.classList.remove(
            'np-status-dot--ok',
            'np-status-dot--warning',
            'np-status-dot--error',
            'np-status-dot--pending'
        );
    }

    setText(texto, configuracao?.texto || 'Estado desconhecido');
    dot?.classList.add(configuracao?.classe || 'np-status-dot--pending');

    if (erro && estado !== 'error') texto?.setAttribute('title', erro);
    else texto?.removeAttribute('title');
}


/* ==========================================================================
   HELPERS FORMULÁRIO
========================================================================== */

function obterDesejado(interfaceRede, campo, fallback = null) {
    const fontes = [
        interfaceRede?.desejado,
        interfaceRede?.estado_desejado,
        interfaceRede?.configuracao,
        interfaceRede?.desired,
        interfaceRede,
    ];

    for (const fonte of fontes) {
        if (
            fonte &&
            fonte[campo] !== undefined &&
            fonte[campo] !== null
        ) {
            return fonte[campo];
        }
    }

    return fallback;
}


function definirValor(elemento, valor) {
    if (elemento) elemento.value = valor ?? '';
}


function definirMarcado(elemento, valor) {
    if (elemento) elemento.checked = Boolean(valor);
}


function marcado(elemento) {
    return Boolean(elemento?.checked);
}


function valorTrim(elemento) {
    return String(elemento?.value || '').trim();
}


function valorNumero(elemento, fallback = 0) {
    const valor = Number(elemento?.value);

    return Number.isFinite(valor)
        ? valor
        : fallback;
}


function paraBooleano(valor, fallback = false) {
    if (
        valor === undefined ||
        valor === null ||
        valor === ''
    ) {
        return fallback;
    }

    if (typeof valor === 'boolean') return valor;
    if (typeof valor === 'number') return valor !== 0;

    return [
        '1',
        'true',
        'yes',
        'sim',
        'on',
        'enabled',
        'ativo',
        'ativa',
    ].includes(String(valor).trim().toLowerCase());
}


function ipv4Valido(valor) {
    const partes = String(valor || '').trim().split('.');

    if (partes.length !== 4) return false;

    return partes.every(
        parte =>
            /^\d{1,3}$/.test(parte) &&
            Number(parte) >= 0 &&
            Number(parte) <= 255
    );
}


/* ==========================================================================
   DESTRUIR / EXPORT
========================================================================== */

function destruir() {
    elementos.container?.removeEventListener('click', tratarCliqueContainer);
    elementos.form?.removeEventListener('submit', salvarConfiguracaoInterface);
    elementos.refreshButton?.removeEventListener('click', atualizarInterfaces);
    elementos.role?.removeEventListener('change', atualizarCamposFormulario);
    elementos.ipv4Mode?.removeEventListener('change', atualizarCamposFormulario);

    inicializado = false;
    carregando = false;
    salvando = false;
    aplicandoId = null;
    carregamentoAtual = null;
    sequenciaSolicitada = 0;
}


export const interfaces = Object.freeze({
    inicializar,
    destruir,
    carregar,
    renderizar,
    sincronizar,
    aoAtivar,
    atualizarInterfaces,
    aplicarInterface,
    editarInterface,
});

export default interfaces;
