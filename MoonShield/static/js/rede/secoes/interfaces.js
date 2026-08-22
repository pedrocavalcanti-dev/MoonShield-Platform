/**
 * MoonShield Network Panel
 * Seção: Interfaces
 */

'use strict';

import { api } from '../nucleo/api.js';
import { estado } from '../nucleo/estado.js';
import { $, $$, setText, setHidden, criar } from '../nucleo/dom.js';
import { normalizarErro } from '../nucleo/utilitarios.js';
import { notificacao } from '../componentes/notificacoes.js';
import { safeApply } from '../componentes/safe_apply.js';

let inicializado = false;
let carregando = false;


/* ==========================================================================
   ELEMENTOS
========================================================================== */

const elementos = {
    container: null,
    empty: null,
    backend: null,
    total: null,
    detectButton: null,
};


/* ==========================================================================
   INICIALIZAÇÃO
========================================================================== */

function inicializar() {
    if (inicializado) return;

    inicializado = true;

    cachearElementos();
    registrarEventos();
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

    elementos.detectButton =
        $('#interfacesDetectButton');
}


function registrarEventos() {
    /*
     * O botão global de detecção já é controlado pelo painel.js.
     * Aqui registramos somente eventos pertencentes aos cards da seção.
     */

    elementos.container?.addEventListener(
        'click',
        tratarCliqueContainer
    );
}


/* ==========================================================================
   CARREGAR
========================================================================== */

async function carregar(opcoes = {}) {
    if (carregando) {
        return estado.get('interfaces.lista', []);
    }

    carregando = true;

    try {
        const resposta = await api.get(
            api.urls.interfaces
        );

        const dados = resposta?.dados ?? resposta ?? {};

        const lista = extrairInterfaces(dados);

        estado.set(
            'interfaces.lista',
            lista
        );

        estado.set(
            'interfaces.backend',
            dados.backend ||
            dados.gerenciador ||
            dados.network_backend ||
            estado.get('interfaces.backend') ||
            null
        );

        estado.set(
            'interfaces.carregado',
            true
        );

        renderizar();

        return lista;

    } catch (error) {
        estado.set(
            'interfaces.carregado',
            false
        );

        if (!opcoes.silencioso) {
            const erro = normalizarErro(error);

            notificacao.erro(
                erro.titulo || 'Erro nas interfaces',
                erro.mensagem ||
                'Não foi possível carregar as interfaces de rede.'
            );
        }

        throw error;

    } finally {
        carregando = false;
    }
}


/* ==========================================================================
   ATIVAÇÃO
========================================================================== */

async function aoAtivar() {
    if (
        estado.get(
            'interfaces.carregado'
        )
    ) {
        renderizar();
        return;
    }

    try {
        await carregar({
            silencioso: true,
        });
    } catch {
        /*
         * O painel continua utilizável mesmo se o Agent
         * estiver offline durante o desenvolvimento.
         */
    }
}


/* ==========================================================================
   RENDER
========================================================================== */

function renderizar() {
    const lista = estado.get(
        'interfaces.lista',
        []
    );

    const backend =
        estado.get(
            'interfaces.backend'
        ) ||
        estado.get(
            'status.agent.status.backend'
        ) ||
        'NetworkManager';

    setText(
        elementos.backend,
        backend
    );

    setText(
        elementos.total,
        lista.length
    );

    setHidden(
        elementos.empty,
        lista.length > 0
    );

    if (!elementos.container) {
        return;
    }

    removerCardsRenderizados();

    lista.forEach(interfaceRede => {
        const card = criarCardInterface(
            interfaceRede
        );

        if (card) {
            elementos.container.appendChild(
                card
            );
        }
    });
}


function sincronizar() {
    renderizar();
}


/* ==========================================================================
   CARD
========================================================================== */

function criarCardInterface(interfaceRede) {
    const template =
        $('#interfaceCardTemplate') ||
        $('[data-interface-template]');

    if (template instanceof HTMLTemplateElement) {
        const fragmento =
            template.content.cloneNode(true);

        const card =
            fragmento.querySelector(
                '[data-interface-card]'
            ) ||
            fragmento.firstElementChild;

        if (!card) return null;

        preencherCard(
            card,
            interfaceRede
        );

        return card;
    }

    /*
     * Fallback para o caso de o HTML não possuir template.
     * Evita que o módulo deixe de funcionar por completo.
     */

    const card = criar('article', {
        className: 'np-interface-card',
        attrs: {
            'data-interface-card': '',
            'data-interface-rendered': 'true',
            'data-interface-id': String(
                obterId(interfaceRede) ?? ''
            ),
        },
    });

    const cabecalho = criar('div', {
        className: 'np-interface-card__header',
    });

    const titulo = criar('div', {
        className: 'np-interface-card__title',
    });

    const nome = criar('strong', {
        text: obterNome(interfaceRede),
    });

    const papel = criar('span', {
        className: 'np-status-pill',
        text: obterPapel(interfaceRede),
    });

    titulo.append(
        nome,
        papel
    );

    const corpo = criar('div', {
        className: 'np-interface-card__body',
    });

    corpo.append(
        criarLinha(
            'Estado',
            obterEstado(interfaceRede)
        ),
        criarLinha(
            'IPv4',
            obterIPv4(interfaceRede)
        ),
        criarLinha(
            'MAC',
            obterMac(interfaceRede)
        ),
        criarLinha(
            'Gateway',
            obterGateway(interfaceRede)
        )
    );

    cabecalho.appendChild(
        titulo
    );

    card.append(
        cabecalho,
        corpo
    );

    return card;
}


function preencherCard(card, interfaceRede) {
    card.dataset.interfaceCard = '';
    card.dataset.interfaceRendered = 'true';

    const id = obterId(interfaceRede);

    if (id !== null && id !== undefined) {
        card.dataset.interfaceId =
            String(id);
    }

    setText(
        $('[data-interface-name]', card),
        obterNome(interfaceRede)
    );

    setText(
        $('[data-interface-role]', card),
        obterPapel(interfaceRede)
    );

    setText(
        $('[data-interface-state]', card),
        obterEstado(interfaceRede)
    );

    setText(
        $('[data-interface-ipv4]', card),
        obterIPv4(interfaceRede)
    );

    setText(
        $('[data-interface-mac]', card),
        obterMac(interfaceRede)
    );

    setText(
        $('[data-interface-gateway]', card),
        obterGateway(interfaceRede)
    );

    setText(
        $('[data-interface-backend]', card),
        interfaceRede.backend ||
        estado.get('interfaces.backend') ||
        'NetworkManager'
    );

    const editar =
        $('[data-interface-edit]', card);

    const aplicar =
        $('[data-interface-apply]', card);

    if (editar && id !== null) {
        editar.dataset.interfaceId =
            String(id);
    }

    if (aplicar && id !== null) {
        aplicar.dataset.interfaceId =
            String(id);
    }

    card.classList.toggle(
        'is-up',
        interfaceAtiva(interfaceRede)
    );

    card.classList.toggle(
        'is-down',
        !interfaceAtiva(interfaceRede)
    );
}


function criarLinha(rotulo, valor) {
    const linha = criar('div', {
        className: 'np-interface-card__row',
    });

    linha.append(
        criar('span', {
            text: rotulo,
        }),
        criar('strong', {
            text: valor || '—',
        })
    );

    return linha;
}


function removerCardsRenderizados() {
    $$(
        '[data-interface-rendered]',
        elementos.container
    ).forEach(card => {
        card.remove();
    });
}


/* ==========================================================================
   EVENTOS DOS CARDS
========================================================================== */

function tratarCliqueContainer(event) {
    const alvo =
        event.target instanceof Element
            ? event.target
            : null;

    if (!alvo) return;

    const editar =
        alvo.closest(
            '[data-interface-edit]'
        );

    if (editar) {
        const id = obterIdElemento(
            editar
        );

        if (id !== null) {
            editarInterface(id);
        }

        return;
    }

    const aplicar =
        alvo.closest(
            '[data-interface-apply]'
        );

    if (aplicar) {
        const id = obterIdElemento(
            aplicar
        );

        if (id !== null) {
            aplicarInterface(id);
        }
    }
}


/* ==========================================================================
   EDITAR
========================================================================== */

async function editarInterface(id) {
    const interfaceRede =
        obterInterface(id);

    if (!interfaceRede) {
        notificacao.erro(
            'Interface não encontrada',
            'Não foi possível localizar a interface selecionada.'
        );

        return;
    }

    /*
     * A edição completa depende do drawer/form presente no HTML.
     * Se o painel possuir o botão configurado, emitimos um evento
     * para permitir que o componente específico abra o formulário.
     */

    document.dispatchEvent(
        new CustomEvent(
            'moonshield:interface-edit',
            {
                detail: {
                    interface: interfaceRede,
                },
            }
        )
    );
}


/* ==========================================================================
   APLICAR INTERFACE
========================================================================== */

async function aplicarInterface(id) {
    if (safeApply.ativo()) {
        notificacao.aviso(
            'Alteração em andamento',
            'Confirme ou reverta a alteração atual antes de aplicar outra.'
        );

        return false;
    }

    const interfaceRede =
        obterInterface(id);

    if (!interfaceRede) {
        notificacao.erro(
            'Interface não encontrada',
            'Não foi possível localizar a interface selecionada.'
        );

        return false;
    }

    const confirmado =
        await safeApply.confirmarOperacao({
            titulo: 'Aplicar configuração da interface?',
            mensagem:
                `A configuração de ${obterNome(interfaceRede)} será enviada ao MoonShield Agent.`,
            detalhes:
                'Um snapshot será criado e o rollback automático permanecerá armado até a confirmação.',
            textoConfirmar:
                'Aplicar configuração',
            perigoso: obterPapel(interfaceRede) === 'WAN',
        });

    if (!confirmado) {
        return false;
    }

    safeApply.mostrarOperacao({
        titulo:
            `Aplicando ${obterNome(interfaceRede)}`,
        descricao:
            'Validando a interface e preparando a alteração segura.',
    });

    try {
        const resposta =
            await api.post(
                urlAplicarInterface(id),
                {}
            );

        const alteracao =
            extrairAlteracao(
                resposta
            );

        safeApply.ocultarOperacao();

        if (!alteracao) {
            throw new Error(
                'A API não retornou a alteração criada.'
            );
        }

        estado.set(
            'alteracoes.ativa',
            alteracao
        );

        safeApply.abrir(
            alteracao
        );

        await carregar({
            silencioso: true,
        });

        notificacao.aviso(
            'Confirmação necessária',
            'A configuração foi aplicada. Confirme que o acesso continua funcionando.'
        );

        return true;

    } catch (error) {
        safeApply.ocultarOperacao();

        const erro =
            normalizarErro(error);

        notificacao.erro(
            erro.titulo ||
            'Falha ao aplicar interface',
            erro.mensagem ||
            'Não foi possível aplicar a configuração da interface.'
        );

        return false;
    }
}


/* ==========================================================================
   URL
========================================================================== */

function urlBaseInterfaces() {
    const base =
        api.urls.interfaces;

    if (!base) {
        throw new Error(
            'URL de interfaces não configurada.'
        );
    }

    return base.endsWith('/')
        ? base
        : `${base}/`;
}


function urlInterface(id) {
    return (
        `${urlBaseInterfaces()}${encodeURIComponent(
            String(id)
        )}/`
    );
}


function urlAplicarInterface(id) {
    /*
     * Mantém compatibilidade tanto com um endpoint
     * dedicado definido em api.urls quanto com a
     * rota REST da interface.
     */

    if (
        typeof api.urls.aplicarInterface ===
        'function'
    ) {
        return api.urls.aplicarInterface(id);
    }

    return `${urlInterface(id)}aplicar/`;
}


/* ==========================================================================
   DADOS
========================================================================== */

function extrairInterfaces(dados) {
    if (Array.isArray(dados)) {
        return dados;
    }

    if (
        Array.isArray(
            dados.interfaces
        )
    ) {
        return dados.interfaces;
    }

    if (
        Array.isArray(
            dados.resultados
        )
    ) {
        return dados.resultados;
    }

    if (
        Array.isArray(
            dados.lista
        )
    ) {
        return dados.lista;
    }

    return [];
}


function extrairAlteracao(resposta) {
    if (!resposta) {
        return null;
    }

    return (
        resposta.dados?.alteracao ||
        resposta.dados?.resultado?.alteracao ||
        resposta.alteracao ||
        null
    );
}


function obterInterface(id) {
    return estado
        .get(
            'interfaces.lista',
            []
        )
        .find(item => {
            return String(
                obterId(item)
            ) === String(id);
        }) || null;
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
    const card =
        elemento.closest(
            '[data-interface-card]'
        );

    const valor =
        elemento.dataset.interfaceId ||
        card?.dataset.interfaceId;

    return valor || null;
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
        interfaceRede?.papel ||
        interfaceRede?.role ||
        interfaceRede?.tipo ||
        'CUSTOM'
    ).toUpperCase();
}


function obterEstado(interfaceRede) {
    if (
        interfaceRede?.estado
    ) {
        return String(
            interfaceRede.estado
        ).toUpperCase();
    }

    if (
        interfaceRede?.state
    ) {
        return String(
            interfaceRede.state
        ).toUpperCase();
    }

    if (
        interfaceRede?.operstate
    ) {
        return String(
            interfaceRede.operstate
        ).toUpperCase();
    }

    return interfaceAtiva(
        interfaceRede
    )
        ? 'UP'
        : 'DOWN';
}


function interfaceAtiva(interfaceRede) {
    const valor =
        interfaceRede?.ativa ??
        interfaceRede?.active ??
        interfaceRede?.up ??
        interfaceRede?.conectada;

    if (
        valor !== undefined &&
        valor !== null
    ) {
        return Boolean(valor);
    }

    const estadoRede =
        String(
            interfaceRede?.estado ||
            interfaceRede?.state ||
            interfaceRede?.operstate ||
            ''
        ).toLowerCase();

    return [
        'up',
        'connected',
        'ativo',
        'ativa',
        'online',
    ].includes(
        estadoRede
    );
}


function obterIPv4(interfaceRede) {
    const direto =
        interfaceRede?.ipv4 ||
        interfaceRede?.ip ||
        interfaceRede?.endereco_ipv4 ||
        interfaceRede?.address;

    if (
        typeof direto ===
        'string'
    ) {
        return direto || '—';
    }

    const lista =
        interfaceRede?.enderecos ||
        interfaceRede?.addresses;

    if (
        Array.isArray(lista)
    ) {
        const ipv4 =
            lista.find(item => {
                const valor =
                    typeof item === 'string'
                        ? item
                        : item?.endereco ||
                        item?.address ||
                        '';

                return (
                    valor &&
                    !valor.includes(':')
                );
            });

        if (
            typeof ipv4 ===
            'string'
        ) {
            return ipv4;
        }

        return (
            ipv4?.endereco ||
            ipv4?.address ||
            '—'
        );
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
        interfaceRede?.gateway ||
        interfaceRede?.gateway_ipv4 ||
        interfaceRede?.rota_padrao?.gateway ||
        '—'
    );
}


/* ==========================================================================
   DESTRUIR
========================================================================== */

function destruir() {
    inicializado = false;
    carregando = false;
}


/* ==========================================================================
   EXPORT
========================================================================== */

export const interfaces = Object.freeze({
    inicializar,
    destruir,
    carregar,
    renderizar,
    sincronizar,
    aoAtivar,
    aplicarInterface,
    editarInterface,
});

export default interfaces;