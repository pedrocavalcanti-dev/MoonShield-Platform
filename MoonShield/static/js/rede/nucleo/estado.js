/**
 * MoonShield Network Panel
 * Estado global
 *
 * Armazena o estado compartilhado entre painel, componentes e seções.
 */

'use strict';

const STORAGE_KEY = 'moonshield_network_ui';

const estadoInicial = {
    status: {},
    agent: {
        online: false,
        status: {},
        erro: null,
    },
    interfaces: {
        lista: [],
        backend: null,
        carregado: false,
        ultimaDeteccao: null,
    },
    roteamento: {
        configuracao: null,
        rotas: [],
        real: null,
        carregado: false,
    },
    nat: {
        regras: [],
        real: null,
        carregado: false,
    },
    diagnostico: {
        resultado: null,
        executando: false,
        ultimaExecucao: null,
    },
    alteracoes: {
        lista: [],
        ativa: null,
        filtros: {
            status: '',
            tipo: '',
        },
        carregado: false,
    },
    ui: {
        secaoAtual: 'visao-geral',
        ultimaAtualizacao: null,
    },
};


/* ==========================================================================
   HELPERS
========================================================================== */

function clonar(valor) {
    if (valor === undefined) return undefined;
    if (valor === null) return null;

    if (typeof structuredClone === 'function') {
        try {
            return structuredClone(valor);
        } catch {
            // fallback abaixo
        }
    }

    try {
        return JSON.parse(JSON.stringify(valor));
    } catch {
        return valor;
    }
}


function partesDoCaminho(caminho) {
    if (Array.isArray(caminho)) return caminho.filter(Boolean);
    if (typeof caminho !== 'string') return [];
    return caminho.split('.').map(item => item.trim()).filter(Boolean);
}


function obterNo(objeto, caminho) {
    const partes = partesDoCaminho(caminho);
    if (!partes.length) return objeto;

    return partes.reduce((atual, chave) => {
        if (atual === undefined || atual === null) return undefined;
        return atual[chave];
    }, objeto);
}


function definirNo(objeto, caminho, valor) {
    const partes = partesDoCaminho(caminho);
    if (!partes.length) return false;

    let atual = objeto;

    for (let i = 0; i < partes.length - 1; i++) {
        const chave = partes[i];

        if (!atual[chave] || typeof atual[chave] !== 'object' || Array.isArray(atual[chave])) {
            atual[chave] = {};
        }

        atual = atual[chave];
    }

    atual[partes.at(-1)] = valor;
    return true;
}


function removerNo(objeto, caminho) {
    const partes = partesDoCaminho(caminho);
    if (!partes.length) return false;

    let atual = objeto;

    for (let i = 0; i < partes.length - 1; i++) {
        atual = atual?.[partes[i]];
        if (!atual || typeof atual !== 'object') return false;
    }

    const chave = partes.at(-1);
    if (!Object.prototype.hasOwnProperty.call(atual, chave)) return false;

    delete atual[chave];
    return true;
}


function mesclarObjetos(destino, origem) {
    if (!origem || typeof origem !== 'object' || Array.isArray(origem)) return destino;

    Object.entries(origem).forEach(([chave, valor]) => {
        if (valor && typeof valor === 'object' && !Array.isArray(valor)) {
            if (!destino[chave] || typeof destino[chave] !== 'object' || Array.isArray(destino[chave])) destino[chave] = {};
            mesclarObjetos(destino[chave], valor);
            return;
        }

        destino[chave] = clonar(valor);
    });

    return destino;
}


/* ==========================================================================
   STORE
========================================================================== */

class NetworkState {
    constructor(inicial = {}) {
        this._dados = clonar(inicial);
        this._listeners = new Map();
        this._carregarUiPersistida();
    }


    /* ======================================================================
       GET
    ====================================================================== */

    get(caminho = null, fallback = undefined) {
        if (!caminho) return this._dados;

        const valor = obterNo(this._dados, caminho);
        return valor === undefined ? fallback : valor;
    }


    has(caminho) {
        return obterNo(this._dados, caminho) !== undefined;
    }


    snapshot(caminho = null) {
        return clonar(caminho ? this.get(caminho) : this._dados);
    }


    /* ======================================================================
       SET
    ====================================================================== */

    set(caminho, valor, opcoes = {}) {
        const { notificar = true, persistir = true } = opcoes;
        if (!caminho) return false;

        const anterior = this.get(caminho);
        definirNo(this._dados, caminho, valor);

        if (persistir) this._persistirSeNecessario(caminho);
        if (notificar) this._emitir(caminho, valor, anterior);

        return true;
    }


    /* ======================================================================
       UPDATE
    ====================================================================== */

    update(caminho, atualizador, opcoes = {}) {
        if (typeof atualizador !== 'function') return false;

        const atual = this.get(caminho);
        const novoValor = atualizador(atual);

        return this.set(caminho, novoValor, opcoes);
    }


    /* ======================================================================
       MERGE
    ====================================================================== */

    merge(caminho, dados, opcoes = {}) {
        if (!dados || typeof dados !== 'object' || Array.isArray(dados)) return false;

        const atual = this.get(caminho, {});
        const novoValor = mesclarObjetos(clonar(atual) || {}, dados);

        return this.set(caminho, novoValor, opcoes);
    }


    /* ======================================================================
       REMOVE
    ====================================================================== */

    remove(caminho, opcoes = {}) {
        const { notificar = true, persistir = true } = opcoes;
        const anterior = this.get(caminho);

        if (!removerNo(this._dados, caminho)) return false;

        if (persistir) this._persistirSeNecessario(caminho);
        if (notificar) this._emitir(caminho, undefined, anterior);

        return true;
    }


    /* ======================================================================
       REPLACE
    ====================================================================== */

    replace(dados, opcoes = {}) {
        const { notificar = true } = opcoes;

        this._dados = clonar(dados || {});

        if (notificar) this._emitir('*', this._dados, null);

        this._persistirUi();
    }


    /* ======================================================================
       RESET
    ====================================================================== */

    reset(caminho = null) {
        if (!caminho) {
            const uiAtual = this.snapshot('ui');
            this._dados = clonar(estadoInicial);

            if (uiAtual?.secaoAtual) this._dados.ui.secaoAtual = uiAtual.secaoAtual;

            this._emitir('*', this._dados, null);
            this._persistirUi();

            return true;
        }

        const padrao = obterNo(estadoInicial, caminho);

        if (padrao === undefined) {
            return this.remove(caminho);
        }

        return this.set(caminho, clonar(padrao));
    }


    /* ======================================================================
       SUBSCRIBE
    ====================================================================== */

    subscribe(caminho, callback, opcoes = {}) {
        if (typeof caminho === 'function') {
            callback = caminho;
            caminho = '*';
        }

        if (typeof callback !== 'function') return () => {};

        caminho = caminho || '*';

        if (!this._listeners.has(caminho)) this._listeners.set(caminho, new Set());
        this._listeners.get(caminho).add(callback);

        if (opcoes.imediato) {
            try {
                callback(this.get(caminho === '*' ? null : caminho), undefined, caminho);
            } catch (error) {
                console.error('[MoonShield Network] Erro em subscriber imediato:', error);
            }
        }

        return () => this.unsubscribe(caminho, callback);
    }


    unsubscribe(caminho, callback) {
        const listeners = this._listeners.get(caminho);
        if (!listeners) return false;

        listeners.delete(callback);

        if (!listeners.size) this._listeners.delete(caminho);
        return true;
    }


    clearSubscribers(caminho = null) {
        if (caminho) {
            this._listeners.delete(caminho);
            return;
        }

        this._listeners.clear();
    }


    /* ======================================================================
       EMIT
    ====================================================================== */

    _emitir(caminho, novoValor, anterior) {
        const executar = (listeners, caminhoNotificado) => {
            if (!listeners) return;

            listeners.forEach(callback => {
                try {
                    callback(novoValor, anterior, caminhoNotificado);
                } catch (error) {
                    console.error(`[MoonShield Network] Erro no subscriber "${caminhoNotificado}":`, error);
                }
            });
        };

        executar(this._listeners.get(caminho), caminho);
        executar(this._listeners.get('*'), caminho);

        const partes = partesDoCaminho(caminho);

        while (partes.length > 1) {
            partes.pop();

            const pai = partes.join('.');
            executar(this._listeners.get(pai), caminho);
        }
    }


    /* ======================================================================
       UI PERSISTIDA
    ====================================================================== */

    _carregarUiPersistida() {
        try {
            const bruto = localStorage.getItem(STORAGE_KEY);
            if (!bruto) return;

            const persistido = JSON.parse(bruto);
            if (!persistido || typeof persistido !== 'object') return;

            if (persistido.secaoAtual) this._dados.ui.secaoAtual = persistido.secaoAtual;
        } catch (error) {
            console.warn('[MoonShield Network] Não foi possível carregar estado visual:', error);
        }
    }


    _persistirSeNecessario(caminho) {
        if (caminho === 'ui' || caminho.startsWith('ui.')) this._persistirUi();
    }


    _persistirUi() {
        try {
            const ui = this.get('ui', {});

            localStorage.setItem(STORAGE_KEY, JSON.stringify({
                secaoAtual: ui.secaoAtual || 'visao-geral',
            }));
        } catch (error) {
            console.warn('[MoonShield Network] Não foi possível persistir estado visual:', error);
        }
    }
}


/* ==========================================================================
   SINGLETON
========================================================================== */

export const estado = new NetworkState(estadoInicial);


/* ==========================================================================
   DEBUG
========================================================================== */

if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
    window.MoonShieldNetworkState = estado;
}


/* ==========================================================================
   EXPORTS
========================================================================== */

export { NetworkState, estadoInicial };

export default estado;