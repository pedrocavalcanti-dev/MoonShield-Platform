/**
 * MoonShield Network Panel
 * Núcleo DOM
 *
 * Helpers para consulta, alteração e criação de elementos.
 */

'use strict';


/* ==========================================================================
   SELETORES
========================================================================== */

export function $(seletor, raiz = document) {
    if (!seletor || !raiz) return null;
    return raiz.querySelector(seletor);
}


export function $$(seletor, raiz = document) {
    if (!seletor || !raiz) return [];
    return Array.from(raiz.querySelectorAll(seletor));
}


export function porId(id) {
    return id ? document.getElementById(id) : null;
}


/* ==========================================================================
   TEXTO / HTML
========================================================================== */

export function setText(elemento, valor, fallback = '—') {
    elemento = resolverElemento(elemento);
    if (!elemento) return;

    const vazio = valor === undefined || valor === null || valor === '';
    elemento.textContent = vazio ? fallback : String(valor);
}


export function setHTML(elemento, html = '') {
    elemento = resolverElemento(elemento);
    if (!elemento) return;
    elemento.innerHTML = html ?? '';
}


export function limpar(elemento) {
    elemento = resolverElemento(elemento);
    if (!elemento) return;

    while (elemento.firstChild) elemento.removeChild(elemento.firstChild);
}


/* ==========================================================================
   VISIBILIDADE
========================================================================== */

export function setHidden(elemento, oculto = true) {
    elemento = resolverElemento(elemento);
    if (!elemento) return;

    elemento.hidden = Boolean(oculto);
}


export function mostrar(elemento) {
    setHidden(elemento, false);
}


export function ocultar(elemento) {
    setHidden(elemento, true);
}


export function toggleHidden(elemento, forcar = undefined) {
    elemento = resolverElemento(elemento);
    if (!elemento) return false;

    const ocultarAgora = forcar === undefined ? !elemento.hidden : Boolean(forcar);
    elemento.hidden = ocultarAgora;
    return !ocultarAgora;
}


/* ==========================================================================
   CLASSES
========================================================================== */

export function addClass(elemento, ...classes) {
    elemento = resolverElemento(elemento);
    if (!elemento) return;

    const validas = classes.flat().filter(Boolean);
    if (validas.length) elemento.classList.add(...validas);
}


export function removeClass(elemento, ...classes) {
    elemento = resolverElemento(elemento);
    if (!elemento) return;

    const validas = classes.flat().filter(Boolean);
    if (validas.length) elemento.classList.remove(...validas);
}


export function toggleClass(elemento, classe, estado = undefined) {
    elemento = resolverElemento(elemento);
    if (!elemento || !classe) return false;

    return estado === undefined ? elemento.classList.toggle(classe) : elemento.classList.toggle(classe, Boolean(estado));
}


export function substituirClasses(elemento, remover = [], adicionar = []) {
    elemento = resolverElemento(elemento);
    if (!elemento) return;

    removeClass(elemento, remover);
    addClass(elemento, adicionar);
}


/* ==========================================================================
   ATRIBUTOS
========================================================================== */

export function setAttr(elemento, nome, valor) {
    elemento = resolverElemento(elemento);
    if (!elemento || !nome) return;

    if (valor === undefined || valor === null || valor === false) {
        elemento.removeAttribute(nome);
        return;
    }

    elemento.setAttribute(nome, valor === true ? '' : String(valor));
}


export function setAttrs(elemento, atributos = {}) {
    elemento = resolverElemento(elemento);
    if (!elemento) return;

    Object.entries(atributos).forEach(([nome, valor]) => setAttr(elemento, nome, valor));
}


/* ==========================================================================
   DATASET
========================================================================== */

export function setData(elemento, chave, valor) {
    elemento = resolverElemento(elemento);
    if (!elemento || !chave) return;

    if (valor === undefined || valor === null) {
        delete elemento.dataset[chave];
        return;
    }

    elemento.dataset[chave] = String(valor);
}


export function getData(elemento, chave, fallback = null) {
    elemento = resolverElemento(elemento);
    if (!elemento || !chave) return fallback;

    const valor = elemento.dataset[chave];
    return valor === undefined ? fallback : valor;
}


/* ==========================================================================
   VALORES DE FORM
========================================================================== */

export function valor(elemento, fallback = '') {
    elemento = resolverElemento(elemento);
    if (!elemento) return fallback;

    const valorAtual = elemento.value;
    return valorAtual === undefined || valorAtual === null ? fallback : valorAtual;
}


export function valorTrim(elemento, fallback = '') {
    return String(valor(elemento, fallback)).trim();
}


export function valorNumero(elemento, fallback = null) {
    const bruto = valorTrim(elemento);
    if (bruto === '') return fallback;

    const numero = Number(bruto);
    return Number.isFinite(numero) ? numero : fallback;
}


export function marcado(elemento) {
    elemento = resolverElemento(elemento);
    return Boolean(elemento?.checked);
}


export function setValor(elemento, valor = '') {
    elemento = resolverElemento(elemento);
    if (!elemento) return;
    elemento.value = valor ?? '';
}


export function setMarcado(elemento, ativo) {
    elemento = resolverElemento(elemento);
    if (!elemento) return;
    elemento.checked = Boolean(ativo);
}


export function setDisabled(elemento, desabilitado = true) {
    elemento = resolverElemento(elemento);
    if (!elemento) return;
    elemento.disabled = Boolean(desabilitado);
}


/* ==========================================================================
   EVENTOS
========================================================================== */

export function on(elemento, evento, callback, opcoes = undefined) {
    elemento = resolverElemento(elemento);
    if (!elemento || !evento || typeof callback !== 'function') return () => {};

    elemento.addEventListener(evento, callback, opcoes);
    return () => elemento.removeEventListener(evento, callback, opcoes);
}


export function onAll(seletor, evento, callback, raiz = document) {
    return $$(seletor, raiz).map(elemento => on(elemento, evento, callback));
}


export function delegar(elemento, evento, seletor, callback) {
    elemento = resolverElemento(elemento);
    if (!elemento || !evento || !seletor || typeof callback !== 'function') return () => {};

    const handler = event => {
        const alvo = event.target instanceof Element ? event.target.closest(seletor) : null;
        if (!alvo || !elemento.contains(alvo)) return;
        callback(event, alvo);
    };

    elemento.addEventListener(evento, handler);
    return () => elemento.removeEventListener(evento, handler);
}


/* ==========================================================================
   CRIAÇÃO
========================================================================== */

export function criar(tag, opcoes = {}) {
    const elemento = document.createElement(tag);

    if (opcoes.className) elemento.className = opcoes.className;
    if (opcoes.text !== undefined) elemento.textContent = String(opcoes.text);
    if (opcoes.html !== undefined) elemento.innerHTML = opcoes.html;
    if (opcoes.attrs) setAttrs(elemento, opcoes.attrs);

    if (opcoes.dataset) {
        Object.entries(opcoes.dataset).forEach(([chave, valor]) => setData(elemento, chave, valor));
    }

    if (opcoes.children) {
        const filhos = Array.isArray(opcoes.children) ? opcoes.children : [opcoes.children];
        filhos.filter(Boolean).forEach(filho => elemento.append(filho));
    }

    return elemento;
}


/* ==========================================================================
   TEMPLATE
========================================================================== */

export function clonarTemplate(template, seletorRaiz = null) {
    template = resolverElemento(template);

    if (!(template instanceof HTMLTemplateElement)) {
        console.warn('[MoonShield Network] Template HTML não encontrado:', template);
        return null;
    }

    const fragmento = template.content.cloneNode(true);
    return seletorRaiz ? fragmento.querySelector(seletorRaiz) : fragmento.firstElementChild;
}


/* ==========================================================================
   STATUS PILL
========================================================================== */

export function setStatusPill(elemento, status, texto = null) {
    elemento = resolverElemento(elemento);
    if (!elemento) return;

    const mapa = {
        ok: 'np-status-pill--ok',
        online: 'np-status-pill--ok',
        success: 'np-status-pill--ok',
        confirmed: 'np-status-pill--ok',

        warning: 'np-status-pill--warning',
        pending: 'np-status-pill--warning',
        waiting_confirmation: 'np-status-pill--warning',
        rollback: 'np-status-pill--warning',
        reverted: 'np-status-pill--warning',

        error: 'np-status-pill--error',
        offline: 'np-status-pill--error',
        failed: 'np-status-pill--error',

        created: 'np-status-pill--pending',
        validating: 'np-status-pill--pending',
        cancelled: 'np-status-pill--pending',

        applying: 'np-status-pill--ok',
    };

    const classes = [
        'np-status-pill--ok',
        'np-status-pill--warning',
        'np-status-pill--error',
        'np-status-pill--pending',
    ];

    elemento.classList.remove(...classes);
    elemento.classList.add(mapa[status] || 'np-status-pill--pending');

    if (status !== undefined && status !== null) elemento.dataset.status = String(status);
    else delete elemento.dataset.status;

    if (texto !== null) setText(elemento, texto);
}


/* ==========================================================================
   STATUS DOT
========================================================================== */

export function setStatusDot(elemento, status = 'pending') {
    elemento = resolverElemento(elemento);
    if (!elemento) return;

    const mapa = {
        ok: 'np-status-dot--ok',
        online: 'np-status-dot--ok',
        success: 'np-status-dot--ok',
        warning: 'np-status-dot--warning',
        pending: 'np-status-dot--pending',
        error: 'np-status-dot--error',
        offline: 'np-status-dot--error',
        failed: 'np-status-dot--error',
    };

    elemento.classList.remove('np-status-dot--ok', 'np-status-dot--warning', 'np-status-dot--error', 'np-status-dot--pending');
    elemento.classList.add(mapa[status] || 'np-status-dot--pending');
}


/* ==========================================================================
   JSON / PRE
========================================================================== */

export function setJson(elemento, dados, fallback = '{}') {
    elemento = resolverElemento(elemento);
    if (!elemento) return;

    if (dados === undefined || dados === null) {
        elemento.textContent = fallback;
        return;
    }

    try {
        elemento.textContent = typeof dados === 'string' ? dados : JSON.stringify(dados, null, 2);
    } catch {
        elemento.textContent = fallback;
    }
}


/* ==========================================================================
   FORM SERIALIZATION
========================================================================== */

export function formParaObjeto(form) {
    form = resolverElemento(form);
    if (!(form instanceof HTMLFormElement)) return {};

    const resultado = {};
    const dados = new FormData(form);

    for (const [chave, valor] of dados.entries()) {
        if (Object.prototype.hasOwnProperty.call(resultado, chave)) {
            if (!Array.isArray(resultado[chave])) resultado[chave] = [resultado[chave]];
            resultado[chave].push(valor);
        } else {
            resultado[chave] = valor;
        }
    }

    $$('input[type="checkbox"][name]', form).forEach(input => {
        if (!dados.has(input.name)) resultado[input.name] = false;
        else if (input.value === 'on') resultado[input.name] = input.checked;
    });

    return resultado;
}


/* ==========================================================================
   ESTADO VISUAL
========================================================================== */

export function setLoading(elemento, ativo = true) {
    elemento = resolverElemento(elemento);
    if (!elemento) return;

    elemento.classList.toggle('is-loading', Boolean(ativo));

    if ('disabled' in elemento) elemento.disabled = Boolean(ativo);
    elemento.setAttribute('aria-busy', ativo ? 'true' : 'false');
}


/* ==========================================================================
   SCROLL / FOCUS
========================================================================== */

export function focar(elemento, opcoes = {}) {
    elemento = resolverElemento(elemento);
    if (!elemento || typeof elemento.focus !== 'function') return;

    requestAnimationFrame(() => elemento.focus({ preventScroll: Boolean(opcoes.preventScroll) }));
}


export function rolarPara(elemento, opcoes = {}) {
    elemento = resolverElemento(elemento);
    if (!elemento) return;

    elemento.scrollIntoView({
        behavior: opcoes.behavior || 'smooth',
        block: opcoes.block || 'nearest',
        inline: opcoes.inline || 'nearest',
    });
}


/* ==========================================================================
   HELPERS INTERNOS
========================================================================== */

function resolverElemento(elemento) {
    if (!elemento) return null;
    if (typeof elemento === 'string') return $(elemento);
    return elemento;
}


/* ==========================================================================
   EXPORT DEFAULT
========================================================================== */

export default {
    $,
    $$,
    porId,
    setText,
    setHTML,
    limpar,
    setHidden,
    mostrar,
    ocultar,
    toggleHidden,
    addClass,
    removeClass,
    toggleClass,
    substituirClasses,
    setAttr,
    setAttrs,
    setData,
    getData,
    valor,
    valorTrim,
    valorNumero,
    marcado,
    setValor,
    setMarcado,
    setDisabled,
    on,
    onAll,
    delegar,
    criar,
    clonarTemplate,
    setStatusPill,
    setStatusDot,
    setJson,
    formParaObjeto,
    setLoading,
    focar,
    rolarPara,
};