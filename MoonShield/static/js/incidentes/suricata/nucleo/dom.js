import { textValue } from './utilitarios.js';

export function $(id) {
    return document.getElementById(id);
}

export function $all(selector, root = document) {
    return Array.from(root.querySelectorAll(selector));
}

export function setText(id, value, fallback = '—') {
    const element = $(id);
    if (!element) return;
    element.textContent = textValue(value, fallback);
}

export function setHidden(id, hidden) {
    const element = $(id);
    if (!element) return;
    element.hidden = Boolean(hidden);
}

export function setButtonLoading(button, loading) {
    if (!button) return;

    if (loading) {
        button.dataset.previousDisabled = String(button.disabled);
        button.disabled = true;
        button.classList.add('is-loading');
    } else {
        button.classList.remove('is-loading');
        button.disabled = button.dataset.previousDisabled === 'true';
        delete button.dataset.previousDisabled;
    }
}

export function updateClassByPrefix(element, prefix, normalizedStatus) {
    if (!element) return;

    for (const className of Array.from(element.classList)) {
        if (className.startsWith(prefix)) {
            element.classList.remove(className);
        }
    }
    element.classList.add(prefix + normalizedStatus);
}