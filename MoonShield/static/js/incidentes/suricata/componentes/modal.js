import { $, setText, setButtonLoading, $all } from '../nucleo/dom.js';
import { state } from '../nucleo/estado.js';
import { handleError } from '../nucleo/api.js';

export function initModal() {
    $('btnCancelConfirmation')?.addEventListener('click', closeConfirmation);
    
    $all('[data-close-confirmation]').forEach((element) => {
        element.addEventListener('click', closeConfirmation);
    });

    $('btnConfirmOperation')?.addEventListener('click', async () => {
        if (!state.pendingConfirmation?.onConfirm) {
            closeConfirmation();
            return;
        }

        const callback = state.pendingConfirmation.onConfirm;
        const button = $('btnConfirmOperation');
        setButtonLoading(button, true);

        try {
            await callback();
            closeConfirmation();
        } catch (error) {
            handleError(error);
        } finally {
            setButtonLoading(button, false);
        }
    });
}

export function confirmOperation({ title, text, details = '', confirmLabel = 'Confirmar', confirmClass = 'sp-btn--primary', onConfirm }) {
    state.pendingConfirmation = { onConfirm };

    setText('confirmationModalTitle', title, 'Confirmar operação');
    setText('confirmationModalText', text, 'Confirme para continuar.');

    const detailsElement = $('confirmationModalDetails');
    if (detailsElement) {
        detailsElement.hidden = !details;
        detailsElement.textContent = details || '';
    }

    const confirmButton = $('btnConfirmOperation');
    if (confirmButton) {
        confirmButton.textContent = confirmLabel;
        confirmButton.className = `sp-btn ${confirmClass}`;
    }

    const modal = $('confirmationModal');
    if (modal) {
        modal.classList.add('is-open');
        modal.setAttribute('aria-hidden', 'false');
        window.setTimeout(() => confirmButton?.focus(), 50);
    }
}

export function closeConfirmation() {
    state.pendingConfirmation = null;
    const modal = $('confirmationModal');
    if (modal) {
        modal.classList.remove('is-open');
        modal.setAttribute('aria-hidden', 'true');
    }
}