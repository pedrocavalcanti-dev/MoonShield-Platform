import { state } from '../nucleo/estado.js';

export function startStatusPolling(refreshCallback) {
    stopStatusPolling();

    state.statusPollTimer = window.setInterval(() => {
        if (state.destroyed || document.hidden || state.isFetchingStatus) {
            return;
        }
        refreshCallback().catch(console.error);
    }, 30000);
}

export function stopStatusPolling() {
    if (state.statusPollTimer) {
        window.clearInterval(state.statusPollTimer);
        state.statusPollTimer = null;
    }
}

export function bindVisibility(refreshCallback, loadDetailCallback) {
    document.addEventListener('visibilitychange', () => {
        if (!document.hidden) {
            refreshCallback().catch(console.error);
            if (state.currentTaskId && loadDetailCallback) {
                loadDetailCallback(state.currentTaskId).catch(console.error);
            }
        }
    });
}