import { applyStatusDot, applyChip, statusLabel, iconSVG, normalizeStatus } from '../nucleo/interface.js';
import { $, setText } from '../nucleo/dom.js';
import { TASK_LABELS, TASK_ICONS, state } from '../nucleo/estado.js';
import { formatRelativeTime, escapeHTML, capitalize } from '../nucleo/utilitarios.js';

export function initStars() {
    const canvas = $('starsCanvas');
    if (!canvas) return;

    const context = canvas.getContext('2d');
    if (!context) return;

    let stars = [];
    let frameId = null;

    const resize = () => {
        const ratio = Math.min(window.devicePixelRatio || 1, 2);
        canvas.width = Math.floor(window.innerWidth * ratio);
        canvas.height = Math.floor(window.innerHeight * ratio);
        canvas.style.width = `${window.innerWidth}px`;
        canvas.style.height = `${window.innerHeight}px`;
        context.setTransform(ratio, 0, 0, ratio, 0, 0);

        const count = Math.max(50, Math.floor((window.innerWidth * window.innerHeight) / 8500));
        stars = Array.from({ length: count }, () => ({
            x: Math.random() * window.innerWidth,
            y: Math.random() * window.innerHeight,
            radius: Math.random() * 1.05 + .15,
            alpha: Math.random() * .55 + .12,
            speed: Math.random() * .0025 + .001,
            phase: Math.random() * Math.PI * 2,
        }));
    };

    const draw = (timestamp) => {
        context.clearRect(0, 0, window.innerWidth, window.innerHeight);

        for (const star of stars) {
            const alpha = star.alpha * (.55 + .45 * Math.sin(star.phase + timestamp * star.speed));
            context.beginPath();
            context.arc(star.x, star.y, star.radius, 0, Math.PI * 2);
            context.fillStyle = `rgba(190, 213, 255, ${Math.max(.05, alpha)})`;
            context.fill();
        }
        frameId = window.requestAnimationFrame(draw);
    };

    resize();
    frameId = window.requestAnimationFrame(draw);
    window.addEventListener('resize', resize);
    window.addEventListener('beforeunload', () => {
        if (frameId) window.cancelAnimationFrame(frameId);
    }, { once: true });
}

export function renderGlobalStatus({ status, healthy, active, message }) {
    const normalized = healthy ? 'ok' : normalizeStatus(status, active ? 'warning' : 'error');

    applyStatusDot('sidebarStatusDot', normalized);
    applyStatusDot('heroStatusDot', normalized);
    applyChip('headerStackChip', normalized, statusLabel(normalized));

    setText('headerStackText', healthy ? 'Saudável' : active ? 'Com avisos' : 'Atenção');
    setText('sidebarStatusTitle', healthy ? 'Proteção ativa' : active ? 'Proteção degradada' : 'Proteção indisponível');
    setText('sidebarStatusText', message);
    setText('heroStatusEyebrow', healthy ? 'Proteção operacional' : active ? 'Operação com avisos' : 'Intervenção necessária');
    setText('heroDescription', message);

    const orbit = $('orbitStatus');
    if (orbit) {
        for (const className of Array.from(orbit.classList)) {
            if (className.startsWith('sp-orbit__status--')) orbit.classList.remove(className);
        }
        orbit.classList.add(`sp-orbit__status--${normalized}`);
    }
    setText('orbitStatusText', healthy ? 'Stack operacional' : active ? 'Stack degradada' : 'Stack indisponível');
}

export function updateLastRefresh() {
    const value = state.lastStatusFetchAt || new Date();
    setText('lastUpdateText', formatRelativeTime(value));
}

export function renderOverviewTasks(tasks) {
    const container = $('overviewTaskList');
    if (!container) return;

    container.innerHTML = '';

    if (!tasks.length) {
        container.innerHTML = `
            <div class="sp-empty-state sp-empty-state--compact">
                <span class="sp-empty-state__icon">${iconSVG('task', 20)}</span>
                <div>
                    <strong>Nenhuma atividade recente</strong>
                    <span>As últimas tarefas aparecerão aqui.</span>
                </div>
            </div>
        `;
        return;
    }

    for (const task of tasks) {
        const status = normalizeStatus(task.status);
        const element = document.createElement('button');
        element.type = 'button';
        element.className = 'sp-activity-item';
        element.dataset.taskOpen = task.id || task.pk || '';

        element.innerHTML = `
            <span class="sp-activity-item__icon">${iconSVG(TASK_ICONS[task.tipo] || 'task', 15)}</span>
            <span class="sp-activity-item__copy">
                <strong>${escapeHTML(TASK_LABELS[task.tipo] || capitalize(task.tipo))}</strong>
                <span>${escapeHTML(task.mensagem || task.etapa_atual || 'Sem detalhes')}</span>
            </span>
            <span class="sp-status-pill sp-status-pill--${status}">${escapeHTML(statusLabel(task.status))}</span>
        `;

        container.appendChild(element);
    }
}