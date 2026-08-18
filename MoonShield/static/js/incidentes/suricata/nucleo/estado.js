export const APP = window.MS_SURICATA_PANEL || {};
export const URLS = APP.urls || {};
export const CONFIG = APP.configuracao || null;

export const REQUIRED_URLS = Object.freeze([
    'status',
    'diagnostico',
    'criarTarefa',
    'listarTarefas',
    'detalheTarefaTemplate',
    'cancelarTarefaTemplate',
    'logsTarefaTemplate',
]);

export const FINAL_TASK_STATUSES = new Set([
    'sucesso',
    'erro',
    'cancelado',
    'ignorado',
]);

export const RUNNING_TASK_STATUSES = new Set([
    'pendente',
    'executando',
]);

export const TASK_LABELS = {
    diagnostico: 'Diagnóstico',
    instalacao: 'Instalação',
    configuracao: 'Configuração',
    atualizacao_regras: 'Atualização de regras',
    validacao: 'Validação',
    reinicio_suricata: 'Reinício do Suricata',
    reinicio_monitor: 'Reinício do monitor',
};

export const TASK_ICONS = {
    diagnostico: 'pulse',
    instalacao: 'download',
    configuracao: 'settings',
    atualizacao_regras: 'refresh',
    validacao: 'check',
    reinicio_suricata: 'restart',
    reinicio_monitor: 'activity',
};

export const STATUS_LABELS = {
    ok: 'Saudável',
    aviso: 'Aviso',
    warning: 'Aviso',
    erro: 'Erro',
    error: 'Erro',
    desconhecido: 'Desconhecido',
    desativado: 'Desativado',
    pendente: 'Pendente',
    executando: 'Executando',
    sucesso: 'Sucesso',
    cancelado: 'Cancelado',
    ignorado: 'Ignorado',
    ativo: 'Ativo',
    inativo: 'Inativo',
    true: 'Sim',
    false: 'Não',
};

export const STATUS_CLASS_MAP = {
    ok: 'ok',
    sucesso: 'ok',
    ativo: 'ok',
    healthy: 'ok',
    warning: 'warning',
    aviso: 'warning',
    degradado: 'warning',
    pending: 'pending',
    pendente: 'pending',
    executando: 'pending',
    desconhecido: 'pending',
    desativado: 'pending',
    error: 'error',
    erro: 'error',
    offline: 'error',
    inativo: 'error',
    cancelado: 'error',
};

export const state = {
    currentSection: 'overview',
    statusData: {},
    cardsData: {},
    diagnosticData: null,
    tasks: [],
    taskTotal: 0,
    taskOffset: 0,
    taskLimit: 20,
    taskPage: 1,
    currentTaskId: null,
    currentTask: null,
    taskPollTimer: null,
    statusPollTimer: null,
    pendingConfirmation: null,
    lastStatusFetchAt: null,
    isFetchingStatus: false,
    isRunningDiagnostic: false,
    destroyed: false,
};