// ==== DMF BRAIN (auto-gerado) ====
window.DMF_BRAIN = window.DMF_BRAIN || {
  usuarios: [],
  pagamentos: [],
  assinaturas: [],
  eventos: [],
  erros: [],
  acoes: [],
  memoria: [],
  conhecimento: []
};

function registrarEvento(tipo, usuario, detalhes){
  try{
    const evento={
      tipo,
      usuario: usuario||'sistema',
      detalhes: detalhes||'',
      data: new Date().toISOString()
    };
    window.DMF_BRAIN.eventos.push(evento);
    if(window.DMF_BRAIN.eventos.length>500) window.DMF_BRAIN.eventos.shift();
    console.log('[EVENTO]',evento);
  }catch(e){
    console.warn('Falha ao registrar evento',e);
  }
}
// ==== FIM DMF BRAIN ====

/**
 * DMF ENTERPRISE SYSTEM v2.0
 * Engine Modular unificada
 */

// Simple hash function (base64 encoding for demo purposes)
function hash(str) {
    return btoa(str);
}

function getApiBase() {
    if (window.DMF_API_BASE) return window.DMF_API_BASE;
    if (!window.location || !window.location.origin || window.location.origin === 'null') {
        return 'http://localhost:3001';
    }
    return window.location.origin;
}

function isLocalRuntime() {
    const host = (window.location && window.location.hostname) ? window.location.hostname : '';
    return host === 'localhost' || host === '127.0.0.1';
}

function getAuthHeaders() {
    const token = localStorage.getItem('dmf_api_token');
    return token ? { Authorization: `Bearer ${token}` } : {};
}

function normalizeRole(role) {
    return String(role || '').trim().toLowerCase();
}

function isAdminUser(user) {
    return normalizeRole(user && (user.cargo || user.role)) === 'admin';
}

function setFlowSyncStatus(message, tone = 'info') {
    const el = document.getElementById('flowSyncStatus');
    if (!el) return;
    el.textContent = message;
    el.classList.remove('is-ok', 'is-warn', 'is-error', 'is-info');
    const toneClass = `is-${tone}`;
    el.classList.add(toneClass);
}

function formatTimeNow() {
    const now = new Date();
    return now.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
}

function setBackendStatus(message, tone = 'info') {
    const el = document.getElementById('backendStatus');
    if (!el) return;
    el.textContent = message;
    el.classList.remove('is-ok', 'is-warn', 'is-error', 'is-info');
    const toneClass = `is-${tone}`;
    el.classList.add(toneClass);
}

function showToast(message, type = 'info', ttl = 3500) {
    if (!message) return;
    showToast.last = showToast.last || {};
    const now = Date.now();
    if (showToast.last[message] && now - showToast.last[message] < 4000) return;
    showToast.last[message] = now;
    const container = document.getElementById('toastContainer');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(-6px)';
        setTimeout(() => toast.remove(), 200);
    }, ttl);
}

function parseJwtPayload(token) {
    try {
        const payload = token.split('.')[1];
        const normalized = payload.replace(/-/g, '+').replace(/_/g, '/');
        const decoded = atob(normalized);
        return JSON.parse(decoded);
    } catch (_) {
        return null;
    }
}

class SyncManager {
    constructor(core) {
        this.core = core;
        this.queueKey = 'dmf_sync_queue';
        this.queue = this.loadQueue();
        this.processing = false;
        this.timer = null;
        this.start();
    }

    loadQueue() {
        try {
            const raw = localStorage.getItem(this.queueKey);
            return raw ? JSON.parse(raw) : [];
        } catch (_) {
            return [];
        }
    }

    saveQueue() {
        localStorage.setItem(this.queueKey, JSON.stringify(this.queue));
    }

    enqueue(item) {
        const payload = {
            id: `${Date.now()}-${Math.random()}`,
            type: item.type,
            data: item.data || null,
            tries: 0,
            nextAt: Date.now()
        };
        this.queue.push(payload);
        this.saveQueue();
        this.kick();
    }

    kick() {
        if (!this.timer) {
            this.timer = setTimeout(() => this.processQueue(), 1000);
        }
    }

    start() {
        this.kick();
        setInterval(() => this.processQueue(), 10000);
    }

    async processQueue() {
        if (this.processing) return;
        this.processing = true;
        try {
            const now = Date.now();
            const readyIndex = this.queue.findIndex(item => item.nextAt <= now);
            if (readyIndex === -1) {
                return;
            }
            const item = this.queue[readyIndex];
            const ok = await this.execute(item);
            if (ok) {
                this.queue.splice(readyIndex, 1);
                this.saveQueue();
            } else {
                item.tries += 1;
                const backoff = Math.min(60000, 2000 * Math.pow(2, item.tries));
                item.nextAt = Date.now() + backoff;
                this.queue[readyIndex] = item;
                this.saveQueue();
            }
        } finally {
            this.processing = false;
            if (this.timer) {
                clearTimeout(this.timer);
                this.timer = null;
            }
        }
    }

    async execute(item) {
        const token = localStorage.getItem('dmf_api_token');
        if (!token) return false;
        try {
            if (item.type === 'import') {
                const company = item.data?.company || this.core.data.currentCompany;
                let records = item.data?.payments;
                if (!records || !Array.isArray(records)) {
                    records = this.core.data.loadCompanyPayments(company);
                }
                const response = await fetch(`${getApiBase()}/api/flow-payments/import?company=${encodeURIComponent(company)}`, {
                    method: 'POST',
                    cache: 'no-store',
                    headers: {
                        'Content-Type': 'application/json',
                        ...getAuthHeaders()
                    },
                    body: JSON.stringify({ company, payments: records })
                });
                return response.ok;
            }
            if (item.type === 'upsert') {
                const company = item.data?.company || this.core.data.currentCompany;
                const response = await fetch(`${getApiBase()}/api/flow-payments?company=${encodeURIComponent(company)}`, {
                    method: 'POST',
                    cache: 'no-store',
                    headers: {
                        'Content-Type': 'application/json',
                        ...getAuthHeaders()
                    },
                    body: JSON.stringify({ ...item.data, company })
                });
                return response.ok;
            }
            if (item.type === 'sign') {
                const company = item.data?.company || this.core.data.currentCompany;
                const response = await fetch(`${getApiBase()}/api/flow-payments/${item.data.id}/sign?company=${encodeURIComponent(company)}`, {
                    method: 'PATCH',
                    headers: {
                        'Content-Type': 'application/json',
                        ...getAuthHeaders()
                    },
                    body: JSON.stringify({ assinatura: item.data.assinatura, company })
                });
                return response.ok;
            }
        } catch (error) {
            console.warn('Sync queue execute failed:', error.message);
        }
        return false;
    }
}

class DMFSystem {
    constructor() {
        this.storageKeys = {
            USERS: 'dmf_enterprise_users',
            ROLES: 'dmf_enterprise_roles',
            PAYMENTS: 'dmf_enterprise_data',
            LOGS: 'dmf_enterprise_audit',
            SESSION: 'dmf_active_session',
            CURRENT_COMPANY: 'dmf_current_company',
            COST_CENTERS: 'dmf_enterprise_cost_centers', // ALTERADO
            COST_CENTER_RULES: 'dmf_enterprise_cc_permissions'
        };

        this.init();
    }

    init() {
        this.sync = new SyncManager(this);
        this.data = new DataProcessor(this);
        this.auth = new AuthManager(this);
        this.ui = new UIManager(this);
        this.audit = new AuditLogger(this);
        this.admin = new AdminManager(this);
        this.cobli = new CobliManager(this);

        this.checkSession();
    }

    checkSession() {
        const session = localStorage.getItem(this.storageKeys.SESSION);
        if (session) {
            this.currentUser = JSON.parse(session);
            window.DMF_CONTEXT.usuarioLogado = this.currentUser;
            console.log('DMF_CONTEXT after checkSession:', window.DMF_CONTEXT);
            this.ui.setupDashboard();
        }
    }
}

class AuthManager {
    constructor(core) { this.core = core; }

    async login() {
        const input = document.getElementById('loginInput').value.trim().toLowerCase();
        const pass = document.getElementById('loginPass').value;

        try {
            const response = await fetch(`${getApiBase()}/api/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: input, password: pass })
            });

            if (response.ok) {
                const data = await response.json();
                const apiRole = normalizeRole(data.user.role);
                const apiUser = {
                    ...data.user,
                    cargo: apiRole,
                    nome: data.user.name || data.user.username,
                    additionalPermissions: Array.isArray(data.user.permissions) ? data.user.permissions : []
                };
                localStorage.setItem('dmf_api_token', data.token);
                this.setSession(apiUser);
                return;
            }
            alert("Falha na autenticação.");
            return;
        } catch (error) {
            console.warn('API login failed:', error.message);
            if (!isLocalRuntime()) {
                alert("Falha na autenticação.");
                return;
            }
            console.warn('Local runtime detected, using local auth fallback.');
        }

        // Verificar usuários armazenados por usuario ou email
        const user = this.core.admin.users.find(u =>
            (u.usuario === input || u.email === input) &&
            (u.senha === hash(pass) || u.senha === pass)
        );
        if (user) {
            this.setSession(user);
        } else {
            alert("Falha na autenticação.");
        }
    }

    setSession(user) {
        const normalizedCargo = normalizeRole(user.cargo || user.role);
        const additionalPermissions = Array.isArray(user.additionalPermissions)
            ? user.additionalPermissions
            : (Array.isArray(user.permissions) ? user.permissions : []);
        this.core.currentUser = { ...user, cargo: normalizedCargo, additionalPermissions };
        localStorage.setItem(this.core.storageKeys.SESSION, JSON.stringify(this.core.currentUser));
        window.DMF_CONTEXT.usuarioLogado = this.core.currentUser;
        console.log('DMF_CONTEXT after setSession:', window.DMF_CONTEXT);
        this.core.ui.setupDashboard();
    }

    logout() {
        localStorage.removeItem(this.core.storageKeys.SESSION);
        localStorage.removeItem('dmf_api_token');
        this.core.currentUser = null;
        window.DMF_CONTEXT.usuarioLogado = null;
        console.log('DMF_CONTEXT after logout:', window.DMF_CONTEXT);
        this.core.ui.showLogin();
    }
}

class DataProcessor {
    constructor(core) {
        this.core = core;
        const persistedCompany = localStorage.getItem(core.storageKeys.CURRENT_COMPANY);
        this.currentCompany = this.normalizeCompany(persistedCompany || 'DMF');
        this.records = this.loadCompanyPayments(this.currentCompany);
        this.archives = [];
        this.flowFetchInFlight = false;
        this.flowFetchLastAt = 0;
        this.flowFetchMinInterval = 60000;
        this.flowFetchBackoff = 0;
        this.flowFetchCooldownUntil = 0;
        this.lastSyncAt = null;
        this.centerCompanyOverrides = this.loadCenterCompanyOverrides();
        this.pendingCenterAssignments = new Set();
        // === Centros de Custo: carga e união com o fluxo === // ALTERADO
        const persisted = JSON.parse(localStorage.getItem(core.storageKeys.COST_CENTERS) || '[]'); // ALTERADO
        const fromRecords = Array.from(new Set((this.records || []).map(r => (r.centro || '').trim()).filter(Boolean))); // ALTERADO
        this.costCenters = this._dedupCaseInsensitive([...(persisted || []), ...fromRecords]); // ALTERADO
        localStorage.setItem(core.storageKeys.COST_CENTERS, JSON.stringify(this.costCenters)); // ALTERADO
        window.DMF_CONTEXT.centrosCusto = this.costCenters; // ALTERADO
        window.DMF_CONTEXT.centroEmpresaOverrides = this.centerCompanyOverrides;
        window.DMF_CONTEXT.pagamentos = this.records;
        window.DMF_CONTEXT.assinaturas = this.records.filter(r => r.assinatura);
        window.DMF_CONTEXT.currentCompany = this.currentCompany;
        if (window.DMF_CONTEXT) {
            window.DMF_CONTEXT.archives = this.archives;
        }
        window.DMF_BRAIN.pagamentos = this.records;
        window.DMF_BRAIN.assinaturas = this.records.filter(r => r.assinatura);
        console.log('DMF_CONTEXT after DataProcessor init:', window.DMF_CONTEXT);
        console.log('DMF_BRAIN after DataProcessor init:', window.DMF_BRAIN);
    }

    parsePaymentDate(value) {
        if (!value) return null;
        if (value instanceof Date) return value;
        const raw = String(value).trim();
        if (!raw || raw.toLowerCase() === 'pendente') return null;
        const iso = new Date(raw);
        if (!isNaN(iso.getTime())) return iso;
        const match = raw.match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
        if (match) {
            const [_, dd, mm, yyyy] = match;
            const d = new Date(Number(yyyy), Number(mm) - 1, Number(dd));
            return isNaN(d.getTime()) ? null : d;
        }
        return null;
    }

    getPaymentsByMonth(monthKey) {
        const target = String(monthKey || '').trim();
        if (!target) return [...(this.records || [])];
        return (this.records || []).filter(p => {
            const d = this.parsePaymentDate(p.data);
            if (!d) return false;
            const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
            return key === target;
        });
    }

    getCompanyTotalsForMonth(monthKey) {
        const original = this.records;
        const filtered = this.getPaymentsByMonth(monthKey);
        this.records = filtered;
        const totals = this.getCompanyTotals();
        this.records = original;
        return totals;
    }

    getCostCenterTotalsForMonth(monthKey) {
        const filtered = this.getPaymentsByMonth(monthKey);
        const totals = {};
        filtered.forEach(p => {
            const key = String(p.centro || 'Sem centro').trim() || 'Sem centro';
            totals[key] = (totals[key] || 0) + Math.abs(Number(p.valor) || 0);
        });
        return totals;
    }

    nextFlowBackoffDelay() {
        const base = 15000;
        const max = 120000;
        if (!this.flowFetchBackoff) {
            this.flowFetchBackoff = base;
        } else {
            this.flowFetchBackoff = Math.min(max, this.flowFetchBackoff * 2);
        }
        return this.flowFetchBackoff;
    }

    normalizeCompany(value) {
        const v = String(value || '').trim().toLowerCase();
        if (v === 'real energy' || v === 'real' || v === 'realenergy') return 'Real Energy';
        if (v === 'jfx') return 'JFX';
        if (v === 'dmf') return 'DMF';
        return value || 'DMF';
    }

    companyKey(value) {
        const c = this.normalizeCompany(value);
        if (c === 'Real Energy') return 'REAL_ENERGY';
        return c;
    }

    getPaymentsStorageKey(company) {
        const key = this.companyKey(company);
        return `${this.core.storageKeys.PAYMENTS}_${key}`;
    }

    loadCompanyPayments(company) {
        try {
            const raw = localStorage.getItem(this.getPaymentsStorageKey(company));
            return raw ? JSON.parse(raw) : [];
        } catch (_) {
            return [];
        }
    }

    userCompanyKey() {
        const u = this.core?.currentUser;
        const raw = u?.id || u?.email || u?.username || null;
        if (!raw) return null;
        const safe = String(raw).trim().toLowerCase().replace(/[^a-z0-9@._-]+/g, '_');
        return `dmf_current_company_${safe}`;
    }

    setCurrentCompany(company) {
        this.currentCompany = this.normalizeCompany(company);
        localStorage.setItem(this.core.storageKeys.CURRENT_COMPANY, this.currentCompany);
        try {
            const k = this.userCompanyKey();
            if (k) localStorage.setItem(k, this.currentCompany);
        } catch (_) {}
        this.records = this.loadCompanyPayments(this.currentCompany);
        window.DMF_CONTEXT.pagamentos = this.records;
        window.DMF_CONTEXT.assinaturas = this.records.filter(r => r.assinatura);
        window.DMF_CONTEXT.currentCompany = this.currentCompany;
        if (window.DMF_BRAIN) {
            window.DMF_BRAIN.pagamentos = this.records;
            window.DMF_BRAIN.assinaturas = this.records.filter(r => r.assinatura);
        }
    }

    resetFlowBackoff() {
        this.flowFetchBackoff = 0;
        this.flowFetchCooldownUntil = 0;
    }

    async loadFromBackend(force = false, companyOverride = null) {
        const company = this.normalizeCompany(companyOverride || this.currentCompany);
        const now = Date.now();
        if (this.flowFetchInFlight) return false;
        if (!force) {
            const sharedKey = 'dmf_flow_fetch_last';
            const sharedLast = Number(localStorage.getItem(sharedKey) || 0);
            if (sharedLast && now - sharedLast < this.flowFetchMinInterval) {
                return false;
            }
            if (now < this.flowFetchCooldownUntil) {
                return false;
            }
            if (now - this.flowFetchLastAt < this.flowFetchMinInterval) {
                return false;
            }
        }
        setFlowSyncStatus('Sincronizando com o servidor...', 'info');
        this.flowFetchInFlight = true;
        this.flowFetchLastAt = now;
        try { localStorage.setItem('dmf_flow_fetch_last', String(now)); } catch (_) {}
        try {
            const response = await fetch(`${getApiBase()}/api/flow-payments?company=${encodeURIComponent(company)}`, {
                cache: 'no-store',
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                }
            });
            if (!response.ok) {
                if (response.status === 401) {
                    console.warn('Flow payments fetch unauthorized');
                    setFlowSyncStatus('Sessão expirada. Faça login novamente.', 'warn');
                    try { hardLogout(); } catch (_) {}
                    this.resetFlowBackoff();
                    return false;
                }
                if (response.status === 403) {
                    console.warn('Flow payments fetch forbidden');
                    setFlowSyncStatus('Sem permissão para acessar o fluxo.', 'warn');
                    this.resetFlowBackoff();
                    return false;
                }
                if (response.status === 409) {
                    setFlowSyncStatus('Conflito de versão detectado. Recarregue o fluxo.', 'warn');
                    showToast('Conflito de versão. Recarregue os dados.', 'warn');
                    return false;
                }
                if (response.status === 429 || response.status >= 500) {
                    const delay = this.nextFlowBackoffDelay();
                    this.flowFetchCooldownUntil = Date.now() + delay;
                    setFlowSyncStatus(`Muitas solicitações. Reenviando em ${Math.ceil(delay / 1000)}s.`, 'warn');
                    showToast('Servidor ocupado. Vamos tentar novamente em instantes.', 'warn');
                    console.warn('Flow payments fetch throttled:', response.status);
                    return false;
                }
                console.warn('Flow payments fetch failed:', response.status);
                if (response.status !== 401 && response.status !== 403) {
                    setFlowSyncStatus('Falha ao sincronizar. Tente novamente.', 'error');
                    showToast('Falha ao sincronizar pagamentos.', 'error');
                }
                return false;
            }
            if (response.status === 304) {
                setFlowSyncStatus(`Sem alterações. Última verificação: ${formatTimeNow()}`, 'ok');
                this.lastSyncAt = new Date();
                this.resetFlowBackoff();
                return true;
            }
            const data = await response.json();
            const incoming = (data.payments || []).map(p => ({
                ...p,
                company: p.company || company
            }));
            incoming.sort((a, b) => {
                const aTime = a.created_at ? new Date(a.created_at).getTime() : 0;
                const bTime = b.created_at ? new Date(b.created_at).getTime() : 0;
                if (aTime !== bTime) return aTime - bTime;
                return String(a.id).localeCompare(String(b.id));
            });
            this.records = incoming;
            this.currentCompany = company;
            this.save();
            window.DMF_CONTEXT.pagamentos = this.records;
            window.DMF_CONTEXT.assinaturas = this.records.filter(r => r.assinatura);
            window.DMF_CONTEXT.currentCompany = this.currentCompany;
            if (window.DMF_BRAIN) {
                window.DMF_BRAIN.pagamentos = this.records;
                window.DMF_BRAIN.assinaturas = this.records.filter(r => r.assinatura);
            }
            if (this.records.length) {
                setFlowSyncStatus(`Sincronizado às ${formatTimeNow()}`, 'ok');
            } else {
                setFlowSyncStatus('Nenhum pagamento encontrado no servidor.', 'warn');
            }
            this.lastSyncAt = new Date();
            this.resetFlowBackoff();
            return true;
        } catch (error) {
            console.warn('Flow payments fetch unavailable:', error.message);
            setFlowSyncStatus('Servidor indisponível. Tente novamente.', 'error');
            showToast('Servidor indisponível. Tente novamente.', 'error');
            const delay = this.nextFlowBackoffDelay();
            this.flowFetchCooldownUntil = Date.now() + delay;
            return false;
        } finally {
            this.flowFetchInFlight = false;
        }
    }

    async loadArchivesFromBackend(filters = {}) {
        try {
            const params = new URLSearchParams();
            if (filters.start) params.set('start', filters.start);
            if (filters.end) params.set('end', filters.end);
            params.set('company', this.currentCompany);
            const response = await fetch(`${getApiBase()}/api/flow-archives${params.toString() ? `?${params}` : ''}`, {
                cache: 'no-store',
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                }
            });
            if (!response.ok) {
                console.warn('Flow archives fetch failed:', response.status);
                return false;
            }
            const data = await response.json();
            this.archives = Array.isArray(data.archives) ? data.archives : [];
            if (window.DMF_CONTEXT) {
                window.DMF_CONTEXT.archives = this.archives;
            }
            return true;
        } catch (error) {
            console.warn('Flow archives fetch unavailable:', error.message);
            return false;
        }
    }

    async archiveCurrentFlow() {
        try {
            const response = await fetch(`${getApiBase()}/api/flow-archives?company=${encodeURIComponent(this.currentCompany)}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                }
            });
            if (!response.ok) {
                const payload = await response.json().catch(() => ({}));
                if (response.status === 400 && payload?.pending) {
                    alert(`Existem ${payload.pending} pagamentos pendentes de assinatura.`);
                    return false;
                }
                alert(payload?.error || 'Não foi possível arquivar o fluxo.');
                return false;
            }
            const data = await response.json();
            this.records = [];
            this.save();
            window.DMF_CONTEXT.pagamentos = this.records;
            window.DMF_CONTEXT.assinaturas = [];
            window.DMF_CONTEXT.currentCompany = this.currentCompany;
            await this.loadArchivesFromBackend();
            return data?.archive || null;
        } catch (error) {
            console.warn('Flow archive create failed:', error.message);
            alert('Falha ao enviar para Fluxos Anteriores.');
            return false;
        }
    }

    async deleteArchive(id) {
        try {
            const response = await fetch(`${getApiBase()}/api/flow-archives/${id}`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                }
            });
            if (!response.ok) {
                const payload = await response.json().catch(() => ({}));
                alert(payload?.error || 'Não foi possível excluir o fluxo.');
                return false;
            }
            await this.loadArchivesFromBackend();
            return true;
        } catch (error) {
            console.warn('Flow archive delete failed:', error.message);
            alert('Falha ao excluir o fluxo anterior.');
            return false;
        }
    }

    exportArchive(archive) {
        if (!archive) return;
        if (!this.core.admin.hasPermission(this.core.currentUser, 'export_archives') &&
            !this.core.admin.hasPermission(this.core.currentUser, 'export_payments')) {
            alert('Você não tem permissão para exportar fluxos anteriores.');
            return;
        }
        const payments = Array.isArray(archive.payments) ? archive.payments : [];
        const header = [
            'Fornecedor',
            'Data',
            'Descrição',
            'Valor',
            'Centro de Custo',
            'Categoria',
            'Status',
            'Assinatura',
            'ID da Assinatura'
        ];
        const rows = payments.map(p => ([
            p.fornecedor,
            p.data,
            p.descricao || "",
            p.valor,
            p.centro,
            p.categoria || "",
            p.assinatura ? 'Assinado' : 'Pendente',
            p.assinatura
                ? `Assinado por ${p.assinatura.usuarioNome} em ${new Date(p.assinatura.dataISO).toLocaleString('pt-BR')}`
                : '-',
            p.assinatura?.hash || '-'
        ]));
        const aoa = [header, ...rows];
        const ws = XLSX.utils.aoa_to_sheet(aoa);
        const wb = XLSX.utils.book_new();
        XLSX.utils.book_append_sheet(wb, ws, "Fluxo Arquivado");
        const safeLabel = String(archive.label || 'Fluxo_Arquivado').replace(/[\\/:*?"<>|]/g, '-');
        XLSX.writeFile(wb, `${safeLabel}.xlsx`);
    }

    import(input) {
        if (!this.core.admin.hasPermission(this.core.currentUser, 'import_payments')) {
            alert('Você não tem permissão para importar o fluxo de pagamentos.');
            input.value = '';
            return;
        }
        const file = input.files[0];
        if (!file) {
            console.warn('Nenhum arquivo selecionado');
            return;
        }

        console.log('Arquivo importado:', file.name);

        const reader = new FileReader();

        reader.onload = (e) => {
            try {
                const data = new Uint8Array(e.target.result);
                const workbook = XLSX.read(data, { type: 'array' });
                const sheet = workbook.Sheets[workbook.SheetNames[0]];
                const rows = XLSX.utils.sheet_to_json(sheet, { defval: '' });

                console.log('Linhas lidas do Excel:', rows);

                // ETL: Mapeamento conforme código Conta Azul original
                // Identificar headers disponíveis
                const headers = Object.keys(rows[0] || {});
                const possiveisDescricoes = ["Descrição", "Historico", "Histórico", "Observação", "Observacao", "Memo"];
                let campoDescricao = possiveisDescricoes.find(c => headers.includes(c));

                console.log('Headers encontrados:', headers);
                console.log('Campo de descrição identificado:', campoDescricao);

                const newPayments = rows.map(r => {
                    const descricao = campoDescricao ? (r[campoDescricao]?.trim() || "") : "";

                    return {
                        id: (Date.now() + Math.random()).toString(),
                        company: this.currentCompany,
                        fornecedor: r['Nome do fornecedor'] || 'N/A',
                        data: r['Data prevista'] || 'Pendente',
                        descricao: descricao,
                        valor: Math.abs(Number(r['Valor no Centro de Custo 1'] || r['Valor original da parcela (R$)'] || 0)),
                        centro: String(r['Centro de Custo 1'] || '').trim(),
                        categoria: r['Categoria'] || r['Categoria 1'] || r['Categoria da despesa'] || '',
                        assinatura: null,
                        timestamp: new Date().toISOString()
                    };
                });

                console.log('Pagamentos processados:', newPayments);

                const novosCentros = Array.from(new Set(newPayments.map(p => p.centro).filter(Boolean))); // ALTERADO
                novosCentros.forEach(c => this.ensureCostCenter(c)); // ALTERADO

                this.records = [...this.records, ...newPayments];
                this.save();
                window.DMF_CONTEXT.pagamentos = this.records;
                window.DMF_CONTEXT.assinaturas = this.records.filter(r => r.assinatura);
                console.log('DMF_CONTEXT after import:', window.DMF_CONTEXT);
                this.syncImportToBackend().catch(() => {});
                this.core.ui.renderPaymentsTable();
                this.core.audit.log('IMPORTAÇÃO', `Importado arquivo com ${newPayments.length} registros.`);
            } catch (error) {
                console.error('Erro ao processar arquivo Excel:', error);
                alert('Erro ao processar o arquivo. Verifique o console para detalhes.');
            }
        };

        reader.onerror = (error) => {
            console.error('Erro ao ler arquivo:', error);
            alert('Erro ao ler o arquivo.');
        };

        reader.readAsArrayBuffer(file);
    }

    async sign(id) { // ALTERADO
        if (!this.core.currentUser) {
            alert('Você precisa estar logado para assinar pagamentos.');
            return false;
        }
        if (!this.core.admin.hasPermission(this.core.currentUser, 'sign_payments')) {
            alert('Você não tem permissão para assinar pagamentos.');
            return false;
        }
        const idx = this.records.findIndex(r => r.id === id);
        if (idx === -1) return false; // ALTERADO
        const r = this.records[idx];
        if (!this.core.admin.canSignCenter(this.core.currentUser, r.centro)) {
            alert('Você não tem permissão para assinar este centro de custo.');
            return false;
        }
        if (r.assinatura) return true; // já assinado // ALTERADO

        const u = this.core.currentUser || {};
        const nomeSeguro = (value) => {
            const v = String(value || '').trim();
            return v;
        };
        const displayName = (() => {
            const nome = nomeSeguro(u.nome || u.name);
            if (nome && !nome.includes('@')) return nome;
            const usuario = nomeSeguro(u.usuario || u.username);
            if (usuario) return usuario;
            const email = nomeSeguro(u.email);
            return email || 'Usuário';
        })();
        const usuarioNome = displayName; // ALTERADO
        const dataISO = new Date().toISOString(); // ALTERADO
        let hash = null;
        try {
            const response = await fetch(`${getApiBase()}/api/signatures/hmac`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                },
                body: JSON.stringify({
                    paymentId: id,
                    userName: usuarioNome,
                    dataISO,
                    valor: r.valor || '',
                    centro: r.centro || ''
                })
            });
            if (!response.ok) {
                alert('Falha ao gerar assinatura segura.');
                return false;
            }
            const data = await response.json();
            hash = data.hash;
        } catch (error) {
            console.warn('Signature hash unavailable:', error.message);
            alert('Falha ao gerar assinatura segura.');
            return false;
        }

        r.assinatura = { usuarioNome, dataISO, hash }; // ALTERADO
        this.records[idx] = r; // ALTERADO
        this.save(); // ALTERADO
        try {
            const response = await fetch(`${getApiBase()}/api/flow-payments/${id}/sign?company=${encodeURIComponent(this.currentCompany)}`, {
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                },
                body: JSON.stringify({ assinatura: r.assinatura, company: this.currentCompany })
            });
            if (response.status === 409) {
                showToast('Pagamento já foi assinado por outro usuário.', 'warn');
                await this.loadFromBackend(true, this.currentCompany);
                this.core?.ui?.renderPaymentsTable?.();
                return false;
            }
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
        } catch (error) {
            console.warn('Flow payment sign sync failed:', error.message);
            this.core.sync.enqueue({ type: 'sign', data: { id, assinatura: r.assinatura, company: this.currentCompany } });
        }

        try { // manter telemetria/contexto, sem quebrar se não existir
            if (window.DMF_CONTEXT) {
                window.DMF_CONTEXT.pagamentos = this.records;
                window.DMF_CONTEXT.assinaturas = this.records.filter(x => x.assinatura);
            }
            if (window.DMF_BRAIN) {
                window.DMF_BRAIN.pagamentos = this.records;
                window.DMF_BRAIN.assinaturas = this.records.filter(x => x.assinatura);
            }
        } catch(e) { console.warn('sync ctx/brain falhou', e); } // ALTERADO

        // Auditoria e evento (se disponíveis)
            this.core?.audit?.log?.('ASSINATURA', `Pagamento ${r.fornecedor} assinado por ${usuarioNome}`, 'assinatura', id); // ALTERADO
        try { registrarEvento('pagamento_assinado', this.core.currentUser, `Assinado: ${r.fornecedor}`, 'pagamento'); } catch(_) {} // ALTERADO

        // Atualizar UI
        this.core?.ui?.renderPaymentsTable?.(); // ALTERADO
        return true; // ALTERADO
    }

    save() {
        localStorage.setItem(this.getPaymentsStorageKey(this.currentCompany), JSON.stringify(this.records));
    }

    async syncImportToBackend() {
        setFlowSyncStatus('Sincronizando importação...', 'info');
        try {
            const response = await fetch(`${getApiBase()}/api/flow-payments/import?company=${encodeURIComponent(this.currentCompany)}`, {
                method: 'POST',
                cache: 'no-store',
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                },
                body: JSON.stringify({ company: this.currentCompany, payments: this.records })
            });
            if (!response.ok) {
                if (response.status === 401) {
                    alert('Sessão expirada. Faça login novamente para sincronizar o fluxo.');
                    setFlowSyncStatus('Sessão expirada. Faça login novamente.', 'warn');
                    try { hardLogout(); } catch (_) {}
                }
                if (response.status === 403) {
                    alert('Sem permissão para sincronizar o fluxo.');
                    setFlowSyncStatus('Sem permissão para sincronizar o fluxo.', 'warn');
                }
                console.warn('Flow payments import failed:', response.status);
                if (response.status !== 401 && response.status !== 403) {
                    setFlowSyncStatus('Falha ao sincronizar importação.', 'error');
                }
                this.core.sync.enqueue({ type: 'import', data: { company: this.currentCompany, payments: this.records } });
                return;
            }
            setFlowSyncStatus(`Importação sincronizada às ${formatTimeNow()}`, 'ok');
        } catch (error) {
            console.warn('Flow payments import unavailable:', error.message);
            setFlowSyncStatus('Servidor indisponível para importação.', 'error');
            this.core.sync.enqueue({ type: 'import', data: { company: this.currentCompany, payments: this.records } });
        }
    }

    getCompanyTotals() {
        const empresas = this.getCompanyCenterMap();
        const totals = {};
        Object.keys(empresas).forEach(company => {
            totals[company] = 0;
        });
        totals.Outros = 0;

        (this.records || []).forEach((p) => {
            const valor = Math.abs(Number(p.valor) || 0);
            const company = this.getPaymentCompany(p);
            totals[company] = (totals[company] || 0) + valor;
        });

        return totals;
    }

    getCompanyCenterTotals() {
        const totalsByCompany = {};
        (this.records || []).forEach((p) => {
            const company = this.getPaymentCompany(p);
            const center = String(p.centro || 'Sem centro').trim() || 'Sem centro';
            const valor = Math.abs(Number(p.valor) || 0);
            if (!totalsByCompany[company]) {
                totalsByCompany[company] = { total: 0, centers: {} };
            }
            totalsByCompany[company].total += valor;
            totalsByCompany[company].centers[center] = (totalsByCompany[company].centers[center] || 0) + valor;
        });
        return totalsByCompany;
    }
    
    export(companyFilter = null) {
        if (!this.core.admin.hasPermission(this.core.currentUser, 'export_payments')) {
            alert('Você não tem permissão para exportar o fluxo de pagamentos.');
            return;
        }
        const maxExportRows = 2000;
        const isAdmin = this.core.admin.hasPermission(this.core.currentUser, 'admin_access');
        const normalizeCompany = (value) => {
            const v = String(value || '').trim().toLowerCase();
            if (v === 'real energy' || v === 'real' || v === 'realenergy') return 'Real Energy';
            if (v === 'jfx') return 'JFX';
            if (v === 'dmf') return 'DMF';
            return value || null;
        };
        const filterCompany = companyFilter && companyFilter !== 'ALL'
            ? normalizeCompany(companyFilter)
            : this.currentCompany;
        const filtered = filterCompany
            ? (this.records || []).filter(p => {
                const c = this.getPaymentCompany(p);
                return c === filterCompany;
            })
            : (this.records || []);

        const totalCount = filtered.length;
        if (totalCount > maxExportRows && !isAdmin) {
            alert(`Exportação bloqueada: limite de ${maxExportRows} registros. Contate o admin.`);
            try {
                this.core.audit.log('EXPORTAÇÃO BLOQUEADA', `Tentativa de exportar ${totalCount} registros (limite ${maxExportRows}).`);
                fetch(`${getApiBase()}/api/audit/events`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        ...getAuthHeaders()
                    },
                    body: JSON.stringify({
                        action: 'EXPORT_BLOCKED',
                        details: `Tentativa de exportar ${totalCount} registros (limite ${maxExportRows}).`,
                        metadata: { company: filterCompany || 'ALL', count: totalCount, limit: maxExportRows }
                    })
                }).catch(() => {});
            } catch (_) {}
            return;
        }
        if (totalCount > maxExportRows && isAdmin) {
            const ok = confirm(`Você está prestes a exportar ${totalCount} registros. Deseja continuar?`);
            if (!ok) return;
        }

        const dates = filtered.map(p => this.parsePaymentDate(p.data)).filter(Boolean);
        const minDate = dates.length ? new Date(Math.min(...dates.map(d => d.getTime()))) : null;
        const maxDate = dates.length ? new Date(Math.max(...dates.map(d => d.getTime()))) : null;
        const exportMeta = {
            company: filterCompany || 'ALL',
            count: totalCount,
            periodStart: minDate ? minDate.toISOString() : null,
            periodEnd: maxDate ? maxDate.toISOString() : null,
            filters: {
                query: this.core?.ui?.paymentFilters?.query || '',
                pendingOnly: !!this.core?.ui?.paymentFilters?.pendingOnly
            }
        };
        try {
            this.core.audit.log('EXPORTAÇÃO', `Exportado ${totalCount} registros (${exportMeta.company}).`);
            fetch(`${getApiBase()}/api/audit/events`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                },
                body: JSON.stringify({
                    action: 'EXPORT_FLOW',
                    details: `Exportado ${totalCount} registros (${exportMeta.company}).`,
                    metadata: exportMeta
                })
            }).catch(() => {});
        } catch (_) {}
        // Preparar dados para exportação na ordem da tabela
        const header = [
            'Fornecedor',
            'Data',
            'Descrição',
            'Valor',
            'Categoria',
            'Centro de Custo',
            'Assinatura',
            'ID da Assinatura'
        ];

        const rows = filtered.map(p => ([
            p.fornecedor,
            p.data,
            p.descricao || "",
            p.valor,
            p.categoria || "",
            p.centro,
            p.assinatura
                ? `Assinado por ${p.assinatura.usuarioNome} em ${new Date(p.assinatura.dataISO).toLocaleString('pt-BR')}` // ALTERADO
                : '-',
            p.assinatura?.hash || '-'
        ]));

        const aoa = [header, ...rows];

        const buildTotalsForExport = (items) => {
            const totalsByCompany = {};
            items.forEach((p) => {
                const company = this.getPaymentCompany(p);
                const center = String(p.centro || 'Sem centro').trim() || 'Sem centro';
                const valor = Math.abs(Number(p.valor) || 0);
                if (!totalsByCompany[company]) {
                    totalsByCompany[company] = { total: 0, centers: {} };
                }
                totalsByCompany[company].total += valor;
                totalsByCompany[company].centers[center] = (totalsByCompany[company].centers[center] || 0) + valor;
            });
            return totalsByCompany;
        };

        const totalsByCompany = buildTotalsForExport(filtered);
        const companies = Object.keys(totalsByCompany)
            .sort((a, b) => (totalsByCompany[b]?.total || 0) - (totalsByCompany[a]?.total || 0));

        if (companies.length) {
            const emptyRow = new Array(header.length).fill('');
            aoa.push(emptyRow, emptyRow, emptyRow, emptyRow);

            const pushMemoryRow = (label, value = '') => {
                const row = new Array(header.length).fill('');
                row[3] = label; // Coluna D
                if (value) row[4] = { t: 's', v: value }; // Coluna E (texto)
                aoa.push(row);
            };

            pushMemoryRow('Memória de calculos');
            companies.forEach((company) => {
                const entry = totalsByCompany[company];
                pushMemoryRow(company, `R$ ${entry.total.toLocaleString('pt-BR')}`);
                Object.entries(entry.centers)
                    .sort((a, b) => b[1] - a[1])
                    .forEach(([center, total]) => {
                        pushMemoryRow(`- ${center}`, `R$ ${total.toLocaleString('pt-BR')}`);
                    });
            });
        }
        const ws = XLSX.utils.aoa_to_sheet(aoa);
        const wb = XLSX.utils.book_new();
        const sheetName = filterCompany ? `Fluxo ${filterCompany}` : "Fluxo";
        const fileName = filterCompany ? `Fluxo_${String(filterCompany).replace(/\s+/g, '_')}.xlsx` : "Fluxo_Pagamentos.xlsx";
        XLSX.utils.book_append_sheet(wb, ws, sheetName);
        XLSX.writeFile(wb, fileName);
    }

    clearAll() {
        if (confirm('Tem certeza que deseja remover todo o fluxo de pagamentos? Esta ação não pode ser desfeita.')) {
            this.records = [];
            this.save();
            window.DMF_CONTEXT.pagamentos = this.records;
            window.DMF_CONTEXT.assinaturas = this.records.filter(r => r.assinatura);
            console.log('DMF_CONTEXT after clearAll:', window.DMF_CONTEXT);
            this.core.ui.renderPaymentsTable();
            this.core.audit.log('LIMPEZA', 'Todo o fluxo de pagamentos foi removido.');
            this.syncImportToBackend().catch(() => {});
            alert('Fluxo de pagamentos removido com sucesso.');
        }
    }

    // === Utilitários para Centros de Custo === // ALTERADO
    _norm(s){ return String(s||'').trim(); } // ALTERADO
    _key(s){ return this._norm(s).toLowerCase(); } // ALTERADO
    _dedupCaseInsensitive(arr){ // ALTERADO
      const seen = new Set(); const out = [];
      (arr||[]).forEach(v => { const k=this._key(v); if(k && !seen.has(k)){ seen.add(k); out.push(this._norm(v)); }});
      return out;
    } // ALTERADO

    getCostCenters(){ return [...(this.costCenters||[])].sort(); } // ALTERADO
    hasCostCenter(name){ return (this.costCenters||[]).some(c => this._key(c) === this._key(name)); } // ALTERADO
    ensureCostCenter(name){ // ALTERADO
      const n = this._norm(name);
      if(!n) return false;
      if(!this.hasCostCenter(n)){
        this.costCenters.push(n);
        this.costCenters = this._dedupCaseInsensitive(this.costCenters);
        localStorage.setItem(this.core.storageKeys.COST_CENTERS, JSON.stringify(this.costCenters));
        window.DMF_CONTEXT.centrosCusto = this.costCenters;
        this.core.audit?.log?.('NOVO CENTRO', `Centro de Custo adicionado: ${n}`, 'centro_de_custo'); // ALTERADO
        try { registrarEvento('centro_novo', this.core.currentUser, `Centro criado: ${n}`, 'centro'); } catch(e){} // ALTERADO
        if (!this.getCenterCompanyOverride(n) && !this.pendingCenterAssignments.has(this._key(n))) {
          this.pendingCenterAssignments.add(this._key(n));
          this.core?.ui?.openCenterAssignmentModal?.(n);
        }
      }
      return true;
    } // ALTERADO

    getCompanyCenterMap() {
        return {
            JFX: ['RECAP', 'EDISER'],
            DMF: [
                'Reisolamento Campina Grande',
                'Reisolamento Natal',
                'Administração Central',
                'Administração Central ADJ',
                'Despesas Pessoais',
                'Manutenção Civil Sede e Subestação',
                'Manutenção Civil AL/PE',
                'Manutenção Civil Bahia',
            ],
            'Real Energy': ['Campos Novos', 'Vitória da Conquista']
        };
    }

    getCompanyForCenter(center) {
        const normalize = (value) => String(value || '').trim().toLowerCase();
        const target = normalize(center);
        const override = this.getCenterCompanyOverride(center);
        if (override) return override;
        const map = this.getCompanyCenterMap();
        for (const [company, centers] of Object.entries(map)) {
            if (centers.map(normalize).includes(target)) return company;
        }
        return 'Outros';
    }

    loadCenterCompanyOverrides() {
        try {
            const raw = localStorage.getItem('dmf_center_company_overrides');
            return raw ? JSON.parse(raw) : {};
        } catch (_) {
            return {};
        }
    }

    async loadCenterCompanyOverridesFromBackend() {
        const token = localStorage.getItem('dmf_api_token');
        if (!token) return false;
        try {
            const response = await fetch(`${getApiBase()}/api/centers/companies`, {
                cache: 'no-store',
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                }
            });
            if (!response.ok) return false;
            const data = await response.json();
            const items = Array.isArray(data.items) ? data.items : [];
            const overrides = {};
            items.forEach(item => {
                const label = String(item.center_label || item.center || '').trim();
                const key = this._key(item.center_key || label);
                if (!label || !key) return;
                overrides[key] = { company: item.company, label };
            });
            this.centerCompanyOverrides = overrides;
            this.saveCenterCompanyOverrides();
            return true;
        } catch (_) {
            return false;
        }
    }

    saveCenterCompanyOverrides() {
        localStorage.setItem('dmf_center_company_overrides', JSON.stringify(this.centerCompanyOverrides || {}));
        if (window.DMF_CONTEXT) {
            window.DMF_CONTEXT.centroEmpresaOverrides = this.centerCompanyOverrides;
        }
    }

    getCenterCompanyOverride(center) {
        if (!center) return null;
        const key = this._key(center);
        const entry = this.centerCompanyOverrides?.[key];
        if (!entry) return null;
        return this.normalizeCompany(entry.company || entry);
    }

    setCenterCompany(center, company, options = {}) {
        const label = this._norm(center);
        if (!label || !company) return false;
        const key = this._key(label);
        this.centerCompanyOverrides = this.centerCompanyOverrides || {};
        this.centerCompanyOverrides[key] = { company: this.normalizeCompany(company), label };
        this.pendingCenterAssignments?.delete?.(key);
        this.saveCenterCompanyOverrides();
        if (this.core?.currentUser && options.sync !== false) {
            fetch(`${getApiBase()}/api/centers/companies`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                },
                body: JSON.stringify({ center: label, company })
            }).then((res) => {
                if (!res.ok) {
                    showToast('Falha ao salvar centro no servidor.', 'warn');
                }
            }).catch(() => {
                showToast('Falha ao salvar centro no servidor.', 'warn');
            });
        }
        return true;
    }

    getPaymentCompany(payment) {
        if (!payment) return 'Outros';
        if (payment.company) {
            return this.normalizeCompany(payment.company);
        }
        return this.getCompanyForCenter(payment.centro);
    }

    addPayment({ fornecedor, data, descricao, valor, centro, categoria }) { // ALTERADO
        const record = {
            id: (Date.now() + Math.random()).toString(), // ALTERADO
            company: this.currentCompany,
            fornecedor: (fornecedor || '').trim() || 'N/A', // ALTERADO
            data: data || 'Pendente', // ALTERADO
            descricao: (descricao || '').trim(), // ALTERADO
            valor: Math.abs(Number(valor) || 0), // ALTERADO
            centro: (centro || '').trim(), // ALTERADO
            categoria: (categoria || '').trim(),
            assinatura: null, // começa Pendente por regra do sistema // ALTERADO
            timestamp: new Date().toISOString() // ALTERADO
        };
        this.records.push(record); // ALTERADO
        this.ensureCostCenter(record.centro); // registra o centro // ALTERADO
        if (window.assistant) window.assistant.addLearning("centros_de_custo", record.centro); // ALTERADO
        this.save(); // ALTERADO
        this.syncPaymentToBackend(record).catch(() => {});

        // Manter contextos em sincronia (com segurança) // ALTERADO
        try { if (window.DMF_CONTEXT) {
            window.DMF_CONTEXT.pagamentos = this.records;
            window.DMF_CONTEXT.assinaturas = this.records.filter(r => r.assinatura);
        }} catch(e) { console.warn('ctx update falhou', e); } // ALTERADO
        try { if (window.DMF_BRAIN) {
            window.DMF_BRAIN.pagamentos = this.records;
            window.DMF_BRAIN.assinaturas = this.records.filter(r => r.assinatura);
        }} catch(e) { console.warn('brain update falhou', e); } // ALTERADO

        this.core.ui.renderPaymentsTable(); // ALTERADO
        this.core.audit.log('INSERÇÃO MANUAL', `Pagamento criado: ${record.fornecedor} - R$ ${record.valor}`, 'pagamento', record.id); // ALTERADO
        try { registrarEvento('pagamento_adicionado', this.core.currentUser, `Pagamento ${record.fornecedor} adicionado`); } catch(_) {} // ALTERADO

        return record; // ALTERADO
    }

    async syncPaymentToBackend(record) {
        setFlowSyncStatus('Sincronizando pagamento...', 'info');
        try {
            const response = await fetch(`${getApiBase()}/api/flow-payments?company=${encodeURIComponent(this.currentCompany)}`, {
                method: 'POST',
                cache: 'no-store',
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                },
                body: JSON.stringify({ ...record, company: this.currentCompany })
            });
            if (!response.ok) {
                if (response.status === 401) {
                    alert('Sessão expirada. Faça login novamente para sincronizar o pagamento.');
                    setFlowSyncStatus('Sessão expirada. Faça login novamente.', 'warn');
                    try { hardLogout(); } catch (_) {}
                }
                if (response.status === 403) {
                    alert('Sem permissão para sincronizar o pagamento.');
                    setFlowSyncStatus('Sem permissão para sincronizar o pagamento.', 'warn');
                }
                console.warn('Flow payment create failed:', response.status);
                if (response.status !== 401 && response.status !== 403) {
                    setFlowSyncStatus('Falha ao sincronizar pagamento.', 'error');
                }
                this.core.sync.enqueue({ type: 'upsert', data: { ...record, company: this.currentCompany } });
                return;
            }
            setFlowSyncStatus(`Pagamento sincronizado às ${formatTimeNow()}`, 'ok');
        } catch (error) {
            console.warn('Flow payment create unavailable:', error.message);
            setFlowSyncStatus('Servidor indisponível para pagamento.', 'error');
            this.core.sync.enqueue({ type: 'upsert', data: { ...record, company: this.currentCompany } });
        }
    }

    syncFromAPI() {
        alert('Sincronização com Conta Azul desativada temporariamente. Use a importação manual.');
        return;
        const apiBase = getApiBase();
        fetch(`${apiBase}/api/payments`, {
            headers: {
                'Content-Type': 'application/json',
                ...getAuthHeaders()
            }
        })
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                console.log('Dados recebidos da API Conta Azul:', data);

                // Processar os dados da API e mapear para o formato do sistema
                const newPayments = data.map(item => ({
                    id: (Date.now() + Math.random()).toString(),
                    fornecedor: item.fornecedor || item.supplier || 'N/A',
                    data: item.data || item.due_date || 'Pendente',
                    descricao: item.descricao || item.description || '',
                    valor: Math.abs(Number(item.valor || item.amount || 0)),
                    centro: String(item.centro || item.cost_center || '').trim(),
                    assinatura: null,
                    timestamp: new Date().toISOString()
                }));

                // Adicionar novos pagamentos
                newPayments.forEach(payment => {
                    this.records.push(payment);
                    this.ensureCostCenter(payment.centro);
                });

                this.save();
                window.DMF_CONTEXT.pagamentos = this.records;
                window.DMF_CONTEXT.assinaturas = this.records.filter(r => r.assinatura);
                console.log('DMF_CONTEXT after syncFromAPI:', window.DMF_CONTEXT);

                this.core.ui.renderPaymentsTable();
                this.core.audit.log('SINCRONIZAÇÃO API', `Sincronizados ${newPayments.length} pagamentos da API Conta Azul.`);
                alert(`Sincronização concluída! ${newPayments.length} pagamentos importados da API Conta Azul.`);
            })
            .catch(error => {
                console.error('Erro ao sincronizar com API Conta Azul:', error);
                alert(`Erro ao sincronizar com a API Conta Azul: ${error.message || error}. Verifique o console para detalhes.`);
            });
    }

    syncFromCobliAPI() {
        const role = normalizeRole(this.core.currentUser && (this.core.currentUser.cargo || this.core.currentUser.role));
        if (role !== 'admin') {
            alert('Somente o cargo ADMIN pode importar/sincronizar o fluxo de pagamentos.');
            return;
        }
        const apiBase = getApiBase();
        fetch(`${apiBase}/api/cobli/payments`, {
            headers: {
                'Content-Type': 'application/json',
                ...getAuthHeaders()
            }
        })
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                console.log('Dados recebidos da API Cobli:', data);

                // Processar os dados da API Cobli e mapear para o formato do sistema DMF
                const newPayments = data.map(item => ({
                    id: (Date.now() + Math.random()).toString(),
                    fornecedor: item.supplier || item.fornecedor || 'N/A',
                    data: item.due_date || item.data || 'Pendente',
                    descricao: item.description || item.descricao || '',
                    valor: Math.abs(Number(item.amount || item.valor || 0)),
                    centro: String(item.cost_center || item.centro || '').trim(),
                    assinatura: null,
                    timestamp: new Date().toISOString()
                }));

                // Adicionar novos pagamentos
                newPayments.forEach(payment => {
                    this.records.push(payment);
                    this.ensureCostCenter(payment.centro);
                });

                this.save();
                window.DMF_CONTEXT.pagamentos = this.records;
                window.DMF_CONTEXT.assinaturas = this.records.filter(r => r.assinatura);
                console.log('DMF_CONTEXT after syncFromCobliAPI:', window.DMF_CONTEXT);

                this.core.ui.renderPaymentsTable();
                this.core.audit.log('SINCRONIZAÇÃO COBLI', `Sincronizados ${newPayments.length} pagamentos da API Cobli.`);
                alert(`Sincronização Cobli concluída! ${newPayments.length} pagamentos importados da API Cobli.`);
            })
            .catch(error => {
                console.error('Erro ao sincronizar com API Cobli:', error);
                alert(`Erro ao sincronizar com a API Cobli: ${error.message || error}. Verifique o console para detalhes.`);
            });
    }
}

class UIManager {
    constructor(core) {
        this.core = core;
        this.paymentFilters = { query: '', pendingOnly: false };
        this.paymentsFilterTimer = null;
        this.userStatusInFlight = false;
        this.userStatusLastAt = 0;
        this.userStatusMinInterval = 60000;
        this.companyFilter = 'DMF';
        this.selectedArchiveId = null;
        this.flowSyncIntervalMs = 3000;
        this.flowNextSyncAt = null;
        this.flowEventSource = null;
        this.flowStreamReconnectTimer = null;
        this.flowStreamReconnectMs = 2000;
        this.dashboardSyncTimer = null;
        this.pendingCenterCompanyUpdates = new Map();
    }

    navigate(viewId, activeButton = null) {
        if (viewId === 'admin' && !this.core.admin.hasPermission(this.core.currentUser, 'admin_access')) {
            this.showAccessDenied({
                title: 'Acesso negado',
                message: 'Você não tem permissão para acessar a aba Administração. Peça ao administrador para liberar o acesso.'
            }, activeButton);
            return;
        }
        if (viewId === 'audit' && !this.core.admin.hasPermission(this.core.currentUser, 'audit_access')) {
            this.showAccessDenied({
                title: 'Acesso negado',
                message: 'Você não tem permissão para acessar os Logs de Auditoria. Peça ao administrador para liberar o acesso.'
            }, activeButton);
            return;
        }
        document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
        document.getElementById(viewId).classList.remove('hidden');
        // Update active button
        document.querySelectorAll('.btn-side').forEach(btn => btn.classList.remove('active'));
        if (activeButton) activeButton.classList.add('active');

        // Special handling for Cobli tab
        if (viewId === 'cobli') {
            this.core.cobli.navigateToCobli().catch(err => {
                console.error('Erro ao carregar Cobli:', err.message);
            });
        }

        if (viewId === 'admin') {
            this.core.admin.refreshUsersFromApi().then(() => {
                this.renderUsersTable();
            });
        }

        if (viewId === 'payments') {
            this.startFlowAutoRefresh();
        } else {
            this.stopFlowAutoRefresh();
        }

        if (viewId === 'payments') {
            const company = activeButton?.getAttribute?.('data-company');
            if (company) {
                this.setCompanyFilter(company);
                this.core.data.setCurrentCompany(company);
                this.core.data.loadFromBackend(true, company).then(() => {
                    this.renderPaymentsTable();
                    this.updateStats();
                });
            }
        }
    }

    showLogin() {
        document.getElementById('appSection').classList.add('hidden');
        document.getElementById('loginSection').classList.remove('hidden');
        // Ensure background timers/streams don't keep running after logout.
        this.stopFlowAutoRefresh();
        this.stopDashboardSummaryAutoRefresh();
    }

    showAccessDenied({ title, message }, activeButton = null) {
        const view = document.getElementById('accessDenied');
        if (!view) return;

        // Stop background activity for views that might have been active.
        this.stopFlowAutoRefresh();
        this.stopDashboardSummaryAutoRefresh();

        document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
        view.classList.remove('hidden');

        document.querySelectorAll('.btn-side').forEach(btn => btn.classList.remove('active'));
        if (activeButton) activeButton.classList.add('active');

        const safeTitle = String(title || 'Acesso negado');
        const safeMsg = String(message || 'Você não tem permissão para acessar esta aba.');
        view.innerHTML = `
            <div class="access-denied-wrap">
                <div class="access-denied-card">
                    <h2 class="access-denied-title">${safeTitle}</h2>
                    <p class="access-denied-msg">${safeMsg}</p>
                    <div class="access-denied-actions">
                        <button class="btn btn-primary" type="button" data-access-denied-go="dashboard">Voltar ao Dashboard</button>
                        <button class="btn btn-ghost" type="button" data-access-denied-go="payments">Ir para o Fluxo</button>
                    </div>
                </div>
            </div>
        `;

        const onClick = (e) => {
            const btn = e.target.closest('button[data-access-denied-go]');
            if (!btn) return;
            const target = String(btn.getAttribute('data-access-denied-go') || '').trim();
            if (target === 'dashboard') {
                this.navigate('dashboard', document.querySelector('[data-nav="dashboard"]'));
                return;
            }
            if (target === 'payments') {
                const first = this.getFirstAvailableCompanyButton();
                this.navigate('payments', first || document.querySelector('[data-nav="payments"]'));
            }
        };
        if (!view.dataset.bound) {
            view.addEventListener('click', onClick);
            view.dataset.bound = 'true';
        }
    }

    initQuickActions() {
        const btnImport = document.getElementById('btnQuickImport');
        const btnExport = document.getElementById('btnQuickExport');
        if (btnImport) {
            btnImport.addEventListener('click', () => {
                this.navigate('payments', document.querySelector('[data-nav="payments"]'));
                setTimeout(() => document.getElementById('btnImportPayments')?.click(), 50);
            });
        }
        if (btnExport) {
            btnExport.addEventListener('click', () => {
                this.navigate('payments', document.querySelector('[data-nav="payments"]'));
                setTimeout(() => document.getElementById('btnExportPayments')?.click(), 50);
            });
        }
    }

    initPaymentsFilters() {
        const input = document.getElementById('paymentsQuickSearch');
        const btnPending = document.getElementById('btnFilterPending');
        const btnClear = document.getElementById('btnClearPaymentsFilter');
        if (input) {
            input.addEventListener('input', () => {
                clearTimeout(this.paymentsFilterTimer);
                this.paymentsFilterTimer = setTimeout(() => {
                    this.paymentFilters.query = input.value || '';
                    this.renderPaymentsTable();
                }, 200);
            });
        }
        if (btnPending) {
            btnPending.addEventListener('click', () => {
                this.paymentFilters.pendingOnly = !this.paymentFilters.pendingOnly;
                btnPending.classList.toggle('is-active', this.paymentFilters.pendingOnly);
                this.renderPaymentsTable();
            });
        }
        if (btnClear) {
            btnClear.addEventListener('click', () => {
                this.paymentFilters = { query: '', pendingOnly: false };
                if (input) input.value = '';
                if (btnPending) btnPending.classList.remove('is-active');
                this.renderPaymentsTable();
            });
        }
    }

    normalizeCompany(value) {
        const v = String(value || '').trim().toLowerCase();
        if (v === 'real energy' || v === 'real' || v === 'realenergy') return 'Real Energy';
        if (v === 'jfx') return 'JFX';
        if (v === 'dmf') return 'DMF';
        return value || 'DMF';
    }

    setCompanyFilter(company) {
        this.companyFilter = this.normalizeCompany(company);
        const title = document.getElementById('paymentsTitle');
        if (title) {
            title.textContent = `Fluxo de Pagamentos ${this.companyFilter}`;
        }
    }

    initAuditFilters() {
        const input = document.getElementById('auditLogFilter');
        const btnClear = document.getElementById('btnClearAuditFilter');
        if (input) {
            input.addEventListener('input', () => {
                const v = input.value || '';
                if (this.core?.audit?.setFilter) {
                    this.core.audit.setFilter(v);
                } else {
                    this.core?.audit?.renderLogs?.();
                }
            });
        }
        if (btnClear) {
            btnClear.addEventListener('click', () => {
                if (input) input.value = '';
                if (this.core?.audit?.setFilter) {
                    this.core.audit.setFilter('');
                } else {
                    this.core?.audit?.renderLogs?.();
                }
            });
        }
    }

    getFilteredPayments() {
        const data = [...(this.core.data.records || [])];
        const query = String(this.paymentFilters.query || '').trim().toLowerCase();
        let filtered = data;
        const company = this.companyFilter;
        if (company) {
            filtered = filtered.filter(p => {
                const c = this.core.data.getPaymentCompany(p);
                return c === this.normalizeCompany(company);
            });
        }
        if (this.paymentFilters.pendingOnly) {
            filtered = filtered.filter(p => !p.assinatura);
        }
        if (query) {
            filtered = filtered.filter(p => {
                const fields = [
                    p.fornecedor,
                    p.descricao,
                    p.centro,
                    p.categoria,
                    p.data,
                    String(p.valor || '')
                ].map(v => String(v || '').toLowerCase());
                return fields.some(v => v.includes(query));
            });
        }
        const countEl = document.getElementById('paymentsFilterCount');
        if (countEl) {
            countEl.textContent = `Mostrando ${filtered.length} de ${data.length}`;
        }
        return filtered;
    }

    updateDashboardSummary(pendingCount) {
        const nextAction = document.getElementById('nextActionText');
        const pendingEl = document.getElementById('pendingCount');
        if (pendingEl) pendingEl.textContent = pendingCount;
        if (nextAction) {
            if (pendingCount > 0) {
                nextAction.textContent = `Assine ${pendingCount} pagamento(s) pendente(s).`;
            } else {
                nextAction.textContent = 'Tudo certo. Nenhum pendente.';
            }
        }
    }

    updateFlowStatusBadges() {
        const lastSyncEl = document.getElementById('flowLastSync');
        const lastSigEl = document.getElementById('flowLastSignature');
        if (lastSyncEl) {
            if (this.core.data.lastSyncAt) {
                const diffMs = Date.now() - new Date(this.core.data.lastSyncAt).getTime();
                if (diffMs >= 0 && diffMs <= 5000) {
                    lastSyncEl.textContent = 'Atualizado agora';
                } else {
                    lastSyncEl.textContent = `Última sincronização: ${new Date(this.core.data.lastSyncAt).toLocaleTimeString('pt-BR')}`;
                }
            } else {
                lastSyncEl.textContent = 'Última sincronização: —';
            }
        }
        if (lastSigEl) {
            const latest = (this.core.data.records || [])
                .filter(p => p.assinatura?.dataISO)
                .sort((a, b) => new Date(b.assinatura.dataISO) - new Date(a.assinatura.dataISO))[0];
            if (latest?.assinatura) {
                const when = new Date(latest.assinatura.dataISO).toLocaleString('pt-BR');
                lastSigEl.textContent = `Última assinatura: ${latest.assinatura.usuarioNome} (${when})`;
            } else {
                lastSigEl.textContent = 'Última assinatura: —';
            }
        }
    }

    setupDashboard() {
        document.getElementById('loginSection').classList.add('hidden');
        document.getElementById('appSection').classList.remove('hidden');
        const role = normalizeRole(this.core.currentUser && (this.core.currentUser.cargo || this.core.currentUser.role));
        if (this.core.currentUser) this.core.currentUser.cargo = role;
        document.getElementById('userRoleBadge').innerText = (role || '—').toUpperCase();

        this.companyFilter = this.normalizeCompany(this.core?.data?.currentCompany || this.companyFilter || 'DMF');
        this.setCompanyFilter(this.companyFilter);

        if (this.core.admin.hasPermission(this.core.currentUser, 'admin_access')) {
            document.getElementById('adminMenu').classList.remove('hidden');
        }

        this.loadInitialDashboardData().then(() => {
            this.renderPaymentsTable();
            this.updateStats();
            this.initCharts();
            this.renderMonthlyReports();
            this.core.data.loadCenterCompanyOverridesFromBackend().then(() => {
                this.renderCompanyTotals();
                this.renderCenterCompanyEditor();
            });
        }).finally(() => {
            // Avoid racing two simultaneous loadFromBackend() calls right after login.
            this.startDashboardSummaryAutoRefresh();
        });
        this.startBackendStatusMonitor();
        this.startSessionMonitor();
        this.renderAdminContent();
        this.applyRolePermissions();
        this.populateBudgetInputs();
        this.initQuickActions();
        this.initPaymentsFilters();
        this.initAuditFilters();
        this.syncCurrentUserRole();
        this.applyInitialRouteFromUrl();
        console.log('DMF_CONTEXT after setupDashboard:', window.DMF_CONTEXT);
    }

    getFirstAvailableCompanyButton() {
        const buttons = Array.from(document.querySelectorAll('[data-nav="payments"][data-company]'));
        return buttons.find((btn) => !btn.classList.contains('hidden') && !btn.disabled) || buttons[0] || null;
    }

    async loadInitialDashboardData() {
        let company = this.normalizeCompany(this.core?.data?.currentCompany || this.companyFilter || 'DMF');
        try {
            // Prefer per-user last company to avoid cross-user localStorage bleed.
            const raw = this.core?.currentUser?.id || this.core?.currentUser?.email || this.core?.currentUser?.username || null;
            if (raw) {
                const safe = String(raw).trim().toLowerCase().replace(/[^a-z0-9@._-]+/g, '_');
                const k = `dmf_current_company_${safe}`;
                const persisted = localStorage.getItem(k);
                if (persisted) company = this.normalizeCompany(persisted);
            }
        } catch (_) {}
        this.core.data.setCurrentCompany(company);
        this.setCompanyFilter(company);

        const primaryOk = await this.core.data.loadFromBackend(true, company);
        if (primaryOk) return true;

        // UI-based fallback (buttons) can be hidden depending on role; prefer backend source of truth.
        let fallbackCompany = null;
        try {
            const resp = await fetch(`${getApiBase()}/api/companies`, { cache: 'no-store', headers: { ...getAuthHeaders() } });
            if (resp.ok) {
                const data = await resp.json().catch(() => ({}));
                const list = Array.isArray(data?.companies) ? data.companies : [];
                fallbackCompany = list.find(c => this.normalizeCompany(c) !== company) || list[0] || null;
            }
        } catch (_) {}

        if (!fallbackCompany) {
            const fallbackButton = this.getFirstAvailableCompanyButton();
            fallbackCompany = fallbackButton?.getAttribute('data-company') || null;
        }
        if (!fallbackCompany) return false;

        const normalizedFallback = this.normalizeCompany(fallbackCompany);
        if (!normalizedFallback || normalizedFallback === company) return false;

        this.core.data.setCurrentCompany(normalizedFallback);
        this.setCompanyFilter(normalizedFallback);
        return this.core.data.loadFromBackend(true, normalizedFallback);
    }

    startDashboardSummaryAutoRefresh() {
        if (this.dashboardSyncTimer) return;

        const refresh = () => {
            const currentView = document.querySelector('.view:not(.hidden)')?.id;
            if (currentView === 'payments') return;
            this.core.data.loadFromBackend(true, this.core.data.currentCompany).then((ok) => {
                if (!ok) return;
                this.updateStats();
                this.renderMonthlyReports();
                this.updateFlowStatusBadges();
            }).catch(() => {});
        };

        refresh();
        this.dashboardSyncTimer = setInterval(refresh, 15000);
    }

    stopDashboardSummaryAutoRefresh() {
        if (this.dashboardSyncTimer) {
            clearInterval(this.dashboardSyncTimer);
            this.dashboardSyncTimer = null;
        }
    }

    applyInitialRouteFromUrl() {
        const params = new URLSearchParams(window.location.search || '');
        const tab = String(params.get('tab') || '').trim().toLowerCase();
        if (!tab) return;

        const allowed = new Set(['dashboard', 'payments', 'audit', 'admin', 'assistente', 'cobli']);
        if (!allowed.has(tab)) return;

        if (tab === 'payments') {
            const companyRaw = String(params.get('company') || '').trim();
            const company = this.normalizeCompany(companyRaw || this.companyFilter || 'DMF');
            const allPaymentButtons = Array.from(document.querySelectorAll('[data-nav="payments"][data-company]'));
            let targetButton = allPaymentButtons.find(btn =>
                this.normalizeCompany(btn.getAttribute('data-company')) === company
            );
            if (!targetButton) {
                targetButton = allPaymentButtons[0] || document.querySelector('[data-nav="payments"]');
            }
            this.navigate('payments', targetButton || null);
            return;
        }

        const btn = document.querySelector(`[data-nav="${tab}"]`);
        this.navigate(tab, btn || null);
    }

    startBackendStatusMonitor() {
        if (this.backendStatusTimer) return;
        const check = async () => {
            try {
                const response = await fetch(`${getApiBase()}/api/health`, { method: 'GET', cache: 'no-store' });
                if (!response.ok) {
                    setBackendStatus('Servidor: indisponível', 'error');
                    return;
                }
                const data = await response.json();
                if (data && data.db_ready === false) {
                    setBackendStatus(`Servidor: online (banco iniciando)`, 'warn');
                    return;
                }
                setBackendStatus(`Servidor: online (${formatTimeNow()})`, 'ok');
            } catch (_) {
                setBackendStatus('Servidor: indisponível', 'error');
            }
        };
        check();
        this.backendStatusTimer = setInterval(check, 30000);
    }

    startSessionMonitor() {
        if (this.sessionStatusTimer) return;
        const update = () => {
            const token = localStorage.getItem('dmf_api_token');
            if (!token) {
                setBackendStatus('Servidor: offline', 'error');
                const el = document.getElementById('sessionStatus');
                if (el) {
                    el.textContent = 'Sessão: offline';
                    el.classList.remove('is-ok', 'is-warn', 'is-error', 'is-info');
                    el.classList.add('is-error');
                }
                return;
            }
            const payload = parseJwtPayload(token);
            const el = document.getElementById('sessionStatus');
            if (!el) return;
            if (!payload?.exp) {
                el.textContent = 'Sessão: ativa';
                el.classList.remove('is-ok', 'is-warn', 'is-error', 'is-info');
                el.classList.add('is-ok');
                return;
            }
            const expMs = payload.exp * 1000;
            const remaining = expMs - Date.now();
            if (remaining <= 0) {
                el.textContent = 'Sessão: expirada';
                el.classList.remove('is-ok', 'is-warn', 'is-error', 'is-info');
                el.classList.add('is-error');
                return;
            }
            const minutes = Math.floor(remaining / 60000);
            const seconds = Math.floor((remaining % 60000) / 1000);
            el.textContent = `Sessão: expira em ${minutes}m ${seconds}s`;
            el.classList.remove('is-ok', 'is-warn', 'is-error', 'is-info');
            if (minutes < 5) {
                el.classList.add('is-warn');
            } else {
                el.classList.add('is-ok');
            }

            const syncEl = document.getElementById('syncCountdown');
            if (syncEl) {
                if (this.flowNextSyncAt) {
                    const remainingMs = Math.max(this.flowNextSyncAt - Date.now(), 0);
                    const syncMinutes = Math.floor(remainingMs / 60000);
                    const syncSeconds = Math.floor((remainingMs % 60000) / 1000);
                    const mm = String(syncMinutes).padStart(2, '0');
                    const ss = String(syncSeconds).padStart(2, '0');
                    syncEl.textContent = `Sincronizando novamente em: ${mm}:${ss}`;
                } else {
                    syncEl.textContent = 'Sincronizando novamente em: --:--';
                }
            }
        };
        update();
        this.sessionStatusTimer = setInterval(update, 1000);
        if (!this.userSyncTimer) {
            this.userSyncTimer = setInterval(() => {
                this.syncCurrentUserRole();
            }, 60000);
        }
    }

    async syncCurrentUserRole() {
        const now = Date.now();
        if (this.userStatusInFlight) return;
        if (now - this.userStatusLastAt < this.userStatusMinInterval) return;
        this.userStatusInFlight = true;
        this.userStatusLastAt = now;
        try {
            const response = await fetch(`${getApiBase()}/api/auth/user-status`, {
                cache: 'no-store',
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                }
            });
            if (!response.ok) return;
            const data = await response.json();
            const apiUser = data?.user;
            if (!apiUser || !this.core.currentUser) return;
            const newRole = normalizeRole(apiUser.role);
            const perms = Array.isArray(apiUser.permissions) ? apiUser.permissions : [];
            if (newRole && newRole !== this.core.currentUser.cargo) {
                this.core.currentUser.cargo = newRole;
                const badge = document.getElementById('userRoleBadge');
                if (badge) badge.innerText = newRole.toUpperCase();
            }
            this.core.currentUser.additionalPermissions = perms;
            localStorage.setItem(this.core.storageKeys.SESSION, JSON.stringify(this.core.currentUser));
            this.applyRolePermissions();
            this.enforceViewAccess();
        } catch (_) {
            // ignore
        } finally {
            this.userStatusInFlight = false;
        }
    }

    enforceViewAccess() {
        const currentView = document.querySelector('.view:not(.hidden)')?.id;
        const isAdminAccess = this.core.admin.hasPermission(this.core.currentUser, 'admin_access');
        const canAudit = this.core.admin.hasPermission(this.core.currentUser, 'audit_access');
        if (currentView === 'admin' && !isAdminAccess) {
            this.showAccessDenied({
                title: 'Acesso negado',
                message: 'Você não tem permissão para acessar a aba Administração.'
            }, document.querySelector('[data-nav="dashboard"]'));
        }
        if (currentView === 'audit' && !canAudit) {
            this.showAccessDenied({
                title: 'Acesso negado',
                message: 'Você não tem permissão para acessar os Logs de Auditoria.'
            }, document.querySelector('[data-nav="dashboard"]'));
        }
        const historyBtn = document.querySelector('[data-payments-tab="history"]');
        if (historyBtn && historyBtn.classList.contains('active') &&
            !this.core.admin.hasPermission(this.core.currentUser, 'view_archives')) {
            const currentBtn = document.querySelector('[data-payments-tab="current"]');
            this.switchPaymentsTab('current', currentBtn);
        }
    }

    startFlowAutoRefresh() {
        if (this.flowAutoRefreshTimer) return;
        this.flowAutoRefreshBusy = true;
        this.flowNextSyncAt = Date.now() + this.flowSyncIntervalMs;
        this.core.data.loadFromBackend(true, this.core.data.currentCompany).then(() => {
            this.renderPaymentsTable();
            this.updateStats();
            this.initCharts();
            this.startFlowPushStream();
        }).finally(() => {
            this.flowAutoRefreshBusy = false;
        });
        this.flowAutoRefreshTimer = setInterval(() => {
            if (this.flowAutoRefreshBusy) return;
            this.flowAutoRefreshBusy = true;
            this.core.data.loadFromBackend(true, this.core.data.currentCompany).then(() => {
                this.renderPaymentsTable();
                this.updateStats();
            }).finally(() => {
                this.flowAutoRefreshBusy = false;
            });
            this.flowNextSyncAt = Date.now() + this.flowSyncIntervalMs;
        }, this.flowSyncIntervalMs);
    }

    stopFlowAutoRefresh() {
        if (this.flowAutoRefreshTimer) {
            clearInterval(this.flowAutoRefreshTimer);
            this.flowAutoRefreshTimer = null;
        }
        if (this.flowStreamReconnectTimer) {
            clearTimeout(this.flowStreamReconnectTimer);
            this.flowStreamReconnectTimer = null;
        }
        this.flowNextSyncAt = null;
        this.stopFlowPushStream();
    }

    scheduleFlowPushReconnect() {
        if (this.flowStreamReconnectTimer) return;
        this.flowStreamReconnectTimer = setTimeout(() => {
            this.flowStreamReconnectTimer = null;
            const currentView = document.querySelector('.view:not(.hidden)')?.id;
            if (currentView !== 'payments') return;
            this.startFlowPushStream();
        }, this.flowStreamReconnectMs);
    }

    startFlowPushStream() {
        if (this.flowEventSource) return;
        if (this.flowStreamReconnectTimer) {
            clearTimeout(this.flowStreamReconnectTimer);
            this.flowStreamReconnectTimer = null;
        }
        const token = localStorage.getItem('dmf_api_token');
        if (!token) return;
        const company = this.core?.data?.currentCompany || this.companyFilter || 'DMF';
        const url = `${getApiBase()}/api/flow-payments/stream?company=${encodeURIComponent(company)}&access_token=${encodeURIComponent(token)}`;
        try {
            this.flowEventSource = new EventSource(url);
        } catch (_) {
            this.flowEventSource = null;
            return;
        }
        this.flowEventSource.addEventListener('flow_update', (event) => {
            try {
                const payload = event?.data ? JSON.parse(event.data) : null;
                const relevant = !payload?.company || payload.company === company;
                if (!relevant) return;
                if (payload?.type === 'payment_signed') {
                    this.applyStreamSignedUpdate(payload);
                    this.core.data.loadFromBackend(true, company).then(() => {
                        this.renderPaymentsTable();
                        this.updateStats();
                    });
                    return;
                }
                if (payload?.type === 'payment_upserted') {
                    this.applyStreamUpsertUpdate(payload);
                    return;
                }
                if (payload?.type === 'flow_imported') {
                    this.core.data.loadFromBackend(true, company).then(() => {
                        this.renderPaymentsTable();
                        this.updateStats();
                    });
                }
            } catch (_) {
                // ignore
            }
        });
        this.flowEventSource.onerror = () => {
            this.stopFlowPushStream();
            this.scheduleFlowPushReconnect();
        };
    }

    applyStreamSignedUpdate(payload) {
        const id = String(payload?.paymentId || '').trim();
        if (!id || !payload?.assinatura) return;
        const idx = (this.core?.data?.records || []).findIndex((item) => String(item?.id) === id);
        if (idx === -1) return;
        const current = this.core.data.records[idx];
        if (current?.assinatura) return;
        this.core.data.records[idx] = {
            ...current,
            assinatura: payload.assinatura
        };
        this.core.data.save();
        this.renderPaymentsTable();
        this.updateStats();
        this.updateFlowStatusBadges();
    }

    applyStreamUpsertUpdate(payload) {
        const payment = payload?.payment;
        if (!payment || !payment.id) return;
        const company = payment.company || this.core?.data?.currentCompany || this.companyFilter || 'DMF';
        if (this.core?.data?.currentCompany && company !== this.core.data.currentCompany) return;
        const id = String(payment.id);
        const idx = (this.core?.data?.records || []).findIndex((item) => String(item?.id) === id);
        if (idx === -1) {
            this.core.data.records.push(payment);
        } else {
            const existing = this.core.data.records[idx] || {};
            this.core.data.records[idx] = {
                ...existing,
                ...payment,
                created_at: existing.created_at || payment.created_at
            };
        }
        this.core.data.save();
        this.renderPaymentsTable();
        this.updateStats();
        this.updateFlowStatusBadges();
    }

    stopFlowPushStream() {
        if (this.flowEventSource) {
            this.flowEventSource.close();
            this.flowEventSource = null;
        }
    }

    switchAdminTab(tab, activeButton = null) {
        document.querySelectorAll('.admin-tab-content').forEach(t => t.classList.add('hidden'));
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.getElementById(`${tab}Tab`).classList.remove('hidden');
        if (activeButton) activeButton.classList.add('active');
        if (tab === 'centers') {
            this.renderCenterPermissions();
        }
    }

    switchAuditTab(tab, activeButton = null) {
        if (tab === 'logins' && !this.core.admin.hasPermission(this.core.currentUser, 'audit_login_access')) {
            this.showAccessDenied({
                title: 'Acesso negado',
                message: 'Você não tem permissão para acessar os logs de acesso (logins). Peça ao administrador para liberar o acesso.'
            }, document.querySelector('[data-nav="audit"]'));
            return;
        }
        document.querySelectorAll('.audit-tab-content').forEach(t => t.classList.add('hidden'));
        document.querySelectorAll('[data-audit-tab]').forEach(b => b.classList.remove('active'));
        document.getElementById(`audit${tab.charAt(0).toUpperCase()}${tab.slice(1)}Tab`).classList.remove('hidden');
        if (activeButton) activeButton.classList.add('active');

        if (tab === 'logins') {
            this.loadLoginAudits();
        }
    }

    switchPaymentsTab(tab, activeButton = null) {
        document.querySelectorAll('.payments-tab-content').forEach(t => t.classList.add('hidden'));
        document.querySelectorAll('[data-payments-tab]').forEach(b => b.classList.remove('active'));
        const target = tab === 'history' ? 'paymentsHistoryTab' : 'paymentsCurrentTab';
        if (tab === 'history' && !this.core.admin.hasPermission(this.core.currentUser, 'view_archives')) {
            alert('Acesso restrito aos fluxos anteriores.');
            return;
        }
        document.getElementById(target).classList.remove('hidden');
        if (activeButton) activeButton.classList.add('active');

        if (tab === 'history') {
            this.core.data.loadArchivesFromBackend().then(() => {
                this.renderFlowArchivesList();
            });
        }
    }

    renderAdminContent() {
        if (this.core.admin.hasPermission(this.core.currentUser, 'admin_access')) {
            this.core.admin.refreshUsersFromApi().then(() => {
                this.renderUsersTable();
            });
            this.core.admin.refreshRolesFromApi().then(() => {
                this.renderRolesTable();
            });
        } else {
            this.renderUsersTable();
        }
        this.renderRolesTable();
        this.renderCenterPermissions();
    }

    applyRolePermissions() {
        const isAdminAccess = this.core.admin.hasPermission(this.core.currentUser, 'admin_access');
        const adminMenu = document.getElementById('adminMenu');
        if (adminMenu) {
            adminMenu.classList.toggle('hidden', !isAdminAccess);
        }

        const importBtn = document.getElementById('btnImportPayments');
        const exportBtn = document.getElementById('btnExportPayments');
        const addPaymentBtn = document.getElementById('btnAddPayment');
        const auditNavBtn = document.querySelector('[data-nav="audit"]');
        const archiveBtn = document.getElementById('btnArchiveFlow');
        const paymentsHistoryTabBtn = document.querySelector('[data-payments-tab="history"]');
        const archiveFilterArea = document.querySelector('.archive-filters');
        const archiveCompareArea = document.querySelector('.archive-compare');
        const compareBtn = document.getElementById('btnCompareArchives');
        const revokeSelfBtn = document.getElementById('btnRevokeSelf');
        const quickImportBtn = document.getElementById('btnQuickImport');
        const quickExportBtn = document.getElementById('btnQuickExport');

        const canImport = this.core.admin.hasPermission(this.core.currentUser, 'import_payments');
        const canExport = this.core.admin.hasPermission(this.core.currentUser, 'export_payments');
        const canAdd = this.core.admin.hasPermission(this.core.currentUser, 'add_payments');
        const canAudit = this.core.admin.hasPermission(this.core.currentUser, 'audit_access');
        const canViewArchives = this.core.admin.hasPermission(this.core.currentUser, 'view_archives');
        const canArchiveFlow = this.core.admin.hasPermission(this.core.currentUser, 'archive_flow');
        const canCompareArchives = this.core.admin.hasPermission(this.core.currentUser, 'compare_archives');
        const canSign = this.core.admin.hasPermission(this.core.currentUser, 'sign_payments');

        if (importBtn) {
            importBtn.classList.toggle('hidden', !canImport);
            importBtn.disabled = !canImport;
        }
        if (exportBtn) {
            exportBtn.classList.toggle('hidden', !canExport);
            exportBtn.disabled = !canExport;
        }
        if (addPaymentBtn) {
            addPaymentBtn.classList.toggle('hidden', !canAdd);
            addPaymentBtn.disabled = !canAdd;
        }
        if (archiveBtn) {
            archiveBtn.classList.toggle('hidden', !canArchiveFlow);
            archiveBtn.disabled = !canArchiveFlow;
        }
        if (auditNavBtn) {
            auditNavBtn.classList.toggle('hidden', !canAudit);
        }
        if (revokeSelfBtn) {
            const canRevokeAll = isAdminUser(this.core.currentUser);
            revokeSelfBtn.classList.toggle('hidden', !canRevokeAll);
            revokeSelfBtn.disabled = !canRevokeAll;
        }
        if (paymentsHistoryTabBtn) {
            paymentsHistoryTabBtn.classList.toggle('hidden', !canViewArchives);
            paymentsHistoryTabBtn.disabled = !canViewArchives;
        }
        if (archiveFilterArea) {
            archiveFilterArea.classList.toggle('hidden', !canViewArchives);
        }
        if (archiveCompareArea) {
            archiveCompareArea.classList.toggle('hidden', !canViewArchives);
        }
        if (compareBtn) {
            compareBtn.disabled = !canCompareArchives;
        }
        if (quickImportBtn) {
            quickImportBtn.classList.toggle('hidden', !canImport);
            quickImportBtn.disabled = !canImport;
        }
        if (quickExportBtn) {
            quickExportBtn.classList.toggle('hidden', !canExport);
            quickExportBtn.disabled = !canExport;
        }
    }

    renderUsersTable() {
        const body = document.getElementById('userGrid');
        if(!body) return;
        body.innerHTML = `
            <table>
                <thead>
                    <tr><th>Nome</th><th>Usuário</th><th>Email</th><th>Cargo</th><th>Ações</th></tr>
                </thead>
                <tbody>
                    ${this.core.admin.users.map(u => `
                        <tr>
                            <td>${u.nome}</td>
                            <td>${u.usuario}</td>
                            <td>${u.email}</td>
                            <td>${u.cargo}</td>
                            <td>
                                <button class="btn btn-ghost" data-user-action="edit" data-user-id="${u.id}">Editar</button>
                                <button class="btn btn-ghost" data-user-action="change-password" data-user-id="${u.id}">Trocar Senha</button>
                                <button class="btn btn-ghost" data-user-action="revoke-session" data-user-id="${u.id}">Revogar Sessão</button>
                                <button class="btn btn-danger" data-user-action="delete" data-user-id="${u.id}">Excluir</button>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
        if (!body.dataset.boundUsers) {
            body.addEventListener('click', (event) => {
                const button = event.target.closest('button[data-user-action]');
                if (!button) return;
                const action = button.getAttribute('data-user-action');
                const id = Number(button.getAttribute('data-user-id'));
                if (!id) return;
                if (action === 'edit') {
                    this.editUser(id);
                } else if (action === 'change-password') {
                    this.changePassword(id);
                } else if (action === 'revoke-session') {
                    this.core.admin.revokeSession(id);
                } else if (action === 'delete') {
                    this.core.admin.deleteUser(id);
                }
            });
            body.dataset.boundUsers = 'true';
        }
    }

    renderRolesTable() {
        const body = document.getElementById('rolesGrid');
        if(!body) return;
        body.innerHTML = `
            <table>
                <thead>
                    <tr><th>Cargo</th><th>Permissões</th><th>Ações</th></tr>
                </thead>
                <tbody>
                    ${this.core.admin.roles.map(r => `
                        <tr>
                            <td>${r.name}</td>
                            <td>${this.formatPermissionsForDisplay(r.permissions)}</td>
                            <td>
                                <button class="btn btn-ghost" data-role-action="edit" data-role-id="${r.id}">Editar</button>
                                <button class="btn btn-danger" data-role-action="delete" data-role-id="${r.id}">Excluir</button>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
            <button class="btn btn-primary btn-top-spaced" data-role-action="create">Criar Novo Cargo</button>
        `;
        if (!body.dataset.boundRoles) {
            body.addEventListener('click', (event) => {
                const button = event.target.closest('button[data-role-action]');
                if (!button) return;
                const action = button.getAttribute('data-role-action');
                const id = Number(button.getAttribute('data-role-id'));
                if (action === 'edit' && id) {
                    this.editRole(id);
                } else if (action === 'delete' && id) {
                    this.core.admin.deleteRole(id);
                    this.renderRolesTable();
                } else if (action === 'create') {
                    this.openCreateRoleModal();
                }
            });
            body.dataset.boundRoles = 'true';
        }
    }

    formatPermissionsForDisplay(permissions) {
        const list = Array.isArray(permissions) ? permissions : [];
        if (!list.length) return 'Sem permissões';
        return list.map((permission) => this.formatPermissionLabel(permission)).join(', ');
    }

    formatPermissionLabel(permission) {
        const raw = String(permission || '').trim();
        if (!raw) return 'Permissão inválida';
        const normalized = raw.toLowerCase().replace(/\s+/g, '_');
        const aliases = {
            audit_acess: 'audit_access',
            audit_login_acess: 'audit_login_access'
        };
        const key = aliases[normalized] || normalized;
        const labels = {
            all: 'Todas as permissões',
            sign_payments: 'Assinar pagamentos',
            import_payments: 'Importar pagamentos',
            export_payments: 'Exportar pagamentos',
            add_payments: 'Adicionar pagamentos',
            delete_payments: 'Excluir pagamentos',
            view_archives: 'Ver fluxos anteriores',
            archive_flow: 'Arquivar fluxo',
            delete_archive: 'Excluir fluxos anteriores',
            export_archives: 'Exportar fluxos anteriores',
            compare_archives: 'Comparar fluxos anteriores',
            admin_access: 'Acessar administração',
            audit_access: 'Acessar auditoria',
            audit_login_access: 'Ver logs de acesso',
            roles_manage: 'Gerenciar cargos',
            user_manage: 'Gerenciar usuários',
            backup_restore: 'Backup e restauração',
            revoke_sessions: 'Revogar sessões'
        };
        return labels[key] || raw;
    }

    renderCenterPermissions() {
        const container = document.getElementById('centerPermissionGrid');
        if (!container) return;
        const centers = this.core.data.costCenters || [];
        const centerList = centers.length ? centers : [];
        container.innerHTML = this.core.admin.users.map(u => {
            const rule = this.core.admin.getUserCenterRule(u.id);
            const selected = new Set((rule.centers || []).map(c => this.core.admin.normalizeCenter(c)));
            const options = centerList.map(c => {
                const normalized = this.core.admin.normalizeCenter(c);
                const checked = selected.has(normalized) ? 'checked' : '';
                return `
                    <label class="center-option">
                        <input type="checkbox" data-center-name="${c}" ${checked}>
                        <span>${c}</span>
                    </label>
                `;
            }).join('');
            return `
                <div class="center-permission-card" data-user-id="${u.id}">
                    <div class="center-card-header">
                        <div>
                            <div class="center-user-name">${u.nome}</div>
                            <div class="center-user-meta">${u.email} • ${String(u.cargo || '').toUpperCase()}</div>
                        </div>
                        <button class="btn btn-ghost" data-cc-action="toggle">Editar</button>
                    </div>
                    <div class="center-editor hidden">
                        <div class="center-mode">
                            <label>
                                <input type="radio" name="center-mode-${u.id}" value="all" ${rule.mode === 'all' ? 'checked' : ''}>
                                Acesso a todos os centros
                            </label>
                            <label>
                                <input type="radio" name="center-mode-${u.id}" value="allow" ${rule.mode === 'allow' ? 'checked' : ''}>
                                Somente centros selecionados
                            </label>
                        </div>
                        <div class="center-options">
                            ${options || '<div class="center-empty">Sem centros cadastrados.</div>'}
                        </div>
                        <div class="center-actions">
                            <button class="btn btn-primary" data-cc-action="save">Salvar</button>
                            <button class="btn btn-ghost" data-cc-action="cancel">Cancelar</button>
                        </div>
                    </div>
                </div>
            `;
        }).join('');

        if (!container.dataset.boundCenters) {
            container.addEventListener('click', (event) => {
                const actionBtn = event.target.closest('[data-cc-action]');
                if (!actionBtn) return;
                const card = event.target.closest('.center-permission-card');
                if (!card) return;
                const userId = Number(card.getAttribute('data-user-id'));
                const editor = card.querySelector('.center-editor');
                const action = actionBtn.getAttribute('data-cc-action');
                if (action === 'toggle') {
                    editor?.classList.toggle('hidden');
                } else if (action === 'cancel') {
                    editor?.classList.add('hidden');
                } else if (action === 'save') {
                    const modeInput = card.querySelector(`input[name="center-mode-${userId}"]:checked`);
                    const mode = modeInput ? modeInput.value : 'all';
                    const selected = Array.from(card.querySelectorAll('input[type="checkbox"][data-center-name]:checked'))
                        .map(i => i.getAttribute('data-center-name'));
                    this.core.admin.setUserCenterRule(userId, { mode, centers: selected });
                    showToast('Permissões de centros atualizadas.', 'success');
                    editor?.classList.add('hidden');
                }
            });
            container.dataset.boundCenters = 'true';
        }
        this.renderCenterCompanyEditor();
        this.core.data.loadCenterCompanyOverridesFromBackend().then(() => {
            this.renderCenterCompanyEditor();
        });
    }

    renderCenterCompanyEditor() {
        const grid = document.getElementById('centerCompanyGrid');
        if (!grid) return;
        const search = (document.getElementById('centerCompanySearch')?.value || '').trim().toLowerCase();
        const centers = (this.core.data.costCenters || []).slice().sort((a, b) => a.localeCompare(b, 'pt-BR'));
        const filtered = search
            ? centers.filter(c => String(c || '').toLowerCase().includes(search))
            : centers;
        if (!filtered.length) {
            grid.innerHTML = '<div class="center-empty">Sem centros cadastrados.</div>';
            return;
        }
        const companyOptions = ['DMF', 'JFX', 'Real Energy', 'Outros'];
        const summaryEl = document.getElementById('centerCompanySummary');
        if (summaryEl) {
            const counts = { DMF: 0, JFX: 0, 'Real Energy': 0, Outros: 0 };
            centers.forEach(center => {
                const company = this.core.data.getCenterCompanyOverride(center) || this.core.data.getCompanyForCenter(center) || 'Outros';
                const key = counts[company] !== undefined ? company : 'Outros';
                counts[key] += 1;
            });
            summaryEl.innerHTML = Object.entries(counts)
                .map(([name, count]) => `<span class="summary-chip">${name}: ${count}</span>`)
                .join('');
        }
        const saveBtn = document.getElementById('btnSaveCenterCompanies');
        if (saveBtn) saveBtn.disabled = this.pendingCenterCompanyUpdates.size === 0;
        grid.innerHTML = `
            <div class="center-company-table">
                <div class="center-company-row center-company-header">
                    <span>Centro de Custo</span>
                    <span>Empresa</span>
                </div>
                ${filtered.map(center => {
                    const current = this.core.data.getCenterCompanyOverride(center) || this.core.data.getCompanyForCenter(center) || 'Outros';
                    const options = companyOptions.map(opt => {
                        const selected = opt === current ? 'selected' : '';
                        return `<option value="${opt}" ${selected}>${opt}</option>`;
                    }).join('');
                    return `
                        <div class="center-company-row" data-center-name="${center}">
                            <div class="center-company-name">${center}</div>
                            <div class="center-company-select">
                                <select class="styled-input" data-center-company-select>
                                    ${options}
                                </select>
                            </div>
                        </div>
                    `;
                }).join('')}
            </div>
        `;

        if (!grid.dataset.boundCenterCompany) {
            grid.addEventListener('change', (event) => {
                const select = event.target.closest('[data-center-company-select]');
                if (!select) return;
                const row = event.target.closest('[data-center-name]');
                const center = row?.getAttribute('data-center-name');
                const company = select.value;
                if (!center) return;
                this.core.data.setCenterCompany(center, company, { sync: false });
                this.pendingCenterCompanyUpdates.set(center, { center, company });
                const saveBtn = document.getElementById('btnSaveCenterCompanies');
                if (saveBtn) saveBtn.disabled = this.pendingCenterCompanyUpdates.size === 0;
            });
            grid.dataset.boundCenterCompany = 'true';
        }
    }

    async saveAllCenterCompanies() {
        const items = Array.from(this.pendingCenterCompanyUpdates.values());
        if (!items.length) {
            showToast('Nenhuma alteração pendente.', 'info');
            return;
        }
        try {
            const response = await fetch(`${getApiBase()}/api/centers/companies/bulk`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                },
                body: JSON.stringify({ items })
            });
            if (!response.ok) {
                showToast('Falha ao salvar centros no servidor.', 'warn');
                return;
            }
            this.pendingCenterCompanyUpdates.clear();
            const saveBtn = document.getElementById('btnSaveCenterCompanies');
            if (saveBtn) saveBtn.disabled = true;
            showToast('Centros de custo salvos.', 'success');
        } catch (_) {
            showToast('Falha ao salvar centros no servidor.', 'warn');
        }
    }

    getSelectedReportMonth() {
        const input = document.getElementById('reportMonth');
        if (input && input.value) return input.value;
        const now = new Date();
        const key = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
        if (input) input.value = key;
        return key;
    }

    loadBudgets() {
        try {
            const raw = localStorage.getItem('dmf_budget_limits');
            return raw ? JSON.parse(raw) : {};
        } catch (_) {
            return {};
        }
    }

    saveBudgets(budgets) {
        localStorage.setItem('dmf_budget_limits', JSON.stringify(budgets || {}));
    }

    renderMonthlyReports() {
        const monthKey = this.getSelectedReportMonth();
        const companyTotals = this.core.data.getCompanyTotalsForMonth(monthKey);
        const costTotals = this.core.data.getCostCenterTotalsForMonth(monthKey);
        const companyList = document.getElementById('reportCompanyTotals');
        const costList = document.getElementById('reportCostCenters');
        if (companyList) {
            const items = Object.entries(companyTotals).map(([name, value]) => `
                <div class="report-item"><span>${name}</span><strong>R$ ${value.toLocaleString('pt-BR')}</strong></div>
            `).join('');
            companyList.innerHTML = items || '<div>Nenhum dado no período.</div>';
        }
        if (costList) {
            const sorted = Object.entries(costTotals).sort((a, b) => b[1] - a[1]).slice(0, 8);
            const items = sorted.map(([name, value]) => `
                <div class="report-item"><span>${name}</span><strong>R$ ${value.toLocaleString('pt-BR')}</strong></div>
            `).join('');
            costList.innerHTML = items || '<div>Nenhum dado no período.</div>';
        }

        const budgets = this.loadBudgets();
        const budgetDMF = Number(budgets.DMF) || 0;
        const budgetJFX = Number(budgets.JFX) || 0;
        const budgetReal = Number(budgets['Real Energy']) || 0;
        const alerts = [];
        if (budgetDMF > 0 && companyTotals.DMF > budgetDMF) {
            alerts.push(`DMF excedeu o orçamento: R$ ${companyTotals.DMF.toLocaleString('pt-BR')} / R$ ${budgetDMF.toLocaleString('pt-BR')}`);
        }
        if (budgetJFX > 0 && companyTotals.JFX > budgetJFX) {
            alerts.push(`JFX excedeu o orçamento: R$ ${companyTotals.JFX.toLocaleString('pt-BR')} / R$ ${budgetJFX.toLocaleString('pt-BR')}`);
        }
        if (budgetReal > 0 && companyTotals['Real Energy'] > budgetReal) {
            alerts.push(`Real Energy excedeu o orçamento: R$ ${companyTotals['Real Energy'].toLocaleString('pt-BR')} / R$ ${budgetReal.toLocaleString('pt-BR')}`);
        }
        const alertBox = document.getElementById('budgetAlerts');
        if (alertBox) {
            if (alerts.length) {
                alertBox.classList.remove('ok');
                alertBox.innerHTML = alerts.map(a => `<div>${a}</div>`).join('');
                this.notifyBudgetExceeded({ monthKey, alerts });
            } else {
                alertBox.classList.add('ok');
                alertBox.textContent = 'Dentro do orçamento configurado.';
            }
        }
    }

    notifyBudgetExceeded(payload) {
        if (this.budgetAlertSentKey === payload.monthKey) return;
        this.budgetAlertSentKey = payload.monthKey;
        try {
            fetch(`${getApiBase()}/api/events/budget-exceeded`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                },
                body: JSON.stringify(payload)
            }).catch(() => {});
        } catch (_) {
            // ignore
        }
    }

    populateBudgetInputs() {
        const budgets = this.loadBudgets();
        const dmf = document.getElementById('budgetDMF');
        const jfx = document.getElementById('budgetJFX');
        const real = document.getElementById('budgetReal');
        if (dmf) dmf.value = Number(budgets.DMF || 0) || '';
        if (jfx) jfx.value = Number(budgets.JFX || 0) || '';
        if (real) real.value = Number(budgets['Real Energy'] || 0) || '';
        const isAdmin = this.core.admin.hasPermission(this.core.currentUser, 'admin_access');
        const budgetSection = document.getElementById('budgetSection');
        if (budgetSection) {
            budgetSection.classList.toggle('hidden', !isAdmin);
        }
    }

    getArchiveFilterState() {
        const search = (document.getElementById('archiveSearchInput')?.value || '').trim().toLowerCase();
        const startValue = document.getElementById('archiveStart')?.value || '';
        const endValue = document.getElementById('archiveEnd')?.value || '';
        const rawSortValue = document.getElementById('archiveSort')?.value || 'newest';
        const allowedSorts = new Set(['newest', 'oldest', 'value_desc', 'count_desc']);
        const sortValue = allowedSorts.has(rawSortValue) ? rawSortValue : 'newest';
        const start = startValue ? new Date(`${startValue}T00:00:00`) : null;
        const end = endValue ? new Date(`${endValue}T23:59:59`) : null;
        return {
            search,
            start,
            end,
            sortValue,
            startValue,
            endValue
        };
    }

    applyArchiveFilters(archives, filterState) {
        const searchTerm = filterState.search;
        const start = filterState.start;
        const end = filterState.end;
        const sorted = archives.map(archive => {
            const stats = this.computeArchiveStats(archive);
            const createdAt = archive?.created_at ? new Date(archive.created_at) : null;
            return { archive, stats, createdAt };
        }).filter(item => {
            if (start || end) {
                if (!item.createdAt) return false;
                if (start && item.createdAt < start) return false;
                if (end && item.createdAt > end) return false;
            }
            if (!searchTerm) return true;
            const haystack = [
                item.archive?.label,
                item.archive?.company,
                item.archive?.created_by
            ].filter(Boolean).join(' ').toLowerCase();
            return haystack.includes(searchTerm);
        });

        switch (filterState.sortValue) {
            case 'oldest':
                sorted.sort((a, b) => (a.createdAt?.getTime() || 0) - (b.createdAt?.getTime() || 0));
                break;
            case 'value_desc':
                sorted.sort((a, b) => b.stats.total - a.stats.total);
                break;
            case 'count_desc':
                sorted.sort((a, b) => b.stats.count - a.stats.count);
                break;
            case 'newest':
            default:
                sorted.sort((a, b) => (b.createdAt?.getTime() || 0) - (a.createdAt?.getTime() || 0));
                break;
        }

        return sorted;
    }

    updateArchiveSummary(filtered, filterState, totalCount) {
        const countEl = document.getElementById('archiveTotalCount');
        const paymentsEl = document.getElementById('archiveTotalPayments');
        const valueEl = document.getElementById('archiveTotalValue');
        const signedEl = document.getElementById('archiveTotalSigned');
        const rangeEl = document.getElementById('archiveSummaryRange');
        const resultsEl = document.getElementById('archiveResultsCount');

        let totalPayments = 0;
        let totalValue = 0;
        let totalSigned = 0;
        filtered.forEach(item => {
            totalPayments += item.stats.count;
            totalValue += item.stats.total;
            totalSigned += item.stats.signed;
        });

        if (countEl) countEl.textContent = String(filtered.length);
        if (paymentsEl) paymentsEl.textContent = String(totalPayments);
        if (valueEl) valueEl.textContent = `R$ ${totalValue.toLocaleString('pt-BR')}`;
        if (signedEl) signedEl.textContent = String(totalSigned);
        if (resultsEl) resultsEl.textContent = `Mostrando ${filtered.length} de ${totalCount}`;
        if (rangeEl) {
            if (filterState.startValue && filterState.endValue) {
                rangeEl.textContent = `Período: ${filterState.startValue} → ${filterState.endValue}`;
            } else if (filterState.startValue) {
                rangeEl.textContent = `Desde ${filterState.startValue}`;
            } else if (filterState.endValue) {
                rangeEl.textContent = `Até ${filterState.endValue}`;
            } else {
                rangeEl.textContent = 'Todos os períodos';
            }
        }
    }

    renderFlowArchivesList() {
        const list = document.getElementById('flowArchivesList');
        if (!list) return;
        const sortSelect = document.getElementById('archiveSort');
        if (sortSelect && !sortSelect.value) {
            sortSelect.value = 'newest';
        }
        const archives = this.core.data.archives || [];
        const filterState = this.getArchiveFilterState();
        const filtered = this.applyArchiveFilters(archives, filterState);
        this.updateArchiveSummary(filtered, filterState, archives.length);

        if (!archives.length) {
            list.innerHTML = `<div class="flow-archive-empty">Nenhum fluxo anterior disponível. Arquive o fluxo atual para começar.</div>`;
            const detail = document.getElementById('flowArchiveDetail');
            if (detail) detail.innerHTML = '';
            this.renderArchiveCompareOptions([]);
            return;
        }

        if (!filtered.length) {
            list.innerHTML = `<div class="flow-archive-empty">Nenhum fluxo encontrado com os filtros atuais. Ajuste a busca ou o período.</div>`;
            const detail = document.getElementById('flowArchiveDetail');
            if (detail) detail.innerHTML = '';
            this.renderArchiveCompareOptions([]);
            return;
        }

        let newestId = null;
        filtered.forEach(item => {
            if (!item.createdAt) return;
            if (!newestId) {
                newestId = item.archive?.id || null;
                return;
            }
            const current = filtered.find(entry => entry.archive?.id === newestId);
            const currentTime = current?.createdAt?.getTime?.() || 0;
            const candidateTime = item.createdAt.getTime();
            if (candidateTime > currentTime) {
                newestId = item.archive?.id || null;
            }
        });

        list.innerHTML = filtered.map(item => {
            const archive = item.archive;
            const createdAt = item.createdAt ? item.createdAt.toLocaleString('pt-BR') : 'Data não informada';
            const company = archive.company ? `Empresa: ${archive.company}` : 'Empresa não informada';
            const createdBy = archive.created_by ? `Criado por ${archive.created_by}` : 'Criador não informado';
            const pending = Math.max(item.stats.count - item.stats.signed, 0);
            const isActive = this.selectedArchiveId === archive.id;
            const isNewest = newestId && archive.id === newestId;
            return `
                <div class="flow-archive-card ${isActive ? 'active' : ''}" data-archive-id="${archive.id}" role="button" tabindex="0">
                    <div class="flow-archive-title">
                        ${archive.label}
                        ${isNewest ? '<span class="flow-archive-badge">Novo</span>' : ''}
                    </div>
                    <div class="flow-archive-meta">${company} • ${createdBy}</div>
                    <div class="flow-archive-meta">${createdAt}</div>
                    <div class="flow-archive-total">R$ ${item.stats.total.toLocaleString('pt-BR')}</div>
                    <div class="flow-archive-tags">
                        <span class="flow-archive-pill">Pagamentos: ${item.stats.count}</span>
                        <span class="flow-archive-pill">Assinados: ${item.stats.signed}</span>
                        <span class="flow-archive-pill">Pendentes: ${pending}</span>
                    </div>
                </div>
            `;
        }).join('');
        this.renderArchiveCompareOptions(filtered.map(item => item.archive));

        if (!list.dataset.boundArchiveClick) {
            list.addEventListener('click', (event) => {
                const button = event.target.closest('[data-archive-id]');
                if (!button) return;
                const id = button.getAttribute('data-archive-id');
                const selected = (this.core.data.archives || []).find(a => a.id === id);
                this.selectedArchiveId = id;
                list.querySelectorAll('.flow-archive-card').forEach(b => b.classList.remove('active'));
                button.classList.add('active');
                this.renderFlowArchiveDetail(selected);
            });
            list.dataset.boundArchiveClick = 'true';
        }

        const first = list.querySelector('[data-archive-id]');
        if (first && !list.querySelector('.flow-archive-card.active')) {
            first.classList.add('active');
            const id = first.getAttribute('data-archive-id');
            this.selectedArchiveId = id;
            const selected = archives.find(a => a.id === id);
            this.renderFlowArchiveDetail(selected);
        }
    }

    renderArchiveCompareOptions(archives) {
        const selectA = document.getElementById('archiveCompareA');
        const selectB = document.getElementById('archiveCompareB');
        if (!selectA || !selectB) return;
        const options = archives.map(a => `<option value="${a.id}">${a.label}</option>`).join('');
        selectA.innerHTML = options;
        selectB.innerHTML = options;
        if (selectA.options.length > 1) {
            selectA.selectedIndex = 0;
            selectB.selectedIndex = 1;
        }
        const result = document.getElementById('archiveCompareResult');
        if (result) result.textContent = '';
    }

    computeArchiveStats(archive) {
        const payments = Array.isArray(archive?.payments) ? archive.payments : [];
        const total = payments.reduce((sum, p) => sum + Math.abs(Number(p.valor) || 0), 0);
        const signed = payments.filter(p => p.assinatura).length;
        return {
            total,
            count: payments.length,
            signed
        };
    }

    compareArchives(a, b) {
        const result = document.getElementById('archiveCompareResult');
        if (!result) return;
        if (!a || !b) {
            result.textContent = 'Selecione dois fluxos para comparar.';
            return;
        }
        const statsA = this.computeArchiveStats(a);
        const statsB = this.computeArchiveStats(b);
        const deltaTotal = statsB.total - statsA.total;
        const deltaCount = statsB.count - statsA.count;
        const deltaSigned = statsB.signed - statsA.signed;
        result.innerHTML = `
            <strong>Comparação</strong><br>
            A: ${a.label}<br>
            B: ${b.label}<br><br>
            Total A: R$ ${statsA.total.toLocaleString('pt-BR')}<br>
            Total B: R$ ${statsB.total.toLocaleString('pt-BR')}<br>
            Diferença Total (B - A): R$ ${deltaTotal.toLocaleString('pt-BR')}<br><br>
            Registros A: ${statsA.count} | B: ${statsB.count} | Diferença: ${deltaCount}<br>
            Assinados A: ${statsA.signed} | B: ${statsB.signed} | Diferença: ${deltaSigned}
        `;
    }
    renderFlowArchiveDetail(archive) {
        const detail = document.getElementById('flowArchiveDetail');
        if (!detail) return;
        if (!archive) {
            detail.innerHTML = '';
            return;
        }
        const canDelete = this.core.admin.hasPermission(this.core.currentUser, 'delete_archive');
        const canExport = this.core.admin.hasPermission(this.core.currentUser, 'export_archives') ||
            this.core.admin.hasPermission(this.core.currentUser, 'export_payments');
        const payments = Array.isArray(archive.payments) ? archive.payments : [];
        const rows = payments.map(p => `
            <tr>
                <td>${p.fornecedor || ''}</td>
                <td>${p.data || ''}</td>
                <td>${p.descricao || ''}</td>
                <td>R$ ${Number(p.valor || 0).toLocaleString('pt-BR')}</td>
                <td>${p.centro || ''}</td>
                <td>${p.categoria || ''}</td>
                <td>${p.assinatura ? 'Assinado' : 'Pendente'}</td>
                <td>${p.assinatura ? `Assinado por ${p.assinatura.usuarioNome}` : '-'}</td>
                <td>${p.assinatura?.hash || '-'}</td>
            </tr>
        `).join('');

        detail.innerHTML = `
            <div class="flex-header">
                <strong>${archive.label}</strong>
                <div class="actions">
                    ${canExport ? `<button class="btn btn-ghost" data-archive-export="${archive.id}">Exportar XLSX</button>` : ''}
                    ${canDelete ? `<button class="btn btn-danger" data-archive-delete="${archive.id}">Excluir</button>` : ''}
                </div>
            </div>
            <div class="data-table-wrapper data-table-spaced">
                <table>
                    <thead>
                        <tr>
                            <th>Fornecedor</th>
                            <th>Data</th>
                            <th>Descrição</th>
                            <th>Valor</th>
                            <th>Centro de Custo</th>
                            <th>Categoria</th>
                            <th>Status</th>
                            <th>Assinatura</th>
                            <th>ID da Assinatura</th>
                        </tr>
                    </thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>
        `;
    }

    async loadLoginAudits() {
        const body = document.getElementById('auditLoginsBody');
        if (!body) return;
        body.innerHTML = `<tr><td colspan="5">Carregando...</td></tr>`;
        try {
            const response = await fetch(`${getApiBase()}/api/audit/logins`, {
                cache: 'no-store',
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                }
            });
            if (!response.ok) {
                body.innerHTML = `<tr><td colspan="5">Falha ao carregar acessos.</td></tr>`;
                return;
            }
            const data = await response.json();
            const items = Array.isArray(data.items) ? data.items : [];
            if (!items.length) {
                body.innerHTML = `<tr><td colspan="5">Nenhum acesso registrado.</td></tr>`;
                return;
            }
            body.innerHTML = items.map(item => {
                const date = item.created_at ? new Date(item.created_at).toLocaleString('pt-BR') : '-';
                const status = item.success ? 'Sucesso' : 'Falha';
                return `
                    <tr>
                        <td>${date}</td>
                        <td>${item.username || '-'}</td>
                        <td>${item.ip || '-'}</td>
                        <td>${status}</td>
                        <td>${item.details || '-'}</td>
                    </tr>
                `;
            }).join('');
        } catch (error) {
            body.innerHTML = `<tr><td colspan="5">Erro ao carregar acessos.</td></tr>`;
        }
    }

    openCreateUserModal() {
        const modal = document.getElementById('createUserModal');
        if (modal) {
            modal.classList.add('is-open');
            // Populate role select
            const roleSelect = document.getElementById('userRole');
            roleSelect.innerHTML = '<option value="">Selecione um cargo</option>';
            this.core.admin.roles.forEach(role => {
                const option = document.createElement('option');
                option.value = role.name;
                option.textContent = role.name;
                roleSelect.appendChild(option);
            });
        }
    }

    openCreateRoleModal() {
        const modal = document.getElementById('createRoleModal');
        if (modal) {
            modal.classList.add('is-open');
        }
    }

    closeModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.remove('is-open');
        }
    }

    openModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.add('is-open');
            if(modalId === 'addPaymentModal'){ this.populateCostCentersDatalist(); } // ALTERADO
        }
    }

    openCenterAssignmentModal(centerName) {
        const modal = document.getElementById('centerAssignModal');
        if (!modal) return;
        if (modal.classList.contains('is-open')) return;
        const labelEl = document.getElementById('centerAssignName');
        if (labelEl) labelEl.textContent = centerName;
        const companySelect = document.getElementById('centerAssignCompany');
        if (companySelect) {
            const current = this.core.data.getCenterCompanyOverride(centerName) || this.core.data.getCompanyForCenter(centerName) || 'Outros';
            companySelect.value = current;
        }
        modal.dataset.centerName = centerName;
        modal.classList.add('is-open');
    }

    saveCenterAssignmentFromModal() {
        const modal = document.getElementById('centerAssignModal');
        const center = modal?.dataset?.centerName ? String(modal.dataset.centerName).trim() : '';
        const company = String(document.getElementById('centerAssignCompany')?.value || '').trim();
        if (!center || !company) {
            showToast('Selecione a empresa para este centro de custo.', 'warn');
            return;
        }
        this.core.data.setCenterCompany(center, company);
        this.closeModal('centerAssignModal');
        this.renderCenterCompanyEditor();
        this.renderPaymentsTable();
        this.updateStats();
        showToast(`Centro "${center}" salvo para ${company}.`, 'success');
        this.core.audit?.log?.('CENTRO VINCULADO', `Centro ${center} vinculado a ${company}.`, 'centro_de_custo');

        const nextKey = Array.from(this.core.data.pendingCenterAssignments || [])[0];
        if (!nextKey) return;
        const nextCenter = (this.core.data.costCenters || []).find(c => this.core.data._key(c) === nextKey);
        if (nextCenter) {
            this.openCenterAssignmentModal(nextCenter);
        }
    }

    populateCostCentersDatalist(){ // ALTERADO
      const el = document.getElementById('centrosDataList');
      if(!el) return;
      el.innerHTML = '';
      (this.core.data.getCostCenters() || []).forEach(c => {
        const opt = document.createElement('option');
        opt.value = c;
        el.appendChild(opt);
      });
    } // ALTERADO

    createUser() {
        const nome = prompt('Nome do usuário:');
        const username = prompt('Username:');
        const email = prompt('Email:');
        const password = prompt('Senha:');
        const role = prompt('Cargo (admin, gestor, etc.):');
        if(nome && username && email && password && role) {
            this.core.admin.createUser(nome, email, password, role, username);
            this.renderUsersTable();
        }
    }

    editUser(id) {
        const user = this.core.admin.users.find(u => Number(u.id) === Number(id));
        if(!user) return;
        // Populate role select with current roles
        const roleSelect = document.getElementById('editUserRole');
        if (roleSelect) {
            roleSelect.innerHTML = '';
            this.core.admin.roles.forEach(role => {
                const option = document.createElement('option');
                option.value = role.name;
                option.textContent = role.name;
                roleSelect.appendChild(option);
            });
        }
        // Populate edit modal
        document.getElementById('editUserName').value = user.nome;
        document.getElementById('editUserUsername').value = user.usuario;
        document.getElementById('editUserEmail').value = user.email;
        document.getElementById('editUserRole').value = user.cargo;
        document.getElementById('editUserId').value = user.id;
        this.openModal('editUserModal');
    }

    changePassword(id) {
        const user = this.core.admin.users.find(u => Number(u.id) === Number(id));
        if(!user) return;
        document.getElementById('changePasswordUserId').value = user.id;
        document.getElementById('changePasswordUserName').textContent = user.nome;
        this.openModal('changePasswordModal');
    }

    async editUserFromModal() {
        const form = document.getElementById('editUserForm');
        const formData = new FormData(form);
        const id = parseInt(formData.get('editUserId'));
        const nome = formData.get('editUserName').trim();
        const usuario = formData.get('editUserUsername').trim();
        const email = formData.get('editUserEmail').trim();
        const cargo = formData.get('editUserRole');

        if (nome && usuario && email && cargo) {
            await this.core.admin.updateUser(id, { nome, usuario, email, cargo });
            this.closeModal('editUserModal');
            this.renderUsersTable();
            form.reset();
        } else {
            alert('Por favor, preencha todos os campos obrigatórios.');
        }
    }

    async changePasswordFromModal() {
        const form = document.getElementById('changePasswordForm');
        const formData = new FormData(form);
        const id = parseInt(formData.get('changePasswordUserId'));
        const newPassword = formData.get('newPassword');
        const confirmPassword = formData.get('confirmPassword');

        if (!newPassword || !confirmPassword) {
            alert('Por favor, preencha ambos os campos de senha.');
            return;
        }
        if (newPassword !== confirmPassword) {
            alert('As senhas não coincidem.');
            return;
        }
        await this.core.admin.updateUser(id, { senha: newPassword });
        this.closeModal('changePasswordModal');
        this.renderUsersTable();
        form.reset();
        alert('Senha alterada com sucesso.');
    }

    editRole(id) {
        const role = this.core.admin.roles.find(r => r.id === id);
        if(!role) return;
        const name = prompt('Nome do cargo:', role.name);
        const permissions = prompt('Permissões (separadas por vírgula):', role.permissions.join(', '));
        if(name && permissions) {
            this.core.admin.updateRole(id, { name, permissions: permissions.split(',').map(p => p.trim()) });
            this.renderRolesTable();
        }
    }

    renderPaymentsTable() {
        const body = document.getElementById('paymentsBody');
        if (!body) return;

        const canSeeQr = this.core.admin.hasPermission(this.core.currentUser, 'sign_payments') ||
            this.core.admin.hasPermission(this.core.currentUser, 'admin_access');
        const publicBase = `${getApiBase()}/verify.html?id=`;

        const rowsRaw = this.getFilteredPayments ? this.getFilteredPayments() : this.core.data.records;
        const rows = (rowsRaw || []).slice().sort((a, b) => {
            const aTime = a?.created_at ? new Date(a.created_at).getTime() : 0;
            const bTime = b?.created_at ? new Date(b.created_at).getTime() : 0;
            if (aTime !== bTime) return aTime - bTime;
            return String(a?.id || '').localeCompare(String(b?.id || ''));
        });

        body.innerHTML = rows.map(p => {
            const assinaturaTime = p.assinatura?.dataISO
                ? new Date(p.assinatura.dataISO).toLocaleString('pt-BR')
                : '';
            const assinaturaStr = p.assinatura
                ? `Assinado por: ${p.assinatura.usuarioNome}` // ALTERADO
                : '-'; // ALTERADO

        const canSign = this.core.admin.hasPermission(this.core.currentUser, 'sign_payments');
        const canSignCenter = this.core.admin.canSignCenter(this.core.currentUser, p.centro);
        const acoesHtml = p.assinatura
            ? '<span>Assinado</span>' // manter simples, sem CSS novo // ALTERADO
            : (canSign && canSignCenter ? `<button class="btn btn-primary" data-payment-action="sign" data-payment-id="${p.id}">Assinar</button>` : '—'); // ALTERADO
            const qrHtml = (canSeeQr && p.assinatura?.hash)
                ? `<a class="btn btn-ghost btn-verify" href="${publicBase}${p.assinatura.hash}" target="_blank" rel="noopener">Verificar</a>`
                : '';

            const rowClass = p.assinatura ? 'payment-row-signed' : '';
            return `
                <tr class="${rowClass}">
                    <td><strong>${p.fornecedor || ''}</strong></td>
                    <td>${p.data || ''}</td>
                    <td>${(p.descricao || '').trim() || '—'}</td>
                    <td>R$ ${Number(p.valor || 0).toLocaleString('pt-BR')}</td>
                    <td>${(p.categoria || '').trim() || '—'}</td>
                    <td>${p.centro || ''}</td>
                    <td>
                        <span class="badge ${p.assinatura ? 'badge-signed' : 'badge-pending'}">
                            ${p.assinatura ? 'Assinado' : 'Pendente'}
                        </span>
                    </td>
                    <td>
                        ${p.assinatura
                            ? `<div class="signature-highlight">${assinaturaStr}</div><div class="signature-time">${assinaturaTime}</div>`
                            : '<span>—</span>'}
                        ${qrHtml}
                    </td>
                    <td>${acoesHtml}</td> <!-- ALTERADO -->
                </tr>
            `;
        }).join('');

        this.updateStats && this.updateStats(); // manter comportamento existente // ALTERADO
        this.renderCompanyTotals && this.renderCompanyTotals();
        this.renderSignatureQrCodes && this.renderSignatureQrCodes();
        this.updateFlowStatusBadges && this.updateFlowStatusBadges();

        if (!body.dataset.boundPayments) {
            body.addEventListener('click', (event) => {
                const button = event.target.closest('button[data-payment-action]');
                if (!button) return;
                const action = button.getAttribute('data-payment-action');
                const id = button.getAttribute('data-payment-id');
                if (action === 'sign' && id) {
                    this.core?.data?.sign?.(id);
                }
            });
            body.dataset.boundPayments = 'true';
        }
    }

    renderSignatureQrCodes() {
        // Mantido por compatibilidade: a tabela usa apenas o botao "Verificar".
    }

    updateStats() {
        const data = this.core.data.records;
        let total = 0;
        data.forEach(p => total += Number(p.valor) || 0);
        this.totalBruto = total;
        document.getElementById('totalBruto').innerText = `R$ ${total.toLocaleString('pt-BR')}`;
        const signed = data.filter(p => p.assinatura).length;
        const pending = data.filter(p => !p.assinatura).length;
        document.getElementById('totalAssinados').innerText = signed;
        document.getElementById('totalPendentes').innerText = pending;
        this.updateDashboardSummary && this.updateDashboardSummary(pending);
    }

    renderCompanyTotals() {
        const container = document.getElementById('companyTotalsBody');
        if (!container) return;
        const totals = this.core.data.getCompanyCenterTotals();
        const companies = Object.keys(totals);
        if (!companies.length) {
            container.innerHTML = '<div class="company-total-empty">Sem dados para exibir.</div>';
            return;
        }

        const rows = companies.map((company) => {
            const entry = totals[company];
            const centers = Object.entries(entry.centers)
                .filter(([, total]) => total > 0)
                .sort((a, b) => b[1] - a[1])
                .map(([center, total]) => `
                    <div class="company-total-row company-total-center">
                        <span>${center}</span>
                        <strong>R$ ${total.toLocaleString('pt-BR')}</strong>
                    </div>
                `)
                .join('');

            return `
                <div class="company-total-group">
                    <div class="company-total-row company-total-header">
                        <span>${company}</span>
                        <strong>R$ ${entry.total.toLocaleString('pt-BR')}</strong>
                    </div>
                    ${centers}
                </div>
            `;
        }).join('');

        container.innerHTML = rows;
    }

    parseValorInput(v) { // ALTERADO
        if (typeof v === 'number') return v;
        const s = String(v || '').trim();
        if (!s) return 0;
        // pt-BR: 1.234,56 -> 1234.56
        const normalized = s.replace(/\./g, '').replace(',', '.');
        const n = Number(normalized);
        return isNaN(n) ? 0 : n;
    } // ALTERADO

    addPaymentFromModal(){ // EXISTENTE ou NOVO // ALTERADO
      if (!this.core.admin.hasPermission(this.core.currentUser, 'add_payments')) {
        alert('Você não tem permissão para adicionar pagamentos.');
        return;
      }
      const form = document.getElementById('addPaymentForm');
      const fd = new FormData(form);
      const fornecedor = (fd.get('fornecedor') || '').trim();
      const data = fd.get('data');
      const descricao = (fd.get('descricao') || '').trim();
      const valor = this.parseValorInput ? this.parseValorInput(fd.get('valor')) : Number(String(fd.get('valor')||'').replace(/\./g,'').replace(',','.')) || 0;
      let centro = (fd.get('centro') || '').trim();
      const categoria = (fd.get('categoria') || '').trim();

      if (!fornecedor || !data || !valor) {
        alert('Preencha Fornecedor, Data e Valor.');
        return;
      }

      // Se o centro é novo, confirmar ou permitir editar // ALTERADO
      if(!this.core.data.hasCostCenter(centro)){
        const manter = confirm(`Detectamos um novo Centro de Custo: "${centro}".\n\nClique "OK" para ADICIONAR ASSIM MESMO.\nClique "Cancelar" para EDITAR o nome.`);
        if(!manter){
          const editado = (prompt('Informe o nome do Centro de Custo:', centro) || '').trim();
          if(!editado){ return; } // usuário cancelou // ALTERADO
          centro = editado;
        }
        this.core.data.ensureCostCenter(centro); // persiste // ALTERADO
        this.populateCostCentersDatalist(); // atualiza sugestões // ALTERADO
      }

      this.core.data.addPayment({ fornecedor, data, descricao, valor, centro, categoria }); // ALTERADO
      if (window.assistant) window.assistant.addLearningQuestion(`Quantos pagamentos estão aguardando assinatura?`, `Há ${this.core.data.records.filter(p => !p.assinatura).length} pagamentos aguardando assinatura.`); // ALTERADO
      form.reset();
      this.closeModal('addPaymentModal');
    } // ALTERADO

    initCharts() {
        const canvas = document.getElementById('financeChart');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        if (this.financeChart) {
            this.financeChart.destroy();
        }
        this.financeChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: ['Jan', 'Fev', 'Mar', 'Abr', 'Mai'],
                datasets: [{
                    label: 'Volume de Pagamentos (Simulado)',
                    data: [12000, 19000, 3000, 5000, 20000],
                    borderColor: '#0a66c2',
                    tension: 0.4,
                    fill: true,
                    backgroundColor: 'rgba(10, 102, 194, 0.1)'
                }]
            },
            options: { responsive: true, plugins: { legend: { display: false } } }
        });
    }
}

class AuditLogger {
    constructor(core) {
        this.core = core;
        this.logs = JSON.parse(localStorage.getItem(core.storageKeys.LOGS)) || [];
        this.filterText = '';
        window.DMF_CONTEXT.logs = this.logs;
        console.log('DMF_CONTEXT after AuditLogger init:', window.DMF_CONTEXT);
    }

    log(acao, detalhes, entidade = null, recordId = null) {
        const entry = {
            acao,
            detalhes,
            entidade,
            recordId,
            userId: this.core.currentUser ? this.core.currentUser.id : null,
            userEmail: this.core.currentUser ? this.core.currentUser.email : null,
            dataISO: new Date().toISOString(),
            userAgent: navigator.userAgent
        };
        this.logs.unshift(entry);
        localStorage.setItem(this.core.storageKeys.LOGS, JSON.stringify(this.logs));
        window.DMF_CONTEXT.logs = this.logs;
        console.log('DMF_CONTEXT after log:', window.DMF_CONTEXT);
        this.renderLogs();
    }

    renderLogs() {
        const body = document.getElementById('auditBody');
        if(!body) return;
        const query = String(this.filterText || '').trim().toLowerCase();
        const filtered = query
            ? this.logs.filter(l => {
                const hay = `${l.userEmail || ''} ${l.acao || ''} ${l.detalhes || ''}`.toLowerCase();
                return hay.includes(query);
            })
            : this.logs;
        body.innerHTML = filtered.slice(0, 50).map(l => `
            <tr><td>${new Date(l.dataISO).toLocaleString()}</td><td>${l.userEmail || 'Sistema'}</td><td><strong>${l.acao}</strong></td><td>${l.detalhes || ''}</td></tr>
        `).join('');
    }

    setFilter(value) {
        this.filterText = value || '';
        this.renderLogs();
    }

    async searchSignatureById() {
        const input = document.getElementById('signatureSearchInput');
        const result = document.getElementById('signatureSearchResult');
        if (!input || !result) return;
        const query = String(input.value || '').trim();
        if (!query) {
            result.innerHTML = '<div class="signature-search-empty">Informe um ID de assinatura.</div>';
            return;
        }

        const match = (this.core.data.records || []).find(p => p.assinatura && String(p.assinatura.hash) === query);
        if (!match) {
            result.innerHTML = '<div class="signature-search-empty">Assinatura não encontrada.</div>';
            return;
        }

        const assinaturaData = match.assinatura?.dataISO
            ? new Date(match.assinatura.dataISO).toLocaleString('pt-BR')
            : '-';

        let validStatus = 'Verificando...';
        try {
            const verify = await fetch(`${getApiBase()}/api/signatures/verify`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                },
                body: JSON.stringify({
                    paymentId: match.id,
                    userName: match.assinatura?.usuarioNome || '',
                    dataISO: match.assinatura?.dataISO || '',
                    valor: match.valor || '',
                    centro: match.centro || '',
                    hash: match.assinatura?.hash || ''
                })
            });
            if (verify.ok) {
                const data = await verify.json();
                validStatus = data.valid ? 'VÁLIDA' : 'INVÁLIDA';
            } else {
                validStatus = 'NÃO VERIFICADA';
            }
        } catch (error) {
            validStatus = 'NÃO VERIFICADA';
        }

        result.innerHTML = `
            <div class="signature-search-card">
                <div><strong>Fornecedor:</strong> ${match.fornecedor || '-'}</div>
                <div><strong>Data:</strong> ${match.data || '-'}</div>
                <div><strong>Valor:</strong> R$ ${(Number(match.valor)||0).toLocaleString('pt-BR')}</div>
                <div><strong>Centro de Custo:</strong> ${match.centro || '-'}</div>
                <div><strong>Assinado por:</strong> ${match.assinatura?.usuarioNome || '-'}</div>
                <div><strong>Assinado em:</strong> ${assinaturaData}</div>
                <div><strong>ID da Assinatura:</strong> ${match.assinatura?.hash || '-'}</div>
                <div><strong>Validação:</strong> ${validStatus}</div>
            </div>
        `;
    }
}

class AdminManager {
    constructor(core) {
        this.core = core;
        this.users = JSON.parse(localStorage.getItem(core.storageKeys.USERS)) || [
            { id: 1, nome: 'Administrador DMF', email: 'admin@dmf.local', senha: hash('Admin@123'), cargo: 'admin', usuario: 'admin' }
        ];

        // Migrate existing users to new structure if needed
        this.users.forEach(user => {
            if (user.role) {
                user.cargo = user.role;
                delete user.role;
            }
            if (user.password) {
                user.senha = user.password;
                delete user.password;
            }
            if (user.username) {
                user.usuario = user.username;
                delete user.username;
            }
            if (!user.usuario) {
                user.usuario = user.email;
            }
        });

        // Create default admin user if not exists
        const defaultAdminExists = this.users.some(u => u.usuario === 'admin' && u.email === 'admin@dmf.local');
        if (!defaultAdminExists) {
            const defaultAdmin = {
                id: Date.now(),
                nome: 'Administrador DMF',
                usuario: 'admin',
                email: 'admin@dmf.local',
                senha: hash('admin'),
                cargo: 'admin'
            };
            this.users.push(defaultAdmin);
        }

        // Load roles from localStorage with fallback
        this.roles = JSON.parse(localStorage.getItem(core.storageKeys.ROLES)) || [
            { id: 1, name: 'admin', permissions: ['all'] },
            { id: 2, name: 'gestor', permissions: ['sign_payments'] },
            { id: 3, name: 'user', permissions: [] }
        ];

        // Ensure baseline roles exist (useful on new domains like GCloud)
        const ensureRole = (name, permissions) => {
            const existing = this.roles.find(r => r.name === name);
            if (!existing) {
                this.roles.push({ id: Date.now() + Math.random(), name, permissions });
                return;
            }
            // Merge permissions if role exists but is missing required ones
            const merged = Array.from(new Set([...(existing.permissions || []), ...(permissions || [])]));
            existing.permissions = merged;
        };
        ensureRole('admin', ['all']);
        ensureRole('gestor', ['sign_payments']);
        ensureRole('user', []);
        this.centerPermissions = JSON.parse(localStorage.getItem(core.storageKeys.COST_CENTER_RULES) || '{}');
        this.saveUsers();
        this.saveRoles();
        this.saveCenterPermissions();
        window.DMF_CONTEXT.usuarios = this.users;
        window.DMF_CONTEXT.centerPermissions = this.centerPermissions;
        window.DMF_BRAIN.usuarios = this.users;
        console.log('DMF_CONTEXT after AdminManager init:', window.DMF_CONTEXT);
        console.log('DMF_BRAIN after AdminManager init:', window.DMF_BRAIN);
    }

    normalizeEmail(email) {
        return String(email || '').trim().toLowerCase();
    }

    normalizeUsername(username) {
        return String(username || '').trim();
    }

    isValidEmail(email) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || '').trim());
    }

    isValidRole(role) {
        return this.roles.some(r => r.name === role);
    }

    validateUserInput({ nome, usuario, email, senha, cargo }, { allowPartial = false } = {}) {
        const errors = [];

        if (!allowPartial || nome !== undefined) {
            if (!String(nome || '').trim() || String(nome || '').trim().length < 2) {
                errors.push('Nome deve ter pelo menos 2 caracteres.');
            }
        }

        if (!allowPartial || usuario !== undefined) {
            const u = String(usuario || '').trim();
            if (!u || u.length < 3 || u.length > 50) {
                errors.push('Usuário deve ter entre 3 e 50 caracteres.');
            }
        }

        if (!allowPartial || email !== undefined) {
            if (!this.isValidEmail(email)) {
                errors.push('Email inválido.');
            }
        }

        if (!allowPartial || senha !== undefined) {
            if (!String(senha || '').trim() || String(senha || '').trim().length < 8) {
                errors.push('Senha deve ter no mínimo 8 caracteres.');
            }
        }

        if (!allowPartial || cargo !== undefined) {
            if (!cargo || !this.isValidRole(cargo)) {
                errors.push('Cargo inválido.');
            }
        }

        return errors;
    }

    async refreshUsersFromApi() {
        if (!getAuthHeaders().Authorization) return false;
        try {
            const response = await fetch(`${getApiBase()}/api/users`, {
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                }
            });
            if (!response.ok) {
                console.warn('API list users failed:', response.status);
                return false;
            }
            const data = await response.json();
            const users = (data.users || []).map(u => ({
                id: Number(u.id),
                nome: u.name || u.username,
                usuario: u.username,
                email: u.email,
                cargo: normalizeRole(u.role),
                senha: null
            }));
            this.users = users;
            this.saveUsers();
            window.DMF_CONTEXT.usuarios = this.users;
            window.DMF_BRAIN.usuarios = this.users;
            return true;
        } catch (error) {
            console.warn('API list users unavailable:', error.message);
            return false;
        }
    }

    async refreshRolesFromApi() {
        if (!getAuthHeaders().Authorization) return false;
        try {
            const response = await fetch(`${getApiBase()}/api/roles`, {
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                }
            });
            if (!response.ok) {
                console.warn('API list roles failed:', response.status);
                return false;
            }
            const data = await response.json();
            const roles = (data.roles || []).map(r => ({
                id: r.id || Date.now() + Math.random(),
                name: r.name,
                permissions: Array.isArray(r.permissions) ? r.permissions : []
            }));
            if (roles.length) {
                this.roles = roles;
                this.saveRoles();
            }
            return true;
        } catch (error) {
            console.warn('API list roles unavailable:', error.message);
            return false;
        }
    }

    async upsertRoleToApi(role) {
        if (!getAuthHeaders().Authorization || !role?.name) return false;
        try {
            const response = await fetch(`${getApiBase()}/api/roles/${encodeURIComponent(role.name)}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                },
                body: JSON.stringify({ permissions: role.permissions || [] })
            });
            if (!response.ok) {
                console.warn('API upsert role failed:', response.status);
                return false;
            }
            return true;
        } catch (error) {
            console.warn('API upsert role unavailable:', error.message);
            return false;
        }
    }

    async deleteRoleFromApi(name) {
        if (!getAuthHeaders().Authorization || !name) return false;
        try {
            const response = await fetch(`${getApiBase()}/api/roles/${encodeURIComponent(name)}`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                }
            });
            if (!response.ok) {
                console.warn('API delete role failed:', response.status);
                return false;
            }
            return true;
        } catch (error) {
            console.warn('API delete role unavailable:', error.message);
            return false;
        }
    }

    requireAdmin() {
        if (!this.hasPermission(this.core.currentUser, 'admin_access')) {
            alert('Somente o cargo ADMIN pode gerenciar usuários e cargos.');
            return false;
        }
        return true;
    }

    saveUsers() {
        localStorage.setItem(this.core.storageKeys.USERS, JSON.stringify(this.users));
    }

    saveRoles() {
        localStorage.setItem(this.core.storageKeys.ROLES, JSON.stringify(this.roles));
    }

    saveCenterPermissions() {
        localStorage.setItem(this.core.storageKeys.COST_CENTER_RULES, JSON.stringify(this.centerPermissions || {}));
    }

    normalizeCenter(center) {
        return String(center || '')
            .normalize('NFD')
            .replace(/[\u0300-\u036f]/g, '')
            .trim()
            .toLowerCase();
    }

    getUserCenterRule(userId) {
        return this.centerPermissions[String(userId)] || { mode: 'all', centers: [] };
    }

    setUserCenterRule(userId, rule) {
        const normalizedCenters = Array.isArray(rule.centers)
            ? rule.centers.map(c => this.normalizeCenter(c)).filter(Boolean)
            : [];
        this.centerPermissions[String(userId)] = {
            mode: rule.mode === 'allow' ? 'allow' : 'all',
            centers: Array.from(new Set(normalizedCenters))
        };
        this.saveCenterPermissions();
        window.DMF_CONTEXT.centerPermissions = this.centerPermissions;
        this.core.audit.log('ATUALIZAÇÃO CENTROS', `Permissões de centro atualizadas para usuário ${userId}.`);
    }

    canSignCenter(user, center) {
        if (!user) return false;
        if (this.hasPermission(user, 'admin_access')) return true;
        const rule = this.getUserCenterRule(user.id);
        if (!rule || rule.mode === 'all') return true;
        const normalized = this.normalizeCenter(center);
        return rule.centers.includes(normalized);
    }

    async createUser(nome, email, senha, cargo, usuario = null) {
        if (!this.requireAdmin()) return;
        // Validate required fields
        if (!nome || !email || !senha || !cargo) {
            alert('Todos os campos são obrigatórios.');
            return;
        }
        const normalizedEmail = this.normalizeEmail(email);
        const normalizedUsername = this.normalizeUsername(usuario || normalizedEmail);
        const errors = this.validateUserInput({
            nome,
            usuario: normalizedUsername,
            email: normalizedEmail,
            senha,
            cargo
        });
        if (errors.length) {
            alert(errors.join('\n'));
            return;
        }
        // Check for duplicate usuario or email
        if (this.users.some(u => this.normalizeUsername(u.usuario) === normalizedUsername)) {
            alert('Usuário já existe.');
            return;
        }
        if (this.users.some(u => this.normalizeEmail(u.email) === normalizedEmail)) {
            alert('Email já existe.');
            return;
        }
        let apiUser = null;

        try {
            const response = await fetch(`${getApiBase()}/api/auth/register`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                },
                body: JSON.stringify({
                    username: normalizedUsername,
                    email: normalizedEmail,
                    password: senha,
                    role: cargo,
                    name: nome
                })
            });

            if (response.ok) {
                const data = await response.json();
                apiUser = data.user;
            } else if (response.status === 409) {
                alert('Usuário já existe.');
                return;
            } else {
                console.warn('API register failed:', response.status);
            }
        } catch (error) {
            console.warn('API register unavailable:', error.message);
        }

        if (!apiUser) {
            alert('Falha ao criar usuário no servidor. Verifique sua conexão e tente novamente.');
            return;
        }

        const newUser = {
            id: Number(apiUser.id),
            nome: apiUser.name || nome,
            usuario: apiUser.username,
            email: apiUser.email,
            senha: hash(senha),
            cargo
        };
        this.users.push(newUser);
        this.saveUsers();
        window.DMF_CONTEXT.usuarios = this.users;
        console.log('DMF_CONTEXT after createUser:', window.DMF_CONTEXT);
        this.core.audit.log('CRIAÇÃO USUÁRIO', `Usuário ${newUser.nome} criado com cargo ${cargo}.`);
        alert('Usuário criado com sucesso.');
        return newUser;
    }

    async updateUser(id, updates) {
        if (!this.requireAdmin()) return;
        const user = this.users.find(u => Number(u.id) === Number(id));
        if (!user) return;
        const normalizedUpdates = { ...updates };
        if (normalizedUpdates.email) normalizedUpdates.email = this.normalizeEmail(normalizedUpdates.email);
        if (normalizedUpdates.usuario) normalizedUpdates.usuario = this.normalizeUsername(normalizedUpdates.usuario);

        const errors = this.validateUserInput({
            nome: normalizedUpdates.nome,
            usuario: normalizedUpdates.usuario,
            email: normalizedUpdates.email,
            senha: normalizedUpdates.senha,
            cargo: normalizedUpdates.cargo
        }, { allowPartial: true });
        if (errors.length) {
            alert(errors.join('\n'));
            return;
        }

        // Check for duplicate usuario or email if changing (local cache)
        if (normalizedUpdates.usuario && normalizedUpdates.usuario !== user.usuario &&
            this.users.some(u => this.normalizeUsername(u.usuario) === normalizedUpdates.usuario)) {
            alert('Usuário já existe.');
            return;
        }
        if (normalizedUpdates.email && normalizedUpdates.email !== user.email &&
            this.users.some(u => this.normalizeEmail(u.email) === normalizedUpdates.email)) {
            alert('Email já existe.');
            return;
        }

        let apiUpdated = null;
        try {
            const payload = {};
            if (normalizedUpdates.usuario) payload.username = normalizedUpdates.usuario;
            if (normalizedUpdates.email) payload.email = normalizedUpdates.email;
            if (normalizedUpdates.cargo) payload.role = normalizedUpdates.cargo;
            if (normalizedUpdates.nome) payload.name = normalizedUpdates.nome;
            if (normalizedUpdates.senha) payload.password = normalizedUpdates.senha;

            const response = await fetch(`${getApiBase()}/api/users/${id}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                },
                body: JSON.stringify(payload)
            });

            if (response.ok) {
                const data = await response.json();
                apiUpdated = data.user || null;
            } else if (response.status === 409) {
                alert('Usuário já existe.');
                return;
            } else if (response.status === 401 || response.status === 403) {
                alert('Sem permissão para atualizar usuários.');
                return;
            } else {
                console.warn('API update failed:', response.status);
                alert('Falha ao atualizar usuário no servidor.');
                return;
            }
        } catch (error) {
            console.warn('API update unavailable:', error.message);
            alert('Falha ao atualizar usuário no servidor.');
            return;
        }

        if (!apiUpdated) {
            alert('Falha ao atualizar usuário no servidor.');
            return;
        }

        if (this.core.currentUser && Number(this.core.currentUser.id) === Number(id)) {
            this.core.currentUser.cargo = apiUpdated?.role || normalizedUpdates.cargo || this.core.currentUser.cargo;
            localStorage.setItem(this.core.storageKeys.SESSION, JSON.stringify(this.core.currentUser));
            const badge = document.getElementById('userRoleBadge');
            if (badge) badge.innerText = String(this.core.currentUser.cargo || '').toUpperCase();
            this.core.ui.applyRolePermissions();
            this.core.ui.enforceViewAccess();
        }

        Object.assign(user, {
            ...normalizedUpdates,
            usuario: apiUpdated?.username || normalizedUpdates.usuario || user.usuario,
            email: apiUpdated?.email || normalizedUpdates.email || user.email,
            cargo: apiUpdated?.role || normalizedUpdates.cargo || user.cargo,
            nome: apiUpdated?.name || normalizedUpdates.nome || user.nome,
            senha: normalizedUpdates.senha ? hash(normalizedUpdates.senha) : user.senha
        });

        this.saveUsers();
        this.core.audit.log('ATUALIZAÇÃO USUÁRIO', `Usuário ${user.nome} atualizado.`);
        alert('Usuário atualizado com sucesso.');
    }

    async deleteUser(id) {
        if (!this.requireAdmin()) return;
        if (this.core.currentUser && Number(this.core.currentUser.id) === Number(id)) {
            alert('Não é permitido excluir o próprio usuário logado.');
            return;
        }
        try {
            const response = await fetch(`${getApiBase()}/api/users/${id}`, {
                method: 'DELETE',
                headers: {
                    ...getAuthHeaders()
                }
            });
            if (response.ok) {
                const data = await response.json();
                if (!data.success) {
                    alert('Erro ao excluir usuário.');
                    return;
                }
            } else {
                console.warn('API delete failed:', response.status);
                alert('Erro ao excluir usuário.');
                return;
            }
        } catch (error) {
            console.warn('API delete unavailable:', error.message);
            alert('Erro ao excluir usuário.');
            return;
        }

        this.users = this.users.filter(u => Number(u.id) !== Number(id));
        this.saveUsers();
        this.core.audit.log('EXCLUSÃO USUÁRIO', `Usuário ID ${id} excluído.`);
        this.core.ui.renderUsersTable();
        alert('Usuário excluído com sucesso.');
    }

    createRole() {
        if (!this.requireAdmin()) return;
        const name = prompt('Nome do cargo:');
        const permissions = prompt('Permissões (separadas por vírgula):');
        if(name && permissions) {
            const newRole = {
                id: Date.now(),
                name,
                permissions: permissions.split(',').map(p => p.trim())
            };
            this.roles.push(newRole);
            this.saveRoles();
            this.core.audit.log('CRIAÇÃO CARGO', `Cargo ${name} criado com permissões: ${permissions}.`);
            this.core.ui.renderRolesTable();
            return newRole;
        }
    }

    createUserFromModal() {
        if (!this.requireAdmin()) return;
        const form = document.getElementById('createUserForm');
        const formData = new FormData(form);
        const nome = formData.get('userName').trim();
        const usuario = formData.get('userUsername').trim();
        const email = formData.get('userEmail').trim();
        const senha = formData.get('userPassword');
        const cargo = formData.get('userRole');

        if (nome && usuario && email && senha && cargo) {
            this.createUser(nome, email, senha, cargo, usuario).then((created) => {
                if (!created) return;
                this.core.ui.closeModal('createUserModal');
                this.core.ui.renderUsersTable();
                form.reset();
            });
        } else {
            alert('Por favor, preencha todos os campos obrigatórios.');
        }
    }

    createRoleFromModal() {
        if (!this.requireAdmin()) return;
        const form = document.getElementById('createRoleForm');
        const formData = new FormData(form);
        const name = formData.get('roleName')?.trim();
        const permissions = [];
        const addPayments = document.getElementById('rolePermAddPayments')?.value === 'yes';
        const signPayments = document.getElementById('rolePermSignPayments')?.value === 'yes';
        const viewAdmin = document.getElementById('rolePermViewAdmin')?.value === 'yes';
        const accessAudit = document.getElementById('rolePermAccessAudit')?.value === 'yes';
        const importPayments = document.getElementById('rolePermImportPayments')?.value === 'yes';
        const exportPayments = document.getElementById('rolePermExportPayments')?.value === 'yes';
        const viewArchives = document.getElementById('rolePermViewArchives')?.value === 'yes';
        const archiveFlow = document.getElementById('rolePermArchiveFlow')?.value === 'yes';
        const deleteArchive = document.getElementById('rolePermDeleteArchive')?.value === 'yes';
        const exportArchive = document.getElementById('rolePermExportArchive')?.value === 'yes';
        const compareArchives = document.getElementById('rolePermCompareArchives')?.value === 'yes';
        const auditLogin = document.getElementById('rolePermAuditLogin')?.value === 'yes';

        if (addPayments) permissions.push('add_payments');
        if (signPayments) permissions.push('sign_payments');
        if (viewAdmin) permissions.push('admin_access');
        if (accessAudit) permissions.push('audit_access');
        if (importPayments) permissions.push('import_payments');
        if (exportPayments) permissions.push('export_payments');
        if (viewArchives) permissions.push('view_archives');
        if (archiveFlow) permissions.push('archive_flow');
        if (deleteArchive) permissions.push('delete_archive');
        if (exportArchive) permissions.push('export_archives');
        if (compareArchives) permissions.push('compare_archives');
        if (auditLogin) permissions.push('audit_login_access');

        if (!name) {
            alert('Por favor, preencha o nome do cargo.');
            return;
        }
        if (permissions.length === 0) {
            alert('Por favor, selecione pelo menos uma permissão.');
            return;
        }

        const newRole = {
            id: Date.now(),
            name,
            permissions
        };
        this.roles.push(newRole);
        this.saveRoles();
        this.core.audit.log('CRIAÇÃO CARGO', `Cargo ${name} criado com permissões: ${permissions.join(', ')}.`);
        this.upsertRoleToApi(newRole);
        this.sendRoleEvent('create', newRole);
        this.core.ui.closeModal('createRoleModal');
        this.core.ui.renderRolesTable();
        form.reset();
    }

    updateRole(id, updates) {
        if (!this.requireAdmin()) return;
        const role = this.roles.find(r => r.id === id);
        if (role) {
            Object.assign(role, updates);
            this.saveRoles();
            this.core.audit.log('ATUALIZAÇÃO CARGO', `Cargo ${role.name} atualizado. Permissões: ${(role.permissions || []).join(', ')}`);
            this.upsertRoleToApi(role);
            this.sendRoleEvent('update', role);
        }
    }

    deleteRole(id) {
        if (!this.requireAdmin()) return;
        const role = this.roles.find(r => r.id === id);
        this.roles = this.roles.filter(r => r.id !== id);
        this.saveRoles();
        this.core.audit.log('EXCLUSÃO CARGO', `Cargo ${role?.name || id} excluído.`);
        if (role) this.sendRoleEvent('delete', role);
        if (role?.name) {
            this.deleteRoleFromApi(role.name);
        }
    }

    getRolePermissions(roleName) {
        const role = this.roles.find(r => r.name === roleName);
        return role ? role.permissions : [];
    }

    async sendRoleEvent(action, role) {
        try {
            await fetch(`${getApiBase()}/api/events/role-change`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                },
                body: JSON.stringify({ action, role })
            });
        } catch (_) {
            // ignore
        }
    }

    async revokeSession(id) {
        if (!this.requireAdmin()) return;
        if (this.core.currentUser && Number(this.core.currentUser.id) === Number(id)) {
            alert('Use "Revogar Sessão" para si mesmo nas configurações da sessão.');
            return;
        }
        if (!confirm('Revogar sessão deste usuário? Ele será desconectado em até 10s.')) return;
        try {
            const response = await fetch(`${getApiBase()}/api/auth/revoke/${id}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                }
            });
            if (!response.ok) {
                alert('Falha ao revogar sessão.');
                return;
            }
            this.core.audit.log('REVOGAÇÃO SESSÃO', `Sessões do usuário ${id} foram revogadas.`);
            alert('Sessão revogada com sucesso.');
        } catch (error) {
            alert('Falha ao revogar sessão.');
        }
    }

    async downloadBackup() {
        if (!this.requireAdmin()) return;
        try {
            const response = await fetch(`${getApiBase()}/api/backup`, {
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                }
            });
            if (!response.ok) {
                alert('Falha ao gerar backup.');
                return;
            }
            const data = await response.json();
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = `dmf-backup-${new Date().toISOString().slice(0,10)}.json`;
            link.click();
            URL.revokeObjectURL(url);
        } catch (error) {
            alert('Falha ao gerar backup.');
        }
    }

    async restoreBackup(file) {
        if (!this.requireAdmin()) return;
        if (!file) return;
        try {
            const text = await file.text();
            const payload = JSON.parse(text);
            const response = await fetch(`${getApiBase()}/api/restore`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                },
                body: JSON.stringify(payload)
            });
            if (!response.ok) {
                alert('Falha ao restaurar backup.');
                return;
            }
            this.core.audit.log('RESTORE', 'Backup restaurado com sucesso.');
            alert('Backup restaurado com sucesso.');
            this.core.data.loadFromBackend().then(() => {
                this.core.ui.renderPaymentsTable();
                this.core.ui.updateStats();
            });
            this.refreshUsersFromApi().then(() => {
                this.core.ui.renderUsersTable();
            });
        } catch (error) {
            alert('Falha ao restaurar backup.');
        }
    }

    hasPermission(user, permission) {
        const roleName = (user && (user.cargo || user.role)) || ''; // ALTERADO
        const rolePerms = this.getRolePermissions(roleName);        // ALTERADO
        const userPerms = (user && user.additionalPermissions) || [];
        return rolePerms.includes('all') || rolePerms.includes(permission) || userPerms.includes(permission);
    }
}

class CobliManager {
    constructor(core) {
        this.core = core;
        this.map = null;
        this.markers = [];
        this.vehicles = [];
        this.updateInterval = null;
    }

    async navigateToCobli() {
        await this.updateStats();
        await this.loadVehiclesAndMap();
    }

    async cobliProxyFetch(path, params = {}) {
        if (!path) {
            throw new Error('Cobli path not configured');
        }

        const apiBase = getApiBase();
        const url = new URL('/api/cobli/proxy', apiBase);
        url.searchParams.set('path', path);
        Object.entries(params).forEach(([key, value]) => {
            if (value !== undefined && value !== null) {
                url.searchParams.set(key, value);
            }
        });

        const response = await fetch(url.toString(), {
            headers: {
                'Content-Type': 'application/json',
                ...getAuthHeaders()
            }
        });

        if (!response.ok) {
            throw new Error(`Cobli proxy error: ${response.status}`);
        }

        return response.json();
    }

    extractArray(payload) {
        if (Array.isArray(payload)) return payload;
        if (payload && Array.isArray(payload.items)) return payload.items;
        if (payload && Array.isArray(payload.data)) return payload.data;
        return [];
    }

    extractNumber(payload, fallback = 0) {
        if (typeof payload === 'number') return payload;
        if (payload && typeof payload.count === 'number') return payload.count;
        if (payload && typeof payload.total === 'number') return payload.total;
        return fallback;
    }

    async updateStats() {
        const elements = {
            veiculos: document.getElementById('veiculosCadastrados'),
            locais: document.getElementById('locaisInteresse'),
            velVeiculo: document.getElementById('eventosVelocidadeVeiculo'),
            velVia: document.getElementById('eventosVelocidadeVia'),
            rotasCom: document.getElementById('rotasComVeiculo'),
            rotasSem: document.getElementById('rotasSemVeiculo'),
            produtividade: document.getElementById('produtividadeMedia')
        };

        Object.values(elements).forEach(el => {
            if (el) el.innerText = '...';
        });

        try {
            // Configure the Cobli API paths below to match your Cobli account.
            const COBLI_PATHS = {
                vehicles: '', // ex: '/vehicles'
                interestLocations: '', // ex: '/locations'
                speedEventsVehicle: '', // ex: '/events/speed/vehicle'
                speedEventsRoad: '', // ex: '/events/speed/road'
                routesWithVehicle: '', // ex: '/routes?with_vehicle=true'
                routesWithoutVehicle: '', // ex: '/routes?with_vehicle=false'
                productivity: '' // ex: '/fleet/productivity'
            };

            const [vehiclesResp, interestResp, speedVehResp, speedRoadResp, routesWithResp, routesWithoutResp, productivityResp] =
                await Promise.all([
                    COBLI_PATHS.vehicles ? this.cobliProxyFetch(COBLI_PATHS.vehicles) : [],
                    COBLI_PATHS.interestLocations ? this.cobliProxyFetch(COBLI_PATHS.interestLocations) : [],
                    COBLI_PATHS.speedEventsVehicle ? this.cobliProxyFetch(COBLI_PATHS.speedEventsVehicle) : [],
                    COBLI_PATHS.speedEventsRoad ? this.cobliProxyFetch(COBLI_PATHS.speedEventsRoad) : [],
                    COBLI_PATHS.routesWithVehicle ? this.cobliProxyFetch(COBLI_PATHS.routesWithVehicle) : [],
                    COBLI_PATHS.routesWithoutVehicle ? this.cobliProxyFetch(COBLI_PATHS.routesWithoutVehicle) : [],
                    COBLI_PATHS.productivity ? this.cobliProxyFetch(COBLI_PATHS.productivity) : null
                ]);

            const vehicles = this.extractArray(vehiclesResp);
            elements.veiculos && (elements.veiculos.innerText = vehicles.length);
            elements.locais && (elements.locais.innerText = this.extractArray(interestResp).length);
            elements.velVeiculo && (elements.velVeiculo.innerText = this.extractArray(speedVehResp).length);
            elements.velVia && (elements.velVia.innerText = this.extractArray(speedRoadResp).length);
            elements.rotasCom && (elements.rotasCom.innerText = this.extractArray(routesWithResp).length);
            elements.rotasSem && (elements.rotasSem.innerText = this.extractArray(routesWithoutResp).length);

            if (elements.produtividade) {
                const productivityValue = this.extractNumber(productivityResp, null);
                elements.produtividade.innerText = productivityValue === null
                    ? '-'
                    : `${Number(productivityValue).toFixed(1)}%`;
            }
        } catch (error) {
            console.error('Erro ao buscar estatísticas Cobli:', error.message);
            Object.values(elements).forEach(el => {
                if (el) el.innerText = '-';
            });
        }
    }

    async loadVehiclesAndMap() {
        try {
            const COBLI_VEHICLES_PATH = ''; // ex: '/vehicles'
            const COBLI_POSITIONS_PATH = ''; // ex: '/vehicles/positions'

            let vehiclesPayload = [];
            if (COBLI_VEHICLES_PATH) {
                vehiclesPayload = await this.cobliProxyFetch(COBLI_VEHICLES_PATH);
            }

            let positionsPayload = null;
            if (COBLI_POSITIONS_PATH) {
                positionsPayload = await this.cobliProxyFetch(COBLI_POSITIONS_PATH);
            }

            const vehicles = this.extractArray(vehiclesPayload);
            const positions = this.extractArray(positionsPayload);

            const positionsById = new Map();
            positions.forEach(p => {
                const key = p.vehicleId || p.vehicle_id || p.id;
                if (key) positionsById.set(String(key), p);
            });

            this.vehicles = vehicles.map(vehicle => {
                const id = vehicle.id || vehicle.vehicleId || vehicle.vehicle_id;
                const position = positionsById.get(String(id)) || vehicle.position || vehicle.location || {};
                const lat = position.lat || position.latitude || vehicle.lat || vehicle.latitude;
                const lng = position.lng || position.longitude || vehicle.lng || vehicle.longitude;

                return {
                    id: id || vehicle.plate || vehicle.name,
                    name: vehicle.name || vehicle.plate || `Veículo ${id || ''}`.trim(),
                    lat: Number(lat),
                    lng: Number(lng)
                };
            }).filter(v => Number.isFinite(v.lat) && Number.isFinite(v.lng));

            this.initMap();
            this.updateMarkers();
        } catch (error) {
            console.error('Erro ao carregar veículos Cobli:', error.message);
        }
    }

    initMap() {
        if (this.map) return; // Already initialized

        const mapContainer = document.getElementById('mapContainer');
        if (!mapContainer) return;

        // Initialize Leaflet map centered on Brazil
        this.map = L.map('mapContainer').setView([-15.7801, -47.9292], 4);

        // Add OpenStreetMap tiles
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '© OpenStreetMap contributors'
        }).addTo(this.map);

        // Add markers for vehicles
        this.updateMarkers();
    }

    updateMarkers() {
        if (!this.map) return;

        // Clear existing markers
        this.markers.forEach(marker => this.map.removeLayer(marker));
        this.markers = [];

        // Add new markers
        this.vehicles.forEach(vehicle => {
            const marker = L.marker([vehicle.lat, vehicle.lng])
                .addTo(this.map)
                .bindPopup(`<b>${vehicle.name}</b><br>Lat: ${vehicle.lat.toFixed(4)}<br>Lng: ${vehicle.lng.toFixed(4)}`);
            this.markers.push(marker);
        });
    }

    startRealTimeUpdates() {
        if (this.updateInterval) return; // Already running

        this.updateInterval = setInterval(() => {
            // Placeholder for real-time updates via Cobli (polling or webhooks)
            this.loadVehiclesAndMap();
        }, 5000); // Update every 5 seconds
    }

    stopRealTimeUpdates() {
        if (this.updateInterval) {
            clearInterval(this.updateInterval);
            this.updateInterval = null;
        }
    }
}

// Barramento de contexto do sistema
window.DMF_CONTEXT = {
    usuarioLogado: null,
    pagamentos: [],
    assinaturas: [],
    usuarios: [],
    logs: [],
    eventos: []
};

// Cérebro Inteligente do Sistema DMF
window.DMF_BRAIN = {
    usuarios: [],
    pagamentos: [],
    assinaturas: [],
    eventos: [],
    erros: [],
    acoes: [],
    conhecimento: [],
    memoria: []
};

// Função para registrar eventos no contexto
function registrarEvento(tipo, usuario, detalhes, entidade = null, recordId = null) {
    const evento = {
        tipo,
        usuario: usuario ? usuario.nome : 'Sistema',
        data: new Date(),
        detalhes,
        entidade,
        recordId
    };
    window.DMF_CONTEXT.eventos.push(evento);
    window.DMF_BRAIN.eventos.push(evento);
    // Manter apenas os últimos 1000 eventos
    if (window.DMF_CONTEXT.eventos.length > 1000) {
        window.DMF_CONTEXT.eventos.shift();
    }
    if (window.DMF_BRAIN.eventos.length > 1000) {
        window.DMF_BRAIN.eventos.shift();
    }
    console.log('DMF_CONTEXT after registrarEvento:', window.DMF_CONTEXT);
    console.log('DMF_BRAIN after registrarEvento:', window.DMF_BRAIN);
}

// Event listeners for modal forms
function initDomBindings() {
    const createUserForm = document.getElementById('createUserForm');
    const createRoleForm = document.getElementById('createRoleForm');
    const editUserForm = document.getElementById('editUserForm');
    const changePasswordForm = document.getElementById('changePasswordForm');

    if (createUserForm) {
        createUserForm.addEventListener('submit', function(e) {
            e.preventDefault();
            system.admin.createUserFromModal();
        });
    }

    if (createRoleForm) {
        createRoleForm.addEventListener('submit', function(e) {
            e.preventDefault();
            system.admin.createRoleFromModal();
        });
    }

    if (editUserForm) {
        editUserForm.addEventListener('submit', function(e) {
            e.preventDefault();
            system.ui.editUserFromModal();
        });
    }

    if (changePasswordForm) {
        changePasswordForm.addEventListener('submit', function(e) {
            e.preventDefault();
            system.ui.changePasswordFromModal();
        });
    }

    // Close modal when clicking outside
    window.addEventListener('click', function(event) {
        if (event.target.classList.contains('modal')) {
            event.target.classList.remove('is-open');
        }
    });

    const loginButton = document.getElementById('btnLogin');
    if (loginButton) {
        loginButton.addEventListener('click', function () {
            system?.auth?.login?.();
        });
    }

    const logoutButton = document.getElementById('btnLogout');
    if (logoutButton) {
        logoutButton.addEventListener('click', function () {
            window.dmfLogout?.();
        });
    }

    const revokeSelfButton = document.getElementById('btnRevokeSelf');
    if (revokeSelfButton) {
        revokeSelfButton.addEventListener('click', function () {
            if (!isAdminUser(system?.currentUser)) {
                return;
            }
            if (!confirm('Revogar todas as sessões ativas e sair?')) return;
            fetch(`${getApiBase()}/api/auth/revoke-self`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                }
            }).finally(() => {
                window.dmfLogout?.();
            });
        });
    }

    const clearPaymentsButton = document.getElementById('btnClearPayments');
    if (clearPaymentsButton) {
        clearPaymentsButton.addEventListener('click', function () {
            system?.data?.clearAll?.();
        });
    }

    const exportPaymentsButton = document.getElementById('btnExportPayments');
    if (exportPaymentsButton) {
        exportPaymentsButton.addEventListener('click', function () {
            system?.data?.export?.(system?.data?.currentCompany || system?.ui?.companyFilter || null);
        });
    }

    const importPaymentsButton = document.getElementById('btnImportPayments');
    const fileInput = document.getElementById('fileInput');
    if (importPaymentsButton && fileInput) {
        importPaymentsButton.addEventListener('click', function () {
            console.log('Botão Importar clicado');
            fileInput.click();
        });

        fileInput.addEventListener('change', function (event) {
            console.log('Arquivo selecionado:', event.target.files[0]);
            if (system && system.data) {
                system.data.import(event.target);
            } else {
                console.error('Sistema não inicializado');
            }
        });
    }

    const addPaymentButton = document.getElementById('btnAddPayment');
    if (addPaymentButton) {
        addPaymentButton.addEventListener('click', function () {
            system?.ui?.openModal?.('addPaymentModal');
        });
    }

    const refreshPaymentsButton = document.getElementById('btnRefreshPayments');
    if (refreshPaymentsButton) {
        refreshPaymentsButton.addEventListener('click', function () {
            system?.data?.loadFromBackend?.(true).then(() => {
                system?.ui?.renderPaymentsTable?.();
                system?.ui?.updateStats?.();
                system?.ui?.initCharts?.();
            });
        });
    }

    const createUserButton = document.getElementById('btnCreateUser');
    if (createUserButton) {
        createUserButton.addEventListener('click', function () {
            system?.ui?.openCreateUserModal?.();
        });
    }

    const createRoleButton = document.getElementById('btnCreateRole');
    if (createRoleButton) {
        createRoleButton.addEventListener('click', function () {
            system?.ui?.openCreateRoleModal?.();
        });
    }

    const backupDownloadButton = document.getElementById('btnBackupDownload');
    if (backupDownloadButton) {
        backupDownloadButton.addEventListener('click', function () {
            system?.admin?.downloadBackup?.();
        });
    }

    const backupUploadButton = document.getElementById('btnBackupUpload');
    const backupFileInput = document.getElementById('backupFileInput');
    if (backupUploadButton && backupFileInput) {
        backupUploadButton.addEventListener('click', function () {
            if (!confirm('Restaurar backup irá substituir usuários e fluxos atuais. Deseja continuar?')) {
                return;
            }
            backupFileInput.click();
        });
        backupFileInput.addEventListener('change', function (event) {
            const file = event.target.files[0];
            if (file) {
                system?.admin?.restoreBackup?.(file);
            }
        });
    }

    const chatSendButton = document.getElementById('chatSendBtn');
    if (chatSendButton) {
        chatSendButton.addEventListener('click', function () {
            window.assistant?.sendMessage?.();
        });
    }

    document.querySelectorAll('[data-close-modal]').forEach(button => {
        button.addEventListener('click', function () {
            const modalId = this.getAttribute('data-close-modal');
            if (modalId) {
                system?.ui?.closeModal?.(modalId);
            }
        });
    });

    document.querySelectorAll('[data-center-company]').forEach(button => {
        button.addEventListener('click', function () {
            const company = this.getAttribute('data-center-company');
            const modal = document.getElementById('centerAssignModal');
            const center = modal?.dataset?.centerName;
            if (center && company) {
                system?.data?.setCenterCompany?.(center, company);
                system?.ui?.closeModal?.('centerAssignModal');
                showToast(`Centro "${center}" salvo para ${company}.`, 'success');
                system?.ui?.renderPaymentsTable?.();
                system?.ui?.updateStats?.();
            }
        });
    });

    const saveCenterAssignmentButton = document.getElementById('btnSaveCenterAssignment');
    if (saveCenterAssignmentButton) {
        saveCenterAssignmentButton.addEventListener('click', function () {
            system?.ui?.saveCenterAssignmentFromModal?.();
        });
    }

    const centerCompanySearch = document.getElementById('centerCompanySearch');
    if (centerCompanySearch) {
        centerCompanySearch.addEventListener('input', function () {
            system?.ui?.renderCenterCompanyEditor?.();
        });
    }

    const saveCenterCompaniesButton = document.getElementById('btnSaveCenterCompanies');
    if (saveCenterCompaniesButton) {
        saveCenterCompaniesButton.addEventListener('click', function () {
            system?.ui?.saveAllCenterCompanies?.();
        });
    }

    // Navigation event listeners
    document.querySelectorAll('[data-nav]').forEach(button => {
        button.addEventListener('click', function() {
            const viewId = this.getAttribute('data-nav');
            system.ui.navigate(viewId, this);
        });
    });

    const paymentsToggle = document.getElementById('btnPaymentsToggle');
    const paymentsSubmenu = document.getElementById('paymentsSubmenu');
    const paymentsToggleIcon = document.getElementById('paymentsToggleIcon');
    if (paymentsToggle && paymentsSubmenu && paymentsToggleIcon) {
        paymentsToggle.addEventListener('click', function() {
            paymentsSubmenu.classList.toggle('hidden');
            const isOpen = !paymentsSubmenu.classList.contains('hidden');
            paymentsToggle.classList.toggle('is-open', isOpen);
            paymentsToggle.setAttribute('aria-expanded', String(isOpen));
        });
    }

    // Admin tab event listeners
    document.querySelectorAll('[data-admin-tab]').forEach(button => {
        button.addEventListener('click', function() {
            const tab = this.getAttribute('data-admin-tab');
            system.ui.switchAdminTab(tab, this);
        });
    });

    document.querySelectorAll('[data-audit-tab]').forEach(button => {
        button.addEventListener('click', function() {
            const tab = this.getAttribute('data-audit-tab');
            system.ui.switchAuditTab(tab, this);
        });
    });

    document.querySelectorAll('[data-payments-tab]').forEach(button => {
        button.addEventListener('click', function() {
            const tab = this.getAttribute('data-payments-tab');
            system.ui.switchPaymentsTab(tab, this);
        });
    });

    const archiveFlowButton = document.getElementById('btnArchiveFlow');
    if (archiveFlowButton) {
        archiveFlowButton.addEventListener('click', function () {
            if (!system?.admin?.hasPermission?.(system?.currentUser, 'archive_flow')) {
                alert('Você não tem permissão para arquivar fluxos.');
                return;
            }
            if (!confirm('Enviar todo o fluxo atual para Fluxos Anteriores? Isso irá limpar o fluxo atual.')) {
                return;
            }
            system?.data?.archiveCurrentFlow?.().then((archive) => {
                if (!archive) return;
                system?.ui?.renderPaymentsTable?.();
                system?.ui?.updateStats?.();
                system?.data?.loadArchivesFromBackend?.().then(() => {
                    system?.ui?.renderFlowArchivesList?.();
                });
                const historyBtn = document.querySelector('[data-payments-tab="history"]');
                if (historyBtn) {
                    system.ui.switchPaymentsTab('history', historyBtn);
                }
            });
        });
    }

    const refreshArchivesButton = document.getElementById('btnRefreshArchives');
    if (refreshArchivesButton) {
        refreshArchivesButton.addEventListener('click', function () {
            system?.data?.loadArchivesFromBackend?.().then(() => {
                system?.ui?.renderFlowArchivesList?.();
            });
        });
    }

    const flowArchiveDetail = document.getElementById('flowArchiveDetail');
    if (flowArchiveDetail) {
        flowArchiveDetail.addEventListener('click', function (event) {
            const button = event.target.closest('[data-archive-delete]');
            const exportButton = event.target.closest('[data-archive-export]');
            if (exportButton) {
                const id = exportButton.getAttribute('data-archive-export');
                const archive = (system?.data?.archives || []).find(a => a.id === id);
                system?.data?.exportArchive?.(archive);
                return;
            }
            if (!button) return;
            const id = button.getAttribute('data-archive-delete');
            if (!id) return;
            if (!confirm('Deseja excluir este fluxo anterior? Esta ação não pode ser desfeita.')) {
                return;
            }
            system?.data?.deleteArchive?.(id).then((ok) => {
                if (!ok) return;
                system?.ui?.renderFlowArchivesList?.();
                const detail = document.getElementById('flowArchiveDetail');
                if (detail) detail.innerHTML = '';
            });
        });
    }

    const filterArchivesButton = document.getElementById('btnFilterArchives');
    if (filterArchivesButton) {
        filterArchivesButton.addEventListener('click', function () {
            const start = document.getElementById('archiveStart')?.value || '';
            const end = document.getElementById('archiveEnd')?.value || '';
            document.querySelectorAll('[data-archive-range]').forEach(btn => btn.classList.remove('active'));
            system?.data?.loadArchivesFromBackend?.({ start, end }).then(() => {
                system?.ui?.renderFlowArchivesList?.();
            });
        });
    }

    const clearArchiveFilterButton = document.getElementById('btnClearArchiveFilter');
    if (clearArchiveFilterButton) {
        clearArchiveFilterButton.addEventListener('click', function () {
            const startInput = document.getElementById('archiveStart');
            const endInput = document.getElementById('archiveEnd');
            if (startInput) startInput.value = '';
            if (endInput) endInput.value = '';
            document.querySelectorAll('[data-archive-range]').forEach(btn => btn.classList.remove('active'));
            system?.data?.loadArchivesFromBackend?.().then(() => {
                system?.ui?.renderFlowArchivesList?.();
            });
        });
    }

    const archiveSearchInput = document.getElementById('archiveSearchInput');
    if (archiveSearchInput) {
        archiveSearchInput.addEventListener('input', function () {
            system?.ui?.renderFlowArchivesList?.();
        });
    }

    const archiveSortSelect = document.getElementById('archiveSort');
    if (archiveSortSelect) {
        archiveSortSelect.addEventListener('change', function () {
            system?.ui?.renderFlowArchivesList?.();
        });
    }

    const archiveRangeButtons = document.querySelectorAll('[data-archive-range]');
    if (archiveRangeButtons.length) {
        archiveRangeButtons.forEach(button => {
            button.addEventListener('click', function () {
                const range = this.getAttribute('data-archive-range');
                const startInput = document.getElementById('archiveStart');
                const endInput = document.getElementById('archiveEnd');
                const today = new Date();
                const formatDate = (date) => date.toISOString().slice(0, 10);

                archiveRangeButtons.forEach(btn => btn.classList.remove('active'));
                this.classList.add('active');

                if (range === 'all') {
                    if (startInput) startInput.value = '';
                    if (endInput) endInput.value = '';
                } else {
                    const days = Number(range);
                    const startDate = new Date(today);
                    startDate.setDate(startDate.getDate() - Math.max(days - 1, 0));
                    if (startInput) startInput.value = formatDate(startDate);
                    if (endInput) endInput.value = formatDate(today);
                }

                const start = startInput?.value || '';
                const end = endInput?.value || '';
                system?.data?.loadArchivesFromBackend?.({ start, end }).then(() => {
                    system?.ui?.renderFlowArchivesList?.();
                });
            });
        });
    }

    const compareArchivesButton = document.getElementById('btnCompareArchives');
    if (compareArchivesButton) {
        compareArchivesButton.addEventListener('click', function () {
            if (!system?.admin?.hasPermission?.(system?.currentUser, 'compare_archives')) {
                alert('Você não tem permissão para comparar fluxos anteriores.');
                return;
            }
            const selectA = document.getElementById('archiveCompareA');
            const selectB = document.getElementById('archiveCompareB');
            const idA = selectA?.value;
            const idB = selectB?.value;
            const archives = system?.data?.archives || [];
            const a = archives.find(x => x.id === idA);
            const b = archives.find(x => x.id === idB);
            system?.ui?.compareArchives?.(a, b);
        });
    }

    const reportRefreshButton = document.getElementById('btnReportRefresh');
    if (reportRefreshButton) {
        reportRefreshButton.addEventListener('click', function () {
            system?.ui?.renderMonthlyReports?.();
        });
    }

    const saveBudgetsButton = document.getElementById('btnSaveBudgets');
    if (saveBudgetsButton) {
        saveBudgetsButton.addEventListener('click', function () {
            const isAdmin = system?.admin?.hasPermission?.(system?.currentUser, 'admin_access');
            if (!isAdmin) {
                alert('Somente admin pode salvar orçamentos.');
                return;
            }
            const budgets = {
                DMF: Number(document.getElementById('budgetDMF')?.value || 0),
                JFX: Number(document.getElementById('budgetJFX')?.value || 0),
                'Real Energy': Number(document.getElementById('budgetReal')?.value || 0)
            };
            system?.ui?.saveBudgets?.(budgets);
            system?.ui?.renderMonthlyReports?.();
            alert('Orçamentos salvos.');
        });
    }

    const signatureSearchButton = document.getElementById('signatureSearchButton');
    if (signatureSearchButton) {
        signatureSearchButton.addEventListener('click', function () {
            system.audit.searchSignatureById();
        });
    }

    const signatureSearchInput = document.getElementById('signatureSearchInput');
    if (signatureSearchInput) {
        signatureSearchInput.addEventListener('keypress', function (e) {
            if (e.key === 'Enter') {
                system.audit.searchSignatureById();
            }
        });
    }

    const addPaymentForm = document.getElementById('addPaymentForm'); // ALTERADO
    if (addPaymentForm) { // ALTERADO
      addPaymentForm.addEventListener('submit', function (e) { // ALTERADO
        e.preventDefault(); // ALTERADO
        system.ui.addPaymentFromModal(); // ALTERADO
      }); // ALTERADO
    } // ALTERADO
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initDomBindings);
} else {
    initDomBindings();
}

// Test function to verify DMF_CONTEXT updates
function testDMFContextUpdates() {
    console.log('Initial DMF_CONTEXT:', window.DMF_CONTEXT);

    // Test creating a new user
    const testUser = system.admin.createUser('Test User', 'test@example.com', 'password', 'gestor', 'testuser');
    console.log('DMF_CONTEXT after creating test user:', window.DMF_CONTEXT);

    // Test adding a payment (simulate import)
    const testPayment = {
        id: 'test-' + Date.now(),
        fornecedor: 'Test Supplier',
        data: '2023-12-01',
        valor: 1000,
        centro: 'Test Center',
        assinatura: null,
        timestamp: new Date().toISOString()
    };
    system.data.records.push(testPayment);
    system.data.save();
    window.DMF_CONTEXT.pagamentos = system.data.records;
    window.DMF_CONTEXT.assinaturas = system.data.records.filter(r => r.assinatura);
    console.log('DMF_CONTEXT after adding test payment:', window.DMF_CONTEXT);

    // Test signing the payment
    system.data.sign(testPayment.id);
    console.log('DMF_CONTEXT after signing test payment:', window.DMF_CONTEXT);

    // Test logging
    system.audit.log('TEST', 'Test log entry');
    console.log('DMF_CONTEXT after test log:', window.DMF_CONTEXT);

    // Test logout (simulate)
    system.auth.logout();
    console.log('DMF_CONTEXT after logout:', window.DMF_CONTEXT);
}

const system = new DMFSystem();
window.system = system;

// Hard logout for production: clear session and force UI reset
window.dmfLogout = function dmfLogout() {
    if (window.__DMF_LOGOUT_IN_PROGRESS) return;
    window.__DMF_LOGOUT_IN_PROGRESS = true;
    try {
        // Stop any background streams first to avoid UI "double transition" effects.
        system?.ui?.stopFlowAutoRefresh?.();
        system?.ui?.stopDashboardSummaryAutoRefresh?.();
    } catch (e) {
        // ignore
    }
    try {
        localStorage.removeItem('dmf_active_session');
        localStorage.removeItem('dmf_api_token');
    } catch (e) {
        console.warn('Failed to clear local storage', e);
    }
    try {
        // Use the normal UI logout path (shows login screen). Avoid full reload to prevent
        // the login animation from playing twice.
        system?.auth?.logout?.();
    } catch (e) {
        try { system?.ui?.showLogin?.(); } catch (_) {}
    } finally {
        window.__DMF_LOGOUT_IN_PROGRESS = false;
    }
};

// Run test after system init
if (window.DMF_DEBUG) setTimeout(testDMFContextUpdates, 1000);


// ==== SINCRONIZAÇÃO AUTOMÁTICA COM DMF_BRAIN ====
function syncBrain(){
  try{
    const sys = window.DMF?.system || window.system;
    if(!sys) return;

    if(sys.admin?.users) DMF_BRAIN.usuarios = sys.admin.users;
    if(sys.data?.records) {
      DMF_BRAIN.pagamentos = sys.data.records;
      DMF_BRAIN.assinaturas = sys.data.records.filter(r=>r.assinatura);
    }
    if(sys.audit?.logs) DMF_BRAIN.logs = sys.audit.logs;
    if(sys.currentUser) DMF_BRAIN.usuarioLogado = sys.currentUser;
  }catch(e){
    console.warn('Erro ao sincronizar DMF_BRAIN',e);
  }
}

// sincroniza a cada 2s sem travar
setInterval(syncBrain,2000);
// ==== FIM SINCRONIZAÇÃO ====
