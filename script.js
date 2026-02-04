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

function getAuthHeaders() {
    const token = localStorage.getItem('dmf_api_token');
    return token ? { Authorization: `Bearer ${token}` } : {};
}

function normalizeRole(role) {
    return String(role || '').trim().toLowerCase();
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
                const records = this.core.data.records || [];
                const response = await fetch(`${getApiBase()}/api/flow-payments/import`, {
                    method: 'POST',
                    cache: 'no-store',
                    headers: {
                        'Content-Type': 'application/json',
                        ...getAuthHeaders()
                    },
                    body: JSON.stringify(records)
                });
                return response.ok;
            }
            if (item.type === 'upsert') {
                const response = await fetch(`${getApiBase()}/api/flow-payments`, {
                    method: 'POST',
                    cache: 'no-store',
                    headers: {
                        'Content-Type': 'application/json',
                        ...getAuthHeaders()
                    },
                    body: JSON.stringify(item.data)
                });
                return response.ok;
            }
            if (item.type === 'sign') {
                const response = await fetch(`${getApiBase()}/api/flow-payments/${item.data.id}/sign`, {
                    method: 'PATCH',
                    headers: {
                        'Content-Type': 'application/json',
                        ...getAuthHeaders()
                    },
                    body: JSON.stringify({ assinatura: item.data.assinatura })
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
            COST_CENTERS: 'dmf_enterprise_cost_centers' // ALTERADO
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
                    nome: data.user.name || data.user.username
                };
                localStorage.setItem('dmf_api_token', data.token);
                this.setSession(apiUser);
                return;
            }
            alert("Falha na autenticação.");
            return;
        } catch (error) {
            console.warn('API login failed, falling back to local auth:', error.message);
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
        this.core.currentUser = { ...user, cargo: normalizedCargo };
        localStorage.setItem(this.core.storageKeys.SESSION, JSON.stringify(user));
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
        this.records = JSON.parse(localStorage.getItem(core.storageKeys.PAYMENTS)) || [];
        this.archives = [];
        // === Centros de Custo: carga e união com o fluxo === // ALTERADO
        const persisted = JSON.parse(localStorage.getItem(core.storageKeys.COST_CENTERS) || '[]'); // ALTERADO
        const fromRecords = Array.from(new Set((this.records || []).map(r => (r.centro || '').trim()).filter(Boolean))); // ALTERADO
        this.costCenters = this._dedupCaseInsensitive([...(persisted || []), ...fromRecords]); // ALTERADO
        localStorage.setItem(core.storageKeys.COST_CENTERS, JSON.stringify(this.costCenters)); // ALTERADO
        window.DMF_CONTEXT.centrosCusto = this.costCenters; // ALTERADO
        window.DMF_CONTEXT.pagamentos = this.records;
        window.DMF_CONTEXT.assinaturas = this.records.filter(r => r.assinatura);
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
            const key = String(p.centro || 'Geral').trim() || 'Geral';
            totals[key] = (totals[key] || 0) + Math.abs(Number(p.valor) || 0);
        });
        return totals;
    }

    async loadFromBackend() {
        setFlowSyncStatus('Sincronizando com o servidor...', 'info');
        try {
            const response = await fetch(`${getApiBase()}/api/flow-payments`, {
                cache: 'no-store',
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                }
            });
            if (!response.ok) {
                if (response.status === 401 || response.status === 403) {
                    console.warn('Flow payments fetch unauthorized');
                    setFlowSyncStatus('Sessão expirada. Faça login novamente.', 'warn');
                }
                console.warn('Flow payments fetch failed:', response.status);
                if (response.status !== 401 && response.status !== 403) {
                    setFlowSyncStatus('Falha ao sincronizar. Tente novamente.', 'error');
                }
                return false;
            }
            if (response.status === 304) {
                setFlowSyncStatus(`Sem alterações. Última verificação: ${formatTimeNow()}`, 'ok');
                return true;
            }
            const data = await response.json();
            this.records = data.payments || [];
            this.save();
            window.DMF_CONTEXT.pagamentos = this.records;
            window.DMF_CONTEXT.assinaturas = this.records.filter(r => r.assinatura);
            if (window.DMF_BRAIN) {
                window.DMF_BRAIN.pagamentos = this.records;
                window.DMF_BRAIN.assinaturas = this.records.filter(r => r.assinatura);
            }
            if (this.records.length) {
                setFlowSyncStatus(`Sincronizado às ${formatTimeNow()}`, 'ok');
            } else {
                setFlowSyncStatus('Nenhum pagamento encontrado no servidor.', 'warn');
            }
            return true;
        } catch (error) {
            console.warn('Flow payments fetch unavailable:', error.message);
            setFlowSyncStatus('Servidor indisponível. Tente novamente.', 'error');
            return false;
        }
    }

    async loadArchivesFromBackend(filters = {}) {
        try {
            const params = new URLSearchParams();
            if (filters.start) params.set('start', filters.start);
            if (filters.end) params.set('end', filters.end);
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
            const response = await fetch(`${getApiBase()}/api/flow-archives`, {
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
                        fornecedor: r['Nome do fornecedor'] || 'N/A',
                        data: r['Data prevista'] || 'Pendente',
                        descricao: descricao,
                        valor: Math.abs(Number(r['Valor no Centro de Custo 1'] || r['Valor original da parcela (R$)'] || 0)),
                        centro: r['Centro de Custo 1'] || 'Geral',
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
            await fetch(`${getApiBase()}/api/flow-payments/${id}/sign`, {
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                },
                body: JSON.stringify({ assinatura: r.assinatura })
            });
        } catch (error) {
            console.warn('Flow payment sign sync failed:', error.message);
            this.core.sync.enqueue({ type: 'sign', data: { id, assinatura: r.assinatura } });
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
        localStorage.setItem(this.core.storageKeys.PAYMENTS, JSON.stringify(this.records));
    }

    async syncImportToBackend() {
        setFlowSyncStatus('Sincronizando importação...', 'info');
        try {
            const response = await fetch(`${getApiBase()}/api/flow-payments/import`, {
                method: 'POST',
                cache: 'no-store',
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                },
                body: JSON.stringify(this.records)
            });
            if (!response.ok) {
                if (response.status === 401 || response.status === 403) {
                    alert('Sessão expirada. Faça login novamente para sincronizar o fluxo.');
                    setFlowSyncStatus('Sessão expirada. Faça login novamente.', 'warn');
                }
                console.warn('Flow payments import failed:', response.status);
                if (response.status !== 401 && response.status !== 403) {
                    setFlowSyncStatus('Falha ao sincronizar importação.', 'error');
                }
                this.core.sync.enqueue({ type: 'import' });
                return;
            }
            setFlowSyncStatus(`Importação sincronizada às ${formatTimeNow()}`, 'ok');
        } catch (error) {
            console.warn('Flow payments import unavailable:', error.message);
            setFlowSyncStatus('Servidor indisponível para importação.', 'error');
            this.core.sync.enqueue({ type: 'import' });
        }
    }

    getCompanyTotals() {
        const empresas = {
            JFX: ['RECAP', 'EDISER', 'Carmo Do Rio Claro'],
            DMF: [
                'Reisolamento Campina Grande',
                'Reisolamento Natal',
                'Manutennção Civil Sede E subestação',
                'Manutenção Civil AL/PE',
                'Manutenção Civil Bahia',
                'Administração Central DJ',
                'Almeirim e Barreiras',
                'Barreiras/Almeirim'
            ],
            'Real Energy': ['Campos Novos', 'Vitória da Conquista']
        };

        const normalize = (value) => String(value || '').trim().toLowerCase();
        const centersByCompany = Object.fromEntries(
            Object.entries(empresas).map(([company, centers]) => [
                company,
                centers.map(normalize)
            ])
        );

        const totals = {};
        Object.keys(centersByCompany).forEach(company => {
            totals[company] = 0;
        });
        totals.Outros = 0;

        (this.records || []).forEach((p) => {
            const centro = normalize(p.centro);
            const valor = Math.abs(Number(p.valor) || 0);
            let matched = false;
            for (const [company, centers] of Object.entries(centersByCompany)) {
                if (centers.includes(centro)) {
                    totals[company] += valor;
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                totals.Outros += valor;
            }
        });

        return totals;
    }
    
    export() {
        if (!this.core.admin.hasPermission(this.core.currentUser, 'export_payments')) {
            alert('Você não tem permissão para exportar o fluxo de pagamentos.');
            return;
        }
        // Preparar dados para exportação na ordem da tabela
        const header = [
            'Fornecedor',
            'Data',
            'Descrição',
            'Valor',
            'Centro de Custo',
            'Categoria',
            'Status',
            'Assinatura',
            'ID da Assinatura',
            '',
            '',
            'Empresa',
            'Total'
        ];

        const rows = this.records.map(p => ([
            p.fornecedor,
            p.data,
            p.descricao || "",
            p.valor,
            p.centro,
            p.categoria || "",
            p.assinatura ? 'Assinado' : 'Pendente',
            p.assinatura
                ? `Assinado por ${p.assinatura.usuarioNome} em ${new Date(p.assinatura.dataISO).toLocaleString('pt-BR')}` // ALTERADO
                : '-',
            p.assinatura?.hash || '-',
            '',
            '',
            '',
            ''
        ]));

        const totals = this.getCompanyTotals();
        const totalRows = [
            ['','','','','','','','','','','', 'DMF', `R$ ${totals.DMF.toLocaleString('pt-BR')}`],
            ['','','','','','','','','','','', 'JFX', `R$ ${totals.JFX.toLocaleString('pt-BR')}`],
            ['','','','','','','','','','','', 'REAL', `R$ ${totals['Real Energy'].toLocaleString('pt-BR')}`]
        ];

        const aoa = [header, ...rows, ...totalRows];
        const ws = XLSX.utils.aoa_to_sheet(aoa);
        const wb = XLSX.utils.book_new();
        XLSX.utils.book_append_sheet(wb, ws, "Fluxo DMF");
        XLSX.writeFile(wb, "DMF_Financeiro_Assinado.xlsx");
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
      }
      return true;
    } // ALTERADO

    addPayment({ fornecedor, data, descricao, valor, centro }) { // ALTERADO
        const record = {
            id: (Date.now() + Math.random()).toString(), // ALTERADO
            fornecedor: (fornecedor || '').trim() || 'N/A', // ALTERADO
            data: data || 'Pendente', // ALTERADO
            descricao: (descricao || '').trim(), // ALTERADO
            valor: Math.abs(Number(valor) || 0), // ALTERADO
            centro: (centro || 'Geral').trim() || 'Geral', // ALTERADO
            categoria: '',
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
            const response = await fetch(`${getApiBase()}/api/flow-payments`, {
                method: 'POST',
                cache: 'no-store',
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                },
                body: JSON.stringify(record)
            });
            if (!response.ok) {
                if (response.status === 401 || response.status === 403) {
                    alert('Sessão expirada. Faça login novamente para sincronizar o pagamento.');
                    setFlowSyncStatus('Sessão expirada. Faça login novamente.', 'warn');
                }
                console.warn('Flow payment create failed:', response.status);
                if (response.status !== 401 && response.status !== 403) {
                    setFlowSyncStatus('Falha ao sincronizar pagamento.', 'error');
                }
                this.core.sync.enqueue({ type: 'upsert', data: record });
                return;
            }
            setFlowSyncStatus(`Pagamento sincronizado às ${formatTimeNow()}`, 'ok');
        } catch (error) {
            console.warn('Flow payment create unavailable:', error.message);
            setFlowSyncStatus('Servidor indisponível para pagamento.', 'error');
            this.core.sync.enqueue({ type: 'upsert', data: record });
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
                    centro: item.centro || item.cost_center || 'Geral',
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
                    centro: item.cost_center || item.centro || 'Geral',
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
    constructor(core) { this.core = core; }

    navigate(viewId, activeButton = null) {
        if (viewId === 'admin' && !this.core.admin.hasPermission(this.core.currentUser, 'admin_access')) {
            alert('Acesso restrito à administração.');
            return;
        }
        if (viewId === 'audit' && !this.core.admin.hasPermission(this.core.currentUser, 'audit_access')) {
            alert('Acesso restrito aos logs de auditoria.');
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
    }

    showLogin() {
        document.getElementById('appSection').classList.add('hidden');
        document.getElementById('loginSection').classList.remove('hidden');
    }

    setupDashboard() {
        document.getElementById('loginSection').classList.add('hidden');
        document.getElementById('appSection').classList.remove('hidden');
        const role = normalizeRole(this.core.currentUser && (this.core.currentUser.cargo || this.core.currentUser.role));
        if (this.core.currentUser) this.core.currentUser.cargo = role;
        document.getElementById('userRoleBadge').innerText = (role || '—').toUpperCase();

        if (this.core.admin.hasPermission(this.core.currentUser, 'admin_access')) {
            document.getElementById('adminMenu').classList.remove('hidden');
        }

        this.core.data.loadFromBackend().then(() => {
            this.renderPaymentsTable();
            this.updateStats();
            this.initCharts();
            this.renderMonthlyReports();
        });
        this.startBackendStatusMonitor();
        this.startSessionMonitor();
        this.renderAdminContent();
        this.applyRolePermissions();
        this.populateBudgetInputs();
        console.log('DMF_CONTEXT after setupDashboard:', window.DMF_CONTEXT);
    }

    startBackendStatusMonitor() {
        if (this.backendStatusTimer) return;
        const check = async () => {
            try {
                const response = await fetch(`${getApiBase()}/api/flow-payments`, {
                    method: 'GET',
                    cache: 'no-store',
                    headers: {
                        'Content-Type': 'application/json',
                        ...getAuthHeaders()
                    }
                });
                if (response.status === 401 || response.status === 403) {
                    setBackendStatus('Servidor: sessão expirada', 'warn');
                    return;
                }
                if (response.ok) {
                    setBackendStatus(`Servidor: online (${formatTimeNow()})`, 'ok');
                } else {
                    setBackendStatus('Servidor: indisponível', 'error');
                }
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
        };
        update();
        this.sessionStatusTimer = setInterval(update, 1000);
        if (!this.userSyncTimer) {
            this.userSyncTimer = setInterval(() => {
                this.syncCurrentUserRole();
            }, 10000);
        }
    }

    async syncCurrentUserRole() {
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
            if (newRole && newRole !== this.core.currentUser.cargo) {
                this.core.currentUser.cargo = newRole;
                localStorage.setItem(this.core.storageKeys.SESSION, JSON.stringify(this.core.currentUser));
                const badge = document.getElementById('userRoleBadge');
                if (badge) badge.innerText = newRole.toUpperCase();
                this.applyRolePermissions();
                this.enforceViewAccess();
            }
        } catch (_) {
            // ignore
        }
    }

    enforceViewAccess() {
        const currentView = document.querySelector('.view:not(.hidden)')?.id;
        const isAdminAccess = this.core.admin.hasPermission(this.core.currentUser, 'admin_access');
        const canAudit = this.core.admin.hasPermission(this.core.currentUser, 'audit_access');
        if (currentView === 'admin' && !isAdminAccess) {
            this.navigate('dashboard', document.querySelector('[data-nav="dashboard"]'));
        }
        if (currentView === 'audit' && !canAudit) {
            this.navigate('dashboard', document.querySelector('[data-nav="dashboard"]'));
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
        this.core.data.loadFromBackend().then(() => {
            this.renderPaymentsTable();
            this.updateStats();
            this.initCharts();
        }).finally(() => {
            this.flowAutoRefreshBusy = false;
        });
        this.flowAutoRefreshTimer = setInterval(() => {
            if (this.flowAutoRefreshBusy) return;
            this.flowAutoRefreshBusy = true;
            this.core.data.loadFromBackend().then(() => {
                this.renderPaymentsTable();
                this.updateStats();
            }).finally(() => {
                this.flowAutoRefreshBusy = false;
            });
        }, 5000);
    }

    stopFlowAutoRefresh() {
        if (this.flowAutoRefreshTimer) {
            clearInterval(this.flowAutoRefreshTimer);
            this.flowAutoRefreshTimer = null;
        }
    }

    switchAdminTab(tab, activeButton = null) {
        document.querySelectorAll('.admin-tab-content').forEach(t => t.classList.add('hidden'));
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.getElementById(`${tab}Tab`).classList.remove('hidden');
        if (activeButton) activeButton.classList.add('active');
    }

    switchAuditTab(tab, activeButton = null) {
        document.querySelectorAll('.audit-tab-content').forEach(t => t.classList.add('hidden'));
        document.querySelectorAll('[data-audit-tab]').forEach(b => b.classList.remove('active'));
        document.getElementById(`audit${tab.charAt(0).toUpperCase()}${tab.slice(1)}Tab`).classList.remove('hidden');
        if (activeButton) activeButton.classList.add('active');

        if (tab === 'logins') {
            if (!this.core.admin.hasPermission(this.core.currentUser, 'audit_login_access')) {
                alert('Acesso restrito aos logs de acesso.');
                return;
            }
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
        } else {
            this.renderUsersTable();
        }
        this.renderRolesTable();
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

        const canImport = this.core.admin.hasPermission(this.core.currentUser, 'import_payments');
        const canExport = this.core.admin.hasPermission(this.core.currentUser, 'export_payments');
        const canAdd = this.core.admin.hasPermission(this.core.currentUser, 'add_payments');
        const canAudit = this.core.admin.hasPermission(this.core.currentUser, 'audit_access');
        const canViewArchives = this.core.admin.hasPermission(this.core.currentUser, 'view_archives');
        const canArchiveFlow = this.core.admin.hasPermission(this.core.currentUser, 'archive_flow');
        const canCompareArchives = this.core.admin.hasPermission(this.core.currentUser, 'compare_archives');

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
            revokeSelfBtn.classList.toggle('hidden', !isAdminAccess);
            revokeSelfBtn.disabled = !isAdminAccess;
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
                            <td>${r.permissions.join(', ')}</td>
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

    renderFlowArchivesList() {
        const list = document.getElementById('flowArchivesList');
        if (!list) return;
        const archives = this.core.data.archives || [];
        if (!archives.length) {
            list.innerHTML = `<div class="flow-archive-empty">Nenhum fluxo anterior disponível.</div>`;
            const detail = document.getElementById('flowArchiveDetail');
            if (detail) detail.innerHTML = '';
            this.renderArchiveCompareOptions([]);
            return;
        }
        list.innerHTML = archives.map(a => `
            <button class="flow-archive-item" data-archive-id="${a.id}">${a.label}</button>
        `).join('');
        this.renderArchiveCompareOptions(archives);

        if (!list.dataset.boundArchiveClick) {
            list.addEventListener('click', (event) => {
                const button = event.target.closest('[data-archive-id]');
                if (!button) return;
                const id = button.getAttribute('data-archive-id');
                const selected = (this.core.data.archives || []).find(a => a.id === id);
                list.querySelectorAll('.flow-archive-item').forEach(b => b.classList.remove('active'));
                button.classList.add('active');
                this.renderFlowArchiveDetail(selected);
            });
            list.dataset.boundArchiveClick = 'true';
        }

        const first = list.querySelector('[data-archive-id]');
        if (first && !list.querySelector('.flow-archive-item.active')) {
            first.classList.add('active');
            const id = first.getAttribute('data-archive-id');
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

        body.innerHTML = this.core.data.records.map(p => {
            const assinaturaStr = p.assinatura
                ? `Assinado por: ${p.assinatura.usuarioNome}` // ALTERADO
                : '-'; // ALTERADO

            const canSign = this.core.admin.hasPermission(this.core.currentUser, 'sign_payments');
            const acoesHtml = p.assinatura
                ? '<span>Assinado</span>' // manter simples, sem CSS novo // ALTERADO
                : (canSign ? `<button class="btn btn-primary" data-payment-action="sign" data-payment-id="${p.id}">Assinar</button>` : '—'); // ALTERADO
            const qrHtml = (canSeeQr && p.assinatura?.hash)
                ? `<div class="qr-box" data-qr="${publicBase}${p.assinatura.hash}"></div>`
                : '';

            return `
                <tr>
                    <td><strong>${p.fornecedor || ''}</strong></td>
                    <td>${p.data || ''}</td>
                    <td>${(p.descricao || '').trim() || '—'}</td>
                    <td>R$ ${(Number(p.valor)||0).toLocaleString('pt-BR')}</td>
                    <td>${p.centro || ''}</td>
                    <td>${(p.categoria || '').trim() || '—'}</td>
                    <td><span>${p.assinatura ? 'Assinado' : 'Pendente'}</span></td>
                    <td><small>${assinaturaStr}</small>${qrHtml}</td>
                    <td>${acoesHtml}</td> <!-- ALTERADO -->
                </tr>
            `;
        }).join('');

        this.updateStats && this.updateStats(); // manter comportamento existente // ALTERADO
        this.renderCompanyTotals && this.renderCompanyTotals();
        this.renderSignatureQrCodes && this.renderSignatureQrCodes();

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
        const qr = window.QRCode;
        document.querySelectorAll('.qr-box').forEach(box => {
            if (box.dataset.rendered) return;
            const text = box.getAttribute('data-qr');
            if (!text) return;
            if (!qr) {
                box.innerHTML = `<a href="${text}" target="_blank" rel="noopener">Verificar</a>`;
                box.dataset.rendered = 'true';
                return;
            }
            qr.toDataURL(text, { width: 96, margin: 1 }, (err, url) => {
                if (err) {
                    box.innerHTML = `<a href="${text}" target="_blank" rel="noopener">Verificar</a>`;
                    box.dataset.rendered = 'true';
                    return;
                }
                const img = document.createElement('img');
                img.src = url;
                img.width = 96;
                img.height = 96;
                img.alt = 'QR de validação';
                box.appendChild(img);
                box.dataset.rendered = 'true';
            });
        });
    }

    updateStats() {
        const data = this.core.data.records;
        let total = 0;
        data.forEach(p => total += Number(p.valor) || 0);
        this.totalBruto = total;
        document.getElementById('totalBruto').innerText = `R$ ${total.toLocaleString('pt-BR')}`;
        document.getElementById('totalAssinados').innerText = data.filter(p => p.assinatura).length;
        document.getElementById('totalPendentes').innerText = data.filter(p => !p.assinatura).length;
    }

    renderCompanyTotals() {
        const container = document.getElementById('companyTotalsBody');
        if (!container) return;
        const totals = this.core.data.getCompanyTotals();

        const rows = Object.entries(totals)
            .filter(([, total]) => total > 0)
            .map(([company, total]) => `
                <div class="company-total-row">
                    <span>${company}</span>
                    <strong>R$ ${total.toLocaleString('pt-BR')}</strong>
                </div>
            `)
            .join('');

        container.innerHTML = rows || '<div class="company-total-empty">Sem dados para exibir.</div>';
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
      let centro = (fd.get('centro') || 'Geral').trim() || 'Geral';

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

      this.core.data.addPayment({ fornecedor, data, descricao, valor, centro }); // ALTERADO
      if (window.assistant) window.assistant.addLearningQuestion(`Quantos pagamentos estão aguardando assinatura?`, `Há ${this.core.data.records.filter(p => !p.assinatura).length} pagamentos aguardando assinatura.`); // ALTERADO
      form.reset();
      this.closeModal('addPaymentModal');
    } // ALTERADO

    initCharts() {
        const ctx = document.getElementById('financeChart').getContext('2d');
        new Chart(ctx, {
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
        body.innerHTML = this.logs.slice(0, 50).map(l => `
            <tr><td>${new Date(l.dataISO).toLocaleString()}</td><td>${l.userEmail || 'Sistema'}</td><td><strong>${l.acao}</strong></td><td>${l.detalhes || ''}</td></tr>
        `).join('');
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
        this.saveUsers();
        this.saveRoles();
        window.DMF_CONTEXT.usuarios = this.users;
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
                headers: { 'Content-Type': 'application/json' },
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
document.addEventListener('DOMContentLoaded', function() {
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
            if (!system?.admin?.hasPermission?.(system?.currentUser, 'admin_access')) {
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
            system?.data?.export?.();
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
            system?.data?.loadFromBackend?.().then(() => {
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

    // Navigation event listeners
    document.querySelectorAll('[data-nav]').forEach(button => {
        button.addEventListener('click', function() {
            const viewId = this.getAttribute('data-nav');
            system.ui.navigate(viewId, this);
        });
    });

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
            system?.data?.loadArchivesFromBackend?.().then(() => {
                system?.ui?.renderFlowArchivesList?.();
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
            system.ui.searchSignatureById();
        });
    }

    const signatureSearchInput = document.getElementById('signatureSearchInput');
    if (signatureSearchInput) {
        signatureSearchInput.addEventListener('keypress', function (e) {
            if (e.key === 'Enter') {
                system.ui.searchSignatureById();
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
});

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
    try {
        system?.auth?.logout?.();
    } catch (e) {
        console.warn('Logout failed, falling back to storage clear', e);
    }
    try {
        localStorage.removeItem('dmf_active_session');
        localStorage.removeItem('dmf_api_token');
    } catch (e) {
        console.warn('Failed to clear local storage', e);
    }
    if (window.location && typeof window.location.reload === 'function') {
        window.location.reload();
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
