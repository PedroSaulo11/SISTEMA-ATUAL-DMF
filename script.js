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
        this.data = new DataProcessor(this);
        this.auth = new AuthManager(this);
        this.ui = new UIManager(this);
        this.audit = new AuditLogger(this);
        this.admin = new AdminManager(this);

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

    login() {
        const input = document.getElementById('loginInput').value.trim().toLowerCase();
        const pass = document.getElementById('loginPass').value;

        // Verificar usuários armazenados por usuario ou email
        const user = this.core.admin.users.find(u =>
            (u.usuario === input || u.email === input) &&
            (u.senha === hash(pass) || u.senha === pass)
        );
        if(user) {
            this.setSession(user);
        } else {
            alert("Falha na autenticação.");
        }
    }

    setSession(user) {
        this.core.currentUser = user;
        localStorage.setItem(this.core.storageKeys.SESSION, JSON.stringify(user));
        window.DMF_CONTEXT.usuarioLogado = user;
        console.log('DMF_CONTEXT after setSession:', window.DMF_CONTEXT);
        this.core.ui.setupDashboard();
    }

    logout() {
        localStorage.removeItem(this.core.storageKeys.SESSION);
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
        // === Centros de Custo: carga e união com o fluxo === // ALTERADO
        const persisted = JSON.parse(localStorage.getItem(core.storageKeys.COST_CENTERS) || '[]'); // ALTERADO
        const fromRecords = Array.from(new Set((this.records || []).map(r => (r.centro || '').trim()).filter(Boolean))); // ALTERADO
        this.costCenters = this._dedupCaseInsensitive([...(persisted || []), ...fromRecords]); // ALTERADO
        localStorage.setItem(core.storageKeys.COST_CENTERS, JSON.stringify(this.costCenters)); // ALTERADO
        window.DMF_CONTEXT.centrosCusto = this.costCenters; // ALTERADO
        window.DMF_CONTEXT.pagamentos = this.records;
        window.DMF_CONTEXT.assinaturas = this.records.filter(r => r.assinatura);
        window.DMF_BRAIN.pagamentos = this.records;
        window.DMF_BRAIN.assinaturas = this.records.filter(r => r.assinatura);
        console.log('DMF_CONTEXT after DataProcessor init:', window.DMF_CONTEXT);
        console.log('DMF_BRAIN after DataProcessor init:', window.DMF_BRAIN);
    }

    import(input) {
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

    sign(id) { // ALTERADO
        const idx = this.records.findIndex(r => r.id === id);
        if (idx === -1) return false; // ALTERADO
        const r = this.records[idx];
        if (r.assinatura) return true; // já assinado // ALTERADO

        const u = this.core.currentUser || {};
        const usuarioNome = (u.nome || u.name || u.usuario || u.email || 'Usuário'); // ALTERADO
        const dataISO = new Date().toISOString(); // ALTERADO
        const hash = (typeof btoa === 'function')
            ? btoa(`${id}|${usuarioNome}|${dataISO}`)  // ALTERADO
            : `${id}-${Date.now()}`; // fallback // ALTERADO

        r.assinatura = { usuarioNome, dataISO, hash }; // ALTERADO
        this.records[idx] = r; // ALTERADO
        this.save(); // ALTERADO

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
    
    export() {
        // Preparar dados para exportação na ordem da tabela
        const exportData = this.records.map(p => ({
            Fornecedor: p.fornecedor,
            Data: p.data,
            Descrição: p.descricao || "",
            Valor: p.valor,
            "Centro de Custo": p.centro,
            Status: p.assinatura ? 'Assinado' : 'Pendente',
            Assinatura: p.assinatura
                ? `Assinado por ${p.assinatura.usuarioNome} em ${new Date(p.assinatura.dataISO).toLocaleString('pt-BR')} (ID: ${p.assinatura.hash})` // ALTERADO
                : '-'
        }));

        const ws = XLSX.utils.json_to_sheet(exportData);
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
            assinatura: null, // começa Pendente por regra do sistema // ALTERADO
            timestamp: new Date().toISOString() // ALTERADO
        };
        this.records.push(record); // ALTERADO
        this.ensureCostCenter(record.centro); // registra o centro // ALTERADO
        if (window.assistant) window.assistant.addLearning("centros_de_custo", record.centro); // ALTERADO
        this.save(); // ALTERADO

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

    syncFromAPI() {
        fetch('http://localhost:3000/api/payments')
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
                alert('Erro ao sincronizar com a API Conta Azul. Verifique o console para detalhes.');
            });
    }
}

class UIManager {
    constructor(core) { this.core = core; }

    navigate(viewId, activeButton = null) {
        document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
        document.getElementById(viewId).classList.remove('hidden');
        // Update active button
        document.querySelectorAll('.btn-side').forEach(btn => btn.classList.remove('active'));
        if (activeButton) activeButton.classList.add('active');
    }

    showLogin() {
        document.getElementById('appSection').classList.add('hidden');
        document.getElementById('loginSection').classList.remove('hidden');
    }

    setupDashboard() {
        document.getElementById('loginSection').classList.add('hidden');
        document.getElementById('appSection').classList.remove('hidden');
        document.getElementById('userRoleBadge').innerText = this.core.currentUser.cargo.toUpperCase();

        if(this.core.currentUser.cargo === 'admin') {
            document.getElementById('adminMenu').classList.remove('hidden');
        }

        this.renderPaymentsTable();
        this.updateStats();
        this.initCharts();
        this.renderAdminContent();
        console.log('DMF_CONTEXT after setupDashboard:', window.DMF_CONTEXT);
    }

    switchAdminTab(tab, activeButton = null) {
        document.querySelectorAll('.admin-tab-content').forEach(t => t.classList.add('hidden'));
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.getElementById(`${tab}Tab`).classList.remove('hidden');
        if (activeButton) activeButton.classList.add('active');
    }

    renderAdminContent() {
        this.renderUsersTable();
        this.renderRolesTable();
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
                                <button onclick="system.ui.editUser(${u.id})" class="btn btn-ghost">Editar</button>
                                <button onclick="system.ui.changePassword(${u.id})" class="btn btn-ghost">Trocar Senha</button>
                                <button onclick="system.admin.deleteUser(${u.id}); system.ui.renderUsersTable()" class="btn btn-danger">Excluir</button>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
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
                                <button onclick="system.ui.editRole(${r.id})" class="btn btn-ghost">Editar</button>
                                <button onclick="system.admin.deleteRole(${r.id}); system.ui.renderRolesTable()" class="btn btn-danger">Excluir</button>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
            <button onclick="system.ui.openCreateRoleModal()" class="btn btn-primary" style="margin-top: 10px">Criar Novo Cargo</button>
        `;
    }

    openCreateUserModal() {
        const modal = document.getElementById('createUserModal');
        if (modal) {
            modal.style.display = 'block';
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
            modal.style.display = 'block';
        }
    }

    closeModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.style.display = 'none';
        }
    }

    openModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.style.display = 'block';
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
        const user = this.core.admin.users.find(u => u.id === id);
        if(!user) return;
        // Populate edit modal
        document.getElementById('editUserName').value = user.nome;
        document.getElementById('editUserUsername').value = user.usuario;
        document.getElementById('editUserEmail').value = user.email;
        document.getElementById('editUserRole').value = user.cargo;
        document.getElementById('editUserId').value = user.id;
        this.openModal('editUserModal');
    }

    changePassword(id) {
        const user = this.core.admin.users.find(u => u.id === id);
        if(!user) return;
        document.getElementById('changePasswordUserId').value = user.id;
        document.getElementById('changePasswordUserName').textContent = user.nome;
        this.openModal('changePasswordModal');
    }

    editUserFromModal() {
        const form = document.getElementById('editUserForm');
        const formData = new FormData(form);
        const id = parseInt(formData.get('editUserId'));
        const nome = formData.get('editUserName').trim();
        const usuario = formData.get('editUserUsername').trim();
        const email = formData.get('editUserEmail').trim();
        const cargo = formData.get('editUserRole');

        if (nome && usuario && email && cargo) {
            this.core.admin.updateUser(id, { nome, usuario, email, cargo });
            this.closeModal('editUserModal');
            this.renderUsersTable();
            form.reset();
        } else {
            alert('Por favor, preencha todos os campos obrigatórios.');
        }
    }

    changePasswordFromModal() {
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
        this.core.admin.updateUser(id, { senha: hash(newPassword) });
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

        body.innerHTML = this.core.data.records.map(p => {
            const assinaturaStr = p.assinatura
                ? `Assinado por ${p.assinatura.usuarioNome} em ${new Date(p.assinatura.dataISO).toLocaleString('pt-BR')} (ID: ${p.assinatura.hash})` // ALTERADO
                : '-'; // ALTERADO

            const canSign = this.core.admin.hasPermission(this.core.currentUser, 'sign_payments'); // ALTERADO
            const acoesHtml = p.assinatura
                ? '<span>Assinado</span>' // manter simples, sem CSS novo // ALTERADO
                : (canSign ? `<button class="btn btn-primary" onclick="system.data.sign('${p.id}')">Assinar</button>` : '—'); // ALTERADO

            return `
                <tr>
                    <td><strong>${p.fornecedor || ''}</strong></td>
                    <td>${p.data || ''}</td>
                    <td>${(p.descricao || '').trim() || '—'}</td>
                    <td>R$ ${(Number(p.valor)||0).toLocaleString('pt-BR')}</td>
                    <td>${p.centro || ''}</td>
                    <td><span>${p.assinatura ? 'Assinado' : 'Pendente'}</span></td>
                    <td><small>${assinaturaStr}</small></td>
                    <td>${acoesHtml}</td> <!-- ALTERADO -->
                </tr>
            `;
        }).join('');

        this.updateStats && this.updateStats(); // manter comportamento existente // ALTERADO
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
            { id: 2, name: 'gestor', permissions: ['sign_payments'] }
        ];
        this.saveUsers();
        this.saveRoles();
        window.DMF_CONTEXT.usuarios = this.users;
        window.DMF_BRAIN.usuarios = this.users;
        console.log('DMF_CONTEXT after AdminManager init:', window.DMF_CONTEXT);
        console.log('DMF_BRAIN after AdminManager init:', window.DMF_BRAIN);
    }

    saveUsers() {
        localStorage.setItem(this.core.storageKeys.USERS, JSON.stringify(this.users));
    }

    saveRoles() {
        localStorage.setItem(this.core.storageKeys.ROLES, JSON.stringify(this.roles));
    }

    createUser(nome, email, senha, cargo, usuario = null) {
        // Validate required fields
        if (!nome || !email || !senha || !cargo) {
            alert('Todos os campos são obrigatórios.');
            return;
        }
        // Check for duplicate usuario or email
        if (this.users.some(u => u.usuario === usuario)) {
            alert('Usuário já existe.');
            return;
        }
        if (this.users.some(u => u.email === email.trim().toLowerCase())) {
            alert('Email já existe.');
            return;
        }
        const newUser = {
            id: Date.now(),
            nome,
            usuario: usuario || email.trim().toLowerCase(),
            email: email.trim().toLowerCase(),
            senha: hash(senha),
            cargo
        };
        this.users.push(newUser);
        this.saveUsers();
        window.DMF_CONTEXT.usuarios = this.users;
        console.log('DMF_CONTEXT after createUser:', window.DMF_CONTEXT);
        this.core.audit.log('CRIAÇÃO USUÁRIO', `Usuário ${nome} criado com cargo ${cargo}.`);
        alert('Usuário criado com sucesso.');
        return newUser;
    }

    updateUser(id, updates) {
        const user = this.users.find(u => u.id === id);
        if (user) {
            // Check for duplicate usuario or email if changing
            if (updates.usuario && updates.usuario !== user.usuario && this.users.some(u => u.usuario === updates.usuario)) {
                alert('Usuário já existe.');
                return;
            }
            if (updates.email && updates.email !== user.email && this.users.some(u => u.email === updates.email)) {
                alert('Email já existe.');
                return;
            }
            Object.assign(user, updates);
            this.saveUsers();
            this.core.audit.log('ATUALIZAÇÃO USUÁRIO', `Usuário ${user.nome} atualizado.`);
            alert('Usuário atualizado com sucesso.');
        }
    }

    deleteUser(id) {
        if (this.core.currentUser && this.core.currentUser.id === id) {
            alert('Não é permitido excluir o próprio usuário logado.');
            return;
        }
        this.users = this.users.filter(u => u.id !== id);
        this.saveUsers();
        this.core.audit.log('EXCLUSÃO USUÁRIO', `Usuário ID ${id} excluído.`);
        alert('Usuário excluído com sucesso.');
    }

    createRole() {
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
        const form = document.getElementById('createUserForm');
        const formData = new FormData(form);
        const nome = formData.get('userName').trim();
        const usuario = formData.get('userUsername').trim();
        const email = formData.get('userEmail').trim();
        const senha = formData.get('userPassword');
        const cargo = formData.get('userRole');

        if (nome && usuario && email && senha && cargo) {
            this.createUser(nome, email, senha, cargo, usuario);
            this.core.ui.closeModal('createUserModal');
            this.core.ui.renderUsersTable();
            form.reset();
        } else {
            alert('Por favor, preencha todos os campos obrigatórios.');
        }
    }

    createRoleFromModal() {
        const form = document.getElementById('createRoleForm');
        const formData = new FormData(form);
        const name = formData.get('roleName')?.trim();
        const permissions = [];
        if (document.getElementById('rolePermSignPayments').checked) permissions.push('sign_payments');
        if (document.getElementById('rolePermManageUsers').checked) permissions.push('manage_users');
        if (document.getElementById('rolePermViewAdmin').checked) permissions.push('admin_access');
        if (document.getElementById('rolePermAccessAudit').checked) permissions.push('audit_access');

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
        this.core.ui.closeModal('createRoleModal');
        this.core.ui.renderRolesTable();
        form.reset();
    }

    updateRole(id, updates) {
        const role = this.roles.find(r => r.id === id);
        if (role) {
            Object.assign(role, updates);
            this.saveRoles();
            this.core.audit.log('ATUALIZAÇÃO CARGO', `Cargo ${role.name} atualizado.`);
        }
    }

    deleteRole(id) {
        this.roles = this.roles.filter(r => r.id !== id);
        this.saveRoles();
        this.core.audit.log('EXCLUSÃO CARGO', `Cargo ID ${id} excluído.`);
    }

    getRolePermissions(roleName) {
        const role = this.roles.find(r => r.name === roleName);
        return role ? role.permissions : [];
    }

    hasPermission(user, permission) {
        const roleName = (user && (user.cargo || user.role)) || ''; // ALTERADO
        const rolePerms = this.getRolePermissions(roleName);        // ALTERADO
        const userPerms = (user && user.additionalPermissions) || [];
        return rolePerms.includes('all') || rolePerms.includes(permission) || userPerms.includes(permission);
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
            event.target.style.display = 'none';
        }
    });

    // Import button listener
    const importBtn = document.querySelector('button[onclick*="fileInput"]');
    const fileInput = document.getElementById('fileInput');

    if (importBtn && fileInput) {
        importBtn.addEventListener('click', function() {
            console.log('Botão Importar clicado');
            fileInput.click();
        });

        fileInput.addEventListener('change', function(event) {
            console.log('Arquivo selecionado:', event.target.files[0]);
            if (system && system.data) {
                system.data.import(event.target);
            } else {
                console.error('Sistema não inicializado');
            }
        });
    }

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
