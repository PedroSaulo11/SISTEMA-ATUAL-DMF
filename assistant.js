class IntelligentAssistant {
    constructor() {
        // Expose instance for inline handlers and other modules.
        window.assistant = this;
        this.history = JSON.parse(localStorage.getItem('dmf_assistant_history')) || [];
        this.memoria = JSON.parse(localStorage.getItem('dmf_assistant_memoria')) || [];
        this.learningData = JSON.parse(localStorage.getItem('dmf_assistant_learning')) || {}; // ALTERADO
        this.isSending = false;
        this.quickPrompts = [
            'Quantos pagamentos pendentes existem hoje?',
            'Qual o total de gastos da Real Energy neste mes?',
            'Quem assinou por ultimo?',
            'Me explique como importar pagamentos'
        ];
        this.init();
    }

    init() {
        this.renderHistory();
        this.renderQuickPrompts();
        this.setupEventListeners();
        this.inicializarConhecimentoBase();
        this.renderWelcomeIfNeeded();
    }

    inicializarConhecimentoBase() {
        const brain = window.DMF_BRAIN;
        if (!brain.conhecimento || brain.conhecimento.length === 0) {
            brain.conhecimento = [
                {
                    topico: "importacao",
                    explicacao: "Para importar pagamentos, vá na aba 'Importar', selecione o arquivo Excel do Conta Azul e clique em 'Importar'. O sistema irá processar automaticamente os dados.",
                    perguntas: ["como importar", "importar arquivo", "como fazer upload"]
                },
                {
                    topico: "assinatura",
                    explicacao: "Para assinar um pagamento, clique no botão 'Assinar' na tabela de pagamentos. Você precisa ter permissão de gestor ou administrador.",
                    perguntas: ["como assinar", "assinar pagamento", "não consigo assinar"]
                },
                {
                    topico: "permissoes",
                    explicacao: "As permissões são definidas por cargo. Administradores têm acesso total, gestores podem assinar pagamentos. Entre em contato com o admin para alterar permissões.",
                    perguntas: ["permissões", "não tenho acesso", "não consigo"]
                },
                {
                    topico: "usuarios",
                    explicacao: "Para gerenciar usuários, vá na aba 'Admin' > 'Usuários'. Você pode criar, editar ou excluir usuários se tiver permissão administrativa.",
                    perguntas: ["criar usuário", "gerenciar usuários", "adicionar usuário"]
                }
            ];
        }
    }

    setupEventListeners() {
        const input = document.getElementById('chatInput');
        if (input) {
            input.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    this.sendMessage();
                }
            });
        }

        const sendButton = document.getElementById('chatSendBtn');
        if (sendButton && !sendButton.dataset.boundAssistant) {
            sendButton.dataset.boundAssistant = 'true';
            sendButton.addEventListener('click', () => this.sendMessage());
        }

        const clearButton = document.getElementById('chatClearBtn');
        if (clearButton && !clearButton.dataset.boundAssistant) {
            clearButton.dataset.boundAssistant = 'true';
            clearButton.addEventListener('click', () => this.clearConversation());
        }

        const quickPromptsContainer = document.getElementById('chatQuickPrompts');
        if (quickPromptsContainer && !quickPromptsContainer.dataset.boundAssistant) {
            quickPromptsContainer.dataset.boundAssistant = 'true';
            quickPromptsContainer.addEventListener('click', (event) => {
                const target = event.target;
                if (!(target instanceof HTMLElement)) return;
                const button = target.closest('[data-quick-prompt]');
                if (!button) return;
                const prompt = button.getAttribute('data-quick-prompt');
                if (!prompt) return;
                this.sendMessage(prompt);
            });
        }
    }

    getCurrentDate() {
        const today = new Date();
        return today.toLocaleDateString('pt-BR');
    }

    normalizeText(text) {
        return text
            .toLowerCase()
            .normalize('NFD')
            .replace(/[\u0300-\u036f]/g, '')
            .replace(/[^\w\s]/g, '')
            .trim();
    }

    // Método para adicionar aprendizado de interação
    addLearning(key, value) { // ALTERADO
        if (!this.learningData[key]) this.learningData[key] = [];
        this.learningData[key].push(value);
        if (this.learningData[key].length > 25) {
            this.learningData[key] = this.learningData[key].slice(-25);
        }
        localStorage.setItem('dmf_assistant_learning', JSON.stringify(this.learningData)); // ALTERADO
    }

    // Método para buscar o aprendizado de interações anteriores
    getLearning(key) { // ALTERADO
        return this.learningData[key] || [];
    }

    // Método para adicionar aprendizado de perguntas frequentes
    addLearningQuestion(question, response) { // ALTERADO
        const key = this.normalizeText(question);
        this.addLearning(key, response);
    }

    // Resposta otimizada, com base no aprendizado
    getOptimizedAnswer(question) { // ALTERADO
        if (!this.shouldUseLearning(question)) return null;
        const key = this.normalizeText(question);
        const learnedAnswers = this.getLearning(key);
        return learnedAnswers.length ? learnedAnswers[learnedAnswers.length - 1] : "Não tenho uma resposta pronta ainda, mas estou aprendendo!";
    }

    // Evitar usar aprendizado para saudações ou mensagens muito curtas
    shouldUseLearning(question) {
        const normalized = this.normalizeText(question);
        if (!normalized) return false;
        if (normalized.length < 3) return false;
        const saudacoes = ['oi', 'ola', 'bomdia', 'boatarde', 'boanoite'];
        return !saudacoes.some(s => normalized.includes(s));
    }

    analisarIntencao(question) {
        const normalized = this.normalizeText(question);
        const brain = window.DMF_BRAIN;

        // Extrair ação, assunto e tempo
        const acao = this.extrairAcao(normalized);
        const assunto = this.extrairAssunto(normalized);
        const tempo = this.extrairTempo(normalized);
        const perguntaStatus = this.extrairStatus(normalized); // ALTERADO

        return { acao, assunto, tempo, perguntaStatus, perguntaOriginal: question }; // ALTERADO
    }

    extrairAcao(text) {
        const acoes = {
            ver: ['ver', 'mostrar', 'listar', 'exibir', 'consultar', 'visualizar'],
            saber: ['saber', 'descobrir', 'entender', 'explicar', 'como'],
            contar: ['quantos', 'quantas', 'numero', 'total', 'contar'],
            quem: ['quem', 'qual usuario', 'qual pessoa'],
            quando: ['quando', 'data', 'hora'],
            onde: ['onde', 'local', 'centro'],
            por_que: ['por que', 'porque', 'motivo', 'problema', 'erro'],
            ajudar: ['ajudar', 'auxilio', 'suporte']
        };

        for (const [acao, palavras] of Object.entries(acoes)) {
            if (palavras.some(palavra => text.includes(palavra))) {
                return acao;
            }
        }
        return 'geral';
    }

    extrairAssunto(text) {
        const assuntos = {
            pagamento: ['pagamento', 'pagamentos', 'financeiro', 'valor', 'dinheiro'],
            assinatura: ['assinatura', 'assinar', 'assinou', 'assinado'],
            usuario: ['usuario', 'usuários', 'user', 'pessoa', 'pessoas'],
            permissao: ['permissao', 'permissões', 'permissao', 'acesso', 'cargo'],
            erro: ['erro', 'problema', 'não funciona', 'falha', 'bug'],
            importacao: ['importar', 'importacao', 'upload', 'arquivo', 'excel'],
            sistema: ['sistema', 'dmf', 'aplicacao', 'app'],
            evento: ['evento', 'aconteceu', 'historia', 'historico']
        };

        for (const [assunto, palavras] of Object.entries(assuntos)) {
            if (palavras.some(palavra => text.includes(palavra))) {
                return assunto;
            }
        }
        return 'geral';
    }

    extrairTempo(text) {
        const tempos = {
            hoje: ['hoje', 'este dia', 'atual'],
            ontem: ['ontem', 'dia passado'],
            semana: ['semana', 'esta semana', 'ultimos 7 dias'],
            mes: ['mes', 'este mes', 'ultimo mes'],
            ultimo: ['ultimo', 'mais recente', 'recente']
        };

        for (const [tempo, palavras] of Object.entries(tempos)) {
            if (palavras.some(palavra => text.includes(palavra))) {
                return tempo;
            }
        }
        return 'todos';
    }

    extrairStatus(texto) { // ALTERADO
        const t = texto.toLowerCase();
        const pendente = ["pendente", "aguardando", "não assinado", "sem assinatura"];
        const assinado = ["assinado", "com assinatura"];
        if (pendente.some(p => t.includes(p))) return "pendente";
        if (assinado.some(a => t.includes(a))) return "assinado";
        return "todos";
    }

    async sendMessage(forcedMessage) {
        const input = document.getElementById('chatInput');
        if (!input && !forcedMessage) return;

        const message = String(forcedMessage || input.value || '').trim();
        if (!message) return;
        if (this.isSending) return;

        this.isSending = true;
        this.setSendingState(true);
        this.addMessage('user', message);
        if (!forcedMessage && input) input.value = '';

        const typingId = this.showTypingIndicator();
        try {
            const response = await Promise.resolve(this.processarPergunta(message));
            this.hideTypingIndicator(typingId);
            this.addMessage('assistant', response);
        } catch (error) {
            this.hideTypingIndicator(typingId);
            this.addMessage('assistant', 'Tive um erro ao processar sua pergunta. Tente novamente.');
        } finally {
            this.isSending = false;
            this.setSendingState(false);
            if (input) input.focus();
        }
    }

    processarPergunta(question) {
        const brain = window.DMF_BRAIN;
        const intencao = this.analisarIntencao(question);
        const signatureHash = this.extrairHashAssinatura(question);
        if (signatureHash) {
            this.validarAssinatura(signatureHash);
            return "Verificando assinatura, aguarde...";
        }

        const respostaIntencao = this.responderPorIntencao(question, intencao);
        if (respostaIntencao) {
            this.adicionarMemoriaInteracao(question, respostaIntencao, intencao);
            return respostaIntencao;
        }

        // Verificar resposta otimizada baseada no aprendizado
        const optimized = this.getOptimizedAnswer(question); // ALTERADO
        if (optimized && optimized !== "Não tenho uma resposta pronta ainda, mas estou aprendendo!") { // ALTERADO
            return optimized; // ALTERADO
        } // ALTERADO

        // Registrar pergunta na memória
        this.registrarPerguntaMemoria(question, intencao);

        // Verificar conhecimento existente
        const conhecimentoExistente = this.buscarConhecimento(question);
        if (conhecimentoExistente) {
            return conhecimentoExistente.explicacao;
        }

        // Processar baseado na intenção
        const resposta = this.gerarResposta(intencao);

        // Aprender com a resposta
        this.aprenderComResposta(question, resposta, intencao);

        return resposta;
    }

    responderPorIntencao(pergunta, intencao) {
        const normalized = this.normalizeText(pergunta);

        if (normalized.includes('gastos') || normalized.includes('pagamentos')) {
            return this.responderGastos(pergunta);
        }

        if (normalized.includes('assinatura') || normalized.includes('assinar')) {
            return this.responderAssinaturaContexto();
        }

        if (normalized.includes('log') || normalized.includes('auditoria')) {
            return this.responderLogs();
        }

        if (normalized.includes('ajuda')) {
            return this.responderAjuda();
        }

        return null;
    }

    adicionarMemoriaInteracao(pergunta, resposta, intencao) {
        const memoria = JSON.parse(localStorage.getItem('dmf_assistant_recent')) || [];
        memoria.push({ pergunta, resposta, intencao, timestamp: new Date().toISOString() });
        while (memoria.length > 5) memoria.shift();
        localStorage.setItem('dmf_assistant_recent', JSON.stringify(memoria));
    }

    obterMemoriaRecente() {
        return JSON.parse(localStorage.getItem('dmf_assistant_recent')) || [];
    }

    responderGastos(pergunta) {
        const pagamentos = (window.DMF_CONTEXT && window.DMF_CONTEXT.pagamentos) || [];
        if (!pagamentos.length) {
            return "Não há pagamentos registrados para calcular gastos.";
        }

        const empresa = this.extrairEmpresa(pergunta);
        const mesAno = this.extrairMesAno(pergunta);
        const total = this.calcularTotal(pagamentos, empresa, mesAno);
        const labelEmpresa = empresa || 'todas as empresas';
        const labelMes = mesAno ? `${mesAno.mes}/${mesAno.ano}` : 'todos os períodos';

        return `Total de gastos (${labelEmpresa}, ${labelMes}): R$ ${total.toLocaleString('pt-BR')}.`;
    }

    extrairEmpresa(pergunta) {
        const normalized = this.normalizeText(pergunta);
        if (normalized.includes('jfx')) return 'JFX';
        if (normalized.includes('dmf')) return 'DMF';
        if (normalized.includes('real energy') || normalized.includes('realenergy') || normalized.includes('real')) return 'Real Energy';
        return null;
    }

    extrairMesAno(pergunta) {
        const normalized = this.normalizeText(pergunta);
        const meses = {
            janeiro: 0, fevereiro: 1, marco: 2, março: 2, abril: 3, maio: 4, junho: 5,
            julho: 6, agosto: 7, setembro: 8, outubro: 9, novembro: 10, dezembro: 11
        };
        for (const [mes, idx] of Object.entries(meses)) {
            if (normalized.includes(mes)) {
                const anoMatch = normalized.match(/20\d{2}/);
                const ano = anoMatch ? Number(anoMatch[0]) : new Date().getFullYear();
                return { mes: idx + 1, ano };
            }
        }
        if (normalized.includes('mensal') || normalized.includes('este mes') || normalized.includes('mes atual')) {
            const now = new Date();
            return { mes: now.getMonth() + 1, ano: now.getFullYear() };
        }
        return null;
    }

    calcularTotal(pagamentos, empresa, mesAno) {
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
        const centers = empresa ? (empresas[empresa] || []).map(normalize) : null;

        return (pagamentos || []).reduce((acc, p) => {
            const valor = Math.abs(Number(p.valor) || 0);
            const centro = normalize(p.centro);
            if (centers && !centers.includes(centro)) return acc;
            if (mesAno) {
                const data = this.parseDate(p.data);
                if (!data) return acc;
                if ((data.getMonth() + 1) !== mesAno.mes || data.getFullYear() !== mesAno.ano) {
                    return acc;
                }
            }
            return acc + valor;
        }, 0);
    }

    parseDate(value) {
        if (!value) return null;
        const asDate = new Date(value);
        if (!isNaN(asDate.getTime())) return asDate;
        const parts = String(value).split('/');
        if (parts.length === 3) {
            const [d, m, y] = parts.map(Number);
            const parsed = new Date(y, m - 1, d);
            if (!isNaN(parsed.getTime())) return parsed;
        }
        return null;
    }

    responderAssinaturaContexto() {
        const assinaturas = (window.DMF_CONTEXT && window.DMF_CONTEXT.assinaturas) || [];
        if (!assinaturas.length) {
            return "Não encontrei assinaturas registradas.";
        }
        const ultima = assinaturas
            .slice()
            .sort((a, b) => new Date(b.assinatura.dataISO) - new Date(a.assinatura.dataISO))[0];
        return `Última assinatura: ${ultima.fornecedor} por ${ultima.assinatura.usuarioNome} em ${new Date(ultima.assinatura.dataISO).toLocaleString('pt-BR')}.`;
    }

    responderLogs() {
        const logs = (window.DMF_CONTEXT && window.DMF_CONTEXT.logs) || [];
        if (!logs.length) return "Nenhum log recente disponível.";
        const recentes = logs.slice(-3).map(l => `${l.acao || 'Ação'}: ${l.detalhes || ''}`).join(' | ');
        return `Últimos logs: ${recentes}. Quer ver mais detalhes?`;
    }

    extrairHashAssinatura(text) {
        const match = String(text || '').match(/\b[a-f0-9]{64}\b/i);
        return match ? match[0] : null;
    }

    async validarAssinatura(hash) {
        try {
            const pagamentos = (window.DMF_CONTEXT && window.DMF_CONTEXT.pagamentos) || [];
            const match = pagamentos.find(p => p.assinatura && String(p.assinatura.hash) === hash);
            const assinaturas = [
                { id: 'abc123', nome: 'Carlos Silva', data: '2023-01-15', hora: '14:30', valido: true },
                { id: 'def456', nome: 'Maria Oliveira', data: '2023-01-16', hora: '09:00', valido: true },
                { id: 'ghi789', nome: 'João Souza', data: '2023-02-20', hora: '16:45', valido: false }
            ];
            if (!match) {
                const local = assinaturas.find(a => a.id === hash);
                if (!local || !local.valido) {
                    this.addMessage('assistant', 'Assinatura Inválida.');
                    return;
                }
                this.addMessage(
                    'assistant',
                    `Assinatura de: ${local.nome}\nData: ${local.data}\nHora: ${local.hora}\nID: Válido`
                );
                return;
            }

            const headers = (window.getAuthHeaders && window.getAuthHeaders()) || {};
            const response = await fetch(`${getApiBase()}/api/signatures/verify`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...headers
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

            if (!response.ok) {
                this.addMessage('assistant', 'Assinatura Inválida.');
                return;
            }

            const data = await response.json();
            if (!data.valid) {
                this.addMessage('assistant', 'Assinatura Inválida.');
                return;
            }
            const dataAssinatura = match.assinatura?.dataISO
                ? new Date(match.assinatura.dataISO)
                : null;
            const dataStr = dataAssinatura ? dataAssinatura.toLocaleDateString('pt-BR') : '-';
            const horaStr = dataAssinatura ? dataAssinatura.toLocaleTimeString('pt-BR') : '-';
            this.addMessage(
                'assistant',
                `Assinatura de: ${match.assinatura?.usuarioNome || '-'}\nData: ${dataStr}\nHora: ${horaStr}\nID: Válido`
            );
        } catch (error) {
            this.addMessage('assistant', 'Erro ao validar assinatura. Tente novamente.');
        }
    }

    registrarPerguntaMemoria(pergunta, intencao) {
        const entrada = {
            pergunta,
            intencao,
            timestamp: new Date().toISOString(),
            frequencia: 1
        };

        const existente = this.memoria.find(m => m.pergunta === pergunta);
        if (existente) {
            existente.frequencia++;
        } else {
            this.memoria.push(entrada);
        }

        // Manter apenas as 1000 perguntas mais frequentes
        this.memoria.sort((a, b) => b.frequencia - a.frequencia);
        this.memoria = this.memoria.slice(0, 1000);

        localStorage.setItem('dmf_assistant_memoria', JSON.stringify(this.memoria));
    }

    buscarConhecimento(pergunta) {
        const brain = window.DMF_BRAIN;
        const normalized = this.normalizeText(pergunta);

        for (const conhecimento of brain.conhecimento) {
            if (conhecimento.perguntas.some(p => normalized.includes(this.normalizeText(p)))) {
                return conhecimento;
            }
        }
        return null;
    }

    gerarResposta(intencao) {
        const brain = window.DMF_BRAIN;

        switch (intencao.acao) {
            case 'ver':
            case 'mostrar':
            case 'listar':
                return this.responderListagem(intencao);
            case 'saber':
            case 'entender':
            case 'explicar':
            case 'como':
                return this.responderExplicacao(intencao);
            case 'contar':
            case 'quantos':
                return this.responderContagem(intencao);
            case 'quem':
                return this.responderQuem(intencao);
            case 'quando':
                return this.responderQuando(intencao);
            case 'por_que':
                return this.responderPorQue(intencao);
            case 'ajudar':
                return this.responderAjuda(intencao);
            default:
                return this.responderGeral(intencao);
        }
    }

    responderListagem(intencao) {
        const brain = window.DMF_BRAIN;

        switch (intencao.assunto) {
            case 'pagamento':
                if (brain.pagamentos.length === 0) return "Não há pagamentos registrados no sistema.";
                const pagamentos = brain.pagamentos.slice(0, 10);
                let resposta = `Aqui estão os ${pagamentos.length} pagamentos mais recentes:\n`;
                pagamentos.forEach(p => {
                    resposta += `- ${p.fornecedor}: R$ ${p.valor.toLocaleString('pt-BR')} (${p.data})\n`;
                });
                return resposta;

            case 'assinatura':
                if (brain.assinaturas.length === 0) return "Não há assinaturas registradas.";
                const assinaturas = brain.assinaturas.slice(0, 10);
                let respostaAssinaturas = `Aqui estão as ${assinaturas.length} assinaturas mais recentes:\n`;
                assinaturas.forEach(a => {
                    respostaAssinaturas += `- ${a.fornecedor} assinado por ${a.assinatura.usuarioNome} em ${new Date(a.assinatura.dataISO).toLocaleString()}\n`;
                });
                return respostaAssinaturas;

            case 'usuario':
                if (brain.usuarios.length === 0) return "Não há usuários registrados.";
                const usuarios = brain.usuarios.slice(0, 10);
                let respostaUsuarios = `Aqui estão os ${usuarios.length} usuários:\n`;
                usuarios.forEach(u => {
                    respostaUsuarios += `- ${u.nome} (${u.role})\n`;
                });
                return respostaUsuarios;

            case 'evento':
                if (brain.eventos.length === 0) return "Não há eventos registrados.";
                const eventos = brain.eventos.slice(0, 10);
                let respostaEventos = `Aqui estão os ${eventos.length} eventos mais recentes:\n`;
                eventos.forEach(e => {
                    respostaEventos += `- ${e.tipo}: ${e.detalhes} (${new Date(e.data).toLocaleString()})\n`;
                });
                return respostaEventos;

            default:
                return "O que você gostaria de listar? Posso mostrar pagamentos, assinaturas, usuários ou eventos.";
        }
    }

    responderExplicacao(intencao) {
        const explicacoes = {
            pagamento: "Os pagamentos são registros financeiros importados do Conta Azul. Cada pagamento tem fornecedor, valor, data e pode ser assinado digitalmente.",
            assinatura: "A assinatura digital confirma que um pagamento foi revisado e aprovado. Só usuários com permissão podem assinar.",
            usuario: "Os usuários têm diferentes cargos (admin, gestor) que definem suas permissões no sistema.",
            permissao: "As permissões controlam o que cada usuário pode fazer: assinar pagamentos, gerenciar usuários, etc.",
            importacao: "A importação permite carregar dados do Excel do Conta Azul automaticamente no sistema.",
            sistema: "Este é o Sistema DMF de Gestão Financeira, usado para controlar pagamentos e assinaturas digitais."
        };

        return explicacoes[intencao.assunto] || "Posso explicar sobre pagamentos, assinaturas, usuários, permissões, importação e o sistema em geral.";
    }

    responderContagem(intencao) {
        const brain = window.DMF_BRAIN;

        switch (intencao.assunto) {
            case 'pagamento':
                let count;
                if (intencao.perguntaStatus === "pendente") {
                    count = brain.pagamentos.filter(p => !p.assinatura).length;
                    return `Há ${count} pagamentos aguardando assinatura.`;
                } else if (intencao.perguntaStatus === "assinado") {
                    count = brain.assinaturas.length;
                    return `Há ${count} pagamentos assinados.`;
                } else {
                    count = brain.pagamentos.length;
                    return `Há ${count} pagamentos registrados no sistema.`;
                }

            case 'assinatura':
                return `Há ${brain.assinaturas.length} pagamentos assinados.`;

            case 'usuario':
                return `Há ${brain.usuarios.length} usuários registrados.`;

            case 'evento':
                return `Há ${brain.eventos.length} eventos registrados.`;

            case 'erro':
                return `Há ${brain.erros.length} erros registrados.`;

            default:
                return `Posso contar pagamentos, assinaturas, usuários, eventos ou erros.`;
        }
    }

    responderQuem(intencao) {
        const brain = window.DMF_BRAIN;

        if (intencao.assunto === 'assinatura' && intencao.tempo === 'hoje') {
            const hoje = new Date().toISOString().split('T')[0];
            const assinaturasHoje = brain.assinaturas.filter(a =>
                a.assinatura && a.assinatura.dataISO.startsWith(hoje)
            );

            if (assinaturasHoje.length === 0) return "Ninguém assinou hoje ainda.";

            const usuarios = [...new Set(assinaturasHoje.map(a => a.assinatura.usuarioNome))];
            return `Hoje, ${usuarios.join(', ')} assinaram pagamentos.`;
        }

        if (intencao.assunto === 'assinatura') {
            if (brain.assinaturas.length === 0) return "Não há assinaturas registradas.";
            const recentes = brain.assinaturas
                .slice()
                .sort((a, b) => new Date(b.assinatura.dataISO) - new Date(a.assinatura.dataISO))
                .slice(0, 5);
            let resposta = "Últimas assinaturas registradas:\n";
            recentes.forEach(a => {
                resposta += `- ${a.fornecedor} assinado por ${a.assinatura.usuarioNome} em ${new Date(a.assinatura.dataISO).toLocaleString()}\n`;
            });
            return resposta.trim();
        }

        if (intencao.assunto === 'usuario') {
            const usuarioLogado = brain.usuarioLogado;
            if (usuarioLogado) {
                return `Você está logado como ${usuarioLogado.nome} (${usuarioLogado.role}).`;
            }
            return "Você não está logado no sistema.";
        }

        return "Posso dizer quem assinou hoje ou informações sobre o usuário logado.";
    }

    responderQuando(intencao) {
        const brain = window.DMF_BRAIN;

        if (intencao.assunto === 'pagamento' && intencao.tempo === 'ultimo') {
            if (brain.pagamentos.length === 0) return "Não há pagamentos registrados.";

            const ultimo = brain.pagamentos.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))[0];
            return `O último pagamento foi registrado em ${new Date(ultimo.timestamp).toLocaleString()}.`;
        }

        if (intencao.assunto === 'assinatura' && intencao.tempo === 'ultimo') {
            if (brain.assinaturas.length === 0) return "Não há assinaturas registradas.";

            const ultima = brain.assinaturas.sort((a, b) =>
                new Date(b.assinatura.dataISO) - new Date(a.assinatura.dataISO)
            )[0];
            return `A última assinatura foi feita em ${new Date(ultima.assinatura.dataISO).toLocaleString()}.`;
        }

        return "Posso informar quando foi o último pagamento ou assinatura.";
    }

    responderPorQue(intencao) {
        const brain = window.DMF_BRAIN;

        if (intencao.assunto === 'erro') {
            if (brain.erros.length === 0) return "Não há erros registrados recentemente.";

            const ultimoErro = brain.erros[brain.erros.length - 1];
            return `O último erro foi: ${ultimoErro.detalhes}. ${this.sugerirSolucao(ultimoErro)}`;
        }

        if (intencao.assunto === 'assinatura' && intencao.acao === 'nao_consigo') {
            const usuario = brain.usuarioLogado;
            if (!usuario) return "Você precisa estar logado para assinar.";

            // Verificar permissões
            const rolePerms = this.getRolePermissions(usuario.role);
            const userPerms = usuario.additionalPermissions || [];

            if (!rolePerms.includes('sign_payments') && !userPerms.includes('sign_payments')) {
                return "Você não tem permissão para assinar pagamentos. Entre em contato com o administrador.";
            }

            return "Verifique se o pagamento já foi assinado ou se há algum problema técnico. Tente recarregar a página.";
        }

        return "Posso explicar erros do sistema ou problemas com assinaturas.";
    }

    responderAjuda(intencao) {
        return "Olá! Sou o assistente inteligente do Sistema DMF. Posso ajudar com:\n\n" +
               "• Pagamentos: ver, contar, explicar\n" +
               "• Assinaturas: quem assinou, quando, como fazer\n" +
               "• Usuários: listar, permissões\n" +
               "• Sistema: explicar funcionamento\n" +
               "• Eventos: o que aconteceu hoje\n\n" +
               "Pergunte o que precisar!";
    }

    responderGeral(intencao) {
        const saudacoes = ['oi', 'ola', 'bom dia', 'boa tarde', 'boa noite'];
        const pergunta = intencao.perguntaOriginal.toLowerCase();
        const perguntaNorm = this.normalizeText(intencao.perguntaOriginal);

        if (saudacoes.some(s => pergunta.includes(s))) {
            return "Olá! Sou o assistente inteligente do Sistema DMF. Como posso te ajudar hoje?";
        }

        if (pergunta.includes('data') || pergunta.includes('hoje')) {
            return `Hoje é ${this.getCurrentDate()}.`;
        }

        // Verificar perguntas frequentes na memória
        const perguntaFrequente = this.memoria.find(m =>
            m.frequencia > 2 && this.normalizeText(m.pergunta) === perguntaNorm
        );
        if (perguntaFrequente) {
            return "Esta é uma pergunta frequente. Posso ajudar com pagamentos, assinaturas, usuários e sistema. Diga 'ajudar' para ver opções.";
        }

        return "Não entendi completamente, mas posso ajudar com pagamentos, assinaturas, usuários e sistema. Tente perguntar de forma diferente ou diga 'ajudar' para ver opções.";
    }

    aprenderComResposta(pergunta, resposta, intencao) {
        const brain = window.DMF_BRAIN;

        // Adicionar ao aprendizado dinâmico
        this.addLearningQuestion(pergunta, resposta); // ALTERADO

        // Se a resposta foi útil (feedback positivo), adicionar ao conhecimento
        if (this.ultimoFeedback === 'positive') {
            const novoConhecimento = {
                topico: intencao.assunto,
                explicacao: resposta,
                perguntas: [pergunta.toLowerCase()]
            };

            const existente = brain.conhecimento.find(c => c.topico === intencao.assunto);
            if (existente) {
                if (!existente.perguntas.includes(pergunta.toLowerCase())) {
                    existente.perguntas.push(pergunta.toLowerCase());
                }
            } else {
                brain.conhecimento.push(novoConhecimento);
            }
        }
    }

    sugerirSolucao(erro) {
        const solucoes = {
            'permissao': 'Verifique suas permissões com o administrador.',
            'login': 'Tente fazer login novamente.',
            'importacao': 'Verifique se o arquivo Excel está no formato correto.',
            'assinatura': 'Certifique-se de ter permissão para assinar.'
        };

        for (const [tipo, solucao] of Object.entries(solucoes)) {
            if (erro.detalhes.toLowerCase().includes(tipo)) {
                return solucao;
            }
        }

        return 'Tente recarregar a página ou entre em contato com o suporte.';
    }

    getRolePermissions(roleName) {
        // ALTERADO: Usar system.admin.getRolePermissions() se disponível, senão fallback local
        if (window.system && window.system.admin && window.system.admin.getRolePermissions) {
            return window.system.admin.getRolePermissions(roleName);
        }
        // Fallback local
        const permissoes = {
            'admin': ['all'],
            'gestor': ['sign_payments'],
            'usuario': []
        };
        return permissoes[roleName] || [];
    }

    addMessage(type, content) {
        const message = {
            type,
            content,
            timestamp: new Date().toISOString()
        };

        this.history.push(message);
        this.saveHistory();
        this.renderMessage(message);
    }

    renderMessage(message) {
        const messagesContainer = document.getElementById('chatMessages');
        if (!messagesContainer) return;

        const messageDiv = document.createElement('div');
        messageDiv.className = `chat-message ${message.type}`;

        const bubble = document.createElement('div');
        bubble.className = 'chat-bubble';
        bubble.textContent = message.content;

        messageDiv.appendChild(bubble);

        if (message.type === 'assistant') {
            const feedbackDiv = document.createElement('div');
            feedbackDiv.className = 'feedback-buttons';
            const positiveButton = document.createElement('button');
            positiveButton.className = 'feedback-btn positive';
            positiveButton.textContent = 'Util';
            positiveButton.addEventListener('click', () => this.giveFeedback('positive'));

            const negativeButton = document.createElement('button');
            negativeButton.className = 'feedback-btn negative';
            negativeButton.textContent = 'Nao util';
            negativeButton.addEventListener('click', () => this.giveFeedback('negative'));

            feedbackDiv.appendChild(positiveButton);
            feedbackDiv.appendChild(negativeButton);
            messageDiv.appendChild(feedbackDiv);
        }

        messagesContainer.appendChild(messageDiv);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }

    renderHistory() {
        const messagesContainer = document.getElementById('chatMessages');
        if (!messagesContainer) return;
        messagesContainer.innerHTML = '';
        this.history.forEach(msg => this.renderMessage(msg));
    }

    giveFeedback(type) {
        this.ultimoFeedback = type;

        if (type === 'positive') {
            console.log('Resposta útil - aprendendo...');
        } else {
            console.log('Resposta não útil - ajustando...');
        }

        if (typeof window.showToast === 'function') {
            window.showToast(`Feedback recebido: ${type === 'positive' ? 'positivo' : 'negativo'}.`, 'success');
        } else {
            console.log(`Feedback recebido: ${type}`);
        }
    }

    saveHistory() {
        localStorage.setItem('dmf_assistant_history', JSON.stringify(this.history.slice(-50)));
    }

    renderQuickPrompts() {
        const container = document.getElementById('chatQuickPrompts');
        if (!container) return;
        if (container.children.length > 0) return;

        this.quickPrompts.forEach((prompt) => {
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'chat-quick-btn';
            button.setAttribute('data-quick-prompt', prompt);
            button.textContent = prompt;
            container.appendChild(button);
        });
    }

    renderWelcomeIfNeeded() {
        if (this.history.length > 0) return;
        this.addMessage(
            'assistant',
            'Posso ajudar com pagamentos, assinaturas, auditoria e operacao do sistema. Use os atalhos acima ou digite sua pergunta.'
        );
    }

    clearConversation() {
        this.history = [];
        this.saveHistory();
        this.renderHistory();
        this.renderWelcomeIfNeeded();
        if (typeof window.showToast === 'function') {
            window.showToast('Conversa limpa.', 'success');
        }
    }

    setSendingState(isSending) {
        const input = document.getElementById('chatInput');
        const sendButton = document.getElementById('chatSendBtn');
        if (input) input.disabled = !!isSending;
        if (sendButton) {
            sendButton.disabled = !!isSending;
            sendButton.textContent = isSending ? 'Enviando...' : 'Enviar';
        }
    }

    showTypingIndicator() {
        const messagesContainer = document.getElementById('chatMessages');
        if (!messagesContainer) return null;
        const id = `typing-${Date.now()}`;
        const wrapper = document.createElement('div');
        wrapper.className = 'chat-message assistant typing';
        wrapper.setAttribute('data-typing-id', id);
        const bubble = document.createElement('div');
        bubble.className = 'chat-bubble';
        bubble.textContent = 'Assistente digitando...';
        wrapper.appendChild(bubble);
        messagesContainer.appendChild(wrapper);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
        return id;
    }

    hideTypingIndicator(id) {
        if (!id) return;
        const node = document.querySelector(`[data-typing-id="${id}"]`);
        if (node && node.parentNode) {
            node.parentNode.removeChild(node);
        }
    }
}

// Initialize and keep a global reference for inline handlers.
new IntelligentAssistant();
