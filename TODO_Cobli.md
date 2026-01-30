# TODO: Integração API Cobli para Pagamentos

## Implementação da Integração
- [x] Adicionar endpoint `/api/cobli/payments` em server.js para buscar pagamentos da API Cobli
- [x] Adicionar método `syncFromCobliAPI` na classe DataProcessor em script.js
- [x] Atualizar seção de pagamentos em index.html com botão para sincronizar pagamentos Cobli
- [x] Mapear campos de pagamento Cobli para formato DMF (supplier -> fornecedor, due_date -> data, etc.)

## Testes e Validação
- [x] Testar integração da API Cobli (endpoint acessível, erro de configuração esperado)
- [x] Lidar com autenticação e casos de erro (erro tratado corretamente quando API não configurada)
- [ ] Verificar mapeamento correto dos campos (requer dados reais da API Cobli)
- [ ] Testar importação de dados no sistema DMF (requer credenciais válidas da API Cobli)

## Documentação e Finalização
- [x] Atualizar TODO.md principal com tarefas concluídas
- [x] Documentar configuração necessária para API Cobli
- [ ] Verificar compatibilidade com deploy no Google Cloud
