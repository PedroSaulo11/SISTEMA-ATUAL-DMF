# TODO: Integração API Conta Azul

## Backend
- [x] Criar .env com Client ID/Secret e tokens fornecidos
- [x] Modificar server.js para usar tokens diretos:
  - [x] Servidor Express básico
  - [x] Remover fluxo OAuth2 e usar tokens fornecidos diretamente
  - [x] Rota para buscar pagamentos da API (/api/payments)
  - [x] Armazenamento seguro do token (em memória, renovação automática)
  - [x] CORS para permitir requests do frontend
  - [x] Implementar renovação automática usando Refresh Token

## Frontend
- [x] index.html já tem botão "Sincronizar API Conta Azul"
- [x] script.js já tem função syncFromAPI() que chama o backend

## Testes
- [x] Executar servidor localmente (`npm start`) - ✅ Servidor rodando em http://localhost:3001
- [ ] Testar sincronização de dados via botão "Sincronizar API Conta Azul" - ❌ BLOQUEADO: Token inválido
- [ ] Verificar se dados da API são importados corretamente - ❌ BLOQUEADO: Token inválido
- [ ] Testar renovação automática de tokens - ❌ BLOQUEADO: Token inválido

## 🚨 PROBLEMA IDENTIFICADO
- [x] **TOKENS ATUALIZADOS**: Novos Client ID, Secret e Access Token fornecidos
- [ ] **API AINDA FALHANDO**: Conta Azul rejeitando o token (mesmo erro "invalid_token")
- [ ] **REFRESH TOKEN AUSENTE**: Ainda usando placeholder "REFRESH_TOKEN"
- [ ] **INVESTIGAÇÃO NECESSÁRIA**: Verificar se tokens são válidos no Conta Azul

## Segurança
- [x] Usar variáveis de ambiente para Client ID/Secret e tokens
- [x] Armazenar tokens no servidor, não no frontend
- [x] Implementar renovação automática de tokens usando Basic Auth
