# Fase 1 - Checklist de Deploy e Rollback

## Antes do deploy
- Verificar `git status` limpo no branch de deploy.
- Confirmar build sem erro de sintaxe:
  - `node --check server.js`
  - `node --check script.js`
  - `node --check bootstrap.js`
- Confirmar variaveis de ambiente no GCloud:
  - `NODE_ENV=production`
  - `JWT_SECRET` definido
  - `CORS_ORIGINS` com dominio correto

## Deploy
- Publicar nova versao no App Engine.
- Aguardar health:
  - `GET /api/health` retorna `200`.

## Smoke test (obrigatorio)
- Login com usuario admin.
- Login com usuario gestor financeiro.
- Abrir `Fluxo de Pagamentos` e validar botoes por permissao.
- Abrir `Dashboard` e confirmar cards atualizando sem trocar de aba.
- Abrir rota direta:
  - `/admin.html`
  - `/dashboard.html`
  - confirmar redirecionamento para `/?tab=...`.

## Se algo falhar (rollback)
- Promover versao anterior no App Engine.
- Limpar cache do navegador (`Ctrl+Shift+R`) nos clientes.
- Revalidar `GET /api/health` e login.
