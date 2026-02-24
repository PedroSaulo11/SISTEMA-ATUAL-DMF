# Backend do Sistema DMF

Repositório do backend (API + integrações Conta Azul/Cobli) hospedado no Google Cloud App Engine.

URL pública atual:
- https://project-b2fcff48-a0ca-4867-995.rj.r.appspot.com

## 1) Git e compartilhamento do código

O projeto já está versionado e publicado no GitHub.

Clonar:
```bash
git clone https://github.com/PedroSaulo11/SISTEMA-ATUAL-DMF.git
cd SISTEMA-ATUAL-DMF
```

Fluxo básico:
```bash
# atualizar
git pull

# adicionar alterações
git add .

# commitar
git commit -m "Minha alteração"

# enviar
git push
```

## 2) Rodar localmente

Instalar dependências:
```bash
npm install
```

Rodar API:
```bash
npm start
```

Rodar em modo desenvolvimento:
```bash
npm run dev
```

Webhook (se necessário):
```bash
npm run start:webhook
```

## 3) VS Code Live Share (colaboração em tempo real)

1. Instale a extensão **Live Share** no VS Code.
2. Clique no ícone do Live Share e em **Start Collaboration Session**.
3. Compartilhe o link gerado com os colaboradores.
4. Os colaboradores precisam ter a extensão instalada para entrar.

## 4) Backend no Google Cloud

O backend está publicado no App Engine e pode ser acessado pela URL pública:
- https://project-b2fcff48-a0ca-4867-995.rj.r.appspot.com

Se quiser usar domínio próprio, configure no App Engine (Custom Domains).

## 5) Deploy para o Google Cloud

Pré-requisitos:
- Google Cloud SDK instalado e autenticado
- Projeto selecionado

Deploy:
```bash
gcloud app deploy
```

## 6) Observações de segurança

- **Não versionar** o arquivo `.env` com segredos.
- No App Engine deste projeto, use `app.yaml` apenas para variáveis não sensíveis e mapeamento de nomes de segredos.
- Os segredos reais devem vir do Secret Manager no startup do backend (`SECRET_MANAGER_ENABLED=true`).

## 7) Check de prontidão multiusuário

Rodar validações locais:
```bash
npm run check:phase3
```

Baseline de não regressão (Etapa 1):
```bash
npm run check:baseline
```

Check de readiness (incluído no `check:phase3`):
```bash
npm run check:readiness
```

Para validar também existência dos segredos no GCP:
```bash
VERIFY_GCLOUD_SECRETS=true npm run check:readiness
```

## 8) Go-live multiusuário (automação completa)

Checklist automatizado (local + produção):
```bash
npm run go-live:check
```

Comportamento:
- Sempre roda `check:phase3`.
- Se `BASE_URL` estiver definido, roda `smoke:prod` e `check:audit-fallback:prod`.
- Se `BASE_URL` e `ACCESS_TOKEN` estiverem definidos, roda carga concorrente (`load:prod:multiuser`).

Variáveis úteis:
- `BASE_URL=https://<app>.rj.r.appspot.com`
- `ACCESS_TOKEN=<jwt_admin_valido>`
- `TEST_COMPANY=Real Energy`
- `LOAD_WORKERS=8`
- `LOAD_ROUNDS=20`
- `LOAD_PAUSE_MS=100`

## 9) Teste de carga concorrente

```bash
BASE_URL=... ACCESS_TOKEN=... npm run load:prod:multiuser
```

Valida em loop:
- criação de pagamento
- assinatura concorrente (esperado `200/409`)
- limpeza do item de teste
- latência p50/p95/max

## 10) Permissões de auditoria no banco (correção definitiva)

Aplicar grants com usuário admin do PostgreSQL:
```bash
DB_ADMIN_URL=postgres://... DB_APP_ROLE=dmf_app npm run db:grant:audit
```

Arquivo SQL de referência:
- `db/migration_2026_02_24_audit_sequence_grants.sql`

## 11) Segredos e acessos no Secret Manager

Setup de segredos e IAM:
```powershell
.\scripts\secret-manager-setup.ps1 -ProjectId "project-b2fcff48-a0ca-4867-995"
```

Para também publicar versões com valores vindos do ambiente local:
```powershell
.\scripts\secret-manager-setup.ps1 -ProjectId "project-b2fcff48-a0ca-4867-995" -PopulateFromEnv
```

## 12) Monitoramento e alertas (Cloud Monitoring)

Provisionar log-metrics + alert policies:
```powershell
.\scripts\setup-monitoring-alerts.ps1 -ProjectId "project-b2fcff48-a0ca-4867-995" -ServiceName "default"
```

Opcional: adicionar canal de notificação:
```powershell
.\scripts\setup-monitoring-alerts.ps1 -ProjectId "project-b2fcff48-a0ca-4867-995" -ServiceName "default" -NotificationChannel "projects/<id>/notificationChannels/<channel_id>"
```

## 13) Rollout por feature flags (Etapa 2)

As flags abaixo existem para habilitar blocos de multiusuário de forma gradual, sem remover o fluxo atual:
- `ENABLE_REDIS_CACHE`
- `ENABLE_DISTRIBUTED_RATE_LIMIT`
- `ENABLE_PUBSUB_SSE`
- `ENABLE_STRICT_API_ONLY_AUTH`
- `ENABLE_HTTPONLY_SESSION`

Quando `ENABLE_HTTPONLY_SESSION=true`:
- Login também emite cookies `HttpOnly` (`ACCESS_COOKIE_NAME` e `REFRESH_COOKIE_NAME`).
- Refresh de sessão de usuário passa a usar `POST /api/auth/user-refresh`.
- Logout de sessão via `POST /api/auth/logout`.

Padrão seguro:
- Todas em `false` no `app.yaml`.
- Ativar uma por vez em ambiente de homologação.
- Validar `GET /api/health` em `feature_flags`.
- Executar smoke após cada ativação.
