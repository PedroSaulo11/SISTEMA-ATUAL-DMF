# Fase 3 - Seguranca e CI

## Bloco 1 (concluido)
- Pipeline de CI em `.github/workflows/ci.yml`
  - sintaxe (`check:syntax`)
  - preflight de seguranca (`check:security`)
  - smoke test de health (`smoke:health`)
- Scripts de suporte:
  - `scripts/security-check.js`
  - `scripts/smoke-health.js`
- Scripts npm adicionados:
  - `check:syntax`
  - `check:security`
  - `smoke:health`
  - `check:phase3`

## Bloco 2 (concluido)
- Segredos removidos de `app.yaml` e migrados para `secret_env_variables`.
- CI endurecido com `SECURITY_GATE_STRICT=true`.
- `scripts/security-check.js` atualizado para validar:
  - ausencia de segredo hardcoded no `app.yaml`
  - presenca obrigatoria dos segredos criticos em `secret_env_variables`.

## Ajuste de compatibilidade (App Engine atual)
- O deploy com `gcloud app deploy` retornou erro de schema: `Unexpected attribute 'secret_env_variables'`.
- Para manter operacao no App Engine atual, o `app.yaml` voltou para `env_variables`.
- CI voltou para `SECURITY_GATE_STRICT=false` temporariamente.
- Migracao definitiva de segredos fica pendente de uma estrategia compativel com App Engine neste projeto.

## Segredos obrigatorios no Secret Manager
- `JWT_SECRET`
- `CONTA_AZUL_CLIENT_SECRET`
- `CONTA_AZUL_ACCESS_TOKEN`
- `CONTA_AZUL_REFRESH_TOKEN`
- `DATABASE_URL`
- `SIGNATURE_SECRET`
- `EVENT_WEBHOOK_SECRET`

## Comandos de setup (uma vez)
```bash
gcloud config set project project-b2fcff48-a0ca-4867-995
gcloud secrets create JWT_SECRET --replication-policy=automatic
gcloud secrets create CONTA_AZUL_CLIENT_SECRET --replication-policy=automatic
gcloud secrets create CONTA_AZUL_ACCESS_TOKEN --replication-policy=automatic
gcloud secrets create CONTA_AZUL_REFRESH_TOKEN --replication-policy=automatic
gcloud secrets create DATABASE_URL --replication-policy=automatic
gcloud secrets create SIGNATURE_SECRET --replication-policy=automatic
gcloud secrets create EVENT_WEBHOOK_SECRET --replication-policy=automatic
```

## Comandos de versao (sempre que atualizar segredo)
```bash
printf 'valor_aqui' | gcloud secrets versions add JWT_SECRET --data-file=-
printf 'valor_aqui' | gcloud secrets versions add CONTA_AZUL_CLIENT_SECRET --data-file=-
printf 'valor_aqui' | gcloud secrets versions add CONTA_AZUL_ACCESS_TOKEN --data-file=-
printf 'valor_aqui' | gcloud secrets versions add CONTA_AZUL_REFRESH_TOKEN --data-file=-
printf 'valor_aqui' | gcloud secrets versions add DATABASE_URL --data-file=-
printf 'valor_aqui' | gcloud secrets versions add SIGNATURE_SECRET --data-file=-
printf 'valor_aqui' | gcloud secrets versions add EVENT_WEBHOOK_SECRET --data-file=-
```

## Permissao da conta de servico do App Engine
```bash
PROJECT_NUMBER="$(gcloud projects describe project-b2fcff48-a0ca-4867-995 --format='value(projectNumber)')"
SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
for SECRET in JWT_SECRET CONTA_AZUL_CLIENT_SECRET CONTA_AZUL_ACCESS_TOKEN CONTA_AZUL_REFRESH_TOKEN DATABASE_URL SIGNATURE_SECRET EVENT_WEBHOOK_SECRET; do
  gcloud secrets add-iam-policy-binding "$SECRET" \
    --member="serviceAccount:${SA}" \
    --role="roles/secretmanager.secretAccessor"
done
```

## Validacao local
- `npm run check:phase3`
