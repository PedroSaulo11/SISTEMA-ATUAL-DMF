# Plano De Execucao Multiusuario

## Objetivo
Levar o sistema para operacao multiusuario com seguranca, consistencia e observabilidade, sem quebrar funcionalidades existentes.

## Bloco Hoje (executado)
- [x] Sincronizacao de fluxo mais rapida entre dispositivos (polling + stream com reconexao).
- [x] Reducao de risco de corrida em importacao/conflito de assinatura.
- [x] Estrategia de segredos compativel com App Engine atual:
  - segredos removidos de `app.yaml`
  - carregamento via Secret Manager no startup do backend.
- [x] Check automatizado de readiness:
  - `npm run check:readiness`
- [x] Health com sinais operacionais:
  - `runtime.sse_subscribers`
  - `runtime.conflicts_total`
  - `runtime.last_conflict_at`

## Bloco Esta Semana (operacional)
- [ ] Criar/validar todos os secrets no GCP com `latest` ativo.
- [ ] Garantir IAM de `secretAccessor` para service account do App Engine.
- [ ] Deploy controlado e smoke pos-deploy.
- [ ] Teste com 2+ usuarios simultaneos (admin + gestor), assinando/importando no mesmo fluxo.
- [ ] Registrar baseline de latencia de propagacao (meta: 0-3s).

Comandos recomendados:
```bash
npm run check:phase3
gcloud app deploy --quiet
```

## Bloco Proxima Semana (hardening)
- [ ] Automatizar teste de concorrencia (assinatura simultanea no mesmo pagamento).
- [ ] Alertas operacionais (5xx, latencia alta, conflito 409 elevado).
- [ ] Simulacao de restore de backup em ambiente de teste.
- [ ] Revisao de acesso admin (MFA/politica de senha, quando aplicavel ao ambiente).

## Criterios De Pronto Para Producao Multiusuario
- [ ] Sem segredos hardcoded no `app.yaml`.
- [ ] `check:phase3` verde no CI.
- [ ] Login, dashboard e fluxo funcionando em multiplos dispositivos sem divergencia.
- [ ] Assinaturas propagando em tempo real entre usuarios.
- [ ] Backup/restore testado com sucesso.
