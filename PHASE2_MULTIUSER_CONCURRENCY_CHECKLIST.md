# Fase 2 - Checklist de Concorrencia Multiusuario

## Preparacao
- Usar 2 dispositivos/sessoes diferentes com usuarios distintos.
- Confirmar ambos na mesma empresa/fluxo (ex.: `Real Energy`).
- Abrir DevTools Network em ambos.

## Teste 1 - Upsert com conflito de versao
- Dispositivo A abre um pagamento e mantem dados em tela.
- Dispositivo B altera o mesmo pagamento e salva primeiro.
- Dispositivo A tenta salvar com versao antiga.
- Esperado:
  - resposta `409`
  - payload com `error=Conflict`
  - `code=FLOW_VERSION_CONFLICT`
  - `expectedVersion` e `currentVersion` preenchidos.

## Teste 2 - Assinatura concorrente
- Dispositivo A e B tentam assinar o mesmo pagamento pendente quase ao mesmo tempo.
- Esperado:
  - primeiro sucesso `200`
  - segundo recebe `409`
  - payload com `code=FLOW_SIGN_CONFLICT`.

## Teste 3 - Auditoria e observabilidade
- Verificar log de backend para conflito:
  - evento `ALERT_CONFLICT`
  - campo `request_id` presente.
- Confirmar `X-Request-Id` no header de resposta das rotas testadas.

## Teste 4 - Nao regressao funcional
- Importar pagamentos.
- Assinar pagamentos diferentes em paralelo.
- Arquivar fluxo.
- Validar que operacoes sem conflito continuam em `200`.

## Criterio de aceite
- Conflitos reais retornam `409` padronizado.
- Operacoes sem corrida continuam funcionais.
- Logs permitem rastrear cada conflito por `request_id`.
