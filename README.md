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

Check de readiness (incluído no `check:phase3`):
```bash
npm run check:readiness
```

Para validar também existência dos segredos no GCP:
```bash
VERIFY_GCLOUD_SECRETS=true npm run check:readiness
```
