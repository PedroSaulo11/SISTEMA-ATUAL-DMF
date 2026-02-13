/* Multiuser smoke test:
   - starts server in local fallback mode
   - creates a payment
   - performs concurrent signature attempts
   - validates conflict handling + final signed state */
const { spawn } = require('child_process');
const jwt = require('jsonwebtoken');

const PORT = process.env.PORT || '39124';
const BASE = `http://127.0.0.1:${PORT}`;
const SECRET = process.env.JWT_SECRET || 'smoke-multiuser-jwt-secret';
const STARTUP_WAIT_MS = 1500;
const MAX_ATTEMPTS = 12;
const RETRY_DELAY_MS = 800;

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function tokenFor(user) {
  return jwt.sign(user, SECRET, { expiresIn: '1h' });
}

async function request(path, { method = 'GET', token = null, body = null } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined
  });
  const text = await response.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch (_) {
    json = { raw: text };
  }
  return { status: response.status, json };
}

async function waitForHealth() {
  await wait(STARTUP_WAIT_MS);
  let lastError = null;
  for (let i = 0; i < MAX_ATTEMPTS; i += 1) {
    try {
      const health = await request('/api/health');
      if (health.status === 200) return health.json;
      lastError = new Error(`Health status ${health.status}`);
    } catch (error) {
      lastError = error;
    }
    await wait(RETRY_DELAY_MS);
  }
  throw lastError || new Error('Health unavailable');
}

async function main() {
  const child = spawn(process.execPath, ['server.js'], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env,
      PORT: String(PORT),
      NODE_ENV: 'development',
      SECRET_MANAGER_ENABLED: 'false',
      DATABASE_URL: '',
      DB_CONNECT_RETRIES: '1',
      JWT_SECRET: SECRET,
      SIGNATURE_SECRET: 'smoke-signature-secret',
      PERMISSIONS_ENFORCED: 'true'
    }
  });

  let output = '';
  child.stdout.on('data', (chunk) => { output += chunk.toString(); });
  child.stderr.on('data', (chunk) => { output += chunk.toString(); });

  try {
    const health = await waitForHealth();
    if (!health?.db_ready) {
      console.log('[SMOKE][SKIP] multiuser: banco indisponivel no ambiente local (db_ready=false).');
      return;
    }

    const adminToken = tokenFor({ id: 1001, username: 'admin-smoke', role: 'admin' });
    const gestorToken = tokenFor({ id: 1002, username: 'gestor-smoke', role: 'gestor' });
    const userToken = tokenFor({ id: 1003, username: 'user-smoke', role: 'user' });

    const paymentId = `smoke-${Date.now()}`;
    const create = await request('/api/flow-payments?company=DMF', {
      method: 'POST',
      token: adminToken,
      body: {
        id: paymentId,
        fornecedor: 'Smoke Supplier',
        data: '11/02/2026',
        descricao: 'Smoke test multiuser',
        valor: 123.45,
        centro: 'Teste',
        categoria: 'Operacional'
      }
    });
    if (create.status === 503) {
      console.log('[SMOKE][SKIP] multiuser: rotas de fluxo indisponiveis (Database not ready).');
      return;
    }
    if (create.status !== 200 || !create.json?.success) {
      throw new Error(`Falha ao criar pagamento: HTTP ${create.status} ${JSON.stringify(create.json)}`);
    }

    const signatureA = {
      usuarioNome: 'Admin Smoke',
      dataISO: new Date().toISOString(),
      hash: `hash-a-${Date.now()}`
    };
    const signatureB = {
      usuarioNome: 'Gestor Smoke',
      dataISO: new Date().toISOString(),
      hash: `hash-b-${Date.now()}`
    };

    const [signA, signB] = await Promise.all([
      request(`/api/flow-payments/${encodeURIComponent(paymentId)}/sign?company=DMF`, {
        method: 'PATCH',
        token: adminToken,
        body: { assinatura: signatureA, company: 'DMF' }
      }),
      request(`/api/flow-payments/${encodeURIComponent(paymentId)}/sign?company=DMF`, {
        method: 'PATCH',
        token: gestorToken,
        body: { assinatura: signatureB, company: 'DMF' }
      })
    ]);

    const statuses = [signA.status, signB.status].sort((a, b) => a - b);
    if (!(statuses[0] === 200 && statuses[1] === 409)) {
      throw new Error(`Conflito concorrente invalido: [${signA.status}, ${signB.status}]`);
    }

    const list = await request('/api/flow-payments?company=DMF', { token: userToken });
    if (list.status !== 200) {
      throw new Error(`Falha ao listar fluxo: HTTP ${list.status}`);
    }
    const payment = (list.json?.payments || []).find((p) => String(p.id) === paymentId);
    if (!payment || !payment.assinatura) {
      throw new Error('Pagamento nao ficou assinado apos corrida concorrente.');
    }

    const healthAfter = await request('/api/health');
    const conflicts = Number(healthAfter.json?.runtime?.conflicts_total || 0);
    if (conflicts < 1) {
      throw new Error('Health nao registrou conflito runtime esperado.');
    }

    console.log('[SMOKE][OK] multiuser concorrencia validada (200/409 + estado final assinado).');
  } finally {
    if (child.exitCode === null && !child.killed) {
      child.kill('SIGTERM');
    }
  }
}

main().catch((error) => {
  console.error('[SMOKE][FAIL] multiuser', error.message);
  process.exit(1);
});
