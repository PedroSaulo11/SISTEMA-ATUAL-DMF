/* eslint-disable no-console */
const jwt = require('jsonwebtoken');

function mustEnv(name, fallback = null) {
  const raw = process.env[name];
  if (raw == null || raw === '') {
    if (fallback != null) return fallback;
    throw new Error(`Missing required env: ${name}`);
  }
  return String(raw).trim();
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function parseSseChunk(buffer) {
  const events = [];
  let remaining = buffer;
  while (true) {
    const idx = remaining.indexOf('\n\n');
    if (idx < 0) break;
    const rawEvent = remaining.slice(0, idx);
    remaining = remaining.slice(idx + 2);
    const lines = rawEvent.split(/\r?\n/);
    let eventName = 'message';
    const dataLines = [];
    for (const line of lines) {
      if (line.startsWith('event:')) eventName = line.slice(6).trim();
      if (line.startsWith('data:')) dataLines.push(line.slice(5).trim());
    }
    let data = null;
    const joined = dataLines.join('\n').trim();
    if (joined) {
      try {
        data = JSON.parse(joined);
      } catch (_) {
        data = joined;
      }
    }
    events.push({ event: eventName, data });
  }
  return { events, remaining };
}

async function main() {
  const base = mustEnv('BASE_URL').replace(/\/+$/, '');
  const accessToken = String(process.env.ACCESS_TOKEN || '').trim();
  const jwtSecret = accessToken ? null : mustEnv('JWT_SECRET');
  const company = mustEnv('TEST_COMPANY', 'DMF');
  const timeoutMs = Number(mustEnv('SSE_TEST_TIMEOUT_MS', '60000'));

  const token = accessToken || jwt.sign(
    { id: 900001, username: 'admin-sse-e2e', role: 'admin' },
    jwtSecret,
    { expiresIn: '15m' }
  );

  const paymentId = `sse-e2e-${Date.now()}`;
  const sseUrl = `${base}/api/flow-payments/stream?company=${encodeURIComponent(company)}&access_token=${encodeURIComponent(token)}`;
  const postUrl = `${base}/api/flow-payments?company=${encodeURIComponent(company)}`;
  const deleteUrl = `${base}/api/flow-payments/${encodeURIComponent(paymentId)}?company=${encodeURIComponent(company)}`;
  const statusUrl = `${base}/api/auth/user-status`;

  const controller = new AbortController();
  const hardTimeout = setTimeout(() => controller.abort(), timeoutMs);
  const stopAt = Date.now() + timeoutMs;
  let upsertSeen = false;
  let rawBuffer = '';

  const authCheck = await fetch(statusUrl, {
    method: 'GET',
    headers: { Authorization: `Bearer ${token}` }
  });
  if (!authCheck.ok) {
    const txt = await authCheck.text();
    throw new Error(`Token auth check failed HTTP ${authCheck.status} body=${txt.slice(0, 300)}`);
  }

  const ssePromise = (async () => {
    const res = await fetch(sseUrl, {
      method: 'GET',
      headers: { Accept: 'text/event-stream' },
      signal: controller.signal
    });
    if (!res.ok) {
      throw new Error(`SSE connect failed HTTP ${res.status}`);
    }
    const reader = res.body.getReader();
    while (Date.now() < stopAt) {
      const { done, value } = await reader.read();
      if (done) break;
      rawBuffer += Buffer.from(value).toString('utf8');
      const parsed = parseSseChunk(rawBuffer);
      rawBuffer = parsed.remaining;
      for (const evt of parsed.events) {
        if (evt.event !== 'flow_update') continue;
        if (evt.data?.type === 'payment_upserted' && String(evt.data?.payment?.id || '') === paymentId) {
          upsertSeen = true;
          return;
        }
      }
    }
    throw new Error('Timed out waiting for SSE payment_upserted event');
  })();

  // Give the stream a brief moment to establish before emitting an update.
  await wait(1200);

  const postRes = await fetch(postUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`
    },
    body: JSON.stringify({
      id: paymentId,
      fornecedor: 'SSE E2E Supplier',
      data: '24/02/2026',
      descricao: 'SSE distributed test',
      valor: 10.5,
      centro: 'Teste',
      categoria: 'Operacional',
      company
    })
  });

  const postText = await postRes.text();
  if (!postRes.ok) {
    controller.abort();
    throw new Error(`POST flow payment failed HTTP ${postRes.status} body=${postText.slice(0, 300)}`);
  }

  await ssePromise;
  controller.abort();

  const delRes = await fetch(deleteUrl, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${token}` }
  });
  const delText = await delRes.text();
  if (!delRes.ok) {
    throw new Error(`Cleanup delete failed HTTP ${delRes.status} body=${delText.slice(0, 300)}`);
  }

  clearTimeout(hardTimeout);

  if (!upsertSeen) {
    throw new Error('SSE did not receive expected payment_upserted event');
  }

  console.log('[sse-e2e] PASS payment_upserted + cleanup_deleted');
}

main().catch((err) => {
  console.error('[sse-e2e] FAIL', err && err.stack ? err.stack : err);
  process.exit(1);
});
