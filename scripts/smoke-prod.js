/* eslint-disable no-console */
// Smoke test against a running deployment (prod/staging).
// Safe-by-default: does not mutate data.
//
// Usage (PowerShell):
//   $env:BASE_URL="https://<app>.rj.r.appspot.com"
//   $env:TEST_USERNAME="admin@email.com"   # optional
//   $env:TEST_PASSWORD="senha"            # optional
//   node scripts/smoke-prod.js

const { setTimeout: sleep } = require('timers/promises');

function mustEnv(name, fallback = null) {
  return (process.env[name] || fallback || '').trim();
}

function assert(cond, msg) {
  if (!cond) {
    const err = new Error(msg);
    err.name = 'SmokeAssertionError';
    throw err;
  }
}

function baseUrl() {
  const raw = mustEnv('BASE_URL', '');
  assert(raw, 'BASE_URL is required (e.g. https://project-...r.appspot.com)');
  return raw.replace(/\/+$/, '');
}

async function httpJson(url, init = {}) {
  const res = await fetch(url, {
    redirect: 'follow',
    cache: 'no-store',
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init.headers || {})
    }
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch (_) {
    json = null;
  }
  return { res, text, json };
}

async function readSseOnce(url, timeoutMs = 7000) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs).unref?.();
  try {
    const res = await fetch(url, {
      method: 'GET',
      headers: { Accept: 'text/event-stream' },
      signal: controller.signal
    });
    assert(res.ok, `SSE GET failed: HTTP ${res.status}`);
    const reader = res.body.getReader();
    let buf = '';
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += Buffer.from(value).toString('utf8');
      // first event should arrive quickly
      if (buf.includes('\n\n')) break;
    }
    reader.cancel().catch(() => {});

    // Parse very small subset: event + data lines
    const lines = buf.split(/\r?\n/).map(l => l.trimEnd());
    const eventLine = lines.find(l => l.startsWith('event:'));
    const dataLine = lines.find(l => l.startsWith('data:'));
    const event = eventLine ? eventLine.slice('event:'.length).trim() : null;
    const dataRaw = dataLine ? dataLine.slice('data:'.length).trim() : null;
    let data = null;
    try { data = dataRaw ? JSON.parse(dataRaw) : null; } catch (_) { data = null; }
    return { event, data, raw: buf };
  } finally {
    clearTimeout(t);
  }
}

async function main() {
  const base = baseUrl();
  const username = mustEnv('TEST_USERNAME', '');
  const password = mustEnv('TEST_PASSWORD', '');
  const company = mustEnv('TEST_COMPANY', 'DMF');

  console.log(`[smoke] base=${base}`);

  // Health should always work
  {
    const { res, json, text } = await httpJson(`${base}/api/health`);
    assert(res.ok, `GET /api/health failed: HTTP ${res.status} body=${text.slice(0, 300)}`);
    assert(json && json.status === 'ok', 'health JSON missing status=ok');
    console.log(`[smoke] health ok db_ready=${json.db_ready} uses_socket=${json.db?.uses_cloudsql_socket ?? null}`);
  }

  // Auth without token should be 401 (not 403)
  {
    const { res } = await httpJson(`${base}/api/auth/user-status`, { method: 'GET', headers: {} });
    assert(res.status === 401, `GET /api/auth/user-status without token expected 401, got ${res.status}`);
    console.log('[smoke] auth no-token -> 401 ok');
  }

  // Invalid token should be 401 (session expired semantics)
  {
    const { res } = await httpJson(`${base}/api/auth/user-status`, {
      method: 'GET',
      headers: { Authorization: 'Bearer invalid.token.value' }
    });
    assert(res.status === 401, `GET /api/auth/user-status invalid token expected 401, got ${res.status}`);
    console.log('[smoke] auth invalid-token -> 401 ok');
  }

  // Optional login and basic API calls
  let token = '';
  if (username && password) {
    const { res, json, text } = await httpJson(`${base}/api/auth/login`, {
      method: 'POST',
      body: JSON.stringify({ username, password })
    });
    assert(res.ok, `POST /api/auth/login failed: HTTP ${res.status} body=${text.slice(0, 300)}`);
    assert(json && json.token, 'login response missing token');
    token = json.token;
    console.log(`[smoke] login ok user=${json.user?.email || json.user?.username || '?'}`);

    // user-status with token
    const st = await httpJson(`${base}/api/auth/user-status`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` }
    });
    assert(st.res.ok, `GET /api/auth/user-status with token failed: HTTP ${st.res.status}`);
    console.log('[smoke] user-status ok');

    // Flow list should be stable ordered when available
    const f1 = await httpJson(`${base}/api/flow-payments?company=${encodeURIComponent(company)}`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` }
    });
    if (f1.res.status === 403) {
      console.log('[smoke] flow-payments -> 403 (no permission/company); skipping ordering check');
    } else {
      assert(f1.res.ok, `GET /api/flow-payments failed: HTTP ${f1.res.status}`);
      const payments = Array.isArray(f1.json?.payments) ? f1.json.payments : [];
      for (let i = 1; i < payments.length; i += 1) {
        const a = payments[i - 1];
        const b = payments[i];
        const at = a?.created_at ? new Date(a.created_at).getTime() : 0;
        const bt = b?.created_at ? new Date(b.created_at).getTime() : 0;
        const ok = at < bt || (at === bt && String(a?.id || '').localeCompare(String(b?.id || '')) <= 0);
        assert(ok, `ordering violated at index ${i} (created_at/id)`);
      }
      console.log(`[smoke] flow ordering ok count=${payments.length}`);
    }

    // SSE endpoint: must connect and emit a flow_update event with type=connected
    const sseUrl = `${base}/api/flow-payments/stream?company=${encodeURIComponent(company)}&access_token=${encodeURIComponent(token)}`;
    const evt = await readSseOnce(sseUrl, 7000);
    assert(evt.event === 'flow_update', `SSE first event expected flow_update, got ${evt.event}`);
    assert(evt.data && evt.data.type === 'connected', `SSE payload expected type=connected, got ${JSON.stringify(evt.data)}`);
    console.log('[smoke] sse connected ok');
  } else {
    console.log('[smoke] TEST_USERNAME/TEST_PASSWORD not set; skipping login-dependent checks');
  }

  // Give the process a clean exit
  await sleep(50);
  console.log('[smoke] PASS');
}

main().catch((err) => {
  console.error('[smoke] FAIL', err && err.stack ? err.stack : err);
  process.exit(1);
});

